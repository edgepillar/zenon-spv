#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Stream a selected HTTPS archive tail or verify one replacement range."""

import hashlib
import http.client
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


READ_BYTES = 64 << 10
HARD_TAIL_BYTES = 4 << 20
HARD_RANGE_BYTES = 64 << 20
HARD_ARCHIVE_BYTES = 1 << 40
HEADER_BYTES = 16 << 10
DEFAULT_BYTES = 1 << 20
DEFAULT_TIMEOUT_SECONDS = 15
TAIL_FORMAT = "zenon-r1-archive-tail/v1"
RANGE_FORMAT = "zenon-r1-archive-range/v1"
REASONS = frozenset(("options", "http_status", "response_origin", "response_headers",
                     "content_range", "content_length", "etag", "transfer_encoding",
                     "content_encoding", "deadline", "body_length", "range_sha256", "output_incomplete"))
USAGE = ("archive-tail: require --url, --archive-bytes, --archive-sha256, "
         "--tail-bytes and --etag; optional --max-tail-bytes and --timeout-seconds. "
         "Binary tail bytes go to stdout; a small receipt goes to stderr.\n")
RANGE_USAGE = ("Run archive-tail range with --url, --archive-bytes, --archive-sha256, "
               "--offset, --range-bytes, --range-sha256 and --etag. Optional flags are "
               "--max-range-bytes and --timeout-seconds. Binary range bytes go to "
               "stdout and a small receipt goes to stderr.\n")


class Refused(ValueError):
    pass


def require(value, reason):
    if not value:
        raise Refused(reason)


def scope():
    return {name: False for name in (
        "whole_archive_sha256_verified", "archive_payload_syntax_checked",
        "ledger_origin_authenticated", "ledger_consistency_authenticated",
        "snapshot_completeness_authenticated", "representative_dataset_accepted",
        "state_tree_reconstructed", "header_authentication_executed", "profile_agreed",
        "network_activation_authenticated", "state_value_acceptance_enabled")}


def limits(configured=None, *, range_mode=False):
    require(configured is None or type(configured) is dict, "options")
    byte_key = "range_bytes" if range_mode else "tail_bytes"
    maximum = HARD_RANGE_BYTES if range_mode else HARD_TAIL_BYTES
    defaults = {byte_key: DEFAULT_BYTES, "timeout_seconds": DEFAULT_TIMEOUT_SECONDS}
    value = defaults if configured is None else dict(configured)
    require(set(value) == set(defaults), "options")
    require(all(type(v) is int for v in value.values()), "options")
    require(0 < value[byte_key] <= maximum and
            0 < value["timeout_seconds"] <= 60, "options")
    return value


def selection(selected, caps, *, range_mode=False):
    byte_key = "range_bytes" if range_mode else "tail_bytes"
    required = {"url", "archive_bytes", "archive_sha256", byte_key, "etag"}
    if range_mode:
        required |= {"offset", "range_sha256"}
    require(type(selected) is dict and set(selected) == required, "options")
    pin = dict(selected)
    require(type(pin["archive_bytes"]) is int and
            0 < pin["archive_bytes"] <= HARD_ARCHIVE_BYTES, "options")
    require(type(pin[byte_key]) is int and
            0 < pin[byte_key] <= min(caps[byte_key], pin["archive_bytes"]), "options")
    require(type(pin["archive_sha256"]) is str and
            re.fullmatch("[0-9a-f]{64}", pin["archive_sha256"]) is not None, "options")
    if range_mode:
        require(type(pin["offset"]) is int and
                0 <= pin["offset"] <= pin["archive_bytes"] - pin[byte_key], "options")
        require(type(pin["range_sha256"]) is str and
                re.fullmatch("[0-9a-f]{64}", pin["range_sha256"]) is not None, "options")
    require(type(pin["etag"]) is str and
            re.fullmatch(r'"[\x21\x23-\x7e]{0,510}"', pin["etag"]) is not None, "options")
    url = pin["url"]
    require(type(url) is str and 0 < len(url) <= 4096 and
            all(0x21 <= ord(c) <= 0x7e for c in url) and "#" not in url, "options")
    try:
        parsed = urllib.parse.urlsplit(url)
        require(parsed.scheme == "https" and parsed.hostname and
                parsed.username is None and parsed.password is None and not parsed.fragment and
                not parsed.netloc.endswith(":"), "options")
        require(parsed.port is None or 0 < parsed.port <= 65535, "options")
    except ValueError:
        raise Refused("options") from None
    return pin


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, newurl):
        return None


def https_open(request, timeout):
    # Do not install a global opener, bypass TLS verification or read an error
    # body. The standard HTTPS handler verifies the selected origin's TLS.
    try:
        return urllib.request.build_opener(NoRedirect()).open(request, timeout=timeout)
    except urllib.error.HTTPError as error:
        error.close()
        raise Refused("http_status") from None


def check_headers(response, pin, start, count):
    require(type(response.status) is int and response.status == 206, "http_status")
    require(response.geturl() == pin["url"], "response_origin")
    fields = list(response.headers.raw_items())
    require(len(fields) <= 64 and all(type(k) is str and type(v) is str for k, v in fields),
            "response_headers")
    require(sum(len(k) + len(v) + 4 for k, v in fields) <= HEADER_BYTES and
            all("\r" not in k + v and "\n" not in k + v for k, v in fields), "response_headers")

    def one(name):
        values = response.headers.get_all(name, [])
        require(len(values) == 1, "response_headers")
        return values[0]

    require(one("Content-Range") == "bytes %d-%d/%d" %
            (start, start + count - 1, pin["archive_bytes"]), "content_range")
    require(one("Content-Length") == str(count), "content_length")
    require(one("ETag") == pin["etag"], "etag")
    require(not response.headers.get_all("Transfer-Encoding", []), "transfer_encoding")
    coding = response.headers.get_all("Content-Encoding", [])
    require(coding == [] or coding == ["identity"], "content_encoding")


def fetch(selected, writer, configured_limits=None, opener=None, clock=time.monotonic, *, range_mode=False):
    caps = limits(configured_limits, range_mode=range_mode)
    pin = selection(selected, caps, range_mode=range_mode)
    count = pin["range_bytes"] if range_mode else pin["tail_bytes"]
    start = pin["offset"] if range_mode else pin["archive_bytes"] - count
    request = urllib.request.Request(pin["url"], method="GET", headers={
        "Range": "bytes=%d-%d" % (start, start + count - 1),
        "If-Match": pin["etag"], "Accept-Encoding": "identity"})
    deadline = clock() + caps["timeout_seconds"]

    def within_deadline():
        require(clock() < deadline, "deadline")

    within_deadline()
    response = (https_open if opener is None else opener)(request, caps["timeout_seconds"])
    try:
        within_deadline()
        check_headers(response, pin, start, count)
        # HTTPResponse.read1 performs one underlying buffered read, so a slow
        # but progressing peer does not keep one coalescing read active while
        # elapsed checks wait. Injected bounded readers may expose read only.
        reader = getattr(response, "read1", None)
        if reader is None:
            reader = response.read
        remaining = count
        digest = hashlib.sha256()
        while remaining:
            within_deadline()
            requested = min(remaining, READ_BYTES)
            part = reader(requested)
            within_deadline()
            require(type(part) is bytes and 0 < len(part) <= requested, "body_length")
            written = writer.write(part)
            require(type(written) is int and written == len(part), "output_incomplete")
            digest.update(part)
            remaining -= len(part)
        within_deadline()
        extra = reader(1)
        require(type(extra) is bytes and extra == b"", "body_length")
        within_deadline()
        observed = digest.hexdigest()
        if range_mode:
            require(observed == pin["range_sha256"], "range_sha256")
        writer.flush()
        within_deadline()
    finally:
        response.close()
    captured = {"offset": start, "bytes": count, "sha256": observed}
    common = {"archive": {"bytes": pin["archive_bytes"], "sha256_selection": pin["archive_sha256"]},
              "conditional_range_headers_matched": True, "response_body_eof_observed": True,
              "stdout_flushed": True, "scope": scope()}
    if range_mode:
        return {"format": RANGE_FORMAT, "status": "SELECTED_RANGE_MATCHED",
                "range": captured, "range_sha256_verified": True, **common}
    return {"format": TAIL_FORMAT, "status": "SELECTED_TAIL_CAPTURED", "tail": captured, **common}


def decimal(token):
    require(type(token) is str and re.fullmatch("0|[1-9][0-9]{0,19}", token) is not None, "options")
    return int(token)


def options(args, *, range_mode=False):
    byte_key = "range_bytes" if range_mode else "tail_bytes"
    byte_flag = "--range-bytes" if range_mode else "--tail-bytes"
    max_flag = "--max-range-bytes" if range_mode else "--max-tail-bytes"
    required = {"--url", "--archive-bytes", "--archive-sha256", byte_flag, "--etag"}
    if range_mode:
        required |= {"--offset", "--range-sha256"}
    known = required | {max_flag, "--timeout-seconds"}
    require(len(args) <= 2 * len(known) and len(args) % 2 == 0, "options")
    values = {}
    for key, value in zip(args[::2], args[1::2]):
        require(key in known and key not in values and type(value) is str, "options")
        values[key] = value
    require(required <= set(values), "options")
    caps = limits({byte_key: decimal(values.get(max_flag, str(DEFAULT_BYTES))),
                   "timeout_seconds": decimal(values.get("--timeout-seconds", str(DEFAULT_TIMEOUT_SECONDS)))},
                  range_mode=range_mode)
    pin = {"url": values["--url"], "archive_bytes": decimal(values["--archive-bytes"]),
           "archive_sha256": values["--archive-sha256"], byte_key: decimal(values[byte_flag]),
           "etag": values["--etag"]}
    if range_mode:
        pin.update(offset=decimal(values["--offset"]), range_sha256=values["--range-sha256"])
    return selection(pin, caps, range_mode=range_mode), caps


def unknown(reason, *, range_mode=False):
    if range_mode:
        return {"format": RANGE_FORMAT, "status": "UNKNOWN", "reason": reason,
                "stdout_may_contain_unverified_range": True, "scope": scope()}
    return {"format": TAIL_FORMAT, "status": "UNKNOWN", "reason": reason,
            "stdout_may_contain_partial_tail": True, "scope": scope()}


def main(args, writer, diagnostic, opener=None, clock=time.monotonic):
    range_mode = args[:1] == ["range"]
    if range_mode:
        args = args[1:]
    code = 0
    try:
        if args == ["--help"]:
            diagnostic.write(RANGE_USAGE if range_mode else USAGE)
            result = unknown("help_only", range_mode=range_mode)
        else:
            try:
                pin, caps = options(args, range_mode=range_mode)
            except (Refused, TypeError, ValueError, OverflowError):
                code, result = 64, unknown("options", range_mode=range_mode)
            else:
                result = fetch(pin, writer, caps, opener, clock, range_mode=range_mode)
    except Refused as error:
        reason = str(error)
        code, result = 2, unknown(reason if reason in REASONS else "refused_data", range_mode=range_mode)
    except KeyboardInterrupt:
        code, result = 130, unknown("interrupted", range_mode=range_mode)
    except (OSError, urllib.error.URLError, http.client.HTTPException, ValueError, TypeError):
        code, result = 70, unknown("io_failure", range_mode=range_mode)
    except Exception:
        code, result = 70, unknown("unexpected_failure", range_mode=range_mode)
    try:
        encoded = json.dumps(result, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n"
        if diagnostic.write(encoded) != len(encoded):
            return 70
        diagnostic.flush()
    except KeyboardInterrupt:
        return 130
    except Exception:
        return 70
    return code


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:], sys.stdout.buffer, sys.stderr))
