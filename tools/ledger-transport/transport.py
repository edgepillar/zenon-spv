#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Describe or check selected raw-ledger transport bytes without copying them.

This offline tool writes metadata only. It parses no ledger records, opens no
paths, launches no children and authenticates no snapshot or state root.
"""
import hashlib
import json
import re
import sys


MANIFEST_FORMAT = "zenon-r1-transport-manifest/v1"
RESULT_FORMAT = "zenon-r1-transport-check/v1"
RANGE_FORMAT = "zenon-r1-transport-range/v1"
READ_BYTES = 64 << 10
MANIFEST_BYTES = 512 << 10
UINT64_MAX = (1 << 64) - 1
DEFAULT_LIMITS = {"bytes": 256 << 20, "chunk_bytes": 16 << 20, "chunks": 1024}
HARD_LIMITS = {"bytes": 16 << 30, "chunk_bytes": 64 << 20, "chunks": 4096}
PIN_KEYS = {"bytes", "sha256", "height", "hash", "provenance_sha256", "record_space"}
USAGE = ("ledger-transport describe|verify|plan-range|verify-range: require --expect-bytes, --expect-sha256, "
         "--expect-height, --expect-hash and --provenance-sha256; optional "
         "--max-bytes, --max-chunk-bytes and --max-chunks. Except for describe, require "
         "--manifest-bytes and --manifest-sha256. Range modes also require "
         "--first-chunk (zero-based) and --chunk-count. Describe reads the selected stream. "
         "Verify reads the manifest followed by the whole stream, plan-range reads only "
         "the manifest, and verify-range reads the manifest followed by the selected range.\n")


class Refused(ValueError):
    """Static reason code; never contains input bytes, options or paths."""


def require(condition, reason):
    if not condition:
        raise Refused(reason)


def digest(value):
    return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def unsigned(value):
    return type(value) is int and 0 <= value <= UINT64_MAX


def scope():
    return {name: False for name in (
        "ledger_record_syntax_checked", "ledger_origin_authenticated",
        "ledger_consistency_authenticated", "snapshot_completeness_authenticated",
        "representative_dataset_accepted", "state_tree_reconstructed",
        "header_authentication_executed", "profile_agreed",
        "network_activation_authenticated", "state_value_acceptance_enabled")}


def limits(configured=None):
    value = dict(DEFAULT_LIMITS) if configured is None else configured
    require(type(value) is dict and set(value) == set(HARD_LIMITS), "limits")
    require(all(type(value[key]) is int and 0 < value[key] <= maximum
                for key, maximum in HARD_LIMITS.items()), "limits")
    return dict(value)


def selection(selected, caps):
    require(type(selected) is dict and set(selected) == PIN_KEYS, "selection")
    pin = dict(selected)
    require(unsigned(pin["bytes"]) and pin["bytes"] <= caps["bytes"], "selection_bytes")
    require(unsigned(pin["height"]), "selection_height")
    require(pin["record_space"] == "effective-raw-ledger" and
            type(pin["record_space"]) is str, "record_space")
    require(all(digest(pin[key]) for key in ("sha256", "hash", "provenance_sha256")), "selection_digest")
    return pin


def read_part(reader, size):
    require(type(size) is int and 0 < size <= READ_BYTES, "read_bound")
    part = reader.read(size)
    require(type(part) is bytes and len(part) <= size, "input_read")
    return part


def read_exact(reader, size):
    raw = bytearray()
    while len(raw) < size:
        part = read_part(reader, min(READ_BYTES, size - len(raw)))
        require(bool(part), "manifest_truncated")
        raw.extend(part)
    return bytes(raw)


def encoded(value):
    raw = (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()
    require(len(raw) <= MANIFEST_BYTES, "manifest_size")
    return raw


def parse_manifest(raw):
    require(type(raw) is bytes and 0 < len(raw) <= MANIFEST_BYTES, "manifest_size")

    def pairs(items):
        value = {}
        for key, item in items:
            require(key not in value, "manifest_json")
            value[key] = item
        return value

    def integer(token):
        require(len(token) <= 20 and re.fullmatch(r"0|[1-9][0-9]*", token, re.ASCII), "manifest_json")
        value = int(token)
        require(unsigned(value), "manifest_json")
        return value

    def noninteger(_):
        raise Refused("manifest_json")

    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_int=integer,
                          parse_float=noninteger, parse_constant=noninteger)
    except (UnicodeError, ValueError, RecursionError):
        raise Refused("manifest_json") from None


def chunk_plan(value, pin, caps):
    require(type(value) is dict and set(value) ==
            {"format", "selection", "chunk_bytes", "chunks", "scope"}, "manifest_schema")
    require(value["format"] == MANIFEST_FORMAT, "manifest_format")
    # Validate types before equality: JSON booleans must never stand in for integers.
    observed_pin = selection(value["selection"], caps)
    require(observed_pin == pin, "manifest_selection")
    authority = value["scope"]
    require(type(authority) is dict and set(authority) == set(scope()) and
            all(item is False for item in authority.values()), "manifest_scope")
    size = value["chunk_bytes"]
    require(type(size) is int and 0 < size <= caps["chunk_bytes"], "chunk_size")
    rows = value["chunks"]
    require(type(rows) is list and len(rows) <= caps["chunks"], "chunk_count")
    count = (pin["bytes"] + size - 1) // size
    require(len(rows) == count, "chunk_count")
    plan = []
    for index, row in enumerate(rows):
        require(type(row) is dict and set(row) == {"bytes", "sha256"}, "chunk_schema")
        expected = min(size, pin["bytes"] - index * size)
        require(type(row["bytes"]) is int and row["bytes"] == expected and
                digest(row["sha256"]), "chunk_shape")
        plan.append((expected, row["sha256"]))
    return tuple(plan)


class _ChunkStream:
    def __init__(self, reader, plan, expected_stream=None):
        self.reader, self.expected_stream = reader, expected_stream
        self.plan = iter(plan)
        self.whole = hashlib.sha256() if expected_stream is not None else None
        self.chunk = None
        self.remaining, self.rows = 0, []
        self.complete, self.failed = False, False

    def read(self, size):
        require(not self.failed, "stream_refused")
        # An inspector cannot suppress a failed read and continue verification.
        self.failed = True
        require(type(size) is int and 0 < size <= READ_BYTES, "read_bound")
        part = self._read(size)
        self.failed = False
        return part

    def _read(self, size):
        if self.complete:
            return b""
        if not self.remaining:
            next_chunk = next(self.plan, None)
            if next_chunk is None:
                require(not read_part(self.reader, 1), "trailing_input")
                if self.whole is not None:
                    require(self.whole.hexdigest() == self.expected_stream, "stream_digest")
                self.complete = True
                return b""
            self.chunk_size, self.expected_chunk = next_chunk
            self.remaining = self.chunk_size
            # At the first boundary the whole-stream state covers exactly the first chunk.
            self.chunk = (self.whole if self.chunk is None and self.whole is not None
                          else hashlib.sha256())
        part = read_part(self.reader, min(size, self.remaining))
        require(bool(part), "stream_truncated")
        if self.whole is not None:
            self.whole.update(part)
        if self.chunk is not self.whole:
            self.chunk.update(part)
        self.remaining -= len(part)
        if not self.remaining:
            actual = self.chunk.hexdigest()
            require(self.expected_chunk is None or actual == self.expected_chunk, "chunk_digest")
            self.rows.append({"bytes": self.chunk_size, "sha256": actual})
        return part


def _drain(stream):
    while stream.read(READ_BYTES):
        pass


def consume(reader, pin, plan):
    """One pass, no chunk buffers or files; retain only hashes and bounded rows."""
    stream = _ChunkStream(reader, plan, pin["sha256"])
    _drain(stream)
    return stream.rows


def describe(reader, selected, configured_limits=None):
    caps = limits(configured_limits)
    pin = selection(selected, caps)
    size = caps["chunk_bytes"]
    count = (pin["bytes"] + size - 1) // size
    require(count <= caps["chunks"], "chunk_count")
    plan = tuple((min(size, pin["bytes"] - index * size), None) for index in range(count))
    rows = consume(reader, pin, plan)
    value = {"format": MANIFEST_FORMAT, "selection": pin, "chunk_bytes": size,
             "chunks": rows, "scope": scope()}
    encoded(value)  # Bound final metadata before reporting successful creation.
    return value


def _read_manifest(reader, manifest_bytes, manifest_sha256, pin, caps):
    require(type(manifest_bytes) is int and 0 < manifest_bytes <= MANIFEST_BYTES and
            digest(manifest_sha256), "manifest_pin")
    raw = read_exact(reader, manifest_bytes)
    require(hashlib.sha256(raw).hexdigest() == manifest_sha256, "manifest_digest")
    value = parse_manifest(raw)
    plan = chunk_plan(value, pin, caps)
    return value["chunk_bytes"], plan


def verify_with(reader, manifest_bytes, manifest_sha256, selected, inspect, configured_limits=None):
    """Return the transport report and a read-only inspector's result after EOF.

    The inspector receives candidate bytes. It must not publish its result or
    apply changes before this function returns successfully.
    """
    caps = limits(configured_limits)
    pin = selection(selected, caps)
    _, plan = _read_manifest(reader, manifest_bytes, manifest_sha256, pin, caps)
    stream = _ChunkStream(reader, plan, pin["sha256"])
    result = inspect(stream)
    require(stream.complete and not stream.failed, "stream_incomplete")
    report = {"format": RESULT_FORMAT, "status": "SELECTED_TRANSPORT_MATCHED", "reason": None,
              "manifest": {"bytes": manifest_bytes, "sha256": manifest_sha256},
              "selection": pin, "chunks_checked": len(plan), "stream_eof_observed": True,
              "limits": caps, "read_request_limit_bytes": READ_BYTES, "scope": scope()}
    return report, result


def verify(reader, manifest_bytes, manifest_sha256, selected, configured_limits=None):
    report, _ = verify_with(reader, manifest_bytes, manifest_sha256, selected, _drain, configured_limits)
    return report


def check_range(reader, manifest_bytes, manifest_sha256, selected, first_chunk, chunk_count,
                configured_limits=None, *, verify_payload=False):
    """Plan a selected contiguous chunk range, or check its exact payload.

    The whole-stream pin selects the manifest's identity. Only verify() and
    verify_with() check the SHA-256 of the complete ordered stream.
    """
    caps = limits(configured_limits)
    pin = selection(selected, caps)
    require(type(verify_payload) is bool and unsigned(first_chunk) and unsigned(chunk_count)
            and 0 < chunk_count <= caps["chunks"] - first_chunk, "range_selection")
    size, plan = _read_manifest(reader, manifest_bytes, manifest_sha256, pin, caps)
    end_chunk = first_chunk + chunk_count
    require(end_chunk <= len(plan), "range_selection")
    part = plan[first_chunk:end_chunk]
    if verify_payload:
        stream = _ChunkStream(reader, part)
        _drain(stream)
        chunks = stream.rows
    else:
        require(not read_part(reader, 1), "trailing_input")
        chunks = [{"bytes": count, "sha256": sha256} for count, sha256 in part]
    return {"format": RANGE_FORMAT,
            "status": "SELECTED_RANGE_MATCHED" if verify_payload else "SELECTED_RANGE_PLANNED",
            "reason": None, "manifest": {"bytes": manifest_bytes, "sha256": manifest_sha256},
            "selection": pin,
            "range": {"first_chunk": first_chunk, "chunk_count": chunk_count, "offset": first_chunk * size,
                      "bytes": sum(row["bytes"] for row in chunks), "chunks": chunks},
            "range_eof_observed": verify_payload, "whole_stream_digest_verified": False,
            "limits": caps, "read_request_limit_bytes": READ_BYTES, "scope": scope()}


def decimal(token):
    require(type(token) is str and 0 < len(token) <= 20 and
            re.fullmatch(r"0|[1-9][0-9]*", token, re.ASCII), "options")
    value = int(token)
    require(unsigned(value), "options")
    return value


def options(args):
    require(type(args) in (list, tuple) and 0 < len(args) <= 25 and
            all(type(arg) is str for arg in args) and sum(map(len, args)) <= 4096, "options")
    mode = args[0]
    require(mode in ("describe", "verify", "plan-range", "verify-range"), "options")
    ranged = mode in ("plan-range", "verify-range")
    required = {"--expect-bytes", "--expect-sha256", "--expect-height", "--expect-hash", "--provenance-sha256"}
    if mode != "describe":
        required |= {"--manifest-bytes", "--manifest-sha256"}
    if ranged:
        required |= {"--first-chunk", "--chunk-count"}
    optional = {"--max-" + key.replace("_", "-") for key in DEFAULT_LIMITS}
    values, index = {}, 1
    while index < len(args):
        key, separator, value = args[index].partition("=")
        require(key in required | optional and key not in values, "options")
        if not separator:
            index += 1
            require(index < len(args), "options")
            value = args[index]
        require(bool(value), "options")
        values[key] = value
        index += 1
    require(required <= set(values), "options")
    caps = limits({key: decimal(values["--max-" + key.replace("_", "-")])
                   if "--max-" + key.replace("_", "-") in values else default
                   for key, default in DEFAULT_LIMITS.items()})
    pin = selection({"bytes": decimal(values["--expect-bytes"]), "sha256": values["--expect-sha256"],
                     "height": decimal(values["--expect-height"]), "hash": values["--expect-hash"],
                     "provenance_sha256": values["--provenance-sha256"],
                     "record_space": "effective-raw-ledger"}, caps)
    manifest = None if mode == "describe" else (decimal(values["--manifest-bytes"]), values["--manifest-sha256"])
    if manifest is not None:
        require(0 < manifest[0] <= MANIFEST_BYTES and digest(manifest[1]), "options")
    span = None
    if ranged:
        span = (decimal(values["--first-chunk"]), decimal(values["--chunk-count"]))
        require(0 < span[1] <= caps["chunks"] - span[0], "options")
    return mode, pin, caps, manifest, span


def unknown(reason):
    return {"format": RESULT_FORMAT, "status": "UNKNOWN", "reason": reason,
            "stream_eof_observed": False, "scope": scope()}


def main(args, reader, writer, diagnostic):
    code = 0
    try:
        if args == ["--help"]:
            diagnostic.write(USAGE)
            result = unknown("help")
        else:
            try:
                mode, pin, caps, manifest, span = options(args)
            except Refused:
                raise Refused("options") from None
            if mode == "describe":
                result = describe(reader, pin, caps)
            elif mode == "verify":
                result = verify(reader, *manifest, pin, caps)
            else:
                result = check_range(reader, *manifest, pin, *span, caps, verify_payload=mode == "verify-range")
    except Refused as error:
        code, result = (64 if str(error) == "options" else 2), unknown(str(error))
    except (OSError, TypeError, ValueError, OverflowError):
        code, result = 70, unknown("input_error")
    except KeyboardInterrupt:
        code, result = 130, unknown("interrupted")
    try:
        raw = encoded(result)
        if writer.write(raw) != len(raw):
            return 70
        writer.flush()
    except (OSError, ValueError):
        return 70
    except KeyboardInterrupt:
        return 130
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:], sys.stdin.buffer, sys.stdout.buffer, sys.stderr))
