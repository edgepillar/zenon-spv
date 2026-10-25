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
READ_BYTES = 64 << 10
MANIFEST_BYTES = 512 << 10
UINT64_MAX = (1 << 64) - 1
DEFAULT_LIMITS = {"bytes": 256 << 20, "chunk_bytes": 16 << 20, "chunks": 1024}
HARD_LIMITS = {"bytes": 16 << 30, "chunk_bytes": 64 << 20, "chunks": 4096}
PIN_KEYS = {"bytes", "sha256", "height", "hash", "provenance_sha256", "record_space"}
USAGE = ("ledger-transport describe|verify: require --expect-bytes, --expect-sha256, "
         "--expect-height, --expect-hash and --provenance-sha256; optional "
         "--max-bytes, --max-chunk-bytes and --max-chunks. Verify also requires "
         "--manifest-bytes and --manifest-sha256. Describe reads the selected "
         "stream; verify reads exact manifest bytes followed by that stream.\n")


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


def consume(reader, pin, plan):
    """One pass, no chunk buffers or files; retain only hashes and bounded rows."""
    whole = hashlib.sha256()
    rows = []
    for size, expected in plan:
        remaining, chunk = size, hashlib.sha256()
        while remaining:
            part = read_part(reader, min(READ_BYTES, remaining))
            require(bool(part), "stream_truncated")
            whole.update(part)
            chunk.update(part)
            remaining -= len(part)
        actual = chunk.hexdigest()
        require(expected is None or actual == expected, "chunk_digest")
        rows.append({"bytes": size, "sha256": actual})
    require(not read_part(reader, 1), "trailing_input")
    require(whole.hexdigest() == pin["sha256"], "stream_digest")
    return rows


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


def verify(reader, manifest_bytes, manifest_sha256, selected, configured_limits=None):
    caps = limits(configured_limits)
    pin = selection(selected, caps)
    require(type(manifest_bytes) is int and 0 < manifest_bytes <= MANIFEST_BYTES and
            digest(manifest_sha256), "manifest_pin")
    raw = read_exact(reader, manifest_bytes)
    require(hashlib.sha256(raw).hexdigest() == manifest_sha256, "manifest_digest")
    plan = chunk_plan(parse_manifest(raw), pin, caps)
    consume(reader, pin, plan)
    return {"format": RESULT_FORMAT, "status": "SELECTED_TRANSPORT_MATCHED", "reason": None,
            "manifest": {"bytes": manifest_bytes, "sha256": manifest_sha256},
            "selection": pin, "chunks_checked": len(plan), "stream_eof_observed": True,
            "limits": caps, "read_request_limit_bytes": READ_BYTES, "scope": scope()}


def decimal(token):
    require(type(token) is str and 0 < len(token) <= 20 and
            re.fullmatch(r"0|[1-9][0-9]*", token, re.ASCII), "options")
    value = int(token)
    require(unsigned(value), "options")
    return value


def options(args):
    require(type(args) in (list, tuple) and 0 < len(args) <= 24 and
            all(type(arg) is str for arg in args) and sum(map(len, args)) <= 4096, "options")
    mode = args[0]
    require(mode in ("describe", "verify"), "options")
    required = {"--expect-bytes", "--expect-sha256", "--expect-height", "--expect-hash", "--provenance-sha256"}
    if mode == "verify":
        required |= {"--manifest-bytes", "--manifest-sha256"}
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
    return mode, pin, caps, manifest


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
                mode, pin, caps, manifest = options(args)
            except Refused:
                raise Refused("options") from None
            result = describe(reader, pin, caps) if mode == "describe" else verify(reader, *manifest, pin, caps)
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
