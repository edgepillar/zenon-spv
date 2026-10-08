#!/usr/bin/env python3
"""Consume a complete trusted observer diagnostic, never a chain proof.

The caller supplies the actual outer process exit, independently expected target
count and selected local-file/collected mode. This command reads only bounded
stdin; it does not open report paths, execute children or choose trust inputs.
"""

import json
import re
import sys


REPORT_BYTES = 16 << 10
INT64_MAX = (1 << 63) - 1
ROOT_FIELDS = {"schema_version", "status", "category", "checked_targets",
               "elapsed_ns", "verifier", "consumer"}
CHILD_FIELDS = {"exit_code", "elapsed_ns", "stdout_bytes", "stderr_bytes"}
STDOUT_LIMITS = {"verifier": 4 << 20, "consumer": 1024, "collector": 64 << 20}
USAGE = "consume-observer-report: require one --mode local-file|collected, --observer-exit-code and --expected-targets 1..256\n"


class Invalid(ValueError):
    pass


def integer(value, low=0, high=INT64_MAX):
    return type(value) is int and low <= value <= high


def parse_integer(token):
    if len(token.lstrip("-")) > 19:
        raise Invalid("integer range")
    value = int(token)
    if not -(1 << 63) <= value <= INT64_MAX:
        raise Invalid("integer range")
    return value


def noninteger(_):
    raise Invalid("noninteger number")


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Invalid("duplicate field")
        result[key] = value
    return result


def selections(args):
    fields = {}
    remaining = iter(args)
    for argument in remaining:
        name, equal, value = argument.partition("=")
        if name not in {"--mode", "--observer-exit-code", "--expected-targets"} or name in fields:
            raise Invalid("option selection")
        if not equal:
            value = next(remaining, "")
        if not value:
            raise Invalid("empty option")
        fields[name] = value
    if len(fields) != 3 or fields["--mode"] not in {"local-file", "collected"}:
        raise Invalid("incomplete selection")
    numbers = []
    for name in ("--observer-exit-code", "--expected-targets"):
        token = fields[name]
        if len(token) > 20 or re.fullmatch(r"-?(?:0|[1-9][0-9]*)", token, flags=re.ASCII) is None:
            raise Invalid("integer selection")
        numbers.append(int(token))
    actual, expected = numbers
    if not integer(actual, -(1 << 31), (1 << 31) - 1) or not integer(expected, 1, 256):
        raise Invalid("selection range")
    return fields["--mode"], actual, expected


def read_complete(reader):
    raw = bytearray()
    while len(raw) <= REPORT_BYTES:
        requested = min(4096, REPORT_BYTES + 1 - len(raw))
        chunk = reader.read(requested)
        if type(chunk) is not bytes or len(chunk) > requested:
            raise Invalid("invalid reader result")
        if not chunk:
            return bytes(raw)
        raw.extend(chunk)
    raise Invalid("report bound")


def decision(raw, mode, expected):
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique,
                       parse_int=parse_integer, parse_float=noninteger, parse_constant=noninteger)
    children = ("verifier", "consumer") if mode == "local-file" else ("collector", "verifier", "consumer")
    fields = ROOT_FIELDS if mode == "local-file" else ROOT_FIELDS | {"collector"}
    if type(value) is not dict or set(value) != fields:
        return "invalid_report"
    if not integer(value["elapsed_ns"]):
        return "invalid_report"
    for name in children:
        child = value[name]
        if type(child) is not dict or set(child) != CHILD_FIELDS:
            return "invalid_report"
        if not integer(child["elapsed_ns"]) or not integer(child["stdout_bytes"], 1, STDOUT_LIMITS[name]) or not integer(child["stderr_bytes"], 0, 16 << 10):
            return "invalid_report"
        if not integer(child["exit_code"]) or child["exit_code"] != 0:
            return "report_mismatch"
    version = 1 if mode == "local-file" else 2
    if (not integer(value["schema_version"]) or value["schema_version"] != version or
            value["status"] != "matched" or value["category"] is not None or
            not integer(value["checked_targets"], 1, 256) or value["checked_targets"] != expected):
        return "report_mismatch"
    return None


def diagnostic(stream, message):
    try:
        stream.write(message)
    except OSError:
        pass


def emit(output, diagnostics, category, count, code):
    value = {"schema_version": 1, "status": "matched" if category is None else "not_matched",
             "category": category, "checked_targets": count if category is None else 0}
    raw = json.dumps(value, separators=(",", ":")) + "\n"
    try:
        if output.write(raw) != len(raw):
            raise OSError("incomplete output")
        output.flush()
    except OSError:
        diagnostic(diagnostics, "consume-observer-report: cannot write result\n")
        return 70
    return code


def run(args, reader, output, diagnostics):
    try:
        mode, actual, expected = selections(args)
    except Invalid:
        diagnostic(diagnostics, USAGE)
        return 64
    # Process completion is caller evidence; a successful-looking report cannot
    # override it. Do not read a stream from a failed or unfinished producer.
    if actual != 0:
        return emit(output, diagnostics, "process_failure", 0, 2)
    try:
        category = decision(read_complete(reader), mode, expected)
    except (Invalid, ValueError, TypeError, RecursionError):
        category = "invalid_report"
    except OSError:
        return emit(output, diagnostics, "input_unavailable", 0, 70)
    except KeyboardInterrupt:
        return emit(output, diagnostics, "cancelled", 0, 130)
    return emit(output, diagnostics, category, expected, 0 if category is None else 2)


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:], sys.stdin.buffer, sys.stdout, sys.stderr))
