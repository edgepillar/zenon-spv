#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Reconcile a captured frontier export before independent stream inventory.

Read only a bounded producer receipt on stdin. Actual process completion,
capture status and stream pins must come from the caller's protected channel.
This program opens no paths, executes no children and authenticates no state.
"""
import hashlib
import json
import re
import sys


FORMAT = "zenon-frontier-export-completion/v1"
LAYOUT = "zenon-9c71-frontier-v1"
NODE_REVISION = "9c71ae82fc983e16f914ae085d4034030c8ebe3b"
REPORT_BYTES = 16 << 10
UINT64_MAX = (1 << 64) - 1
LIMITS = {
    "--max-bytes": ("output_bytes", 256 << 20, 16 << 30),
    "--max-records": ("records", 2_000_000, 100_000_000),
    "--max-scan-bytes": ("scan_key_and_encoded_value_bytes", 256 << 20, 16 << 30),
    "--max-scan-records": ("scan_records", 2_000_000, 100_000_000),
    "--max-key-bytes": ("key_bytes", 1024, 1 << 20),
    "--max-value-bytes": ("value_bytes", 1 << 20, 64 << 20),
}
REQUIRED = {"--layout", "--expect-height", "--expect-hash", "--provenance-sha256",
            "--producer-exit", "--capture-status", "--capture-bytes", "--capture-sha256"}
PRODUCER_SCOPE = {"input_role_required": "declared-immutable-copy", **{
    name: False for name in (
        "input_immutability_authenticated", "ledger_origin_authenticated",
        "snapshot_completeness_authenticated", "representative_dataset_accepted",
        "profile_agreed", "network_activation_authenticated",
        "header_authentication_executed", "canonical_chain_qualified",
        "absence_or_delete_proof", "state_value_acceptance_enabled")}}
STATISTICS = {"records", "put_wire_bytes", "scanned_records",
              "scanned_key_and_encoded_value_bytes", "physical_tombstones_omitted",
              "present_empty_values", "put_stream_sha256"}
USAGE = ("consume-completion: require --layout zenon-9c71-frontier-v1, "
         "--expect-height, --expect-hash, --provenance-sha256, --producer-exit, "
         "--capture-status complete|incomplete|unknown, --capture-bytes and "
         "--capture-sha256; optional exporter --max-* limits\n")


class Refused(ValueError):
    """Static reason code; never contains arguments, paths or producer text."""


def require(condition, reason):
    if not condition:
        raise Refused(reason)


def unsigned(value):
    return type(value) is int and 0 <= value <= UINT64_MAX


def hex_digest(value):
    return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def decimal(token, signed=False):
    require(type(token) is str and 0 < len(token) <= 20, "options")
    pattern = r"-?(?:0|[1-9][0-9]*)" if signed else r"0|[1-9][0-9]*"
    require(token != "-0" and re.fullmatch(pattern, token, flags=re.ASCII), "options")
    value = int(token)
    require(-(1 << 31) <= value < (1 << 31) if signed else unsigned(value), "options")
    return value


def options(args):
    require(type(args) in (list, tuple) and len(args) <= 32 and
            all(type(value) is str for value in args) and
            sum(map(len, args)) <= 8 << 10, "options")
    values = {}
    index = 0
    while index < len(args):
        key, separator, value = args[index].partition("=")
        require(key in REQUIRED | set(LIMITS) and key not in values, "options")
        if not separator:
            index += 1
            require(index < len(args), "options")
            value = args[index]
        require(bool(value), "options")
        values[key] = value
        index += 1
    require(REQUIRED <= set(values) and values["--layout"] == LAYOUT, "options")
    require(all(hex_digest(values[key]) for key in
                ("--expect-hash", "--provenance-sha256", "--capture-sha256")), "options")
    require(values["--capture-status"] in ("complete", "incomplete", "unknown"), "options")
    caps = {}
    for key, (field, default, maximum) in LIMITS.items():
        value = decimal(values[key]) if key in values else default
        require(0 < value <= maximum, "options")
        caps[field] = value
    return {"selection": {"height": decimal(values["--expect-height"]),
                          "hash": values["--expect-hash"],
                          "provenance_sha256": values["--provenance-sha256"]},
            "limits": caps, "actual_exit": decimal(values["--producer-exit"], signed=True),
            "capture_status": values["--capture-status"],
            "bytes": decimal(values["--capture-bytes"]),
            "sha256": values["--capture-sha256"]}


def read_receipt(reader):
    parts = bytearray()
    while len(parts) <= REPORT_BYTES:
        requested = min(4096, REPORT_BYTES + 1 - len(parts))
        chunk = reader.read(requested)
        require(type(chunk) is bytes and len(chunk) <= requested, "receipt_input")
        if not chunk:
            return bytes(parts)
        parts.extend(chunk)
    raise Refused("receipt_size")


def parse_receipt(raw):
    require(type(raw) is bytes and len(raw) <= REPORT_BYTES, "receipt_size")
    def pairs(items):
        value = {}
        for key, item in items:
            require(key not in value, "receipt_json")
            value[key] = item
        return value

    def number(token):
        require(len(token) <= 20 and re.fullmatch(r"0|[1-9][0-9]*", token, re.ASCII), "receipt_json")
        value = int(token)
        require(unsigned(value), "receipt_json")
        return value

    def noninteger(_):
        raise Refused("receipt_json")

    value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_int=number,
                       parse_float=noninteger, parse_constant=noninteger)
    pending = [(value, 0)]
    nodes = 0
    while pending:
        item, depth = pending.pop()
        nodes += 1
        require(nodes <= 512 and depth <= 5, "receipt_shape")
        if type(item) is dict:
            require(len(item) <= 64, "receipt_shape")
            pending.extend((child, depth + 1) for child in item.values())
        else:
            require(type(item) in (str, int, bool, type(None)), "receipt_shape")
    return value


def scope():
    return {**PRODUCER_SCOPE, "outer_completion_authenticated": False,
            "independent_stream_inventory_executed": False,
            "physical_scan_statistics_independently_verified": False}


def varint_width(value):
    return max(1, (value.bit_length() + 6) // 7)


def match_receipt(raw, selected):
    value = parse_receipt(raw)
    keys = {"format", "status", "put_stream_complete", "source_layout_node_revision",
            "layout", "scope", "iterator_eof_observed", "selection", "limits", "statistics"}
    require(type(value) is dict and set(value) == keys, "receipt_schema")
    require(value["format"] == "zenon-frontier-export/v1" and
            value["status"] == "SELECTED_FRONTIER_EXPORTED" and
            value["put_stream_complete"] is True and value["iterator_eof_observed"] is True,
            "producer_incomplete")
    require(value["layout"] == LAYOUT and value["source_layout_node_revision"] == NODE_REVISION,
            "source_layout")
    authority = value["scope"]
    require(type(authority) is dict and set(authority) == set(PRODUCER_SCOPE) and
            authority["input_role_required"] == "declared-immutable-copy" and
            all(authority[key] is False for key in authority if key != "input_role_required"),
            "producer_scope")
    identity = value["selection"]
    require(type(identity) is dict and set(identity) == set(selected["selection"]) and
            unsigned(identity["height"]) and identity == selected["selection"], "selection_mismatch")
    caps = selected["limits"]
    reported = value["limits"]
    require(type(reported) is dict and set(reported) == set(caps) and
            all(unsigned(number) and number > 0 for number in reported.values()) and
            reported == caps, "limits_mismatch")
    stats = value["statistics"]
    require(type(stats) is dict and set(stats) == STATISTICS and
            all(unsigned(stats[key]) for key in STATISTICS - {"put_stream_sha256"}) and
            hex_digest(stats["put_stream_sha256"]), "statistics")
    records, scanned, tombstones = (stats[key] for key in
                                   ("records", "scanned_records", "physical_tombstones_omitted"))
    wire, scan = stats["put_wire_bytes"], stats["scanned_key_and_encoded_value_bytes"]
    require(1 <= records <= caps["records"] and scanned == records + tombstones and
            scanned <= caps["scan_records"] and stats["present_empty_values"] < records,
            "statistics_counts")
    require(wire == selected["bytes"] and wire <= caps["output_bytes"] and
            stats["put_stream_sha256"] == selected["sha256"] and
            scan <= caps["scan_key_and_encoded_value_bytes"], "capture_mismatch")
    # One nonempty protobuf metadata value must be in the exported view.
    height = selected["selection"]["height"]
    metadata_bytes = 36 + (1 + varint_width(height) if height else 0)
    require(caps["value_bytes"] >= metadata_bytes and
            wire >= metadata_bytes + 4 + 3 * (records - 1) and
            scan >= metadata_bytes + 3 + 2 * (records - 1) + tombstones,
            "statistics_bytes")
    maximum_delta = varint_width(caps["key_bytes"]) + varint_width(caps["value_bytes"]) - 1
    require(records - tombstones * (caps["key_bytes"] + 1) <= wire - scan <=
            1 + (records - 1) * maximum_delta - tombstones and
            scan <= records * (caps["key_bytes"] + caps["value_bytes"] + 2) +
            tombstones * (caps["key_bytes"] + 1), "statistics_bytes")
    return {"format": FORMAT, "status": "SELECTED_EXPORT_COMPLETION_MATCHED", "reason": None,
            "capture_matched": True, "producer_receipt_sha256": hashlib.sha256(raw).hexdigest(),
            "selected_frontier": dict(selected["selection"]),
            "inventory_selection": {"record_space": "effective-raw-ledger", "bytes": wire,
                                    "records": records, "sha256": selected["sha256"],
                                    "provenance_sha256": selected["selection"]["provenance_sha256"]},
            "inventory_limits": {"bytes": caps["output_bytes"], "records": caps["records"],
                                 "key_bytes": caps["key_bytes"], "value_bytes": caps["value_bytes"]},
            "statistics_origin": "producer-reported; output records require independent stream recount",
            "scope": scope()}


def unknown(reason):
    return {"format": FORMAT, "status": "UNKNOWN", "reason": reason,
            "capture_matched": False, "inventory_selection": None, "scope": scope()}


def run(args, reader, output, diagnostics):
    code = 2
    try:
        if type(args) in (list, tuple) and len(args) == 1 and args[0] in ("--help", "-h"):
            diagnostics.write(USAGE)
            result, code = unknown("help_only"), 0
            selected = None
        else:
            selected = options(args)
    except Refused:
        result, code = unknown("options"), 64
    except OSError:
        result, code = unknown("help_output"), 70
    else:
        if selected is None:
            pass
        elif selected["actual_exit"] != 0:
            result = unknown("process_failure")
        elif selected["capture_status"] != "complete":
            result = unknown("capture_incomplete")
        elif selected["bytes"] > selected["limits"]["output_bytes"]:
            result = unknown("capture_limit")
        else:
            try:
                result = match_receipt(read_receipt(reader), selected)
                code = 0
            except Refused as error:
                result = unknown(str(error))
            except (ValueError, TypeError, RecursionError, OverflowError):
                result = unknown("receipt_json")
            except OSError:
                result, code = unknown("receipt_input"), 70
            except KeyboardInterrupt:
                result, code = unknown("cancelled"), 130
    raw = json.dumps(result, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n"
    try:
        if output.write(raw) != len(raw):
            raise OSError("short result write")
        output.flush()
    except OSError:
        try:
            diagnostics.write("consume-completion: result write failed\n")
        except OSError:
            pass
        return 70
    return code


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:], sys.stdin.buffer, sys.stdout, sys.stderr))
