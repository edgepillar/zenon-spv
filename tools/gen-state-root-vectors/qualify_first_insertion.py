#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Observe original point catch-up on an isolated unsigned H2.

Only fresh hosted workspaces are written. Original node sources are verified
against Git blobs before and after execution. The read-only Ledger RPC handler
runs in memory against the test chain. Retain failed command streams.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import shutil
import struct
import sys

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("first_insertion_common", HERE / "qualify_closed_parent_oracle.py")
C = importlib.util.module_from_spec(spec)
spec.loader.exec_module(C)
require, Refused = C.require, C.Refused
ROOT = HERE.parents[1]
INPUT = "tools/gen-state-root-vectors/first-insertion-catchup_test.go.txt"
TYPED_ROWS = "internal/testdata/conformance/batch-context-node-witness.json"
TYPED_ROWS_SHA256 = "773cda402e08709ffd73adfea355f73269b1470b7336c5a027ddd5b331ab9d96"
HARNESS_INPUTS = {
    INPUT: "consensus/spv_first_insertion_catchup_test.go",
    "tools/gen-state-root-vectors/first-insertion-cpu_test.go.txt": "consensus/spv_first_insertion_cpu_test.go",
    "tools/gen-state-root-vectors/first-insertion-export_test.go.txt": "consensus/spv_first_insertion_export_test.go",
}
INPUTS = {**HARNESS_INPUTS, TYPED_ROWS: "consensus/spv_batch_context_node_witness.json"}
WORKFLOW = ".github/workflows/first-insertion-catchup.yml"
PUBLIC_PATHS = (*INPUTS, WORKFLOW, ".gitattributes", "tools/gen-state-root-vectors/qualify_first_insertion.py",
                "tools/gen-state-root-vectors/qualify_first_insertion_test.py",
                "tools/gen-state-root-vectors/qualify_closed_parent_oracle.py",
                "docs/first-insertion-catchup.md")
CASES = {"one-period": 300, "one-day": 86400, "fixture-window": 54815400}
TEST = "TestSPVFirstInsertionCatchup"
PACKAGE = "github.com/zenon-network/go-zenon/consensus"
MARKER = "SPV_FIRST_INSERTION_CATCHUP "
CPU_MARKER = "SPV_FIRST_INSERTION_CPU "
VISIBILITY_MARKER = "SPV_FIRST_INSERTION_VISIBILITY "
RECORDED_H2_MARKER = "SPV_RECORDED_STARTUP_H2 "
RECORDED_BOUNDARY_MARKER = "SPV_RECORDED_STARTUP_BOUNDARY "
RECORDED_PROOFS_MARKER = "SPV_RECORDED_STARTUP_PROOFS "
UNSIGNED_H3_MARKER = "SPV_UNSIGNED_H3_LEDGER "
H3_HISTORY_MARKER = "SPV_H3_HISTORY_AT_H4 "
TYPED_HISTORY_MARKER = "SPV_TYPED_HISTORY "
RECORDED_H2 = {
    "format": "recorded-chain69-h2/v1",
    "recorded_run": 43653383092,
    "recorded_artifact_id": 14136634774,
    "rpc_sha256": "931a991acef939bd4d9c0f55e293c64402189940b406b612a0e8bed9668acbc4",
    "height": 2,
    "version": 1,
    "hash": "6203eed405db9b47b93628ed4178740150d35dbb3353bcee75fd622133c9798e",
    "parent_hash": "fab7609bae7fd78eb7d2b0d4a5023832f1a6730921b862f2415da25524698dc9",
    "timestamp": 1794699050,
    "signature_verified": True,
    "source_parent_slot_match": True,
    "source_frontier_unchanged": True,
    "accepted_header_authority": False,
}
RECORDED_BOUNDARY = {
    "format": "recorded-chain69-h2-boundary/v1",
    "parent_height": RECORDED_H2["height"],
    "parent_hash": RECORDED_H2["hash"],
    "source_vm_empty_patch": True,
    "reopened_parent": True,
    "state_root_active_at_h1": False,
    "state_root_active_at_h2": True,
    "unsigned_height": 3,
    "unsigned_version": 3,
    "rejected_versions": [1, 2],
    "unsigned_header_committed": False,
    "accepted_header_authority": False,
}
SETTLEMENT_STORAGE_PREFIX = "0301b3b6e5adcb4d0cad7fcef33598c6318c6318c004"
RECORDED_PROOF_KEYS = {
    "batch_entry": SETTLEMENT_STORAGE_PREFIX + "02000000010000000000000000",
    "domain_record": SETTLEMENT_STORAGE_PREFIX + "0100000001",
    "domain_config": SETTLEMENT_STORAGE_PREFIX + "1500000001",
}
MAX_ABSENCE_PROOF = 99 + 256 * 32
CPU_LIMITS = {"reference": "max 100000", "half-core": "50000 100000"}
# Resources from the reference-gas contract used by the historical signed run.
FIXTURE_CONTRACT = "6f67a35cf6db1e2fd91a529880b9fa555461a4687ed0a76d9a27c900ca6b6f31"
FIXTURE_MEMORY_BYTES = 768 << 20
FIXTURE_READINESS_SECONDS = 90
FALSE_FIELDS = frozenset(("Chain_Start", "consensus_Start", "wallet_or_signing", "network_or_broadcast",
    "actual_fixture_cause_established", "accepted_header_authority", "new_devnet_acceptance_established",
    "peak_disk_or_RSS_measured"))
TRUE_FIELDS = frozenset(("original_points_listener_completed", "real_LevelDB_managers",
                        "owned_databases_closed", "unsigned_test_fixture_bypasses_authentication"))
INTEGER_FIELDS = frozenset(("source_genesis_unix", "unsigned_H2_unix", "gap_seconds", "period_seconds",
    "completed_periods", "completed_epochs", "consensus_get_calls", "consensus_put_calls",
    "consensus_put_value_bytes", "closed_consensus_files", "closed_consensus_logical_bytes"))


def decode(raw):
    def pairs(values):
        result = {}
        for key, value in values:
            require(key not in result, "duplicate_JSON_field")
            result[key] = value
        return result

    def constant(_):
        raise Refused("nonfinite_JSON_number")

    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    except (ValueError, UnicodeError) as error:
        raise Refused("invalid_JSON") from error


def selected_trace(text, marker):
    require(text.endswith("\n") and text.count(marker) == 1, "native_trace_count")
    line, = [line for line in text.splitlines() if marker in line]
    return decode(line.split(marker, 1)[1].strip())


def cpu_observation(text, profile):
    row = selected_trace(text, CPU_MARKER)
    require(type(row) is dict and set(row) == {"format", "profile", "cpu_max", "memory_max_bytes",
             "memory_swap_max_bytes", "gomaxprocs", "listener_cpu_delta"}, "cpu_trace_fields")
    require(row["format"] == "first-insertion-cpu-observation/v1" and row["profile"] == profile
            and row["cpu_max"] == CPU_LIMITS[profile], "cpu_trace_limit")
    for name, expected in (("memory_max_bytes", FIXTURE_MEMORY_BYTES), ("memory_swap_max_bytes", 0),
                           ("gomaxprocs", 1)):
        require(type(row[name]) is int and row[name] == expected, "cpu_trace_environment")
    delta = row["listener_cpu_delta"]
    require(type(delta) is dict and set(delta) == {"usage_usec", "nr_periods", "nr_throttled", "throttled_usec"}
            and all(type(v) is int and 0 <= v < 1 << 40 for v in delta.values())
            and delta["usage_usec"] > 0, "cpu_trace_delta")
    return row


def insertion_visibility(text, *, require_first_period_read=False, require_frontier_rpc=False):
    row = selected_trace(text, VISIBILITY_MARKER)
    require(type(row) is dict, "frontier_visibility_fields")
    edition = row.get("format")
    rpc = edition == "first-insertion-frontier-visibility/v3"
    period_read = rpc or edition == "first-insertion-frontier-visibility/v2"
    fields = {
        "format", "before_height", "during_height", "callback_held_during_read",
        "insert_returned_after_release", "accepted_header_authority",
    }
    if period_read:
        fields.add("first_period_read_held")
    if rpc:
        fields.update(("rpc_method", "rpc_transport"))
    require(set(row) == fields, "frontier_visibility_fields")
    require((period_read or edition == "first-insertion-frontier-visibility/v1")
            and (not require_first_period_read or period_read)
            and (not require_frontier_rpc or rpc)
            and (not period_read or row["first_period_read_held"] is True)
            and (not rpc or (row["rpc_method"], row["rpc_transport"]) == ("ledger.getFrontierMomentum", "in-memory-http"))
            and type(row["before_height"]) is int and row["before_height"] == 1
            and type(row["during_height"]) is int and row["during_height"] == 2
            and row["callback_held_during_read"] is True and row["insert_returned_after_release"] is True
            and row["accepted_header_authority"] is False, "frontier_visibility_observation")
    return row


def recorded_startup_proofs(text, boundary):
    row = selected_trace(text, RECORDED_PROOFS_MARKER)
    require(boundary is not None and type(row) is dict
            and set(row) == {"format", "height", "hash", "local_tree_root", "header_state_root",
                             "root_rpc_refused", "witnesses", "accepted_header_authority"}
            and row["format"] == "recorded-chain69-h2-settlement-proofs/v1"
            and type(row["height"]) is int and row["height"] == RECORDED_H2["height"]
            and row["hash"] == RECORDED_H2["hash"]
            and row["local_tree_root"] == boundary["unsigned_empty_patch_root"]
            and row["header_state_root"] == "0" * 64 and row["root_rpc_refused"] is True
            and row["accepted_header_authority"] is False, "recorded_proofs_scope")
    witnesses = row["witnesses"]
    require(type(witnesses) is dict and set(witnesses) == RECORDED_PROOF_KEYS.keys(), "recorded_proofs_roster")
    for name, key in RECORDED_PROOF_KEYS.items():
        witness = witnesses[name]
        require(type(witness) is dict and set(witness) == {"key", "proof", "value", "proof_rpc_refused"}
                and witness["key"] == key and witness["value"] is None
                and witness["proof_rpc_refused"] is True, "recorded_proof_scope")
        encoded = witness["proof"]
        require(type(encoded) is str and len(encoded) <= ((MAX_ABSENCE_PROOF + 2) // 3) * 4,
                "recorded_proof_bound")
        try:
            raw = base64.b64decode(encoded, validate=True)
        except ValueError as error:
            raise Refused("recorded_proof_encoding") from error
        require(99 <= len(raw) <= MAX_ABSENCE_PROOF
                and base64.b64encode(raw).decode("ascii") == encoded
                and raw[0] == 0 and raw[1:33] == hashlib.sha3_256(bytes.fromhex(key)).digest(),
                "recorded_proof_encoding")
    return row


def unsigned_v3_hash(height, parent, timestamp, root, changes):
    empty = hashlib.sha3_256(b"").digest()
    preimage = (struct.pack(">QQ", 3, 69) + bytes.fromhex(parent)
                + struct.pack(">QQ", height, timestamp) + empty * 2 + changes
                + struct.pack(">QQ", 1000, 1000) + bytes.fromhex(root))
    return hashlib.sha3_256(preimage).hexdigest()


def unsigned_h3_ledger(text, proofs):
    row = selected_trace(text, UNSIGNED_H3_MARKER)
    expected = {
        "format": "chain69-unsigned-h3-absence-rpc/v1",
        "height": 3, "version": 3, "parent_hash": RECORDED_H2["hash"],
        "timestamp": RECORDED_H2["timestamp"] + 10,
        "reopened_fixture": True, "unsigned_vm_refused": True,
        "h2_remains_refused": True, "accepted_header_authority": False,
    }
    require(proofs is not None and type(row) is dict
            and set(row) == expected.keys() | {"hash", "header_state_root", "ledger_root", "proof_pins"}
            and all(type(row[key]) is type(value) and row[key] == value for key, value in expected.items())
            and row["header_state_root"] == row["ledger_root"] == proofs["local_tree_root"], "unsigned_h3_scope")
    # Independently assemble the unsigned fixture hash. Its data, content and
    # LevelDB change batch are all empty; the original minimum prices are 1000.
    require(row["hash"] == unsigned_v3_hash(3, expected["parent_hash"], expected["timestamp"],
            row["ledger_root"], hashlib.sha3_256(b"").digest()), "unsigned_h3_hash")
    pins = row["proof_pins"]
    require(type(pins) is dict and set(pins) == RECORDED_PROOF_KEYS.keys(), "unsigned_h3_roster")
    for name, witness in proofs["witnesses"].items():
        raw = base64.b64decode(witness["proof"], validate=True)
        pin = pins[name]
        require(type(pin) is dict and pin == C.digest(raw) and type(pin["bytes"]) is int,
                "unsigned_h3_proof_pin")
    return row


def h3_history_at_h4(text, h3):
    row = selected_trace(text, H3_HISTORY_MARKER)
    require(h3 is not None, "h3_history_requires_h3")
    expected = {
        "format": "chain69-h3-history-at-h4-fixture/v1",
        "height": h3["height"], "hash": h3["hash"], "state_root": h3["ledger_root"],
        "tip_height": h3["height"] + 1, "tip_parent_hash": h3["hash"],
        "tip_timestamp": h3["timestamp"] + 10,
        "checked_at_tip_before_and_after_reopen": True,
        "marker_absent_at_h3_and_present_at_h4": True, "accepted_header_authority": False,
    }
    require(type(row) is dict
            and set(row) == expected.keys() | {"tip_hash", "tip_state_root", "tip_changes_hash", "proof_pins"}
            and all(type(row[key]) is type(value) and row[key] == value for key, value in expected.items()),
            "h3_history_scope")
    root = row["tip_state_root"]
    require(type(root) is str and re.fullmatch("[0-9a-f]{64}", root) is not None
            and root not in ("0" * 64, h3["ledger_root"]), "h3_history_tip_root")
    marker_key = bytes.fromhex(SETTLEMENT_STORAGE_PREFIX + "ff")
    marker_value = b"spv-historical-proof-tip"
    # The original LevelDB batch contains one put record. Both lengths fit
    # into a single unsigned varint byte.
    changes = hashlib.sha3_256(bytes((1, len(marker_key))) + marker_key
                              + bytes((len(marker_value),)) + marker_value).digest()
    require(row["tip_changes_hash"] == changes.hex(), "h3_history_changes")
    require(row["tip_hash"] == unsigned_v3_hash(expected["tip_height"], h3["hash"],
            expected["tip_timestamp"], root, changes), "h3_history_tip_hash")
    pins = row["proof_pins"]
    require(type(pins) is dict and pins == h3["proof_pins"]
            and all(type(pin["bytes"]) is int for pin in pins.values()), "h3_history_proof_pins")
    return row


def typed_history_values():
    raw = C.regular(ROOT / TYPED_ROWS, 32 << 10)
    require(hashlib.sha256(raw).hexdigest() == TYPED_ROWS_SHA256, "typed_history_input")
    rows = decode(raw)["rows"]
    values = {row["name"]: bytes.fromhex(row["value_hex"]) for row in rows[:3]}
    require(list(values) == list(RECORDED_PROOF_KEYS)
            and all(row["ledger_key_hex"] == RECORDED_PROOF_KEYS[row["name"]] for row in rows[:3])
            and all(0 < len(value) <= 4096 for value in values.values()), "typed_history_input_rows")
    return values


def batch_varint(size):
    raw = bytearray()
    while size >= 128:
        raw.append((size & 0x7f) | 0x80)
        size >>= 7
    raw.append(size)
    return bytes(raw)


def typed_history_header(row, parent, patch):
    require(type(row) is dict and set(row) == {
        "height", "hash", "parent_hash", "timestamp", "state_root", "changes_hash"}, "typed_history_header_fields")
    digest = hashlib.sha3_256(patch).digest()
    require(type(row["height"]) is int and row["height"] == parent["height"] + 1
            and type(row["timestamp"]) is int and row["timestamp"] == parent["timestamp"] + 10
            and row["parent_hash"] == parent["hash"] and row["changes_hash"] == digest.hex(),
            "typed_history_header_link_or_changes")
    root = row["state_root"]
    require(type(root) is str and re.fullmatch("[0-9a-f]{64}", root) is not None
            and root not in ("0" * 64, parent["state_root"]), "typed_history_root")
    require(row["hash"] == unsigned_v3_hash(row["height"], row["parent_hash"], row["timestamp"], root, digest),
            "typed_history_header_hash")
    return bytes.fromhex(root)


def typed_history_proof(root, key, encoded, value):
    """Recompute a canonical NodeTree proof from the selected raw key and value."""
    max_bytes = MAX_ABSENCE_PROOF + (4 + len(value) if value is not None else 0)
    require(type(encoded) is str and len(encoded) <= ((max_bytes + 2) // 3) * 4, "typed_history_proof_bound")
    try:
        raw = base64.b64decode(encoded, validate=True)
    except ValueError as error:
        raise Refused("typed_history_proof_encoding") from error
    require(99 <= len(raw) <= max_bytes and base64.b64encode(raw).decode("ascii") == encoded,
            "typed_history_proof_encoding")
    path, empty = hashlib.sha3_256(key).digest(), bytes(32)
    present = value is not None
    leaf = hashlib.sha3_256(path + value).digest() if present else empty
    require(raw[0] == int(present) and raw[1:33] == path and raw[33:65] == leaf,
            "typed_history_proof_path_or_leaf")
    levels = [level for level in range(256) if raw[65 + level // 8] & (128 >> (level % 8))]
    cursor = 99 + 32 * len(levels)
    expected_tail = struct.pack(">I", len(value)) + value if present else b""
    require(int.from_bytes(raw[97:99], "big") == len(levels) and len(raw) == cursor + len(expected_tail)
            and raw[cursor:] == expected_tail, "typed_history_proof_framing")
    siblings = {level: raw[99 + index * 32:131 + index * 32] for index, level in enumerate(levels)}
    require(empty not in siblings.values(), "typed_history_proof_zero_sibling")
    bits = int.from_bytes(path, "big")
    current = leaf
    for level in range(256):
        sibling = siblings.get(level, empty)
        if current != empty or sibling != empty:
            pair = sibling + current if bits & (1 << level) else current + sibling
            current = hashlib.sha3_256(pair).digest()
    require(current == root, "typed_history_proof_root")
    return C.digest(raw)


def typed_history(text, h4):
    row = selected_trace(text, TYPED_HISTORY_MARKER)
    require(h4 is not None, "typed_history_requires_h4")
    require(type(row) is dict and set(row) == {"format", "target", "tip", "memberships", "tip_batch_absence",
                                            "checked_at_tip_before_and_after_reopen", "accepted_header_authority"}
            and row["format"] == "chain69-typed-rows-after-reopen/v1"
            and row["checked_at_tip_before_and_after_reopen"] is True
            and row["accepted_header_authority"] is False, "typed_history_scope")
    values = typed_history_values()
    keys = {name: bytes.fromhex(key) for name, key in RECORDED_PROOF_KEYS.items()}
    # LevelDB batch payload encodes a one-byte put/delete kind, unsigned
    # varint lengths and the original key/value bytes in patch order.
    puts = b"".join(b"\x01" + batch_varint(len(keys[name])) + keys[name]
                    + batch_varint(len(value)) + value for name, value in values.items())
    batch_key = keys["batch_entry"]
    deletion = b"\x00" + batch_varint(len(batch_key)) + batch_key
    parent = {key: h4["tip_" + key] for key in ("height", "hash", "timestamp", "state_root")}
    target_root = typed_history_header(row["target"], parent, puts)
    tip_root = typed_history_header(row["tip"], row["target"], deletion)
    proofs = row["memberships"]
    require(type(proofs) is dict and proofs.keys() == keys.keys(), "typed_history_proof_roster")
    pins = {name: typed_history_proof(target_root, keys[name], proofs[name], value)
            for name, value in values.items()}
    absence = typed_history_proof(tip_root, batch_key, row["tip_batch_absence"], None)
    return {"format": row["format"], "target": row["target"], "tip": row["tip"],
            "membership_pins": pins, "tip_batch_absence_pin": absence, "value_source_sha256": TYPED_ROWS_SHA256,
            "checked_at_tip_before_and_after_reopen": True, "accepted_header_authority": False}


def native_controls(raw, cpu_profile=None, *, require_first_period_read=False, require_frontier_rpc=False,
                    require_recorded_h2=False, require_recorded_boundary=False, require_recorded_proofs=False,
                    require_unsigned_h3=False, require_h3_history=False, require_typed_history=False):
    require(cpu_profile is None or cpu_profile in CPU_LIMITS, "cpu_profile_selection")
    cases = {"fixture-window": CASES["fixture-window"]} if cpu_profile == "half-core" else CASES
    require(type(raw) is bytes and 0 < len(raw) <= C.MAX_STREAM and raw.endswith(b"\n"), "native_stream")
    lines = raw.splitlines()
    require(len(lines) <= 4096, "native_event_bound")
    expected = {TEST, *(TEST + "/" + name for name in cases)}
    started, passed, outputs = set(), set(), {}
    package_started = package_passed = False
    for line in lines:
        require(not package_passed, "native_after_package_pass")
        event = decode(line)
        require(type(event) is dict, "native_package")
        action = event.get("Action")
        if action == "build-output":
            # Go test can interleave compiler diagnostics and test events.
            # The Linux test2json lane runs an already compiled binary.
            require(cpu_profile is None and set(event) == {"Action", "ImportPath", "Output"}
                    and type(event["ImportPath"]) is str and bool(event["ImportPath"])
                    and type(event["Output"]) is str and bool(event["Output"]), "native_build_output")
            continue
        require(event.get("Package") == PACKAGE, "native_package")
        name = event.get("Test")
        require(action in ("start", "run", "output", "pass"), "native_outcome")
        if name is not None:
            require(type(name) is str and name in expected and package_started, "native_selection")
            if action == "run":
                require(name not in started and (name == TEST or TEST in started), "native_run_order")
                started.add(name)
            else:
                require(name in started and name not in passed, "native_test_order")
            if action == "pass":
                passed.add(name)
        elif action == "start":
            require(not package_started and not started, "native_package_start")
            package_started = True
        elif action == "pass":
            require(package_started and started == passed == expected, "native_package_completion")
            package_passed = True
        else:
            require(action == "output" and package_started, "native_package_event")
        output = event.get("Output", "")
        require(type(output) is str and (not output or action == "output"), "native_output_action")
        outputs[name] = outputs.get(name, "") + output
        require(len(outputs[name].encode("utf-8")) <= 128 << 10, "native_output_bound")
    require(package_passed and started == passed == expected, "native_completion")
    require(all(MARKER not in text for name, text in outputs.items()
                if name not in {TEST + "/" + case for case in cases}), "foreign_trace")
    visibility_test = TEST + "/one-period" if "one-period" in cases else None
    require(all(VISIBILITY_MARKER not in text for name, text in outputs.items()
                if visibility_test is None or name != visibility_test), "foreign_visibility_trace")
    require(all(RECORDED_H2_MARKER not in text for name, text in outputs.items()
                if visibility_test is None or name != visibility_test), "foreign_recorded_h2_trace")
    require(all(RECORDED_BOUNDARY_MARKER not in text for name, text in outputs.items()
                if visibility_test is None or name != visibility_test), "foreign_recorded_boundary_trace")
    require(all(RECORDED_PROOFS_MARKER not in text for name, text in outputs.items()
                if visibility_test is None or name != visibility_test), "foreign_recorded_proofs_trace")
    require(all(UNSIGNED_H3_MARKER not in text for name, text in outputs.items()
                if visibility_test is None or name != visibility_test), "foreign_unsigned_h3_trace")
    require(all(H3_HISTORY_MARKER not in text for name, text in outputs.items()
                if visibility_test is None or name != visibility_test), "foreign_h3_history_trace")
    require(all(TYPED_HISTORY_MARKER not in text for name, text in outputs.items()
                if visibility_test is None or name != visibility_test), "foreign_typed_history_trace")
    cpu_test = TEST + "/fixture-window" if cpu_profile else None
    require(all(CPU_MARKER not in text for name, text in outputs.items()
                if cpu_test is None or name != cpu_test), "foreign_cpu_trace")
    observations = {}
    for case, gap in cases.items():
        text = outputs.get(TEST + "/" + case, "")
        trace = selected_trace(text, MARKER)
        fields = (FALSE_FIELDS | TRUE_FIELDS | INTEGER_FIELDS |
                  {"format", "case", "node_revision", "source_genesis_sha256",
                   "unsigned_insert_seconds", "points_listener_seconds"})
        require(type(trace) is dict and set(trace) == fields, "native_trace_fields")
        require(trace["format"] == "selected-first-insertion-catchup/v1" and trace["case"] == case
                and trace["node_revision"] == C.NODE_REVISION
                and trace["source_genesis_sha256"] == C.GENESIS_SHA256, "native_trace_source")
        require(all(trace[k] is False for k in FALSE_FIELDS) and all(trace[k] is True for k in TRUE_FIELDS),
                "native_trace_scope")
        require(all(type(trace[k]) is int and 0 <= trace[k] < 1 << 40 for k in INTEGER_FIELDS), "native_trace_integers")
        require(trace["source_genesis_unix"] == 1739923200 and trace["unsigned_H2_unix"] == 1739923200 + gap
                and trace["gap_seconds"] == gap and trace["period_seconds"] == 300
                and trace["completed_periods"] == gap // 300 and trace["completed_epochs"] == gap // 86400,
                "native_trace_history")
        require(0 < trace["closed_consensus_files"] <= 4096
                and trace["closed_consensus_logical_bytes"] <= 256 << 20
                and trace["consensus_put_calls"] >= trace["completed_periods"] + trace["completed_epochs"],
                "native_trace_measurement")
        for key in ("unsigned_insert_seconds", "points_listener_seconds"):
            require(type(trace[key]) in (float, int) and math.isfinite(trace[key]) and 0 <= trace[key] <= 180,
                    "native_trace_duration")
        observations[case] = trace
    result = {"root_tests": 1, "subtests": len(cases), "failed": 0, "skipped": 0,
            "observations": observations, "actual_fixture_cause_established": False,
            "new_devnet_acceptance_established": False}
    if visibility_test:
        result["frontier_visibility"] = insertion_visibility(outputs.get(visibility_test, ""),
                                                              require_first_period_read=require_first_period_read,
                                                              require_frontier_rpc=require_frontier_rpc)
    recorded_text = outputs.get(visibility_test, "")
    if require_recorded_h2 or RECORDED_H2_MARKER in recorded_text:
        row = selected_trace(recorded_text, RECORDED_H2_MARKER)
        require(type(row) is dict and row == RECORDED_H2
                and all(type(row[key]) is type(expected) for key, expected in RECORDED_H2.items()),
                "recorded_h2_observation")
        result["recorded_h2"] = row
    if require_recorded_boundary or RECORDED_BOUNDARY_MARKER in recorded_text:
        row = selected_trace(recorded_text, RECORDED_BOUNDARY_MARKER)
        require("recorded_h2" in result and type(row) is dict
                and set(row) == RECORDED_BOUNDARY.keys() | {"unsigned_empty_patch_root"}
                and all(type(row[key]) is type(expected) and row[key] == expected
                        for key, expected in RECORDED_BOUNDARY.items())
                and all(type(version) is int for version in row["rejected_versions"]), "recorded_boundary_observation")
        root = row["unsigned_empty_patch_root"]
        require(type(root) is str and re.fullmatch("[0-9a-f]{64}", root) is not None
                and root != "0" * 64, "recorded_boundary_root")
        result["recorded_boundary"] = row
    if require_recorded_proofs or RECORDED_PROOFS_MARKER in recorded_text:
        result["recorded_proofs"] = recorded_startup_proofs(recorded_text, result.get("recorded_boundary"))
    if require_unsigned_h3 or UNSIGNED_H3_MARKER in recorded_text:
        result["unsigned_h3_ledger"] = unsigned_h3_ledger(recorded_text, result.get("recorded_proofs"))
    if require_h3_history or H3_HISTORY_MARKER in recorded_text:
        result["h3_history_at_h4"] = h3_history_at_h4(recorded_text, result.get("unsigned_h3_ledger"))
    if require_typed_history or TYPED_HISTORY_MARKER in recorded_text:
        result["typed_history"] = typed_history(recorded_text, result.get("h3_history_at_h4"))
    if cpu_profile:
        result["cpu"] = cpu_observation(outputs.get(cpu_test, ""), cpu_profile)
    return result


def compare_cpu_controls(reference, constrained, binary_pin):
    a = reference["observations"]["fixture-window"]
    b = constrained["observations"]["fixture-window"]
    workload = ("completed_periods", "completed_epochs", "consensus_get_calls",
                "consensus_put_calls", "consensus_put_value_bytes")
    require(all(a[key] == b[key] for key in workload), "cpu_comparison_workload")
    return {"format": "first-insertion-cpu-comparison/v1", "test_binary": binary_pin,
            "historical_fixture_contract_sha256": FIXTURE_CONTRACT,
            "historical_readiness_seconds": FIXTURE_READINESS_SECONDS,
            "reference_listener_seconds": a["points_listener_seconds"],
            "half_core_listener_seconds": b["points_listener_seconds"],
            "half_core_listener_reached_readiness_duration": b["points_listener_seconds"] >= FIXTURE_READINESS_SECONDS,
            "same_measured_workload": {key: a[key] for key in workload},
            "half_core_controls": constrained, "actual_fixture_cause_established": False}


def linux_cpu_controls(work, node, output, selected, records):
    require(sys.platform == "linux" and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
            and os.getuid() != 0 and os.getgid() != 0, "hosted_linux_cpu_scope")
    binary = work / "consensus-catchup.test"
    require(not binary.exists() and not binary.is_symlink(), "fresh_test_binary")
    C.command(output, "compile-native-test", ["go", "test", *C.NATIVE_FLAGS, "-c", "-o", str(binary),
              "./consensus"], node, records, timeout=480)
    initial = C.digest(C.regular(binary, C.MAX_BINARY))
    require(initial["bytes"] > 0, "compiled_test_binary")
    binary.chmod(0o500)

    def run(profile, label, pattern):
        scratch = work / (profile + "-db")
        scratch.mkdir(mode=0o700)
        unit = f"spv-catchup-{selected['run_id']}-{selected['run_attempt']}-{profile}.service"
        args = ["go", "tool", "test2json", "-t", "-p", PACKAGE, "sudo", "-n", "--", "/usr/bin/systemd-run",
                "--quiet", "--wait", "--pipe", "--collect", "--service-type=exec", "--expand-environment=no",
                "--unit=" + unit, "--slice=system.slice", f"--uid={os.getuid()}", f"--gid={os.getgid()}",
                "--working-directory=" + str(node / "consensus"), "--setenv=GOMAXPROCS=1",
                "--setenv=SPV_CATCHUP_CPU_PROFILE=" + profile, "--setenv=SPV_CATCHUP_CPU_UNIT=" + unit,
                "--setenv=TMPDIR=" + str(scratch),
                "--property=PrivateNetwork=yes", "--property=NoNewPrivileges=yes",
                "--property=ProtectSystem=strict", "--property=ReadWritePaths=" + str(scratch),
                "--property=RuntimeMaxSec=190s", "--property=TimeoutStopSec=5s",
                "--property=CPUWeight=100", "--property=CPUQuotaPeriodSec=100ms",
                f"--property=MemoryMax={FIXTURE_MEMORY_BYTES}", "--property=MemorySwapMax=0"]
        if profile == "half-core":
            args.append("--property=CPUQuota=50%")
        args.extend(("--", str(binary), "-test.v=test2json", "-test.count=1", "-test.timeout=180s",
                     "-test.run", pattern))
        raw = C.command(output, label, args, work, records, timeout=215)
        require(C.digest(C.regular(binary, C.MAX_BINARY)) == initial and not any(scratch.iterdir()),
                "cpu_sample_binary_or_scratch")
        return native_controls(raw, profile, require_frontier_rpc=True,
                               require_recorded_proofs=profile == "reference",
                               require_unsigned_h3=profile == "reference",
                               require_h3_history=profile == "reference", require_typed_history=profile == "reference")

    reference = run("reference", "native-test", "^" + TEST + "$")
    constrained = run("half-core", "half-core-test", "^" + TEST + "$/^fixture-window$")
    return reference, compare_cpu_controls(reference, constrained, initial)


def context(platform):
    selected = C.context(platform)
    selected["workflow"] = "first-insertion-catchup"
    return selected


def space(path):
    free = shutil.disk_usage(path).free
    require(free >= 14 * C.GIB, "free_space_floor")
    return {"free_bytes": free, "floor_bytes": 10 * C.GIB,
            "expected_allocation_bytes": 3 * C.GIB, "safety_margin_bytes": C.GIB,
            "OS_disk_quota_or_peak_measurement": False}


def owned_scope(work, output, selected):
    if selected is None:
        return False
    try:
        marker = decode(C.regular(work / "scope.json", 4096))
        return (marker["format"] == "owned-first-insertion-scope/v1" and marker["context"] == selected
                and not work.is_symlink() and not output.is_symlink()
                and marker["work_identity"] == [work.stat().st_dev, work.stat().st_ino]
                and marker["output_identity"] == [output.stat().st_dev, output.stat().st_ino])
    except (Refused, OSError, KeyError, TypeError):
        return False


def stage(work, output, selected, records):
    require(not work.exists() and not work.is_symlink() and not output.exists() and not output.is_symlink(),
            "fresh_workspace_required")
    require(work.parent.is_dir() and output.parent.is_dir() and work != output
            and work not in output.parents and output not in work.parents, "workspace_separation")
    inputs = {name: C.regular(ROOT / name, C.MAX_SOURCE_FILE) for name in INPUTS}
    allocation = space(work.parent)
    work.mkdir(mode=0o700)
    output.mkdir(mode=0o700)
    C.seal(work / "scope.json", C.encoded({"format": "owned-first-insertion-scope/v1", "context": selected,
        "work_identity": [work.stat().st_dev, work.stat().st_ino],
        "output_identity": [output.stat().st_dev, output.stat().st_ino]}))
    node = work / "node"
    C.git(output, "node-init", ["init", "--quiet", str(node)], work, records)
    C.git(output, "node-line-endings", ["config", "--local", "core.autocrlf", "false"], node, records)
    C.git(output, "node-fetch", ["fetch", "--quiet", "--depth=1", "--no-tags", C.NODE_REPOSITORY, C.NODE_REVISION], node, records)
    C.git(output, "node-checkout", ["checkout", "--quiet", "--detach", "FETCH_HEAD"], node, records)
    head = C.git(output, "node-head", ["rev-parse", "HEAD"], node, records).decode().strip()
    tree = C.git(output, "node-tree", ["rev-parse", "HEAD^{tree}"], node, records).decode().strip()
    require((head, tree) == (C.NODE_REVISION, C.NODE_TREE), "node_source_pin")
    require(C.git(output, "node-clean", ["status", "--porcelain=v1"], node, records) == b"", "original_source_dirty")
    index = C.git(output, "node-index", ["ls-files", "--stage", "-z"], node, records)
    original = C.source_inventory(node, index)
    require(original["docker/devnet/genesis.json"] == {"bytes": 8137, "sha256": C.GENESIS_SHA256}, "source_genesis")
    for name, target in INPUTS.items():
        require(not (node / target).exists() and not (node / target).is_symlink(), "added_path_exists")
        C.seal(node / target, inputs[name])
    C.seal(work / "ownership.json", C.encoded({"format": "owned-first-insertion-work/v1", "context": selected,
        "node_identity": [node.stat().st_dev, node.stat().st_ino], "original_sources": original,
        "added_inputs": {name: C.digest(raw) for name, raw in inputs.items()}}))
    C.seal(output / "preparation.json", C.encoded({"format": "first-insertion-preparation/v1", "context": selected,
        "node_revision": head, "node_tree": tree, "original_sources": original,
        "added_inputs": {name: C.digest(raw) for name, raw in inputs.items()},
        "allocation_admission": allocation, "commands": records, "native_execution": False}))


def qualify(work, output, selected, records):
    require(owned_scope(work, output, selected), "owned_stage_scope")
    marker = decode(C.regular(work / "ownership.json", 256 << 10))
    node = work / "node"
    require(marker["format"] == "owned-first-insertion-work/v1" and marker["context"] == selected
            and not node.is_symlink() and marker["node_identity"] == [node.stat().st_dev, node.stat().st_ino],
            "owned_node_identity")
    index = C.git(output, "qualified-node-index", ["ls-files", "--stage", "-z"], node, records)

    def unchanged():
        require(C.source_inventory(node, index) == marker["original_sources"]
                and set(marker["added_inputs"]) == set(INPUTS), "source_drift")
        for name, target in INPUTS.items():
            raw = C.regular(node / target, C.MAX_SOURCE_FILE)
            require(raw == C.regular(ROOT / name, C.MAX_SOURCE_FILE)
                    and C.digest(raw) == marker["added_inputs"][name], "added_source_drift")

    unchanged()
    allocation = space(work)
    go = decode(C.command(output, "go-environment", ["go", "env", "-json", "GOOS", "GOARCH", "GOVERSION", "CGO_ENABLED", "CC"], node, records))
    C.require_toolchain(go, selected["platform"])
    comparison = None
    if selected["platform"] == "linux-amd64":
        controls, comparison = linux_cpu_controls(work, node, output, selected, records)
    else:
        raw = C.command(output, "native-test", ["go", "test", *C.NATIVE_FLAGS, "-json", "-count=1", "-timeout=180s",
                        "-run", "^" + TEST + "$", "./consensus"], node, records, timeout=600)
        controls = native_controls(raw, require_frontier_rpc=True, require_recorded_proofs=True,
                                   require_unsigned_h3=True, require_h3_history=True, require_typed_history=True)
    unchanged()
    require(C.git(output, "node-head-after", ["rev-parse", "HEAD"], node, records).decode().strip() == C.NODE_REVISION
            and C.git(output, "node-tree-after", ["rev-parse", "HEAD^{tree}"], node, records).decode().strip() == C.NODE_TREE,
            "node_revision_after")
    C.git(output, "node-index-after", ["diff", "--cached", "--exit-code", "HEAD"], node, records)
    status = C.git(output, "node-working-after", ["status", "--porcelain=v1", "-z", "--untracked-files=all"], node, records)
    require(status.endswith(b"\0") and sorted(status.split(b"\0")[:-1])
            == sorted(b"?? " + target.encode() for target in INPUTS.values()), "unexpected_working_change")
    require(C.git(output, "spv-source-head", ["rev-parse", "HEAD"], ROOT, records).decode().strip()
            == selected["source_revision"], "SPV_source_revision")
    tree = C.git(output, "spv-source-tree", ["rev-parse", "HEAD^{tree}"], ROOT, records).decode().strip()
    C.git(output, "spv-index-clean", ["diff", "--cached", "--exit-code", "HEAD"], ROOT, records)
    selected_index = C.git(output, "spv-selected-index", ["ls-files", "--stage", "-z", "--", *PUBLIC_PATHS], ROOT, records)
    sources, working = C.selected_sources(selected_index, PUBLIC_PATHS)
    for name in HARNESS_INPUTS:
        C.seal(output / Path(name).name, C.regular(ROOT / name, C.MAX_SOURCE_FILE))
    C.seal(output / "NODE_LICENSE", C.regular(node / "LICENSE", 64 << 10))
    result = {"format": "first-insertion-catchup-ci/v1", "status": "UNSIGNED_BOOKKEEPING_CONTROLS_PASSED",
        **selected, "source_tree": tree, "node_revision": C.NODE_REVISION, "node_tree": C.NODE_TREE,
        "source_files": sources, "working_sources": working, "original_node_sources_unchanged": True,
        "node_original_files": len(marker["original_sources"]), "go": go, "native_controls": controls,
        "linux_cpu_comparison": comparison,
        "allocation_admission": allocation, "commands": records,
        "scope": {"unsigned_test_fixture_bypasses_authentication": True, "actual_fixture_cause_established": False,
                  "new_devnet_acceptance_established": False, "authenticated_distribution": False,
                  "production_qualified": False}}
    C.seal(output / "manifest.json", C.encoded(result))
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("prepare", "qualify"), required=True)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--platform", choices=("linux-amd64", "darwin-amd64", "windows-amd64"), required=True)
    args = parser.parse_args(argv)
    records, selected = [], None
    try:
        selected = context(args.platform)
        if args.mode == "prepare":
            stage(args.workspace, args.evidence, selected, records)
        else:
            qualify(args.workspace, args.evidence, selected, records)
        print(json.dumps({"format": "first-insertion-stage-complete/v1", "mode": args.mode,
                          "context": selected, "new_devnet_acceptance_established": False}, sort_keys=True))
        return 0
    except (Refused, OSError, ValueError, KeyError, TypeError, UnicodeError) as error:
        if owned_scope(args.workspace, args.evidence, selected):
            failure = args.evidence / ("failure-" + args.mode + ".json")
            if not failure.exists():
                C.seal(failure, C.encoded({"format": "first-insertion-failure/v1", "mode": args.mode,
                    "error_type": type(error).__name__, "reason": str(error) if isinstance(error, Refused) else None,
                    "status": "FAILURE_OR_UNKNOWN", "commands": records}))
        print("First insertion control refused; retain owned command evidence.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
