#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Compare one actual offline-helper observation with independent finite roots.

This bounded reader checks full identifiers, returned root maps, canonical proof
bytes and complete snapshot digests. Logical-record equality is a closed-reopen
observation, not a reconstruction of all internal refcounts or snapshot trust.
No node execution, activation or state-value acceptance is performed here.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("offline_rebuild_independent_model", HERE / "offline_rebuild_successor_model.py")
M = importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)
P = M.P
ZERO = "0" * 64
COMMON = ("rebuild-default", "rebuild-short-pruned", "rebuild-short-archive", "prebuild-reopen", "prebuild-delta")
FAULTS = ("wrong-height", "missing-momentum", "wrong-hash", "stopped-store", "read-error", "missing-retained-hash", "wrong-retained-hash")
FALSE_FIELDS = ("full_node_started", "chain_Init_or_Start_executed", "network_executed",
                "signing_or_broadcast_executed", "accepted_header_root_binding", "profile_agreed", "production_resources_qualified")


def require(value):
    if not value:
        raise ValueError("Successor offline rebuild observation refused")


def uint(value, lower, upper):
    return type(value) is int and lower <= value <= upper


def digest(value):
    return type(value) is str and re.fullmatch("[0-9a-f]{64}", value) is not None


def selected_expectations(expected):
    P.exact(expected, M.derive())
    return expected


def logical(row):
    require(type(row) is dict and set(row) == {"records", "logical_bytes", "sha256"})
    require(uint(row["records"], 1, 2_000_000) and uint(row["logical_bytes"], 1, 2 << 30) and digest(row["sha256"]))


def snapshot(row, expected, height=64, horizon=1, retained_fault=None):
    require(type(row) is dict and set(row) == {"frontier", "roots", "queries", "identity_refusals", "logical_records"})
    P.exact(row["frontier"], M.identifier(height))
    require(type(row["roots"]) is list and len(row["roots"]) == height)
    roots = {r["height"]: r["root"] for r in expected["history"]["roots"]}
    for h, actual in enumerate(row["roots"], 1):
        error, root = None, roots[h]
        if h < horizon:
            error, root = "no-version", ZERO
        if h == 32 and retained_fault:
            error, root = ("version-hash-missing" if retained_fault == "missing-retained-hash" else "version-hash-mismatch"), ZERO
        P.exact(actual, {"identifier": M.identifier(h), "root": root, "error": error})
    selected_heights = [h for h in expected["selection"]["query_heights"] if h <= height]
    require(type(row["queries"]) is list and len(row["queries"]) == len(selected_heights))
    proofs_checked, no_version = 0, 0
    for actual, h in zip(row["queries"], selected_heights):
        require(type(actual) is dict and set(actual) == {"identifier", "root", "root_error", "proofs"})
        P.exact(actual["identifier"], M.identifier(h))
        absent_version = h < horizon
        P.exact(actual["root"], ZERO if absent_version else roots[h])
        P.exact(actual["root_error"], "no-version" if absent_version else None)
        reference = expected["history"]["checkpoints"][str(h)]
        require(type(actual["proofs"]) is list and len(actual["proofs"]) == 15)
        for observed, wanted in zip(actual["proofs"], reference):
            P.exact(observed, {
                "selection": wanted["selection"], "raw_key": wanted["raw_key"],
                "value": None if absent_version else wanted["value"],
                "proof": None if absent_version else wanted["proof"],
                "error": "no-version" if absent_version else None, "consumer_result": "REFUSED",
            })
            if absent_version:
                no_version += 1
            else:
                value = bytes.fromhex(observed["value"]) if observed["value"] is not None else b""
                result = M.M.G.B.proof_result(bytes.fromhex(roots[h]), bytes.fromhex(wanted["path"]),
                                              value, bytes.fromhex(observed["proof"]), wanted["present_in_projection"])
                require(result == "match")
                proofs_checked += 1
    P.exact(row["identity_refusals"], [
        {"name": "wrong-hash", "identifier": M.identifier(height, "X"), "root": ZERO, "error": "version-hash-mismatch"},
        {"name": "height-only", "identifier": {"height": height, "hash": ZERO}, "root": ZERO, "error": "version-hash-mismatch"},
        {"name": "missing-version", "identifier": M.identifier(height + 1), "root": ZERO, "error": "no-version"},
    ])
    logical(row["logical_records"])
    return {"proofs_checked": proofs_checked, "no_version_proof_refusals": no_version}


def closed(row, expected, horizon=1, fault=None):
    require(type(row) is list and len(row) == 2)
    result = snapshot(row[0], expected, horizon=horizon, retained_fault=fault)
    P.exact(row[1], {"complete_snapshot_sha256": hashlib.sha256(M.encoded(row[0])).hexdigest()})
    return result


def calls(lower, upper):
    return {str(h): 1 for h in range(lower, upper + 1)}


def prebuild(row, expected, delta):
    require(type(row) is dict and set(row) == {
        "name", "operation", "prebuild_frontier", "prebuild_snapshot", "initial_patch_requests", "delta_patch_requests",
        "steps", "ready_before_stop", "final_root", "final_root_error", "closed_reopens"})
    P.exact(row["name"], "prebuild-delta" if delta else "prebuild-reopen")
    P.exact(row["operation"], "PrebuildStateTree+StateTreeBuild")
    start = 32 if delta else 64
    P.exact(row["prebuild_frontier"], M.identifier(start))
    initial = snapshot(row["prebuild_snapshot"], expected, height=start)
    P.exact(row["initial_patch_requests"], calls(1, start))
    P.exact(row["delta_patch_requests"], calls(33, 64) if delta else {})
    require(type(row["steps"]) is list and 1 <= len(row["steps"]) <= 64)
    previous = start
    for index, step in enumerate(row["steps"]):
        require(type(step) is dict and set(step) == {"done", "error", "frontier", "ready"})
        require(type(step["frontier"]) is dict and type(step["frontier"].get("height")) is int)
        height = step["frontier"]["height"]
        if delta:
            require(previous < height <= min(previous + 10, 64))
        else:
            require(len(row["steps"]) == 1 and height == 64)
        P.exact(step, {"done": height == 64, "error": None, "frontier": M.identifier(height), "ready": height == 64})
        require(height != 64 or index == len(row["steps"]) - 1)
        previous = height
    require(previous == 64)
    P.exact(row["ready_before_stop"], True)
    P.exact(row["final_root"], expected["history"]["final_root"])
    P.exact(row["final_root_error"], None)
    result = closed(row["closed_reopens"], expected)
    if not delta:
        P.exact(row["prebuild_snapshot"], row["closed_reopens"][0])
    return {key: initial[key] + result[key] for key in initial}


def check_observation(raw, expected, variant):
    selected_expectations(expected)
    require(variant in M.R.VARIANTS and type(raw) is bytes and 0 < len(raw) <= 4 << 20)
    document = json.loads(raw, object_pairs_hook=P.pairs)
    require(type(document) is dict and set(document) == {
        "kind", "format_version", "variant", "node_revision", "node_tree", "runtime_tree", "Go_version", "platform",
        "raw_input_sha256", "selection_sha256", "history_height", "cases", "actual_exported_offline_helpers_executed",
        "manager_and_genesis_are_controlled_adapters", "source_identifiers_and_suffix_patches_are_synthetic",
        "consumer_result", *FALSE_FIELDS})
    header = {k: v for k, v in document.items() if k != "cases"}
    P.exact(header, dict({
        "kind": "successor-offline-rebuild-component-observation", "format_version": 1, "variant": variant,
        "node_revision": M.P.REVISION, "node_tree": M.P.TREE,
        "runtime_tree": M.R.MODIFIED_TREE if variant == "full-identifier" else M.R.T.MODIFIED_TREE,
        "Go_version": "go1.25.14", "platform": "darwin/arm64", "raw_input_sha256": expected["raw_input"]["sha256"],
        "selection_sha256": expected["selection_sha256"], "history_height": 64,
        "actual_exported_offline_helpers_executed": True, "manager_and_genesis_are_controlled_adapters": True,
        "source_identifiers_and_suffix_patches_are_synthetic": True, "consumer_result": "REFUSED",
    }, **{key: False for key in FALSE_FIELDS}))
    rows = document["cases"]
    names = COMMON + tuple("fault-" + name for name in FAULTS) if variant == "full-identifier" else COMMON
    require(type(rows) is list and len(rows) == len(names))
    require(all(type(row) is dict for row in rows))
    P.exact([row.get("name") for row in rows], list(names))
    proof_count, refusals = 0, 0
    expected_roots = {str(r["height"]): r["root"] for r in expected["history"]["roots"]}
    for index, row in enumerate(rows):
        if index < 3:
            require(set(row) == {"name", "operation", "archive", "retention_override", "result", "error",
                                 "frontier_snapshots", "patch_requests", "closed_reopens"})
            short = row["name"] == "rebuild-short-pruned"
            P.exact(row["operation"], "RebuildStateTree")
            P.exact(row["archive"], row["name"] == "rebuild-short-archive")
            P.exact(row["retention_override"], 0 if index == 0 else 5)
            P.exact(row["patch_requests"], calls(1, 64))
            if variant == "terminal-parent":
                P.exact(row["result"], None)
                P.exact(row["error"], "version-hash-mismatch")
                P.exact(row["frontier_snapshots"], 2)
            else:
                wanted_roots = {k: v for k, v in expected_roots.items() if not short or int(k) >= 59}
                P.exact(row["result"], {"frontier": M.identifier(64), "roots": wanted_roots})
                P.exact(row["error"], None)
                P.exact(row["frontier_snapshots"], 3)
            result = closed(row["closed_reopens"], expected, horizon=59 if short else 1)
        elif index < 5:
            result = prebuild(row, expected, index == 4)
        else:
            require(set(row) == {"name", "operation", "fault", "result", "error", "frontier_snapshots",
                                 "fault_snapshots_applied", "before", "closed_reopens"})
            fault = FAULTS[index - 5]
            P.exact(row["fault"], fault)
            P.exact(row["operation"], "RebuildStateTree-refusal")
            P.exact(row["result"], None)
            error = {"wrong-height": "invalid-chain-momentum", "missing-momentum": "invalid-chain-momentum",
                     "wrong-hash": "version-hash-mismatch", "stopped-store": "chain-store-stopped",
                     "read-error": "injected-chain-read", "missing-retained-hash": "version-hash-missing",
                     "wrong-retained-hash": "version-hash-mismatch"}[fault]
            P.exact(row["error"], error)
            P.exact(row["frontier_snapshots"], 3)
            retained = fault in ("missing-retained-hash", "wrong-retained-hash")
            P.exact(row["fault_snapshots_applied"], 0 if retained else 1)
            result = closed(row["closed_reopens"], expected, fault=fault if retained else None)
            P.exact(row["before"], row["closed_reopens"][1])
        proof_count += result["proofs_checked"]
        refusals += result["no_version_proof_refusals"]
    return {
        "kind": "successor-offline-rebuild-observation-check", "variant": variant,
        "cases": len(rows), "history_height": 64, "proofs_checked": proof_count,
        "no_version_proof_refusals": refusals, "complete_snapshot_reopens_checked": 2 * len(rows),
        "parent_height_only_rebuild_refusals": 3 if variant == "terminal-parent" else 0,
        "fixed_full_identifier_rebuilds": 3 if variant == "full-identifier" else 0,
        "fixed_selected_refusals": 7 if variant == "full-identifier" else 0,
        "new_node_backend_executed_by_reader": False, "production_resources_qualified": False,
        "accepted_header_root_binding": False, "consumer_result": "REFUSED",
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--observation", type=Path, required=True)
    parser.add_argument("--expected", type=Path, required=True)
    parser.add_argument("--variant", choices=M.R.VARIANTS, required=True)
    args = parser.parse_args(argv)
    expected = json.loads(P.read_regular(args.expected, 1 << 20), object_pairs_hook=P.pairs)
    print(json.dumps(check_observation(P.read_regular(args.observation, 4 << 20), expected, args.variant), sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, IndexError, AssertionError):
        print("Successor offline rebuild observation refused; preserve inputs and diagnostics.", file=sys.stderr)
        sys.exit(1)
