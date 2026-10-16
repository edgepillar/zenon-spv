#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Check a real component observation against expectations sealed before it ran."""
import importlib.util
import hashlib
import json
from pathlib import Path
import re

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("genesis_build_prior_identity_oracle", HERE / "check_hash_bound_versions.py")
H = importlib.util.module_from_spec(spec)
spec.loader.exec_module(H)
ZERO = "00" * 32
TIMERS = ("fixture_initialization_ns", "component_init_ns", "worker_and_controlled_restart_elapsed_ns",
          "stop_elapsed_ns", "clean_reopen_elapsed_ns", "component_workflow_elapsed_ns")
FIELDS = {
    "kind", "policy", "Go_version", "platform", "raw_input_sha256", "history_height",
    "retention_test_override", *TIMERS, "source_identifiers_and_suffix_patches_are_synthetic",
    "initial_reads", "interrupted", "snapshot_before_stop", "closed_snapshot", "reopened_snapshot",
    "queries", "reopened_queries", "patch_heights_requested", "each_patch_requested_once",
    "post_stop_public_root", "post_stop_public_error", "post_stop_direct_root", "post_stop_direct_error",
    "physical_files_after_final_close", "actual_chain_Init_Start_Stop_executed",
    "actual_background_batches_executed", "manager_and_genesis_are_controlled_adapters",
    "full_node_started", "network_executed", "signing_or_broadcast_executed",
    "production_concurrency_qualified", "profile_agreed", "accepted_header_root_binding", "consumer_result",
}


def snapshot_shape(row, root_count):
    H.require(type(row) is dict and set(row) == {"format", "logical_records", "logical_key_value_bytes",
              "logical_records_sha256", "record_prefix_counts", "retained_roots"})
    H.require(row["format"] == "03")
    H.require(type(row["logical_records"]) is int and 19257 < row["logical_records"] <= 1000000)
    H.require(type(row["logical_key_value_bytes"]) is int and 0 < row["logical_key_value_bytes"] <= 256 << 20)
    H.require(type(row["logical_records_sha256"]) is str and re.fullmatch("[0-9a-f]{64}", row["logical_records_sha256"]))
    counts = row["record_prefix_counts"]
    H.require(type(counts) is dict and set(counts) == {"00", "01", "02", "03", "05", "06"})
    H.require(all(type(value) is int and value > 0 for value in counts.values()))
    H.require(counts["00"] == counts["05"] == 1 and counts["01"] == counts["02"])
    H.require(counts["03"] == counts["06"] == root_count)
    H.require(sum(counts.values()) == row["logical_records"])

def identifier(fork, height):
    H.require(fork in ("G", "X") and type(height) is int and 1 <= height <= 4096)
    return {"height": height, "hash": hashlib.sha3_256(
        ("synthetic-hash-bound-node-v1/%s/%d" % (fork, height)).encode("ascii")).hexdigest()}

def check_observation(document, base, history):
    H.require(type(document) is dict and set(document) == FIELDS)
    H.require(document["kind"] == "source-genesis-background-component-observation")
    H.require(all(type(document[key]) is str and 0 < len(document[key]) <= 128 for key in ("Go_version", "platform")))
    policy = document["policy"]
    H.require(policy in ("archive", "pruned", "stop-resume"))
    archive = policy == "archive"
    H.require(document["raw_input_sha256"] == "a222aac55304b1a489d395235c61af4182ac08b887d24d0c3f654aa402f35e75")
    H.require(type(document["history_height"]) is int and document["history_height"] == 4096)
    H.require(type(document["retention_test_override"]) is int and document["retention_test_override"] == 256)
    H.require(document["manager_and_genesis_are_controlled_adapters"] is True)
    H.require(document["source_identifiers_and_suffix_patches_are_synthetic"] is True)
    H.require(document["actual_chain_Init_Start_Stop_executed"] is True and document["actual_background_batches_executed"] is True)
    H.require(all(document[k] is False for k in ("full_node_started", "network_executed", "signing_or_broadcast_executed", "production_concurrency_qualified", "profile_agreed", "accepted_header_root_binding")))
    H.require(document["consumer_result"] == "REFUSED")
    H.exact(document["initial_reads"], {"root": ZERO, "error": "not-ready"})
    H.require(type(document["patch_heights_requested"]) is int and document["patch_heights_requested"] == 4096)
    H.require(document["each_patch_requested_once"] is True)
    roots = {r["height"]: r["root"] for r in history["archive_policy_roots"]}
    H.require(len(roots) == 4096 and roots[1] == base["expected_root"] and roots[4096] == history["final_root"])
    selected = range(1, 4097) if archive else range(3840, 4097)
    expected_roots = [{"height": h, "root": roots[h], "hash": identifier("G", h)["hash"]} for h in selected]
    first = document["snapshot_before_stop"]
    for name in ("snapshot_before_stop", "closed_snapshot", "reopened_snapshot"):
        row = document[name]
        H.exact(row, first)
        H.exact(row["retained_roots"], expected_roots)
        snapshot_shape(row, len(expected_roots))
    queries = []
    for h in (1, 3840, 3841, 3968, 4096):
        present = archive or h >= 3840
        rows = []
        selected_proofs = history["selected_checkpoints"][str(h)]
        for sample in selected_proofs:
            rows.append({"selection": sample["selection"], "raw_key": sample["raw_key"],
                         "value": sample["value"] if present else None,
                         "proof": sample["proof"] if present else None,
                         "error": None if present else "no-version", "consumer_result": "REFUSED"})
        queries.append({"height": h, "root": roots[h] if present else ZERO,
                        "root_error": None if present else "no-version", "proofs": rows})
    queries += [
        {"identifier": identifier("G", 3839), "root": roots[3839] if archive else ZERO,
         "root_error": None if archive else "no-version"},
        {"identifier": identifier("X", 4096), "root": ZERO, "root_error": "version-hash-mismatch"},
        {"identifier": dict(H.ORIGIN), "root": ZERO, "root_error": None},
    ]
    H.exact(document["queries"], queries)
    H.exact(document["reopened_queries"], queries)
    for field in ("post_stop_public_root", "post_stop_direct_root"):
        H.require(document[field] == ZERO)
    H.require(document["post_stop_public_error"] == "not-ready" and document["post_stop_direct_error"] == "database-closed")
    if policy == "stop-resume":
        row = document["interrupted"]
        H.require(type(row) is dict and set(row) == {"frontier", "ready", "direct_closed_root", "direct_closed_error", "closed_snapshot"})
        H.exact(row["frontier"], identifier("G", 1))
        H.require(row["ready"] is False and row["direct_closed_root"] == ZERO and row["direct_closed_error"] == "database-closed")
        H.exact(row["closed_snapshot"]["retained_roots"], [{"height": 1, "root": roots[1], "hash": identifier("G", 1)["hash"]}])
        snapshot_shape(row["closed_snapshot"], 1)
    else:
        H.require(document["interrupted"] is None)
    H.require(type(document["physical_files_after_final_close"]) is list and 0 < len(document["physical_files_after_final_close"]) <= 1024)
    names = set()
    for file in document["physical_files_after_final_close"]:
        H.require(type(file) is dict and set(file) == {"name", "bytes", "sha256"} and type(file["name"]) is str)
        H.require(re.fullmatch("[A-Za-z0-9][A-Za-z0-9._-]{0,127}", file["name"]) and file["name"].casefold() not in names)
        H.require(type(file["bytes"]) is int and 0 <= file["bytes"] <= 256 << 20)
        H.require(type(file["sha256"]) is str and re.fullmatch("[0-9a-f]{64}", file["sha256"]))
        names.add(file["name"].casefold())
    for field in TIMERS:
        H.require(type(document[field]) is int and document[field] >= 0)
    return {"kind": "source-genesis-background-component-check", "policy": policy,
            "retained_roots": len(expected_roots), "query_heights": 5, "selected_proof_observations": 75,
            "unsigned_history_heights": 4096, "initial_admitted_leaf_keys": 19257,
            "actual_reference_NodeTree_executed": True, "complete_node_qualified": False,
            "profile_agreed": False, "production_resources_qualified": False, "consumer_result": "REFUSED"}
