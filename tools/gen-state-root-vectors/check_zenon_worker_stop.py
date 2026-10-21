#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Check retained core-manager Stop records; never execute a reference backend."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("worker_stop_preparation", HERE / "prepare_zenon_worker_stop.py")
PREP = importlib.util.module_from_spec(spec)
spec.loader.exec_module(PREP)
M = PREP.M
PRIOR = PREP.BASE.load("worker_stop_prior_native_inventory", "check_cache_read_errors.py")
CORPUS = "native-zenon-worker-stop.json"
CORPUS_BYTES = 54727
CORPUS_SHA256 = "bdf837785e8686fe462d54f7cfe5b0c64d0a6d928921ae8978d5e773ef3f7f80"
BINARY_PINS = {
    "baseline": {"bytes": 22625010, "sha256": "d0f1e5dc5b24f9f7b0a25e6b4e73ad27c7c779a252704887f84373d62a6c5168"},
    "candidate": {"bytes": 22625090, "sha256": "f557869364ca89a7a63105d9a22b65f6859c847eb5c31f79c7fc7dfdab239b2c"},
}
SCOPE = {
    "keyless_core_managers_executed": True, "internal_services_started_in_reopen_controls": True,
    "wallet_manager_created": False, "node_wrapper_created": False, "peer_server_created": False,
    "RPC_listener_started": False, "external_peer_configured": False, "producing_key_configured": False,
    "repeated_Stop_or_concurrent_lifecycle_qualified": False, "full_node_recovery_qualified": False,
    "consensus_validity_qualified": False, "network_activation_authenticated": False,
    "profile_agreement": False, "accepted_header_binding": False,
    "production_state_value_accepted": False, "private_capture_or_distribution_authenticated": False,
}

def native_passes():
    result = PRIOR.native_passes() + [
        {"package": "github.com/zenon-network/go-zenon/pillar", "name": name} for name in PREP.new_roots()]
    result.sort(key=lambda row: (row["package"], row["name"]))
    M.require(len(result) == 59 and len({(row["package"], row["name"]) for row in result}) == 59)
    M.exact(sorted({row["name"] for row in result if "/" not in row["name"]}), PREP.roots())
    return result

def pin(value):
    M.require(type(value) is dict and set(value) == {"sha256", "bytes"})
    M.require(type(value["bytes"]) is int and 0 <= value["bytes"] <= 32 << 20)
    M.require(type(value["sha256"]) is str and re.fullmatch("[0-9a-f]{64}", value["sha256"]) is not None)

def command(value):
    M.require(type(value) is dict and set(value) == {
        "state", "actual_exit", "output_complete", "reason", "stdout", "stderr"})
    M.exact({key: value[key] for key in ("state", "actual_exit", "output_complete", "reason")},
            {"state": "COMPLETE", "actual_exit": 0, "output_complete": True, "reason": None})
    pin(value["stdout"])
    pin(value["stderr"])

def check_corpus(document):
    # These are fixed private-capture records, not a claim that arbitrary new
    # executions can authenticate themselves by supplying matching counters.
    raw = M.encoded(document)
    M.require(len(raw) == CORPUS_BYTES and hashlib.sha256(raw).hexdigest() == CORPUS_SHA256)
    M.require(type(document) is dict and set(document) == {
        "format_version", "kind", "source", "recorded_native", "interrupted_attempt", "scope", "variants"})
    M.exact(document["format_version"], 1)
    M.exact(document["kind"], "recorded-core-Zenon-prestart-worker-stop")
    M.exact(document["scope"], SCOPE)
    M.exact(document["source"], {
        "repository": "digitalSloth/go-zenon", "revision": PREP.P.REVISION,
        "parent_runtime_tree": PREP.PARENT_TREE, "candidate_runtime_tree": PREP.CANDIDATE_TREE,
        "build_trees": PREP.BUILD_TREES, "prepared_source_files_per_variant": 475,
        "model": {"sha256": PREP.MODEL_SHA256, "bytes": PREP.MODEL_BYTES},
        "selection": {"sha256": M.SELECTION_SHA256, "bytes": M.SELECTION_BYTES},
        "sources": {name: {"bytes": size, "sha256": digest} for name, _, size, digest in PREP.EXTRAS},
        "go_mod_sha256": "ac08476abe3df0bc67f1c5c6868f04889b864310f16a37b0d51a6598b9017a45",
        "go_sum_sha256": "e536610c08abc9f4b979ce39cd5ae7323c3df14a189d186d911ee1d1184b8537"})
    for variant in PREP.VARIANTS:
        M.require(PREP.P.UTIL.reconstruct_tree(PREP.build_pins(variant)) == PREP.BUILD_TREES[variant])
    native = document["recorded_native"]
    M.require(type(native) is dict and set(native) == {
        "go_version", "platform", "CGO_ENABLED", "ordinary_builds", "qualified_ordinary_processes",
        "keyless_core_Start_Stop_controls", "native_unit_invocations", "native_unit_packages",
        "native_unit_root_tests", "native_unit_pass_results", "native_unit_skips", "new_worker_root_tests",
        "retained_prior_root_tests", "native_unit_passes", "commands", "downloaded_unit_cache_archives_verified",
        "whole_module_payload_graph_qualified", "new_external_dependency_transports"})
    M.exact({key: value for key, value in native.items() if key != "commands"}, {
        "go_version": "go1.25.14", "platform": "darwin/arm64", "CGO_ENABLED": 1,
        "ordinary_builds": 2, "qualified_ordinary_processes": 6, "keyless_core_Start_Stop_controls": 2,
        "native_unit_invocations": 1, "native_unit_packages": 4, "native_unit_root_tests": 50,
        "native_unit_pass_results": 59, "native_unit_skips": 0, "new_worker_root_tests": 9,
        "retained_prior_root_tests": 41, "native_unit_passes": native_passes(),
        "downloaded_unit_cache_archives_verified": 30, "whole_module_payload_graph_qualified": False,
        "new_external_dependency_transports": 0})
    M.require(set(native["commands"]) == {"selected_native_units", "downloaded_cache_verify"})
    for row in native["commands"].values():
        command(row)
    M.exact(document["interrupted_attempt"], {
        "qualification": "UNKNOWN", "actual_exit": None, "output_complete": False,
        "original_metadata_and_scratch_preserved": True, "missing_exit_inferred": False,
        "fresh_candidate_resume_cases": 3, "completed_builds_or_baseline_cases_repeated": 0})
    M.require(type(document["variants"]) is dict and set(document["variants"]) == set(PREP.VARIANTS))
    panics, ready = {}, 0
    for variant in PREP.VARIANTS:
        row = document["variants"][variant]
        M.require(type(row) is dict and set(row) == {
            "binary", "build", "capture", "module_information", "linked_module_inputs", "streams"})
        M.exact(row["binary"], BINARY_PINS[variant])
        for key in ("build", "capture", "module_information"):
            command(row[key])
        M.exact(row["capture"]["stdout"], row["binary"])
        M.require(type(row["linked_module_inputs"]) is list and len(row["linked_module_inputs"]) == 30)
        M.require(type(row["streams"]) is list and len(row["streams"]) == 3)
        panics[variant] = 0
        for recording, mode in zip(row["streams"], PREP.MODES):
            M.require(type(recording) is dict and set(recording) == {"case", "command", "jsonl"})
            M.exact(recording["case"], mode)
            command(recording["command"])
            M.require(type(recording["jsonl"]) is str)
            stream = recording["jsonl"].encode()
            M.exact(recording["command"]["stdout"], {
                "bytes": len(stream), "sha256": hashlib.sha256(stream).hexdigest()})
            report = M.check(stream, variant, mode)
            panics[variant] += int(bool(report["stop"]["panic"]))
            ready += sum(int(report[key]["ready"]) for key in ("before_stop", "after_stop"))
    M.exact(panics, {"baseline": 2, "candidate": 0})
    M.require(ready == 5)
    return {"kind": "recorded-core-Zenon-prestart-Stop-check", "node_revision": PREP.P.REVISION,
        "parent_runtime_tree": PREP.PARENT_TREE, "candidate_runtime_tree": PREP.CANDIDATE_TREE,
        "corpus_sha256": CORPUS_SHA256, "ordinary_builds": 2, "qualified_ordinary_processes": 6,
        "observed_baseline_API_panics": 2, "observed_candidate_API_panics": 0,
        "outer_process_nonzero_exits": 0, "root_value_proof_observations": 12,
        "successful_root_value_proof_observations": 5, "foreign_identifier_refusals": 12,
        "selected_native_root_tests": 50, "selected_native_pass_results": 59, "selected_native_skips": 0,
        "new_worker_root_tests": 9, "retained_prior_root_tests": 41,
        "unknown_interrupted_attempts": 1, "unknown_exit_inferred": False,
        "reference_backend_reexecuted": False, "consumer_result": "REFUSED",
        "production_state_value_accepted": False, "scope": document["scope"],
        "reader_inputs_sha256": {name: hashlib.sha256((HERE / name).read_bytes()).hexdigest()
            for name in ("prepare_zenon_worker_stop.py", "check_zenon_worker_stop.py", "zenon_worker_stop_model.py")}}

def check_file(path=None):
    selected = HERE / "testdata" / CORPUS if path is None else Path(path)
    raw = M.read_bounded(selected, 128 << 10)
    M.require(len(raw) == CORPUS_BYTES and hashlib.sha256(raw).hexdigest() == CORPUS_SHA256)
    return check_corpus(json.loads(raw, object_pairs_hook=M.pairs, parse_constant=M.constant))

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--file")
    parser.add_argument("--source-revision")
    args = parser.parse_args(argv)
    M.require(args.source_revision is None or re.fullmatch("[0-9a-f]{40}", args.source_revision) is not None)
    result = check_file(args.file)
    if args.source_revision is not None:
        result["source_revision"] = args.source_revision
    print(json.dumps(result, sort_keys=True))

if __name__ == "__main__":
    try:
        main()
    except (ValueError, TypeError, KeyError, OSError):
        print("Recorded core-manager Stop evidence refused; state values remain disabled.", file=sys.stderr)
        raise SystemExit(1)
