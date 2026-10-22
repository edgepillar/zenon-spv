#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Check recorded owned core Stop errors; never execute a reference backend."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("core_stop_error_preparation", HERE / "prepare_core_stop_errors.py")
PREP = importlib.util.module_from_spec(spec)
spec.loader.exec_module(PREP)
M = PREP.M
PRIOR = PREP.BASE.BASE.load("core_stop_error_prior_native_inventory", "check_zenon_worker_stop.py")
CORPUS = "native-core-stop-errors.json"
CORPUS_BYTES = 99481
CORPUS_SHA256 = "172052227422020795b701e61b173bbf2360f6bb67bf88e050d220336fdb5eb7"
BINARY_PINS = {'baseline': {'bytes': 22608466, 'sha256': 'ee2605aaf434f34c22ca39e93efd688c51d01009455309ed6dd66e9f81aad37e'}, 'candidate': {'bytes': 22624978, 'sha256': '31c66df05cd7044baa5dfe467ff82c7f97d5d8f2f99d784c3e9add3d9e652dae'}, 'ordinary_node_entrypoint': {'bytes': 46294514, 'sha256': '528cfea9ff8e5890a1dee98fe91d838a63ce6ee8bc6599db0928f9a33cb8d01f'}}
LINKED_INPUT_PINS = {'baseline': {'bytes': 8204, 'sha256': '73e436021f1c9c2512e94a857d244585d604669bd859e402f71be9af38896025'}, 'candidate': {'bytes': 8204, 'sha256': '73e436021f1c9c2512e94a857d244585d604669bd859e402f71be9af38896025'}, 'ordinary_node_entrypoint': {'bytes': 31444, 'sha256': '20ef323342128f20eac0904fc5e9640f3c777c8cdf28e591c7bd873a8f922cfb'}}
SCOPE = {
    "keyless_core_managers_executed": True, "core_Start_executed": False,
    "controlled_owned_handle_closes": True, "hardware_or_power_failure_qualified": False,
    "test_only_diagnostic_handlers_silenced": True, "assertions_or_return_values_changed": False,
    "wallet_manager_created": False, "node_wrapper_created": False, "peer_server_created": False,
    "RPC_listener_started": False, "external_peer_configured": False, "producing_key_configured": False,
    "repeated_Stop_or_concurrent_lifecycle_qualified": False, "full_node_recovery_qualified": False,
    "consensus_validity_qualified": False, "network_activation_authenticated": False,
    "profile_agreement": False, "accepted_header_binding": False,
    "production_state_value_accepted": False, "private_capture_or_distribution_authenticated": False,
}

def native_passes():
    result = PRIOR.native_passes() + [
        {"package": "github.com/zenon-network/go-zenon/zenon", "name": name} for name in PREP.new_roots()]
    result.sort(key=lambda row: (row["package"], row["name"]))
    M.require(len(result) == len({(row["package"], row["name"]) for row in result}) == 62)
    M.exact(sorted({row["name"] for row in result if "/" not in row["name"]}), PREP.roots())
    return result

def pin(value):
    M.require(type(value) is dict and set(value) == {"sha256", "bytes"})
    M.require(type(value["bytes"]) is int and 0 <= value["bytes"] <= 128 << 20)
    M.require(type(value["sha256"]) is str and re.fullmatch("[0-9a-f]{64}", value["sha256"]) is not None)

def command(value):
    M.require(type(value) is dict and set(value) == {
        "state", "actual_exit", "output_complete", "reason", "stdout", "stderr"})
    M.exact({key: value[key] for key in ("state", "actual_exit", "output_complete", "reason")},
            {"state": "COMPLETE", "actual_exit": 0, "output_complete": True, "reason": None})
    pin(value["stdout"])
    pin(value["stderr"])

def binary(value, label):
    M.require(type(value) is dict and set(value) == {
        "binary", "build", "capture", "module_information", "linked_module_inputs"})
    M.exact(value["binary"], BINARY_PINS[label])
    for key in ("build", "capture", "module_information"):
        command(value[key])
    M.exact(value["capture"]["stdout"], value["binary"])
    linked = value["linked_module_inputs"]
    M.require(type(linked) is list and len(linked) == (116 if label == "ordinary_node_entrypoint" else 30))
    M.exact({"bytes": len(M.encoded(linked)), "sha256": hashlib.sha256(M.encoded(linked)).hexdigest()},
            LINKED_INPUT_PINS[label])

def check_corpus(document):
    raw = M.encoded(document)
    M.require(len(raw) == CORPUS_BYTES and hashlib.sha256(raw).hexdigest() == CORPUS_SHA256)
    M.require(type(document) is dict and set(document) == {
        "format_version", "kind", "source", "recorded_native", "output_limit_attempt",
        "scope", "variants", "ordinary_node_entrypoint"})
    M.exact(document["format_version"], 1)
    M.exact(document["kind"], "recorded-owned-core-Zenon-Stop-errors")
    M.exact(document["scope"], SCOPE)
    M.exact(document["source"], {
        "repository": "digitalSloth/go-zenon", "revision": PREP.P.REVISION,
        "parent_runtime_tree": PREP.PARENT_TREE, "candidate_runtime_tree": PREP.CANDIDATE_TREE,
        "comparison_build_trees": PREP.BUILD_TREES, "comparison_source_files_per_variant": 480,
        "native_unit_tree": PREP.NATIVE_TREE, "native_unit_source_files": 481,
        "model": {"sha256": PREP.MODEL_SHA256, "bytes": PREP.MODEL_BYTES},
        "selection": {"sha256": M.SELECTION_SHA256, "bytes": M.SELECTION_BYTES},
        "sources": {name: {"bytes": size, "sha256": digest}
                    for name, _, size, digest in PREP.EXTRAS + (PREP.QUIET_EXTRA,)},
        "go_mod_sha256": "ac08476abe3df0bc67f1c5c6868f04889b864310f16a37b0d51a6598b9017a45",
        "go_sum_sha256": "e536610c08abc9f4b979ce39cd5ae7323c3df14a189d186d911ee1d1184b8537"})
    for variant in PREP.VARIANTS:
        M.require(PREP.P.UTIL.reconstruct_tree(PREP.build_pins(variant)) == PREP.BUILD_TREES[variant])
    M.require(PREP.P.UTIL.reconstruct_tree(PREP.build_pins("candidate", True)) == PREP.NATIVE_TREE)
    native = document["recorded_native"]
    M.require(type(native) is dict and set(native) == {
        "go_version", "platform", "CGO_ENABLED", "ordinary_comparison_builds", "qualified_ordinary_processes",
        "ordinary_node_entrypoint_builds", "ordinary_node_entrypoint_executions", "qualified_native_unit_invocations",
        "native_unit_packages", "native_unit_root_tests", "native_unit_pass_results", "native_unit_skips",
        "new_core_stop_root_tests", "retained_prior_root_tests", "native_unit_passes", "commands",
        "native_unit_stdout_limit_bytes", "native_unit_stdout_bytes", "downloaded_cache_archives_verified",
        "whole_module_payload_graph_qualified", "new_external_dependency_transports", "comparison_builds_or_cases_repeated"})
    M.exact({key: value for key, value in native.items() if key != "commands"}, {
        "go_version": "go1.25.14", "platform": "darwin/arm64", "CGO_ENABLED": 1,
        "ordinary_comparison_builds": 2, "qualified_ordinary_processes": 6,
        "ordinary_node_entrypoint_builds": 1, "ordinary_node_entrypoint_executions": 0,
        "qualified_native_unit_invocations": 1, "native_unit_packages": 5, "native_unit_root_tests": 53,
        "native_unit_pass_results": 62, "native_unit_skips": 0, "new_core_stop_root_tests": 3,
        "retained_prior_root_tests": 50, "native_unit_passes": native_passes(),
        "native_unit_stdout_limit_bytes": 8 << 20, "native_unit_stdout_bytes": 75351,
        "downloaded_cache_archives_verified": 116, "whole_module_payload_graph_qualified": False,
        "new_external_dependency_transports": 0, "comparison_builds_or_cases_repeated": 0})
    M.require(set(native["commands"]) == {"selected_native_units", "downloaded_cache_verify"})
    for row in native["commands"].values():
        command(row)
    M.require(native["commands"]["selected_native_units"]["stdout"]["bytes"] == native["native_unit_stdout_bytes"])
    M.exact(document["output_limit_attempt"], {
        "qualification": "FAILED_CAPTURE_LIMIT", "actual_exit": -13, "output_complete": False,
        "reason": "OUTPUT_LIMIT_OR_CAPTURE_FAILURE",
        "partial_stdout": {"bytes": 8388608, "sha256": "bc6e5050d252ba2436875f24bb2deadf4984e146eded7ea0c9ab4c18f4debc29"},
        "native_pass_inferred": False, "original_closed_metadata_and_scratch_preserved": True,
        "successful_comparison_builds_or_cases_repeated": 0,
        "same_stdout_limit_used_on_resume": True, "test_only_log_handler_added_on_resume": True})
    M.require(type(document["variants"]) is dict and set(document["variants"]) == set(PREP.VARIANTS))
    open_handles, error_leaves, ready = {}, {}, 0
    for variant in PREP.VARIANTS:
        row = document["variants"][variant]
        M.require(type(row) is dict and set(row) == {"recorded_binary", "streams"})
        binary(row["recorded_binary"], variant)
        M.require(type(row["streams"]) is list and len(row["streams"]) == 3)
        open_handles[variant], error_leaves[variant] = 0, 0
        for recording, mode in zip(row["streams"], PREP.MODES):
            M.require(type(recording) is dict and set(recording) == {"case", "command", "jsonl"})
            M.exact(recording["case"], mode)
            command(recording["command"])
            M.require(type(recording["jsonl"]) is str)
            stream = recording["jsonl"].encode()
            M.exact(recording["command"]["stdout"], {
                "bytes": len(stream), "sha256": hashlib.sha256(stream).hexdigest()})
            report = M.check(stream, variant, mode)
            open_handles[variant] += int(report["consensus_after_stop"] == "open")
            error_leaves[variant] += len(report["stop"]["leaf_classes"])
            ready += sum(int(report[key]["ready"]) for key in ("before_stop", "after_stop"))
    M.exact(open_handles, {"baseline": 1, "candidate": 0})
    M.exact(error_leaves, {"baseline": 2, "candidate": 3})
    M.require(ready == 6)
    entrypoint = document["ordinary_node_entrypoint"]
    M.require(type(entrypoint) is dict and set(entrypoint) == {"recorded_binary", "build_tree", "executed"})
    M.exact(entrypoint["executed"], False)
    M.exact(entrypoint["build_tree"], PREP.NATIVE_TREE)
    binary(entrypoint["recorded_binary"], "ordinary_node_entrypoint")
    return {"kind": "recorded-core-Stop-errors-check", "node_revision": PREP.P.REVISION,
        "parent_runtime_tree": PREP.PARENT_TREE, "candidate_runtime_tree": PREP.CANDIDATE_TREE,
        "corpus_sha256": CORPUS_SHA256, "ordinary_comparison_builds": 2, "qualified_ordinary_processes": 6,
        "observed_baseline_open_databases_after_Stop": 1, "observed_candidate_open_databases_after_Stop": 0,
        "baseline_retained_error_leaves": 2, "candidate_retained_error_leaves": 3,
        "root_value_proof_observations": 12, "successful_root_value_proof_observations": 6,
        "foreign_identifier_refusals": 12, "selected_native_root_tests": 53,
        "selected_native_pass_results": 62, "selected_native_skips": 0,
        "new_core_stop_root_tests": 3, "retained_prior_root_tests": 50,
        "ordinary_node_entrypoint_compiled": True, "ordinary_node_entrypoint_executed": False,
        "failed_capture_limit_attempts": 1, "failed_attempt_pass_inferred": False,
        "comparison_builds_or_cases_repeated": 0, "reference_backend_reexecuted": False,
        "consumer_result": "REFUSED", "production_state_value_accepted": False, "scope": document["scope"],
        "reader_inputs_sha256": {name: hashlib.sha256((HERE / name).read_bytes()).hexdigest()
            for name in ("prepare_core_stop_errors.py", "check_core_stop_errors.py", "core_stop_error_model.py")}}

def check_file(path=None):
    selected = HERE / "testdata" / CORPUS if path is None else Path(path)
    raw = M.read_bounded(selected, 256 << 10)
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
        print("Recorded core Stop error evidence refused; state values remain disabled.", file=sys.stderr)
        raise SystemExit(1)
