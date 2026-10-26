#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Check recorded failed-Init cleanup; never execute a node or download inputs."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


P = load("failed_init_source_recipe", "prepare_core_init_failure.py")
OLD = load("failed_init_prior_module_bindings", "check_core_repeat_stop.py")
M = P.M
CORPUS = "native-core-init-failure.json"
CORPUS_BYTES = 17224
CORPUS_SHA256 = "291a93d18ebd2f6b017f411232cd3aad8ba42f9c2e96f6e12a022b80889a277f"
BINARY = {'bytes': 22626466, 'sha256': '3aac67375b5c20524c03a1f8e5e09bcf5044787af7b02ba074343281e1e7c4b2'}
MAX_STREAM = 8192
SCOPE = {
    "selected_real_keyless_failed_Init_cases_executed": True,
    "same_handle_closure_and_fresh_existing_store_reopen_observed": True,
    "additional_runtime_patch_selected": False,
    "core_Start_executed": False, "node_wrapper_created": False,
    "peer_server_created": False, "RPC_listener_started": False,
    "wallet_manager_created": False, "producing_key_configured": False,
    "concurrent_lifecycle_qualified": False,
    "arbitrary_Init_failure_or_manager_panic_recovery_qualified": False,
    "hardware_or_power_failure_qualified": False,
    "full_node_or_network_qualified": False,
    "profile_agreement": False, "activation_authenticated": False,
    "accepted_header_binding": False, "production_state_value_accepted": False,
    "independent_human_acceptance": False, "distribution_authenticated": False,
    "production_resource_budget_qualified": False,
}


def expected_observation(case):
    P.require(type(case) is str and case in P.CASES)
    ledger = case == P.CASES[0]
    call = {"error": "none", "panic": False}
    before = {"ledger_open": not ledger, "cache_open": True,
              "consensus": "none", "tree_ready": False}
    # The pinned LevelDB storage returns a formatted, unwrapped error for an
    # existing file. The probe deliberately records its non-specific class;
    # the marker and real call order bind this selected fault condition.
    result = {
        "case": case, "fault_setup": dict(call),
        "before_Init": dict(before),
        "Init": {"error": "ledger-unavailable" if ledger else "other-error", "panic": False},
        "after_Init": dict(before), "Stop": dict(call),
        "after_Stop": {"ledger_open": False, "cache_open": False,
                       "consensus": "leveldb-closed", "tree_ready": False},
        "store_reopen": {name: dict(call) for name in ("nom", "cache", "consensus")},
        "second_Stop": dict(call),
    }
    if not ledger:
        marker = hashlib.sha256(b"owned Init open-error control\n").hexdigest()
        result["marker"] = {"before_sha256": marker, "after_sha256": marker,
                            "same_file": True, "bytes_matched": True}
    return {
        "schema": "experimental-core-Init-failure-observation-v1", "status": "OBSERVED",
        "genesis": json.loads(P.K.R.selected_input())["genesis"], "observation": result,
        "core_Start_selected": False, "network_or_wallet_or_signing_selected": False,
        "accepted_header_binding": False, "production_state_value_accepted": False,
    }


def observation(raw, case):
    P.require(type(raw) is bytes and 0 < len(raw) <= MAX_STREAM and raw.endswith(b"\n"))
    P.require(len(raw.splitlines()) == 1)
    value = json.loads(raw, object_pairs_hook=M.pairs, parse_constant=M.constant)
    M.exact(value, expected_observation(case))
    return value


def stream(row, case):
    P.require(type(row) is dict and set(row) == {"case", "command", "jsonl"})
    M.exact(row["case"], case)
    OLD.command(row["command"])
    P.require(type(row["jsonl"]) is str)
    raw = row["jsonl"].encode()
    M.exact(row["command"]["stdout"], {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
    return observation(raw, case)


def check_corpus(value):
    raw = P.encoded(value)
    P.require(len(raw) == CORPUS_BYTES and hashlib.sha256(raw).hexdigest() == CORPUS_SHA256)
    P.require(type(value) is dict and set(value) == {
        "format_version", "kind", "source", "native", "binding", "streams", "linked_module_inputs", "scope"})
    M.exact(value["format_version"], 1)
    M.exact(value["kind"], "recorded-experimental-core-failed-Init-cleanup")
    M.exact(value["scope"], SCOPE)
    M.exact(value["source"], {
        "repository": "digitalSloth/go-zenon", "revision": P.P.REVISION,
        "original_tree": P.P.TREE, "runtime_tree": P.K.CANDIDATE_TREE,
        "build_tree": P.P.UTIL.reconstruct_tree(P.build_pins()), "source_blobs": 487,
        "additional_runtime_patch_selected": False,
        "parent_preparer_sha256": P.PARENT_SHA256,
        "extras": {name: {"bytes": size, "sha256": digest} for name, _, size, digest in P.EXTRAS},
        "go_mod_sha256": "ac08476abe3df0bc67f1c5c6868f04889b864310f16a37b0d51a6598b9017a45",
        "go_sum_sha256": "e536610c08abc9f4b979ce39cd5ae7323c3df14a189d186d911ee1d1184b8537",
    })
    native = value["native"]
    P.require(type(native) is dict and set(native) == {
        "compiler", "compiler_binary_sha256", "platform", "CGO_ENABLED",
        "ordinary_builds", "ordinary_processes", "race_builds", "race_processes",
        "build_settings", "cache_verification", "new_external_transports",
        "source_map_matches_actual_build", "whole_native_regression_graph_reexecuted",
        "initial_controller_outcome", "read_only_reconciliation", "additional_native_executions"})
    M.exact({key: item for key, item in native.items() if key != "cache_verification"}, {
        "compiler": "go1.25.14",
        "compiler_binary_sha256": "55770db639faa42f3ebc998ac583b008f7ff2b4bbb9dbb8a76511a9a6ffa4a19",
        "platform": "darwin/arm64", "CGO_ENABLED": 1,
        "ordinary_builds": 1, "ordinary_processes": 2, "race_builds": 0, "race_processes": 0,
        "build_settings": {"-tags": P.TAGS, "-trimpath": "true",
                           "CGO_ENABLED": "1", "GOOS": "darwin", "GOARCH": "arm64"},
        "new_external_transports": 0, "source_map_matches_actual_build": True,
        "whole_native_regression_graph_reexecuted": False,
        "initial_controller_outcome": "FAILURE",
        "read_only_reconciliation": "unwrapped-storage-path-error-class",
        "additional_native_executions": 0,
    })
    OLD.command(native["cache_verification"])
    M.exact(native["cache_verification"]["stdout"], {
        "bytes": 21, "sha256": "b4537ed75f533f993f371954de47e42a793b8e5b0587577de7e27fb3e50696bd"})
    linked = value["linked_module_inputs"]
    P.require(type(linked) is list and len(linked) == 30)
    linked_pin = {"bytes": len(P.encoded(linked)), "sha256": hashlib.sha256(P.encoded(linked)).hexdigest()}
    M.exact(linked_pin, OLD.PRIOR.LINKED_INPUT_PINS["candidate"])
    binding = value["binding"]
    P.require(type(binding) is dict and set(binding) == {
        "binary", "build", "capture", "module_information", "linked_module_catalog"})
    M.exact(binding["binary"], BINARY)
    for name in ("build", "capture", "module_information"):
        OLD.command(binding[name])
    M.exact(binding["capture"]["stdout"], BINARY)
    M.exact(binding["linked_module_catalog"], linked_pin)
    P.require(type(value["streams"]) is list and len(value["streams"]) == len(P.CASES))
    for row, case in zip(value["streams"], P.CASES):
        stream(row, case)
    return {
        "kind": "recorded-core-failed-Init-cleanup-check",
        "node_revision": P.P.REVISION, "runtime_tree": P.K.CANDIDATE_TREE,
        "build_tree": value["source"]["build_tree"], "source_blobs": 487,
        "corpus_sha256": CORPUS_SHA256, "binary": BINARY,
        "ordinary_builds": 1, "ordinary_processes": 2,
        "race_builds": 0, "race_processes": 0,
        "selected_cases": list(P.CASES), "linked_modules": len(linked),
        "capture_platform": "darwin/arm64", "portable_reader_platform": sys.platform,
        "new_external_dependency_transports": 0,
        "reader_reference_backend_executions": 0, "reader_downloads": 0,
        "initial_controller_outcome": "FAILURE",
        "read_only_reconciliation": "unwrapped-storage-path-error-class",
        "consumer_result": "REFUSED", "production_state_value_accepted": False,
        "scope": SCOPE,
        "reader_source_sha256": {name: hashlib.sha256((HERE / name).read_bytes()).hexdigest()
                                 for name in ("prepare_core_init_failure.py", "check_core_init_failure.py")},
    }


def check_file(path=None):
    path = HERE / "testdata" / CORPUS if path is None else Path(path)
    raw = M.read_bounded(path, 256 << 10)
    P.require(len(raw) == CORPUS_BYTES and hashlib.sha256(raw).hexdigest() == CORPUS_SHA256)
    return check_corpus(json.loads(raw, object_pairs_hook=M.pairs, parse_constant=M.constant))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--file")
    parser.add_argument("--source-revision")
    args = parser.parse_args(argv)
    P.require(args.source_revision is None or re.fullmatch("[0-9a-f]{40}", args.source_revision) is not None)
    result = check_file(args.file)
    if args.source_revision is not None:
        result["source_revision"] = args.source_revision
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, TypeError, KeyError, OSError):
        print("Recorded failed-Init cleanup refused; state values remain disabled.", file=sys.stderr)
        raise SystemExit(1)
