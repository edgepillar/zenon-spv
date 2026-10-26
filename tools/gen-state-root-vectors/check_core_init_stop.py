#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Check source-bound Init/Stop observations without executing a node."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, HERE / file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


P = load("core_init_stop_source_recipe", "prepare_core_init_stop.py")
OLD = load("core_init_stop_retained_module_inputs", "check_core_repeat_stop.py")
M = P.M
CORPUS = "native-core-init-stop.json"
CORPUS_BYTES = 36209
CORPUS_SHA256 = "c6e0c22b5d58a5ae6ecef4a144f024d23263f8c70119bd257474e1287e4be0b6"
BINARY_PINS = {
  "baseline": {
    "bytes": 22632530,
    "sha256": "66dc1bd755954ddc9889d704774451efcba2262aae52cf0fd790cdb3c95cbbad"
  },
  "candidate": {
    "bytes": 22632610,
    "sha256": "05f95241e018882a2cd2d5b86c2d6d68349b9c1b30af893b1b202360de10a268"
  },
  "race": {
    "bytes": 26643746,
    "sha256": "4a4d78f6919d44bb76986c6168a8bda7042cdc9aefc71d6756a3306a93016c8f"
  }
}
MAX_STREAM = 8192
SCOPE = {
    "real_keyless_core_managers_executed": True,
    "controlled_protocol_close_selected": True,
    "controlled_Chain_Init_scheduling_selected": True,
    "selected_Init_Stop_cases_qualified": True,
    "core_Start_executed": False,
    "uncontrolled_scheduler_interleaving_proven": False,
    "concurrent_Init_Start_Stop_qualified": False,
    "full_node_or_network_qualified": False,
    "arbitrary_initialization_or_manager_panic_recovery_qualified": False,
    "hardware_or_power_failure_qualified": False,
    "wallet_manager_created": False, "producing_key_configured": False,
    "peer_server_created": False, "RPC_listener_started": False,
    "profile_agreement": False, "activation_authenticated": False,
    "accepted_header_binding": False, "production_state_value_accepted": False,
    "independent_human_acceptance": False, "distribution_authenticated": False,
    "production_resource_budget_qualified": False,
}


def expected_observation(variant, case):
    P.require(type(variant) is str and variant in P.VARIANTS)
    P.require(type(case) is str and case in P.CASES)
    partial = case == "incomplete-Stop"
    obs = {
        "case": case,
        "Init": {"error": "stop-incomplete" if partial and variant == "candidate" else "none", "panic": ""},
        "Stop": {"error": "none", "panic": "close of closed channel" if partial else ""},
        "ready_before_Stop": not partial,
        "ready_after_Init": partial and variant == "baseline",
        "consensus_after_Init": "open" if partial else "closed",
        "Stop_completed_before_Init_release": not partial and variant == "baseline",
        "explicit_teardown": {"error": "none", "panic": ""},
        "ready_after_teardown": False, "consensus_after_teardown": "closed",
        "controlled_first_protocol_close": partial,
        "controlled_Init_scheduling": not partial,
    }
    return {
        "schema": "experimental-core-Init-Stop-observation-v1",
        "genesis": json.loads(P.R.selected_input())["genesis"],
        "observation": obs, "core_Start_selected": False,
        "network_or_wallet_or_signing_selected": False,
        "accepted_header_binding": False, "production_state_value_accepted": False}


def observation(raw, variant, case):
    P.require(type(raw) is bytes and 0 < len(raw) <= MAX_STREAM and raw.endswith(b"\n"))
    P.require(len(raw.splitlines()) == 1)
    value = json.loads(raw, object_pairs_hook=M.pairs, parse_constant=M.constant)
    M.exact(value, expected_observation(variant, case))
    return value


def stream(row, variant, case):
    P.require(type(row) is dict and set(row) == {"variant", "case", "profile", "command", "jsonl"})
    M.exact(row["variant"], variant)
    M.exact(row["case"], case)
    M.exact(row["profile"], "race" if variant == "race" else "ordinary")
    OLD.command(row["command"])
    P.require(type(row["jsonl"]) is str)
    raw = row["jsonl"].encode()
    M.exact(row["command"]["stdout"], {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
    return observation(raw, "candidate" if variant == "race" else variant, case)


def native_tests(value):
    P.require(type(value) is dict and set(value) == {"command", "jsonl"})
    OLD.command(value["command"])
    P.require(type(value["jsonl"]) is str)
    raw = value["jsonl"].encode()
    P.require(0 < len(raw) <= 8 << 20)
    M.exact(value["command"]["stdout"], {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
    events = [json.loads(line, object_pairs_hook=M.pairs, parse_constant=M.constant) for line in raw.splitlines()]
    P.require(not any(event.get("Action") in ("skip", "fail") for event in events))
    package = "github.com/zenon-network/go-zenon/zenon"
    passes = [{"package": event["Package"], "name": event["Test"]} for event in events
              if event.get("Action") == "pass" and "Test" in event]
    M.exact(sorted(passes, key=lambda row: row["name"]), OLD.new_passes())
    P.require(len(passes) == 9)
    package_passes = [event["Package"] for event in events if event.get("Action") == "pass" and "Test" not in event]
    M.exact(package_passes, [package])
    return 5, 9


def check_corpus(value):
    raw = P.encoded(value)
    P.require(len(raw) == CORPUS_BYTES and hashlib.sha256(raw).hexdigest() == CORPUS_SHA256)
    P.require(type(value) is dict and set(value) == {
        "format_version", "kind", "source", "native", "bindings", "streams", "linked_module_inputs", "scope"})
    M.exact(value["format_version"], 1)
    M.exact(value["kind"], "recorded-experimental-core-Init-Stop")
    M.exact(value["scope"], SCOPE)
    M.exact(value["source"], {
        "repository": "digitalSloth/go-zenon", "revision": P.P.REVISION, "original_tree": P.P.TREE,
        "parent_runtime_tree": P.PARENT_TREE, "candidate_runtime_tree": P.CANDIDATE_TREE,
        "source_blobs_per_build": 484,
        "build_trees": {variant: P.P.UTIL.reconstruct_tree(P.build_pins(variant)) for variant in P.VARIANTS},
        "patch": {"bytes": P.PATCH_BYTES, "sha256": P.PATCH_SHA256},
        "extras": {name: {"bytes": size, "sha256": digest} for name, _, size, digest in P.EXTRAS},
        "module_sha256": "ac08476abe3df0bc67f1c5c6868f04889b864310f16a37b0d51a6598b9017a45",
        "sum_sha256": "e536610c08abc9f4b979ce39cd5ae7323c3df14a189d186d911ee1d1184b8537"})
    native = value["native"]
    P.require(type(native) is dict and set(native) == {
        "compiler", "compiler_binary_sha256", "platform", "CGO_ENABLED", "ordinary_builds",
        "ordinary_processes", "race_builds", "race_processes", "focused_native", "cache_verification",
        "new_external_transports", "whole_native_regression_graph_reexecuted",
        "public_preparer_matches_both_actual_build_sources"})
    M.exact({key: val for key, val in native.items() if key not in ("focused_native", "cache_verification")}, {
        "compiler": "go1.25.14",
        "compiler_binary_sha256": "55770db639faa42f3ebc998ac583b008f7ff2b4bbb9dbb8a76511a9a6ffa4a19",
        "platform": "darwin/arm64", "CGO_ENABLED": 1,
        "ordinary_builds": 2, "ordinary_processes": 4, "race_builds": 1, "race_processes": 2,
        "new_external_transports": 0, "whole_native_regression_graph_reexecuted": False,
        "public_preparer_matches_both_actual_build_sources": True})
    roots, passes = native_tests(native["focused_native"])
    P.require(type(native["cache_verification"]) is dict and set(native["cache_verification"]) == {"ordinary", "race"})
    for cmd in native["cache_verification"].values():
        OLD.command(cmd)
        M.exact(cmd["stdout"], {"bytes": 21, "sha256": "b4537ed75f533f993f371954de47e42a793b8e5b0587577de7e27fb3e50696bd"})
    linked = value["linked_module_inputs"]
    P.require(type(linked) is list and len(linked) == 30)
    linked_pin = {"bytes": len(P.encoded(linked)), "sha256": hashlib.sha256(P.encoded(linked)).hexdigest()}
    M.exact(linked_pin, OLD.PRIOR.LINKED_INPUT_PINS["candidate"])
    P.require(type(value["bindings"]) is dict and set(value["bindings"]) == {"baseline", "candidate", "race"})
    for label, binding in value["bindings"].items():
        P.require(type(binding) is dict and set(binding) == {
            "binary", "build", "capture", "module_information", "linked_module_catalog"})
        M.exact(binding["binary"], BINARY_PINS[label])
        for name in ("build", "capture", "module_information"):
            OLD.command(binding[name])
        M.exact(binding["capture"]["stdout"], binding["binary"])
        M.exact(binding["linked_module_catalog"], linked_pin)
    P.require(type(value["streams"]) is list and len(value["streams"]) == 6)
    for row, (variant, case) in zip(value["streams"], [
            (variant, case) for variant in ("baseline", "candidate", "race") for case in P.CASES]):
        stream(row, variant, case)
    return {
        "kind": "recorded-core-Init-Stop-check", "node_revision": P.P.REVISION,
        "parent_runtime_tree": P.PARENT_TREE, "candidate_runtime_tree": P.CANDIDATE_TREE,
        "corpus_sha256": CORPUS_SHA256, "ordinary_builds": 2, "ordinary_processes": 4,
        "race_builds": 1, "race_processes": 2,
        "focused_native_roots": roots, "focused_native_passes": passes, "focused_native_skips": 0,
        "capture_platform": "darwin/arm64", "portable_reader_platform": sys.platform,
        "linked_modules_per_binary": len(linked), "new_external_dependency_transports": 0,
        "reader_reference_backend_executions": 0, "reader_downloads": 0,
        "consumer_result": "REFUSED", "production_state_value_accepted": False,
        "scope": SCOPE,
        "reader_source_sha256": {name: hashlib.sha256((HERE / name).read_bytes()).hexdigest()
                                 for name in ("prepare_core_init_stop.py", "check_core_init_stop.py")}}


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
        print("Recorded core Init/Stop evidence refused; state values remain disabled.", file=sys.stderr)
        raise SystemExit(1)
