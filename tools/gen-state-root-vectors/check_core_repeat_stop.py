#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Check retained repeated Stop evidence; never run a reference backend."""
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
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value

PREP = load("core_repeat_stop_source_recipe", "prepare_core_repeat_stop.py")
M = PREP.M
PRIOR = load("core_repeat_stop_prior_capture", "check_core_stop_errors.py")
CORPUS = "native-core-repeated-stop.json"
CORPUS_BYTES = 157103
CORPUS_SHA256 = "81449fc212ec2a9a0f3328c27013ee45716dd09530a6b51cf3cc400b0671c1a6"
BINARY_PINS = {'baseline': {'bytes': 22624978, 'sha256': '082be38d00b23c5ca1729cdc31fc4158c6f7d765dc4589c9650f84936b7ed9ac'}, 'candidate': {'bytes': 22625202, 'sha256': 'cc0a138ede969c302ac6c0c4883316b5d6caf93c7f5ec58900ea60ca9a534668'}}
SCOPE = {
    "keyless_real_core_managers_executed": True,
    "comparison_core_Start_executed": False,
    "selected_sequential_repeated_Stop_cases_passed": True,
    "controlled_concurrent_Stop_callers_per_case": 8,
    "controlled_concurrent_Stop_cases": 2,
    "controlled_partial_protocol_Stop_executed": True,
    "concurrent_Init_Start_Stop_qualified": False,
    "full_node_or_network_qualified": False,
    "hardware_or_power_failure_qualified": False,
    "wallet_manager_created": False, "node_wrapper_created": False,
    "peer_server_created": False, "RPC_listener_started": False,
    "external_peer_configured": False, "producing_key_configured": False,
    "profile_agreement": False, "network_activation_authenticated": False,
    "accepted_header_binding": False, "production_state_value_accepted": False,
    "distribution_authenticated": False,
}
command, pin = PRIOR.command, PRIOR.pin

def stream(row, variant, mode):
    M.require(type(row) is dict and set(row) == {"case", "command", "jsonl"})
    M.exact(row["case"], mode)
    command(row["command"])
    M.require(type(row["jsonl"]) is str)
    raw = row["jsonl"].encode()
    M.exact(row["command"]["stdout"], {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
    return M.check(raw, variant, mode)

def new_passes():
    package = "github.com/zenon-network/go-zenon/zenon"
    names = PREP.new_roots() + [
        "TestCandidateCoreRepeatStop_CloseErrorsRetainIdentity/1",
        "TestCandidateCoreRepeatStop_CloseErrorsRetainIdentity/2",
        "TestCandidateCoreRepeatStop_ConcurrentCallers/0",
        "TestCandidateCoreRepeatStop_ConcurrentCallers/2",
    ]
    return [{"package": package, "name": name} for name in sorted(names)]

def tests(recording, race):
    M.require(type(recording) is dict and set(recording) == {"command", "jsonl"})
    command(recording["command"])
    M.require(type(recording["jsonl"]) is str)
    raw = recording["jsonl"].encode()
    M.require(0 < len(raw) <= 8 << 20)
    M.exact(recording["command"]["stdout"], {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
    events = [json.loads(line, object_pairs_hook=M.pairs, parse_constant=M.constant) for line in raw.splitlines()]
    M.require(not any(event.get("Action") in ("skip", "fail") for event in events))
    passes = [{"package": event["Package"], "name": event["Test"]} for event in events
              if event.get("Action") == "pass" and "Test" in event]
    expected = new_passes() if race else PRIOR.native_passes() + new_passes()
    order = lambda row: (row["package"], row["name"])
    M.exact(sorted(passes, key=order), sorted(expected, key=order))
    M.require(len(passes) == (9 if race else 71))
    roots = [row["name"] for row in passes if "/" not in row["name"]]
    M.exact(sorted(roots), PREP.new_roots() if race else PREP.roots())
    packages = {event["Package"] for event in events if event.get("Action") == "pass" and "Test" not in event}
    M.require(len(packages) == (1 if race else 5))
    return len(roots), len(passes)

def check_corpus(value):
    raw = M.encoded(value)
    M.require(len(raw) == CORPUS_BYTES and hashlib.sha256(raw).hexdigest() == CORPUS_SHA256)
    M.require(type(value) is dict and set(value) == {"format_version", "kind", "source", "native", "variants", "scope"})
    M.exact(value["format_version"], 1)
    M.exact(value["kind"], "recorded-owned-core-repeated-Stop")
    M.exact(value["scope"], SCOPE)
    M.exact(value["source"], {
        "repository": "digitalSloth/go-zenon", "revision": PREP.P.REVISION,
        "runtime_trees": {"baseline": PREP.PARENT_TREE, "candidate": PREP.CANDIDATE_TREE},
        "build_trees": {variant: PREP.P.UTIL.reconstruct_tree(PREP.build_pins(variant)) for variant in PREP.VARIANTS},
        "source_files": {"baseline": 480, "candidate": 482},
        "selection": {"bytes": M.SELECTION_BYTES, "sha256": M.SELECTION_SHA256},
        "patch": {"bytes": PREP.PATCH_BYTES, "sha256": PREP.PATCH_SHA256},
        "model": {"bytes": PREP.MODEL_BYTES, "sha256": PREP.MODEL_SHA256},
        "extra_sources": {name: {"bytes": size, "sha256": digest} for name, _, size, digest in PREP.EXTRAS},
        "go_mod_sha256": "ac08476abe3df0bc67f1c5c6868f04889b864310f16a37b0d51a6598b9017a45",
        "go_sum_sha256": "e536610c08abc9f4b979ce39cd5ae7323c3df14a189d186d911ee1d1184b8537",
    })
    native = value["native"]
    M.require(type(native) is dict and set(native) == {
        "go_version", "platform", "CGO_ENABLED", "ordinary_builds", "ordinary_processes",
        "new_external_dependency_transports", "whole_module_payload_graph_qualified", "regressions", "race", "cache_verification"})
    M.exact({key: val for key, val in native.items() if key not in ("regressions", "race", "cache_verification")}, {
        "go_version": "go1.25.14", "platform": "darwin/arm64", "CGO_ENABLED": 1,
        "ordinary_builds": 2, "ordinary_processes": 6, "new_external_dependency_transports": 0,
        "whole_module_payload_graph_qualified": False})
    roots, passes = tests(native["regressions"], False)
    race_roots, race_passes = tests(native["race"], True)
    M.require(set(native["cache_verification"]) == set(PREP.VARIANTS))
    for entry in native["cache_verification"].values():
        command(entry)
    M.require(type(value["variants"]) is dict and set(value["variants"]) == set(PREP.VARIANTS))
    panics, leaves, ready = {}, {}, 0
    for variant in PREP.VARIANTS:
        body = value["variants"][variant]
        M.require(type(body) is dict and set(body) == {"binary", "build", "capture", "module_information", "linked_module_inputs", "streams"})
        M.exact(body["binary"], BINARY_PINS[variant])
        for name in ("build", "capture", "module_information"):
            command(body[name])
        M.exact(body["capture"]["stdout"], body["binary"])
        linked = body["linked_module_inputs"]
        M.require(type(linked) is list and len(linked) == 30)
        M.exact({"bytes": len(M.encoded(linked)), "sha256": hashlib.sha256(M.encoded(linked)).hexdigest()},
                PRIOR.LINKED_INPUT_PINS["candidate"])
        M.require(type(body["streams"]) is list and len(body["streams"]) == 3)
        panics[variant], leaves[variant] = 0, 0
        for row, mode in zip(body["streams"], PREP.MODES):
            observed = stream(row, variant, mode)
            panics[variant] += int(bool(observed["repeated_stop"]["panic"]))
            leaves[variant] += len(observed["stop"]["leaf_classes"])
            ready += sum(int(observed[key]["ready"]) for key in ("before_stop", "after_stop", "after_repeated_stop"))
    M.exact(panics, {"baseline": 3, "candidate": 0})
    M.exact(leaves, {"baseline": 3, "candidate": 3})
    M.require(ready == 6)
    return {
        "kind": "recorded-core-repeated-Stop-check", "node_revision": PREP.P.REVISION,
        "parent_runtime_tree": PREP.PARENT_TREE, "candidate_runtime_tree": PREP.CANDIDATE_TREE,
        "corpus_sha256": CORPUS_SHA256, "ordinary_builds": 2, "qualified_ordinary_processes": 6,
        "baseline_repeated_Stop_panics": 3, "candidate_repeated_Stop_panics": 0,
        "first_Stop_error_leaves_per_variant": 3, "root_value_proof_observations": 18,
        "successful_root_value_proof_observations": 6, "foreign_identifier_refusals": 18,
        "native_root_tests": roots, "native_pass_results": passes,
        "race_root_tests": race_roots, "race_pass_results": race_passes,
        "native_test_skips": 0, "reference_backend_reexecuted": False,
        "production_state_value_accepted": False, "consumer_result": "REFUSED", "scope": SCOPE,
        "reader_inputs_sha256": {name: hashlib.sha256((HERE / name).read_bytes()).hexdigest()
                                for name in ("prepare_core_repeat_stop.py", "core_repeat_stop_model.py", "check_core_repeat_stop.py")},
    }

def check_file(path=None):
    path = HERE / "testdata" / CORPUS if path is None else Path(path)
    raw = M.read_bounded(path, 512 << 10)
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
        print("Recorded repeated Stop evidence refused; state values remain disabled.", file=sys.stderr)
        raise SystemExit(1)
