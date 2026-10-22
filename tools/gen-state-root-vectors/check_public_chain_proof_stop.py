#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Check recorded public Chain read/Stop observations without starting a node.

Recorded bytes are unsigned evidence. This reader does not authenticate their
origin, a header commitment, network activation or production resource limits.
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


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


P = load("recorded_read_Stop_recipe", "prepare_public_chain_proof_stop.py")
W = load("recorded_read_Stop_parent", "check_public_chain_proof_workload.py")
M, S = P.M, P.S
MAX_CORPUS = 4 << 20
NATIVE_BINARIES = {
    "ordinary": {"sha256": "ab48a375fb6002b2b6d5431a874431cd3085414a1c144ffd58b19a89b61387aa", "bytes": 19831346},
    "race": {"sha256": "4f77cf7182f9268e16fa70e53d51b1146bcc4e14bddda2f8349d37b064c1e9e8", "bytes": 23261858},
}
NATIVE_PROFILE_OUTCOMES = {"ordinary": "INCONCLUSIVE", "race": "MATCH"}
INITIAL_PROBE = {"sha256": "98d2f37ee6fe424d4c16dfb1341dee07ca3c6f1278c98fc8e42576106986cce6", "bytes": 10894}
INITIAL_BINARIES = {
    "ordinary": {"sha256": "e36802a7fed1d946e5960d7fa5b3c73685e0d3b3d81bb377bee63c4f0489e59f", "bytes": 19831170},
    "race": {"sha256": "89bf2edfea7c5b9358294f29f8d67e7a16a693def16526edb937a463c588616b", "bytes": 23261682},
}
INITIAL_STDOUT = {
    "ordinary": {"sha256": "5591518dfee928533ca7e0324d129387d23aeb03850b7efc16ef797516975bea", "bytes": 754966},
    "race": {"sha256": "4870e9553bd6005ef2cd53bc7f4d9c67a82822cd6068ef8b721cc2da1b2dbc0c", "bytes": 762074},
}
SCOPE = {
    "unsigned_source_genesis": True,
    "actual_public_disk_managers": True,
    "controlled_ledger_or_cache_adapters": False,
    "new_reference_backend_executed_for_recording": True,
    "portable_checker_executes_reference_backend": False,
    "Chain_Start_executed": False,
    "Node_or_wallet_signing_user_transaction_or_chain_network_execution": False,
    "header_authentication_executed": False,
    "accepted_header_binding": False,
    "profile_agreed": False,
    "canonicality_finality_or_activation_qualified": False,
    "internal_database_interleaving_proven": False,
    "snapshot_import_retention_churn_or_representative_VM_history_qualified": False,
    "speedup_or_production_resource_budget_qualified": False,
    "full_M4_qualified": False,
    "independent_review_or_authenticated_distribution_qualified": False,
}


def require(value):
    if not value:
        raise ValueError("Recorded public Chain read/Stop observations refused")


def exact(actual, expected):
    P.P.exact(actual, expected)


def decoded(raw, limit):
    return W.decoded(raw, limit)


def buildinfo(raw, profile):
    value = decoded(raw, 64 << 10)
    require(value["GoVersion"] == "go1.25.14")
    require(value["Path"] == "github.com/zenon-network/go-zenon/cmd/candidate-public-chain-proof-stop")
    require(value["Main"]["Path"] == "github.com/zenon-network/go-zenon" and value["Main"]["Version"] == "(devel)")
    parent = decoded(P.P.read_regular(HERE / "testdata/native-public-chain-reorg-reopen.json", 128 << 10), 128 << 10)
    parent_info = decoded(parent["execution"]["buildinfo_stdout_utf8"].encode(), 64 << 10)
    exact(value["Deps"], parent_info["Deps"])
    require(len(value["Deps"]) == 25)
    settings = value["Settings"]
    require(type(settings) is list and all(type(row) is dict and set(row) == {"Key", "Value"} for row in settings))
    require(len({row["Key"] for row in settings}) == len(settings))
    flags = {row["Key"]: row["Value"] for row in settings}
    require(flags["-trimpath"] == "true" and flags.get("-cover") != "true")
    require(flags["-tags"] == P.TAG and flags["CGO_ENABLED"] == "1")
    require((flags.get("-race") == "true") is (profile == "race"))
    require(flags["GOOS"] == "darwin" and flags["GOARCH"] == "arm64")
    return value


def check_initial_failure(value, expectations):
    require(type(value) is dict and set(value) == {
        "probe", "frame_order", "required_frame_order", "profiles",
        "original_contract_sha256", "original_complete_outputs_retained",
        "original_outcome", "core_runtime_defect_established"})
    exact(value["probe"], INITIAL_PROBE)
    exact(value["frame_order"], ["root", "key", "value", "proof"])
    exact(value["required_frame_order"], ["key", "value", "root", "proof"])
    require(value["original_contract_sha256"] == S.CONTRACT_SHA256)
    require(value["original_complete_outputs_retained"] is True)
    require(value["original_outcome"] == "COMPONENT_FAILURE_BOTH_PROFILES")
    require(value["core_runtime_defect_established"] is False)
    alternate = []
    for row in expectations["expected_rows"]:
        fields = (bytes.fromhex(row["root"]), bytes.fromhex(row["raw_key"]),
                  bytes.fromhex(row["value_hex"]) if row["present_in_projection"] else None,
                  bytes.fromhex(row["proof_hex"]))
        raw = b"".join(bytes([int(part is not None)]) +
                       (0 if part is None else len(part)).to_bytes(8, "big") +
                       (b"" if part is None else part) for part in fields)
        alternate.append(hashlib.sha256(raw).hexdigest())
    require(all(a != row["row_sha256"] for a, row in zip(alternate, expectations["expected_rows"])))
    require(type(value["profiles"]) is list and len(value["profiles"]) == 2)
    for row, profile in zip(value["profiles"], ("ordinary", "race")):
        require(type(row) is dict and set(row) == {
            "profile", "binary", "command", "observed_warmup_row_sha256s", "stderr_utf8"})
        require(row["profile"] == profile)
        exact(row["binary"], INITIAL_BINARIES[profile])
        W.check_command(row["command"], stderr=row["stderr_utf8"].encode())
        require(row["command"]["stdout_sha256"] == INITIAL_STDOUT[profile]["sha256"] and
                row["command"]["stdout_bytes"] == INITIAL_STDOUT[profile]["bytes"])
        require(row["stderr_utf8"] == "Initialized NoM. Height: 1, Hash: " + M.GENESIS["hash"] + "\n")
        exact(row["observed_warmup_row_sha256s"], alternate)


def check_corpus(document):
    require(type(document) is dict and set(document) == {
        "format_version", "kind", "source", "execution", "initial_framing_failure",
        "cases", "scope", "component_overlap_qualified", "consumer_result", "production_state_value_accepted", "proven"})
    require(type(document["format_version"]) is int and document["format_version"] == 1)
    require(document["kind"] == "native-public-chain-proof-stop")
    exact(document["scope"], SCOPE)
    require(document["consumer_result"] == "REFUSED" and document["production_state_value_accepted"] is False and document["proven"] == [])
    pins = P.build_pins()
    exact(document["source"], {
        "repository": "https://github.com/digitalSloth/go-zenon", "revision": M.REVISION,
        "original_tree": P.C.P.TREE, "runtime_tree": M.RUNTIME_TREE,
        "build_tree": P.P.UTIL.reconstruct_tree(pins), "source_blobs": 472,
        "probe": {"sha256": P.PROBE_SHA256, "bytes": P.PROBE_BYTES},
        "selection": {"sha256": P.FIXTURES["selection"][1], "bytes": P.FIXTURES["selection"][0]},
        "contract": {"sha256": P.FIXTURES["contract"][1], "bytes": P.FIXTURES["contract"][0]},
        "module_sha256": pins["go.mod"]["sha256"], "sum_sha256": pins["go.sum"]["sha256"],
    })
    fixtures = {name: decoded(raw, 1 << 20) for name, raw in P.fixtures().items()}
    parent_raw = P.P.read_regular(HERE / "testdata/public-chain-proof-workload-expectations.json", 1 << 20)
    size, digest = P.W.FIXTURES["expectations"]
    require(len(parent_raw) == size and hashlib.sha256(parent_raw).hexdigest() == digest)
    check_initial_failure(document["initial_framing_failure"], decoded(parent_raw, 1 << 20))
    exact(document["execution"], {
        "compiler": "go1.25.14",
        "compiler_binary_sha256": "55770db639faa42f3ebc998ac583b008f7ff2b4bbb9dbb8a76511a9a6ffa4a19",
        "reference_platform": "darwin-arm64", "selected_profiles": ["ordinary", "race"],
        "selected_builds": 2, "selected_process_attempts_per_profile": 1,
        "actual_recorded_processes": 2, "linked_modules_per_binary": 25,
        "new_external_transports": 0, "automatic_component_retries": 0,
        "initial_failed_producer_builds": 2, "initial_failed_producer_processes": 2,
        "corrected_producer_rebuilt": True, "core_runtime_changed": False,
        "whole_module_archive_graph_verification": "NOT_QUALIFIED",
        "resource_scope": {
            "production_minimum_free_bytes": 10 << 30,
            "expected_allocation_bytes": 1536 << 20, "task_quota_bytes": 4 << 30,
            "owned_scratch_absent": True, "physical_disk_reclaim_measured": False,
            "native_phase_memory_or_performance_budget_qualified": False,
        },
    })
    cases = document["cases"]
    require(type(cases) is list and len(cases) == 2 and set(NATIVE_BINARIES) == set(NATIVE_PROFILE_OUTCOMES) == {"ordinary", "race"})
    results = []
    for case, profile in zip(cases, ("ordinary", "race")):
        require(type(case) is dict and set(case) == {
            "profile", "binary", "buildinfo_stdout_utf8", "commands", "stdout_utf8",
            "stderr_utf8", "closed_file_lengths", "physical_allocated_bytes_measured"})
        require(case["profile"] == profile and case["physical_allocated_bytes_measured"] is False)
        exact(case["binary"], NATIVE_BINARIES[profile])
        info_raw = case["buildinfo_stdout_utf8"].encode()
        buildinfo(info_raw, profile)
        commands = case["commands"]
        require(type(commands) is dict and set(commands) ==
                {"build", "binary_capture", "buildinfo", "case"} | ({"vet"} if profile == "ordinary" else set()))
        for command in commands.values():
            W.check_command(command)
        W.check_command(commands["buildinfo"], info_raw, b"")
        require(commands["binary_capture"]["stdout_sha256"] == case["binary"]["sha256"] and
                commands["binary_capture"]["stdout_bytes"] == case["binary"]["bytes"])
        raw, stderr = case["stdout_utf8"].encode(), case["stderr_utf8"].encode()
        W.check_command(commands["case"], raw, stderr)
        require(stderr == ("Initialized NoM. Height: 1, Hash: " + M.GENESIS["hash"] + "\n").encode())
        observation = decoded(raw, 2 << 20)
        result = S.validate(fixtures["contract"], observation, profile)
        require(result["status"] in ("MATCH", "INCONCLUSIVE") and result["status"] == NATIVE_PROFILE_OUTCOMES[profile])
        stores = case["closed_file_lengths"]
        require(type(stores) is dict and set(stores) == {"ledger", "cache", "tree"})
        for store in stores.values():
            require(type(store) is dict and set(store) == {"regular_files", "sum_file_lengths", "largest_file_length"})
            for number in store.values():
                W.integer(number, positive=True)
            require(store["largest_file_length"] <= store["sum_file_lengths"])
        results.append(result)
    qualified = all(row["status"] == "MATCH" for row in results)
    require(document["component_overlap_qualified"] is qualified)
    return {
        "recorded_corrected_producer_processes": 2, "total_recorded_reference_processes": 4,
        "recorded_ordinary_builds": 1,
        "recorded_race_builds": 1, "recorded_initial_framing_failure_processes": 2,
        "independent_warmup_witnesses_per_process": 128,
        "concurrent_request_pairs": 4096, "individual_Root_and_GetProof_calls": 8708,
        "profile_results": results, "new_reference_backend_executions": 0,
        "component_read_Stop_overlap_qualified": qualified,
        "native_resource_measurements_performed_by_this_reader": 0,
        "internal_database_interleaving_proven": False, "full_M4_qualified": False,
        "accepted_header_binding": False, "production_state_value_accepted": False,
        "execution_provenance_authenticated": False, "consumer_result": "REFUSED",
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, default=HERE / "testdata/native-public-chain-proof-stop.json")
    parser.add_argument("--source-revision")
    args = parser.parse_args(argv)
    require(args.source_revision is None or re.fullmatch("[0-9a-f]{40}", args.source_revision) is not None)
    raw = P.P.read_regular(args.corpus, MAX_CORPUS)
    result = check_corpus(decoded(raw, MAX_CORPUS))
    result.update(corpus_sha256=hashlib.sha256(raw).hexdigest(), source_revision=args.source_revision,
                  node_revision=M.REVISION, runtime_tree=M.RUNTIME_TREE)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, IndexError, AssertionError):
        print("Recorded read/Stop observations refused; state-value acceptance remains disabled.", file=sys.stderr)
        sys.exit(1)
