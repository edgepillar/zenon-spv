#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Check recorded real-manager proof requests; launch no reference process.

Byte equality and unsigned process records do not authenticate their own origin,
a network checkpoint, an accepted header, activation or production resources.
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
spec = importlib.util.spec_from_file_location("proof_workload_recorded_recipe", HERE / "prepare_public_chain_proof_workload.py")
P = importlib.util.module_from_spec(spec)
spec.loader.exec_module(P)
M = P.M
MAX_CORPUS = 2 << 20
NATIVE_BINARY = {"sha256": "21ac545701c654c409248f29c4cfbb629009db35c79bcf420acc448fede98442", "bytes": 19815186}
REQUEST_MODEL = "fixed closed-loop workers; API pair latency excludes time before the worker starts the request"
CPU_PRECISION = "native timeval microseconds converted to nanoseconds"
SCOPE = {
    "unsigned_source_genesis": True, "actual_public_disk_managers": True,
    "controlled_ledger_or_cache_adapters": False,
    "new_reference_backend_executed_for_recording": True,
    "portable_checker_executes_reference_backend": False,
    "Chain_Start_executed": False, "Node_or_wallet_signing_user_transaction_or_network_execution": False,
    "header_authentication_executed": False, "accepted_header_binding": False,
    "profile_agreed": False, "canonicality_finality_or_activation_qualified": False,
    "snapshot_import_retention_churn_or_representative_VM_history_qualified": False,
    "speedup_or_production_resource_budget_qualified": False, "full_node_qualified": False,
    "independent_review_or_authenticated_distribution_qualified": False,
}


def require(value):
    if not value:
        raise ValueError("Recorded public Chain proof workload refused")


def constant(value):
    raise ValueError("Non-finite JSON refused")


def decoded(raw, limit):
    require(type(raw) is bytes and len(raw) <= limit)
    return json.loads(raw, object_pairs_hook=M.H.B.object_pairs, parse_constant=constant)


def integer(value, maximum=(1 << 63)-1, positive=False):
    require(type(value) is int and (1 if positive else 0) <= value <= maximum)
    return value


def digest(value):
    require(type(value) is str and re.fullmatch("[0-9a-f]{64}", value) is not None)
    return value


def check_heap(value):
    require(type(value) is dict and set(value) == {"heap_alloc_bytes", "total_alloc_bytes", "mallocs", "num_gc"})
    for number in value.values():
        integer(number, (1 << 64)-1)
    require(value["heap_alloc_bytes"] <= value["total_alloc_bytes"])


def check_usage(value, platform):
    require(type(value) is dict and set(value) == {"native_peak_rss", "native_peak_rss_unit", "SELF_lifetime_peak_rss_through_capture_bytes", "SELF_user_cpu_ns", "SELF_system_cpu_ns", "cpu_precision"})
    factor, unit = (1, "bytes") if platform == "darwin" else (1024, "KiB")
    integer(value["native_peak_rss"], positive=True)
    integer(value["SELF_lifetime_peak_rss_through_capture_bytes"], positive=True)
    require(value["native_peak_rss_unit"] == unit and value["SELF_lifetime_peak_rss_through_capture_bytes"] == value["native_peak_rss"] * factor)
    integer(value["SELF_user_cpu_ns"]); integer(value["SELF_system_cpu_ns"])
    require(value["cpu_precision"] == CPU_PRECISION)


def check_output(raw, stderr, workers, reopen):
    require(type(workers) is int and workers in M.WORKERS and type(reopen) is bool)
    require(type(raw) is bytes and len(raw) <= 256 << 10)
    expected_stderr = ("Initialized NoM. Height: 1, Hash: " + M.GENESIS["hash"] + "\n").encode()
    require(stderr == expected_stderr)
    values = [decoded(line, 256 << 10) for line in raw.splitlines()]
    stages = ["selection", "source-genesis", "initialized", "requests-completed", "stopped"]
    require(len(values) == 5 and [row.get("stage") for row in values] == stages)
    common = {"stage", "workers", "reopen"}
    for row in values:
        require(type(row) is dict and type(row["workers"]) is int and row["workers"] == workers and type(row["reopen"]) is bool and row["reopen"] is reopen)
    selected, genesis, initialized, phase, stopped = values
    require(set(selected) == common | {"selection_sha256", "requests", "keys", "go_version", "GOOS", "GOARCH", "GOMAXPROCS", "public_Chain_Init_selected", "Chain_Start_selected", "full_node_or_network_started", "wallet_signing_or_broadcast", "accepted_header_binding", "consumer_result"})
    require(selected["selection_sha256"] == P.FIXTURES["selection"][1] and selected["go_version"] == "go1.25.14")
    require(type(selected["requests"]) is int and selected["requests"] == M.REQUESTS and type(selected["keys"]) is int and selected["keys"] == 128)
    require(selected["GOOS"] in ("darwin", "linux") and selected["GOARCH"] in ("arm64", "amd64"))
    require(type(selected["GOMAXPROCS"]) is int and selected["GOMAXPROCS"] == 2)
    require(selected["public_Chain_Init_selected"] is True and selected["Chain_Start_selected"] is False and selected["full_node_or_network_started"] is False and selected["wallet_signing_or_broadcast"] is False)
    require(selected["accepted_header_binding"] is False and selected["consumer_result"] == "REFUSED")
    require(set(genesis) == common | {"identifier", "patch_sha256", "patch_bytes", "header_state_root"})
    P.P.exact(genesis["identifier"], M.GENESIS)
    require(genesis["patch_sha256"] == M.H.RAW["sha256"] and type(genesis["patch_bytes"]) is int and genesis["patch_bytes"] == M.H.RAW["bytes"] and genesis["header_state_root"] == "00"*32)
    require(set(initialized) == common | {"init_elapsed_ns", "heap_snapshot", "usage_through_capture"})
    integer(initialized["init_elapsed_ns"], positive=True); check_heap(initialized["heap_snapshot"])
    require(set(phase) == common | {"root_calls", "proof_calls", "batch_elapsed_ns", "api_pair_p50_ns", "api_pair_p95_ns", "api_pair_max_ns", "ordered_request_rows_sha256", "first_cycle_observations", "heap_before", "heap_after", "usage_before", "usage_after", "request_model", "heap_snapshots_are_not_phase_peaks", "cache_state_qualified"})
    for field in ("root_calls", "proof_calls"):
        require(type(phase[field]) is int and phase[field] == M.REQUESTS)
    for field in ("batch_elapsed_ns", "api_pair_p50_ns", "api_pair_p95_ns", "api_pair_max_ns"):
        integer(phase[field], positive=True)
    require(phase["api_pair_p50_ns"] <= phase["api_pair_p95_ns"] <= phase["api_pair_max_ns"] <= phase["batch_elapsed_ns"])
    fixtures = P.fixtures()
    expected = decoded(fixtures["expectations"], 1 << 20)
    require(phase["ordered_request_rows_sha256"] == expected["ordered_request_rows_sha256"])
    rows = [{key: row[key] for key in ("raw_key", "root", "present_in_projection", "value_hex", "proof_sha256", "proof_bytes", "row_sha256")} for row in expected["expected_rows"]]
    P.P.exact(phase["first_cycle_observations"], rows)
    require(phase["request_model"] == REQUEST_MODEL and phase["heap_snapshots_are_not_phase_peaks"] is True and phase["cache_state_qualified"] is False)
    check_heap(phase["heap_before"]); check_heap(phase["heap_after"])
    for key in ("total_alloc_bytes", "mallocs", "num_gc"):
        require(initialized["heap_snapshot"][key] <= phase["heap_before"][key] <= phase["heap_after"][key])
    require(set(stopped) == common | {"stop_elapsed_ns", "main_elapsed_through_report_ns", "closed_root_and_proof_refused", "usage_through_capture", "process_peak_RSS_through_exit_measured", "accepted_header_binding", "production_state_value_accepted", "consumer_result"})
    integer(stopped["stop_elapsed_ns"], positive=True); integer(stopped["main_elapsed_through_report_ns"], positive=True)
    require(stopped["main_elapsed_through_report_ns"] >= phase["batch_elapsed_ns"] + initialized["init_elapsed_ns"] + stopped["stop_elapsed_ns"])
    require(stopped["closed_root_and_proof_refused"] is True and stopped["process_peak_RSS_through_exit_measured"] is False)
    require(stopped["accepted_header_binding"] is False and stopped["production_state_value_accepted"] is False and stopped["consumer_result"] == "REFUSED")
    usages = [initialized["usage_through_capture"], phase["usage_before"], phase["usage_after"], stopped["usage_through_capture"]]
    for usage in usages:
        check_usage(usage, selected["GOOS"])
    for key in ("native_peak_rss", "SELF_user_cpu_ns", "SELF_system_cpu_ns"):
        require([usage[key] for usage in usages] == sorted(usage[key] for usage in usages))
    return values


def check_command(command, stdout=None, stderr=None):
    require(type(command) is dict and set(command) == {"completed", "actual_exit", "output_complete", "stdout_sha256", "stderr_sha256", "stdout_bytes", "stderr_bytes"})
    require(command["completed"] is True and type(command["actual_exit"]) is int and command["actual_exit"] == 0 and command["output_complete"] is True)
    for name, raw in (("stdout", stdout), ("stderr", stderr)):
        digest(command[name + "_sha256"]); integer(command[name + "_bytes"], 128 << 20)
        if raw is not None:
            require(command[name + "_sha256"] == hashlib.sha256(raw).hexdigest() and command[name + "_bytes"] == len(raw))


def check_corpus(document):
    require(type(document) is dict and set(document) == {"format_version", "kind", "source", "execution", "cases", "scope", "consumer_result", "production_state_value_accepted", "proven"})
    require(type(document["format_version"]) is int and document["format_version"] == 1 and document["kind"] == "native-public-chain-proof-workload")
    P.P.exact(document["scope"], SCOPE)
    require(document["consumer_result"] == "REFUSED" and document["production_state_value_accepted"] is False and document["proven"] == [])
    source, execution = document["source"], document["execution"]
    pins = P.build_pins()
    P.P.exact(source, {"repository": "https://github.com/digitalSloth/go-zenon", "revision": M.REVISION,
        "original_tree": P.P.TREE, "runtime_tree": M.RUNTIME_TREE, "build_tree": P.P.UTIL.reconstruct_tree(pins),
        "source_blobs": 472, "probe": {"sha256": P.PROBE_SHA256, "bytes": P.PROBE_BYTES},
        "selection": {"sha256": P.FIXTURES["selection"][1], "bytes": P.FIXTURES["selection"][0]},
        "expectations": {"sha256": P.FIXTURES["expectations"][1], "bytes": P.FIXTURES["expectations"][0]},
        "module_sha256": pins["go.mod"]["sha256"], "sum_sha256": pins["go.sum"]["sha256"]})
    require(type(execution) is dict and set(execution) == {"compiler", "compiler_binary_sha256", "binary", "buildinfo_stdout_utf8", "commands", "ordinary_builds", "ordinary_processes", "linked_modules_per_binary", "new_external_transports", "component_retries", "reference_platform", "whole_module_archive_graph_verification", "initial_collector_outcome", "initial_failure_preserved", "first_case_reexecuted", "original_binary_rebuilt", "resource_scope"})
    require(execution["compiler"] == "go1.25.14" and execution["compiler_binary_sha256"] == "55770db639faa42f3ebc998ac583b008f7ff2b4bbb9dbb8a76511a9a6ffa4a19")
    P.P.exact(execution["binary"], NATIVE_BINARY)
    for key, value in (("ordinary_builds", 1), ("ordinary_processes", 4), ("linked_modules_per_binary", 25), ("new_external_transports", 0), ("component_retries", 0)):
        require(type(execution[key]) is int and execution[key] == value)
    require(execution["reference_platform"] == "darwin-arm64" and execution["whole_module_archive_graph_verification"] == "NOT_QUALIFIED")
    require(execution["initial_collector_outcome"] == "FAILURE_AFTER_COMPLETE_FIRST_CASE" and execution["initial_failure_preserved"] is True and execution["first_case_reexecuted"] is False and execution["original_binary_rebuilt"] is False)
    resource = execution["resource_scope"]
    P.P.exact(resource, {"production_minimum_free_bytes": 10 << 30, "first_task_expected_allocation_bytes": 2 << 30,
        "first_task_quota_bytes": 3 << 30, "resumed_task_expected_allocation_bytes": 512 << 20, "resumed_task_quota_bytes": 1 << 30,
        "owned_scratch_absent": True, "physical_disk_reclaim_measured": False,
        "heap_snapshots_are_not_phase_peaks": True, "SELF_peak_RSS_through_capture_observed": True,
        "process_peak_RSS_through_exit_measured": False, "whole_pipeline_peak_memory_measured": False})
    info = decoded(execution["buildinfo_stdout_utf8"].encode(), 64 << 10)
    require(info["GoVersion"] == "go1.25.14" and info["Path"] == "github.com/zenon-network/go-zenon/cmd/candidate-public-chain-proof-workload")
    require(info["Main"]["Path"] == "github.com/zenon-network/go-zenon" and info["Main"]["Version"] == "(devel)")
    old = decoded(P.P.read_regular(HERE / "testdata/native-public-chain-reorg-reopen.json", 128 << 10), 128 << 10)
    oldinfo = decoded(old["execution"]["buildinfo_stdout_utf8"].encode(), 64 << 10)
    P.P.exact(info["Deps"], oldinfo["Deps"])
    require(old["source"]["module_sha256"] == source["module_sha256"] and old["source"]["sum_sha256"] == source["sum_sha256"])
    settings = {row["Key"]: row["Value"] for row in info["Settings"]}
    require(settings["-trimpath"] == "true" and settings.get("-race") != "true" and settings.get("-cover") != "true" and settings["GOOS"] == "darwin" and settings["GOARCH"] == "arm64")
    require(set(execution["commands"]) == {"build", "vet", "buildinfo", "binary_capture"})
    for command in execution["commands"].values():
        check_command(command)
    check_command(execution["commands"]["buildinfo"], execution["buildinfo_stdout_utf8"].encode(), b"")
    require(execution["commands"]["binary_capture"]["stdout_sha256"] == execution["binary"]["sha256"] and execution["commands"]["binary_capture"]["stdout_bytes"] == execution["binary"]["bytes"])
    require(type(document["cases"]) is list and len(document["cases"]) == 4)
    wanted = [(1, False), (4, False), (16, False), (4, True)]
    samples = []
    for index, (case, (workers, reopen)) in enumerate(zip(document["cases"], wanted)):
        require(type(case) is dict and set(case) == {"workers", "reopen", "stdout_utf8", "stderr_utf8", "command", "closed_file_lengths", "physical_allocated_bytes_measured", "reused_complete_actual_execution"})
        require(type(case["workers"]) is int and case["workers"] == workers and type(case["reopen"]) is bool and case["reopen"] is reopen)
        require(case["reused_complete_actual_execution"] is (index == 0) and case["physical_allocated_bytes_measured"] is False)
        raw, stderr = case["stdout_utf8"].encode(), case["stderr_utf8"].encode()
        check_command(case["command"], raw, stderr)
        rows = check_output(raw, stderr, workers, reopen)
        require(rows[0]["GOOS"] == "darwin" and rows[0]["GOARCH"] == "arm64")
        require(set(case["closed_file_lengths"]) == {"ledger", "cache", "tree"})
        for store in case["closed_file_lengths"].values():
            require(set(store) == {"regular_files", "sum_file_lengths", "largest_file_length"})
            for value in store.values(): integer(value, positive=True)
            require(store["largest_file_length"] <= store["sum_file_lengths"])
        samples.append({"workers": workers, "reopen": reopen, "requests": M.REQUESTS,
                        "batch_elapsed_ns": rows[3]["batch_elapsed_ns"],
                        "api_pair_p50_ns": rows[3]["api_pair_p50_ns"], "api_pair_p95_ns": rows[3]["api_pair_p95_ns"],
                        "SELF_lifetime_peak_RSS_through_final_capture_bytes": rows[4]["usage_through_capture"]["SELF_lifetime_peak_rss_through_capture_bytes"],
                        "closed_store_sum_file_lengths": sum(store["sum_file_lengths"] for store in case["closed_file_lengths"].values())})
    return {"recorded_real_manager_processes": 4, "recorded_ordinary_builds": 1,
            "timed_request_pairs": 16384, "timed_root_and_proof_API_calls": 32768,
            "separate_post_Stop_refusal_API_calls": 8, "independent_witnesses_per_process": 128,
            "recorded_closed_file_length_observations": 12, "resource_observations": samples,
            "new_reference_backend_executions": 0, "native_resource_measurements_performed_by_this_reader": 0,
            "accepted_header_binding": False, "production_state_value_accepted": False,
            "execution_provenance_authenticated": False, "consumer_result": "REFUSED"}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, default=HERE / "testdata/native-public-chain-proof-workload.json")
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
        print("Recorded proof workload refused; state-value acceptance remains disabled.", file=sys.stderr)
        sys.exit(1)
