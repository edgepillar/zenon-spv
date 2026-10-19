#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Check recorded native cache replay-patch observations without a backend.

The shared genesis metadata is decoded once per check. Full source-augmented
genesis patch digests remain native/private-byte-check observations; this
reader does not execute the genesis VM or authenticate execution receipts.
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


def load(name):
    spec = importlib.util.spec_from_file_location("recorded_" + name, HERE / (name + ".py"))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


H = load("prepare_cache_replay_patches")
R = load("cache_replay_patch_records")
B = load("cache_replay_patch_bytes")
P, W = H.P, R.W
CORPUS = "native-cache-replay-patches.json"
CORPUS_SHA256 = "d734c30f6d1f027238c18f0cbfcab053b4f13513395552a1dd5e4b063a894d66"
CORPUS_BYTES = 190971
MAX_BYTES = 512 << 10
EXECUTION_SHA256 = "68a784715e2258ed5dda8e80ea4e454e2806b9477b0bdac593b8c008f2472bce"
GENESIS_METADATA = "testdata/cache-replay-patch-genesis-metadata.bin"
GENESIS_CHANGES_HASH = "fe37ddbea9fc05b16cd91e8b50d6aa74c1754f00f3339c3512717fe92fdb3d78"
SCOPE = {
    "real_public_Chain_Init_and_Stop": True,
    "real_disk_ledger_cache_and_NodeTree_managers": True,
    "source_embedded_unsigned_genesis_VM": True,
    "three_local_unsigned_successor_momentums": True,
    "controlled_closed_ledger_patch_removal": True,
    "explicit_fixture_restore_separate_from_runtime": True,
    "required_patch_availability_preflight": True,
    "empty_content_nil_patch_allowed": True,
    "apply_pass_patch_rechecked": True,
    "caller_recovered_Init_panics_explicit": True,
    "all_prior_46_native_pass_names_retained": True,
    "full_genesis_metadata_decoded_by_public_reader": True,
    "full_empty_successor_metadata_decoded_by_public_reader": True,
    "hosted_checks_replay_recorded_bytes": True,
    "process_exit_zero_implies_startup_success": False,
    "genesis_source_patch_dump_rehashed_by_public_reader": False,
    "complete_augmented_genesis_patch_rehashed_by_public_reader": False,
    "complete_logical_stores_rebuilt_by_public_reader": False,
    "private_execution_receipts_authenticated": False,
    "Chain_Start_called": False,
    "network_or_consensus_executed": False,
    "full_node_service_executed": False,
    "whole_window_IO_atomicity_claimed": False,
    "complete_patch_retention_qualified": False,
    "runtime_repairs_missing_ledger_entries": False,
    "test_overlays_or_scheduler_hooks": False,
    "live_reorg_qualified": False,
    "power_loss_qualified": False,
    "concurrent_lifecycle_qualified": False,
    "representative_resource_budget_qualified": False,
    "node_client_profile_agreed": False,
    "network_activation_authenticated": False,
    "accepted_header_binding": False,
    "runtime_state_value_acceptance": False,
    "production_qualified": False,
    "checker_executes_reference_backend": False,
}
INPUTS = tuple(dict.fromkeys((
    "check_cache_replay_patches.py", "prepare_cache_replay_patches.py", H.PATCH, H.PROBE, H.RETAINED_PROBE, H.CONTROL, H.COMPAT_CONTROL,
    "cache_replay_patch_records.py", "cache_replay_patch_bytes.py", GENESIS_METADATA,
    "check_cache_replay_window.py", "testdata/" + R.WINDOW.CORPUS, *R.WINDOW.INPUTS,
)))


def document(raw):
    P.require(type(raw) is bytes and 0 < len(raw) <= MAX_BYTES)
    def constant(_):
        raise ValueError("Non-finite JSON refused")
    return json.loads(raw, object_pairs_hook=P.pairs, parse_constant=constant)


def expected_source():
    plan = H.plan("NEW_OWNED_WORKSPACE", "PINNED_GO")
    previous = R.WINDOW.expected_source()
    controls = dict(previous["native_controls"])
    controls.pop(H.H.CONTROL)
    controls[H.COMPAT_CONTROL] = {"target": H.H.CONTROL_TARGET, "bytes": H.COMPAT_BYTES, "sha256": H.COMPAT_SHA256}
    controls[H.CONTROL] = {"target": H.CONTROL_TARGET, "bytes": H.CONTROL_BYTES, "sha256": H.CONTROL_SHA256}
    return {
        "repository": "https://github.com/digitalSloth/go-zenon", "revision": P.REVISION,
        "original_tree": P.TREE, "original_source_blobs": 467,
        "parent_compiled_source_blobs": 472, "candidate_compiled_source_blobs": 473,
        "source_manifest_sha256": P.SOURCE_SHA256,
        "parent_runtime_tree": H.H.MODIFIED_TREE, "candidate_runtime_tree": H.MODIFIED_TREE,
        "retained_positive_build_tree": H.retained_positive_build_tree(),
        "parent_remaining_build_tree": H.parent_build_tree(), "candidate_build_tree": H.BUILD_TREE,
        "retained_positive_probe": plan["retained_positive_probe"],
        "parent_remaining_probe": plan["recorded_parent_probe"], "candidate_probe": plan["probe"],
        "patch_sha256": H.PATCH_SHA256, "module_sha256": plan["module_sha256"],
        "sum_sha256": plan["sum_sha256"], "native_controls": controls,
        "genesis_changes_sha3_256": GENESIS_CHANGES_HASH,
        "metadata_capture": dict(R.PATCH_MODELS[1], file=GENESIS_METADATA),
    }


def command_projection(value):
    P.require(type(value) is dict)
    fields = {"state", "actual_exit", "output_complete", "reason", "stdout", "stderr"}
    P.require(set(value) == fields)
    return value


def execution(value):
    P.require(type(value) is dict and P.sha(P.UTIL.encoded(value)) == EXECUTION_SHA256)
    P.exact([value[k] for k in ("ordinary_entrypoint_builds", "retained_parent_ordinary_builds",
                               "new_candidate_ordinary_builds", "intended_case_processes",
                               "retained_parent_case_processes", "new_candidate_case_processes",
                               "separate_failed_pre_Init_fixture_processes", "parent_backend_reexecuted")],
            [3, 2, 1, 10, 5, 5, 1, False])
    P.exact([value[k] for k in ("compiler", "recorded_reference_platform", "new_source_or_dependency_network_transports",
                               "verified_dependency_inputs", "linked_modules", "whole_module_graph_verification",
                               "candidate_task_outcome", "candidate_scratch_cleanup", "physical_reclaim_claimed")],
            ["go1.25.14", "darwin/arm64", 0, 75, 25, "NOT_QUALIFIED", "SUCCESS", "CLEANED", False])
    P.exact(value["retained_parent_task_outcomes"],
            ["FAILURE_DUE_TO_LATER_FIXTURE_ASSERTION", "FAILURE_DUE_TO_POST_EXPERIMENT_CALLER_CLEANUP"])
    for name in ("retained_positive_build", "retained_remaining_build", "candidate_build"):
        R.WINDOW.command(command_projection(value[name]))
    R.WINDOW.command(command_projection(value["separate_failed_fixture_command"]), actual_exit=2)
    R.WINDOW.command(command_projection(value["prior_candidate_control_compile_failure"]), actual_exit=1)
    P.exact(value["prior_candidate_control_compile_failure_passed_storage_tests"], 18)
    for name in ("retained_positive_binary", "retained_remaining_binary", "candidate_binary"):
        R.WINDOW.ref(value[name])
    P.require(len({value[name]["sha256"] for name in
                   ("retained_positive_binary", "retained_remaining_binary", "candidate_binary")}) == 3)
    modules = value["linked_module_details"]
    P.require(type(modules) is list and len(modules) == 25 and len({row["module"] for row in modules}) == 25)
    for row in modules:
        P.require(type(row) is dict and set(row) == {"module", "version", "go_sum"})
        P.require(all(type(row[key]) is str and 0 < len(row[key]) < 256 for key in row))
        P.require(re.fullmatch(r"h1:[A-Za-z0-9+/]{43}=", row["go_sum"]) is not None)
    units = value["native_unit_controls"]
    P.require(type(units) is dict and set(units) == {"race_detector", "root_tests", "test_pass_results", "package_pass_results",
                                                    "skipped_or_failed", "selected_roots", "test_pass_names", "command"})
    R.WINDOW.command(command_projection(units["command"]))
    P.exact([units[k] for k in ("race_detector", "root_tests", "test_pass_results", "package_pass_results", "skipped_or_failed")],
            [True, 15, 58, 2, 0])
    P.exact(units["selected_roots"], list(H.NATIVE_ROOTS))
    names = units["test_pass_names"]
    P.require(type(names) is list and len(names) == len(set(names)) == 58)
    P.require(all(type(name) is str and len(name) < 256 and name.split("/")[0] in H.NATIVE_ROOTS for name in names))
    P.exact(sorted(name for name in names if "/" not in name), list(H.NATIVE_ROOTS))
    old = R.WINDOW.document(P.read_regular(HERE / "testdata" / R.WINDOW.CORPUS, R.WINDOW.MAX_BYTES))
    P.require(set(old["execution"]["native_unit_controls"]["test_pass_names"]) <= set(names))


def metadata_models():
    raw = P.read_regular(HERE / GENESIS_METADATA, B.MAX_METADATA_BYTES)
    expected = R.PATCH_MODELS[1]
    P.require(len(raw) == expected["metadata_bytes"] and P.sha(raw) == expected["metadata_sha256"])
    ids = R.WINDOW.identifiers()
    genesis = B.verify_metadata(raw, ids["A1"], R.WINDOW.ZERO, 1637755200,
                                bytes.fromhex(GENESIS_CHANGES_HASH), 14094)
    # This tiny complete patch is independently reconstructible without a
    # source genesis VM dump. Its MomentumProto is the earlier v1 byte model.
    _, wrapped = R.WINDOW.removed_entry(2)
    digest = bytes.fromhex(ids["A2"]["hash"])
    identifier = b"\x0a\x22\x0a\x20" + digest + b"\x10\x02"
    def put(key, value):
        return b"\x01" + R.WINDOW.varint(len(key)) + key + R.WINDOW.varint(len(value)) + value
    empty = put(b"\0", identifier) + put(b"\1" + digest, bytes.fromhex("0000000000000002"))
    empty += put(b"\2" + bytes.fromhex("0000000000000002"), wrapped[1:])
    successor = B.verify_metadata(empty, ids["A2"], ids["A1"]["hash"], 1637755210, hashlib.sha3_256(b"").digest(), 0)
    P.require(P.sha(empty) == R.PATCH_MODELS[2]["expected_stored_sha256"])
    result = {}
    for height, report in ((1, genesis), (2, successor)):
        model = R.PATCH_MODELS[height]
        report.update({key: model[key] for key in
                       ("source_changes_bytes", "source_changes_sha256", "expected_stored_bytes", "expected_stored_sha256")})
        R.metadata_report(report, height)
        result[height] = report
    return result


def check_corpus(value):
    P.require(type(value) is dict and set(value) == {"format_version", "kind", "source", "execution", "scope", "cases", "consumer_result"})
    P.exact([value["format_version"], value["kind"], value["consumer_result"]],
            [1, "recorded-native-cache-replay-patches", "REFUSED"])
    P.exact(value["source"], expected_source())
    P.exact(value["scope"], SCOPE)
    execution(value["execution"])
    models = metadata_models()
    rows = value["cases"]
    P.require(type(rows) is list and len(rows) == 10)
    phases = []
    snapshots, final_caches = [], []
    for phase, generation in enumerate(("parent", "candidate")):
        selected = rows[phase * 5:(phase + 1) * 5]
        projected = []
        for index, (case, row) in enumerate(zip(H.CASES, selected)):
            P.require(type(row) is dict and set(row) == {"generation", "case", "build_tree", "ordinary_binary", "command", "stdout_utf8", "metadata_report"})
            P.exact([row["generation"], row["case"]], [generation, case])
            tree = H.BUILD_TREE if generation == "candidate" else H.RETAINED_POSITIVE_BUILD_TREE if index == 0 else H.PARENT_BUILD_TREE
            binary = value["execution"]["candidate_binary"] if generation == "candidate" else value["execution"]["retained_positive_binary"] if index == 0 else value["execution"]["retained_remaining_binary"]
            P.exact(row["build_tree"], tree)
            P.exact(row["ordinary_binary"], binary)
            P.exact(row["metadata_report"], None if index == 0 else models[2 if index == 4 else 1])
            projected.append({key: row[key] for key in ("case", "command", "stdout_utf8", "metadata_report")})
            text = row["stdout_utf8"]
            P.require(type(text) is str and 0 < len(text.encode()) <= R.MAX_STDOUT_BYTES and text.endswith("\n"))
            events = [document(line.encode()) for line in text.splitlines()]
            P.require(all(type(event) is dict for event in events))
            snapshots.extend({"generation": generation, "case": case, "event": event}
                             for event in events if "raw_store_sha256" in event)
            final = [event for event in events if event.get("stage") == "cache-after-public-stop"]
            P.require(bool(final))
            final_caches.append(R.WINDOW.cache_projection(final[-1]))
        phases.append(R.check_generation(generation, projected))
    P.require(all(cache == final_caches[0] for cache in final_caches))
    P.require(phases[0]["init_panics"] == 2 and phases[1]["init_panics"] == 0 and phases[1]["candidate_prewrite_refusals"] == 2)
    return {
        "kind": "recorded-native-cache-replay-patch-check", "recorded_cases": 10,
        "recorded_raw_exits": [0] * 10, "recorded_event_observations": 260,
        "recorded_public_queries": 36, "recorded_available_component_queries": 32,
        "recorded_parent_Init_panics": 2, "recorded_candidate_Init_panics": 0,
        "recorded_candidate_prewrite_refusals": 2, "recorded_explicit_fixture_restores": 8,
        "recorded_native_unit_root_tests": 15, "recorded_native_unit_pass_results": 58,
        "recorded_native_unit_skips": 0, "independent_metadata_put_sets": 2,
        "independent_genesis_account_headers": 14094, "independent_v1_hash_frames": 4,
        "independent_canonical_witness_models": 1, "witness_levels_per_fold": 256,
        "recorded_reference_platform": "darwin/arm64", "reference_processes_executed_by_this_check": 0,
        "genesis_source_augmented_patch_digest_rehashed_by_this_check": False,
        "whole_module_graph_verification": "NOT_QUALIFIED", "consumer_result": "REFUSED",
        "source": expected_source(), "scope": dict(SCOPE),
        "recorded_snapshot_set_sha256": P.sha(P.UTIL.encoded(snapshots)),
        "reader_inputs_sha256": {name: P.sha(P.read_regular(HERE / name, 1 << 20)) for name in INPUTS},
    }


def check_file(path):
    raw = P.read_regular(path, MAX_BYTES)
    P.require(len(raw) == CORPUS_BYTES and P.sha(raw) == CORPUS_SHA256)
    result = check_corpus(document(raw))
    result["corpus_sha256"] = P.sha(raw)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, default=HERE / "testdata" / CORPUS)
    parser.add_argument("--source-revision")
    args = parser.parse_args(argv)
    if args.source_revision is not None:
        P.require(type(args.source_revision) is str and re.fullmatch("[0-9a-f]{40}", args.source_revision) is not None)
    result = check_file(args.corpus)
    if args.source_revision is not None:
        result["source_revision"] = args.source_revision
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, IndexError, RecursionError):
        print("Recorded cache replay patches refused; preserve failures and disabled acceptance.", file=sys.stderr)
        raise SystemExit(1)
