#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Check recorded patch-snapshot observations without starting the reference node.

SHA-256 binds published inputs and projections. It does not authenticate the
private execution receipts or qualify a network profile or production budget.
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
    spec = importlib.util.spec_from_file_location("snapshot_recorded_" + name, HERE / (name + ".py"))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


H = load("prepare_patch_snapshot_lifetime")
R = load("check_cache_replay_patches")
P = H.P
CORPUS = "native-patch-snapshot-lifetime.json"
CORPUS_SHA256 = "47fe1ddfe070791481a9788e66840756108167f4e7e10a9bd6992ca56ff7ec42"
CORPUS_BYTES = 73819
EXECUTION_SHA256 = "8d48034e038fcf0f6f51ebbdbe6f14b370386f60bb22ed20c160c104d9ecfde7"
MAX_BYTES = 256 << 10
ROOT = "TestCandidatePatchSnapshotLifetime"
CASES = tuple(reader + "_" + case + "_" + gc
              for reader in ("public_get_patch", "internal_get_rollback")
              for case in ("present", "absent", "invalid_dump")
              for gc in ("disabled", "inherited"))
PACKAGES = ("github.com/zenon-network/go-zenon/chain", "github.com/zenon-network/go-zenon/chain/cache/storage",
            "github.com/zenon-network/go-zenon/common/db")
SCOPE = {
    "two_short_lived_read_snapshot_helpers": True,
    "snapshot_acquisition_error_diagnostic_intentionally_changed": True,
    "independent_patch_dump_and_ordered_database_frames": True,
    "recorded_finalizer_controls_return_to_zero": True,
    "recorded_returned_patch_survives_rewrite_GC_and_Stop": True,
    "all_previous_58_native_pass_names_retained": True,
    "five_previous_Chain_Init_Stop_stdout_payloads_reused_by_digest": True,
    "hosted_checks_replay_recorded_bytes": True,
    "returned_version_DB_snapshot_ownership_changed": False,
    "permanent_leak_claimed": False,
    "private_execution_receipts_authenticated": False,
    "exact_original_random_stress_vector_reproducible": False,
    "reported_maximum_RSS_is_aggregate_process_tree_peak": False,
    "representative_resource_budget_qualified": False,
    "network_or_consensus_executed": False,
    "full_node_service_executed": False,
    "node_client_profile_agreed": False,
    "accepted_header_binding": False,
    "runtime_state_value_acceptance": False,
    "production_qualified": False,
    "checker_executes_reference_backend": False,
}
INPUTS = tuple(dict.fromkeys((
    "check_patch_snapshot_lifetime.py", "prepare_patch_snapshot_lifetime.py", H.PATCH, H.PROBE,
    "testdata/" + R.CORPUS, *R.INPUTS,
)))


def document(raw):
    P.require(type(raw) is bytes and 0 < len(raw) <= MAX_BYTES)
    def constant(_):
        raise ValueError("Non-finite JSON refused")
    return json.loads(raw, object_pairs_hook=P.pairs, parse_constant=constant)


def ref(value):
    P.require(type(value) is dict and set(value) == {"bytes", "sha256"})
    P.require(type(value["bytes"]) is int and 0 <= value["bytes"] <= 64 << 20)
    P.require(type(value["sha256"]) is str and re.fullmatch("[0-9a-f]{64}", value["sha256"]) is not None)
    if value["bytes"] == 0:
        P.require(value["sha256"] == hashlib.sha256(b"").hexdigest())


def command(value):
    P.require(type(value) is dict and set(value) == {"state", "actual_exit", "output_complete", "reason", "stdout", "stderr"})
    P.exact([value[k] for k in ("state", "actual_exit", "output_complete", "reason")], ["COMPLETE", 0, True, None])
    ref(value["stdout"])
    ref(value["stderr"])


def expected_source():
    manifest, _, pins = H.selection()
    component_parent, component_candidate = H.component_build_trees()
    P.require(len(H.build_pins()) == 474 and len(manifest["files"]) == len(pins) == 467)
    return {
        "repository": "https://github.com/digitalSloth/go-zenon", "revision": P.REVISION,
        "original_tree": P.TREE, "original_source_blobs": 467, "source_manifest_sha256": P.SOURCE_SHA256,
        "component_parent_runtime_tree": P.TREE, "component_candidate_runtime_tree": H.COMPONENT_RUNTIME_TREE,
        "component_parent_build_tree": component_parent, "component_candidate_build_tree": component_candidate,
        "component_source_blobs": 468, "integrated_parent_runtime_tree": H.H.MODIFIED_TREE,
        "integrated_parent_build_tree": H.H.BUILD_TREE, "integrated_candidate_runtime_tree": H.MODIFIED_TREE,
        "integrated_candidate_build_tree": H.BUILD_TREE, "integrated_source_blobs": 474,
        "patch_sha256": H.PATCH_SHA256,
        "probe": {"bytes": H.PROBE_BYTES, "sha256": H.PROBE_SHA256},
        "parent_probe": {"bytes": H.PARENT_PROBE_BYTES, "sha256": H.PARENT_PROBE_SHA256},
        "module_sha256": pins["go.mod"]["sha256"], "sum_sha256": pins["go.sum"]["sha256"],
        "prior_recorded_corpus": {"bytes": R.CORPUS_BYTES, "sha256": R.CORPUS_SHA256},
    }


def check_observations(rows, expect_release):
    P.require(type(expect_release) is bool and type(rows) is list and len(rows) == 12)
    identities = []
    dump = b"\x01\x05alpha\x03one\x00\x04beta"
    fields = {"format_version", "kind", "reader", "case", "gc_policy", "gc_percent", "reads", "snapshots_before",
              "snapshots_after_reads", "snapshots_after_explicit_gc", "explicit_gc_rounds", "decode_panics", "returned_nil",
              "returned_expected_patch", "patch_dump_hex", "stored_value_hex", "logical_database_before", "logical_database_after",
              "explicit_release_source_expected", "permanent_leak_claimed", "representative_load_or_hardware_budget_qualified",
              "full_node_or_network_executed", "accepted_header_binding", "consumer_result"}
    for row in rows:
        P.require(type(row) is dict and set(row) == fields)
        P.exact([row["format_version"], row["kind"], row["consumer_result"]],
                [1, "native-patch-read-snapshot-lifetime", "REFUSED"])
        P.require(all(type(row[k]) is str for k in ("reader", "case", "gc_policy")))
        identity = "_".join(row[k] for k in ("reader", "case", "gc_policy"))
        P.require(identity in CASES)
        identities.append(identity)
        for key in ("gc_percent", "reads", "snapshots_before", "snapshots_after_reads", "snapshots_after_explicit_gc",
                    "explicit_gc_rounds", "decode_panics", "returned_nil", "returned_expected_patch"):
            P.require(type(row[key]) is int)
        P.require(row["reads"] == 64 and row["snapshots_before"] == row["snapshots_after_explicit_gc"] == 0)
        P.require(0 <= row["snapshots_after_reads"] <= 64 and 0 <= row["explicit_gc_rounds"] <= 10000)
        P.require(row["explicit_release_source_expected"] is expect_release)
        if expect_release:
            P.require(row["snapshots_after_reads"] == row["explicit_gc_rounds"] == 0)
        if row["gc_policy"] == "disabled":
            P.require(row["gc_percent"] == -1 and row["snapshots_after_reads"] == (0 if expect_release else 64))
            if not expect_release:
                P.require(row["explicit_gc_rounds"] > 0)
        else:
            P.require(row["gc_percent"] >= 0)
        P.require(row["patch_dump_hex"] == dump.hex())
        stored = b"\xff" if row["case"] == "invalid_dump" else dump
        P.require(row["stored_value_hex"] == stored.hex())
        key = (b"\x66" if row["reader"] == "public_get_patch" else b"\x77") + (42).to_bytes(8, "big")
        entries = [] if row["case"] == "absent" else [(key, stored)]
        frame = b"".join(len(k).to_bytes(8, "big") + k + len(v).to_bytes(8, "big") + v for k, v in entries)
        image = {"records": len(entries), "key_bytes": sum(len(k) for k, v in entries),
                 "value_bytes": sum(len(v) for k, v in entries), "ordered_length_framed_sha256": hashlib.sha256(frame).hexdigest()}
        P.exact(row["logical_database_before"], image)
        P.exact(row["logical_database_after"], image)
        P.require(row["decode_panics"] == (64 if row["case"] == "invalid_dump" else 0))
        P.require(row["returned_nil"] == (0 if row["case"] == "present" else 64))
        P.require(row["returned_expected_patch"] == (64 if row["case"] == "present" else 0))
        for field in ("permanent_leak_claimed", "representative_load_or_hardware_budget_qualified",
                      "full_node_or_network_executed", "accepted_header_binding"):
            P.require(row[field] is False)
    P.require(len(set(identities)) == 12 and set(identities) == set(CASES))
    return {"cases": 12, "reads": 768, "GC_disabled_cases": 6, "GC_disabled_reads": 384}


def check_units(value, roots, names, packages, tree):
    P.require(type(value) is dict and set(value) == {"build_tree", "command", "race_detector", "root_tests", "test_pass_names",
                                                   "package_pass_names", "explicit_skips", "failed_tests"})
    P.exact(value["build_tree"], tree)
    command(value["command"])
    P.require(value["race_detector"] is True)
    P.exact(value["root_tests"], sorted(roots))
    P.exact(value["test_pass_names"], sorted(names))
    P.exact(value["package_pass_names"], sorted(packages))
    P.exact(value["explicit_skips"], [])
    P.exact(value["failed_tests"], [])


def prior_corpus():
    raw = P.read_regular(HERE / "testdata" / R.CORPUS, R.MAX_BYTES)
    P.require(len(raw) == R.CORPUS_BYTES and P.sha(raw) == R.CORPUS_SHA256)
    value = R.document(raw)
    P.exact(value["source"], R.expected_source())
    return value


def check_chain_cases(rows, earlier):
    P.require(type(rows) is list and len(rows) == 5)
    models = R.metadata_models()
    projected = []
    for index, (case, row, old) in enumerate(zip(H.H.CASES, rows, earlier["cases"][5:])):
        P.require(type(row) is dict and set(row) == {"case", "command", "recorded_stdout"})
        P.exact(row["case"], case)
        P.exact([old["generation"], old["case"]], ["candidate", case])
        command(row["command"])
        raw = old["stdout_utf8"].encode()
        pin = {"bytes": len(raw), "sha256": P.sha(raw)}
        P.exact(row["recorded_stdout"], pin)
        P.exact(row["command"]["stdout"], pin)
        P.exact(old["metadata_report"], None if index == 0 else models[2 if index == 4 else 1])
        projected.append({"case": case, "command": row["command"], "stdout_utf8": old["stdout_utf8"],
                          "metadata_report": old["metadata_report"]})
    result = R.R.check_generation("candidate", projected)
    P.require(result["init_panics"] == 0 and result["candidate_prewrite_refusals"] == 2)
    return result


def check_corpus(value):
    P.require(type(value) is dict and set(value) == {"format_version", "kind", "source", "scope", "execution", "observations",
                                                  "unit_runs", "chain_cases", "consumer_result"})
    P.exact([value["format_version"], value["kind"], value["consumer_result"]],
            [1, "recorded-native-patch-snapshot-lifetime", "REFUSED"])
    P.exact(value["source"], expected_source())
    P.exact(value["scope"], SCOPE)
    execution = value["execution"]
    P.require(type(execution) is dict and P.sha(P.UTIL.encoded(execution)) == EXECUTION_SHA256)
    P.exact([execution[k] for k in ("compiler", "reference_platform", "new_dependency_transports", "verified_dependency_inputs",
                                  "linked_modules", "whole_module_graph_verification", "parent_caller_outcome", "parent_native_exit",
                                  "parent_raw_capture_rewritten", "native_parent_reexecuted_for_parser_repair")],
            ["go1.25.14", "darwin/arm64", 0, 75, 25, "NOT_QUALIFIED", "FAILURE", 0, False, False])
    observations = value["observations"]
    P.require(type(observations) is dict and set(observations) == {"parent_component", "candidate_component", "integrated_candidate"})
    for phase in observations:
        check_observations(observations[phase], phase != "parent_component")
    earlier = prior_corpus()
    core_names = {ROOT, *(ROOT + "/" + case for case in CASES)}
    candidate_names = core_names | set(H.SNAPSHOT_ROOTS[1:])
    integrated_names = set(earlier["execution"]["native_unit_controls"]["test_pass_names"]) | candidate_names
    P.require(len(core_names) == 13 and len(candidate_names) == 15 and len(integrated_names) == 73)
    db_names = set(H.DB_ROOTS) | {
        "TestLevelDBManagerPopInvalidatesRollbackCaches/identifier_beyond_the_near_cache_window",
        "TestLevelDBManagerPopInvalidatesRollbackCaches/identifier_within_the_near_cache_window",
        "TestLevelDBManagerPopInvalidatesRollbackCaches/view_read_between_the_pops_and_the_adds",
        "TestManagerStopIsIdempotent/leveldb", "TestManagerStopIsIdempotent/memdb",
    }
    runs = value["unit_runs"]
    P.require(type(runs) is dict and set(runs) == {"parent_component", "candidate_component", "integrated_candidate", "original_DB"})
    for phase in runs:
        P.exact(runs[phase]["command"], execution["unit_commands"][phase])
    check_units(runs["parent_component"], (ROOT,), core_names, PACKAGES[2:], H.COMPONENT_PARENT_BUILD_TREE)
    check_units(runs["candidate_component"], H.SNAPSHOT_ROOTS, candidate_names, PACKAGES[2:], H.COMPONENT_CANDIDATE_BUILD_TREE)
    check_units(runs["integrated_candidate"], H.NATIVE_ROOTS, integrated_names, PACKAGES, H.BUILD_TREE)
    check_units(runs["original_DB"], H.DB_ROOTS, db_names, PACKAGES[2:], H.BUILD_TREE)
    chain = check_chain_cases(value["chain_cases"], earlier)
    return {
        "kind": "recorded-native-patch-snapshot-lifetime-check", "recorded_snapshot_cases": 36,
        "recorded_reads_per_case": 64, "independent_patch_dump_bytes": 17, "independent_database_frames": 6,
        "recorded_GC_disabled_parent_snapshots_per_case": 64, "recorded_GC_disabled_candidate_snapshots_per_case": 0,
        "recorded_component_parent_pass_results": 13, "recorded_component_candidate_pass_results": 15,
        "recorded_integrated_pass_results": 73, "recorded_original_DB_roots": 22, "recorded_original_DB_pass_results": 27,
        "recorded_native_skips": 0, "recorded_Chain_Init_Stop_cases": 5, "recorded_chain_events": chain["event_count"],
        "recorded_chain_Init_panics": chain["init_panics"], "recorded_chain_prewrite_refusals": chain["candidate_prewrite_refusals"],
        "recorded_reference_platform": "darwin/arm64", "reference_processes_executed_by_this_check": 0,
        "source": expected_source(), "scope": dict(SCOPE), "consumer_result": "REFUSED",
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
        print("Recorded patch snapshot lifetime refused; preserve failures and disabled acceptance.", file=sys.stderr)
        raise SystemExit(1)
