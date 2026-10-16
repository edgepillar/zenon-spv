#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Check recorded component measurements; do not execute the node in this checker.

The small shared tables deduplicate equal recorded inventories and queries. The
complete initial projection is independently reproduced by the separate deriver;
this checker verifies its pinned witnesses and replays all 4,096 fixture roots.
Neither recorded measurements nor green native CI qualify production resources.
"""
import argparse
import functools
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import re
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent


def module(name, file):
    spec = importlib.util.spec_from_file_location(name, HERE / file)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


C = module("recorded_genesis_background_observation", "check_genesis_background.py")
D = module("recorded_genesis_background_derivation", "derive_genesis_background.py")
H = C.H
MAX_FILE_BYTES = 2 << 20
BASE_SHA256 = "18fed87609d33edeadb4dd2361483a753cc06ad0128145a23014a1e9d66b1ad1"
# Pin the observed sample manifest, including timing/file/stream observations.
# These are empirical conformance bytes, not independently derived performance
# bounds or an authentication mechanism for the original host or distribution.
RUNS_SHA256 = "d54f6272baf1a9200484e9fbc4b8b46d1e3d1dcc2eef2b53a5bcd5f5d598cefd"
INPUTS = (
    "check_genesis_background_corpus.py", "check_genesis_background.py", "derive_genesis_background.py",
    "genesis_sparse_model.py", "genesis_witness_model.py", "genesis_input_decode.py",
    "genesis_background_probe_test.go", "genesis-input/main.go", "prepare_genesis_background.py",
    "measure_genesis_background.py", "prepare_hash_bound_versions.py", "hash_bound_versions_probe_test.go",
    "hash-bound-versions-patch.json", "prepare_lifecycle_stop.py", "lifecycle-stop-patch.json",
    "node-recovery-source-pins.json", "regenerate.py", "check.py", "check_patch_decode.py",
    "check_hash_bound_versions.py", "check_retention.py", "go.mod", "go.sum",
)
MATRIX = tuple(("resource", policy, generation) for policy in ("pruned", "archive") for generation in range(3)) + (
    ("race", "pruned", 0), ("race", "archive", 0), ("race", "stop-resume", 0))
SCOPE = {
    **{name: True for name in (
        "source_derived_initial_projection", "independent_expectations_sealed_before_backend",
        "actual_chain_Init_Start_Stop_recorded", "actual_background_batches_recorded",
        "controlled_manager_cache_and_genesis_adapters", "unsigned_synthetic_history",
        "test_only_retention_override_256", "fresh_owned_disk_LevelDB",
        "controlled_stop_resume_and_clean_reopen", "separate_normal_and_race_measurements",
        "full_original_outputs_and_failure_state_retained_privately",
        "equal_recorded_tables_stored_once", "all_completed_samples_retained",
    )},
    **{name: False for name in (
        "scheduler_checkpoints_injected_into_runtime_source", "full_node_qualified",
        "persistent_chain_manager_qualified", "network_executed", "header_authentication_executed",
        "VM_suffix_transition_correctness_qualified", "power_loss_or_crash_recovery_qualified",
        "production_concurrency_qualified", "production_retention_budget_qualified",
        "authenticated_retained_provenance", "profile_agreed", "network_activation_authenticated",
        "accepted_header_root_binding", "runtime_SPV_acceptance_changed", "production_state_value_accepted",
    )},
}
EVIDENCE = {
    "presealed_initial_expectations_sha256": "ea1a375d44e5464fb9bcd99b166443fda59ca5cd43e89d2b07d603e1e43a008b",
    "presealed_history_expectations_sha256": "dcf9136a00e9dff3be2c2deb856869f7cce2afa8ec4ef48098eadbc8c8079456",
    "complete_local_experiment_sha256": "b73dd60411bc231537d7947d8add46ba74fbb0154d55f0b3a106e6697252397b",
    "complete_independent_reproduction_sha256": "ae666bb484194f5c58010e6c5a1b249f19558b5440f66999f86d6bd2e9af219a",
    "normal_binary_sha256": "3e5bd09736081fce0c39b96039306b8107a8f68ee0583f563ff59e99a6c0c967",
    "race_binary_sha256": "e3d069d2ef79927e68c39d7a71d0b04629783408fc5df58a9fc6990d061e49d8",
    "receipt_hashes_authenticate_distribution": False,
    "private_paths_or_credentials_embedded": False,
}
RECORDED_LOGICAL = {
    "pruned": (84366, 7503024, "19b8d88356f7ca9d8e74c80cdaba3d230e5ffc92b3839e370c71e6ddb2543295"),
    "archive": (189342, 17593329, "1c16899e158e35ed23202968c75c09c2d59a02eaf6034524718c1863f3063b84"),
}
HARNESS_HISTORY = [
    {"kind": "probe_namespace_defect", "actual_process_exit": 2, "output_complete": True,
     "qualified_as_resource_sample": False, "runtime_changed_to_hide_failure": False,
     "failure_receipt_sha256": "489cf7ef65e3f94afd96a53fb4a02e12aa65fc7cb1c91da0bda9b423ed211132"},
    {"kind": "checker_fixture_label_defect", "actual_process_exit": 0, "output_complete": True,
     "complete_actual_process_repeated": False, "complete_record_rechecked_as": "resource-pruned-0",
     "failure_receipt_sha256": "6ac53fc8450c0bbb9bffc1aec007d49b7230ee38a52c207051511d40d1e455fb"},
]


def source_pins():
    return {"node_revision": H.REVISION, "node_original_tree": H.TREE, "source_blobs": 439,
            "runtime_tree_without_probes": "d3d9215bc9ea23b2e700aad53ebb23d4bdea3428",
            "source_inputs": {name: hashlib.sha256((HERE / name).read_bytes()).hexdigest() for name in INPUTS},
            "local_reference_platform": "darwin/arm64", "local_reference_Go_version": "go1.25.14",
            "historical_sources_and_manifests_rebound": False}


def read_corpus(path):
    with Path(path).open("rb") as stream:
        raw = stream.read(MAX_FILE_BYTES + 1)
    H.require(len(raw) <= MAX_FILE_BYTES, "genesis background corpus exceeds bound")
    return raw, json.loads(raw, object_pairs_hook=H.BYTE.object_pairs)


@functools.lru_cache(maxsize=1)
def expected_history(base_bytes):
    H.require(hashlib.sha256(base_bytes).hexdigest() == BASE_SHA256)
    return D.derive_history(json.loads(base_bytes, object_pairs_hook=H.BYTE.object_pairs))


def expand_observation(row, document):
    result = dict(row)
    policy = result["policy"]
    H.require(policy in ("archive", "pruned", "stop-resume"))
    table = "archive" if policy == "archive" else "pruned"
    for name in ("snapshot_before_stop", "closed_snapshot", "reopened_snapshot"):
        result[name] = dict(result[name])
        H.require("retained_roots" not in result[name])
        H.require(result[name].pop("retained_roots_table") == table)
        result[name]["retained_roots"] = document["root_tables"][table]
    for name in ("queries", "reopened_queries"):
        H.require(result.pop(name + "_table") == table and name not in result)
        result[name] = document["query_tables"][table]
    return result


def resource_shape(row, workflow_ns):
    H.require(type(row) is dict and set(row) == {
        "kind", "process_exit", "output_completeness", "elapsed_ns", "peak_rss_bytes",
        "user_cpu_seconds", "system_cpu_seconds", "major_page_faults", "minor_page_faults",
        "measurement_scope", "descendant_process_memory_included", "production_resources_qualified"})
    H.require(row["kind"] == "source-genesis-background-process-resource-observation")
    H.require(type(row["process_exit"]) is int and row["process_exit"] == 0)
    H.require(row["output_completeness"] == "REQUIRES_SEPARATE_SUPERVISOR_EVIDENCE")
    H.require(row["measurement_scope"] == "entire_waited_component_process_including_fixture_and_queries")
    H.require(row["descendant_process_memory_included"] is False and row["production_resources_qualified"] is False)
    H.require(type(row["elapsed_ns"]) is int and row["elapsed_ns"] >= workflow_ns)
    H.require(type(row["peak_rss_bytes"]) is int and 0 < row["peak_rss_bytes"] < 1 << 40)
    for field in ("major_page_faults", "minor_page_faults"):
        H.require(type(row[field]) is int and row[field] >= 0)
    for field in ("user_cpu_seconds", "system_cpu_seconds"):
        H.require(type(row[field]) in (float, int) and math.isfinite(row[field]) and row[field] >= 0)


def check_corpus(document):
    H.require(type(document) is dict and set(document) == {
        "format_version", "kind", "source", "scope", "evidence", "initial_expectations",
        "history_summary", "root_tables", "query_tables", "runs", "harness_history", "consumer_result"})
    H.require(type(document["format_version"]) is int and document["format_version"] == 1)
    H.require(document["kind"] == "recorded-source-genesis-background-component-comparison")
    H.exact(document["source"], source_pins())
    H.exact(document["scope"], SCOPE)
    H.exact(document["evidence"], EVIDENCE)
    H.exact(document["harness_history"], HARNESS_HISTORY)
    H.require(document["consumer_result"] == "REFUSED")
    base = document["initial_expectations"]
    history = expected_history(D.encoded(base))
    H.exact(document["history_summary"], {k: v for k, v in history.items()
                                          if k not in ("archive_policy_roots", "selected_checkpoints")})
    archive = [{"height": r["height"], "hash": C.identifier("G", r["height"])["hash"], "root": r["root"]}
               for r in history["archive_policy_roots"]]
    H.exact(document["root_tables"], {"archive": archive, "pruned": archive[3839:]})
    H.require(type(document["query_tables"]) is dict and set(document["query_tables"]) == {"archive", "pruned"})
    H.require(type(document["runs"]) is list and len(document["runs"]) == 9)
    H.require(hashlib.sha256(D.encoded(document["runs"])).hexdigest() == RUNS_SHA256,
              "recorded sample manifest differs")
    byte_totals = {}
    for record, (mode, policy, generation) in zip(document["runs"], MATRIX):
        H.require(type(record) is dict and set(record) == {
            "label", "mode", "generation", "actual_exit", "output_complete", "stdout", "stderr",
            "observation", "process_resource", "normal_resource_measurement", "physical_file_bytes"})
        H.require(record["label"] == mode + "-" + policy + "-" + str(generation))
        H.require(record["mode"] == mode and type(record["generation"]) is int and record["generation"] == generation)
        H.require(type(record["actual_exit"]) is int and record["actual_exit"] == 0 and record["output_complete"] is True)
        H.require(record["normal_resource_measurement"] is (mode == "resource"))
        for field in ("stdout", "stderr"):
            value = record[field]
            H.require(type(value) is dict and set(value) == {"sha256", "bytes"})
            H.require(type(value["sha256"]) is str and re.fullmatch("[0-9a-f]{64}", value["sha256"]))
            H.require(type(value["bytes"]) is int and 0 < value["bytes"] <= 4 << 20)
        row = expand_observation(record["observation"], document)
        H.require(row["policy"] == policy and row["Go_version"] == "go1.25.14" and row["platform"] == "darwin/arm64")
        C.check_observation(row, base, history)
        logical = row["snapshot_before_stop"]
        H.exact((logical["logical_records"], logical["logical_key_value_bytes"], logical["logical_records_sha256"]),
                RECORDED_LOGICAL["archive" if policy == "archive" else "pruned"])
        resource_shape(record["process_resource"], row["component_workflow_elapsed_ns"])
        physical = sum(file["bytes"] for file in row["physical_files_after_final_close"])
        H.require(type(record["physical_file_bytes"]) is int and record["physical_file_bytes"] == physical)
        byte_totals[record["label"]] = physical
    return {"kind": "recorded-source-genesis-background-check", "recorded_component_processes": 9,
            "normal_reference_processes": 6, "race_reference_processes": 3,
            "source_initial_projection_leaves": 19257, "source_balance_values_independently_compared": 14091,
            "independently_replayed_history_heights": 4096, "selected_proof_observations": 1350,
            "final_pruned_retained_roots": 257, "final_archive_retained_roots": 4096,
            "pruned_horizon_inclusive": 3840, "recorded_physical_file_bytes": byte_totals,
            "recorded_sample_manifest_sha256": RUNS_SHA256,
            "source_initial_full_projection_recomputed_in_this_checker": False,
            "all_node_record_bytes_independently_reconstructed": False,
            "normal_resources_include_controlled_fixture_and_query_cost": True,
            "native_reference_node_or_CGO_execution": False, "network_executed": False,
            "production_resource_budgets_qualified": False, "profile_agreed": False,
            "accepted_header_root_binding": False, "consumer_result": "REFUSED"}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, default=HERE / "testdata/candidate-genesis-background.json")
    parser.add_argument("--source-revision")
    args = parser.parse_args(argv)
    if args.source_revision is not None:
        H.require(type(args.source_revision) is str and re.fullmatch("[0-9a-f]{40}", args.source_revision))
    raw, document = read_corpus(args.corpus)
    result = check_corpus(document)
    result["corpus_sha256"] = hashlib.sha256(raw).hexdigest()
    if args.source_revision is not None:
        result["source_revision"] = args.source_revision
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError, IndexError, AssertionError):
        print("Recorded genesis background comparison refused; production acceptance remains disabled.", file=sys.stderr)
        sys.exit(1)
