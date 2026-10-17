#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Check a recorded offline-helper comparison without executing a node.

Each complete snapshot appears once. Explicit references reconstruct the exact
captured component bytes before independent root/proof checking. A digest binds
bytes; it does not authenticate a release or turn this experiment into a pilot.
"""
import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("recorded_offline_rebuild_checker", HERE / "check_offline_rebuild_successor.py")
C = importlib.util.module_from_spec(spec)
spec.loader.exec_module(C)
M, P = C.M, C.P
# Filled from the independently captured, closed local execution before this
# recorded reader is eligible for qualification. No backend is launched here.
INPUTS = (
    'assess_tree_resources.py',
    'bulk_guards.go',
    'bulk_tail.go',
    'capture_child_lifecycle.py',
    'capture_child_lifecycle_test.py',
    'chain_startup.go',
    'check.py',
    'check_applier.py',
    'check_applier_test.py',
    'check_balance_observations.py',
    'check_balance_observations_test.py',
    'check_bulk_guards.py',
    'check_bulk_guards_test.py',
    'check_bulk_tail.py',
    'check_bulk_tail_test.py',
    'check_chain_startup.py',
    'check_chain_startup_test.py',
    'check_default_retention.py',
    'check_default_retention_corpus.py',
    'check_default_retention_corpus_test.py',
    'check_default_retention_successor.py',
    'check_default_retention_successor_corpus.py',
    'check_default_retention_successor_corpus_test.py',
    'check_default_retention_successor_test.py',
    'check_default_retention_test.py',
    'check_disk_lifecycle.py',
    'check_disk_lifecycle_test.py',
    'check_dispatcher.py',
    'check_dispatcher_test.py',
    'check_empty_versions.py',
    'check_empty_versions_test.py',
    'check_fold.py',
    'check_fold_test.py',
    'check_genesis_background.py',
    'check_genesis_background_corpus.py',
    'check_genesis_background_test.py',
    'check_genesis_models_test.py',
    'check_hash_bound_versions.py',
    'check_hash_bound_versions_test.py',
    'check_height_boundary.py',
    'check_height_boundary_test.py',
    'check_lifecycle_stop.py',
    'check_lifecycle_stop_test.py',
    'check_offline_rebuild_successor.py',
    'check_offline_rebuild_successor_test.py',
    'check_oracle_projection.py',
    'check_oracle_projection_test.py',
    'check_patch_decode.py',
    'check_patch_decode_test.py',
    'check_patch_file.py',
    'check_patch_file_resources.py',
    'check_patch_file_resources_test.py',
    'check_patch_file_test.py',
    'check_patch_import.py',
    'check_patch_import_comparison.py',
    'check_patch_import_comparison_test.py',
    'check_patch_import_test.py',
    'check_patch_plan_encodings.py',
    'check_patch_plan_encodings_test.py',
    'check_patch_plan_reads.py',
    'check_patch_plan_reads_test.py',
    'check_patch_plan_resources.py',
    'check_patch_plan_resources_test.py',
    'check_patch_resources.py',
    'check_patch_resources_test.py',
    'check_patch_targets.py',
    'check_patch_targets_test.py',
    'check_patch_tree.py',
    'check_patch_tree_tail.py',
    'check_patch_tree_tail_test.py',
    'check_patch_tree_test.py',
    'check_projected_driver.py',
    'check_projected_driver_test.py',
    'check_recovery_successor.py',
    'check_recovery_successor_test.py',
    'check_resource_budgets.py',
    'check_resource_budgets_test.py',
    'check_retention.py',
    'check_retention_test.py',
    'check_rpc_methods.py',
    'check_rpc_methods_test.py',
    'check_staging_boundary.py',
    'check_staging_boundary_test.py',
    'check_startup_quarantine.py',
    'check_startup_quarantine_test.py',
    'check_temp_workspace.py',
    'check_temp_workspace_test.py',
    'check_terminal_stop_successor.py',
    'check_terminal_stop_successor_test.py',
    'check_test.py',
    'check_tree_driver_resources.py',
    'check_tree_driver_resources_test.py',
    'check_tree_import_lifecycle.py',
    'check_tree_import_lifecycle_test.py',
    'check_tree_import_scale.py',
    'check_tree_import_scale_test.py',
    'check_tree_scale.py',
    'check_tree_scale_test.py',
    'check_wire.py',
    'check_wire_test.py',
    'compare_patch_import.py',
    'default_retention_model.py',
    'default_retention_model_test.py',
    'default_retention_probe_test.go',
    'default_retention_successor_model.py',
    'default_retention_successor_probe_test.go',
    'derive_genesis_background.py',
    'disk_lifecycle.go',
    'empty_versions.go',
    'genesis_background_probe_test.go',
    'genesis_input_decode.py',
    'genesis_sparse_model.py',
    'genesis_witness_model.py',
    'hash_bound_versions_probe_test.go',
    'hash_bound_versions_successor_probe_test.go',
    'height_boundary.go',
    'lifecycle_stop_probe_test.go',
    'lifecycle_stop_successor_probe_test.go',
    'main.go',
    'measure_genesis_background.py',
    'measure_oracle_projection.py',
    'measure_patch_plan.py',
    'measure_patch_plan_encodings.py',
    'measure_patch_plan_reads.py',
    'measure_projected_driver.py',
    'node-offline-rebuild-9c71-patch.json',
    'node-recovery-9c71-patch.json',
    'node-recovery-9c71-source-pins.json',
    'node-terminal-stop-9c71-patch.json',
    'observe_balance.py',
    'observe_driver_resources.py',
    'observe_driver_resources_test.py',
    'observe_temp_workspace.py',
    'observe_temp_workspace_test.py',
    'offline_rebuild_successor_model.py',
    'offline_rebuild_successor_probe_test.go',
    'patch_decode.go',
    'patch_file.go',
    'patch_file_resources_test.go',
    'patch_file_test.go',
    'patch_import.go',
    'patch_import_ownership_test.go',
    'patch_resources.go',
    'patch_targets.go',
    'patch_tree_tail_test.go',
    'patch_tree_test.go',
    'plan_patch.py',
    'plan_patch_test.py',
    'prepare_default_retention.py',
    'prepare_default_retention_successor.py',
    'prepare_default_retention_successor_test.py',
    'prepare_default_retention_test.py',
    'prepare_genesis_background.py',
    'prepare_hash_bound_versions.py',
    'prepare_lifecycle_stop.py',
    'prepare_offline_rebuild_successor.py',
    'prepare_offline_rebuild_successor_test.py',
    'prepare_recovery_successor.py',
    'prepare_recovery_successor_test.py',
    'prepare_startup_quarantine.py',
    'prepare_terminal_stop_successor.py',
    'prepare_terminal_stop_successor_test.py',
    'project_driver_oracles.py',
    'project_sparse_oracle.py',
    'project_target_hex.py',
    'project_target_hex_batch_test.py',
    'project_target_hex_test.py',
    'regenerate.py',
    'report_hash_bound_versions.py',
    'reproduce_patch_file.py',
    'reproduce_patch_file_resources.py',
    'reproduce_patch_tree.py',
    'reproduce_patch_tree_tail.py',
    'reproduce_temp_workspace.py',
    'reproduce_tree_driver_resources.py',
    'reproduce_tree_import_lifecycle.py',
    'reproduce_tree_import_scale.py',
    'reproduce_tree_scale.py',
    'retention_resources.go',
    'rpc_dispatcher.go',
    'rpc_methods.go',
    'run_target_hex.py',
    'staging_boundary.go',
    'startup_quarantine_probe_test.go',
    'testdata/successor-default-retention.json',
    'testdata/successor-genesis-input-execution.json',
    'tree_import_scale_test.go',
    'tree_scale_test.go',
    'wire.go',
)
EVIDENCE = {
    "actual_prepared_source_controls_sha256": "7dc69c1cbae5ed0eaeedaea37017b96bb3082bfb86704ef04e1a22459f965d73",
    "bounded_case_worker_sha256": "ce9880d9dd7d11d4dbcd12c73880ad838b4216a10dcc33a68fd2b62374867309",
    "bounded_local_driver_sha256": "5875c6f742eeb3acc757c77832afcb977623e42ad4b6930cfca94015468daf2b",
    "independent_expectations_sha256": "fb73dd797dd69fe3659ae7e6d7fec8be6ddb977d49660d7d143a253c879b399f",
    "independent_selection_sha256": "f06d4cc4e66a42b68d2647c0d1cab4d65b6e1f4e761557a8ff3d4ea228c10d14",
    "local_comparison_sha256": "286665b221847a7992d08ed19b90665616fd6c009c17362e9ef0f2e739731378",
    "private_paths_or_credentials_embedded": False,
    "receipt_hashes_authenticate_distribution": False,
    "recorded_runs_sha256": "f3abcec838774e9ec0ab9cb42664bc2fe26e499d68aabeed9cae0b0db9785c78",
    "source_genesis_qualification_reused_sha256": "b616df6c5262ce3404961a401c829b0c0b00829d943dd6044d60b4289b0b5815"
}
SCOPE = {
    "ordinary_functional_comparison_not_resource_benchmark": True,
    "source_identifiers_and_suffix_patches_are_synthetic": True,
    "manager_and_genesis_are_controlled_adapters": True,
    "source_genesis_execution_reused_without_relabeling": True,
    "new_hosted_node_or_genesis_execution": False,
    "full_node_qualified": False,
    "snapshot_authentication_qualified": False,
    "profile_agreed": False,
    "accepted_header_root_binding": False,
    "production_resources_qualified": False,
    "state_value_acceptance_enabled": False,
}


def source_pins():
    C.require(bool(INPUTS))
    return dict(M.source_identity(), source_inputs={name: P.sha(P.read_regular(HERE / name, 16 << 20)) for name in INPUTS},
                local_reference_platform="darwin/arm64", local_reference_Go_version="go1.25.14",
                historical_sources_and_manifests_rebound=False)


def snapshot_reference(value, tables):
    C.require(type(value) is dict and set(value) == {"snapshot_sha256"} and C.digest(value["snapshot_sha256"]))
    key = value["snapshot_sha256"]
    C.require(key in tables)
    return key, copy.deepcopy(tables[key])


def expand_observation(value, tables):
    C.require(type(value) is dict and type(value.get("cases")) is list and 0 < len(value["cases"]) <= 12)
    result, used = copy.deepcopy(value), set()
    for row in result["cases"]:
        C.require(type(row) is dict and type(row.get("closed_reopens")) is list and len(row["closed_reopens"]) == 2)
        key, table = snapshot_reference(row["closed_reopens"][0], tables)
        row["closed_reopens"][0] = table
        used.add(key)
        if "prebuild_snapshot" in row:
            key, table = snapshot_reference(row["prebuild_snapshot"], tables)
            row["prebuild_snapshot"] = table
            used.add(key)
    return result, used


def compact_observation(value, tables):
    """Preserve an exact canonical preimage for every reference; no recursion."""
    result = copy.deepcopy(value)
    for row in result["cases"]:
        fields = [(row["closed_reopens"], 0)]
        if "prebuild_snapshot" in row:
            fields.append((row, "prebuild_snapshot"))
        for target, key in fields:
            table = target[key]
            digest = P.sha(M.encoded(table))
            if digest in tables:
                P.exact(tables[digest], table)
            else:
                tables[digest] = table
            target[key] = {"snapshot_sha256": digest}
    return result


def command(row):
    C.require(type(row) is dict and set(row) == {"state", "actual_exit", "output_complete", "reason"})
    P.exact(row, {"state": "COMPLETE", "actual_exit": 0, "output_complete": True, "reason": None})


def check_corpus(document):
    C.require(type(document) is dict and set(document) == {
        "format_version", "kind", "source", "scope", "evidence", "expectations", "shared_snapshots",
        "observations", "runs", "consumer_result"})
    P.exact(document["format_version"], 1)
    P.exact(document["kind"], "recorded-successor-offline-rebuild-comparison")
    P.exact(document["consumer_result"], "REFUSED")
    P.exact(document["source"], source_pins())
    P.exact(document["scope"], SCOPE)
    C.require(bool(EVIDENCE))
    P.exact(document["evidence"], EVIDENCE)
    expected = C.selected_expectations(document["expectations"])
    tables = document["shared_snapshots"]
    C.require(type(tables) is dict and 1 <= len(tables) <= 24 and all(C.digest(k) for k in tables))
    C.require(all(P.sha(M.encoded(v)) == k for k, v in tables.items()))
    observations = document["observations"]
    C.require(type(observations) is dict and set(observations) == set(M.R.VARIANTS))
    runs = document["runs"]
    C.require(type(runs) is list and len(runs) == 2)
    C.require(P.sha(M.encoded(runs)) == EVIDENCE["recorded_runs_sha256"])
    used, results = set(), []
    for row, variant in zip(runs, M.R.VARIANTS):
        C.require(type(row) is dict and set(row) == {
            "variant", "payload", "binary", "compile", "worker", "component_process", "capture",
            "ready_record_sha256", "delivery_sha256", "owned_case_workspace_removed", "durable_CAS_ack_before_cleanup"})
        P.exact(row["variant"], variant)
        P.exact(row["owned_case_workspace_removed"], True)
        P.exact(row["durable_CAS_ack_before_cleanup"], True)
        command(row["compile"])
        command(row["worker"])
        for ref in (row["payload"], row["binary"]):
            C.require(type(ref) is dict and set(ref) == {"sha256", "bytes"} and C.digest(ref["sha256"])
                      and C.uint(ref["bytes"], 1, 64 << 20))
        C.require(C.digest(row["ready_record_sha256"]) and C.digest(row["delivery_sha256"]))
        process, capture = row["component_process"], row["capture"]
        P.exact(process, {"kind": "successor-offline-rebuild-functional-process-observation", "process_exit": 0,
                          "output_complete": True, "reason": None, "production_resources_qualified": False})
        C.require(type(capture) is dict and set(capture) == {
            "child_stdout_sha256", "child_stdout_bytes", "child_stderr_sha256", "child_stderr_bytes"})
        C.require(C.digest(capture["child_stdout_sha256"]) and C.digest(capture["child_stderr_sha256"])
                  and C.uint(capture["child_stdout_bytes"], row["payload"]["bytes"], 4 << 20)
                  and C.uint(capture["child_stderr_bytes"], 0, 1 << 20))
        expanded, selected = expand_observation(observations[variant], tables)
        raw = M.encoded(expanded)
        P.exact({"sha256": P.sha(raw), "bytes": len(raw)}, row["payload"])
        used.update(selected)
        results.append(C.check_observation(raw, expected, variant))
    C.require(used == set(tables))
    return dict(M.source_identity(), kind="recorded-successor-offline-rebuild-comparison-check",
                recorded_component_processes=2, ordinary_reference_builds=2,
                recorded_functional_cases=sum(row["cases"] for row in results),
                recorded_height_only_parent_rebuild_refusals=3, recorded_fixed_full_identifier_rebuilds=3,
                recorded_fixed_selected_refusals=7, independent_history_heights=64,
                canonical_proof_matches=sum(row["proofs_checked"] for row in results),
                no_version_proof_refusals=sum(row["no_version_proof_refusals"] for row in results),
                complete_snapshot_reopens_checked=sum(row["complete_snapshot_reopens_checked"] for row in results),
                distinct_complete_snapshot_preimages=len(tables),
                new_reference_node_execution=False, new_resource_measurement=False,
                profile_agreed=False, accepted_header_root_binding=False,
                production_resources_qualified=False, consumer_result="REFUSED")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, default=HERE / "testdata/successor-offline-rebuild.json")
    parser.add_argument("--source-revision")
    args = parser.parse_args(argv)
    if args.source_revision is not None:
        C.require(type(args.source_revision) is str and len(args.source_revision) == 40
                  and all(char in "0123456789abcdef" for char in args.source_revision))
    raw = P.read_regular(args.corpus, 4 << 20)
    report = check_corpus(json.loads(raw, object_pairs_hook=P.pairs))
    report["corpus_sha256"] = P.sha(raw)
    if args.source_revision is not None:
        report["source_revision"] = args.source_revision
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, IndexError, AssertionError):
        print("Recorded offline rebuild comparison refused; preserve inputs and diagnostics.", file=sys.stderr)
        sys.exit(1)
