#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Check recorded source-default retention cases without executing the node.

Observed root tables use an explicit reversible codec. Expanding each table must
reproduce its original complete payload size and SHA-256. A separate witness
model replays all heights before roots or canonical proofs are compared.
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
spec = importlib.util.spec_from_file_location("recorded_default_retention_observation", HERE / "check_default_retention.py")
C = importlib.util.module_from_spec(spec)
spec.loader.exec_module(C)
M = C.M
MAX_FILE_BYTES = 8 << 20
BASE_SHA256 = "f545c3a58562794f080d1a1cbc3ebd4f2e07cc620c6e37085562b9eb1e4c6496"
RUNS_SHA256 = "96da3e5516ed5853f659249bd7187c3554af91246f48b705eee2b6b7ea0f8be1"
EXPECTED_SHA256 = "c4d175be3d2639a71d795cebd43d23bb941555ee75d7ba41615c46958ea74412"
MATRIX = tuple((policy, index) for policy in ("pruned", "archive") for index in range(3))
INPUTS = (
    "check_default_retention_corpus.py", "check_default_retention.py", "default_retention_model.py",
    "default_retention_probe_test.go", "prepare_default_retention.py", "prepare_genesis_background.py",
    "derive_genesis_background.py", "genesis_sparse_model.py", "genesis_witness_model.py",
    "genesis_input_decode.py", "genesis_background_probe_test.go", "genesis-input/main.go",
    "prepare_hash_bound_versions.py", "hash_bound_versions_probe_test.go", "hash-bound-versions-patch.json",
    "prepare_lifecycle_stop.py", "lifecycle-stop-patch.json", "node-recovery-source-pins.json",
    "regenerate.py", "check.py", "check_patch_decode.py", "check_hash_bound_versions.py",
    "check_retention.py", "go.mod", "go.sum",
)
SCOPE = {
    **{name: True for name in (
        "source_derived_genesis_projection", "independent_expectations_sealed_before_backend",
        "actual_chain_Init_Start_Stop_and_clean_reopen_recorded", "actual_background_batches_recorded",
        "controlled_manager_cache_and_genesis_adapters", "unsigned_synthetic_history",
        "source_default_retention_and_batch_caps", "fresh_owned_disk_LevelDB",
        "all_32768_patch_requests_and_mutation_frame_checked", "three_normal_processes_per_policy",
        "all_completed_samples_retained_without_component_retry", "explicit_reversible_observed_table_codec",
        "protected_evidence_retained_before_disposable_workspace_cleanup",
    )},
    **{name: False for name in (
        "retention_or_bulk_batch_override", "runtime_scheduler_checkpoints_injected",
        "race_instrumented_resource_measurements", "full_node_qualified", "persistent_chain_manager_qualified",
        "VM_suffix_transition_correctness_qualified", "network_executed", "header_authentication_executed",
        "power_loss_or_crash_recovery_qualified", "production_concurrency_qualified",
        "production_resources_qualified", "authenticated_retained_provenance", "profile_agreed",
        "network_activation_authenticated", "accepted_header_root_binding", "runtime_SPV_acceptance_changed",
        "production_state_value_accepted",
    )},
}
EVIDENCE = {
    "independent_expectations_sha256": EXPECTED_SHA256,
    "independent_selection_sha256": "ac2157d776d26f5c4d00ccd4ab3f832224039d5043314d2ea7f2cb7045972622",
    "ordinary_binary_sha256": "83e2b6cf82c5867b00a7fd56745c6605ca54e3a694870b2f9c9e284404091910",
    "ordinary_compile_receipt_sha256": "7bcb0848d4dbcb281232507b76f57c4456d9ed7fe09671523e002e004560b51a",
    "independent_derivation_receipt_sha256": "ad200f316769fef4c70ccfb62be6f3051ecee6cf5da848fd7a53946ca957c73d",
    "ordered_plan_sha256": "257110e533a963d435893ed21ee40f8b99495ff0e2e4365387825709ee4ce356",
    "private_supervisor_amendment_sha256": "417b226f2e63bc5fb113b5e28fb31da03b293ec700163b82ffb9ec13e16d9429",
    "first_case_cleanup_erratum_sha256": "ea56d6791446afeedd0074e4029f7e54c5bb4b25ed0f7826554b986b6405a303",
    "first_case_explicit_cleanup_receipt_sha256": "78d85423d8f5650e21cbdeb77f3b82bcc513b1709ffe4368e6b770e2da2ac462",
    "private_cleanup_regression_receipt_sha256": "239cecf5a0cac81132201448f653608446c424bc624bbcbe88851cec32807c62",
    "private_durable_ACK_and_actual_cleanup_receipt_sha256": "26c0f0660062414e11ad5bf6f82cbb7eda4688e71f05fba664d3f3a661336e39",
    "receipt_hashes_authenticate_distribution": False,
    "private_paths_or_credentials_embedded": False,
}


def require(value):
    C.require(value)


def source_pins():
    return {"node_revision": "33d7d1ee1b6a915c40aea196e2a10f1e893d171f",
            "node_original_tree": "40d71efb7e462d5bbd0f27d83ed7588e121c3cb6", "source_blobs": 439,
            "runtime_tree_without_probes": "d3d9215bc9ea23b2e700aad53ebb23d4bdea3428",
            "source_inputs": {name: hashlib.sha256((HERE / name).read_bytes()).hexdigest() for name in INPUTS},
            "local_reference_platform": "darwin/arm64", "local_reference_Go_version": "go1.25.14",
            "historical_sources_and_manifests_rebound": False}


def read_corpus(path):
    P = M.module("default_retention_recorded_reader", "prepare_hash_bound_versions.py")
    raw = P.read_regular(path, MAX_FILE_BYTES)
    return raw, json.loads(raw, object_pairs_hook=P.pairs)


@functools.lru_cache(maxsize=1)
def expected_from_presealed_witnesses(base_bytes):
    require(type(base_bytes) is bytes and hashlib.sha256(base_bytes).hexdigest() == BASE_SHA256)
    result = json.loads(base_bytes, object_pairs_hook=M.G.B.object_pairs)
    selection = result["selection"]
    history, _ = M.history(bytes.fromhex(result["source_initial"]["expected_root"]),
                           result["initial_witnesses"],
                           [bytes.fromhex(key) for key in selection["mutation_keys"]],
                           [bytes.fromhex(row["raw_key"]) for row in selection["selected_proofs"]])
    result["history"] = history
    require(hashlib.sha256(M.encoded(result)).hexdigest() == EXPECTED_SHA256)
    C.selected_expectations(result)
    return result


def expand_table(table, roots):
    require(type(table) is dict and set(table) == {"policy", "snapshot", "queries"})
    policy = table["policy"]
    require(policy in ("pruned", "archive"))
    snapshot = table["snapshot"]
    require(type(snapshot) is dict and set(snapshot) == {
        "format", "logical_records", "logical_key_value_bytes", "logical_records_sha256", "record_prefix_counts"})
    require(type(roots) is list and len(roots) == 32768 and all(C.digest(root) for root in roots))
    start = 1 if policy == "archive" else 15388
    pairs = [{"height": h, "root": roots[h - 1], "hash": C.identifier("G", h)["hash"]}
             for h in range(start, 32769)]
    return M.encoded({"snapshot": {**snapshot, "retained_roots": pairs}, "queries": table["queries"]})


def process_resource(row, component):
    require(type(row) is dict and set(row) == {
        "kind", "process_exit", "output_complete", "reason", "elapsed_ns", "peak_rss_bytes",
        "user_cpu_seconds", "system_cpu_seconds", "major_page_faults", "minor_page_faults",
        "measurement_scope", "descendant_process_memory_included", "sampled_child_RSS_peak_bytes",
        "child_RSS_samples", "sample_interval_seconds", "sampled_RSS_stop_bytes", "child_deadline_seconds",
        "configured_GOMAXPROCS", "sampling_is_not_an_OS_memory_quota", "production_resources_qualified"})
    require(row["kind"] == "source-default-retention-process-resource-observation"
            and type(row["process_exit"]) is int and row["process_exit"] == 0
            and row["output_complete"] is True and row["reason"] is None
            and row["measurement_scope"] == "waited_component_process_including_fixture_and_queries"
            and row["descendant_process_memory_included"] is False
            and row["sampling_is_not_an_OS_memory_quota"] is True
            and row["production_resources_qualified"] is False)
    require(C.uint(row["elapsed_ns"], sum(component[name] for name in C.TIMERS), 610_000_000_000)
            and C.uint(row["peak_rss_bytes"], 1, 2 << 30)
            and C.uint(row["sampled_child_RSS_peak_bytes"], 1, 2 << 30)
            and C.uint(row["child_RSS_samples"], 1, 2000))
    require(type(row["sample_interval_seconds"]) is float and row["sample_interval_seconds"] == 0.5)
    for field, value in (("sampled_RSS_stop_bytes", 2 << 30), ("child_deadline_seconds", 600),
                         ("configured_GOMAXPROCS", 2)):
        require(type(row[field]) is int and row[field] == value)
    for field in ("major_page_faults", "minor_page_faults"):
        require(C.uint(row[field]))
    for field in ("user_cpu_seconds", "system_cpu_seconds"):
        require(type(row[field]) in (int, float) and math.isfinite(row[field]) and row[field] >= 0)


def check_corpus(document):
    require(type(document) is dict and set(document) == {
        "format_version", "kind", "source", "scope", "evidence", "presealed_expectations_without_history",
        "history_summary", "observed_root_codec", "observed_archive_roots", "shared_observed_tables", "runs", "consumer_result"})
    require(type(document["format_version"]) is int and document["format_version"] == 1
            and document["kind"] == "recorded-source-default-retention-background-comparison"
            and document["consumer_result"] == "REFUSED")
    C.exact(document["source"], source_pins())
    C.exact(document["scope"], SCOPE)
    C.exact(document["evidence"], EVIDENCE)
    # Reject altered witnesses before an expensive model replay; cached graphs
    # are keyed by the complete admitted bytes, not mutable object identity.
    expected = expected_from_presealed_witnesses(M.encoded(document["presealed_expectations_without_history"]))
    C.exact(document["history_summary"], {k: v for k, v in expected["history"].items()
                                         if k not in ("roots", "checkpoints")})
    require(document["observed_root_codec"] == "height=one_based_index;hash=SHA3-256(synthetic-hash-bound-node-v1/G/height)")
    roots = document["observed_archive_roots"]
    C.exact(roots, [row["root"] for row in expected["history"]["roots"]])
    tables = document["shared_observed_tables"]
    require(type(tables) is dict and 2 <= len(tables) <= 6 and all(C.digest(key) for key in tables))
    expanded = {digest: expand_table(table, roots) for digest, table in tables.items()}
    require(all(hashlib.sha256(raw).hexdigest() == digest for digest, raw in expanded.items()))
    runs = document["runs"]
    require(type(runs) is list and len(runs) == 6
            and hashlib.sha256(M.encoded(runs)).hexdigest() == RUNS_SHA256)
    used, checks, resources = set(), [], {}
    for record, (policy, index) in zip(runs, MATRIX):
        require(type(record) is dict and set(record) == {
            "label", "policy", "sample_index", "payload", "capture", "component", "process",
            "worker_actual_exit", "worker_output_complete", "ready_record_sha256", "case_delivery_sha256",
            "owned_workspace_removed", "cleanup_method"})
        require(record["label"] == policy + "-" + str(index) and record["policy"] == policy
                and type(record["sample_index"]) is int and record["sample_index"] == index
                and type(record["worker_actual_exit"]) is int and record["worker_actual_exit"] == 0
                and record["worker_output_complete"] is True and record["owned_workspace_removed"] is True)
        require(record["cleanup_method"] == ("explicitly_approved_cleanup_after_preserved_erratum" if (policy, index) == ("pruned", 0)
                                            else "supervised_after_durable_CAS_ack_and_absence_check"))
        require(C.digest(record["ready_record_sha256"]) and C.digest(record["case_delivery_sha256"]))
        payload = record["payload"]
        require(type(payload) is dict and set(payload) == {"sha256", "bytes"} and payload["sha256"] in expanded
                and C.uint(payload["bytes"], 1, 64 << 20))
        raw = expanded[payload["sha256"]]
        require(len(raw) == payload["bytes"] and tables[payload["sha256"]]["policy"] == policy)
        used.add(payload["sha256"])
        capture = record["capture"]
        require(type(capture) is dict and set(capture) == {
            "child_stdout_sha256", "child_stdout_bytes", "child_stderr_sha256", "child_stderr_bytes"})
        require(C.digest(capture["child_stdout_sha256"]) and C.digest(capture["child_stderr_sha256"])
                and C.uint(capture["child_stdout_bytes"], len(raw), 64 << 20)
                and C.uint(capture["child_stderr_bytes"], 1, 1 << 20))
        component = record["component"]
        require(component["policy"] == policy and component["platform"] == "darwin/arm64"
                and component["Go_version"] == "go1.25.14")
        checked = C.check_tables(raw, component, expected)
        require((component["rollback_cache"], component["retention_margin"]) == (100, 17280))
        process_resource(record["process"], component)
        resources[record["label"]] = {"elapsed_ns": record["process"]["elapsed_ns"],
                                     "peak_rss_bytes": record["process"]["peak_rss_bytes"],
                                     "physical_file_bytes": checked["physical_file_bytes"]}
        checks.append(checked)
    require(used == set(tables))
    return {"kind": "recorded-source-default-retention-background-check", "recorded_component_processes": 6,
            "normal_reference_processes": 6, "reference_binaries": 1, "race_reference_processes": 0,
            "independently_replayed_history_heights": 32768, "distinct_mutation_addresses": 256,
            "source_default_retention": 17380, "retention_or_bulk_batch_override": False,
            "pruned_horizon_inclusive": 15388, "final_pruned_retained_roots": 17381,
            "final_archive_retained_roots": 32768, "selected_proof_keys": 15, "query_heights_per_set": 6,
            "recorded_query_sets_per_case": 2, "recorded_matched_proof_observations": 2 * sum(c["canonical_proofs_matched"] for c in checks),
            "recorded_pruned_proof_refusals": 2 * sum(c["pruned_proof_refusals"] for c in checks),
            "all_mutated_keys_individually_queried": False, "root_pairs_and_complete_payload_bytes_reconstructed": True,
            "recorded_sample_manifest_sha256": RUNS_SHA256, "unique_observed_payloads": len(tables),
            "recorded_resources": resources, "source_initial_full_projection_recomputed_in_this_checker": False,
            "all_node_record_bytes_independently_reconstructed": False,
            "native_reference_node_or_CGO_execution": False, "new_resource_measurements": False,
            "network_executed": False, "full_node_qualified": False, "production_resources_qualified": False,
            "profile_agreed": False, "accepted_header_root_binding": False, "consumer_result": "REFUSED"}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, default=HERE / "testdata/candidate-default-retention.json")
    parser.add_argument("--source-revision")
    args = parser.parse_args(argv)
    if args.source_revision is not None:
        require(type(args.source_revision) is str and re.fullmatch("[0-9a-f]{40}", args.source_revision))
    raw, document = read_corpus(args.corpus)
    report = check_corpus(document)
    report["corpus_sha256"] = hashlib.sha256(raw).hexdigest()
    if args.source_revision is not None:
        report["source_revision"] = args.source_revision
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError, IndexError, AssertionError, RecursionError):
        print("Recorded source-default retention comparison refused; preserve original evidence.", file=sys.stderr)
        sys.exit(1)
