#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Check the separately recorded successor retention/resource comparison.

Replay the sealed finite workload and reconstruct complete observed table bytes.
This reader executes no node and makes no new native resource measurement.
Historical records stay unchanged; shared functions provide only byte codecs,
finite sparse-tree arithmetic and process-resource field validation.
"""
import argparse
import functools
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


C = module("recorded_successor_retention_checker", "check_default_retention_successor.py")
R = module("recorded_successor_retention_byte_codec", "check_default_retention_corpus.py")
M = C.M
B = C.C
BASE_SHA256 = "97463c1b2720f277e59cf2d8abd55d90d286c9d359130377fc0f4658e7b28c4b"
EXPECTED_SHA256 = "684e318dfaa6444cc9179397e6a5bca7d02d079cec17bb73957b065bb46cdaa0"
RUNS_SHA256 = "ffbcfd1d3a5f71d9e9875cc3d6b5e6602eab1f46e9695bcd0ec335a358cdb694"
GENESIS_SHA256 = "8d80a7160bf0e7ff4fcae8bc4c18ca40b64dd65200c8fd1de5dca8fc16f8c0f0"
EVIDENCE = {
    "actual_workspace_adverse_controls_sha256": "e129d852b766febba7f970ea7eb2789374faf46957c710d5df4aa45e3950e3ec",
    "bounded_case_worker_sha256": "435d5eda9779016f32adab6c632cd0ae529204ff7efd735c9e10092b74921591",
    "bounded_local_driver_sha256": "f495eed0f479fe199df60832394892625ad5974d6aa331883d40a830be09daac",
    "independent_derivation_receipt_sha256": "2edc0562129e5d99f6d5cef7b89a824e846bc91d7d2d6ed8504f65abda93cd9c",
    "independent_expectations_sha256": "684e318dfaa6444cc9179397e6a5bca7d02d079cec17bb73957b065bb46cdaa0",
    "independent_selection_sha256": "28b2d094ce936217e279397fbb3b500753a107ad355f2bbffed945ce63d35ef8",
    "local_comparison_sha256": "70c6b8a55fb0d14d7f74008d646754906a70d9dd2b6bdd34c6392bedde11a6a2",
    "ordinary_binary_sha256": "531a047229051c0b66e14cabeb936954e605bc99e53a51264e991199299d4fee",
    "ordinary_compile_receipt_sha256": "5dd967bd76b48ab81d20b06f3853c5dc68cbb6ef51ca9341a7c0bd43c31f4bef",
    "private_paths_or_credentials_embedded": False,
    "receipt_hashes_authenticate_distribution": False,
    "source_genesis_manifest_sha256": "8d80a7160bf0e7ff4fcae8bc4c18ca40b64dd65200c8fd1de5dca8fc16f8c0f0",
    "source_genesis_qualification_sha256": "b616df6c5262ce3404961a401c829b0c0b00829d943dd6044d60b4289b0b5815"
}
INPUTS = tuple(dict.fromkeys(R.INPUTS + (
    "check_default_retention_successor_corpus.py", "check_default_retention_successor.py",
    "default_retention_successor_model.py", "default_retention_successor_probe_test.go",
    "prepare_default_retention_successor.py", "prepare_terminal_stop_successor.py",
    "prepare_recovery_successor.py", "hash_bound_versions_successor_probe_test.go",
    "node-terminal-stop-9c71-patch.json", "node-recovery-9c71-patch.json",
    "node-recovery-9c71-source-pins.json", "genesis-input-successor/main.go",
    "testdata/successor-genesis-input-execution.json",
)))
SCOPE = dict(R.SCOPE, fresh_successor_source_genesis_executed_twice_before_backend=True,
             old_node_process_results_relabelled=False)
MATRIX = tuple((policy, index) for policy in ("pruned", "archive") for index in range(3))


def source_pins():
    return dict(M.source_identity(), source_inputs={name: hashlib.sha256((HERE / name).read_bytes()).hexdigest()
                                                    for name in INPUTS},
                local_reference_platform="darwin/arm64", local_reference_Go_version="go1.25.14",
                historical_sources_and_manifests_rebound=False)


def genesis_execution():
    raw = M.P.read_regular(HERE / "testdata/successor-genesis-input-execution.json", 64 << 10)
    B.require(hashlib.sha256(raw).hexdigest() == GENESIS_SHA256)
    result = json.loads(raw, object_pairs_hook=M.P.pairs)
    B.require(result["kind"] == "recorded-successor-unsigned-source-genesis-input"
                and type(result["format_version"]) is int and result["format_version"] == 1
                and result["node_revision"] == M.P.REVISION and result["node_tree"] == M.P.TREE
                and type(result["source_blob_count"]) is int and result["source_blob_count"] == 467)
    B.exact(result["raw_input"], M.M.G.RAW)
    B.require(result["independent_sparse_root"] == M.M.G.INITIAL_ROOT
                and result["source_module_sha256"] == M.source_identity()["module_sha256"]
                and result["source_sum_sha256"] == M.source_identity()["sum_sha256"]
                and result["source_generator_sha256"] == hashlib.sha256((HERE / "genesis-input-successor/main.go").read_bytes()).hexdigest())
    B.require(result["same_payload_per_digest"] is True
                and all(result[name] is False for name in (
                    "historical_source_records_rebound", "network_authenticated_genesis",
                    "NodeTree_backend_executed", "production_qualified"))
                and result["consumer_result"] == "REFUSED")
    commands = [result["actual_compile"]]
    B.require(type(result["fresh_generations"]) is list and len(result["fresh_generations"]) == 2)
    for index, run in enumerate(result["fresh_generations"]):
        B.exact(run["generation"], index)
        B.exact(run["raw_input"], result["raw_input"])
        B.exact(run["actual_command"]["stdout"], result["raw_input"])
        meta = run["metadata"]
        B.require(meta["node_revision"] == M.P.REVISION and meta["node_tree"] == M.P.TREE
                    and meta["kind"] == "pinned-successor-source-unsigned-genesis-input"
                    and meta["Go_version"] == "go1.25.14" and meta["platform"] == "darwin/arm64"
                    and meta["raw_input_sha256"] == result["raw_input"]["sha256"]
                    and meta["raw_input_bytes"] == meta["stdout_written_bytes"] == result["raw_input"]["bytes"])
        B.exact(meta["replay_counts"], result["independent_replay_counts"])
        B.require(all(type(meta[name]) is int and meta[name] == 1 for name in ("version", "height", "chain_identifier"))
                  and meta["in_memory_genesis_VM_derivation"] is True
                  and all(meta[name] is False for name in (
                      "NodeTree_executed", "chain_Init_or_Start_executed", "disk_database_opened",
                      "network_executed", "signing_or_broadcast_executed", "production_acceptance")))
        commands.append(run["actual_command"])
    for row in commands:
        B.require(row["state"] == "COMPLETE" and type(row["actual_exit"]) is int and row["actual_exit"] == 0
                    and row["output_complete"] is True and row["reason"] is None)
    return result


@functools.lru_cache(maxsize=1)
def expected_from_presealed_witnesses(base_raw):
    B.require(type(base_raw) is bytes and hashlib.sha256(base_raw).hexdigest() == BASE_SHA256)
    result = json.loads(base_raw, object_pairs_hook=M.P.pairs)
    selection = result["selection"]
    history, _ = M.M.history(bytes.fromhex(result["source_initial"]["expected_root"]), result["initial_witnesses"],
                             [bytes.fromhex(key) for key in selection["mutation_keys"]],
                             [bytes.fromhex(row["raw_key"]) for row in selection["selected_proofs"]])
    result["history"] = history
    B.require(hashlib.sha256(M.encoded(result)).hexdigest() == EXPECTED_SHA256)
    C.selected_expectations(result)
    genesis = genesis_execution()
    B.exact(result["source_initial"]["raw_input"], genesis["raw_input"])
    B.exact(result["input_replay_counts"], genesis["independent_replay_counts"])
    return result


def run_header(row, policy, index):
    """Reject invalid receipts before expanding or replaying large tables."""
    B.require(type(row) is dict and set(row) == {
        "label", "policy", "sample_index", "payload", "capture", "component", "process", "worker_actual_exit",
        "worker_output_complete", "ready_record_sha256", "case_delivery_sha256", "owned_workspace_removed", "cleanup_method"})
    B.require(row["label"] == policy + "-" + str(index) and row["policy"] == policy
              and type(row["sample_index"]) is int and row["sample_index"] == index
              and type(row["worker_actual_exit"]) is int and row["worker_actual_exit"] == 0
              and row["worker_output_complete"] is True and row["owned_workspace_removed"] is True
              and row["cleanup_method"] == "supervised_after_durable_CAS_ack_and_absence_check"
              and B.digest(row["ready_record_sha256"]) and B.digest(row["case_delivery_sha256"]))
    payload, component = row["payload"], row["component"]
    B.require(type(payload) is dict and set(payload) == {"sha256", "bytes"} and B.digest(payload["sha256"])
              and B.uint(payload["bytes"], 1, 64 << 20) and type(component) is dict
              and set(component) == B.FIELDS | set(C.SOURCE_FIELDS))
    B.require(component["policy"] == policy and component["platform"] == "darwin/arm64" and component["Go_version"] == "go1.25.14"
              and component["logical_tables_sha256"] == payload["sha256"]
              and type(component["logical_tables_bytes"]) is int and component["logical_tables_bytes"] == payload["bytes"])
    R.process_resource(row["process"], component)


def check_corpus(document):
    require = B.require
    require(type(document) is dict and set(document) == {
        "format_version", "kind", "source", "scope", "evidence", "presealed_expectations_without_history",
        "history_summary", "observed_root_codec", "observed_archive_roots", "shared_observed_tables", "runs", "consumer_result"})
    require(type(document["format_version"]) is int and document["format_version"] == 1
            and document["kind"] == "recorded-successor-source-default-retention-background-comparison"
            and document["consumer_result"] == "REFUSED")
    B.exact(document["source"], source_pins())
    B.exact(document["scope"], SCOPE)
    B.exact(document["evidence"], EVIDENCE)
    runs = document["runs"]
    require(type(runs) is list and len(runs) == 6 and hashlib.sha256(M.encoded(runs)).hexdigest() == RUNS_SHA256)
    for row, (policy, index) in zip(runs, MATRIX):
        run_header(row, policy, index)
    expected = expected_from_presealed_witnesses(M.encoded(document["presealed_expectations_without_history"]))
    B.exact(document["history_summary"], {k: v for k, v in expected["history"].items() if k not in ("roots", "checkpoints")})
    require(document["observed_root_codec"] == "height=one_based_index;hash=SHA3-256(synthetic-hash-bound-node-v1/G/height)")
    roots = document["observed_archive_roots"]
    B.exact(roots, [row["root"] for row in expected["history"]["roots"]])
    tables = document["shared_observed_tables"]
    require(type(tables) is dict and 2 <= len(tables) <= 6 and all(B.digest(key) for key in tables))
    expanded = {digest: R.expand_table(table, roots) for digest, table in tables.items()}
    require(all(hashlib.sha256(raw).hexdigest() == digest for digest, raw in expanded.items()))
    used, checked, resources = set(), [], {}
    for row, (policy, index) in zip(runs, MATRIX):
        payload = row["payload"]
        require(payload["sha256"] in expanded)
        raw = expanded[payload["sha256"]]
        require(type(payload["bytes"]) is int and len(raw) == payload["bytes"] and tables[payload["sha256"]]["policy"] == policy)
        used.add(payload["sha256"])
        capture = row["capture"]
        require(type(capture) is dict and set(capture) == {
            "child_stdout_sha256", "child_stdout_bytes", "child_stderr_sha256", "child_stderr_bytes"})
        require(B.digest(capture["child_stdout_sha256"]) and B.digest(capture["child_stderr_sha256"])
                and B.uint(capture["child_stdout_bytes"], len(raw), 64 << 20)
                and B.uint(capture["child_stderr_bytes"], 1, 1 << 20))
        component = row["component"]
        checked.append(C.check_tables(raw, component, expected))
        resources[row["label"]] = {"elapsed_ns": row["process"]["elapsed_ns"], "peak_rss_bytes": row["process"]["peak_rss_bytes"],
                                   "physical_file_bytes": checked[-1]["physical_file_bytes"]}
    require(used == set(tables))
    return dict(M.source_identity(), kind="recorded-successor-source-default-retention-background-check",
                recorded_component_processes=6, normal_reference_processes=6, reference_binaries=1,
                race_reference_processes=0, independently_replayed_history_heights=32768,
                distinct_mutation_addresses=256, source_default_retention=17380, retention_or_bulk_batch_override=False,
                pruned_horizon_inclusive=15388, final_pruned_retained_roots=17381, final_archive_retained_roots=32768,
                selected_proof_keys=15, query_heights_per_set=6, recorded_query_sets_per_case=2,
                recorded_matched_proof_observations=2 * sum(v["canonical_proofs_matched"] for v in checked),
                recorded_pruned_proof_refusals=2 * sum(v["pruned_proof_refusals"] for v in checked),
                all_mutated_keys_individually_queried=False, unique_observed_payloads=len(tables),
                complete_observed_table_bytes_reconstructed=True, recorded_resources=resources,
                source_initial_full_projection_recomputed_in_this_checker=False,
                all_node_record_bytes_independently_reconstructed=False, new_reference_node_or_CGO_execution=False,
                new_resource_measurements=False, network_executed=False, full_node_qualified=False,
                production_resources_qualified=False, profile_agreed=False, accepted_header_root_binding=False,
                consumer_result="REFUSED")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, default=HERE / "testdata/successor-default-retention.json")
    parser.add_argument("--source-revision")
    args = parser.parse_args(argv)
    if args.source_revision is not None:
        B.require(type(args.source_revision) is str and re.fullmatch("[0-9a-f]{40}", args.source_revision))
    raw = M.P.read_regular(args.corpus, 8 << 20)
    report = check_corpus(json.loads(raw, object_pairs_hook=M.P.pairs))
    report["corpus_sha256"] = hashlib.sha256(raw).hexdigest()
    if args.source_revision is not None:
        report["source_revision"] = args.source_revision
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError, IndexError, AssertionError):
        print("Recorded successor retention corpus refused; preserve source and evidence.", file=sys.stderr)
        sys.exit(1)
