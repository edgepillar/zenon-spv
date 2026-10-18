#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Check recorded cache forward-replay observations without a native backend.

The selected unsigned second momentum and three small metadata images are
independently reconstructed. Complete canonical cache images and private
execution receipts remain recorded component observations, not authentication.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("recorded_forward_preparer", HERE / "prepare_cache_forward_replay.py")
H = importlib.util.module_from_spec(spec)
spec.loader.exec_module(H)
spec = importlib.util.spec_from_file_location("recorded_prior_cache_integrity", HERE / "check_cache_identifier_rollback.py")
PRIOR = importlib.util.module_from_spec(spec)
spec.loader.exec_module(PRIOR)
P, W = H.P, PRIOR.W
CORPUS = "native-cache-forward-replay.json"
CORPUS_SHA256 = "d95d173f8ecf305d34429effde9de0adb9b9d48169b51f8f58e23f1228e477b9"
CORPUS_BYTES = 71909
MAX_BYTES = 128 << 10
EXECUTION_SHA256 = "204366dcfea57c13b0512a37064dce56a9a6496afd2aad4b3cd50e9c185ce00d"
SNAPSHOTS_SHA256 = "28c50c1954f79054ccc264c205e7e7fbdd2aa623d3cf8b8ee24537b44e623090"
CASE_STDERR = [{'bytes': 342, 'sha256': '43cb566b4e830206c2e9898828b0314ed9d0f55d9ecddd89f6e2fef7c54add2f'}, {'bytes': 342, 'sha256': '43cb566b4e830206c2e9898828b0314ed9d0f55d9ecddd89f6e2fef7c54add2f'}, {'bytes': 342, 'sha256': '43cb566b4e830206c2e9898828b0314ed9d0f55d9ecddd89f6e2fef7c54add2f'}, {'bytes': 342, 'sha256': '43cb566b4e830206c2e9898828b0314ed9d0f55d9ecddd89f6e2fef7c54add2f'}, {'bytes': 342, 'sha256': '43cb566b4e830206c2e9898828b0314ed9d0f55d9ecddd89f6e2fef7c54add2f'}, {'bytes': 342, 'sha256': '43cb566b4e830206c2e9898828b0314ed9d0f55d9ecddd89f6e2fef7c54add2f'}, {'bytes': 144, 'sha256': 'fc4db9798b33d36661ccb37793463dd3526084025dc4bce5497712d079fcc7eb'}, {'bytes': 342, 'sha256': '43cb566b4e830206c2e9898828b0314ed9d0f55d9ecddd89f6e2fef7c54add2f'}]
SCOPE = {'real_public_Chain_Init_and_Stop': True, 'real_disk_ledger_cache_and_NodeTree_managers': True, 'source_embedded_unsigned_genesis_VM': True, 'local_unsigned_second_momentum': True, 'separate_foreign_nonzero_cache_metadata_fixture': True, 'experimental_native_cache_forward_preflight': True, 'prewrite_identity_refusal_observed': True, 'canonical_empty_and_behind_cache_replay_recorded': True, 'race_native_component_controls_recorded': True, 'hosted_checks_replay_recorded_bytes': True, 'Chain_Start_called': False, 'full_node_service_executed': False, 'network_or_consensus_executed': False, 'live_reorg_qualified': False, 'concurrent_public_lifecycle_qualified': False, 'power_loss_qualified': False, 'whole_window_atomicity_claimed': False, 'test_overlays_or_scheduler_hooks': False, 'node_client_profile_agreed': False, 'network_activation_authenticated': False, 'accepted_header_binding': False, 'runtime_state_value_acceptance': False, 'production_qualified': False, 'checker_executes_reference_backend': False, 'public_record_authenticates_private_receipts': False, 'complete_alternate_chain_cache_application_qualified': False}
ZERO = "00" * 32
FRAMING = "ordered u64be key length, key bytes, u64be value length, value bytes"
INPUTS = tuple(dict.fromkeys(("prepare_cache_forward_replay.py", H.PATCH, H.PROBE, H.CONTROL,
                             "check_cache_identifier_rollback.py", *PRIOR.INPUTS)))


def document(raw):
    P.require(type(raw) is bytes and 0 < len(raw) <= MAX_BYTES)
    return W.document(raw)


def identifiers():
    first = dict(W.GENESIS)
    empty = hashlib.sha3_256(b"").digest()
    # The selected v1 source hash frame uses big-endian uint64 values and the
    # empty changes/data/content digests. StateRoot is not a v1 hash field.
    frame = struct.pack(">QQ", 1, 1) + bytes.fromhex(first["hash"])
    frame += struct.pack(">QQ", 2, 1637755210) + empty * 3
    P.require(len(frame) == 160)
    second = {"hash": hashlib.sha3_256(frame).hexdigest(), "height": 2}
    P.require(second["hash"] == "fbe4d2002715d5993894e36fe23eefab052ffe697861465b1be8c07d786beed0")
    foreign = dict(first, hash=("%02x" % (int(first["hash"][:2], 16) ^ 1)) + first["hash"][2:])
    return {"A1": first, "A2": second, "B1": foreign, "EMPTY": {"hash": ZERO, "height": 0}}


def raw_identifier(label):
    selected = identifiers()[label]
    if label == "EMPTY":
        return b""
    return b"\0\x0a\x22\x0a\x20" + bytes.fromhex(selected["hash"]) + b"\x10" + bytes([selected["height"]])


def small_image(kind):
    P.require(kind in ("B1", "FOREIGN_A2", "EMPTY"))
    rows = []
    if kind != "EMPTY":
        current = "A2" if kind == "FOREIGN_A2" else "B1"
        rows = [(bytes([85, 0]), raw_identifier(current)),
                (bytes([119]) + struct.pack(">Q", 1), bytes([0, 1, 0]))]
        if kind == "FOREIGN_A2":
            previous = raw_identifier("B1")[1:]
            # Source goleveldb batch: Put=1, key length/key, value length/value.
            # The first Add's predecessor is a Delete=0 record for key zero.
            rows.append((bytes([119]) + struct.pack(">Q", 2), bytes([1, 1, 0, len(previous)]) + previous))
    frame = b"".join(struct.pack(">Q", len(k)) + k + struct.pack(">Q", len(v)) + v for k, v in sorted(rows))
    return {"records": len(rows), "key_bytes": sum(len(k) for k, _ in rows),
            "value_bytes": sum(len(v) for _, v in rows), "raw_store_sha256": P.sha(frame)}


def expected_source():
    plan = H.plan("NEW_OWNED_WORKSPACE", "PINNED_GO")
    controls = {name: dict(pin) for name, pin in H.G.CONTROL_SOURCES.items()}
    controls[H.CONTROL] = {"target": H.CONTROL_TARGET, "bytes": H.CONTROL_BYTES, "sha256": H.CONTROL_SHA256}
    return {"repository": "https://github.com/digitalSloth/go-zenon", "revision": P.REVISION,
            "original_tree": P.TREE, "source_blobs": 467, "compiled_source_blobs": 471,
            "source_manifest_sha256": P.SOURCE_SHA256, "parent_runtime_tree": H.G.MODIFIED_TREE,
            "candidate_runtime_tree": H.MODIFIED_TREE, "parent_build_tree": H.parent_build_tree(),
            "candidate_build_tree": plan["build_tree"], "probe": plan["probe"],
            "patch_sha256": H.PATCH_SHA256, "module_sha256": plan["module_sha256"],
            "sum_sha256": plan["sum_sha256"], "native_controls": controls}


def command(row, raw, stderr):
    P.exact(row, {"state": "COMPLETE", "actual_exit": 0, "output_complete": True, "reason": None,
                  "stdout": {"sha256": P.sha(raw), "bytes": len(raw)}, "stderr": stderr})


def snapshot(value, case, label, before, metadata, empty, small_kind):
    fields = {"stage", "case", "frontier", "frontier_raw_value", "frontier_present",
              "records", "key_bytes", "value_bytes", "framing", "raw_store_sha256"}
    if before:
        fields |= {"metadata_only_fixture", "empty_cache_fixture"}
    P.require(type(value) is dict and set(value) == fields)
    P.exact([value["stage"], value["case"], value["frontier"], value["frontier_raw_value"],
             value["frontier_present"], value["framing"]],
            ["cache-fixture-before-public-init" if before else "cache-fixture-after-public-stop",
             case, identifiers()[label], raw_identifier(label).hex(), label != "EMPTY", FRAMING])
    if before:
        P.exact([value["metadata_only_fixture"], value["empty_cache_fixture"]], [metadata, empty])
    P.require(all(type(value[k]) is int and 0 <= value[k] < (1 << 31)
                  for k in ("records", "key_bytes", "value_bytes")))
    P.require(value["records"] <= 1000000 and type(value["raw_store_sha256"]) is str and
              re.fullmatch("[0-9a-f]{64}", value["raw_store_sha256"]) is not None)
    if small_kind is not None:
        P.exact({k: value[k] for k in small_image(small_kind)}, small_image(small_kind))


def second_momentum():
    ids = identifiers()
    return {"version": 1, "chainIdentifier": 1, "hash": ids["A2"]["hash"],
            "previousHash": ids["A1"]["hash"], "height": 2, "timestamp": 1637755210,
            "changesHash": hashlib.sha3_256(b"").hexdigest(), "data": None, "content": None,
            "publicKey": None, "signature": None, "nextFusionPrice": 0, "nextWorkPrice": 0, "stateRoot": ZERO}


def check_corpus(value):
    P.require(type(value) is dict and set(value) == {"format_version", "kind", "source", "execution", "scope", "cases", "consumer_result"})
    P.exact([value["format_version"], value["kind"], value["consumer_result"]],
            [1, "recorded-native-cache-forward-replay", "REFUSED"])
    P.exact(value["source"], expected_source())
    P.exact(value["scope"], SCOPE)
    execution = value["execution"]
    P.require(P.sha(P.UTIL.encoded(execution)) == EXECUTION_SHA256)
    P.exact([execution["ordinary_entrypoint_builds"], execution["actual_case_processes"],
             execution["new_source_or_dependency_transports"], execution["verified_dependency_inputs"],
             execution["linked_modules"], execution["physical_reclaim_or_peak_disk_claim"]],
            [2, 8, 0, 75, 25, False])
    unit = execution["native_unit_controls"]
    P.exact([unit["race_detector"], unit["root_tests"], unit["test_pass_results"],
             unit["package_pass_results"], unit["skipped_or_failed"]], [True, 13, 30, 2, 0])
    P.require(type(unit["selected_roots"]) is list and len(unit["selected_roots"]) == 13)
    P.require(type(unit["test_pass_names"]) is list and len(unit["test_pass_names"]) == 30)
    proof = PRIOR.canonical_proof()
    P.require(type(value["cases"]) is list and len(value["cases"]) == 8)
    ids = identifiers()
    observations, positive_after = [], []
    event_count = queries = available = 0
    for index, row in enumerate(value["cases"]):
        generation = "parent" if index < 4 else "candidate"
        case_index = index % 4
        case = H.CASES[case_index]
        P.require(type(row) is dict and set(row) == {"generation", "case", "command", "stdout_utf8", "stderr_diagnostics"})
        P.exact([row["generation"], row["case"]], [generation, case])
        text = row["stdout_utf8"]
        P.require(type(text) is str and 0 < len(text) < (16 << 10) and text.endswith("\n"))
        command(row["command"], text.encode(), CASE_STDERR[index])
        P.exact(row["stderr_diagnostics"], {"normal_process_complete": True, "runtime_panic_observed": False})
        events = [document(line.encode()) for line in text.splitlines()]
        ready = generation == "parent" or case_index != 2
        before = ("A2", "A1", "B1", "EMPTY")[case_index]
        after = "A2" if ready else "B1"
        P.require(len(events) == (9 if ready else 7))
        before_kind = "B1" if case_index == 2 else "EMPTY" if case_index == 3 else None
        after_kind = ("FOREIGN_A2" if ready else "B1") if case_index == 2 else None
        snapshot(events[2], case, before, True, case_index == 2, case_index == 3, before_kind)
        snapshot(events[6], case, after, False, case_index == 2, case_index == 3, after_kind)
        if not ready:
            for key in ("frontier", "frontier_raw_value", "frontier_present", "records", "key_bytes", "value_bytes", "raw_store_sha256"):
                P.exact(events[2][key], events[6][key])
        observations.append({"generation": generation, "case": case, "before": events[2], "after": events[6]})
        if case_index != 2:
            positive_after.append({k: v for k, v in events[6].items() if k not in ("case", "stage")})
        def event(stage, **fields):
            return dict(fields, case=case, stage=stage)
        def query(stage):
            return event(stage, identifier=ids["A2"], root=W.ROOT if ready else ZERO,
                         root_error="none" if ready else "not-ready", proof_error="none" if ready else "not-ready",
                         value=W.VALUE if ready else "", proof=proof if ready else "")
        expected = [
            event("source-genesis-and-unsigned-second-momentum", genesis_identifier=ids["A1"],
                  genesis_timestamp=1637755200, second_identifier=ids["A2"], second_momentum=second_momentum(),
                  input_patch_dump="", input_patch_sha256=hashlib.sha256(b"").hexdigest(),
                  genesis_patch_bytes=W.DUMP["bytes"], genesis_patch_sha256=W.DUMP["sha256"],
                  network_started=False, consensus_validation_selected=False, wallet_signing_or_broadcast=False),
            event("canonical-height-two-ledger-and-tree-primed", identifier=ids["A2"], root=W.ROOT,
                  cache_identifier=ids["A2"] if case_index == 0 else ids["A1"], ready_after_stop=False),
            events[2], event("public-init-returned", ready=ready,
                             error="none" if ready else "cache-frontier-identity-mismatch",
                             ledger_frontier=ids["A2"], cache_frontier=ids[after], frontiers_equal=ready),
            query("public-state-query"), event("public-stop", ready=False), events[6],
        ]
        if ready:
            expected += [event("public-clean-reopen", ready=True, error="none",
                               ledger_frontier=ids["A2"], cache_frontier=ids["A2"]), query("reopened-state-query")]
        P.exact(events, expected)
        event_count += len(events)
        queries += 2 if ready else 1
        available += 2 if ready else 0
    P.require(len(positive_after) == 6)
    P.require(all(row == positive_after[0] for row in positive_after))
    parent_foreign = observations[2]["after"]
    P.require(parent_foreign["raw_store_sha256"] != positive_after[0]["raw_store_sha256"])
    P.require(P.sha(P.UTIL.encoded(observations)) == SNAPSHOTS_SHA256)
    P.exact([event_count, queries, available], [70, 15, 14])
    return {"kind": "recorded-native-cache-forward-replay-check", "recorded_cases": 8,
            "recorded_raw_exits": [0] * 8, "recorded_event_observations": event_count,
            "recorded_parent_foreign_base_replays": 1, "recorded_candidate_prewrite_refusals": 1,
            "recorded_canonical_empty_and_behind_reopens": 6, "recorded_parent_foreign_reopen_ready": 1,
            "recorded_public_queries": queries, "recorded_available_canonical_queries": available,
            "recorded_native_unit_root_tests": 13, "recorded_native_unit_pass_results": 30,
            "recorded_native_unit_skips": 0, "prior_rollback_native_roots_rerun": 12,
            "independent_small_cache_metadata_images": 3, "independent_v1_second_momentum_hash_frames": 1,
            "independent_canonical_witness_folds": 1, "witness_levels_per_fold": 256,
            "recorded_reference_platform": "darwin/arm64", "reference_processes_executed_by_this_check": 0,
            "whole_module_graph_verification": "NOT_QUALIFIED", "consumer_result": "REFUSED",
            "source": expected_source(), "scope": dict(SCOPE),
            "reader_inputs_sha256": {name: P.sha(P.read_regular(HERE / name, 1 << 20)) for name in INPUTS},
            "raw_stderr_or_private_receipts_rehashed_by_this_check": False}


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
        print("Recorded cache forward replay refused; preserve failures and disabled acceptance.", file=sys.stderr)
        sys.exit(1)
