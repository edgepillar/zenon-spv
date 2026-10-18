#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Check recorded native cache recovery, without starting a reference backend.

The small metadata fault images are independently reconstructed. Large canonical
cache digests and command references remain recorded component observations;
this reader does not authenticate private receipts or an accepted chain header.
"""
import argparse
import hashlib
import importlib.util
from pathlib import Path
import json
import re
import struct
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("recorded_cache_fix_preparer", HERE / "prepare_cache_identifier_rollback.py")
G = importlib.util.module_from_spec(spec)
spec.loader.exec_module(G)
spec = importlib.util.spec_from_file_location("recorded_cache_canonical_witness", HERE / "check_public_chain_lifecycle_successor.py")
W = importlib.util.module_from_spec(spec)
spec.loader.exec_module(W)
P = G.P
CORPUS = "native-cache-identifier-rollback.json"
CORPUS_SHA256 = "a1a9d4b48f21b53d49d3f7c359ddbdea70e22acbd6964d2552923d673faa91e0"
CORPUS_BYTES = 57410
MAX_BYTES = 128 << 10
EXECUTION_SHA256 = "4c9c5436701e3bdedc7dbba4ce81e34c0f270286130a6c7d58fd5b44693ca6b3"
SNAPSHOTS_SHA256 = "939eb544f9f59ff19872b35c49d5cb70cae0d910eda6fbc1640206760f7ade05"
CASE_STDERR = [
    {
        "bytes": 341,
        "sha256": "b7a05b279e6452674a61d2d3372228d538d37e56c975e7319b07ec42d22a6cd4"
    },
    {
        "bytes": 143,
        "sha256": "415ff0c35dadf8f8a726c5317a98902761f4807ace1c6786ab6a1ab3c20d39f6"
    },
    {
        "bytes": 242,
        "sha256": "d35bc7092a837e727dccf8326121b7efc867049bdad411150532b1b6b55f25d7"
    },
    {
        "bytes": 440,
        "sha256": "8634b22ee95401751abf5ea38abe3a423e8e9acb6a6bf8249e0ee9ac679d01ac"
    },
    {
        "bytes": 341,
        "sha256": "b7a05b279e6452674a61d2d3372228d538d37e56c975e7319b07ec42d22a6cd4"
    },
    {
        "bytes": 143,
        "sha256": "415ff0c35dadf8f8a726c5317a98902761f4807ace1c6786ab6a1ab3c20d39f6"
    },
    {
        "bytes": 143,
        "sha256": "415ff0c35dadf8f8a726c5317a98902761f4807ace1c6786ab6a1ab3c20d39f6"
    },
    {
        "bytes": 440,
        "sha256": "8634b22ee95401751abf5ea38abe3a423e8e9acb6a6bf8249e0ee9ac679d01ac"
    }
]
ZERO = "00" * 32
FRAMING = "ordered u64be key length, key bytes, u64be value length, value bytes"
SCOPE = {name: True for name in (
    "real_public_Chain_Init_and_Stop", "real_disk_ledger_cache_and_NodeTree_managers",
    "source_embedded_unsigned_genesis_VM", "separate_native_cache_frontier_metadata_fault_fixtures",
    "experimental_native_cache_identity_fix", "prewrite_identity_refusal_observed",
    "canonical_clean_reopens_recorded", "race_native_component_controls_recorded",
    "hosted_checks_replay_recorded_bytes",
)}
SCOPE.update({name: False for name in (
    "Chain_Start_called", "full_node_service_executed", "network_or_consensus_executed",
    "live_reorg_qualified", "concurrent_public_lifecycle_qualified", "power_loss_qualified",
    "whole_window_atomicity_claimed", "test_overlays_or_scheduler_hooks", "node_client_profile_agreed",
    "network_activation_authenticated", "accepted_header_binding", "runtime_state_value_acceptance",
    "production_qualified", "checker_executes_reference_backend", "public_record_authenticates_private_receipts",
    "complete_alternate_chain_cache_application_qualified",
)})
INPUTS = tuple(dict.fromkeys(("prepare_cache_identifier_rollback.py", G.PATCH,
    "prepare_public_chain_cache_startup.py", G.F.PROBE, *G.CONTROL_SOURCES,
    "check_public_chain_lifecycle_successor.py", "testdata/" + W.CORPUS, *W.INPUTS)))


def document(raw):
    P.require(type(raw) is bytes and 0 < len(raw) <= MAX_BYTES)
    return W.document(raw)


def identifiers():
    a = dict(W.GENESIS)
    b = dict(a, hash=("%02x" % (int(a["hash"][:2], 16) ^ 1)) + a["hash"][2:])
    b2 = dict(b, hash=("%02x" % (int(b["hash"][:2], 16) ^ 2)) + b["hash"][2:], height=2)
    return {"A1": a, "B1": b, "B2": b2}


def raw_identifier(label):
    selected = identifiers()[label]
    # Source protobuf: HashHeightProto field 1 nests HashProto bytes field 1;
    # field 2 holds height. The selected heights use one canonical varint byte.
    return b"\0\x0a\x22\x0a\x20" + bytes.fromhex(selected["hash"]) + b"\x10" + bytes([selected["height"]])


def fault_image(label):
    P.require(label in ("B1", "B2"))
    rows = [(bytes([85, 0]), raw_identifier(label)),
            (bytes([119]) + struct.pack(">Q", 1), bytes([0, 1, 0]))]
    if label == "B2":
        previous = raw_identifier("B1")[1:]
        # goleveldb Batch.Dump: Put=1, key length/key, value length/value.
        # The predecessor of the first Add is Delete=0, key length/key.
        rows.append((bytes([119]) + struct.pack(">Q", 2), bytes([1, 1, 0, len(previous)]) + previous))
    frame = b"".join(struct.pack(">Q", len(k)) + k + struct.pack(">Q", len(v)) + v for k, v in sorted(rows))
    return {"records": len(rows), "key_bytes": sum(len(k) for k, _ in rows),
            "value_bytes": sum(len(v) for _, v in rows), "raw_store_sha256": P.sha(frame)}


def canonical_proof():
    raw = P.read_regular(HERE / "testdata" / W.CORPUS, W.MAX_BYTES)
    P.require(len(raw) == W.CORPUS_BYTES and P.sha(raw) == W.CORPUS_SHA256)
    proof = document(raw)["selection"]["witness"]["proof"]
    P.require(W.witness_root(W.KEY, W.VALUE, proof) == W.ROOT)
    return proof


def expected_source():
    parent = G.F.plan("NEW_OWNED_WORKSPACE", "PINNED_GO")
    candidate = G.plan("NEW_OWNED_WORKSPACE", "PINNED_GO")
    P.require(parent["build_tree"] == "fddb1aa97799fbe1303f2c37ce950a80ac8e82e5")
    P.require(candidate["build_tree"] == "22b5e4721422e4e303b8da2ba3ae243f01925f53")
    return {"repository": "https://github.com/digitalSloth/go-zenon", "revision": P.REVISION,
            "original_tree": P.TREE, "source_blobs": 467, "source_manifest_sha256": P.SOURCE_SHA256,
            "parent_runtime_tree": G.F.C.MODIFIED_TREE, "candidate_runtime_tree": G.MODIFIED_TREE,
            "parent_build_tree": parent["build_tree"], "candidate_build_tree": candidate["build_tree"],
            "probe": {"sha256": G.F.PROBE_SHA256, "bytes": G.F.PROBE_BYTES},
            "patch_sha256": G.PATCH_SHA256, "module_sha256": candidate["module_sha256"],
            "sum_sha256": candidate["sum_sha256"],
            "added_native_control_targets": sorted(G.extra_sources().keys() - {G.F.ENTRYPOINT})}


def command(row, raw, stderr):
    P.exact(row, {"state": "COMPLETE", "actual_exit": 0, "output_complete": True, "reason": None,
                  "stdout": {"sha256": P.sha(raw), "bytes": len(raw)}, "stderr": stderr})


def snapshot(value, generation, case, label, before, metadata):
    fields = {"stage", "case", "frontier", "frontier_raw_value", "records", "key_bytes", "value_bytes",
              "framing", "raw_store_sha256"} | ({"metadata_only_fixture"} if before else set())
    P.require(type(value) is dict and set(value) == fields)
    P.exact([value["stage"], value["case"], value["frontier"], value["frontier_raw_value"], value["framing"]],
            ["cache-fixture-before-public-init" if before else "cache-fixture-after-public-stop",
             case, identifiers()[label], raw_identifier(label).hex(), FRAMING])
    if before:
        P.exact(value["metadata_only_fixture"], metadata)
    P.require(all(type(value[k]) is int and 0 < value[k] < (1 << 31) for k in ("records", "key_bytes", "value_bytes")))
    P.require(value["records"] <= 1000000 and type(value["raw_store_sha256"]) is str and
              re.fullmatch("[0-9a-f]{64}", value["raw_store_sha256"]) is not None)
    if metadata:
        P.exact({k: value[k] for k in fault_image(label)}, fault_image(label))


def check_corpus(value):
    P.require(type(value) is dict and set(value) == {"format_version", "kind", "source", "execution", "scope", "cases", "consumer_result"})
    P.exact([value["format_version"], value["kind"], value["consumer_result"]],
            [1, "recorded-native-cache-identifier-rollback", "REFUSED"])
    P.exact(value["source"], expected_source())
    P.exact(value["scope"], SCOPE)
    execution = value["execution"]
    P.require(P.sha(P.UTIL.encoded(execution)) == EXECUTION_SHA256)
    P.exact([execution["ordinary_entrypoint_builds"], execution["actual_case_processes"],
             execution["new_source_or_dependency_transports"], execution["verified_dependency_inputs"],
             execution["linked_modules"], execution["physical_reclaim_or_peak_disk_claim"]], [2, 8, 0, 75, 25, False])
    unit = execution["native_unit_controls"]
    P.exact([unit["race_detector"], unit["root_tests"], unit["test_pass_results"], unit["package_pass_results"],
             unit["skipped_or_failed"]], [True, 12, 22, 2, 0])
    proof = canonical_proof()
    P.require(type(value["cases"]) is list and len(value["cases"]) == 8)
    ids = identifiers()
    observations = []
    queries = available = event_count = 0
    for index, row in enumerate(value["cases"]):
        generation = "parent" if index < 4 else "candidate"
        case_index = index % 4
        case = G.F.CASES[case_index]
        P.require(type(row) is dict and set(row) == {"generation", "case", "command", "stdout_utf8", "stderr_diagnostics"})
        P.exact([row["generation"], row["case"]], [generation, case])
        text = row["stdout_utf8"]
        P.require(type(text) is str and 0 < len(text) < (16 << 10) and text.endswith("\n"))
        raw = text.encode()
        command(row["command"], raw, CASE_STDERR[index])
        P.exact(row["stderr_diagnostics"], {"normal_process_complete": True, "runtime_panic_observed": False})
        events = [document(line.encode()) for line in text.splitlines()]
        ready = case_index in (0, 3) or (case_index == 2 and generation == "parent")
        before = "A1" if case_index == 0 else "B1" if case_index == 1 else "B2"
        after = "B1" if case_index == 2 and generation == "parent" else "A1" if ready else before
        metadata = case_index in (1, 2)
        P.require(len(events) == (9 if ready else 7))
        snapshot(events[2], generation, case, before, True, metadata)
        snapshot(events[6], generation, case, after, False, metadata)
        P.require((events[2]["raw_store_sha256"] == events[6]["raw_store_sha256"]) is (before == after))
        observations.append({"generation": generation, "case": case, "before": events[2], "after": events[6]})
        def event(stage, **fields):
            return dict(fields, case=case, stage=stage)
        def query(stage, good):
            return event(stage, identifier=W.GENESIS, root=W.ROOT if good else ZERO,
                         root_error="none" if good else "not-ready", proof_error="none" if good else "not-ready",
                         value=W.VALUE if good else "", proof=proof if good else "")
        equal = after == "A1"
        expected = [event("source-genesis", identifier=W.GENESIS, raw_patch_bytes=W.DUMP["bytes"],
                          raw_patch_sha256=W.DUMP["sha256"], network_started=False, wallet_signing_or_broadcast=False),
                    event("canonical-ledger-cache-tree-primed", identifier=W.GENESIS, root=W.ROOT, ready_after_stop=False),
                    events[2], event("public-init-returned", ready=ready,
                                    error="none" if ready else "cache-frontier-identity-mismatch",
                                    ledger_frontier=W.GENESIS, cache_frontier=ids[after], frontiers_equal=equal),
                    query("public-state-query", ready), event("public-stop", ready=False), events[6]]
        if ready:
            reopened_ready = equal
            expected += [event("public-clean-reopen", ready=reopened_ready,
                               error="none" if equal else "cache-frontier-identity-mismatch",
                               ledger_frontier=W.GENESIS, cache_frontier=ids[after]),
                         query("reopened-state-query", reopened_ready)]
        P.exact(events, expected)
        event_count += len(events)
        queries += 2 if ready else 1
        available += (1 + int(equal)) if ready else 0
    P.require(P.sha(P.UTIL.encoded(observations)) == SNAPSHOTS_SHA256)
    return {"kind": "recorded-native-cache-identifier-rollback-check", "recorded_cases": 8,
            "recorded_raw_exits": [0] * 8, "recorded_event_observations": event_count,
            "recorded_parent_mixed_identity_starts": 1, "recorded_candidate_prewrite_refusals": 2,
            "recorded_canonical_clean_reopens": 4, "recorded_parent_mixed_reopen_refusals": 1,
            "recorded_public_queries": queries, "recorded_available_canonical_queries": available,
            "recorded_native_unit_root_tests": 12, "recorded_native_unit_pass_results": 22,
            "recorded_native_unit_skips": 0, "independent_small_cache_metadata_images": 2,
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
        print("Recorded native cache recovery refused; preserve failures and disabled acceptance.", file=sys.stderr)
        sys.exit(1)
