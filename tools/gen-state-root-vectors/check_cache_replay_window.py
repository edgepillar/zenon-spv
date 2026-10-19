#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Check recorded native replay-window observations without a backend.

Successor hash frames, removed protobuf records and the witness fold have
independent byte models. Full database digests remain recorded observations.
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
spec = importlib.util.spec_from_file_location("recorded_window_preparer", HERE / "prepare_cache_replay_window.py")
H = importlib.util.module_from_spec(spec)
spec.loader.exec_module(H)
spec = importlib.util.spec_from_file_location("recorded_window_predecessor", HERE / "check_cache_forward_replay.py")
PRIOR = importlib.util.module_from_spec(spec)
spec.loader.exec_module(PRIOR)
P, W = H.P, PRIOR.W
CORPUS = "native-cache-replay-window.json"
CORPUS_SHA256 = "4acfd383e0cb606c72340cc21b0d23011ee29456abfe6785850e2b96597ccc7d"
CORPUS_BYTES = 138178
MAX_BYTES = 256 << 10
EXECUTION_SHA256 = "15497851262d4a99debbbe9feb45a92e0e825e3b92b405ea39c36788bc1c380c"
SNAPSHOTS_SHA256 = "44d406c47229e055b59851c1178789b4dd44197330b9fd32c7399e0fd4f4fa22"
NORMAL_STDERR = {"bytes": 341, "sha256": "3f61fd9714c8a2806b251b5563be66f910f4767488efefa94132c3a551a78eb5"}
CASE_STDERR = [NORMAL_STDERR] * 3 + [
    {"bytes": 2567, "sha256": "a2d9cf355b86f7ee89637e593ffff5430e6de29098c6657626b9ed8b0f05a853"},
    {"bytes": 2567, "sha256": "6d0c65349e8ce2dbc0d75698df1a2744b6b6b8af127a18f824b25a7d46231506"},
] + [NORMAL_STDERR] * 5
ZERO = "00" * 32
KEY = "0300000000000000000000000000000000000000000304066318c6318c6318c6"
FRAMING = "ordered u64be key length, key bytes, u64be value length, value bytes"
SCOPE = {
    "real_public_Chain_Init_and_Stop": True, "real_disk_ledger_cache_and_NodeTree_managers": True,
    "source_embedded_unsigned_genesis_VM": True, "three_local_unsigned_successor_momentums": True,
    "controlled_closed_ledger_entry_removal": True, "explicit_fixture_restore_separate_from_runtime": True,
    "experimental_complete_replay_window_preflight": True, "native_component_race_controls_recorded": True,
    "hosted_checks_replay_recorded_bytes": True, "caller_recovered_Init_panics_are_explicit": True,
    "process_exit_zero_implies_startup_success": False, "Chain_Start_called": False,
    "full_node_service_executed": False, "network_or_consensus_executed": False,
    "live_reorg_qualified": False, "concurrent_public_lifecycle_qualified": False, "power_loss_qualified": False,
    "whole_window_IO_atomicity_claimed": False, "ledger_patch_retention_qualified": False,
    "runtime_repairs_missing_ledger_entries": False, "test_overlays_or_scheduler_hooks": False,
    "node_client_profile_agreed": False, "network_activation_authenticated": False,
    "accepted_header_binding": False, "runtime_state_value_acceptance": False, "production_qualified": False,
    "checker_executes_reference_backend": False, "public_record_authenticates_private_receipts": False,
    "complete_logical_store_digests_independently_rebuilt_by_checker": False,
}
INPUTS = tuple(dict.fromkeys((
    "prepare_cache_replay_window.py", H.PATCH, H.PROBE, H.CONTROL, H.COMPAT_CONTROL,
    "check_cache_forward_replay.py", "testdata/" + PRIOR.CORPUS, *PRIOR.INPUTS,
)))


def document(raw):
    P.require(type(raw) is bytes and 0 < len(raw) <= MAX_BYTES)
    # The complete ten-case recording exceeds the older reader's 128 KiB cap.
    # Keep its duplicate-name and non-finite refusals with this local bound.
    def constant(_):
        raise ValueError("Non-finite JSON refused")
    return json.loads(raw, object_pairs_hook=P.pairs, parse_constant=constant)


def identifiers():
    ids = {"A1": dict(W.GENESIS), "EMPTY": {"hash": ZERO, "height": 0}}
    empty = hashlib.sha3_256(b"").digest()
    for height in range(2, 5):
        previous = ids["A" + str(height - 1)]
        frame = struct.pack(">QQ", 1, 1) + bytes.fromhex(previous["hash"])
        frame += struct.pack(">QQ", height, 1637755200 + (height - 1) * 10) + empty * 3
        P.require(len(frame) == 160)
        ids["A" + str(height)] = {"hash": hashlib.sha3_256(frame).hexdigest(), "height": height}
    return ids


def momentum(height):
    ids = identifiers()
    return {"version": 1, "chainIdentifier": 1, "hash": ids["A" + str(height)]["hash"],
            "previousHash": ids["A" + str(height - 1)]["hash"], "height": height,
            "timestamp": 1637755200 + (height - 1) * 10,
            "changesHash": hashlib.sha3_256(b"").hexdigest(), "data": None, "content": None,
            "publicKey": None, "signature": None, "nextFusionPrice": 0, "nextWorkPrice": 0, "stateRoot": ZERO}


def varint(value):
    P.require(type(value) is int and 0 <= value < (1 << 64))
    result = bytearray()
    while value >= 128:
        result.append((value & 127) | 128)
        value >>= 7
    result.append(value)
    return bytes(result)


def removed_entry(height):
    P.require(height in (2, 3))
    header = momentum(height)
    def hash_message(tag, value):
        return bytes([tag, 34, 10, 32]) + bytes.fromhex(value)
    # MomentumProto fields 1,2,3,4,5,6,9. Empty optional fields, including
    # StateRoot field 14, are absent. The LevelDB wrapper prefixes present data.
    raw = b"\x08\x01\x10\x01" + hash_message(26, header["hash"])
    raw += hash_message(34, header["previousHash"])
    raw += b"\x28" + varint(height) + b"\x30" + varint(header["timestamp"])
    raw += hash_message(74, header["changesHash"])
    return b"\x55\x02" + struct.pack(">Q", height), b"\x00" + raw


def expected_source():
    plan = H.plan("NEW_OWNED_WORKSPACE", "PINNED_GO")
    controls = {name: dict(pin) for name, pin in H.H.G.CONTROL_SOURCES.items()}
    controls[H.COMPAT_CONTROL] = {"target": H.H.CONTROL_TARGET, "bytes": H.COMPAT_BYTES, "sha256": H.COMPAT_SHA256}
    controls[H.CONTROL] = {"target": H.CONTROL_TARGET, "bytes": H.CONTROL_BYTES, "sha256": H.CONTROL_SHA256}
    return {"repository": "https://github.com/digitalSloth/go-zenon", "revision": P.REVISION,
            "original_tree": P.TREE, "source_blobs": 467, "parent_compiled_source_blobs": 471,
            "candidate_compiled_source_blobs": 472, "source_manifest_sha256": P.SOURCE_SHA256,
            "parent_runtime_tree": H.H.MODIFIED_TREE, "candidate_runtime_tree": H.MODIFIED_TREE,
            "parent_build_tree": H.parent_build_tree(), "candidate_build_tree": H.BUILD_TREE,
            "probe": plan["probe"], "patch_sha256": H.PATCH_SHA256,
            "module_sha256": plan["module_sha256"], "sum_sha256": plan["sum_sha256"], "native_controls": controls}


def ref(value):
    P.require(type(value) is dict and set(value) == {"sha256", "bytes"})
    P.require(type(value["sha256"]) is str and re.fullmatch("[0-9a-f]{64}", value["sha256"]) is not None)
    P.require(type(value["bytes"]) is int and 0 <= value["bytes"] < (1 << 31))


def command(value, raw=None, stderr=None, actual_exit=0):
    P.require(type(value) is dict and set(value) == {"state", "actual_exit", "output_complete", "reason", "stdout", "stderr"})
    P.exact([value[k] for k in ("state", "actual_exit", "output_complete", "reason")],
            ["COMPLETE", actual_exit, True, None])
    ref(value["stdout"])
    ref(value["stderr"])
    if raw is not None:
        P.exact(value["stdout"], {"sha256": P.sha(raw), "bytes": len(raw)})
    if stderr is not None:
        P.exact(value["stderr"], stderr)


def cache_projection(row):
    return {k: row[k] for k in ("frontier", "frontier_raw_value", "frontier_present", "records",
                               "key_bytes", "value_bytes", "raw_store_sha256")}


def ledger_projection(row):
    return {k: row[k] for k in ("frontier", "records", "key_bytes", "value_bytes", "raw_store_sha256")}


def snapshot(row, stage, case, cache, attempt=None):
    fields = {"case", "stage", "frontier", "records", "key_bytes", "value_bytes", "framing", "raw_store_sha256"}
    if cache:
        fields |= {"frontier_raw_value", "frontier_present"}
    if attempt is not None:
        fields.add("attempt")
    P.require(type(row) is dict and set(row) == fields)
    P.exact([row["case"], row["stage"], row["framing"]], [case, stage, FRAMING])
    if attempt is not None:
        P.exact(row["attempt"], attempt)
    P.require(all(type(row[k]) is int and 0 <= row[k] < (1 << 31) for k in ("records", "key_bytes", "value_bytes")))
    P.require(row["records"] <= 1000000 and type(row["raw_store_sha256"]) is str and
              re.fullmatch("[0-9a-f]{64}", row["raw_store_sha256"]) is not None)
    ids = identifiers()
    P.require(row["frontier"] in ids.values())
    if cache:
        identifier = row["frontier"]
        raw = b"" if identifier == ids["EMPTY"] else \
            b"\0\x0a\x22\x0a\x20" + bytes.fromhex(identifier["hash"]) + b"\x10" + bytes([identifier["height"]])
        P.exact([row["frontier_raw_value"], row["frontier_present"]], [raw.hex(), identifier != ids["EMPTY"]])


def execution(value):
    P.require(type(value) is dict and P.sha(P.UTIL.encoded(value)) == EXECUTION_SHA256)
    P.exact([value[k] for k in ("ordinary_entrypoint_builds", "actual_case_processes", "new_candidate_ordinary_builds",
                               "new_candidate_case_processes", "retained_parent_ordinary_builds", "retained_parent_case_processes",
                               "parent_backend_reexecuted_by_candidate_followup", "parent_task_outcome")],
            [2, 10, 1, 5, 1, 5, False, "FAILURE_DUE_TO_CANDIDATE_CONTROL_BUILD_ERROR"])
    P.exact([value[k] for k in ("compiler", "recorded_reference_platform", "new_source_or_dependency_transports",
                               "verified_dependency_inputs", "linked_modules", "serial_private_compiler_cache_reused_within_candidate_task",
                               "physical_reclaim_or_peak_disk_claim", "whole_module_graph_verification")],
            ["go1.25.14", "darwin/arm64", 0, 75, 25, True, False, "NOT_QUALIFIED_PRIOR_UNUSED_PROXY_FAILURE_PRESERVED"])
    command(value["prior_candidate_control_compile_failure"], actual_exit=1)
    command(value["parent_build"])
    command(value["candidate_build"])
    ref(value["parent_ordinary_binary"])
    ref(value["candidate_ordinary_binary"])
    P.require(value["parent_ordinary_binary"] != value["candidate_ordinary_binary"])
    modules = value["linked_module_details"]
    P.require(type(modules) is list and len(modules) == 25 and len({r["module"] for r in modules}) == 25)
    for row in modules:
        P.require(type(row) is dict and set(row) == {"module", "version", "go_sum"})
        P.require(all(type(row[k]) is str and 0 < len(row[k]) < 256 for k in row))
        P.require(re.fullmatch(r"h1:[A-Za-z0-9+/]{43}=", row["go_sum"]) is not None)
    unit = value["native_unit_controls"]
    P.require(type(unit) is dict and set(unit) == {"race_detector", "root_tests", "test_pass_results", "package_pass_results",
                                                 "skipped_or_failed", "selected_roots", "test_pass_names", "command"})
    command(unit["command"])
    P.exact([unit[k] for k in ("race_detector", "root_tests", "test_pass_results", "package_pass_results", "skipped_or_failed")],
            [True, 14, 46, 2, 0])
    P.exact(unit["selected_roots"], list(H.NATIVE_ROOTS))
    names = unit["test_pass_names"]
    P.require(type(names) is list and len(names) == len(set(names)) == 46)
    P.require(all(type(n) is str and len(n) < 256 and n.split("/")[0] in H.NATIVE_ROOTS for n in names))
    P.exact(sorted(n for n in names if "/" not in n), list(H.NATIVE_ROOTS))


def check_corpus(value):
    P.require(type(value) is dict and set(value) == {"format_version", "kind", "source", "execution", "scope", "cases", "consumer_result"})
    P.exact([value["format_version"], value["kind"], value["consumer_result"]], [1, "recorded-native-cache-replay-window", "REFUSED"])
    P.exact(value["source"], expected_source())
    P.exact(value["scope"], SCOPE)
    execution(value["execution"])
    ids = identifiers()
    proof = PRIOR.PRIOR.canonical_proof()
    P.require(W.witness_root(KEY, W.VALUE, proof) == W.ROOT)
    P.require(type(value["cases"]) is list and len(value["cases"]) == 10)
    snapshots, final_caches = [], []
    event_count = query_count = available = parent_panics = prewrite_refusals = parent_partial = 0
    for index, row in enumerate(value["cases"]):
        generation = "parent" if index < 5 else "candidate"
        case_index = index % 5
        case = H.CASES[case_index]
        gap = case_index >= 3
        height = 2 if case_index == 3 else 3
        P.require(type(row) is dict and set(row) == {"generation", "case", "command", "stdout_utf8", "stderr_diagnostics"})
        P.exact([row["generation"], row["case"]], [generation, case])
        text = row["stdout_utf8"]
        P.require(type(text) is str and 0 < len(text) < (64 << 10) and text.endswith("\n"))
        command(row["command"], text.encode(), CASE_STDERR[index])
        P.exact(row["stderr_diagnostics"], {"normal_process_complete": True,
                                           "recovered_Init_panic_count": 2 if gap and generation == "parent" else 0,
                                           "unrecovered_process_panic": False})
        events = [document(line.encode()) for line in text.splitlines()]
        stages = ["source-genesis-and-unsigned-replay-window", "canonical-ledger-and-tree-primed",
                  "ledger-before-controlled-fault", "cache-before-controlled-fault"]
        attempt_stages = ["public-init-observed", "public-state-query", "public-stop-observed",
                          "cache-after-public-stop", "ledger-after-public-stop"]
        stages += (["controlled-ledger-entry-removed", "ledger-after-controlled-fault"] if gap else []) + attempt_stages * 2
        if gap:
            stages += ["explicit-fixture-ledger-entry-restored", "ledger-after-explicit-fixture-restore"] + attempt_stages * 2
        P.require(all(type(e) is dict and e.get("case") == case for e in events))
        P.exact([e.get("stage") for e in events], stages)
        def event(stage, **fields):
            return dict(fields, case=case, stage=stage)
        P.exact(events[0], event("source-genesis-and-unsigned-replay-window", genesis_identifier=ids["A1"],
                                genesis_timestamp=1637755200, genesis_patch_bytes=W.DUMP["bytes"], genesis_patch_sha256=W.DUMP["sha256"],
                                momentums=[momentum(h) for h in range(2, 5)], target=ids["A4"], network_started=False,
                                consensus_validation_selected=False, wallet_signing_or_broadcast=False))
        P.exact(events[1], event("canonical-ledger-and-tree-primed", identifier=ids["A4"], root=W.ROOT,
                                cache_identifier=ids["A4"] if case_index == 1 else ids["A1"], ready_after_stop=False))
        ledger_before, cache_before = events[2:4]
        snapshot(ledger_before, stages[2], case, False)
        snapshot(cache_before, stages[3], case, True)
        initial = ids["EMPTY"] if case_index == 2 else ids["A4"] if case_index == 1 else ids["A1"]
        P.exact(ledger_before["frontier"], ids["A4"])
        P.exact(cache_before["frontier"], initial)
        if case_index == 2:
            P.exact([cache_before[k] for k in ("records", "key_bytes", "value_bytes", "raw_store_sha256")],
                    [0, 0, 0, hashlib.sha256(b"").hexdigest()])
        ledger_damaged = ledger_before
        if gap:
            key, raw = removed_entry(height)
            P.exact(events[4], event("controlled-ledger-entry-removed", height=height, raw_key=key.hex(), raw_value=raw.hex(),
                                    raw_value_sha256=P.sha(raw), runtime_repair_selected=False))
            ledger_damaged = events[5]
            snapshot(ledger_damaged, "ledger-after-controlled-fault", case, False)
            P.exact(ledger_damaged["frontier"], ids["A4"])
            P.exact([ledger_damaged[k] for k in ("records", "key_bytes", "value_bytes")],
                    [ledger_before["records"] - 1, ledger_before["key_bytes"] - len(key), ledger_before["value_bytes"] - len(raw)])
            P.require(ledger_damaged["raw_store_sha256"] != ledger_before["raw_store_sha256"])
        offset = 6 if gap else 4
        partial_caches = []
        for attempt in range(4 if gap else 2):
            if gap and attempt == 2:
                key, _ = removed_entry(height)
                P.exact(events[offset], event("explicit-fixture-ledger-entry-restored", height=height, raw_key=key.hex(), runtime_repair_selected=False))
                snapshot(events[offset + 1], "ledger-after-explicit-fixture-restore", case, False)
                P.exact(ledger_projection(events[offset + 1]), ledger_projection(ledger_before))
                offset += 2
            start, query, stop, cache, ledger = events[offset:offset + 5]
            offset += 5
            damaged = gap and attempt < 2
            panicked = damaged and generation == "parent"
            ready = not damaged
            P.require(set(start) == {"stage", "case", "attempt", "error", "panicked", "panic_type", "panic_functions", "ready"})
            P.exact([start[k] for k in ("stage", "case", "attempt", "error", "panicked", "ready")],
                    ["public-init-observed", case, attempt, "none" if panicked or ready else "missing-replay-momentum", panicked, ready])
            if panicked:
                P.require(type(start["panic_type"]) is str and 0 < len(start["panic_type"]) < 64)
                funcs = start["panic_functions"]
                P.require(type(funcs) is list and 0 < len(funcs) <= 64)
                P.require(all(type(f) is str and f.startswith("github.com/zenon-network/go-zenon/") and len(f) < 256 for f in funcs))
                P.require(any("chain.(*chainCache).Init" in f for f in funcs))
                parent_panics += 1
            else:
                P.exact([start["panic_type"], start["panic_functions"]], ["", None])
            P.exact(query, event("public-state-query", attempt=attempt, identifier=ids["A4"],
                                 root=W.ROOT if ready else ZERO, root_error="none" if ready else "not-ready",
                                 proof_error="none" if ready else "not-ready", value=W.VALUE if ready else "", proof=proof if ready else ""))
            P.exact(stop, event("public-stop-observed", attempt=attempt, error="none", panicked=False,
                                panic_type="", panic_functions=None, ready=False))
            snapshot(cache, "cache-after-public-stop", case, True, attempt)
            snapshot(ledger, "ledger-after-public-stop", case, False, attempt)
            P.exact(ledger_projection(ledger), ledger_projection(ledger_damaged if damaged else ledger_before))
            if damaged and generation == "candidate":
                P.exact(cache_projection(cache), cache_projection(cache_before))
                prewrite_refusals += 1
            elif damaged:
                P.exact(cache["frontier"], ids["A1"] if height == 2 else ids["A2"])
                partial_caches.append(cache_projection(cache))
                if height == 3:
                    parent_partial += 1
                else:
                    P.exact(cache_projection(cache), cache_projection(cache_before))
            else:
                P.exact(cache["frontier"], ids["A4"])
            query_count += 1
            available += int(ready)
        P.require(offset == len(events))
        if partial_caches:
            P.exact(partial_caches[0], partial_caches[1])
        final_caches.append(cache_projection(cache))
        snapshots.extend({"generation": generation, "case": case, "event": e} for e in events if "raw_store_sha256" in e)
        event_count += len(events)
    P.require(all(row == final_caches[0] for row in final_caches))
    P.require(P.sha(P.UTIL.encoded(snapshots)) == SNAPSHOTS_SHA256)
    P.exact([event_count, query_count, available, parent_panics, prewrite_refusals, parent_partial], [196, 28, 20, 4, 4, 2])
    return {"kind": "recorded-native-cache-replay-window-check", "recorded_cases": 10,
            "recorded_raw_exits": [0] * 10, "recorded_event_observations": event_count,
            "recorded_parent_Init_panics": parent_panics, "recorded_parent_partial_replay_observations": parent_partial,
            "recorded_candidate_Init_panics": 0, "recorded_candidate_prewrite_refusals": prewrite_refusals,
            "recorded_final_clean_reopens": 10, "recorded_explicit_fixture_restores": 4,
            "recorded_public_queries": query_count, "recorded_available_canonical_queries": available,
            "recorded_native_unit_root_tests": 14, "recorded_native_unit_pass_results": 46, "recorded_native_unit_skips": 0,
            "independent_v1_successor_hash_frames": 3, "independent_removed_entry_protobuf_models": 2,
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
        print("Recorded cache replay window refused; preserve failures and disabled acceptance.", file=sys.stderr)
        sys.exit(1)
