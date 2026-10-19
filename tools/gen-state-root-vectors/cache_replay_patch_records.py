#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Check replay-patch case records without executing the reference backend.

This helper checks recorded command completeness, the complete event sequence,
source-selected identities, startup/readiness/stop boundaries, logical database
observations and separately supplied metadata reports. It is not a complete
candidate/source/binary qualification or authentication of private receipts.
Use cache_replay_patch_bytes with the retained payloads to independently decode
all metadata and rehash the stored patch augmentation.
"""
import hashlib
import importlib.util
from pathlib import Path
import re
import struct
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("patch_record_window", HERE / "check_cache_replay_window.py")
WINDOW = importlib.util.module_from_spec(spec)
spec.loader.exec_module(WINDOW)
spec = importlib.util.spec_from_file_location("patch_record_preparer", HERE / "prepare_cache_replay_patches.py")
H = importlib.util.module_from_spec(spec)
spec.loader.exec_module(H)
P, W = WINDOW.P, WINDOW.W
MAX_STDOUT_BYTES = 64 << 10
PATCH_MODELS = {
    1: {"source_changes_bytes": 10849399,
        "source_changes_sha256": "a222aac55304b1a489d395235c61af4182ac08b887d24d0c3f654aa402f35e75",
        "metadata_bytes": 930529,
        "metadata_sha256": "4c00de71eb1f7aecd015c5724adbffd9037c5c8d52cc96c142d726628008556c",
        "content_headers": 14094, "expected_stored_bytes": 11779928,
        "expected_stored_sha256": "4bfe2db6664305ddcc0c9c8c2b268ca17927a278e5226b6ddadd4547e516e48b"},
    2: {"source_changes_bytes": 0,
        "source_changes_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "metadata_bytes": 218,
        "metadata_sha256": "f67ba4ddbf4cf699d3dc6515d24a657897c09e4cea02c028bd7f123094d3d539",
        "content_headers": 0, "expected_stored_bytes": 218,
        "expected_stored_sha256": "f67ba4ddbf4cf699d3dc6515d24a657897c09e4cea02c028bd7f123094d3d539"},
}
ATTEMPT_STAGES = ["public-init-observed", "public-state-query", "public-stop-observed",
                  "cache-after-public-stop", "ledger-after-public-stop"]


def event(stage, case, **fields):
    return dict(fields, case=case, stage=stage)


def metadata_report(report, height):
    expected = PATCH_MODELS[height]
    fields = set(expected) | {"metadata_puts", "serialized_momentum_bytes",
                              "independent_v1_frame_hex", "independent_v1_frame_sha3_256"}
    P.require(type(report) is dict and set(report) == fields)
    P.exact({key: report[key] for key in expected}, expected)
    P.exact(report["metadata_puts"], 3)
    size = report["serialized_momentum_bytes"]
    P.require(type(size) is int and 0 < size < (4 << 20))
    # The first put has a 1-byte key and 38-byte HashHeight value. The
    # hash-index put has a 33-byte key and 8-byte value. The body index has
    # a 9-byte key and a canonical varint value length.
    P.exact(expected["metadata_bytes"], 42 + 44 + 11 + len(WINDOW.varint(size)) + size)
    frame = report["independent_v1_frame_hex"]
    P.require(type(frame) is str and re.fullmatch("[0-9a-f]{320}", frame) is not None)
    raw = bytes.fromhex(frame)
    ids = WINDOW.identifiers()
    previous = WINDOW.ZERO if height == 1 else ids["A1"]["hash"]
    prefix = struct.pack(">QQ", 1, 1) + bytes.fromhex(previous)
    prefix += struct.pack(">QQ", height, 1637755200 + (height - 1) * 10)
    P.exact(raw[:64], prefix)
    P.exact(hashlib.sha3_256(raw).hexdigest(), ids["A" + str(height)]["hash"])
    P.exact(report["independent_v1_frame_sha3_256"], ids["A" + str(height)]["hash"])
    if height == 2:
        P.exact(raw[64:], hashlib.sha3_256(b"").digest() * 3)
    return expected


def check_case(generation, case, command, stdout, report=None):
    P.require(type(generation) is str and generation in ("parent", "candidate"))
    P.require(type(case) is str and case in H.CASES)
    P.require(type(stdout) is bytes and 0 < len(stdout) <= MAX_STDOUT_BYTES and stdout.endswith(b"\n"))
    WINDOW.command(command, raw=stdout)
    events = [WINDOW.document(line) for line in stdout.splitlines()]
    gap = case != H.CASES[0]
    required_missing = case == H.CASES[1]
    height = 2 if case == H.CASES[4] else 1
    stages = ["source-genesis-and-unsigned-replay-window", "canonical-ledger-and-tree-primed",
              "ledger-before-controlled-fault", "cache-before-controlled-fault"]
    if gap:
        stages += ["stored-ledger-patch-source-check", "controlled-ledger-entry-removed", "ledger-after-controlled-fault"]
    stages += ATTEMPT_STAGES * 2
    if gap:
        stages += ["explicit-fixture-ledger-entry-restored", "ledger-after-explicit-fixture-restore"] + ATTEMPT_STAGES * 2
    P.require(all(type(row) is dict and row.get("case") == case for row in events))
    P.exact([row.get("stage") for row in events], stages)
    ids = WINDOW.identifiers()
    proof = WINDOW.PRIOR.PRIOR.canonical_proof()
    P.require(W.witness_root(WINDOW.KEY, W.VALUE, proof) == W.ROOT)
    P.exact(events[0], event(stages[0], case, genesis_identifier=ids["A1"], genesis_timestamp=1637755200,
                            genesis_patch_bytes=W.DUMP["bytes"], genesis_patch_sha256=W.DUMP["sha256"],
                            genesis_account_block_count=14094, momentums=[WINDOW.momentum(h) for h in range(2, 5)],
                            target=ids["A4"], network_started=False, consensus_validation_selected=False,
                            wallet_signing_or_broadcast=False))
    P.exact(events[1], event(stages[1], case, identifier=ids["A4"], root=W.ROOT,
                            cache_identifier=ids["A4"] if case == H.CASES[2] else ids["A1"], ready_after_stop=False))
    ledger_before, cache_before = events[2:4]
    WINDOW.snapshot(ledger_before, stages[2], case, False)
    WINDOW.snapshot(cache_before, stages[3], case, True)
    initial = ids["EMPTY"] if case in (H.CASES[0], H.CASES[1], H.CASES[4]) else ids["A4"] if case == H.CASES[2] else ids["A1"]
    P.exact(ledger_before["frontier"], ids["A4"])
    P.exact(cache_before["frontier"], initial)
    if initial == ids["EMPTY"]:
        P.exact([cache_before[key] for key in ("records", "key_bytes", "value_bytes", "raw_store_sha256")],
                [0, 0, 0, hashlib.sha256(b"").hexdigest()])
    damaged_ledger = ledger_before
    key = b"\x66" + struct.pack(">Q", height)
    if gap:
        model = metadata_report(report, height)
        P.exact(events[4], event(stages[4], case, height=height,
                                source_changes_bytes=model["source_changes_bytes"], source_changes_sha256=model["source_changes_sha256"],
                                frontier_metadata_bytes=model["metadata_bytes"], frontier_metadata_sha256=model["metadata_sha256"],
                                expected_stored_bytes=model["expected_stored_bytes"], expected_stored_sha256=model["expected_stored_sha256"],
                                actual_stored_bytes=model["expected_stored_bytes"], actual_stored_sha256=model["expected_stored_sha256"],
                                metadata_file="expected-ledger-metadata.bin", mismatch_capture_file="unexpected-stored-patch.bin",
                                stored_bytes_equal_source_augmentation=True))
        P.exact(events[5], event(stages[5], case, height=height, raw_key=key.hex(),
                                raw_value_bytes=model["expected_stored_bytes"], raw_value_sha256=model["expected_stored_sha256"],
                                runtime_repair_selected=False))
        damaged_ledger = events[6]
        WINDOW.snapshot(damaged_ledger, stages[6], case, False)
        P.exact(damaged_ledger["frontier"], ids["A4"])
        P.exact([damaged_ledger["records"] + 1, damaged_ledger["key_bytes"] + len(key),
                 damaged_ledger["value_bytes"] + model["expected_stored_bytes"]],
                [ledger_before[key] for key in ("records", "key_bytes", "value_bytes")])
        P.require(damaged_ledger["raw_store_sha256"] != ledger_before["raw_store_sha256"])
    else:
        P.require(report is None)
    offset = 7 if gap else 4
    panics = errors = available = prewrite = 0
    for attempt in range(4 if gap else 2):
        if gap and attempt == 2:
            P.exact(events[offset], event("explicit-fixture-ledger-entry-restored", case,
                                         height=height, raw_key=key.hex(), runtime_repair_selected=False))
            WINDOW.snapshot(events[offset + 1], "ledger-after-explicit-fixture-restore", case, False)
            P.exact(WINDOW.ledger_projection(events[offset + 1]), WINDOW.ledger_projection(ledger_before))
            offset += 2
        start, query, stop, cache, ledger = events[offset:offset + 5]
        offset += 5
        unavailable = required_missing and attempt < 2
        panicked = unavailable and generation == "parent"
        returned_error = unavailable and generation == "candidate"
        ready = not unavailable
        P.require(set(start) == {"stage", "case", "attempt", "error", "panicked", "panic_type", "panic_functions", "ready"})
        P.exact([start[key] for key in ("stage", "case", "attempt", "error", "panicked", "ready")],
                ["public-init-observed", case, attempt, "missing-replay-patch" if returned_error else "none", panicked, ready])
        if panicked:
            functions = start["panic_functions"]
            P.require(type(start["panic_type"]) is str and 0 < len(start["panic_type"]) < 64)
            P.require(type(functions) is list and 0 < len(functions) <= 64)
            P.require(all(type(name) is str and name.startswith("github.com/zenon-network/go-zenon/") and len(name) < 256 for name in functions))
            P.require(any("chain.(*chainCache).Init" in name for name in functions))
            panics += 1
        else:
            P.exact([start["panic_type"], start["panic_functions"]], ["", None])
        errors += int(returned_error)
        P.exact(query, event("public-state-query", case, attempt=attempt, identifier=ids["A4"],
                             root=W.ROOT if ready else WINDOW.ZERO, root_error="none" if ready else "not-ready",
                             proof_error="none" if ready else "not-ready", value=W.VALUE if ready else "", proof=proof if ready else ""))
        P.exact(stop, event("public-stop-observed", case, attempt=attempt, error="none", panicked=False,
                            panic_type="", panic_functions=None, ready=False))
        WINDOW.snapshot(cache, "cache-after-public-stop", case, True, attempt)
        WINDOW.snapshot(ledger, "ledger-after-public-stop", case, False, attempt)
        P.exact(WINDOW.ledger_projection(ledger), WINDOW.ledger_projection(damaged_ledger if gap and attempt < 2 else ledger_before))
        if unavailable:
            P.exact(WINDOW.cache_projection(cache), WINDOW.cache_projection(cache_before))
            prewrite += int(returned_error)
        else:
            P.exact(cache["frontier"], ids["A4"])
        available += int(ready)
    P.require(offset == len(events))
    return {"generation": generation, "case": case, "event_count": len(events), "queries": 4 if gap else 2,
            "available_queries": available, "init_panics": panics, "init_errors": errors,
            "candidate_prewrite_refusals": prewrite, "explicit_fixture_restores": int(gap),
            "final_cache": WINDOW.cache_projection(cache), "consumer_result": "REFUSED",
            "reference_backend_executed": False, "private_receipts_authenticated": False,
            "source_and_binary_qualification": False, "metadata_payloads_decoded_by_this_helper": False,
            "complete_candidate_qualification": False}


def check_generation(generation, rows):
    P.require(type(rows) is list and len(rows) == len(H.CASES))
    results = []
    for case, row in zip(H.CASES, rows):
        P.require(type(row) is dict and set(row) == {"case", "command", "stdout_utf8", "metadata_report"})
        P.exact(row["case"], case)
        text = row["stdout_utf8"]
        P.require(type(text) is str and 0 < len(text) <= MAX_STDOUT_BYTES)
        results.append(check_case(generation, case, row["command"], text.encode(), row["metadata_report"]))
    P.require(all(result["final_cache"] == results[0]["final_cache"] for result in results))
    totals = {key: sum(result[key] for result in results) for key in
              ("event_count", "queries", "available_queries", "init_panics", "init_errors", "candidate_prewrite_refusals", "explicit_fixture_restores")}
    P.exact(totals, {"event_count": 130, "queries": 18, "available_queries": 16,
                     "init_panics": 2 if generation == "parent" else 0,
                     "init_errors": 2 if generation == "candidate" else 0,
                     "candidate_prewrite_refusals": 2 if generation == "candidate" else 0, "explicit_fixture_restores": 4})
    return dict(totals, kind="recorded-replay-patch-generation-observation-check", generation=generation,
                cases=len(results), raw_process_exits=[0] * len(results), consumer_result="REFUSED",
                reference_backend_executed=False, private_receipts_authenticated=False,
                source_and_binary_qualification=False, complete_candidate_qualification=False)
