#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""RAM-only protocol controls using a synthetic projection of an older record.

These fixtures are not execution of the new parent or candidate. Actual recorded
patch cases, binary/source qualification and retained metadata payload decoding
remain separate evidence inputs.
"""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import unittest

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("patch_record_controls", HERE / "cache_replay_patch_records.py")
H = importlib.util.module_from_spec(spec)
spec.loader.exec_module(H)


def synthetic_projection():
    raw = H.P.read_regular(HERE / "testdata" / H.WINDOW.CORPUS, H.WINDOW.MAX_BYTES)
    H.P.require(len(raw) == H.WINDOW.CORPUS_BYTES and H.P.sha(raw) == H.WINDOW.CORPUS_SHA256)
    corpus = H.WINDOW.document(raw)
    previous = next(row for row in corpus["cases"] if row["generation"] == "parent" and row["case"] == "empty-cache-replay")
    events = [H.WINDOW.document(line.encode()) for line in previous["stdout_utf8"].splitlines()]
    for event in events:
        event["case"] = "intact-empty-cache"
    events[0]["genesis_account_block_count"] = 14094
    return events, copy.deepcopy(previous["command"])


def encode(events, command):
    raw = b"".join((json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n").encode() for event in events)
    command = copy.deepcopy(command)
    command["stdout"] = {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}
    return raw, command


def check(events, command, generation="parent"):
    raw, receipt = encode(events, command)
    return H.check_case(generation, "intact-empty-cache", receipt, raw)


class ReplayPatchRecordTests(unittest.TestCase):
    def setUp(self):
        self.events, self.command = synthetic_projection()

    def test_synthetic_intact_fixture_checks_observations_without_qualifying_source(self):
        for generation in ("parent", "candidate"):
            result = check(self.events, self.command, generation)
            self.assertEqual(result["event_count"], 14)
            self.assertEqual(result["queries"], 2)
            self.assertEqual(result["available_queries"], 2)
            self.assertEqual(result["init_panics"], 0)
            self.assertEqual(result["consumer_result"], "REFUSED")
            for name in ("reference_backend_executed", "private_receipts_authenticated", "source_and_binary_qualification",
                         "metadata_payloads_decoded_by_this_helper", "complete_candidate_qualification"):
                self.assertIs(result[name], False)

    def test_process_exit_zero_does_not_qualify_an_init_panic(self):
        self.assertEqual(self.command["actual_exit"], 0)
        self.events[4].update(panicked=True, ready=False, panic_type="synthetic panic",
                              panic_functions=["github.com/zenon-network/go-zenon/chain.(*chainCache).Init"])
        with self.assertRaises(ValueError):
            check(self.events, self.command)

    def test_readiness_query_and_stop_boundaries_are_separate(self):
        for index, changes in ((4, {"ready": False}), (4, {"error": "other"}),
                               (5, {"root_error": "not-ready"}), (5, {"proof_error": "not-ready"}),
                               (6, {"ready": True}), (6, {"panicked": True}), (6, {"error": "other"})):
            events = copy.deepcopy(self.events)
            events[index].update(changes)
            with self.subTest(index=index, changes=changes), self.assertRaises(ValueError):
                check(events, self.command)

    def test_command_completeness_exit_and_stdout_digest_are_required(self):
        raw, original = encode(self.events, self.command)
        for changes in ({"actual_exit": 1}, {"state": "RUNNING"}, {"output_complete": False},
                        {"reason": "INTERRUPTED_UNVERIFIED"}, {"actual_exit": False},
                        {"stdout": {"bytes": len(raw), "sha256": "0" * 64}}):
            command = copy.deepcopy(original)
            command.update(changes)
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                H.check_case("parent", "intact-empty-cache", command, raw)

    def test_complete_event_order_names_and_shapes_are_required(self):
        variants = []
        variants.append(self.events[:-1])
        variants.append(self.events + [self.events[-1]])
        swapped = copy.deepcopy(self.events)
        swapped[4], swapped[5] = swapped[5], swapped[4]
        variants.append(swapped)
        for index, changes in ((0, {"case": "other"}), (0, {"extra": True}),
                               (4, {"attempt": False}), (6, {"ready": 0}), (7, {"attempt": 1})):
            events = copy.deepcopy(self.events)
            events[index].update(changes)
            variants.append(events)
        for index, events in enumerate(variants):
            with self.subTest(index=index), self.assertRaises(ValueError):
                check(events, self.command)

    def test_selected_context_and_proof_cannot_be_substituted(self):
        for index, changes in ((0, {"network_started": True}), (0, {"wallet_signing_or_broadcast": True}),
                               (0, {"genesis_account_block_count": 1}), (0, {"genesis_timestamp": 0}),
                               (5, {"root": "0" * 64}), (5, {"value": "00"}), (5, {"proof": ""}),
                               (5, {"identifier": H.WINDOW.identifiers()["A1"]})):
            events = copy.deepcopy(self.events)
            events[index].update(changes)
            with self.subTest(index=index, changes=changes), self.assertRaises(ValueError):
                check(events, self.command)

    def test_snapshot_empty_image_types_and_frontiers_are_checked(self):
        for index, changes in ((3, {"records": 1}), (3, {"raw_store_sha256": "0" * 64}),
                               (7, {"records": True}), (7, {"records": 1000001}),
                               (7, {"frontier": H.WINDOW.identifiers()["A1"]}),
                               (7, {"frontier_raw_value": ""})):
            events = copy.deepcopy(self.events)
            events[index].update(changes)
            with self.subTest(index=index, changes=changes), self.assertRaises(ValueError):
                check(events, self.command)

    def test_incomplete_generation_is_not_a_complete_matrix(self):
        raw, receipt = encode(self.events, self.command)
        row = {"case": "intact-empty-cache", "command": receipt, "stdout_utf8": raw.decode(), "metadata_report": None}
        with self.assertRaises(ValueError):
            H.check_generation("parent", [row])
        with self.assertRaises(ValueError):
            H.check_generation("parent", [row] * 5)

    def test_input_bounds_and_duplicate_json_names_are_refused(self):
        raw, receipt = encode(self.events, self.command)
        for generation, case, data in (("unknown", "intact-empty-cache", raw),
                                       ("parent", "unknown", raw), ("parent", "intact-empty-cache", b""),
                                       ("parent", "intact-empty-cache", raw[:-1]),
                                       ("parent", "intact-empty-cache", bytes(H.MAX_STDOUT_BYTES + 1)),
                                       ("parent", "intact-empty-cache", bytearray(raw))):
            with self.subTest(generation=generation, case=case, size=len(data)), self.assertRaises(ValueError):
                H.check_case(generation, case, receipt, data)
        first, rest = raw.split(b"\n", 1)
        duplicate = first[:-1] + b',"case":"intact-empty-cache"}\n' + rest
        altered = copy.deepcopy(receipt)
        altered["stdout"] = {"bytes": len(duplicate), "sha256": hashlib.sha256(duplicate).hexdigest()}
        with self.assertRaises(ValueError):
            H.check_case("parent", "intact-empty-cache", altered, duplicate)


if __name__ == "__main__":
    unittest.main()
