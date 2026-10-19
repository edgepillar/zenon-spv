#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Adverse controls for the recorded replay window and independent byte models."""
import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("cache_window_reader_controls", HERE / "check_cache_replay_window.py")
C = importlib.util.module_from_spec(spec)
spec.loader.exec_module(C)


class CacheReplayWindowRecordingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = (HERE / "testdata" / C.CORPUS).read_bytes()
        cls.record = C.document(cls.raw)
        # These controls mutate only independent in-memory corpus copies. Pin
        # the complete source graph at both ends and reuse its selection within
        # this serial class, rather than reconstructing it for every mutation.
        cls._uncached_expected_source = staticmethod(C.expected_source)
        cls._selected_source = C.expected_source()
        paths = {HERE / name for name in C.INPUTS} | {Path(C.__file__), Path(__file__)}
        cls._source_hashes = {path: C.P.sha(C.P.read_regular(path, 1 << 20)) for path in paths}
        cls._source_patch = mock.patch.object(C, "expected_source", return_value=cls._selected_source)
        cls._source_patch.start()
        cls.addClassCleanup(cls._source_patch.stop)

    @classmethod
    def tearDownClass(cls):
        for path, digest in cls._source_hashes.items():
            if C.P.sha(C.P.read_regular(path, 1 << 20)) != digest:
                raise AssertionError("Source input changed during the serial test class")
        if cls._uncached_expected_source() != cls._selected_source:
            raise AssertionError("Complete source selection changed during the test class")

    def changed(self):
        return copy.deepcopy(self.record)

    def refused(self, record):
        with self.assertRaises((ValueError, TypeError, KeyError, IndexError)):
            C.check_corpus(record)

    def change_events(self, record, index, mutate):
        row = record["cases"][index]
        events = [C.document(line.encode()) for line in row["stdout_utf8"].splitlines()]
        mutate(events)
        raw = "".join(json.dumps(e, sort_keys=True, separators=(",", ":")) + "\n" for e in events)
        row["stdout_utf8"] = raw
        row["command"]["stdout"] = {"sha256": C.P.sha(raw.encode()), "bytes": len(raw.encode())}

    def test_complete_recording_preserves_failed_parent_task_scope(self):
        result = C.check_file(HERE / "testdata" / C.CORPUS)
        self.assertEqual(result["recorded_cases"], 10)
        self.assertEqual(result["recorded_raw_exits"], [0] * 10)
        self.assertEqual(result["recorded_event_observations"], 196)
        self.assertEqual(result["recorded_parent_Init_panics"], 4)
        self.assertEqual(result["recorded_parent_partial_replay_observations"], 2)
        self.assertEqual(result["recorded_candidate_Init_panics"], 0)
        self.assertEqual(result["recorded_candidate_prewrite_refusals"], 4)
        self.assertEqual(result["recorded_public_queries"], 28)
        self.assertEqual(result["recorded_available_canonical_queries"], 20)
        self.assertEqual(result["recorded_native_unit_pass_results"], 46)
        self.assertEqual(result["reference_processes_executed_by_this_check"], 0)
        self.assertEqual(result["consumer_result"], "REFUSED")
        self.assertEqual(self.record["execution"]["parent_task_outcome"], "FAILURE_DUE_TO_CANDIDATE_CONTROL_BUILD_ERROR")
        self.assertFalse(self.record["execution"]["parent_backend_reexecuted_by_candidate_followup"])

    def test_independent_hash_frames_and_removed_protobuf_records(self):
        ids = C.identifiers()
        self.assertEqual(ids["A2"]["hash"], "fbe4d2002715d5993894e36fe23eefab052ffe697861465b1be8c07d786beed0")
        self.assertEqual(ids["A3"]["hash"], "c700dac1028246069f59344ae6a3f223dfe017cc05480979ec3368d4c130454a")
        self.assertEqual(ids["A4"]["hash"], "676bd966430b26f32e58de72b95fde5514beaba824e0c881fd767ef417db37c5")
        for height, digest in ((2, "f238db35d88f03a900b94e079675dca7a73a21b2fd42101a89b7c62d8b911186"),
                               (3, "ddd309a7e642ac1db94c5d1bc520d5629459ea893dba6c5a625468d6fe926e5f")):
            key, value = C.removed_entry(height)
            self.assertEqual(key.hex(), "5502" + ("%016x" % height))
            self.assertEqual(len(value), 121)
            self.assertEqual(C.P.sha(value), digest)
        self.assertEqual(C.varint((1 << 64) - 1), b"\xff" * 9 + b"\x01")
        for value in (-1, 1 << 64, True):
            with self.assertRaises(ValueError):
                C.varint(value)

    def test_source_revision_runtime_builds_and_native_sources_are_bound(self):
        for key, bad in (("revision", "0" * 40), ("source_blobs", True),
                         ("parent_runtime_tree", "0" * 40), ("candidate_runtime_tree", C.H.H.MODIFIED_TREE),
                         ("parent_build_tree", "0" * 40), ("candidate_build_tree", "0" * 40),
                         ("candidate_compiled_source_blobs", 471), ("patch_sha256", "0" * 64),
                         ("module_sha256", "0" * 64), ("sum_sha256", "0" * 64), ("native_controls", {})):
            record = self.changed()
            record["source"][key] = bad
            self.refused(record)

    def test_parent_recovered_panic_is_not_success_or_a_normal_error(self):
        for index in (3, 4):
            for mutate in (
                lambda e: e[6].update(panicked=False),
                lambda e: e[6].update(ready=True),
                lambda e: e[6].update(error="missing-replay-momentum"),
                lambda e: e[6].update(panic_functions=[]),
                lambda e: e[6].update(panic_type=""),
            ):
                record = self.changed()
                self.change_events(record, index, mutate)
                self.refused(record)

    def test_late_parent_partial_progress_cannot_be_hidden(self):
        record = self.changed()
        self.change_events(record, 4, lambda e: e[9].update(frontier=C.identifiers()["A1"]))
        self.refused(record)
        record = self.changed()
        self.change_events(record, 4, lambda e: e[14].update(raw_store_sha256="0" * 64))
        self.refused(record)

    def test_candidate_missing_entries_are_refused_before_any_write(self):
        for index in (8, 9):
            for mutate in (
                lambda e: e[6].update(ready=True, error="none"),
                lambda e: e[6].update(panicked=True),
                lambda e: e[9].update(frontier=C.identifiers()["A2"]),
                lambda e: e[9].update(records=e[9]["records"] + 1),
                lambda e: e[9].update(key_bytes=e[9]["key_bytes"] + 1),
                lambda e: e[9].update(value_bytes=e[9]["value_bytes"] + 1),
                lambda e: e[9].update(raw_store_sha256="0" * 64),
            ):
                record = self.changed()
                self.change_events(record, index, mutate)
                self.refused(record)

    def test_failed_init_queries_expose_no_root_value_or_proof(self):
        for index in (3, 4, 8, 9):
            for field, bad in (("root", C.W.ROOT), ("value", C.W.VALUE), ("proof", C.PRIOR.PRIOR.canonical_proof()),
                               ("root_error", "none"), ("proof_error", "none")):
                record = self.changed()
                self.change_events(record, index, lambda e: e[7].update({field: bad}))
                self.refused(record)

    def test_controlled_fault_has_exact_independent_key_and_value_bytes(self):
        for index in (3, 4, 8, 9):
            for field, bad in (("height", 4), ("raw_key", "55020000000000000004"),
                               ("raw_value", "00"), ("raw_value_sha256", "0" * 64),
                               ("runtime_repair_selected", True)):
                record = self.changed()
                self.change_events(record, index, lambda e: e[4].update({field: bad}))
                self.refused(record)

    def test_ledger_fault_and_closed_manager_observations_are_preserved(self):
        for index in (3, 4, 8, 9):
            for mutate in (
                lambda e: e[5].update(records=e[2]["records"]),
                lambda e: e[5].update(raw_store_sha256=e[2]["raw_store_sha256"]),
                lambda e: e[10].update(raw_store_sha256=e[2]["raw_store_sha256"]),
                lambda e: e[10].update(frontier=C.identifiers()["A3"]),
            ):
                record = self.changed()
                self.change_events(record, index, mutate)
                self.refused(record)

    def test_explicit_restore_is_separate_and_clean_replay_is_required(self):
        for index in (3, 4, 8, 9):
            for mutate in (
                lambda e: e[16].update(runtime_repair_selected=True),
                lambda e: e[17].update(raw_store_sha256="0" * 64),
                lambda e: e[18].update(ready=False),
                lambda e: e[19].update(proof=""),
                lambda e: e[24].update(root=C.ZERO),
            ):
                record = self.changed()
                self.change_events(record, index, mutate)
                self.refused(record)

    def test_unfaulted_empty_behind_and_current_caches_reopen(self):
        for index in (0, 1, 2, 5, 6, 7):
            for mutate in (
                lambda e: e[4].update(ready=False),
                lambda e: e[7].update(frontier=C.identifiers()["A3"]),
                lambda e: e[10].update(root=C.ZERO),
            ):
                record = self.changed()
                self.change_events(record, index, mutate)
                self.refused(record)

    def test_exact_case_order_and_complete_stage_inventory_are_required(self):
        for mutate in (lambda r: r.pop(), lambda r: r.reverse(), lambda r: r.append(copy.deepcopy(r[0]))):
            record = self.changed()
            mutate(record["cases"])
            self.refused(record)
        for index in range(10):
            record = self.changed()
            self.change_events(record, index, lambda e: e.pop(2))
            self.refused(record)

    def test_actual_exits_completeness_and_process_marker_are_required(self):
        for index in range(10):
            for key, bad in (("actual_exit", 1), ("actual_exit", False), ("state", "UNKNOWN"),
                             ("output_complete", False), ("reason", "TIMEOUT")):
                record = self.changed()
                record["cases"][index]["command"][key] = bad
                self.refused(record)
        record = self.changed()
        record["cases"][3]["stderr_diagnostics"]["normal_process_complete"] = False
        self.refused(record)

    def test_stdout_and_private_stderr_references_remain_pinned(self):
        for stream in ("stdout", "stderr"):
            record = self.changed()
            record["cases"][0]["command"][stream]["sha256"] = "0" * 64
            self.refused(record)

    def test_native_counts_failures_and_module_evidence_cannot_be_inflated(self):
        for mutate in (
            lambda e: e["native_unit_controls"].update(test_pass_results=47),
            lambda e: e["native_unit_controls"].update(skipped_or_failed=1),
            lambda e: e["native_unit_controls"]["command"].update(actual_exit=1),
            lambda e: e["prior_candidate_control_compile_failure"].update(actual_exit=0),
            lambda e: e["candidate_ordinary_binary"].update(sha256="0" * 64),
            lambda e: e["linked_module_details"][0].update(go_sum="changed"),
            lambda e: e.update(parent_task_outcome="SUCCESS"),
            lambda e: e.update(parent_backend_reexecuted_by_candidate_followup=True),
            lambda e: e.update(ordinary_entrypoint_builds=1),
            lambda e: e.update(physical_reclaim_or_peak_disk_claim=True),
            lambda e: e.update(whole_module_graph_verification="SUCCESS"),
        ):
            record = self.changed()
            mutate(record["execution"])
            self.refused(record)

    def test_boolean_and_numeric_types_are_distinct(self):
        for mutate in (lambda e: e[4].update(ready=1), lambda e: e[3].update(records=True),
                       lambda e: e[0]["genesis_identifier"].update(height=True), lambda e: e[6].update(ready=0)):
            record = self.changed()
            self.change_events(record, 0, mutate)
            self.refused(record)

    def test_scope_and_consumer_never_claim_authentication_or_atomicity(self):
        for key in C.SCOPE:
            record = self.changed()
            record["scope"][key] = not C.SCOPE[key]
            self.refused(record)
        record = self.changed()
        record["consumer_result"] = "VERIFIED"
        self.refused(record)

    def test_duplicate_nonfinite_and_oversize_json_are_refused(self):
        for raw in (b'{"case":1,"case":2}', b'{"case":NaN}', b" " * (C.MAX_BYTES + 1)):
            with self.assertRaises(ValueError):
                C.document(raw)
        record = self.changed()
        row = record["cases"][0]
        raw = row["stdout_utf8"].replace('"stage":"source-genesis-and-unsigned-replay-window"',
                                         '"stage":"source-genesis-and-unsigned-replay-window","stage":"duplicate"', 1)
        self.assertNotEqual(raw, row["stdout_utf8"])
        row["stdout_utf8"] = raw
        row["command"]["stdout"] = {"sha256": C.P.sha(raw.encode()), "bytes": len(raw.encode())}
        self.refused(record)

    def test_file_digest_source_label_and_current_corpus_bound(self):
        self.assertGreater(len(self.raw), C.W.MAX_BYTES)
        self.assertLess(len(self.raw), C.MAX_BYTES)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / "changed.json"
            path.write_bytes(self.raw + b"\n")
            with self.assertRaises(ValueError):
                C.check_file(path)
        with self.assertRaises(ValueError):
            C.main(["--source-revision", "main"])

    def test_reader_does_not_start_subprocesses_or_network(self):
        # Include actual source selection in the no-execution boundary check.
        with mock.patch.object(C, "expected_source", side_effect=type(self)._uncached_expected_source), \
             mock.patch.object(subprocess, "Popen", side_effect=AssertionError("No backend permitted")), \
             mock.patch.object(socket, "create_connection", side_effect=AssertionError("No network permitted")):
            with contextlib.redirect_stdout(io.StringIO()):
                C.main(["--source-revision", "1" * 40])


if __name__ == "__main__":
    unittest.main()
