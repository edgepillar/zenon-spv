#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Adverse controls for the finite native cache identity recording."""
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
spec = importlib.util.spec_from_file_location("cache_rollback_reader_controls", HERE / "check_cache_identifier_rollback.py")
C = importlib.util.module_from_spec(spec)
spec.loader.exec_module(C)


class CacheIdentifierRecordingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = (HERE / "testdata" / C.CORPUS).read_bytes()
        cls.record = C.document(cls.raw)

    def changed(self):
        return copy.deepcopy(self.record)

    def refused(self, record):
        with self.assertRaises((ValueError, TypeError, KeyError, IndexError)):
            C.check_corpus(record)

    def change_events(self, record, index, mutate):
        row = record["cases"][index]
        events = [C.document(line.encode()) for line in row["stdout_utf8"].splitlines()]
        mutate(events)
        raw = "".join(json.dumps(r, sort_keys=True, separators=(",", ":")) + "\n" for r in events)
        row["stdout_utf8"] = raw
        row["command"]["stdout"] = {"sha256": C.P.sha(raw.encode()), "bytes": len(raw.encode())}

    def test_complete_parent_and_candidate_recording(self):
        result = C.check_file(HERE / "testdata" / C.CORPUS)
        self.assertEqual(result["recorded_cases"], 8)
        self.assertEqual(result["recorded_raw_exits"], [0] * 8)
        self.assertEqual(result["recorded_event_observations"], 66)
        self.assertEqual(result["recorded_public_queries"], 13)
        self.assertEqual(result["recorded_available_canonical_queries"], 9)
        self.assertEqual(result["recorded_parent_mixed_identity_starts"], 1)
        self.assertEqual(result["recorded_candidate_prewrite_refusals"], 2)
        self.assertEqual(result["recorded_native_unit_pass_results"], 22)
        self.assertEqual(result["reference_processes_executed_by_this_check"], 0)
        self.assertEqual(result["consumer_result"], "REFUSED")

    def test_independent_protobuf_batch_and_ordered_metadata_images(self):
        self.assertEqual(len(C.raw_identifier("A1")), 39)
        self.assertEqual(C.raw_identifier("B1")[0], 0)
        self.assertEqual(C.fault_image("B1"), {"records": 2, "key_bytes": 11, "value_bytes": 42,
                         "raw_store_sha256": "a6273298e1834f543f2fc80082ce911905f2918dc96892b5d55f98f1c1013e16"})
        self.assertEqual(C.fault_image("B2"), {"records": 3, "key_bytes": 20, "value_bytes": 84,
                         "raw_store_sha256": "d44e0d0ab186f076daf1d3f8798707fb6c2211eff307b6efa984ff21f7392fdb"})

    def test_complete_runtime_build_trees_probe_and_modules_bound(self):
        for key, bad in (("revision", "0" * 40), ("source_blobs", True),
                         ("parent_runtime_tree", "0" * 40), ("candidate_runtime_tree", C.G.F.C.MODIFIED_TREE),
                         ("parent_build_tree", "0" * 40), ("candidate_build_tree", "0" * 40),
                         ("patch_sha256", "0" * 64), ("module_sha256", "0" * 64),
                         ("sum_sha256", "0" * 64), ("added_native_control_targets", [])):
            record = self.changed()
            record["source"][key] = bad
            self.refused(record)

    def test_parent_defect_cannot_be_rewritten_as_a_refusal(self):
        for mutate in (
            lambda e: e[3].update(ready=False, error="cache-frontier-identity-mismatch"),
            lambda e: e[3].update(frontiers_equal=True),
            lambda e: e[3].update(cache_frontier=C.W.GENESIS),
            lambda e: e[7].update(ready=True, error="none"),
        ):
            record = self.changed()
            self.change_events(record, 2, mutate)
            self.refused(record)

    def test_fixed_mismatches_cannot_become_ready(self):
        for index in (5, 6):
            record = self.changed()
            self.change_events(record, index, lambda e: e[3].update(ready=True, error="none"))
            self.refused(record)

    def test_refused_queries_return_no_state_value_or_proof(self):
        for index in (1, 5, 6):
            for field, bad in (("root", C.W.ROOT), ("value", C.W.VALUE), ("proof", C.canonical_proof()),
                               ("root_error", "none"), ("proof_error", "none")):
                record = self.changed()
                self.change_events(record, index, lambda e: e[4].update({field: bad}))
                self.refused(record)

    def test_refusal_preserves_all_explicit_fault_metadata(self):
        for index in (5, 6):
            for key, bad in (("records", 1), ("key_bytes", 1), ("value_bytes", 1),
                             ("raw_store_sha256", "0" * 64), ("frontier_raw_value", "00")):
                record = self.changed()
                self.change_events(record, index, lambda e: [e[i].update({key: bad}) for i in (2, 6)])
                self.refused(record)

    def test_correct_retained_target_still_rolls_back_and_reopens(self):
        for index in (3, 7):
            for mutate in (
                lambda e: e[6].update(frontier=C.identifiers()["B2"]),
                lambda e: e[7].update(ready=False),
                lambda e: e[8].update(root=C.ZERO),
                lambda e: e[4].update(proof=e[4]["proof"][:-2]),
            ):
                record = self.changed()
                self.change_events(record, index, mutate)
                self.refused(record)

    def test_exact_case_generation_order_and_stage_inventory(self):
        for mutate in (lambda r: r.pop(), lambda r: r.reverse(), lambda r: r.append(copy.deepcopy(r[0]))):
            record = self.changed()
            mutate(record["cases"])
            self.refused(record)
        for index in range(8):
            record = self.changed()
            self.change_events(record, index, lambda e: e.pop(2))
            self.refused(record)

    def test_exit_completeness_timeout_and_terminal_marker_required(self):
        for index in range(8):
            for key, bad in (("actual_exit", 2), ("actual_exit", False), ("state", "UNKNOWN"),
                             ("output_complete", False), ("reason", "TIMEOUT")):
                record = self.changed()
                record["cases"][index]["command"][key] = bad
                self.refused(record)
        record = self.changed()
        record["cases"][0]["stderr_diagnostics"]["normal_process_complete"] = False
        self.refused(record)

    def test_stdout_and_private_stderr_references_bound(self):
        for stream in ("stdout", "stderr"):
            record = self.changed()
            record["cases"][0]["command"][stream]["sha256"] = "0" * 64
            self.refused(record)

    def test_native_unit_and_binary_evidence_cannot_be_inflated(self):
        for mutate in (
            lambda e: e["native_unit_controls"].update(test_pass_results=23),
            lambda e: e["native_unit_controls"].update(skipped_or_failed=1),
            lambda e: e["native_unit_controls"]["command"].update(actual_exit=1),
            lambda e: e["candidate_binary"].update(sha256="0" * 64),
            lambda e: e["parent_binary"].update(bytes=1),
            lambda e: e["selected_linked_dependencies"][0].update(go_sum="changed"),
            lambda e: e.update(ordinary_entrypoint_builds=1),
            lambda e: e.update(physical_reclaim_or_peak_disk_claim=True),
            lambda e: e.update(whole_module_graph_verification="SUCCESS"),
        ):
            record = self.changed()
            mutate(record["execution"])
            self.refused(record)

    def test_boolean_and_numeric_types_are_distinct(self):
        for mutate in (lambda e: e[3].update(ready=1), lambda e: e[2].update(records=True),
                       lambda e: e[0]["identifier"].update(height=True), lambda e: e[5].update(ready=0)):
            record = self.changed()
            self.change_events(record, 0, mutate)
            self.refused(record)

    def test_scope_and_consumer_cannot_claim_acceptance_or_atomicity(self):
        for key in C.SCOPE:
            record = self.changed()
            record["scope"][key] = not C.SCOPE[key]
            self.refused(record)
        record = self.changed()
        record["consumer_result"] = "VERIFIED"
        self.refused(record)

    def test_duplicate_nonfinite_and_oversize_json_refused(self):
        for raw in (b'{"case":1,"case":2}', b'{"case":NaN}', b" " * (C.MAX_BYTES + 1)):
            with self.assertRaises(ValueError):
                C.document(raw)
        record = self.changed()
        row = record["cases"][0]
        raw = row["stdout_utf8"].replace('"stage":"source-genesis"', '"stage":"source-genesis","stage":"source-genesis"', 1)
        self.assertNotEqual(raw, row["stdout_utf8"])
        row["stdout_utf8"] = raw
        row["command"]["stdout"] = {"sha256": C.P.sha(raw.encode()), "bytes": len(raw.encode())}
        self.refused(record)

    def test_whole_file_and_source_label_required(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / "changed.json"
            path.write_bytes(self.raw + b"\n")
            with self.assertRaises(ValueError):
                C.check_file(path)
        with self.assertRaises(ValueError):
            C.main(["--source-revision", "main"])

    def test_node_internal_control_sources_are_noncompiled_containers(self):
        self.assertTrue(all(name.endswith(".go.txt") for name in C.G.CONTROL_SOURCES))
        self.assertTrue(all(pin["target"].endswith("_test.go") for pin in C.G.CONTROL_SOURCES.values()))

    def test_reader_cannot_launch_backend_or_network(self):
        with mock.patch.object(subprocess, "run", side_effect=AssertionError("unexpected backend")), \
             mock.patch.object(subprocess, "Popen", side_effect=AssertionError("unexpected backend")), \
             mock.patch.object(socket, "socket", side_effect=AssertionError("unexpected network")), \
             contextlib.redirect_stdout(io.StringIO()) as stream:
            C.main(["--source-revision", "1" * 40])
        result = json.loads(stream.getvalue())
        self.assertEqual(result["source_revision"], "1" * 40)
        self.assertEqual(result["reference_processes_executed_by_this_check"], 0)


if __name__ == "__main__":
    unittest.main()
