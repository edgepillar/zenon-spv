#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Adverse controls for the finite public Chain foreign-startup recording."""
import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("foreign_startup_recording_controls", HERE / "check_public_chain_foreign_startup.py")
C = importlib.util.module_from_spec(spec)
spec.loader.exec_module(C)


class RecordedForeignStartupTests(unittest.TestCase):
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

    def test_all_real_manager_cases_and_refusal_boundaries(self):
        result = C.check_file(HERE / "testdata" / C.CORPUS)
        self.assertEqual(result["recorded_raw_exits"], [0, 0, 0, 0])
        self.assertEqual(result["recorded_event_observations"], 38)
        self.assertEqual(result["recorded_unchanged_refused_raw_stores"], 2)
        self.assertEqual(result["recorded_canonical_rollback_and_reopen"], 1)
        self.assertEqual(result["recorded_public_queries"], 12)
        self.assertEqual(result["recorded_available_canonical_queries"], 2)
        self.assertEqual(result["reference_processes_executed_by_this_check"], 0)
        self.assertEqual(result["consumer_result"], "REFUSED")

    def test_canonical_and_both_foreign_roots_are_independently_derived(self):
        selected = C.selection()
        self.assertEqual(C.W.witness_root(selected["key"], selected["canonical_value"], selected["canonical_proof"]), C.W.ROOT)
        for key in ("canonical_root", "foreign_single_leaf_root", "foreign_full_projection_root"):
            doc = self.changed()
            doc["selection"][key] = C.ZERO
            self.refused(doc)
        for key in ("canonical_value", "foreign_value", "key", "canonical_proof"):
            doc = self.changed()
            doc["selection"][key] = C.ZERO
            self.refused(doc)

    def test_full_source_runtime_probe_module_and_build_tree_are_bound(self):
        for key, value in (("revision", "0" * 40), ("original_tree", "0" * 40),
                           ("runtime_tree", C.P.TREE), ("build_tree", "0" * 40),
                           ("source_blobs", True), ("runtime_changed", True),
                           ("module_sha256", "0" * 64), ("sum_sha256", "0" * 64),
                           ("probe", {"sha256": "0" * 64, "bytes": 9182})):
            doc = self.changed()
            doc["source"][key] = value
            self.refused(doc)

    def test_exact_case_inventory_order_and_stage_inventory(self):
        for mutate in (lambda rows: rows.pop(), lambda rows: rows.reverse(), lambda rows: rows.append(copy.deepcopy(rows[0]))):
            doc = self.changed()
            mutate(doc["cases"])
            self.refused(doc)
        for index in range(4):
            doc = self.changed()
            self.change_events(doc, index, lambda rows: rows.pop(2))
            self.refused(doc)

    def test_wrong_same_height_identity_cannot_become_ready(self):
        for index in (1, 2):
            for field, value in (("ready", True), ("error", "none"), ("error", None)):
                doc = self.changed()
                self.change_events(doc, index, lambda rows: rows[3].update({field: value}))
                self.refused(doc)

    def test_refused_queries_cannot_leak_a_foreign_root_value_or_proof(self):
        for index in (1, 2):
            for field, value in (("root", C.SINGLE_ROOT), ("value", self.record["selection"]["foreign_value"]),
                                 ("proof", self.record["selection"]["canonical_proof"]),
                                 ("root_error", "none"), ("proof_error", "none")):
                doc = self.changed()
                self.change_events(doc, index, lambda rows: rows[4].update({field: value}))
                self.refused(doc)

    def test_refused_raw_store_changes_are_not_hidden(self):
        for index in (1, 2):
            for key, value in (("raw_store_sha256", "0" * 64), ("records", 1),
                               ("key_bytes", 1), ("value_bytes", 1), ("framing", "unframed"),
                               ("frontier", C.W.GENESIS)):
                doc = self.changed()
                self.change_events(doc, index, lambda rows: rows[8].update({key: value}))
                self.refused(doc)
        # Even changing both sides coherently cannot replace the recorded image.
        doc = self.changed()
        self.change_events(doc, 1, lambda rows: [rows[i].update(raw_store_sha256="1" * 64) for i in (2, 8)])
        self.refused(doc)

    def test_native_format_fixture_frontier_and_retained_roots_are_exact(self):
        for index in range(4):
            doc = self.changed()
            self.change_events(doc, index, lambda rows: rows[2]["roots"][0].update(error="none", root="1" * 64))
            self.refused(doc)
            doc = self.changed()
            self.change_events(doc, index, lambda rows: rows[2].update(frontier={"hash": "1" * 64, "height": 1}))
            self.refused(doc)

    def test_canonical_rollback_removes_foreign_ahead_version_before_serving(self):
        for mutate in (
            lambda rows: rows[8].update(frontier=C.identifiers()[2]),
            lambda rows: rows[8]["roots"][2].update(root=C.CHANGED_ROOT, error="none"),
            lambda rows: rows[4].update(root=C.CHANGED_ROOT),
            lambda rows: rows[9].update(root=C.CHANGED_ROOT),
            lambda rows: rows[9].update(ready=False),
        ):
            doc = self.changed()
            self.change_events(doc, 3, mutate)
            self.refused(doc)

    def test_good_queries_still_require_complete_hash_and_height(self):
        for index in (0, 3):
            for mutate in (
                lambda rows: rows[4]["identifier"].update(hash=C.identifiers()[1]["hash"]),
                lambda rows: rows[4]["identifier"].update(height=2),
                lambda rows: rows[5].update(root=C.W.ROOT, root_error="none"),
                lambda rows: rows[6].update(proof_error="none"),
                lambda rows: rows[4].update(value=C.ZERO),
                lambda rows: rows[4].update(proof=rows[4]["proof"][:-2]),
            ):
                doc = self.changed()
                self.change_events(doc, index, mutate)
                self.refused(doc)

    def test_actual_exit_timeout_output_and_terminal_marker_evidence_are_required(self):
        for index in range(4):
            for field, value in (("actual_exit", 2), ("actual_exit", False), ("state", "UNKNOWN"),
                                 ("output_complete", False), ("reason", "TIMEOUT")):
                doc = self.changed()
                doc["cases"][index]["command"][field] = value
                self.refused(doc)
        doc = self.changed()
        doc["cases"][0]["stderr_diagnostics"]["normal_process_complete"] = False
        self.refused(doc)

    def test_stdout_and_private_stderr_references_are_bound(self):
        for stream in ("stdout", "stderr"):
            for field, value in (("sha256", "0" * 64), ("bytes", 0)):
                doc = self.changed()
                doc["cases"][0]["command"][stream][field] = value
                self.refused(doc)

    def test_build_binary_and_dependency_evidence_cannot_be_substituted(self):
        for key, value in (("actual_builds", 2), ("actual_case_processes", 3),
                           ("new_source_or_dependency_transports", 1), ("verified_dependency_inputs", 74),
                           ("original_task_outcome", "FAILURE"), ("whole_module_graph_verification", "SUCCESS"),
                           ("physical_reclaim_or_peak_disk_claim", True), ("platform", "windows/amd64")):
            doc = self.changed()
            doc["execution"][key] = value
            self.refused(doc)
        for mutate in (
            lambda ex: ex["ordinary_binary"].update(sha256="0" * 64),
            lambda ex: ex["commands"]["build"].update(actual_exit=1),
            lambda ex: ex["selected_linked_dependencies"][0].update(go_sum="substituted"),
            lambda ex: ex["presealed_plan"].update(bytes=1),
            lambda ex: ex["private_execution"].update(sha256="0" * 64),
        ):
            doc = self.changed()
            mutate(doc["execution"])
            self.refused(doc)

    def test_boolean_and_numeric_types_are_not_interchangeable(self):
        for mutate in (lambda rows: rows[3].update(ready=1), lambda rows: rows[2].update(records=True),
                       lambda rows: rows[0]["identifier"].update(height=True), lambda rows: rows[7].update(ready=0)):
            doc = self.changed()
            self.change_events(doc, 0, mutate)
            self.refused(doc)

    def test_all_scope_flags_and_refused_consumer_are_preserved(self):
        for key in C.SCOPE:
            doc = self.changed()
            doc["scope"][key] = not C.SCOPE[key]
            self.refused(doc)
        doc = self.changed()
        doc["consumer_result"] = "VERIFIED"
        self.refused(doc)

    def test_duplicate_nonfinite_and_oversize_json_are_refused(self):
        for raw in (b'{"case":1,"case":2}', b'{"case":NaN}', b" " * (C.MAX_BYTES + 1)):
            with self.assertRaises(ValueError):
                C.document(raw)
        doc = self.changed()
        row = doc["cases"][0]
        raw = row["stdout_utf8"].replace('"stage":"source-genesis"', '"stage":"source-genesis","stage":"source-genesis"', 1)
        self.assertNotEqual(raw, row["stdout_utf8"])
        row["stdout_utf8"] = raw
        row["command"]["stdout"] = {"sha256": C.P.sha(raw.encode()), "bytes": len(raw.encode())}
        self.refused(doc)

    def test_whole_file_and_source_label_pins_are_required(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / "record.json"
            path.write_bytes(self.raw + b"\n")
            with self.assertRaises(ValueError):
                C.check_file(path)
        with self.assertRaises(ValueError):
            C.main(["--source-revision", "main"])

    def test_reader_cannot_execute_backend_or_network(self):
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
