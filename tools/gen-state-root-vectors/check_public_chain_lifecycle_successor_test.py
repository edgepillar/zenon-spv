#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Adverse controls for finite public Chain recordings and the byte witness."""
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
spec = importlib.util.spec_from_file_location("public_chain_recording_controls", HERE / "check_public_chain_lifecycle_successor.py")
C = importlib.util.module_from_spec(spec)
spec.loader.exec_module(C)


class RecordedPublicChainTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = (HERE / "testdata" / C.CORPUS).read_bytes()
        cls.document = C.document(cls.raw)

    def changed(self):
        return copy.deepcopy(self.document)

    def refused(self, document):
        with self.assertRaises((ValueError, TypeError, KeyError, IndexError)):
            C.check_corpus(document)

    def change_events(self, document, mutate, variant="public-chain-terminal", index=0):
        row = document["variants"][variant][index]
        events = [C.document(line.encode()) for line in row["stdout_utf8"].splitlines()]
        mutate(events)
        raw = "".join(json.dumps(e, sort_keys=True, separators=(",", ":")) + "\n" for e in events)
        row["stdout_utf8"] = raw
        row["command"]["stdout"] = {"sha256": C.P.sha(raw.encode()), "bytes": len(raw.encode())}

    def test_complete_recorded_cases_preserve_parent_failures(self):
        result = C.check_corpus(self.document)
        self.assertEqual(result["recorded_cases"], 6)
        self.assertEqual(result["recorded_parent_raw_exits"], [2, 0, 2])
        self.assertEqual(result["recorded_candidate_raw_exits"], [0, 0, 0])
        self.assertEqual(result["positive_queries_and_clean_reopens"], 4)
        self.assertEqual(result["original_task_outcome"], "FAILURE")
        self.assertEqual(result["whole_module_graph_verification"], "NOT_QUALIFIED")

    def test_independent_canonical_witness_and_reversed_path_refusal(self):
        w = self.document["selection"]["witness"]
        self.assertEqual(C.witness_root(C.KEY, C.VALUE, w["proof"]), C.ROOT)
        for key, value in (("00" * 32, C.VALUE), (C.KEY, "00" * 32)):
            with self.assertRaises(ValueError):
                C.witness_root(key, value, w["proof"])
        proof = bytearray.fromhex(w["proof"])
        proof[1:33] = proof[1:33][::-1]
        with self.assertRaises(ValueError):
            C.witness_root(C.KEY, C.VALUE, proof.hex())

    def test_proof_bounds_flags_bitmap_and_canonical_zero(self):
        original = bytes.fromhex(self.document["selection"]["witness"]["proof"])
        for raw in (original[:-1], original + b"\0", b"\0" + original[1:],
                    original[:97] + b"\x01\x01" + original[99:],
                    original[:99] + bytes(32) + original[131:]):
            with self.assertRaises(ValueError):
                C.witness_root(C.KEY, C.VALUE, raw.hex())

    def test_source_tree_module_and_patch_substitution(self):
        for key, value in (("parent_runtime_tree", "0" * 40), ("revision", "0" * 40),
                           ("candidate_runtime_tree", C.P.TREE), ("source_blobs", True),
                           ("sum_sha256", "0" * 64)):
            doc = self.changed()
            doc["source"][key] = value
            self.refused(doc)

    def test_selection_cannot_be_taken_from_candidate(self):
        for field, value in (("root", "00" * 32), ("genesis_identifier", {"hash": "00" * 32, "height": 1})):
            doc = self.changed()
            doc["selection"][field] = value
            self.refused(doc)
        for field, value in (("raw_key", "00" * 32), ("value", "00" * 32), ("present_in_projection", False)):
            doc = self.changed()
            doc["selection"]["witness"][field] = value
            self.refused(doc)

    def test_all_case_inventories_are_exact(self):
        for variant in C.C.VARIANTS:
            doc = self.changed()
            doc["variants"][variant].pop()
            self.refused(doc)
            doc = self.changed()
            doc["variants"][variant].reverse()
            self.refused(doc)

    def test_parent_panic_is_not_reclassified_as_success(self):
        for key, value in (("actual_exit", 0), ("output_complete", False), ("reason", "TIMEOUT"), ("state", "UNKNOWN")):
            doc = self.changed()
            doc["variants"][C.C.VARIANTS[0]][0]["command"][key] = value
            self.refused(doc)
        doc = self.changed()
        doc["variants"][C.C.VARIANTS[0]][2]["stderr_diagnostics"]["runtime_nil_pointer_panic"] = False
        self.refused(doc)

    def test_original_failure_and_missing_graph_stay_visible(self):
        for key, value in (("original_task_outcome", "SUCCESS"), ("original_final_comparison_emitted", True),
                           ("new_dependency_transports", 1), ("actual_case_processes", 3)):
            doc = self.changed()
            doc["execution"][key] = value
            self.refused(doc)
        doc = self.changed()
        doc["execution"]["whole_module_graph_verification"]["actual_exit"] = 0
        self.refused(doc)

    def test_selected_module_cache_or_zip_mismatch_refused(self):
        for field in ("go_sum", "extracted_cache_h1", "version"):
            doc = self.changed()
            doc["execution"]["selected_linked_dependencies"][0][field] = "substituted"
            self.refused(doc)

    def test_guarded_nil_error_or_ready_true_refused(self):
        for field, value in (("error", None), ("ready", True)):
            doc = self.changed()
            self.change_events(doc, lambda rows: next(r for r in rows if r["stage"] == "terminal-call-returned").update({field: value}))
            self.refused(doc)

    def test_parent_false_start_success_must_not_be_hidden(self):
        doc = self.changed()
        self.change_events(doc, lambda rows: next(r for r in rows if r["stage"] == "terminal-call-returned").update(error="chain instance is stopped"), C.C.VARIANTS[0], 1)
        self.refused(doc)

    def test_reopen_and_wrong_hash_gate_must_be_checked(self):
        for stage, field, replacement in (("clean-reopen", "root", "00" * 32),
                                           ("query", "wrong_hash_error", None),
                                           ("query", "value", "00" * 32)):
            doc = self.changed()
            self.change_events(doc, lambda rows: next(r for r in rows if r["stage"] == stage).update({field: replacement}))
            self.refused(doc)
        doc = self.changed()
        self.change_events(doc, lambda rows: rows.pop(next(i for i, r in enumerate(rows) if r["stage"] == "clean-reopen")))
        self.refused(doc)

    def test_event_and_command_type_strictness(self):
        doc = self.changed()
        self.change_events(doc, lambda rows: next(r for r in rows if r["stage"] == "stopped").update(ready=0))
        self.refused(doc)
        doc = self.changed()
        doc["variants"][C.C.VARIANTS[1]][0]["command"]["actual_exit"] = False
        self.refused(doc)

    def test_scope_cannot_be_promoted_to_full_node_or_acceptance(self):
        for key in C.SCOPE:
            doc = self.changed()
            doc["scope"][key] = not C.SCOPE[key]
            self.refused(doc)
        doc = self.changed()
        doc["consumer_result"] = "VERIFIED"
        self.refused(doc)

    def test_duplicate_names_nan_and_oversize_json_refused(self):
        for raw in (b'{"case":1,"case":2}', b'{"case":NaN}', b" " * (C.MAX_BYTES + 1)):
            with self.assertRaises(ValueError):
                C.document(raw)
        doc = self.changed()
        row = doc["variants"][C.C.VARIANTS[1]][2]
        raw = row["stdout_utf8"].replace('"case":"stop-before-init"', '"case":"stop-before-init","case":"stop-before-init"', 1)
        row["stdout_utf8"] = raw
        row["command"]["stdout"] = {"sha256": C.P.sha(raw.encode()), "bytes": len(raw.encode())}
        self.refused(doc)

    def test_stdout_digest_and_complete_bytes_required(self):
        for field, value in (("sha256", "0" * 64), ("bytes", 1)):
            doc = self.changed()
            doc["variants"][C.C.VARIANTS[1]][0]["command"]["stdout"][field] = value
            self.refused(doc)

    def test_public_file_pin_and_source_label(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / "record.json"
            path.write_bytes(self.raw + b"\n")
            with self.assertRaises(ValueError):
                C.check_file(path)
        with self.assertRaises(ValueError):
            C.main(["--source-revision", "main"])

    def test_reader_cannot_start_backend_or_network(self):
        with mock.patch.object(subprocess, "run", side_effect=AssertionError("unexpected backend")), \
             mock.patch.object(subprocess, "Popen", side_effect=AssertionError("unexpected backend")), \
             mock.patch.object(socket, "socket", side_effect=AssertionError("unexpected network")), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            C.main(["--source-revision", "1" * 40])
        result = json.loads(output.getvalue())
        self.assertEqual(result["source_revision"], "1" * 40)
        self.assertEqual(result["reference_processes_executed_by_this_check"], 0)


if __name__ == "__main__":
    unittest.main()
