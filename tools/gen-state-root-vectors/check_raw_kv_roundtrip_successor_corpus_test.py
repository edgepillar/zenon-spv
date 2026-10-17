#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Recorded capture/source bindings; execute no reference node."""
import copy
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("recorded_raw_kv_controls", HERE / "check_raw_kv_roundtrip_successor_corpus.py")
C = importlib.util.module_from_spec(spec)
spec.loader.exec_module(C)


class RecordedRawKVCorpusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = (HERE / "testdata" / C.CORPUS).read_bytes()
        cls.manifest = (HERE / "testdata" / C.EXECUTION).read_bytes()

    def test_complete_recorded_evidence_has_no_new_reference_execution(self):
        with mock.patch("subprocess.Popen", side_effect=AssertionError("Unselected process")):
            result = C.check_files(self.raw, self.manifest)
        self.assertEqual(result["reference_processes_executed_by_this_check"], 0)
        self.assertEqual(sum(row["canonical_proof_positions"] for row in result["policies"]), 3015)
        self.assertEqual(result["recorded_reference_platform"], "darwin/arm64")
        self.assertFalse(result["original_transport_bytes_reconstructed_or_rehashed"])
        self.assertTrue(result["original_transport_digest_metadata_bound_to_selected_manifest"])
        self.assertEqual(result["consumer_result"], "REFUSED")
        self.assertFalse(result["runtime_state_value_acceptance"])
        self.assertFalse(result["accepted_header_binding"])

    def test_corpus_truncation_mutation_whitespace_and_type_aliases_are_refused(self):
        for raw in (self.raw[:-1], self.raw + b"\n", b"x" + self.raw[1:], bytearray(self.raw)):
            with self.assertRaises(ValueError):
                C.check_files(raw, self.manifest)

    def test_execution_metadata_cannot_be_replaced_independently(self):
        value = C.C.document(self.manifest, 128 << 10)
        value["original_transports"]["archive"]["sha256"] = "0" * 64
        for raw in (C.K.encoded(value), self.manifest[:-1], bytearray(self.manifest)):
            with self.assertRaises(ValueError):
                C.check_files(self.raw, raw)

    def test_selected_probe_drift_invalidates_recorded_source_binding(self):
        original = C.C.P.read_regular

        def read(path, limit):
            raw = original(path, limit)
            return raw + b"\n" if Path(path).name == "raw_kv_roundtrip_successor_probe_test.go" else raw

        with mock.patch.object(C.C.P, "read_regular", side_effect=read):
            with self.assertRaises(ValueError):
                C.check_files(self.raw, self.manifest)

    def test_independent_source_selection_cannot_be_rebound_to_captured_output(self):
        sources = copy.deepcopy(C.C.M.source_inputs())
        sources["raw_kv_roundtrip_codec.py"]["sha256"] = "0" * 64
        with mock.patch.object(C.C.M, "source_inputs", return_value=sources):
            with self.assertRaises(ValueError):
                C.check_files(self.raw, self.manifest)

    def test_optional_source_revision_is_a_separate_caller_selected_binding(self):
        revision = "a" * 40
        stream = io.StringIO()
        with mock.patch.object(C, "check", return_value={"consumer_result": "REFUSED"}):
            with contextlib.redirect_stdout(stream):
                C.main(["--source-revision", revision])
        self.assertEqual(json.loads(stream.getvalue()), {"consumer_result": "REFUSED", "source_revision": revision})

    def test_invalid_source_revisions_are_refused_before_reading_corpus(self):
        for revision in ("", "A" * 40, "a" * 39, "g" * 40):
            with mock.patch.object(C, "check", side_effect=AssertionError("Unexpected corpus read")):
                with self.assertRaises(ValueError):
                    C.main(["--source-revision", revision])


if __name__ == "__main__":
    unittest.main()
