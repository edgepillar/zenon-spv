#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Recorded-source, capture and reference controls; no backend is executed."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("offline_rebuild_corpus_controls", HERE / "check_offline_rebuild_successor_corpus.py")
C = importlib.util.module_from_spec(spec)
spec.loader.exec_module(C)


class OfflineRebuildCorpusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original = json.loads((HERE / "testdata/successor-offline-rebuild.json").read_bytes(), object_pairs_hook=C.P.pairs)

    def changed(self):
        return copy.deepcopy(self.original)

    def assert_refused(self, changed):
        with self.assertRaises(ValueError):
            C.check_corpus(changed)

    def test_recorded_comparison_and_exact_reference_expansion(self):
        result = C.check_corpus(self.original)
        self.assertEqual(result["recorded_component_processes"], 2)
        self.assertEqual(result["recorded_functional_cases"], 17)
        self.assertEqual(result["canonical_proof_matches"], 1650)
        self.assertEqual(result["no_version_proof_refusals"], 90)
        self.assertEqual(result["complete_snapshot_reopens_checked"], 34)
        self.assertEqual(result["distinct_complete_snapshot_preimages"], 5)
        self.assertFalse(result["new_reference_node_execution"])
        self.assertEqual(result["consumer_result"], "REFUSED")

    def test_source_module_parent_and_false_acceptance_are_refused(self):
        for field, value in (("node_revision", "0" * 40), ("caller_runtime_tree", C.M.R.T.MODIFIED_TREE),
                             ("module_sha256", "0" * 64), ("source_blobs", True)):
            changed = self.changed()
            changed["source"][field] = value
            self.assert_refused(changed)
        changed = self.changed()
        changed["scope"]["accepted_header_root_binding"] = True
        self.assert_refused(changed)

    def test_invalid_caller_revision_is_refused_before_corpus_replay(self):
        for revision in ("", "0" * 39, "A" * 40, "main"):
            with mock.patch.object(C, "check_corpus", side_effect=AssertionError("must not replay")):
                with self.assertRaises(ValueError):
                    C.main(["--source-revision", revision])

    def test_capture_binary_and_actual_exit_rebinding_are_refused(self):
        changes = (
            lambda row: row["binary"].__setitem__("sha256", "0" * 64),
            lambda row: row["payload"].__setitem__("bytes", row["payload"]["bytes"] + 1),
            lambda row: row["compile"].__setitem__("actual_exit", True),
            lambda row: row["worker"].__setitem__("output_complete", False),
            lambda row: row["component_process"].__setitem__("process_exit", 1),
            lambda row: row.__setitem__("owned_case_workspace_removed", False),
        )
        for change in changes:
            changed = self.changed()
            change(changed["runs"][0])
            self.assert_refused(changed)

    def test_unknown_and_mutated_snapshot_references_are_refused(self):
        changed = self.changed()
        changed["observations"]["full-identifier"]["cases"][0]["closed_reopens"][0]["snapshot_sha256"] = "0" * 64
        self.assert_refused(changed)
        changed = self.changed()
        first = next(iter(changed["shared_snapshots"].values()))
        first["logical_records"]["sha256"] = "0" * 64
        self.assert_refused(changed)

    def test_unreferenced_preimage_and_recursive_reference_are_refused(self):
        changed = self.changed()
        raw = {"not_a_snapshot": True}
        changed["shared_snapshots"][C.P.sha(C.M.encoded(raw))] = raw
        self.assert_refused(changed)
        changed = self.changed()
        ref = changed["observations"]["full-identifier"]["cases"][0]["closed_reopens"][0]
        ref["recursive_alias"] = copy.deepcopy(ref)
        self.assert_refused(changed)

    def test_reencoded_outer_capture_cannot_override_independent_root(self):
        changed = self.changed()
        row = changed["observations"]["full-identifier"]["cases"][0]
        old = row["closed_reopens"][0]["snapshot_sha256"]
        table = copy.deepcopy(changed["shared_snapshots"][old])
        table["roots"][63]["root"] = "0" * 64
        key = C.P.sha(C.M.encoded(table))
        changed["shared_snapshots"][key] = table
        row["closed_reopens"][0] = {"snapshot_sha256": key}
        row["closed_reopens"][1] = {"complete_snapshot_sha256": key}
        expanded, _ = C.expand_observation(changed["observations"]["full-identifier"], changed["shared_snapshots"])
        raw = C.M.encoded(expanded)
        changed["runs"][1]["payload"] = {"sha256": C.P.sha(raw), "bytes": len(raw)}
        evidence = copy.deepcopy(C.EVIDENCE)
        evidence["recorded_runs_sha256"] = C.P.sha(C.M.encoded(changed["runs"]))
        changed["evidence"] = evidence
        # Bypass only the outer frozen-capture checksum in this adversary.
        # The independently selected roots must still refuse correlated data.
        with mock.patch.object(C, "EVIDENCE", evidence):
            self.assert_refused(changed)


if __name__ == "__main__":
    unittest.main()
