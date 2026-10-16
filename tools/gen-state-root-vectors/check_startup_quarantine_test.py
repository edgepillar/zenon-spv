#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Adverse controls for the recorded startup-quarantine component comparison."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("selected_quarantine_checker", HERE / "check_startup_quarantine.py")
CHECK = importlib.util.module_from_spec(spec)
spec.loader.exec_module(CHECK)


class StartupQuarantineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _, cls.document = CHECK.BYTE.read_corpus(HERE / "testdata/candidate-startup-quarantine.json")

    def changed(self):
        return copy.deepcopy(self.document)

    def phase(self, document, variant="startup-quarantine", case="above-divergent-retained", round=0, phase=0):
        rows = document["variants"][variant]["cases"]
        return next(row for row in rows if row["input"]["name"] == case)["rounds"][round]["phases"][phase]

    def refused(self, document):
        with self.assertRaises((ValueError, KeyError, TypeError)):
            CHECK.check_corpus(document)

    def test_recorded_complete_comparison(self):
        result = CHECK.check_corpus(self.document)
        self.assertEqual(result["component_initializations"], 30)
        self.assertEqual(result["read_api_observations"], 180)
        self.assertEqual(result["complete_logical_database_snapshots"], 86)

    def test_refusal_preserves_whole_store_and_reopen(self):
        for case in self.document["variants"]["startup-quarantine"]["cases"]:
            for round in case["rounds"]:
                for phase in round["phases"]:
                    if phase["init_error"] is not None:
                        self.assertIs(phase["ready"], False)
                        self.assertEqual(phase["records_before"], phase["records_after"])
                self.assertEqual(round["records_after_close_reopen"], round["phases"][-1]["records_after"])

    def test_matching_ahead_rollback_has_explicit_availability_cost(self):
        baseline = self.phase(self.document, "baseline", "above-matching-retained")
        guarded = self.phase(self.document, case="above-matching-retained")
        self.assertIs(baseline["ready"], True)
        self.assertEqual(guarded["init_error"], CHECK.BLOCKED)
        self.assertEqual(guarded["retained_frontier"]["height"], 3)
        self.assertEqual(guarded["selected_identifier"]["height"], 2)

    def test_previously_ready_error_clears_readiness(self):
        name = "previously-ready-same-height-other-hash"
        baseline = self.phase(self.document, "baseline", name, phase=1)
        guarded = self.phase(self.document, case=name, phase=1)
        self.assertIs(baseline["ready"], True)
        self.assertIs(guarded["ready"], False)
        self.assertEqual(baseline["init_error"], guarded["init_error"])
        self.assertEqual(guarded["init_error"], CHECK.START.WRONG_ANCESTRY)
        self.assertTrue(all(row["error"] == CHECK.START.NOT_READY for row in guarded["queries"]))

    def test_height_only_reads_remain_unrepaired(self):
        for variant in CHECK.VARIANTS:
            phase = self.phase(self.document, variant, "matching-prebuild")
            self.assertNotEqual(phase["queries"][0]["identifier"], phase["queries"][1]["identifier"])
            self.assertEqual(phase["queries"][0]["root"], phase["queries"][1]["root"])
            self.assertEqual(phase["queries"][2]["proof"], phase["queries"][3]["proof"])
        self.assertIs(self.document["scope"]["low_level_height_only_APIs_repaired"], False)
        self.assertEqual(self.document["consumer_result"], "REFUSED")

    def test_coherent_provider_replacement_cannot_select_expected_state(self):
        doc = self.changed()
        row = self.phase(doc, "baseline")
        root, value, levels, values = CHECK.START.state_bytes("B", 2)
        row["queries"][0]["root"] = root.hex()
        row["queries"][2]["value"] = value.hex()
        row["queries"][2]["proof"] = CHECK.BYTE.canonical_proof(levels, values, CHECK.BYTE.digest(CHECK.START.selected_key())).hex()
        self.refused(doc)

    def test_changed_target_identifier_refused(self):
        doc = self.changed()
        self.phase(doc)["selected_identifier"]["hash"] = "00" * 32
        self.refused(doc)

    def test_changed_retained_identifier_refused(self):
        doc = self.changed()
        self.phase(doc)["retained_frontier"] = self.phase(doc)["selected_identifier"]
        self.refused(doc)

    def test_changed_database_frontier_refused(self):
        doc = self.changed()
        row = next(row for row in self.phase(doc)["records_after"] if row["key"] == "00")
        row["value"] = "00" * 40
        self.refused(doc)

    def test_missing_logical_record_refused(self):
        doc = self.changed()
        self.phase(doc)["records_after"].pop()
        self.refused(doc)

    def test_changed_refcount_refused(self):
        doc = self.changed()
        row = next(row for row in self.phase(doc)["records_after"] if row["key"].startswith("02"))
        row["value"] = "00" * 7 + "02"
        self.refused(doc)

    def test_changed_version_root_refused(self):
        doc = self.changed()
        row = next(row for row in self.phase(doc)["records_after"] if row["key"].startswith("03"))
        row["value"] = "00" * 32
        self.refused(doc)

    def test_reopen_drift_refused(self):
        doc = self.changed()
        doc["variants"]["startup-quarantine"]["cases"][7]["rounds"][0]["records_after_close_reopen"].pop()
        self.refused(doc)

    def test_ready_boolean_cannot_be_integer(self):
        doc = self.changed()
        self.phase(doc)["ready"] = 0
        self.refused(doc)

    def test_lost_quarantine_error_refused(self):
        doc = self.changed()
        self.phase(doc)["init_error"] = None
        self.refused(doc)

    def test_missing_priming_call_refused(self):
        doc = self.changed()
        doc["variants"]["startup-quarantine"]["cases"][-1]["rounds"][0]["phases"].pop(0)
        self.refused(doc)

    def test_missing_reopen_round_refused(self):
        doc = self.changed()
        doc["variants"]["startup-quarantine"]["cases"][9]["rounds"].pop()
        self.refused(doc)

    def test_missing_original_case_refused(self):
        doc = self.changed()
        doc["variants"]["baseline"]["cases"].pop(0)
        self.refused(doc)

    def test_swapped_variant_labels_refused(self):
        doc = self.changed()
        doc["variants"]["baseline"], doc["variants"]["startup-quarantine"] = doc["variants"]["startup-quarantine"], doc["variants"]["baseline"]
        self.refused(doc)

    def test_unknown_fields_refused(self):
        doc = self.changed()
        self.phase(doc)["recovery_approved"] = True
        self.refused(doc)

    def test_changed_probe_pin_refused(self):
        doc = self.changed()
        doc["source"]["producer_inputs"]["startup_quarantine_probe_test.go"] = "00" * 32
        self.refused(doc)

    def test_production_acceptance_claim_refused(self):
        doc = self.changed()
        doc["scope"]["production_state_value_accepted"] = True
        self.refused(doc)

    def test_current_complete_node_qualification_claim_refused(self):
        doc = self.changed()
        doc["scope"]["complete_current_node_revision_qualified"] = True
        self.refused(doc)

    def test_duplicate_json_fields_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "duplicate.json"
            path.write_bytes(b'{"format_version":1,"format_version":1}')
            with self.assertRaises(ValueError):
                CHECK.BYTE.read_corpus(path)

    def test_oversized_raw_input_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "oversized.json"
            path.write_bytes(b" " * (CHECK.BYTE.MAX_FILE_BYTES + 1))
            with self.assertRaises(ValueError):
                CHECK.BYTE.read_corpus(path)

    def test_unselected_patch_source_refused(self):
        with self.assertRaises(ValueError):
            CHECK.PREP.patch_source(b"unselected complete source")

    def test_existing_workspace_refused_before_source_acquisition(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sentinel = root / "preserved.txt"
            sentinel.write_bytes(b"preserved")
            before = sentinel.stat()
            with mock.patch.object(CHECK.PREP.SOURCE, "snapshot_source", side_effect=AssertionError("unexpected source read")):
                with self.assertRaises(ValueError):
                    CHECK.PREP.prepare(root, root, "baseline", "selected-go")
            self.assertEqual(sentinel.read_bytes(), b"preserved")
            self.assertEqual((before.st_dev, before.st_ino), (sentinel.stat().st_dev, sentinel.stat().st_ino))

    def test_unknown_variant_refused_before_source_acquisition(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "new"
            with mock.patch.object(CHECK.PREP.SOURCE, "snapshot_source", side_effect=AssertionError("unexpected source read")):
                with self.assertRaises(ValueError):
                    CHECK.PREP.prepare(Path(directory), root, "unselected", "selected-go")
            self.assertFalse(root.exists())

    def test_patch_descriptor_keeps_qualification_closed(self):
        patch = json.loads((HERE / CHECK.PREP.PATCH).read_bytes())
        self.assertEqual(len(patch["replacements"]), 2)
        self.assertIn("func (s *stateTree) Init(", patch["replacements"][0]["before"])
        self.assertIn("s.ready.Store(false)", patch["replacements"][0]["after"])
        for key in ("persisted_schema_changed", "low_level_height_only_API_repaired",
                    "authenticated_retained_version_provenance_qualified", "production_qualified"):
            self.assertIs(patch[key], False)


if __name__ == "__main__":
    unittest.main()

