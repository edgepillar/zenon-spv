#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Preparation contract controls; no compiler, node or database is executed."""
import copy
import importlib.util
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("raw_kv_preparation_controls", HERE / "prepare_raw_kv_roundtrip_successor.py")
C = importlib.util.module_from_spec(spec)
spec.loader.exec_module(C)


class RawKVPreparationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest, cls.changed, cls.pins = C.selection()
        cls.probe = C.probe_bytes()
        cls.workspace = Path("/selected-owned-raw-kv-roundtrip")

    def plan(self, pins=None, go="/selected/go"):
        return C.plan(self.workspace, go, self.pins if pins is None else pins, self.probe)

    def test_original_runtime_and_instrumented_source_are_separate(self):
        plan = self.plan()
        self.assertEqual((plan["source_blobs"], plan["staged_blobs"]), (467, 468))
        self.assertEqual(plan["original_node_tree"], C.P.TREE)
        self.assertEqual(plan["runtime_tree_without_probe"], C.R.MODIFIED_TREE)
        self.assertNotEqual(plan["staged_tree_with_probe"], plan["runtime_tree_without_probe"])
        self.assertEqual(set(self.changed), {"chain/state_tree.go", "common/trie/nodestore.go"})
        self.assertEqual(C.P.UTIL.reconstruct_tree(self.pins), C.R.MODIFIED_TREE)

    def test_only_trie_component_and_selected_entry_are_executed(self):
        plan = self.plan()
        self.assertEqual(plan["build_argv"][-1], "./common/trie")
        self.assertEqual(plan["run_argv"][-1], "-test.run=^TestCandidateRawKVRoundtripSuccessor$")
        self.assertIn("-mod=readonly", plan["build_argv"])
        self.assertIn("-trimpath", plan["build_argv"])
        self.assertNotIn("-race", plan["build_argv"])
        self.assertFalse(plan["chain_wrappers_compiled_or_executed"])
        self.assertFalse(plan["compiler_overlays_added"])
        self.assertTrue(plan["upstream_test_sources_unchanged"])
        self.assertFalse(plan["upstream_tests_selected_for_execution"])

    def test_module_and_runtime_pins_cannot_be_reselected(self):
        plan = self.plan()
        self.assertEqual(plan["module_sha256"], self.manifest["files"]["go.mod"]["sha256"])
        self.assertEqual(plan["sum_sha256"], self.manifest["files"]["go.sum"]["sha256"])
        for name in ("go.mod", "go.sum", "common/trie/nodestore.go", "chain/state_tree.go"):
            changed = copy.deepcopy(self.pins)
            changed[name]["git_blob"] = "0" * 40
            with self.assertRaises(ValueError):
                self.plan(changed)

    def test_additional_or_missing_source_is_refused(self):
        for insert in (False, True):
            changed = copy.deepcopy(self.pins)
            if insert:
                changed["unknown.go"] = dict(next(iter(changed.values())))
            else:
                changed.pop("go.mod")
            with self.assertRaises(ValueError):
                self.plan(changed)

    def test_go_selector_types_and_empty_values_are_refused(self):
        for go in ("", None, True, b"go", 1):
            with self.assertRaises(ValueError):
                self.plan(go=go)

    def test_expected_evidence_is_not_a_node_input(self):
        plan = self.plan()
        self.assertFalse(plan["expected_roots_or_proofs_passed_to_node"])
        self.assertEqual(set(plan["required_run_environment"]), {
            "ZENON_RAW_KV_SELECTION", "ZENON_RAW_KV_SELECTION_SHA256",
            "ZENON_RAW_KV_POLICY", "ZENON_RAW_KV_WORKSPACE"})
        self.assertEqual(plan["selection_sha256"], C.SELECTION_SHA256)
        self.assertIn(b'io.LimitReader(f, (1<<20)+1)', self.probe)
        self.assertNotIn(b'ZENON_RAW_KV_EXPECTATIONS', self.probe)

    def test_preparation_does_not_claim_authentication_or_execution(self):
        plan = self.plan()
        for field in ("reference_backend_executed", "source_acquisition_performed",
                      "Go_race_detector_selected", "authenticated_snapshot_import",
                      "accepted_header_binding", "balance_value_encoding_agreed",
                      "representative_resources_qualified", "production_state_value_accepted"):
            self.assertIs(plan[field], False)
        self.assertEqual(plan["consumer_result"], "REFUSED")


if __name__ == "__main__":
    unittest.main()
