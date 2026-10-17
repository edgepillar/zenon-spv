#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Caller/source controls without a compiler, database or node execution."""
import copy
import importlib.util
from pathlib import Path
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("offline_rebuild_preparation_controls", HERE / "prepare_offline_rebuild_successor.py")
C = importlib.util.module_from_spec(spec)
spec.loader.exec_module(C)


class OfflineRebuildPreparationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest, cls.modified, cls.pins = C.T.parent_selection()
        cls.terminal = C.T.patch_state(cls.modified[C.T.STATE])
        cls.workspace, cls.go = Path("/selected-owned-offline-rebuild"), "/selected/go"
        cls.parent = C.P.plan(cls.workspace, "hash-bound", cls.go, cls.pins,
                             (HERE / C.P.PROBE).read_bytes(), b"{}\n", b"selected module\n", b"selected sums\n")

    def plan(self, variant="full-identifier", parent=None, go=None):
        return C.plan(self.workspace, variant, self.go if go is None else go,
                      self.parent if parent is None else parent, (HERE / C.PROBE).read_bytes())

    def test_complete_parent_and_caller_trees_are_separate(self):
        for variant, tree in (("terminal-parent", C.T.MODIFIED_TREE), ("full-identifier", C.MODIFIED_TREE)):
            manifest, _, state, pins = C.runtime_selection(variant)
            self.assertEqual(len(manifest["files"]), 467)
            self.assertEqual(C.P.UTIL.reconstruct_tree(pins), tree)
            self.assertNotIn(b"lifecycleCheckpoint(", state)
            self.assertEqual(pins["common/trie/nodestore.go"], self.pins["common/trie/nodestore.go"])
        self.assertNotEqual(C.MODIFIED_TREE, C.T.MODIFIED_TREE)

    def test_unique_complete_file_and_inverse_bind_the_caller_patch(self):
        patched = C.patch_state(self.terminal)
        descriptor = C.P.document(C.PATCH, C.PATCH_SHA256)
        row = descriptor["replacements"][0]
        self.assertEqual(patched.replace(row["after"].encode(), row["before"].encode(), 1), self.terminal)
        self.assertEqual((len(patched), C.P.sha(patched)), (C.AFTER_BYTES, C.AFTER))
        self.assertIn(b"st.tree.Root(momentum.Identifier())", patched)
        self.assertIn(b"momentum == nil || momentum.Height != h", patched)

    def test_unselected_or_correlated_parent_bytes_are_refused(self):
        for raw in (self.modified[C.T.STATE], self.terminal + b"\n", b"", self.terminal.replace(b"retentionFloor", b"retentionAltered")):
            with self.assertRaises(ValueError):
                C.patch_state(raw)

    def test_false_acceptance_and_unbound_descriptor_fields_are_refused(self):
        original = C.P.document(C.PATCH, C.PATCH_SHA256)
        for field, value in (("production_qualified", True), ("public_Root_identity_checks_relaxed", True),
                             ("historical_source_records_rebound", True), ("state_value_acceptance_enabled", True),
                             ("base_blob_count", True), ("terminal_parent_tree", C.P.TREE),
                             ("after_sha256", "0" * 64)):
            changed = copy.deepcopy(original)
            changed[field] = value
            with mock.patch.object(C.P, "document", return_value=changed):
                with self.assertRaises(ValueError):
                    C.patch_state(self.terminal)

    def test_ordinary_build_keeps_own_modules_and_only_selected_new_test(self):
        plan = self.plan()
        self.assertNotIn("-race", plan["build_argv"])
        self.assertEqual(plan["build_argv"][-1], "./chain")
        self.assertIn("-mod=readonly", plan["build_argv"])
        self.assertEqual(plan["build_argv"][plan["build_argv"].index("-tags") + 1], C.P.TAG + "," + C.TAG)
        self.assertEqual(plan["module_sha256"], self.parent["module_sha256"])
        self.assertEqual(plan["sum_sha256"], self.parent["sum_sha256"])
        self.assertEqual(plan["run_argv"][-1], "-test.run=^TestCandidateOfflineRebuildSuccessor$")
        self.assertEqual((plan["history_height"], plan["short_functional_retention_override"]), (64, 5))
        self.assertFalse(plan["reference_backend_executed"])
        self.assertFalse(plan["production_resources_qualified"])
        self.assertEqual(plan["consumer_result"], "REFUSED")

    def test_race_recursive_variant_and_compiler_drift_are_refused(self):
        for change in (lambda p: p["build_argv"].insert(2, "-race"),
                       lambda p: p["build_argv"].__setitem__(-1, "./..."),
                       lambda p: p["build_argv"].__setitem__(0, "/other/go")):
            parent = copy.deepcopy(self.parent)
            change(parent)
            with self.assertRaises(ValueError):
                self.plan(parent=parent)
        with self.assertRaises(ValueError):
            self.plan(variant="baseline")


if __name__ == "__main__":
    unittest.main()
