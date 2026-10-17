#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Source/selection controls; no node, compiler or resource sample is executed."""
import copy
import importlib.util
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("successor_retention_preparation_controls", HERE / "prepare_default_retention_successor.py")
C = importlib.util.module_from_spec(spec)
spec.loader.exec_module(C)


class SuccessorRetentionPreparationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest, cls.modified, cls.pins = C.T.parent_selection()
        cls.workspace = Path("/selected-owned-successor-resource-workspace")
        cls.go = "/selected/go"
        cls.parent = C.P.plan(cls.workspace, "hash-bound", cls.go, cls.pins,
                             (HERE / C.P.PROBE).read_bytes(), b"{}\n", b"selected node module\n", b"selected sums\n")

    def plan(self, parent=None):
        return C.plan(self.workspace, self.go, self.parent if parent is None else parent,
                      (HERE / C.PROBE).read_bytes(), (HERE / C.HELPER).read_bytes())

    def test_complete_separate_runtime_tree_without_scheduler_hooks(self):
        self.assertEqual(len(self.manifest["files"]), 467)
        terminal = C.T.patch_state(self.modified[C.T.STATE])
        self.assertNotIn(b"lifecycleCheckpoint(", terminal)
        pins = copy.deepcopy(self.pins)
        pins[C.T.STATE]["git_blob"] = C.P.UTIL.git_hash("blob", terminal)
        self.assertEqual(C.P.UTIL.reconstruct_tree(pins), C.T.MODIFIED_TREE)
        self.assertNotEqual(C.T.MODIFIED_TREE, C.P.TREE)

    def test_one_ordinary_build_uses_selected_module_and_only_new_test(self):
        selected = self.plan()
        self.assertNotIn("-race", selected["build_argv"])
        self.assertIn("-mod=readonly", selected["build_argv"])
        self.assertIn("-p=1", selected["build_argv"])
        self.assertEqual(selected["build_argv"][-1], "./chain")
        self.assertEqual(selected["build_argv"][selected["build_argv"].index("-tags") + 1],
                         ",".join((C.P.TAG, C.HELPER_TAG, C.TAG)))
        self.assertEqual(selected["module_sha256"], self.parent["module_sha256"])
        self.assertEqual(selected["sum_sha256"], self.parent["sum_sha256"])
        self.assertEqual(selected["run_argv"][-1], "-test.run=^TestCandidateDefaultRetentionSuccessor$")
        self.assertFalse(selected["reference_backend_executed"])
        self.assertFalse(selected["historical_source_records_rebound"])
        self.assertEqual(selected["consumer_result"], "REFUSED")

    def test_race_recursive_or_different_compiler_parent_is_refused(self):
        for change in (lambda p: p["build_argv"].insert(2, "-race"),
                       lambda p: p["build_argv"].__setitem__(-1, "./..."),
                       lambda p: p["build_argv"].__setitem__(0, "/other/go")):
            parent = copy.deepcopy(self.parent)
            change(parent)
            with self.assertRaises(ValueError):
                self.plan(parent)

    def test_default_retention_and_both_policies_remain_explicit(self):
        selected = self.plan()
        self.assertEqual((selected["history_height"], selected["mutation_addresses"]), (32768, 256))
        self.assertEqual((selected["retention_override"], selected["bulk_batch_override"]), (0, 0))
        self.assertEqual((selected["expected_pruned_horizon_inclusive"], selected["expected_pruned_roots"]),
                         (15388, 17381))
        self.assertEqual(selected["expected_archive_roots"], 32768)
        self.assertEqual(selected["required_run_environment"]["ZENON_DEFAULT_RETENTION_POLICY"], "pruned or archive")

    def test_fresh_genesis_generator_diff_is_only_three_explicit_bindings(self):
        raw = (HERE / "genesis-input/main.go").read_bytes()
        changes = ((b'"pinned-source-unsigned-genesis-input"', b'"pinned-successor-source-unsigned-genesis-input"'),
                   (b"33d7d1ee1b6a915c40aea196e2a10f1e893d171f", C.P.REVISION.encode()),
                   (b"40d71efb7e462d5bbd0f27d83ed7588e121c3cb6", C.P.TREE.encode()))
        for before, after in changes:
            self.assertEqual(raw.count(before), 1)
            raw = raw.replace(before, after, 1)
        self.assertEqual(raw, (HERE / "genesis-input-successor/main.go").read_bytes())
        self.assertIn(b"genesis.MakeEmbeddedGenesisConfig()", raw)
        self.assertIn(b"m.ComputeHash() != m.Hash", raw)
        self.assertIn(b'"NodeTree_executed":', raw)

    def test_shared_genesis_helper_remains_original_and_is_not_selected(self):
        selected = self.plan()
        self.assertIn(C.HELPER, selected["parent_helpers_compiled_but_not_selected"])
        self.assertEqual(selected["genesis_helper_sha256"], C.P.sha((HERE / C.HELPER).read_bytes()))
        self.assertNotIn("TestCandidateGenesisBackground", " ".join(selected["run_argv"]))
        self.assertFalse(selected["scheduler_checkpoints_injected"])


if __name__ == "__main__":
    unittest.main()
