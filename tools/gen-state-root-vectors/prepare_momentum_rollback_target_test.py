#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Rollback-target source boundaries; no compiler or reference process is started."""
import copy
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest import mock

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("rollback_target_source_controls", HERE / "prepare_momentum_rollback_target.py")
H = importlib.util.module_from_spec(spec)
spec.loader.exec_module(H)


class MomentumRollbackTargetPreparationTests(unittest.TestCase):
    def test_runtime_changes_only_rollback_target_preflight(self):
        manifest, modified, pins = H.selection()
        _, earlier, parent = H.H.selection()
        self.assertEqual((len(manifest["files"]), len(pins)), (467, 467))
        self.assertEqual(set(modified) - set(earlier), {H.FILE})
        self.assertEqual(H.P.UTIL.reconstruct_tree(pins), H.MODIFIED_TREE)
        for name in earlier:
            self.assertEqual(modified[name], earlier[name])
        for name in set(pins) - {H.FILE}:
            self.assertEqual(pins[name], parent[name])
        for name in ("go.mod", "go.sum"):
            self.assertEqual(pins[name], manifest["files"][name])

    def test_patch_has_an_exact_inverse_and_no_pop_changes(self):
        patch = H.P.document(H.PATCH, H.PATCH_SHA256)
        before, after = patch["before"], patch["after"]
        old = "\tif momentum.Hash != identifier.Hash {\n"
        new = ("\tif momentum == nil {\n"
               "\t\treturn errors.Errorf(\"can't rollback momentums. No momentum at height %v\", identifier.Height)\n"
               "\t}\n\tif momentum.Identifier() != identifier {\n")
        self.assertEqual(after.replace(new, old), before)
        marker = "func (c *momentumPool) RollbackTo("
        body = after.split(marker, 1)[1].split("\nfunc ", 1)[0]
        original_body = before.split(marker, 1)[1].split("\nfunc ", 1)[0]
        self.assertLess(body.index("if momentum == nil"), body.index("if momentum.Identifier()"))
        self.assertLess(body.index("if momentum.Identifier()"), body.index("c.chainManager.Pop()"))
        self.assertEqual(original_body.split("c.chainManager.Pop()", 1)[1], body.split("c.chainManager.Pop()", 1)[1])

    def test_ordinary_and_unit_sources_are_separate_pinned_trees(self):
        for variant, unit, tree in (("parent", False, H.PARENT_BUILD_TREE),
                                    ("candidate", False, H.BUILD_TREE),
                                    ("candidate", True, H.UNIT_BUILD_TREE)):
            pins = H.build_pins(variant, unit)
            self.assertEqual(len(pins), 468)
            self.assertEqual(H.P.UTIL.reconstruct_tree(pins), tree)
            self.assertEqual(H.PROBE_TARGET in pins, not unit)
            self.assertEqual(H.UNIT_TARGET in pins, unit)
        self.assertEqual(len({H.PARENT_BUILD_TREE, H.BUILD_TREE, H.UNIT_BUILD_TREE}), 3)

    def test_patch_metadata_substitution_refuses(self):
        original = H.P.document(H.PATCH, H.PATCH_SHA256)
        changes = [lambda row, key=key: row.update({key: not row[key]})
                   for key in original if type(original[key]) is bool]
        changes += [lambda row, key=key: row.update({key: "0" * len(row[key])})
                    for key in ("node_revision", "runtime_parent_tree", "runtime_candidate_tree",
                                "before_sha256", "after_sha256", "before_git_blob", "after_git_blob")]
        changes += [lambda row: row.update(mode="100755"), lambda row: row.update(file="chain/cache.go"),
                    lambda row: row.update(before=row["before"] + "\n"),
                    lambda row: row.update(after=row["after"] + "\n"),
                    lambda row: row.update(after_bytes=True), lambda row: row.update(unexpected=True)]
        real = H.P.document
        for change in changes:
            row = copy.deepcopy(original)
            change(row)
            with mock.patch.object(H.P, "document", side_effect=lambda n, h: row if n == H.PATCH else real(n, h)):
                with self.assertRaises((ValueError, KeyError, TypeError)):
                    H.selection()

    def test_both_probe_byte_substitutions_refuse(self):
        read = H.P.read_regular
        for filename, unit in ((H.PROBE, False), (H.UNIT, True)):
            def changed(path, limit):
                raw = read(path, limit)
                return raw + b"\n" if Path(path).name == filename else raw
            with mock.patch.object(H.P, "read_regular", side_effect=changed):
                with self.assertRaises(ValueError):
                    H.extra_source(unit)

    def test_plan_does_not_select_network_or_acceptance(self):
        plan = H.plan(Path("/selected-owned-rollback"), "/selected/go")
        self.assertEqual(plan["source_blobs"], 468)
        self.assertEqual(plan["minimum_free_floor_bytes"], 10 << 30)
        self.assertEqual(plan["consumer_result"], "REFUSED")
        for key in ("reference_backend_executed", "new_dependency_transports_permitted", "Chain_Init_or_Start_selected",
                    "cache_or_state_tree_selected", "consensus_or_network_selected", "accepted_header_binding",
                    "runtime_state_value_acceptance"):
            self.assertIs(plan[key], False)
        for key in ("build_argv", "native_test_argv"):
            self.assertEqual(plan[key][0], "/selected/go")
            self.assertIn("-mod=readonly", plan[key])
            self.assertIn("-trimpath", plan[key])
            self.assertNotIn("-overlay", plan[key])

    def test_focused_controls_retain_pop_failure_classifications(self):
        plan = H.plan(Path("/selected-owned-rollback"), "go", unit=True)
        self.assertEqual(len(plan["native_test_roots"]), 5)
        self.assertEqual(plan["expected_native_unit_pass_results"], 11)
        self.assertIn("TestRollbackToFailureAfterPopIsUnrecoverable", plan["native_test_roots"])
        self.assertIn("TestRollbackToFirstPopFailureLeavesCanonicalStateCertain", plan["native_test_roots"])
        self.assertEqual(plan["added_source_file"], H.UNIT_TARGET)
        raw = H.extra_source(True)[1]
        self.assertIn(b"same hash with a wrong returned height", raw)
        self.assertIn(b"corruptEntryAtHeight", raw)

    def test_existing_workspace_refuses_before_source_read(self):
        with mock.patch.object(H.P, "private_destination", side_effect=ValueError("existing workspace")), \
                mock.patch.object(H.P.UTIL, "snapshot_source") as snapshot:
            with self.assertRaises(ValueError):
                H.prepare(Path("/selected-original"), Path("/selected-existing"), "go")
        snapshot.assert_not_called()

    def test_invalid_selection_and_compiler_refuse(self):
        for go in (None, "", "go\x00other"):
            with self.assertRaises(ValueError):
                H.plan(Path("/selected-owned"), go)
        for variant, unit in (("other", False), ("parent", True), ("candidate", 1)):
            with self.assertRaises(ValueError):
                H.build_pins(variant, unit)


if __name__ == "__main__":
    unittest.main()
