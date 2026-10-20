#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Source-bound startup preparation controls; no compiler/backend is executed."""
import copy
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest import mock

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("startup_source_controls", HERE / "prepare_public_chain_startup_record.py")
H = importlib.util.module_from_spec(spec)
spec.loader.exec_module(H)


class PublicChainStartupRecordPreparationTests(unittest.TestCase):
    def test_runtime_changes_only_public_startup(self):
        manifest, modified, pins = H.selection()
        _, earlier, parent = H.H.selection()
        self.assertEqual(len(manifest["files"]), 467)
        self.assertEqual(set(modified), set(earlier))
        self.assertEqual(H.P.UTIL.reconstruct_tree(pins), H.MODIFIED_TREE)
        for name in set(pins) - {H.FILE}:
            self.assertEqual(pins[name], parent[name])
        for name in set(earlier) - {H.FILE}:
            self.assertEqual(modified[name], earlier[name])
        for name in ("go.mod", "go.sum"):
            self.assertEqual(pins[name], manifest["files"][name])

    def test_start_stop_and_insert_implementations_are_unchanged(self):
        row = H.P.document(H.PATCH, H.PATCH_SHA256)
        before, after = row["before"], row["after"]
        start, end = "func (c *chain) Start()", "func (c *chain) checkGenesisCompatibility()"
        self.assertEqual(before.split(start)[1].split(end)[0], after.split(start)[1].split(end)[0])
        self.assertEqual(before.split("func (c *chain) AcquireInsert")[1],
                         after.split("func (c *chain) AcquireInsert")[1])
        self.assertLess(after.index("frontier.ComputeHash()"), after.index("c.Register(c.accountPool)"))
        self.assertLess(after.index("if genesisMomentum == nil"),
                        after.index("if genesisMomentum.Identifier()"))
        self.assertIn("genesisMomentum.ComputeHash() != genesisMomentum.Hash", after)

    def test_ordinary_and_unit_build_trees_are_pinned_separately(self):
        for variant, unit, tree, count in (("parent", False, H.PARENT_BUILD_TREE, 468),
                                          ("candidate", False, H.BUILD_TREE, 468),
                                          ("candidate", True, H.UNIT_BUILD_TREE, 470)):
            pins = H.build_pins(variant, unit)
            self.assertEqual(len(pins), count)
            self.assertEqual(H.P.UTIL.reconstruct_tree(pins), tree)
            self.assertIn(H.PROBE_TARGET, pins)
            self.assertEqual(H.UNIT_TARGET in pins, unit)
            self.assertEqual(H.H.UNIT_TARGET in pins, unit)

    def test_patch_metadata_or_body_substitution_refuses(self):
        original = H.P.document(H.PATCH, H.PATCH_SHA256)
        changes = [lambda row, key=key: row.update({key: not row[key]})
                   for key in original if type(original[key]) is bool]
        changes += [lambda row, key=key: row.update({key: "0" * len(row[key])})
                    for key in ("node_revision", "runtime_parent_tree", "runtime_candidate_tree",
                                "before_sha256", "after_sha256", "before_git_blob", "after_git_blob")]
        changes += [lambda row: row.update(mode="100755"), lambda row: row.update(file="chain/cache.go"),
                    lambda row: row.update(after=row["after"] + "\n"),
                    lambda row: row.update(after_bytes=True), lambda row: row.update(extra=True)]
        real = H.P.document
        for change in changes:
            row = copy.deepcopy(original)
            change(row)
            with mock.patch.object(H.P, "document", side_effect=lambda n, h: row if n == H.PATCH else real(n, h)):
                with self.assertRaises((ValueError, KeyError, TypeError)):
                    H.selection()

    def test_probe_and_unit_substitution_refuses(self):
        read = H.P.read_regular
        for filename, unit in ((H.PROBE, False), (H.UNIT, True)):
            def changed(path, limit):
                raw = read(path, limit)
                return raw + b"\n" if Path(path).name == filename else raw
            with mock.patch.object(H.P, "read_regular", side_effect=changed):
                with self.assertRaises(ValueError):
                    H.extras(unit)

    def test_plan_keeps_execution_and_acceptance_boundaries(self):
        plan = H.plan(Path("/selected-owned-startup"), "/selected/go")
        self.assertEqual(plan["source_blobs"], 468)
        self.assertEqual(plan["minimum_free_floor_bytes"], 10 << 30)
        self.assertEqual(plan["consumer_result"], "REFUSED")
        for key in ("reference_backend_executed", "new_dependency_transports_permitted",
                    "Chain_Start_or_network_selected", "full_node_or_concurrent_lifecycle_qualified",
                    "accepted_header_binding", "runtime_state_value_acceptance"):
            self.assertIs(plan[key], False)
        self.assertIs(plan["public_Chain_Init_and_Stop_selected"], True)
        for key in ("build_argv", "native_test_argv"):
            self.assertEqual(plan[key][0], "/selected/go")
            self.assertIn("-mod=readonly", plan[key])
            self.assertIn("-trimpath", plan[key])

    def test_native_controls_keep_prior_rollback_and_stop_roots(self):
        plan = H.plan(Path("/selected-owned-startup"), "go", unit=True)
        self.assertEqual(len(plan["native_test_roots"]), 11)
        self.assertEqual(plan["expected_native_unit_pass_results"], 17)
        self.assertEqual(plan["source_blobs"], 470)
        self.assertTrue(set(H.H.ROOTS).issubset(plan["native_test_roots"]))
        raw = H.extras(True)[H.UNIT_TARGET]
        self.assertIn(b"package chain_test", raw)
        self.assertIn(b"quietStartupFixture(t)", raw)
        self.assertIn(b"errors.Is(got, sentinel)", raw)

    def test_existing_workspace_refuses_before_source_read(self):
        with mock.patch.object(H.P, "private_destination", side_effect=ValueError("existing workspace")), \
                mock.patch.object(H.P.UTIL, "snapshot_source") as snapshot:
            with self.assertRaises(ValueError):
                H.prepare(Path("/selected-source"), Path("/selected-existing"), "go")
        snapshot.assert_not_called()

    def test_invalid_variant_or_compiler_refuses(self):
        for go in (None, "", "go\x00other"):
            with self.assertRaises(ValueError):
                H.plan(Path("/selected-owned"), go)
        for variant, unit in (("other", False), ("parent", True), ("candidate", 1)):
            with self.assertRaises(ValueError):
                H.build_pins(variant, unit)


if __name__ == "__main__":
    unittest.main()
