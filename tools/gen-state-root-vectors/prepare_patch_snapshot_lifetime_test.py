#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Source and preparation controls; no compiler, database or backend is started."""
import copy
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest import mock

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("snapshot_preparation_controls", HERE / "prepare_patch_snapshot_lifetime.py")
H = importlib.util.module_from_spec(spec)
spec.loader.exec_module(H)


class PatchSnapshotPreparationTests(unittest.TestCase):
    def test_complete_runtime_tree_and_unchanged_dependency_inputs(self):
        manifest, modified, pins = H.selection()
        self.assertEqual(len(manifest["files"]), 467)
        self.assertEqual(len(pins), 467)
        self.assertEqual(H.P.UTIL.reconstruct_tree(pins), H.MODIFIED_TREE)
        _, earlier, parent = H.H.selection()
        self.assertEqual(set(modified) - set(earlier), {H.FILE})
        for name in earlier:
            self.assertEqual(modified[name], earlier[name])
        for name in pins:
            if name != H.FILE:
                self.assertEqual(pins[name], parent[name])
        for name in ("go.mod", "go.sum"):
            self.assertEqual(pins[name], manifest["files"][name])

    def test_only_two_short_lived_snapshot_helpers_change(self):
        row = H.P.document(H.PATCH, H.PATCH_SHA256)["replacements"][0]
        old = "\tsnapshot, _ := m.ldb.GetSnapshot()\n"
        new = "\tsnapshot, err := m.ldb.GetSnapshot()\n\tcommon.DealWithErr(err)\n\tdefer snapshot.Release()\n"
        self.assertEqual(row["before"].count(old), 4)
        self.assertEqual(row["after"].count(new), 2)
        expected = row["before"]
        for marker in ("func (m *ldbManager) getPatch(", "func (m *ldbManager) getRollback("):
            prefix, selected = expected.split(marker, 1)
            self.assertTrue(selected.startswith(row["before"].split(marker, 1)[1].split("\nfunc ", 1)[0]))
            expected = prefix + marker + selected.replace(old, new, 1)
            body = row["after"].split(marker, 1)[1].split("\nfunc ", 1)[0]
            self.assertEqual(body.count(new), 1)
            self.assertLess(body.index("defer snapshot.Release()"), body.index("snapshot.Get("))
        self.assertEqual(expected, row["after"])
        self.assertEqual(row["after"].count(old), 2)

    def test_isolated_component_source_identities_are_reconstructed(self):
        self.assertEqual(H.component_build_trees(),
                         (H.COMPONENT_PARENT_BUILD_TREE, H.COMPONENT_CANDIDATE_BUILD_TREE))
        self.assertNotEqual(H.COMPONENT_RUNTIME_TREE, H.MODIFIED_TREE)

    def test_substituted_patch_headers_and_full_file_bytes_refuse(self):
        original = H.P.document(H.PATCH, H.PATCH_SHA256)
        changes = [lambda d, key=key: d.update({key: not d[key]})
                   for key in original if type(original[key]) is bool]
        changes += [
            lambda d: d.update(runtime_parent_tree="0" * 40),
            lambda d: d.update(runtime_after_tree="0" * 40),
            lambda d: d.update(node_revision="0" * 40),
            lambda d: d["replacements"].pop(),
            lambda d: d["replacements"][0].update(before="changed"),
            lambda d: d["replacements"][0].update(after=d["replacements"][0]["after"] + "\n"),
            lambda d: d["replacements"][0].update(after_git_blob="0" * 40),
            lambda d: d["replacements"][0].update(mode="100755"),
            lambda d: d.update(unexpected=True),
        ]
        real = H.P.document
        for change in changes:
            value = copy.deepcopy(original)
            change(value)
            with mock.patch.object(H.P, "document", side_effect=lambda n, h: value if n == H.PATCH else real(n, h)):
                with self.assertRaises((ValueError, KeyError, TypeError)):
                    H.selection()

    def test_all_six_previous_probe_and_control_sources_are_unchanged(self):
        earlier, current = H.H.extra_sources(), H.extra_sources()
        self.assertEqual(len(earlier), 6)
        self.assertEqual(len(current), 7)
        for name, raw in earlier.items():
            self.assertEqual(current[name], raw)
        self.assertEqual(set(current) - set(earlier), {H.PROBE_TARGET})
        self.assertEqual(current[H.PROBE_TARGET], H.probe_bytes())
        self.assertEqual(len(H.build_pins()), 474)
        self.assertEqual(H.P.UTIL.reconstruct_tree(H.build_pins()), H.BUILD_TREE)

    def test_original_parent_probe_prefix_is_preserved(self):
        raw = H.parent_probe_bytes()
        self.assertEqual(len(raw), 6941)
        self.assertEqual(H.P.sha(raw), H.PARENT_PROBE_SHA256)
        self.assertEqual(H.probe_bytes()[:len(raw)], raw)
        self.assertNotIn(b"TestCandidateSnapshotReturnedPatchLifetime", raw)
        self.assertIn(b"TestCandidateSnapshotAcquisitionError", H.probe_bytes())

    def test_probe_byte_substitution_refuses(self):
        read = H.P.read_regular
        def changed(path, limit):
            raw = read(path, limit)
            return raw + b"\n" if Path(path).name == H.PROBE else raw
        with mock.patch.object(H.P, "read_regular", side_effect=changed):
            with self.assertRaises(ValueError):
                H.extra_sources()

    def test_native_case_and_original_DB_commands_remain_distinct(self):
        plan = H.plan(Path("/selected-owned-snapshot"), "/selected/go")
        self.assertEqual(plan["source_blobs"], 474)
        self.assertEqual(plan["expected_native_unit_pass_results"], 73)
        self.assertEqual(len(plan["native_control_roots"]), 18)
        self.assertEqual(set(H.NATIVE_ROOTS) - set(H.H.NATIVE_ROOTS), set(H.SNAPSHOT_ROOTS))
        self.assertEqual(plan["snapshot_core_cases"], 12)
        self.assertEqual(plan["snapshot_environment"], {
            "SPV_SNAPSHOT_CASE_ROOT": "NEW_REGISTERED_SNAPSHOT_CASE_ROOT",
            "SPV_EXPECT_PATCH_SNAPSHOT_RELEASE": "true",
        })
        self.assertIn("candidate_patch_snapshot_lifetime", plan["native_test_argv"])
        self.assertNotIn("candidate_patch_snapshot_lifetime", plan["original_DB_test_argv"])
        self.assertEqual(plan["original_DB_root_count"], 22)
        self.assertEqual(plan["original_DB_root_tests"], list(H.DB_ROOTS))
        self.assertEqual(len(set(H.DB_ROOTS)), 22)
        for key in ("native_test_argv", "original_DB_test_argv"):
            self.assertEqual(plan[key][0], "/selected/go")
            self.assertIn("-mod=readonly", plan[key])
            self.assertIn("-race", plan[key])
            self.assertNotIn("-overlay", plan[key])

    def test_ordinary_entrypoint_probe_and_build_are_not_overwritten(self):
        current = H.plan(Path("/selected-owned-snapshot"), "go")
        parent = H.H.plan(Path("/selected-owned-snapshot"), "go")
        for key in ("probe", "build_argv", "binary", "run_argv_template", "cases", "registered_capture_files"):
            self.assertEqual(current[key], parent[key])
        self.assertEqual(current["snapshot_probe"], {"bytes": H.PROBE_BYTES, "sha256": H.PROBE_SHA256})
        self.assertNotEqual(current["snapshot_probe"], current["probe"])

    def test_preparation_keeps_execution_and_acceptance_unselected(self):
        plan = H.plan(Path("/selected-owned-snapshot"), "go")
        self.assertEqual(plan["minimum_free_floor_bytes"], 10 << 30)
        self.assertEqual(plan["consumer_result"], "REFUSED")
        for key in ("reference_backend_executed", "native_control_execution_selected", "accepted_header_binding",
                    "runtime_state_value_acceptance", "whole_window_atomicity_claimed", "new_dependency_transports_permitted",
                    "returned_version_DB_snapshot_ownership_changed", "permanent_leak_claimed", "production_resource_budgets_qualified"):
            self.assertIs(plan[key], False)
        self.assertIs(plan["snapshot_acquisition_error_diagnostic_changed"], True)

    def test_existing_destination_is_not_overwritten(self):
        with mock.patch.object(H.P, "private_destination", side_effect=ValueError("existing path")), \
             mock.patch.object(H.P.UTIL, "snapshot_source") as snapshot:
            with self.assertRaises(ValueError):
                H.prepare(Path("/selected-source"), Path("/selected-existing-workspace"), "go")
        snapshot.assert_not_called()

    def test_invalid_compiler_is_refused(self):
        for value in (None, "", "go\x00other"):
            with self.assertRaises(ValueError):
                H.plan(Path("/selected-owned-snapshot"), value)


if __name__ == "__main__":
    unittest.main()
