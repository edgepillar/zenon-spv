#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Source, input, lifecycle-selection and resource controls; no backend launch."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("worker_stop_prepare_controls", HERE / "prepare_zenon_worker_stop.py")
P = importlib.util.module_from_spec(spec)
spec.loader.exec_module(P)

class WorkerStopPreparationControls(unittest.TestCase):
    def test_complete_both_runtime_and_build_trees(self):
        for variant, tree in (("baseline", P.PARENT_TREE), ("candidate", P.CANDIDATE_TREE)):
            _, _, pins = P.selection(variant)
            self.assertEqual((len(pins), P.P.UTIL.reconstruct_tree(pins)), (471, tree))
            built = P.build_pins(variant)
            self.assertEqual((len(built), P.P.UTIL.reconstruct_tree(built)), (475, P.BUILD_TREES[variant]))

    def test_only_worker_constructor_changes_in_runtime(self):
        before = P.selection("baseline")[2]
        after = P.selection("candidate")[2]
        self.assertEqual(set(before), set(after))
        self.assertEqual({name for name in before if before[name] != after[name]}, {"pillar/worker.go"})

    def test_every_other_runtime_byte_is_preserved(self):
        patch = json.loads((HERE / P.PATCH).read_bytes())
        insertion = "\t\tclosed:      make(chan struct{}),\n"
        self.assertEqual(patch["after"].count(insertion), 1)
        self.assertEqual(patch["after"].replace(insertion, ""), patch["before"])

    def test_all_prior_roots_and_nine_new_roots_remain(self):
        self.assertEqual((len(P.roots()), len(P.new_roots())), (50, 9))
        self.assertTrue(set(P.BASE.roots()) <= set(P.roots()))

    def test_same_tagged_instrumentation_is_used_for_both_variants(self):
        before, after = P.build_pins("baseline"), P.build_pins("candidate")
        self.assertEqual({name for name in before if before[name] != after[name]}, {"pillar/worker.go"})
        for name, target, _, _ in P.EXTRAS:
            self.assertIn(target, before)
            self.assertTrue((HERE / name).read_bytes().startswith(b"//go:build " + P.TAG.encode() + b"\n"))

    def test_child_selection_has_no_expected_root_value_or_proof(self):
        raw = P.selected_input()
        self.assertEqual((len(raw), hashlib.sha256(raw).hexdigest()), (375, P.M.SELECTION_SHA256))
        value = json.loads(raw)
        self.assertEqual(set(value), {"schema", "raw_key", "genesis", "genesis_patch_bytes", "genesis_patch_sha256"})
        self.assertNotIn("root", value)
        self.assertNotIn("value", value)
        self.assertNotIn("proof", value)

    def test_independent_genesis_witness_remains_source_selected(self):
        state = P.M.fixture()["states"]["A1"]
        self.assertEqual(state["root"], "864dbad1c3ef38e2c867950390364878c58238183d01b8bf97ef73e2efa4383d")
        self.assertEqual(state["value"], (100000).to_bytes(32, "big").hex())
        self.assertEqual(state["identifier"]["height"], 1)

    def test_plan_does_not_create_workspace_or_launch_backend(self):
        with tempfile.TemporaryDirectory() as root:
            workspace = Path(root) / "not-created"
            for variant in P.VARIANTS:
                result = P.plan(workspace, "selected-go", variant)
                self.assertFalse(workspace.exists())
                self.assertFalse(result["reference_backend_executed"])
                self.assertEqual(result["expected_API_panics"], 2 if variant == "baseline" else 0)
                self.assertEqual(result["consumer_result"], "REFUSED")

    def test_case_order_requires_two_fresh_roots_and_one_reopen(self):
        result = P.plan("unused-workspace", "selected-go")
        self.assertEqual(result["cases"], [
            {"case": "construct-stop", "root": "constructed", "requires_empty_root": True},
            {"case": "init-stop", "root": "initialized", "requires_empty_root": True},
            {"case": "reopen-start-stop", "root": "initialized", "requires_empty_root": False}])
        self.assertTrue(result["reopen_uses_same_closed_initialized_root"])

    def test_resource_floor_is_separate_from_expected_allocation(self):
        result = P.plan("unused-workspace", "selected-go")
        self.assertEqual((result["minimum_free_floor_bytes"], result["expected_allocation_bytes"],
                          result["suggested_task_quota_bytes"]), (10 << 30, 3 << 30, 4 << 30))

    def test_core_services_and_unqualified_scopes_are_explicit(self):
        result = P.plan("unused-workspace", "selected-go")
        self.assertTrue(result["keyless_internal_services_start_in_reopen_control"])
        for key in ("node_wrapper_or_wallet_or_peer_server_selected", "new_dependency_transports_permitted",
                    "repeated_Stop_or_concurrent_lifecycle_qualified", "full_node_or_network_qualified",
                    "accepted_header_binding", "production_state_value_accepted"):
            self.assertIs(result[key], False)

    def test_invalid_variant_values_refused(self):
        for value in (None, True, 1, "", "other", []):
            with self.subTest(value=repr(value)), self.assertRaises(ValueError):
                P.selection(value)

    def test_invalid_compiler_values_refused(self):
        for value in (None, True, 1, "", "go\0other"):
            with self.subTest(value=repr(value)), self.assertRaises(ValueError):
                P.plan("unused-workspace", value)

    def corrupt(self, selected):
        original = P.P.read_regular
        def reader(path, limit):
            raw = original(path, limit)
            if Path(path) == HERE / selected:
                return raw[:-1] + bytes([raw[-1] ^ 1])
            return raw
        return mock.patch.object(P.P, "read_regular", side_effect=reader)

    def test_changed_instrumentation_is_refused(self):
        for name, _, _, _ in P.EXTRAS:
            with self.subTest(name=name), self.corrupt(name), self.assertRaises(ValueError):
                P.build_pins()

    def test_changed_patch_is_refused(self):
        with self.corrupt(P.PATCH), self.assertRaises(ValueError):
            P.selection()

    def test_changed_model_is_refused(self):
        with self.corrupt(P.MODEL), self.assertRaises(ValueError):
            P.selected_input()

    def test_existing_destination_is_not_adopted(self):
        with tempfile.TemporaryDirectory() as root, self.assertRaises((ValueError, FileExistsError)):
            P.prepare(root, root, "selected-go")

if __name__ == "__main__":
    unittest.main(verbosity=2)
