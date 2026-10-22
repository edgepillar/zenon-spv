#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Source, input, lifecycle-selection and resource controls; no backend launch."""
import hashlib
import importlib.util
import json
import re
from pathlib import Path
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("core_stop_error_prepare_controls", HERE / "prepare_core_stop_errors.py")
P = importlib.util.module_from_spec(spec)
spec.loader.exec_module(P)

class CoreStopErrorPreparationControls(unittest.TestCase):
    def test_complete_both_runtime_and_build_trees(self):
        for variant, tree in (("baseline", P.PARENT_TREE), ("candidate", P.CANDIDATE_TREE)):
            _, _, pins = P.selection(variant)
            self.assertEqual((len(pins), P.P.UTIL.reconstruct_tree(pins)), (471, tree))
            built = P.build_pins(variant)
            self.assertEqual((len(built), P.P.UTIL.reconstruct_tree(built)), (480, P.BUILD_TREES[variant]))

    def test_only_core_Stop_error_cleanup_changes_in_runtime(self):
        before = P.selection("baseline")[2]
        after = P.selection("candidate")[2]
        self.assertEqual(set(before), set(after))
        self.assertEqual({name for name in before if before[name] != after[name]}, {"zenon/zenon.go"})

    def test_every_other_runtime_byte_is_preserved(self):
        patch = json.loads((HERE / P.PATCH).read_bytes())
        def outside_stop(raw):
            raw = raw.replace('\t"errors"\n\n', "")
            return re.sub(r"(?ms)^func \(z \*zenon\) Stop\(\) error \{.*?^\}", "SELECTED_STOP", raw)
        self.assertEqual(outside_stop(patch["before"]), outside_stop(patch["after"]))
        after = patch["after"].split("func (z *zenon) Stop() error {", 1)[1].split("\n}", 1)[0]
        self.assertIn("return errors.Join(", after)
        calls = re.findall(r"z\.(\w+)\.(Stop|Close)\(\)", after)
        self.assertEqual(calls, [("protocol", "Stop"), ("pillar", "Stop"), ("subscribe", "Stop"),
                                 ("evPrinter", "Stop"), ("consensus", "Stop"), ("chain", "Stop"), ("levelDb", "Close")])

    def test_all_prior_roots_and_three_new_roots_remain(self):
        self.assertEqual((len(P.roots()), len(P.new_roots())), (53, 3))
        self.assertTrue(set(P.BASE.roots()) <= set(P.roots()))

    def test_same_tagged_instrumentation_is_used_for_both_variants(self):
        before, after = P.build_pins("baseline"), P.build_pins("candidate")
        self.assertEqual({name for name in before if before[name] != after[name]}, {"zenon/zenon.go"})
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
        state = P.M.BASE.fixture()["states"]["A1"]
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
                self.assertFalse(result["node_entrypoint_execution_selected"])
                self.assertEqual(result["consumer_result"], "REFUSED")

    def test_case_order_requires_three_fresh_owned_roots(self):
        result = P.plan("unused-workspace", "selected-go")
        self.assertEqual(result["cases"], [{"case": mode, "requires_empty_root": True} for mode in P.MODES])
        self.assertFalse(result["core_Start_selected"])
        self.assertTrue(result["controlled_handle_close_not_hardware_failure"])

    def test_resource_floor_is_separate_from_expected_allocation(self):
        result = P.plan("unused-workspace", "selected-go")
        self.assertEqual((result["minimum_free_floor_bytes"], result["expected_allocation_bytes"],
                          result["suggested_task_quota_bytes"]), (10 << 30, 3 << 30, 4 << 30))

    def test_core_services_and_unqualified_scopes_are_explicit(self):
        result = P.plan("unused-workspace", "selected-go")
        for key in ("core_Start_selected", "wallet_or_peer_server_or_RPC_listener_selected",
                    "new_dependency_transports_permitted", "node_entrypoint_execution_selected",
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

    def test_native_logging_fixture_changes_only_the_tagged_test_view(self):
        ordinary = P.build_pins("candidate")
        native = P.build_pins("candidate", True)
        self.assertEqual({name for name in native if name not in ordinary}, {P.QUIET_EXTRA[1]})
        self.assertTrue(P.QUIET_EXTRA[1].endswith("_test.go"))
        self.assertEqual({name: native[name] for name in ordinary}, ordinary)
        self.assertEqual((len(native), P.P.UTIL.reconstruct_tree(native)), (481, P.NATIVE_TREE))
        planned = P.plan("unused-workspace", "selected-go", "candidate", True)
        self.assertTrue(planned["native_tests"])
        self.assertFalse(planned["native_test_preparation_required"])
        self.assertEqual(len(planned["native_test_roots"]), 53)
        self.assertEqual(planned["expected_native_pass_results"], 62)

    def test_invalid_native_source_view_is_refused(self):
        for value in (None, 0, 1, "", "yes", []):
            with self.subTest(value=repr(value)), self.assertRaises(ValueError):
                P.build_pins("candidate", value)
        with self.assertRaises(ValueError):
            P.build_pins("baseline", True)

    def test_changed_test_logging_fixture_is_refused(self):
        with self.corrupt(P.QUIET_EXTRA[0]), self.assertRaises(ValueError):
            P.build_pins("candidate", True)

    def test_node_entrypoint_is_only_a_build_recipe(self):
        result = P.plan("unused-workspace", "selected-go")
        argv = result["ordinary_node_entrypoint_build_argv"]
        self.assertEqual(argv[:2], ["selected-go", "build"])
        self.assertEqual(argv[-1], "./cmd/znnd")
        self.assertFalse(result["node_entrypoint_execution_selected"])
        self.assertEqual(result["native_test_argv"], [])

if __name__ == "__main__":
    unittest.main(verbosity=2)
