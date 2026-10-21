#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Source and resource controls for the finite cache read-error recipe."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("cache_read_prepare_controls", HERE / "prepare_cache_read_errors.py")
P = importlib.util.module_from_spec(spec)
spec.loader.exec_module(P)

class CacheReadPreparationControls(unittest.TestCase):
    def test_complete_baseline_and_candidate_build_trees(self):
        for variant, count in (("baseline", 471), ("candidate", 472)):
            pins = P.build_pins(variant)
            self.assertEqual(len(pins), count)
            self.assertEqual(P.P.UTIL.reconstruct_tree(pins), P.BUILD_TREES[variant])

    def test_only_initial_iterator_error_and_one_unit_source_change(self):
        _, _, before = P.selection("baseline")
        _, _, after = P.selection("candidate")
        self.assertEqual({name for name in set(before) & set(after) if before[name] != after[name]},
                         {"chain/cache/store.go"})
        self.assertEqual(set(after) - set(before), {P.UNIT_TARGET})

    def test_all_other_function_bytes_are_preserved(self):
        patch = json.loads(P.P.read_regular(HERE / P.PATCH, 32 << 10))
        insertion = "\t\tif err := iterator.Error(); err != nil {\n\t\t\treturn nil, err\n\t\t}\n"
        self.assertEqual(patch["after"].count(insertion), 1)
        self.assertEqual(patch["after"].replace(insertion, ""), patch["before"])

    def test_independent_fixture_and_complete_raw_image(self):
        raw = P.selected_fixture()
        self.assertEqual((len(raw), hashlib.sha256(raw).hexdigest()), (1588, P.FIXTURE_SHA256))
        image = P.M.expected_image(json.loads(raw))
        self.assertEqual(image["records"], 4)
        self.assertEqual(image["sha256"], "7b6cfee7dd05b8cd1192f13458e4871b47a07e851394537c52de5609bc85050f")

    def test_all_prior_and_new_native_roots_remain_selected(self):
        self.assertEqual(len(P.roots()), 41)
        self.assertEqual(len(P.new_roots()), 12)
        self.assertTrue(set(P.C.roots()) <= set(P.roots()))
        self.assertTrue({name for _, name in P.EXISTING_CACHE_ROOTS} <= set(P.roots()))

    def test_plan_keeps_resources_and_execution_scopes_separate(self):
        with tempfile.TemporaryDirectory() as root:
            for variant in P.VARIANTS:
                destination = Path(root) / variant
                plan = P.plan(destination, "selected-go", variant)
                self.assertFalse(destination.exists())
                self.assertEqual((plan["minimum_free_floor_bytes"], plan["expected_allocation_bytes"],
                                  plan["suggested_task_quota_bytes"]), (10 << 30, 2 << 30, 3 << 30))
                self.assertEqual((plan["ordinary_builds"], plan["ordinary_processes"],
                                  plan["expected_events"], plan["expected_queries"]), (1, 2, 29, 19))
                self.assertIs(plan["separate_units_include_selected_public_chain_regressions"], variant == "candidate")
                self.assertEqual(plan["consumer_result"], "REFUSED")
                for field in ("reference_backend_executed", "new_dependency_transports_permitted",
                              "nominal_identifier_is_verified_momentum", "account_block_execution_selected",
                              "concurrent_lifecycle_or_full_node_qualified", "cache_value_authentication",
                              "accepted_header_binding", "runtime_state_value_acceptance"):
                    self.assertIs(plan[field], False)

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

    def test_changed_probe_refused(self):
        with self.corrupt(P.PROBE), self.assertRaises(ValueError):
            P.build_pins()

    def test_changed_unit_refused(self):
        with self.corrupt(P.UNIT), self.assertRaises(ValueError):
            P.selection()

    def test_changed_patch_refused(self):
        with self.corrupt(P.PATCH), self.assertRaises(ValueError):
            P.selection()

    def test_changed_model_refused(self):
        with self.corrupt(P.MODEL), self.assertRaises(ValueError):
            P.selected_fixture()

    def test_existing_destination_is_not_adopted(self):
        with tempfile.TemporaryDirectory() as root, self.assertRaises((ValueError, FileExistsError)):
            P.prepare(root, root, "selected-go")

    def test_prior_projector_and_execution_recipe_stay_frozen(self):
        for name, digest in {
            "project_target_hex.py": "80624b66ea7f7930c2237bf04b08462e38efe76109084577680b67cde09b2a73",
            "run_target_hex.py": "3bf4f6078adba2520bcbf9b750961e9d09569d7a50235447f1812a625c7c5231",
        }.items():
            self.assertEqual(hashlib.sha256((HERE / name).read_bytes()).hexdigest(), digest)

if __name__ == "__main__":
    unittest.main(verbosity=2)
