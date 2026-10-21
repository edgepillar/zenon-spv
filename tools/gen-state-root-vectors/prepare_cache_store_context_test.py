#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Check immutable source selection and bounded reproduction recipes."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("cache_context_preparation_controls", HERE / "prepare_cache_store_context.py")
P = importlib.util.module_from_spec(spec)
spec.loader.exec_module(P)

class CacheContextPreparationControls(unittest.TestCase):
    def test_baseline_and_candidate_complete_source_trees(self):
        baseline = P.build_pins("baseline")
        candidate = P.build_pins("candidate")
        self.assertEqual((len(baseline), len(candidate)), (468, 471))
        for variant, pins in (("baseline", baseline), ("candidate", candidate)):
            self.assertEqual(P.P.UTIL.reconstruct_tree(pins), P.BUILD_TREES[variant])

    def test_only_runtime_lookup_and_three_unit_sources_change(self):
        _, _, baseline = P.selection("baseline")
        _, changed, candidate = P.selection("candidate")
        common = set(baseline) & set(candidate)
        self.assertEqual({name for name in common if baseline[name] != candidate[name]}, {"chain/chain.go"})
        self.assertEqual(len(set(candidate) - set(baseline)), 3)
        self.assertTrue(all(name.endswith("_test.go") for name in set(candidate) - set(baseline)))
        self.assertEqual(hashlib.sha256(changed["chain/chain.go"]).hexdigest(),
                         "48a3615f079c14a1b965b7f9f7c5213e80e6c11cdea11e6e3bd364adaea34d54")

    def test_all_previous_chain_function_bytes_remain(self):
        raw = P.P.read_regular(HERE / P.PATCH, 32 << 10)
        patch = json.loads(raw)
        before, after = patch["before"], patch["after"]
        marker = "// GetCacheStore resolves the complete identifier in the current ledger before\n"
        start = after.index(marker)
        end = after.index("func (c *chain) AcquireInsert(", start)
        self.assertEqual(after[:start] + after[end:], before)

    def test_original_independent_fixture_remains_exact(self):
        raw = P.selected_fixture()
        self.assertEqual((len(raw), hashlib.sha256(raw).hexdigest()), (13485, P.R.FIXTURE_SHA256))
        self.assertEqual(raw, P.R.selected_fixture())

    def test_candidate_retains_the_complete_unit_inventory(self):
        self.assertEqual(len(P.roots()), 23)
        self.assertTrue(set(P.N.ROOTS) <= set(P.roots()))
        self.assertEqual(len([name for name in P.roots() if name.startswith("TestCacheContext_")]), 12)

    def test_plan_keeps_resource_and_authority_boundaries(self):
        with tempfile.TemporaryDirectory() as root:
            for variant, count in (("baseline", 468), ("candidate", 471)):
                path = Path(root) / variant
                plan = P.plan(path, "selected-go", variant)
                self.assertFalse(path.exists())
                self.assertEqual(plan["source_blobs"], count)
                self.assertEqual(plan["minimum_free_floor_bytes"], 10 << 30)
                self.assertEqual(plan["expected_allocation_bytes"], 2 << 30)
                self.assertEqual(plan["suggested_task_quota_bytes"], 3 << 30)
                self.assertEqual((plan["ordinary_builds"], plan["ordinary_processes"], plan["expected_queries"]), (1, 2, 8))
                self.assertEqual(plan["consumer_result"], "REFUSED")
                for key in ("reference_backend_executed", "new_dependency_transports_permitted", "new_account_blocks_added",
                            "concurrent_history_changes_or_full_node_qualified", "cache_value_correctness_qualified",
                            "accepted_header_binding", "runtime_state_value_acceptance"):
                    self.assertIs(plan[key], False)

    def test_bad_variants_are_refused_before_source_work(self):
        for variant in (None, True, 1, "", "other", []):
            with self.subTest(variant=repr(variant)), self.assertRaises(ValueError):
                P.selection(variant)

    def test_bad_compiler_values_are_refused(self):
        for go in (None, True, 1, "", "go\0other"):
            with self.subTest(go=repr(go)), self.assertRaises(ValueError):
                P.plan("plan-only", go)

    def corrupt(self, selected):
        original = P.P.read_regular
        def reader(path, limit):
            raw = original(path, limit)
            if Path(path) == HERE / selected:
                return raw[:-1] + bytes([raw[-1] ^ 1])
            return raw
        return mock.patch.object(P.P, "read_regular", side_effect=reader)

    def test_changed_probe_is_refused(self):
        with self.corrupt(P.PROBE), self.assertRaises(ValueError):
            P.build_pins("candidate")

    def test_changed_unit_source_is_refused(self):
        with self.corrupt(P.UNIT), self.assertRaises(ValueError):
            P.selection("candidate")

    def test_changed_patch_is_refused(self):
        with self.corrupt(P.PATCH), self.assertRaises(ValueError):
            P.selection("candidate")

    def test_original_recipe_and_optimizer_inputs_stay_frozen(self):
        pins = {"run_target_hex.py": "3bf4f6078adba2520bcbf9b750961e9d09569d7a50235447f1812a625c7c5231",
                "project_target_hex.py": "80624b66ea7f7930c2237bf04b08462e38efe76109084577680b67cde09b2a73"}
        for name, digest in pins.items():
            self.assertEqual(hashlib.sha256((HERE / name).read_bytes()).hexdigest(), digest)

if __name__ == "__main__":
    unittest.main(verbosity=2)
