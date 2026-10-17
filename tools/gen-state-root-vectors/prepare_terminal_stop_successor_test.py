#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Successor patch, instrumentation and plan controls; execute no node/build."""
import copy
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("successor_terminal_controls", HERE / "prepare_terminal_stop_successor.py")
C = importlib.util.module_from_spec(spec)
spec.loader.exec_module(C)


class SuccessorTerminalPreparationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest, cls.modified, cls.parent_pins = C.parent_selection()
        cls.original = cls.modified[C.STATE]
        cls.patch = C.P.document(C.PATCH, C.PATCH_SHA256)

    def patched_document(self, changed):
        read = C.P.document
        return mock.patch.object(C.P, "document", side_effect=lambda name, digest:
                                 changed if name == C.PATCH else read(name, digest))

    def test_complete_parent_and_exact_forward_inverse(self):
        self.assertEqual(len(self.manifest["files"]), 467)
        self.assertEqual(C.P.UTIL.reconstruct_tree(self.parent_pins), C.P.MODIFIED_TREE)
        after = C.patch_state(self.original)
        row = self.patch["replacements"][0]
        self.assertEqual(after.decode().replace(row["after"], row["before"], 1).encode(), self.original)
        pins = copy.deepcopy(self.parent_pins)
        pins[C.STATE].update(git_blob=C.P.UTIL.git_hash("blob", after))
        self.assertEqual(C.P.UTIL.reconstruct_tree(pins), C.MODIFIED_TREE)
        self.assertNotEqual(C.MODIFIED_TREE, C.P.MODIFIED_TREE)

    def test_historical_source_or_changed_parent_refused(self):
        old = C.P.document("lifecycle-stop-patch.json",
                           "2778017b5de86be222956a600dcb8bed49dd5fd543566f0230e6c2a042a8a165")
        for raw in (b"", self.original + b"\n", old["replacements"][0]["before"].encode()):
            with self.subTest(size=len(raw)), self.assertRaises(ValueError):
                C.patch_state(raw)
        self.assertEqual(C.P.sha((HERE / "check_lifecycle_stop.py").read_bytes()),
                         "24cf8d6c093cb145314337c62577457fbcc5451e4632d88b2e5a791bc23ed354")

    def test_patch_scope_types_source_and_trust_escalations_refused(self):
        cases = (("format_version", True), ("base_blob_count", True), ("base_revision", "00" * 20),
                 ("base_tree", "00" * 20), ("hash_identity_parent_tree", "00" * 20),
                 ("hash_identity_patch_sha256", "00" * 32), ("modified_node_tree_without_probes", "00" * 20),
                 ("experimental_only", False), ("disk_format_changed", True), ("SMT_profile_changed", True),
                 ("automatic_migration_added", True), ("network_activation_authenticated", True),
                 ("state_value_acceptance_enabled", True), ("historical_source_records_rebound", True),
                 ("production_qualified", True))
        for key, value in cases:
            with self.subTest(field=key):
                changed = copy.deepcopy(self.patch)
                changed[key] = value
                with self.patched_document(changed), self.assertRaises(ValueError):
                    C.patch_state(self.original)

    def test_complete_byte_and_unknown_field_substitution_refused(self):
        for mode in ("before", "after", "after-length", "replacement-field", "extra-field", "extra-replacement"):
            with self.subTest(mode=mode):
                changed = copy.deepcopy(self.patch)
                row = changed["replacements"][0]
                if mode in ("before", "after"):
                    row[mode] += "PRIVATE"
                elif mode == "after-length":
                    changed["after_bytes"] = True
                elif mode == "replacement-field":
                    row["PRIVATE_FIELD"] = "PRIVATE"
                elif mode == "extra-field":
                    changed["PRIVATE_FIELD"] = True
                else:
                    changed["replacements"].append(copy.deepcopy(row))
                with self.patched_document(changed), self.assertRaises(ValueError):
                    C.patch_state(self.original)

    def test_checkpoints_remain_exactly_three_reversible_test_calls(self):
        for raw in (self.original, C.patch_state(self.original)):
            with self.subTest(size=len(raw)):
                selected = C.instrument(raw)
                for before, after in reversed(C.HOOKS):
                    self.assertEqual(selected.count(after.encode()), 1)
                    selected = selected.replace(after.encode(), before.encode())
                self.assertEqual(selected, raw)
                self.assertEqual(C.instrument(raw).count(b"lifecycleCheckpoint("), 3)
        with self.assertRaises(ValueError):
            C.instrument(self.original + C.HOOKS[0][0].encode())
        with self.assertRaises(ValueError):
            C.instrument(self.original.replace(C.HOOKS[1][0].encode(), b"PRIVATE"))

    def test_probe_changes_only_four_explicit_successor_bindings(self):
        raw = (HERE / "lifecycle_stop_probe_test.go").read_bytes()
        changes = (
            (b"//go:build candidate_state_tree_stop\n", b"//go:build candidate_state_tree_stop_successor\n"),
            (b'os.Getenv("ZENON_STOP_VARIANT")', b'os.Getenv("ZENON_STOP_SUCCESSOR_VARIANT")'),
            (b'"kind": "current-node-stop-lifecycle-observations"', b'"kind": "successor-node-stop-lifecycle-observations"'),
            (b'"node_revision": "33d7d1ee1b6a915c40aea196e2a10f1e893d171f"',
             b'"node_revision": "9c71ae82fc983e16f914ae085d4034030c8ebe3b"'),
        )
        for before, after in changes:
            self.assertEqual(raw.count(before), 1)
            raw = raw.replace(before, after, 1)
        self.assertEqual(raw, (HERE / C.PROBE).read_bytes())

    def test_selected_plan_keeps_parent_modules_readonly_race_and_case_selection(self):
        workspace = Path("/selected-owned-terminal-workspace")
        go = "/selected/go"
        parent_probe = (HERE / C.P.PROBE).read_bytes()
        probe = (HERE / C.PROBE).read_bytes()
        # Synthetic module and overlay bytes exercise formatting only. Complete
        # source staging and real dependency selection require a separate run.
        parent = C.P.plan(workspace, "hash-bound", go, self.parent_pins, parent_probe,
                          b"{}\n", b"synthetic module\n", b"synthetic sums\n")
        for variant in C.VARIANTS:
            with self.subTest(variant=variant):
                plan = C.expected_plan(workspace, variant, go, parent, self.original, probe)
                self.assertEqual(plan["node_source_blobs"], 467)
                self.assertEqual(plan["module_sha256"], parent["module_sha256"])
                self.assertEqual(plan["sum_sha256"], parent["sum_sha256"])
                self.assertEqual(plan["original_upstream_tests_excluded_by_explicit_overlay"], list(C.P.UPSTREAM_TESTS))
                self.assertIn("-race", plan["build_argv"])
                self.assertIn("-mod=readonly", plan["build_argv"])
                self.assertIn("-p=1", plan["build_argv"])
                self.assertEqual(plan["build_argv"][plan["build_argv"].index("-tags") + 1], C.P.TAG + "," + C.TAG)
                self.assertEqual(plan["run_argv"][-1], "-test.run=^TestCandidateStateTreeStop$")
                self.assertEqual(plan["required_run_environment"], {"ZENON_STOP_SUCCESSOR_VARIANT": variant})
                for field in ("network_acquisition_performed", "reference_execution_performed",
                              "existing_database_adopted", "historical_source_records_rebound", "profile_agreed", "production_qualified"):
                    self.assertIs(plan[field], False)
        changed = copy.deepcopy(parent)
        changed["build_argv"][0] = "PRIVATE_GO"
        with self.assertRaises(ValueError):
            C.expected_plan(workspace, "hash-bound", go, changed, self.original, probe)

    def test_existing_destination_is_preserved_before_source_access(self):
        with tempfile.TemporaryDirectory(prefix="terminal-successor-owned-") as directory:
            marker = Path(directory) / "owned-marker"
            marker.write_bytes(b"preserved")
            with mock.patch.object(C.P, "prepare", side_effect=AssertionError("parent must not run")), self.assertRaises(ValueError):
                C.prepare(Path(directory) / "PRIVATE_SOURCE", directory, "hash-bound", "selected-go")
            self.assertEqual(marker.read_bytes(), b"preserved")
            self.assertEqual([p.name for p in Path(directory).iterdir()], ["owned-marker"])

    def test_invalid_variant_or_go_refused_before_workspace_access(self):
        for variant, go in (("baseline", "go"), ("hash-bound", ""), ("monotonic-stop", None)):
            with self.subTest(variant=variant, go=go), mock.patch.object(C.P, "private_destination", side_effect=AssertionError("workspace must not be read")):
                with self.assertRaises(ValueError):
                    C.prepare("PRIVATE_SOURCE", "PRIVATE_WORKSPACE", variant, go)


if __name__ == "__main__":
    unittest.main()
