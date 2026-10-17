#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Source/plan controls only; no node, compiler or network execution."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
selected = importlib.util.spec_from_file_location("recovery_successor_controls", HERE / "prepare_recovery_successor.py")
module = importlib.util.module_from_spec(selected)
selected.loader.exec_module(module)


class RecoverySuccessorPreparationControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = module.source_manifest()
        cls.patch = module.document(module.PATCH, module.PATCH_SHA256)
        cls.original = {name: row["replacements"][0]["before"].encode()
                        for name, row in cls.patch["files"].items()}

    def test_complete_successor_source_contract(self):
        self.assertEqual((self.manifest["blob_count"], self.manifest["logical_blob_bytes"]), (467, 7549463))
        self.assertEqual(module.UTIL.reconstruct_tree(self.manifest["files"]), module.TREE)
        self.assertEqual(self.manifest["files"]["chain/state_tree.go"]["git_blob"],
                         "4adee54cb7607957cfb7bdf519ae3242c2a71ac3")
        self.assertEqual(self.manifest["files"]["common/trie/nodestore.go"]["git_blob"],
                         "d5f5e7e57a3437060b2f20acc477933af1e34b0d")
        self.assertFalse(self.manifest["historical_source_and_records_rebound"])

    def test_patch_matches_complete_source_and_inverse(self):
        modified, _ = module.patch_files(self.original, self.manifest)
        self.assertEqual(set(modified), {"chain/state_tree.go", "common/trie/nodestore.go"})
        pins = copy.deepcopy(self.manifest["files"])
        for name, raw in modified.items():
            row = self.patch["files"][name]
            self.assertEqual(module.sha(raw), row["after_sha256"])
            self.assertEqual(module.UTIL.git_hash("blob", raw), row["after_git_blob"])
            pins[name].update(sha256=module.sha(raw), git_blob=module.UTIL.git_hash("blob", raw), bytes=len(raw))
            self.assertEqual(raw.decode().replace(row["replacements"][0]["after"],
                                                 row["replacements"][0]["before"], 1).encode(), self.original[name])
        self.assertEqual(module.UTIL.reconstruct_tree(pins), "249f3e33e54263efc7c3cad16c02a4784df74040")

    def test_historical_source_and_patch_bytes_remain_pinned(self):
        self.assertEqual(module.sha((HERE / "node-recovery-source-pins.json").read_bytes()),
                         "12ec9f524b1a4c3ba45344fa619f433df2b11a63eaf523ea695d9ca4ba84f460")
        self.assertEqual(module.sha((HERE / "hash-bound-versions-patch.json").read_bytes()),
                         "a1a00190d81fcd5eed0326570d95b29e8869d82edd2c5a0804bb3af440e506ef")

    def test_old_and_missing_source_inputs_refused(self):
        bad = dict(self.original)
        bad["chain/state_tree.go"] += b"\n// changed source\n"
        with self.assertRaises(ValueError):
            module.patch_files(bad, self.manifest)
        with self.assertRaises(ValueError):
            module.patch_files({}, self.manifest)

    def test_patch_scope_types_and_trust_escalations_refused(self):
        cases = (("format_version", True), ("base_blob_count", True), ("base_revision", "0" * 40),
                 ("base_tree", "0" * 40), ("disk_format_after", 2),
                 ("baseline_already_refuses_incompatible_databases", False),
                 ("historical_patch_or_records_rebound", True), ("experimental_only", False),
                 ("automatic_existing_database_migration", True), ("automatic_incompatible_database_wipe", True),
                 ("SMT_root_and_proof_profile_changed", True), ("node_client_protocol_profile_agreed", True),
                 ("accepted_v3_header_binding_qualified", True), ("production_qualified", True))
        for key, value in cases:
            with self.subTest(field=key):
                bad = copy.deepcopy(self.patch)
                bad[key] = value
                with mock.patch.object(module, "document", return_value=bad), self.assertRaises(ValueError):
                    module.patch_files(self.original, self.manifest)

    def test_patch_byte_and_inverse_substitution_refused(self):
        for mode in ("before", "after", "after-length", "extra-file", "extra-replacement-field"):
            with self.subTest(mode=mode):
                bad = copy.deepcopy(self.patch)
                row = bad["files"]["chain/state_tree.go"]
                if mode == "before":
                    row["replacements"][0]["before"] += "PRIVATE"
                elif mode == "after":
                    row["replacements"][0]["after"] += "PRIVATE"
                elif mode == "after-length":
                    row["after_bytes"] = True
                elif mode == "extra-file":
                    bad["files"]["go.mod"] = copy.deepcopy(row)
                else:
                    row["replacements"][0]["PRIVATE_FIELD"] = "PRIVATE_VALUE"
                with mock.patch.object(module, "document", return_value=bad), self.assertRaises(ValueError):
                    module.patch_files(self.original, self.manifest)

    def test_manifest_wrong_revision_types_and_inventory_refused(self):
        for key, value in (("revision", "0" * 40), ("tree", "0" * 40), ("blob_count", True),
                           ("logical_blob_bytes", True), ("historical_source_and_records_rebound", True)):
            with self.subTest(field=key):
                bad = copy.deepcopy(self.manifest)
                bad[key] = value
                with mock.patch.object(module, "document", return_value=bad), self.assertRaises(ValueError):
                    module.source_manifest()
        bad = copy.deepcopy(self.manifest)
        bad["files"].pop("go.mod")
        with mock.patch.object(module, "document", return_value=bad), self.assertRaises(ValueError):
            module.source_manifest()

    def test_duplicate_metadata_and_boolean_integer_refused(self):
        with self.assertRaises(ValueError):
            json.loads('{"version":1,"version":1}', object_pairs_hook=module.pairs)
        with self.assertRaises(ValueError):
            module.exact({"version": True}, {"version": 1})
        with self.assertRaises(ValueError):
            module.exact({"extra": 1}, {})

    def test_existing_workspace_refuses_before_source_read(self):
        with tempfile.TemporaryDirectory(prefix="successor-owned-control-") as temporary:
            marker = Path(temporary) / "owned-marker"
            marker.write_bytes(b"preserved")
            with mock.patch.object(module, "source_manifest", side_effect=AssertionError("source must not be read")):
                with self.assertRaises(ValueError):
                    module.prepare(Path(temporary) / "PRIVATE_SOURCE", temporary, "baseline", "selected-go")
            self.assertEqual(marker.read_bytes(), b"preserved")
            self.assertEqual(sorted(path.name for path in Path(temporary).iterdir()), ["owned-marker"])

    def test_source_owned_probe_changes_only_explicit_bindings(self):
        old = (HERE / "hash_bound_versions_probe_test.go").read_bytes()
        new = (HERE / module.PROBE).read_bytes()
        changes = (
            (b"//go:build candidate_hash_bound_versions\n", b"//go:build candidate_hash_bound_versions_successor\n"),
            (b'os.Getenv("ZENON_HASH_BOUND_VARIANT")', b'os.Getenv("ZENON_HASH_BOUND_SUCCESSOR_VARIANT")'),
            (b'"kind": "current-node-hash-bound-version-research"', b'"kind": "successor-node-hash-bound-version-research"'),
            (b'"source_revision": "33d7d1ee1b6a915c40aea196e2a10f1e893d171f"',
             b'"source_revision": "9c71ae82fc983e16f914ae085d4034030c8ebe3b"'),
        )
        for before, after in changes:
            self.assertEqual(old.count(before), 1)
            old = old.replace(before, after, 1)
        self.assertEqual(old, new)

    def test_returned_plan_binds_source_modules_overlay_and_readonly_commands(self):
        workspace = Path("/selected-owned-workspace")
        probe = (HERE / module.PROBE).read_bytes()
        # Explicit synthetic module bytes test plan formatting only. Real source
        # staging is a separate complete-snapshot integration, never inferred here.
        value = module.plan(workspace, "baseline", "/selected/go", self.manifest["files"],
                            probe, b"{}\n", b"synthetic module\n", b"synthetic sums\n")
        self.assertEqual(value["selected_node_tree_without_probe"], module.TREE)
        self.assertEqual(value["node_blob_count"], 467)
        self.assertIn("-mod=readonly", value["build_argv"])
        self.assertEqual(value["required_run_environment"], {"ZENON_HASH_BOUND_SUCCESSOR_VARIANT": "baseline"})
        self.assertEqual(len(value["upstream_tests_excluded_by_explicit_compiler_overlay"]), 8)
        self.assertFalse(value["reference_execution_performed"])
        self.assertFalse(value["network_acquisition_performed"])
        self.assertFalse(value["production_qualified"])
        changed = copy.deepcopy(value)
        changed["build_argv"][-1] = "./..."
        with self.assertRaises(ValueError):
            module.exact(changed, value)


if __name__ == "__main__":
    unittest.main()
