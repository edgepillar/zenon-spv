#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Source, patch inverse and fresh-workspace controls; no reference backend."""
import copy
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("public_chain_preparation_controls", HERE / "prepare_public_chain_lifecycle_successor.py")
C = importlib.util.module_from_spec(spec)
spec.loader.exec_module(C)


class PublicChainPreparationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.descriptor = C.P.document(C.PATCH, C.PATCH_SHA256)
        cls.before = cls.descriptor["replacements"][0]["before"].encode()

    def test_full_parent_and_candidate_trees(self):
        for variant, tree in zip(C.VARIANTS, (C.R.MODIFIED_TREE, C.MODIFIED_TREE)):
            manifest, modified, pins = C.selection(variant)
            self.assertEqual((len(manifest["files"]), len(pins)), (467, 467))
            self.assertEqual(C.P.UTIL.reconstruct_tree(pins), tree)
            self.assertEqual(pins["go.mod"], manifest["files"]["go.mod"])
            self.assertEqual(pins["go.sum"], manifest["files"]["go.sum"])
            self.assertNotIn(b"lifecycleCheckpoint(", modified[C.R.T.STATE])
        self.assertNotEqual(C.R.MODIFIED_TREE, C.MODIFIED_TREE)

    def test_exact_file_inverse_and_outer_guards(self):
        after = C.patch_chain(self.before)
        row = self.descriptor["replacements"][0]
        self.assertEqual(after.replace(row["after"].encode(), row["before"].encode(), 1), self.before)
        self.assertEqual((len(after), C.P.sha(after)), (5532, C.AFTER))
        self.assertEqual(after.count(b'errors.New("chain instance is stopped")'), 2)
        for name in (b"Init", b"Start", b"Stop"):
            start = after.index(b"func (c *chain) " + name + b"() error {")
            end = after.index(b"\n}", start)
            self.assertLess(after.index(b"c.lifecycle.Lock()", start), end)
            self.assertLess(after.index(b"if c.stopped", start), end)
        init = after[after.index(b"func (c *chain) Init() error {"):]
        self.assertLess(init.index(b"if c.stopped"), init.index(b"c.GetFrontierMomentumStore()"))

    def test_unselected_file_bytes_refused(self):
        for raw in (b"", self.before + b"\n", self.before.replace(b"func (c *chain) Init", b"func (c *chain) Lost")):
            with self.assertRaises(ValueError):
                C.patch_chain(raw)

    def test_false_acceptance_and_source_pin_drift_refused(self):
        for name, replacement in (("experimental_only", False), ("SMT_profile_changed", True),
                                  ("upstream_mutated", True), ("disk_format_changed", True),
                                  ("accepted_header_or_consumer_acceptance_changed", True),
                                  ("format_version", True), ("before_sha256", "0" * 64),
                                  ("runtime_parent_tree", C.P.TREE), ("after_git_blob", "0" * 40)):
            changed = copy.deepcopy(self.descriptor)
            changed[name] = replacement
            with self.subTest(name=name), mock.patch.object(C.P, "document", return_value=changed):
                with self.assertRaises(ValueError):
                    C.patch_chain(self.before)

    def test_unbound_descriptor_fields_or_duplicate_replacements_refused(self):
        for mutate in (lambda d: d.update(production_qualified=True),
                       lambda d: d["replacements"].append(copy.deepcopy(d["replacements"][0])),
                       lambda d: d["replacements"][0].update(before="incorrect parent"),
                       lambda d: d["replacements"][0].update(after=d["replacements"][0]["after"] + "\n")):
            changed = copy.deepcopy(self.descriptor)
            mutate(changed)
            with mock.patch.object(C.P, "document", return_value=changed):
                with self.assertRaises(ValueError):
                    C.patch_chain(self.before)

    def test_ordinary_command_has_no_tests_overlays_or_race_flag(self):
        for variant in C.VARIANTS:
            plan = C.plan(Path("/selected-owned-public-chain"), variant, "/selected/go")
            self.assertEqual(plan["build_argv"][:5], ["/selected/go", "build", "-mod=readonly", "-trimpath", "-buildvcs=false"])
            self.assertEqual(plan["build_argv"][-1], "./cmd/candidate-public-chain-lifecycle")
            self.assertEqual(plan["cases"], list(C.CASES))
            self.assertEqual(plan["minimum_free_floor_bytes_before_reservations"], 10 << 30)
            self.assertNotIn("-race", plan["build_argv"])
            self.assertFalse(plan["test_overlays_or_scheduler_hooks"])
            self.assertFalse(plan["reference_backend_executed"])
            self.assertFalse(plan["runtime_state_value_acceptance"])
            self.assertEqual(plan["consumer_result"], "REFUSED")

    def test_unknown_variant_and_invalid_compiler_refused(self):
        for variant, go in (("baseline", "go"), (C.VARIANTS[0], ""), (C.VARIANTS[1], None), (C.VARIANTS[0], "go\0")):
            with self.assertRaises(ValueError):
                C.plan(Path("/selected-owned-public-chain"), variant, go)

    def test_probe_substitution_refused(self):
        for raw in (b"", C.probe_bytes() + b"\n", C.probe_bytes().replace(b"candidate_public_chain_lifecycle", b"unselected_tag")):
            with mock.patch.object(C.P, "read_regular", return_value=raw):
                with self.assertRaises(ValueError):
                    C.probe_bytes()

    def test_existing_workspace_is_never_adopted(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            sentinel = workspace / "existing-proof"
            sentinel.write_bytes(b"preserve")
            with self.assertRaises(ValueError):
                C.prepare(workspace / "absent-source", workspace, C.VARIANTS[0], "go")
            self.assertEqual(sentinel.read_bytes(), b"preserve")

    def test_linked_workspace_and_source_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            link = root / "alias"
            try:
                link.symlink_to(root, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("Symlink creation unavailable on this host")
            for node, workspace in ((root, link / "new"), (link, root / "new")):
                with self.assertRaises(ValueError):
                    C.prepare(node, workspace, C.VARIANTS[1], "go")
                self.assertFalse((root / "new").exists())


if __name__ == "__main__":
    unittest.main()
