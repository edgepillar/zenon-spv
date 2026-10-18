#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Source/tree, ordinary-build and fresh-destination controls; no node execution."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("foreign_startup_preparation_controls", HERE / "prepare_public_chain_foreign_startup.py")
F = importlib.util.module_from_spec(spec)
spec.loader.exec_module(F)


class ForeignStartupPreparationTests(unittest.TestCase):
    def test_complete_runtime_tree_is_unchanged(self):
        manifest, modified, pins = F.selection()
        self.assertEqual(len(manifest["files"]), 467)
        self.assertEqual(len(pins), 467)
        self.assertEqual(F.P.UTIL.reconstruct_tree(pins), "8420610538a6a51fd43ed4c6f0e2feb2db8f120f")
        self.assertEqual(set(modified), {"chain/chain.go", "chain/state_tree.go", "common/trie/nodestore.go"})
        self.assertEqual(F.P.sha(modified["chain/chain.go"]), "dc60bef56e43ff00e10b73a737562c78d4e1971376ce2d31c1eb9496341a24c4")
        for name in ("go.mod", "go.sum"):
            self.assertEqual(pins[name], manifest["files"][name])

    def test_ordinary_build_and_finite_cases(self):
        plan = F.plan(Path("/selected-owned-startup"), "/selected/go")
        self.assertEqual(plan["build_argv"][:5], ["/selected/go", "build", "-mod=readonly", "-trimpath", "-buildvcs=false"])
        self.assertEqual(plan["build_argv"][-1], "./cmd/candidate-public-chain-foreign-startup")
        self.assertEqual(plan["cases"], list(F.CASES))
        self.assertEqual(len(plan["cases"]), 4)
        self.assertEqual(plan["runtime_tree"], F.C.MODIFIED_TREE)
        self.assertFalse(plan["runtime_changed"])
        self.assertFalse(plan["reference_backend_executed"])
        self.assertFalse(plan["test_overlays_or_scheduler_hooks"])
        self.assertFalse(plan["runtime_state_value_acceptance"])
        self.assertFalse(plan["accepted_header_binding"])
        self.assertEqual(plan["consumer_result"], "REFUSED")
        self.assertNotIn("-race", plan["build_argv"])
        self.assertNotIn("-overlay", plan["build_argv"])
        self.assertEqual((plan["build_timeout_seconds"], plan["case_timeout_seconds"]), (240, 90))
        self.assertEqual(plan["minimum_free_floor_bytes"], 10 << 30)

    def test_entrypoint_tree_binds_complete_probe_bytes(self):
        _, _, pins = F.selection()
        probe = F.probe_bytes()
        pins[F.ENTRYPOINT] = {"mode": "100644", "bytes": len(probe), "sha256": F.P.sha(probe),
                              "git_blob": F.P.UTIL.git_hash("blob", probe)}
        self.assertEqual(F.P.UTIL.reconstruct_tree(pins), F.plan(Path("/selected-owned-startup"), "go")["build_tree"])
        self.assertNotEqual(F.P.UTIL.reconstruct_tree(pins), F.C.MODIFIED_TREE)
        self.assertIn(b"chain.NewChain", probe)
        self.assertIn(b".Init()", probe)
        self.assertNotIn(b".Start()", probe)
        self.assertIn(b"ErrorIfExist: true", probe)

    def test_probe_substitution_refused(self):
        raw = F.probe_bytes()
        for changed in (b"", raw + b"\n", raw.replace(b"candidate_public_chain_foreign_startup", b"unselected_tag")):
            with mock.patch.object(F.P, "read_regular", return_value=changed):
                with self.assertRaises(ValueError):
                    F.probe_bytes()

    def test_invalid_compiler_selection_refused(self):
        for go in (None, "", "go\x00unexpected"):
            with self.assertRaises(ValueError):
                F.plan(Path("/selected-owned-startup"), go)

    def test_existing_destination_never_adopted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sentinel = root / "existing-evidence"
            sentinel.write_bytes(b"preserve")
            with self.assertRaises(ValueError):
                F.prepare(root / "absent", root, "go")
            self.assertEqual(sentinel.read_bytes(), b"preserve")

    def test_linked_source_or_destination_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            alias = root / "alias"
            try:
                alias.symlink_to(root, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("Symlink creation unavailable on this host")
            for source, destination in ((alias, root / "new"), (root, alias / "new")):
                with self.assertRaises(ValueError):
                    F.prepare(source, destination, "go")
                self.assertFalse((root / "new").exists())

    def test_prepared_entrypoint_bytes_inventory_and_mode_refused(self):
        # Isolate this verifier's file boundary; the full 467-blob selection is
        # checked separately above and in the actual ordinary-build recording.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            entry = root / "node" / F.ENTRYPOINT
            entry.parent.mkdir(parents=True)
            entry.write_bytes(b"selected probe")
            entry.chmod(0o644)
            expected = {"isolated_boundary_fixture": True}
            (root / "public-chain-foreign-startup-prepared.json").write_text(json.dumps(expected))
            with mock.patch.object(F, "selection", return_value=({}, {}, {})), \
                 mock.patch.object(F, "plan", return_value=expected), \
                 mock.patch.object(F, "probe_bytes", return_value=b"selected probe"):
                self.assertEqual(F.verify(root, "go"), expected)
                entry.write_bytes(b"substituted probe")
                with self.assertRaises(ValueError):
                    F.verify(root, "go")
                entry.write_bytes(b"selected probe")
                extra = root / "node" / "unselected"
                extra.write_bytes(b"extra")
                with self.assertRaises(ValueError):
                    F.verify(root, "go")
                extra.unlink()
                if F.sys.platform != "win32":
                    entry.chmod(0o755)
                    with self.assertRaises(ValueError):
                        F.verify(root, "go")


if __name__ == "__main__":
    unittest.main()
