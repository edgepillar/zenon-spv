#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Exact-source and inverse controls; run no compiler or diagnostic workload."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("observer_eof_preparation", HERE / "prepare.py")
C = importlib.util.module_from_spec(spec)
spec.loader.exec_module(C)
ROOT = HERE.parents[1]


class PreparationTests(unittest.TestCase):
    def fixture(self, directory):
        root = directory / "source"
        root.mkdir()
        for name in C.PINS:
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((ROOT / name).read_bytes())
        return root

    def test_exact_whole_file_inverses_and_seven_overlays(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = self.fixture(base)
            manifest = C.prepare(root, base / "overlay")
            self.assertEqual(manifest["original_sha256"], C.PINS)
            self.assertEqual(len(manifest["overlay_files"]), 7)
            self.assertTrue(manifest["whole_file_patch_inverses_verified"])
            self.assertFalse(manifest["ordinary_build_or_release_qualification"])
            self.assertEqual([manifest[k] for k in ("observer_timeout_seconds", "pipe_wait_delay_seconds", "concurrency", "rounds")], [30, 1, 4, 21])
            mapping = json.loads((base / "overlay/overlay.json").read_text())["Replace"]
            for relative, pin in manifest["overlay_files"].items():
                raw = Path(mapping[str(root / relative)]).read_bytes()
                self.assertEqual((len(raw), C.sha(raw)), (pin["bytes"], pin["sha256"]))
            for relative, digest in C.PINS.items():
                self.assertEqual(C.sha((root / relative).read_bytes()), digest)

    def test_runtime_refusal_logic_and_workload_bounds_unchanged(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = self.fixture(base)
            C.prepare(root, base / "overlay")
            mapping = json.loads((base / "overlay/overlay.json").read_text())["Replace"]
            original = (root / "tools/observe-block/process.go").read_text()
            modified = Path(mapping[str(root / "tools/observe-block/process.go")]).read_text()
            self.assertEqual(original[original.index("\tswitch {"):], modified[modified.index("\tswitch {"):])
            before = original[original.index("func joinedCopyError"):original.index("func (w *boundedOutput) Write")]
            self.assertIn(before, modified)
            self.assertEqual(modified.count("cmd.Stdout, cmd.Stderr, cmd.WaitDelay = out, diagnostics, time.Second"), 1)
            resource = Path(mapping[str(root / "internal/conformance/cli_observer_resources_test.go")]).read_text()
            for selected in ("for round := range 21", "[]int{1, 4}", '"--timeout", "30s"', "len(losslessObject(t, result.stdout)) != 7"):
                self.assertIn(selected, resource)
            self.assertEqual(resource.count('t.Logf("observer-eof-diagnostic-attempt %s", raw)'), 1)

    def test_source_drift_refused_before_allocation(self):
        for name in C.PINS:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                base = Path(directory).resolve()
                root = self.fixture(base)
                path = root / name
                path.write_bytes(path.read_bytes() + b"\n")
                with self.assertRaises(ValueError):
                    C.prepare(root, base / "overlay")
                self.assertFalse((base / "overlay").exists())

    def test_existing_workspace_never_adopted(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = self.fixture(base)
            destination = base / "overlay"
            destination.mkdir()
            sentinel = destination / "proof"
            sentinel.write_bytes(b"preserve")
            with self.assertRaises(ValueError):
                C.prepare(root, destination)
            self.assertEqual(sentinel.read_bytes(), b"preserve")

    def test_source_nested_destination_and_preexisting_added_file_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = self.fixture(base)
            with self.assertRaises(ValueError):
                C.prepare(root, root / "overlay")
            (root / "tools/observe-block/zz_eof_diagnostic.go").write_bytes(b"preserve")
            with self.assertRaises(ValueError):
                C.prepare(root, base / "overlay")
            self.assertFalse((base / "overlay").exists())

    def test_source_or_destination_alias_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = self.fixture(base)
            link = base / "alias"
            try:
                link.symlink_to(root, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("Symlink creation unavailable on this host")
            for source, destination in ((link, base / "overlay"), (root, link / "overlay")):
                with self.assertRaises(ValueError):
                    C.prepare(source, destination)

    def test_hard_linked_input_refused(self):
        import os
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = self.fixture(base)
            os.link(root / "tools/observe-block/process.go", base / "alias.go")
            with self.assertRaises(ValueError):
                C.prepare(root, base / "overlay")
            self.assertFalse((base / "overlay").exists())


if __name__ == "__main__":
    unittest.main()
