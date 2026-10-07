"""Filesystem and privacy controls for the read-only metadata sampler."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock

SCRIPT = Path(__file__).with_name("sample-private-staging.py")
spec = importlib.util.spec_from_file_location("private_staging_sampler", SCRIPT)
sampler = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sampler)


class PrivateStagingTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="PRIVATE_STAGING_")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def refusal(self, category, operation):
        with self.assertRaises(sampler.ScanError) as caught:
            operation()
        self.assertEqual(caught.exception.category, category)
        self.assertNotIn("PRIVATE", str(caught.exception))
        self.assertNotIn(str(self.root), str(caught.exception))

    def test_empty_root(self):
        result = sampler.snapshot(self.root)
        self.assertEqual((result["entries"], result["regular_files"], result["directories"],
                          result["logical_file_bytes"], result["vanished_entries"]), (0, 0, 0, 0, 0))

    def test_nested_regular_files(self):
        child = self.root / "PRIVATE_OBSERVATION"
        child.mkdir(mode=0o700)
        (self.root / "PRIVATE_A").write_bytes(b"a" * 17)
        (child / "PRIVATE_B").write_bytes(b"b" * 31)
        result = sampler.snapshot(self.root)
        self.assertEqual((result["entries"], result["regular_files"], result["directories"],
                          result["logical_file_bytes"]), (3, 2, 1, 48))
        self.assertNotIn("PRIVATE", json.dumps(result))

    def test_sparse_file_is_not_treated_as_physical_allocation(self):
        path = self.root / "PRIVATE_SPARSE"
        with path.open("wb") as stream:
            stream.truncate(1 << 20)
        result = sampler.snapshot(self.root)
        self.assertEqual(result["logical_file_bytes"], 1 << 20)
        info = path.stat()
        if hasattr(info, "st_blocks"):
            self.assertEqual(result["filesystem_reported_allocated_bytes"], info.st_blocks * 512)
        else:
            self.assertIsNone(result["filesystem_reported_allocated_bytes"])

    def test_metadata_scan_preserves_owned_file_bytes(self):
        path = self.root / "PRIVATE_DATA"
        path.write_bytes(b"PRIVATE_CONTENT_SENTINEL")
        before = path.stat()
        sampler.snapshot(self.root)
        after = path.stat()
        self.assertEqual((before.st_ino, before.st_size, before.st_mtime_ns),
                         (after.st_ino, after.st_size, after.st_mtime_ns))
        self.assertEqual(path.read_bytes(), b"PRIVATE_CONTENT_SENTINEL")

    def test_repeated_owned_cleanup_returns_to_empty(self):
        for _ in range(3):
            with tempfile.TemporaryDirectory(dir=self.root) as selected:
                Path(selected, "PRIVATE_CANDIDATE").write_bytes(b"{}")
                self.assertEqual(sampler.snapshot(self.root)["logical_file_bytes"], 2)
            self.assertEqual(sampler.snapshot(self.root)["entries"], 0)

    def test_missing_or_regular_root_refuses_without_path(self):
        self.refusal("input_unavailable", lambda: sampler.snapshot(self.root / "PRIVATE_MISSING"))
        path = self.root / "PRIVATE_FILE"
        path.write_bytes(b"{}")
        self.refusal("unsafe_directory", lambda: sampler.snapshot(path))

    def test_visible_symlink_refused(self):
        target = self.root / "PRIVATE_TARGET"
        target.write_bytes(b"PRIVATE_CONTENT")
        try:
            os.symlink(target, self.root / "PRIVATE_LINK")
        except (NotImplementedError, OSError):
            if os.name != "nt":
                self.fail("native symlink fixture unavailable")
            self.skipTest("native symlink fixture unavailable on Windows")
        self.refusal("unsafe_entry", lambda: sampler.snapshot(self.root))

    def test_reparse_metadata_is_unsafe_on_every_platform(self):
        info = types.SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_file_attributes=0x400)
        self.assertTrue(sampler.unsafe(info))

    def test_special_entry_refuses_without_opening(self):
        if hasattr(os, "mkfifo"):
            os.mkfifo(self.root / "PRIVATE_FIFO", 0o600)
            self.refusal("unsafe_entry", lambda: sampler.snapshot(self.root))
        else:
            path = self.root / "PRIVATE_SPECIAL"
            path.write_bytes(b"")
            native_stat = os.stat
            device = self.root.stat().st_dev

            def selected_stat(selected, **options):
                if Path(selected) == path:
                    return types.SimpleNamespace(st_mode=stat.S_IFIFO | 0o600, st_dev=device)
                return native_stat(selected, **options)

            with mock.patch.object(sampler.os, "stat", side_effect=selected_stat):
                self.refusal("unsafe_entry", lambda: sampler.snapshot(self.root))

    def test_entry_and_depth_limits(self):
        (self.root / "PRIVATE_FIRST").write_bytes(b"x")
        (self.root / "PRIVATE_SECOND").write_bytes(b"y")
        self.refusal("entry_limit", lambda: sampler.snapshot(self.root, max_entries=1))
        (self.root / "PRIVATE_DIRECTORY").mkdir(mode=0o700)
        self.refusal("depth_limit", lambda: sampler.snapshot(self.root, max_depth=0))
        for entries, depth in ((0, 2), (4097, 2), (True, 2), (128, -1), (128, 17)):
            self.refusal("invalid_options", lambda: sampler.snapshot(self.root, entries, depth))

    def test_disappearing_entries_are_retained_as_races(self):
        path = self.root / "PRIVATE_GONE"
        path.write_bytes(b"")
        native_stat = os.stat

        def selected_stat(selected, **options):
            if Path(selected) == path:
                self.assertIs(options["follow_symlinks"], False)
                raise FileNotFoundError("PRIVATE_FAILURE")
            return native_stat(selected, **options)

        with mock.patch.object(sampler.os, "stat", side_effect=selected_stat):
            result = sampler.snapshot(self.root)
        self.assertEqual((result["entries"], result["vanished_entries"], result["regular_files"]), (1, 1, 0))

    def test_missing_allocation_metadata_remains_unknown(self):
        path = self.root / "PRIVATE_NO_BLOCKS"
        path.write_bytes(b"x" * 33)
        native_stat = os.stat
        device = self.root.stat().st_dev

        def selected_stat(selected, **options):
            if Path(selected) == path:
                return types.SimpleNamespace(st_mode=stat.S_IFREG | 0o600,
                                             st_dev=device, st_size=33)
            return native_stat(selected, **options)

        with mock.patch.object(sampler.os, "stat", side_effect=selected_stat):
            result = sampler.snapshot(self.root)
        self.assertEqual(result["logical_file_bytes"], 33)
        self.assertIsNone(result["filesystem_reported_allocated_bytes"])

    def test_cached_directory_entry_metadata_is_not_used(self):
        path = self.root / "PRIVATE_CURRENT"
        path.write_bytes(b"current")
        entry = mock.Mock()
        entry.name = path.name
        entry.stat.side_effect = AssertionError("cached entry metadata was used")
        with mock.patch.object(sampler.os, "scandir") as scan:
            scan.return_value.__enter__.return_value = iter([entry])
            result = sampler.snapshot(self.root)
        self.assertEqual(result["logical_file_bytes"], 7)
        entry.stat.assert_not_called()

    def test_root_identity_and_invalid_metadata_refuse(self):
        initial = self.root.stat()
        final = types.SimpleNamespace(st_mode=initial.st_mode, st_dev=initial.st_dev,
                                      st_ino=initial.st_ino + 1)
        with mock.patch.object(sampler.os, "stat", side_effect=[initial, final]):
            self.refusal("unsafe_directory", lambda: sampler.snapshot(self.root))
        path = self.root / "PRIVATE_BAD_SIZE"
        path.write_bytes(b"")
        native_stat = os.stat
        for size, blocks in ((-1, 0), (0, -1)):
            def selected_stat(selected, **options):
                if Path(selected) == path:
                    return types.SimpleNamespace(st_mode=stat.S_IFREG | 0o600,
                                                 st_dev=initial.st_dev, st_size=size,
                                                 st_blocks=blocks)
                return native_stat(selected, **options)
            with mock.patch.object(sampler.os, "stat", side_effect=selected_stat):
                self.refusal("invalid_metadata", lambda: sampler.snapshot(self.root))

    def test_permission_errors_and_invalid_options_remain_private(self):
        with mock.patch.object(sampler.os, "scandir", side_effect=PermissionError("PRIVATE_FAILURE")):
            self.refusal("input_unavailable", lambda: sampler.snapshot(self.root))
        for args in (["--private-dir", str(self.root), "--samples", "PRIVATE_BAD"],
                     ["--private-dir", str(self.root), "--samples", "4097"],
                     ["--private-dir", str(self.root), "--samples", "100", "--interval-ms", "1000"],
                     ["--private-dir", str(self.root), "--PRIVATE_UNKNOWN"]):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = sampler.main(args)
            report = json.loads(output.getvalue())
            self.assertEqual((code, report["status"], report["category"]), (64, "not_observed", "invalid_options"))
            self.assertNotIn("PRIVATE", output.getvalue())
            self.assertNotIn(str(self.root), output.getvalue())

    def test_actual_cli_and_failed_sample_do_not_promote_partial_observations(self):
        (self.root / "PRIVATE_DATA").write_bytes(b"private")
        result = subprocess.run([sys.executable, str(SCRIPT), "--private-dir", str(self.root),
                                 "--samples", "2", "--interval-ms", "1"],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        self.assertEqual(result.returncode, 0)
        report = json.loads(result.stdout)
        self.assertEqual((report["status"], report["observed_samples"],
                          report["maximum_sampled_logical_file_bytes"]), ("observed", 2, 7))
        self.assertEqual(result.stderr, b"")
        self.assertNotIn(b"PRIVATE", result.stdout)
        self.assertNotIn(str(self.root).encode(), result.stdout)
        output = io.StringIO()
        with mock.patch.object(sampler, "snapshot", side_effect=[sampler.snapshot(self.root), sampler.ScanError("input_unavailable")]), \
                contextlib.redirect_stdout(output):
            code = sampler.main(["--private-dir", str(self.root), "--samples", "3", "--interval-ms", "1"])
        refused = json.loads(output.getvalue())
        self.assertEqual((code, refused["status"], refused["observed_samples"],
                          refused["failed_sample_index"]), (70, "not_observed", 1, 1))
        self.assertEqual(len(refused["samples"]), 1)

    def test_interruption_preserves_completed_samples_without_traceback(self):
        output = io.StringIO()
        with mock.patch.object(sampler.time, "sleep", side_effect=KeyboardInterrupt), \
                contextlib.redirect_stdout(output):
            code = sampler.main(["--private-dir", str(self.root), "--samples", "3", "--interval-ms", "1"])
        report = json.loads(output.getvalue())
        self.assertEqual((code, report["status"], report["category"],
                          report["observed_samples"], report["failed_sample_index"]),
                         (130, "not_observed", "cancelled", 1, None))
        self.assertNotIn(str(self.root), output.getvalue())


if __name__ == "__main__":
    unittest.main(verbosity=2)
