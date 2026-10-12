#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Actual owned directory/file controls; no node or resource workload starts."""
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('workspace_observer_controls', HERE / 'observe_temp_workspace.py')
OBS = importlib.util.module_from_spec(spec)
spec.loader.exec_module(OBS)


@unittest.skipUnless(sys.platform in ('darwin', 'linux'), 'Owned workspace stat observation requires Darwin/Linux')
class WorkspaceControls(unittest.TestCase):
    def test_actual_input_and_database_files_have_separate_observations(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            observer = OBS.Observer(root)
            first = observer.take('before-spawn')
            self.assertEqual(first['regular_files'], 0)
            child = root / 'selected-child' / '001'
            database = child / 'database'
            database.mkdir(parents=True)
            (child / 'input-1-0.raw').write_bytes(b'i' * 17)
            (database / '000001.ldb').write_bytes(b'd' * 4097)
            row = observer.take('while-waiting')
            self.assertEqual((row['input_files'], row['database_files'], row['other_files']), (1, 1, 0))
            self.assertEqual((row['input_file_bytes'], row['database_file_bytes']), (17, 4097))
            self.assertEqual(row['file_bytes'], 4114)
            expected = sum(p.stat().st_blocks * 512 for p in (child / 'input-1-0.raw', database / '000001.ldb'))
            self.assertEqual(row['allocated_file_bytes'], expected)
            self.assertFalse(OBS.summary(observer.points)['peak_disk_measured'])
            self.assertFalse(OBS.summary(observer.points)['instantaneous_footprint_measured'])

    def test_sparse_oversize_is_refused_without_reading_contents(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / 'input-1-0.raw'
            with path.open('wb') as stream:
                stream.truncate(OBS.MAX_FILE_BYTES + 1)
            observer = OBS.Observer(root)
            with self.assertRaises(ValueError):
                observer.take('while-waiting')
            self.assertEqual(observer.points, [])

    def test_symlink_and_fifo_are_refused_without_opening_them(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / 'alias'
            path.symlink_to(root)
            with self.assertRaises(ValueError):
                OBS.Observer(root).take('while-waiting')
            path.unlink()
            os.mkfifo(path)
            with self.assertRaises(ValueError):
                OBS.Observer(root).take('while-waiting')

    def test_replaced_workspace_root_is_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            root = parent / 'owned'
            root.mkdir()
            observer = OBS.Observer(root)
            root.rename(parent / 'old')
            root.mkdir()
            with self.assertRaises(ValueError):
                observer.take('while-waiting')

    def test_entry_depth_and_sample_caps_refuse_before_unbounded_traversal(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            deep = root
            for _ in range(OBS.MAX_DEPTH + 1):
                deep = deep / 'd'
                deep.mkdir()
            with self.assertRaises(ValueError):
                OBS.Observer(root).take('while-waiting')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for number in range(OBS.MAX_ENTRIES + 1):
                (root / str(number)).touch()
            with self.assertRaises(ValueError):
                OBS.Observer(root).take('while-waiting')
            observer = OBS.Observer(root)
            observer.points = [None] * OBS.MAX_SAMPLES
            with self.assertRaises(ValueError):
                observer.take('while-waiting')


if __name__ == '__main__':
    unittest.main()
