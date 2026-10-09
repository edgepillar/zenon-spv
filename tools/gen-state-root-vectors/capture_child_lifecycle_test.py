#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Local Unix capture controls using Python children, never a node backend."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('local_lifecycle_capture_controls', HERE / 'capture_child_lifecycle.py')
CAPTURE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(CAPTURE)


class CaptureChildLifecycleControls(unittest.TestCase):
    def run_child(self, directory, program, **options):
        return CAPTURE.capture_command([sys.executable, '-I', '-B', '-c', program],
            cwd=directory, env=os.environ.copy(), directory=directory, label='control', **options)

    def verify_preserved(self, directory, result, row):
        path = Path(directory)
        self.assertEqual(json.loads((path / 'lifecycle-control.json').read_bytes()), row)
        for stream, value in (('stdout', result.stdout), ('stderr', result.stderr)):
            self.assertEqual((path / ('lifecycle-control.' + stream)).read_bytes(), value)
            self.assertEqual((path / ('lifecycle-control.' + stream)).stat().st_mode & 0o777, 0o400)

    def test_late_allocation_is_in_exit_RSS(self):
        program = 'import resource,json; print(json.dumps({"before":resource.getrusage(resource.RUSAGE_SELF).ru_maxrss}),flush=True); data=bytearray(64<<20); print(len(data),flush=True)'
        with tempfile.TemporaryDirectory() as directory:
            result, row = self.run_child(directory, program)
            self.verify_preserved(directory, result, row)
            self.assertEqual(result.returncode, 0)
            self.assertEqual(row['refusal'], '')
            self.assertGreaterEqual(row['process_peak_rss_bytes'], 64 << 20)
            before = json.loads(result.stdout.splitlines()[0])['before']
            factor = CAPTURE.native_rss_unit(sys.platform)[1]
            self.assertGreater(row['process_peak_rss_bytes'], before * factor)
            self.assertFalse(row['parent_memory_measured'])

    def test_actual_nonzero_exit_is_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            result, row = self.run_child(directory, 'import sys; print("partial",flush=True); sys.exit(7)')
            self.verify_preserved(directory, result, row)
            self.assertEqual(row['actual_exit'], 7)
            self.assertEqual(row['refusal'], 'nonzero-exit')
            self.assertTrue(row['process_reaped'])

    def test_deadline_reaps_owned_child_and_preserves_partial_output(self):
        with tempfile.TemporaryDirectory() as directory:
            result, row = self.run_child(directory, 'import time; print("partial",flush=True); time.sleep(5)', timeout_ns=300_000_000)
            self.verify_preserved(directory, result, row)
            self.assertEqual(row['refusal'], 'timeout')
            self.assertFalse(row['completed'])
            self.assertTrue(row['process_reaped'])
            self.assertLess(row['actual_exit'], 0)
            self.assertIn(b'partial', result.stdout)

    def test_output_overshoot_is_preserved_and_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            result, row = self.run_child(directory, 'import sys; sys.stdout.write("x"*8192); sys.stdout.flush()', stdout_ceiling=128)
            self.verify_preserved(directory, result, row)
            self.assertEqual(row['refusal'], 'output-ceiling')
            self.assertGreater(row['stdout_bytes'], 128)

    def test_existing_evidence_is_never_replaced(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'lifecycle-control.stdout'
            path.write_bytes(b'owned previous evidence')
            with self.assertRaises(ValueError):
                self.run_child(directory, 'print("must not run")')
            self.assertEqual(path.read_bytes(), b'owned previous evidence')

    def test_unsupported_platform_refused_before_files_or_spawn(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(CAPTURE.sys, 'platform', 'win32'):
            with self.assertRaises(ValueError):
                self.run_child(directory, 'print("must not run")')
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_spawn_failure_preserves_actual_no_process_outcome(self):
        with tempfile.TemporaryDirectory() as directory:
            result, row = CAPTURE.capture_command([str(Path(directory) / 'missing-executable')],
                cwd=directory, env=os.environ.copy(), directory=directory, label='control')
            self.verify_preserved(directory, result, row)
            self.assertEqual(row['refusal'], 'spawn-error')
            self.assertIsNone(row['actual_exit'])
            self.assertIsNone(row['process_peak_rss_bytes'])
            self.assertFalse(row['process_reaped'])

    def test_linux_and_Darwin_unit_conversion_are_distinct(self):
        self.assertEqual(CAPTURE.native_rss_unit('linux'), ('KiB', 1024))
        self.assertEqual(CAPTURE.native_rss_unit('darwin'), ('bytes', 1))


if __name__ == '__main__':
    unittest.main()
