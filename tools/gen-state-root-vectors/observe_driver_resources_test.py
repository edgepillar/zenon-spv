#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Unix observer controls with real local Python children, never a node.

These checks exercise scope separation and exceptional completion. They are
not hosted Windows observations, workload samples or target hardware budgets.
"""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('driver_observer_controls', HERE / 'observe_driver_resources.py')
OBS = importlib.util.module_from_spec(spec)
spec.loader.exec_module(OBS)


class DriverObserverControls(unittest.TestCase):
    def test_waited_child_allocation_is_not_parent_SELF_RSS(self):
        # A fresh driver prevents a previous unittest allocation from masking
        # the scope check. Touch every page in a separate large child.
        script = """
import importlib.util, json, resource, subprocess, sys
spec = importlib.util.spec_from_file_location('scope_probe', sys.argv[1])
o = importlib.util.module_from_spec(spec); spec.loader.exec_module(o)
rows = []
o.observe_call('scope-probe', lambda: subprocess.run([sys.executable, '-I', '-B', '-c',
    'import resource; b=bytearray(128<<20); print(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)'],
    capture_output=True, check=True, timeout=30), rows.append)
print(json.dumps(rows[0]))
"""
        result = subprocess.run([sys.executable, '-I', '-B', '-c', script,
                                 str(HERE / 'observe_driver_resources.py')],
                                capture_output=True, check=True, timeout=45)
        row = json.loads(result.stdout)
        self.assertTrue(row['call_returned'])
        self.assertLess(row['after']['self']['process_peak_rss_bytes'], 96 << 20)
        self.assertGreater(row['waited_children_user_cpu_delta_ns'] + row['waited_children_system_cpu_delta_ns'], 0)
        self.assertNotIn('peak_rss', row['after']['waited_children_cpu'])

    def test_actual_exception_observation_retained_and_propagated(self):
        rows = []

        def fail():
            retained_allocation = bytearray(8 << 20)
            self.assertEqual(len(retained_allocation), 8 << 20)
            raise RuntimeError('selected failure')

        with self.assertRaises(RuntimeError):
            OBS.observe_call('failure-probe', fail, rows.append)
        self.assertEqual(len(rows), 1)
        self.assertFalse(rows[0]['call_returned'])
        self.assertEqual(rows[0]['exception_type'], 'RuntimeError')
        self.assertGreater(rows[0]['elapsed_ns'], 0)
        self.assertGreaterEqual(rows[0]['after']['self']['native_peak_rss'], rows[0]['before']['self']['native_peak_rss'])

    def test_nonzero_subprocess_exit_is_not_hidden_by_callable_return(self):
        rows = []
        result = OBS.observe_call('exit-probe', lambda: subprocess.run(
            [sys.executable, '-I', '-B', '-c', 'raise SystemExit(7)'],
            capture_output=True, timeout=30), rows.append)
        self.assertEqual(result.returncode, 7)
        self.assertTrue(rows[0]['call_returned'])
        # The caller must separately bind the actual command exit, as the
        # tree checker does. A returned callable alone is not a passing build.

    def test_unsupported_platform_refuses_before_callable_or_retention(self):
        call, retain = mock.Mock(), mock.Mock()
        with mock.patch.object(OBS.sys, 'platform', 'win32'), self.assertRaises(ValueError):
            OBS.observe_call('unsupported-probe', call, retain)
        call.assert_not_called()
        retain.assert_not_called()


if __name__ == '__main__':
    unittest.main(verbosity=2)
