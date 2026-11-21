#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Control ordering and completion of the recorded workspace check."""
from contextlib import redirect_stdout
import importlib.util
import io
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('workspace_checks_controls', HERE / 'run_workspace_checks.py')
RUN = importlib.util.module_from_spec(spec)
spec.loader.exec_module(RUN)

REVISION = 'ab' * 20
RECORDING = '{"workspace_children_bound":24}'


class WorkspaceChecksControls(unittest.TestCase):
    def test_invalid_revision_stops_before_selecting_the_program(self):
        with mock.patch.object(RUN.HEX, 'load') as load, self.assertRaises(ValueError):
            RUN.main(['--source-revision', 'main'])
        load.assert_not_called()

    def test_recording_failure_stops_controls(self):
        program = RUN.HEX.load('workspace_checks_fixture', RUN.CONTROLS)
        output = io.StringIO()
        with mock.patch.object(RUN.HEX, 'load', return_value=program), \
                mock.patch.object(program.CHECK, 'main', side_effect=ValueError('recording refused')) as check, \
                mock.patch.object(RUN.unittest.TextTestRunner, 'run') as run, redirect_stdout(output):
            with self.assertRaisesRegex(ValueError, 'recording refused'):
                RUN.main(['--source-revision', REVISION])
        check.assert_called_once_with([])
        run.assert_not_called()
        self.assertEqual(output.getvalue(), '')

    def test_completion_requires_the_recording_then_every_unskipped_control(self):
        program = RUN.HEX.load('workspace_checks_fixture', RUN.CONTROLS)
        count = unittest.defaultTestLoader.loadTestsFromModule(program).countTestCases()
        for success, skipped, ran in ((True, [], count), (False, [], count),
                                      (True, ['skipped control'], count), (True, [], count - 1)):
            with self.subTest(success=success, skipped=skipped, ran=ran):
                output = io.StringIO()

                def run_controls(_):
                    self.assertEqual(output.getvalue(), RECORDING + '\n')
                    return SimpleNamespace(wasSuccessful=lambda: success, skipped=skipped, testsRun=ran)

                with mock.patch.object(RUN.HEX, 'load', return_value=program), \
                        mock.patch.object(program.CHECK, 'main', side_effect=lambda _: print(RECORDING)), \
                        mock.patch.object(RUN.unittest.TextTestRunner, 'run', side_effect=run_controls), \
                        redirect_stdout(output):
                    if success and not skipped and ran == count:
                        RUN.main(['--source-revision', REVISION])
                        recording, raw_report = output.getvalue().splitlines()
                        report = json.loads(raw_report)
                        self.assertEqual(recording, RECORDING)
                        self.assertEqual(report['source_revision'], REVISION)
                        self.assertEqual(len(report['control_names']), report['tests_run'])
                        self.assertEqual(report['tests_run'], count)
                        self.assertTrue(report['checks_completed'])
                        self.assertTrue(report['graph_reuse']['selected_functions_restored'])
                    else:
                        with self.assertRaises(ValueError):
                            RUN.main(['--source-revision', REVISION])
                        self.assertEqual(output.getvalue(), RECORDING + '\n')


if __name__ == '__main__':
    unittest.main(verbosity=2)
