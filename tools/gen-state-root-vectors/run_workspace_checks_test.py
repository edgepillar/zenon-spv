#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Control ordering and completion of paired observation checks."""
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

    def test_tree_pairs_run_the_exact_recording_and_all_its_controls_in_one_scope(self):
        for name, stem in RUN.TREE_CHECKS.items():
            with self.subTest(name=name):
                controls = stem + '_test.py'
                program = RUN.HEX.load('tree_pair_fixture', controls)
                suite = unittest.defaultTestLoader.loadTestsFromModule(program)
                expected = list(RUN.control_names(suite))
                output = io.StringIO()

                def complete_controls(tests):
                    self.assertEqual(output.getvalue(), RECORDING + '\n')
                    self.assertEqual(list(RUN.control_names(tests)), expected)
                    return SimpleNamespace(wasSuccessful=lambda: True, skipped=[], testsRun=len(expected))

                with mock.patch.object(RUN.HEX, 'load', return_value=program) as load, \
                        mock.patch.object(program.CHECK, 'main', side_effect=lambda _: print(RECORDING)) as record, \
                        mock.patch.object(RUN.unittest.TextTestRunner, 'run', side_effect=complete_controls), \
                        redirect_stdout(output):
                    RUN.main(['--source-revision', REVISION, '--tree-check', name])
                load.assert_called_once_with('recorded_observation_controls', controls)
                record.assert_called_once_with(['--source-revision', REVISION])
                recording, raw_report = output.getvalue().splitlines()
                self.assertEqual(recording, RECORDING)
                report = json.loads(raw_report)
                self.assertEqual(report['kind'], 'recorded-tree-checks-execution')
                self.assertEqual(report['recording_program'], stem + '.py')
                self.assertEqual(report['control_program'], controls)
                self.assertEqual(report['control_names'], expected)
                self.assertTrue(report['graph_reuse']['selected_functions_restored'])

    def test_refuses_a_mismatched_recording_before_running_either_check(self):
        wrong = RUN.HEX.load('wrong_recording_controls', RUN.CONTROLS)
        with mock.patch.object(RUN.HEX, 'load', return_value=wrong), \
                mock.patch.object(wrong.CHECK, 'main') as record, \
                mock.patch.object(RUN.unittest.TextTestRunner, 'run') as controls, self.assertRaises(ValueError):
            RUN.main(['--source-revision', REVISION, '--tree-check', 'projected-driver'])
        record.assert_not_called()
        controls.assert_not_called()


if __name__ == '__main__':
    unittest.main(verbosity=2)
