#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Control ordering and completion of paired observation checks."""
from contextlib import redirect_stdout
import importlib.util
import io
import json
from pathlib import Path
from types import ModuleType, SimpleNamespace
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('workspace_checks_controls', HERE / 'run_workspace_checks.py')
RUN = importlib.util.module_from_spec(spec)
spec.loader.exec_module(RUN)

REVISION = 'ab' * 20
RECORDING = '{"workspace_children_bound":24}'


def scale_module(compute):
    scale = ModuleType('test_scale_model')
    scale.compute = compute
    exec('from functools import lru_cache\n'
         '@lru_cache(maxsize=1)\n'
         'def expected_document():\n'
         '    return compute()\n', vars(scale))
    return scale


class SharedScaleModelControls(unittest.TestCase):
    def test_reuses_bound_model_and_keeps_reader_documents_independent(self):
        first_scale = scale_module(mock.Mock(return_value={'cases': [{'root': 'original'}]}))
        second_scale = scale_module(mock.Mock(side_effect=AssertionError('second model build')))
        first_original = first_scale.expected_document
        second_original = second_scale.expected_document
        model = RUN.SharedScaleModel()
        with mock.patch.object(RUN, 'scale_model_binding', return_value=b'bound'):
            with model.select(first_scale):
                original = first_scale.expected_document()
                original['cases'][0]['root'] = 'changed by first reader'
            with model.select(second_scale):
                reused = second_scale.expected_document()
                self.assertEqual(reused, {'cases': [{'root': 'original'}]})
                self.assertIs(second_scale.expected_document(), reused)
        self.assertIs(first_scale.expected_document, first_original)
        self.assertIs(second_scale.expected_document, second_original)
        self.assertEqual(first_original.cache_info().currsize, 0)
        self.assertEqual(second_original.cache_info().currsize, 0)
        self.assertEqual(model.report()['scale_models_reused'], 1)
        first_scale.compute.assert_called_once_with()
        second_scale.compute.assert_not_called()

    def test_refuses_changed_model_inputs_before_replacing_second_reader(self):
        first_scale = scale_module(mock.Mock(return_value={'cases': []}))
        second_scale = scale_module(mock.Mock())
        second_original = second_scale.expected_document
        model = RUN.SharedScaleModel()
        with mock.patch.object(RUN, 'scale_model_binding', side_effect=[b'first', b'first', b'different']):
            with model.select(first_scale):
                first_scale.expected_document()
            with self.assertRaises(ValueError), model.select(second_scale):
                self.fail('changed model inputs were admitted')
        self.assertIs(second_scale.expected_document, second_original)
        second_scale.compute.assert_not_called()

    def test_shared_mode_completes_only_when_each_selected_pair_reads_the_model(self):
        expected = [None, 'tree-driver-resources', 'tree-import-scale', 'tree-import-lifecycle',
                    'oracle-projection', 'projected-driver']

        for missing_reader in (None, 'oracle-projection'):
            with self.subTest(missing_reader=missing_reader):
                output = io.StringIO()
                touched = []

                def record(revision, name, model):
                    self.assertEqual(revision, REVISION)
                    touched.append((name, model))
                    if name is None:
                        self.assertIsNone(model.document)
                        model.document, model.binding = b'{}', b'bound'
                        model.computed += 1
                    elif name != missing_reader:
                        model.reused += 1
                    return 3

                args = ['--source-revision', REVISION, '--shared-scale-model']
                with mock.patch.object(RUN, 'run_pair', side_effect=record), redirect_stdout(output):
                    if missing_reader is None:
                        RUN.main(args)
                    else:
                        with self.assertRaises(ValueError):
                            RUN.main(args)
                self.assertEqual([name for name, _ in touched], expected)
                model = touched[0][1]
                self.assertTrue(all(other is model for _, other in touched))
                self.assertIsNone(model.document)
                if missing_reader is None:
                    report = json.loads(output.getvalue())
                    self.assertEqual(report['tests_run'], 18)
                    self.assertEqual(report['scale_models_reused'], 5)
                    self.assertTrue(report['model_cache_cleared'])
                else:
                    self.assertEqual(output.getvalue(), '')

    def test_shared_mode_failure_clears_cache_without_running_second_pair(self):
        output = io.StringIO()
        touched = []

        def fail(_, kind, model):
            self.assertIsNone(kind)
            model.document = b'discard on failure'
            touched.append(model)
            raise ValueError('recorded pair refused')

        with mock.patch.object(RUN, 'run_pair', side_effect=fail) as run, redirect_stdout(output):
            with self.assertRaisesRegex(ValueError, 'recorded pair refused'):
                RUN.main(['--source-revision', REVISION, '--shared-scale-model'])
        run.assert_called_once()
        self.assertEqual(len(touched), 1)
        self.assertIsNone(touched[0].document)
        self.assertEqual(output.getvalue(), '')


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
