#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Equivalence, source identity, rollback and actual opt-in CLI controls."""
import copy
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import unittest
from contextlib import redirect_stdout
from types import SimpleNamespace
from unittest import mock

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('hex_seam_controls', HERE / 'project_target_hex.py')
HEX = importlib.util.module_from_spec(spec)
spec.loader.exec_module(HEX)
spec = importlib.util.spec_from_file_location('hex_runner_controls', HERE / 'run_target_hex.py')
RUN = importlib.util.module_from_spec(spec)
spec.loader.exec_module(RUN)


def outcome(function, target, limits):
    try:
        return 'RETURN', function(target, limits)
    except Exception as error:
        return 'RAISE', type(error).__name__


class HexEquivalenceControls(unittest.TestCase):
    def test_2647_finite_equivalence_and_exception_controls(self):
        reference = HEX.REFERENCE.target_refusal
        candidate = lambda target, limits: HEX.target_refusal(target, limits, HEX.REFERENCE.CEILINGS)
        count = 0
        def compare(target, limits):
            nonlocal count
            self.assertEqual(outcome(reference, target, limits), outcome(candidate, target, limits))
            count += 1
        for char in [chr(i) for i in range(256)] + ['\u0660', '\uff10', '\U0001f600', '\ud800', '\u200b']:
            for text in ('', char, char * 2, '00' + char * 2, char * 2 + '00'):
                compare({text: '00'}, HEX.REFERENCE.CEILINGS)
                compare({'00': text}, HEX.REFERENCE.CEILINGS)
        for field in ('entries', 'hex_bytes'):
            for value in (None, False, True, 0, -1, 1.0, '1', HEX.REFERENCE.CEILINGS[field], HEX.REFERENCE.CEILINGS[field] + 1):
                compare({'00': '00'}, HEX.REFERENCE.CEILINGS | {field: value})
        for target in ([], None, {'00': None}, {'00': 0}, {'00': True}, {'00': ['0', '0']},
                       {'00': b'00'}, {'00': 'Aa'}, {'00': '0'}, {'': ''}):
            compare(target, HEX.REFERENCE.CEILINGS)
        class Substring(str):
            def translate(self, _):
                raise AssertionError('A string subclass must retain reference iteration')
        compare({Substring('00'): Substring('ff')}, HEX.REFERENCE.CEILINGS)
        large = {'%064x' % i: '%064x' % (i + 1) for i in range(4096)}
        for target, limits in ((large, HEX.REFERENCE.CEILINGS),
                               (large, {'entries': 4095, 'hex_bytes': 1 << 20}),
                               (large, {'entries': 4096, 'hex_bytes': 524287}),
                               ({'': '00' * ((1 << 20) // 2)}, HEX.REFERENCE.CEILINGS)):
            compare(target, limits)
        changed = large.copy()
        for action in (lambda x: x.update({'00': 'ff'}), lambda x: x.pop(next(iter(x))),
                       lambda x: x.update({next(iter(x)): 'f0' * 65}),
                       lambda x: x.update({next(iter(x)): 'GG'})):
            action(changed)
            compare(changed, HEX.REFERENCE.CEILINGS)
        self.assertEqual(count, 2647)

    def test_limit_entry_byte_encoding_refusal_precedence(self):
        target = {'GG': 'ZZ', '0': 'x'}
        for limits, expected in (({'entries': False, 'hex_bytes': 1}, 'invalid_target_limits'),
                                 ({'entries': 1, 'hex_bytes': 1}, 'target_entry_limit'),
                                 ({'entries': 2, 'hex_bytes': 5}, 'target_hex_limit'),
                                 ({'entries': 2, 'hex_bytes': 6}, 'invalid_target_encoding')):
            self.assertEqual(HEX.target_refusal(target, limits, HEX.REFERENCE.CEILINGS), expected)

    def test_ordered_replay_maps_aliases_and_transient_refusals_identical(self):
        program = HEX.load('hex_complete_file_cases', 'check_patch_file_resources.py')
        rows = program.FILE.TARGET.inputs()
        original = [program.FILE.TARGET.expected_case(copy.deepcopy(row)) for row in rows]
        with HEX.selected_oracles(program, 'check_patch_file_resources.py', 'translated'):
            derived = [program.FILE.TARGET.expected_case(copy.deepcopy(row)) for row in rows]
        self.assertEqual(original, derived)
        self.assertEqual(len(original), 46)


class HexSeamControls(unittest.TestCase):
    def setUp(self):
        self.program = HEX.load('hex_selected_fixture', 'check_patch_file_resources.py')
        self.seams, self.inputs = HEX.selected_seams(self.program, 'check_patch_file_resources.py')

    def intact(self):
        self.assertTrue(all(module.target_refusal is original for _, module, original in self.seams))

    def test_all_twenty_two_programs_have_exact_distinct_selected_seams(self):
        self.assertEqual(len(HEX.SEAMS), 22)
        for selected in HEX.SEAMS:
            program = HEX.load('hex_all_seams', selected)
            seams, inputs = HEX.selected_seams(program, selected)
            self.assertEqual(tuple(name for name, _, _ in seams), HEX.SEAMS[selected])
            self.assertEqual(len({id(module) for _, module, _ in seams}), len(seams))
            self.assertEqual(inputs['check_patch_targets.py'], HEX.REFERENCE_SHA256)

    def test_import_and_lifecycle_identity_restoration_and_missing_seam_refusal(self):
        for selected in ('check_tree_import_scale.py', 'check_tree_import_scale_test.py',
                         'check_tree_import_lifecycle.py', 'check_tree_import_lifecycle_test.py'):
            with self.subTest(program=selected):
                program = HEX.load('hex_import_lifecycle_fixture', selected)
                seams, _ = HEX.selected_seams(program, selected)
                for mode in HEX.MODES:
                    with self.assertRaisesRegex(RuntimeError, 'injected lifecycle failure'):
                        with HEX.selected_oracles(program, selected, mode):
                            raise RuntimeError('injected lifecycle failure')
                    self.assertTrue(all(module.target_refusal is original for _, module, original in seams))
                owner_path, _, _ = seams[-1]
                parent_path, name = owner_path.rsplit('.', 1)
                parent = program
                for part in parent_path.split('.')[1:]:
                    parent = getattr(parent, part)
                owner = getattr(parent, name)
                delattr(parent, name)
                try:
                    with self.assertRaises(ValueError):
                        HEX.selected_seams(program, selected)
                    self.assertTrue(all(module.target_refusal is original for _, module, original in seams))
                finally:
                    setattr(parent, name, owner)

    def test_reference_mode_leaves_all_function_identities_intact(self):
        with HEX.selected_oracles(self.program, 'check_patch_file_resources.py', 'reference') as bindings:
            self.intact()
            self.assertFalse(bindings['builtin_str_translate_only'])
        self.intact()

    def test_tree_handoff_tail_exception_restoration_and_missing_seam_refusal(self):
        for selected in ('check_patch_tree.py', 'check_patch_tree_test.py',
                         'check_patch_tree_tail.py', 'check_patch_tree_tail_test.py'):
            with self.subTest(program=selected):
                program = HEX.load('hex_tree_handoff_tail_fixture', selected)
                seams, _ = HEX.selected_seams(program, selected)
                for mode in HEX.MODES:
                    with self.assertRaisesRegex(RuntimeError, 'injected tree handoff failure'):
                        with HEX.selected_oracles(program, selected, mode):
                            raise RuntimeError('injected tree handoff failure')
                    self.assertTrue(all(module.target_refusal is original for _, module, original in seams))
                owner_path, _, _ = seams[-1]
                parent_path, name = owner_path.rsplit('.', 1)
                parent = program
                for part in parent_path.split('.')[1:]:
                    parent = getattr(parent, part)
                owner = getattr(parent, name)
                delattr(parent, name)
                try:
                    with self.assertRaises(ValueError):
                        HEX.selected_seams(program, selected)
                    self.assertTrue(all(module.target_refusal is original for _, module, original in seams))
                finally:
                    setattr(parent, name, owner)

    def test_resource_callback_exception_restoration_and_missing_seam_refusal(self):
        for selected in ('check_patch_resources.py', 'check_patch_resources_test.py',
                         'check_patch_import_comparison.py', 'check_patch_import_comparison_test.py'):
            with self.subTest(program=selected):
                program = HEX.load('hex_resource_callback_fixture', selected)
                seams, _ = HEX.selected_seams(program, selected)
                for mode in HEX.MODES:
                    with self.assertRaisesRegex(RuntimeError, 'injected resource callback failure'):
                        with HEX.selected_oracles(program, selected, mode):
                            raise RuntimeError('injected resource callback failure')
                    self.assertTrue(all(module.target_refusal is original for _, module, original in seams))
                owner_path, _, _ = seams[-1]
                parent_path, name = owner_path.rsplit('.', 1)
                parent = program
                for part in parent_path.split('.')[1:]:
                    parent = getattr(parent, part)
                owner = getattr(parent, name)
                delattr(parent, name)
                try:
                    with self.assertRaises(ValueError):
                        HEX.selected_seams(program, selected)
                    self.assertTrue(all(module.target_refusal is original for _, module, original in seams))
                finally:
                    setattr(parent, name, owner)

    def test_driver_exception_restoration_and_missing_seam_refusal(self):
        for selected in ('check_tree_driver_resources.py', 'check_tree_driver_resources_test.py'):
            with self.subTest(program=selected):
                program = HEX.load('hex_driver_fixture', selected)
                seams, _ = HEX.selected_seams(program, selected)
                for mode in HEX.MODES:
                    with self.assertRaisesRegex(RuntimeError, 'injected driver failure'):
                        with HEX.selected_oracles(program, selected, mode):
                            raise RuntimeError('injected driver failure')
                    self.assertTrue(all(module.target_refusal is original for _, module, original in seams))
                owner_path, _, _ = seams[-1]
                parent_path, name = owner_path.rsplit('.', 1)
                parent = program
                for part in parent_path.split('.')[1:]:
                    parent = getattr(parent, part)
                owner = getattr(parent, name)
                delattr(parent, name)
                try:
                    with self.assertRaises(ValueError):
                        HEX.selected_seams(program, selected)
                    self.assertTrue(all(module.target_refusal is original for _, module, original in seams))
                finally:
                    setattr(parent, name, owner)

    def test_projection_exception_restoration_and_missing_seam_refusal(self):
        for selected in ('check_oracle_projection.py', 'check_oracle_projection_test.py',
                         'check_projected_driver.py', 'check_projected_driver_test.py'):
            with self.subTest(program=selected):
                program = HEX.load('hex_projection_fixture', selected)
                seams, _ = HEX.selected_seams(program, selected)
                for mode in HEX.MODES:
                    with self.assertRaisesRegex(RuntimeError, 'injected projection failure'):
                        with HEX.selected_oracles(program, selected, mode):
                            raise RuntimeError('injected projection failure')
                    self.assertTrue(all(module.target_refusal is original for _, module, original in seams))
                owner_path, _, _ = seams[-1]
                parent_path, name = owner_path.rsplit('.', 1)
                parent = program
                for part in parent_path.split('.')[1:]:
                    parent = getattr(parent, part)
                owner = getattr(parent, name)
                delattr(parent, name)
                try:
                    with self.assertRaises(ValueError):
                        HEX.selected_seams(program, selected)
                    self.assertTrue(all(module.target_refusal is original for _, module, original in seams))
                finally:
                    setattr(parent, name, owner)

    def test_translated_mode_restores_all_identities_and_separates_source_pins(self):
        with HEX.selected_oracles(self.program, 'check_patch_file_resources.py', 'translated') as bindings:
            self.assertTrue(all(module.target_refusal is not original for _, module, original in self.seams))
            self.assertTrue(bindings['complete_prospective_maps_and_refusal_order_preserved'])
            self.assertFalse(bindings['recorded_producer_source_inputs_rebound'])
            self.assertFalse(bindings['later_imports_and_subprocesses_accelerated'])
            self.assertIn('project_target_hex.py', bindings['current_execution_inputs'])
        self.intact()

    def test_exception_restores_every_original_identity(self):
        with self.assertRaisesRegex(RuntimeError, 'injected'):
            with HEX.selected_oracles(self.program, 'check_patch_file_resources.py', 'translated'):
                raise RuntimeError('injected')
        self.intact()

    def test_unexpected_replacement_is_refused_after_all_identities_restored(self):
        with self.assertRaises(ValueError):
            with HEX.selected_oracles(self.program, 'check_patch_file_resources.py', 'translated'):
                self.seams[0][1].target_refusal = lambda *_: ''
        self.intact()

    def test_nested_selection_refused_without_disturbing_outer_owner(self):
        with HEX.selected_oracles(self.program, 'check_patch_file_resources.py', 'translated'):
            current = [module.target_refusal for _, module, _ in self.seams]
            with self.assertRaises(ValueError):
                with HEX.selected_oracles(self.program, 'check_patch_file_resources.py', 'translated'):
                    self.fail('Nested selection must refuse')
            self.assertEqual(current, [module.target_refusal for _, module, _ in self.seams])
        self.intact()

    def test_unknown_program_mode_and_root_refused(self):
        for selected, mode in (('../check_patch_file_resources.py', 'translated'),
                               ('check_patch_file_resources.py', 'other'),
                               ('check_temp_workspace.py', 'translated')):
            with self.assertRaises(ValueError):
                with HEX.selected_oracles(self.program, selected, mode):
                    self.fail('Unknown selection must refuse')
        self.intact()

    def test_reference_source_mismatch_refused_before_replacement(self):
        with mock.patch.object(HEX, 'REFERENCE_SHA256', '00' * 32):
            with self.assertRaises(ValueError):
                HEX.selected_seams(self.program, 'check_patch_file_resources.py')
        self.intact()

    def test_changed_function_code_or_defaults_refused(self):
        module, original = self.seams[0][1:]
        for function in (lambda *_: '',):
            module.target_refusal = function
            try:
                with self.assertRaises(ValueError):
                    HEX.selected_seams(self.program, 'check_patch_file_resources.py')
            finally:
                module.target_refusal = original
        original.__defaults__ = (None,)
        try:
            with self.assertRaises(ValueError):
                HEX.selected_seams(self.program, 'check_patch_file_resources.py')
        finally:
            original.__defaults__ = None
        self.intact()

    def test_extra_missing_or_excess_module_inventory_refused(self):
        self.program.EXTRA = HEX.load('hex_extra_fixture', 'check_patch_targets.py')
        with self.assertRaises(ValueError):
            HEX.selected_seams(self.program, 'check_patch_file_resources.py')
        del self.program.EXTRA
        with mock.patch.object(HEX, 'MAX_MODULES', 1):
            with self.assertRaises(ValueError):
                HEX.selected_seams(self.program, 'check_patch_file_resources.py')
        target = self.program.FILE.TARGET
        del self.program.FILE.TARGET
        try:
            with self.assertRaises(ValueError):
                HEX.selected_seams(self.program, 'check_patch_file_resources.py')
        finally:
            self.program.FILE.TARGET = target
        self.intact()

    def test_exit_source_mismatch_refused_after_identity_restoration(self):
        inputs = self.inputs | {'check_patch_targets.py': '00' * 32}
        with mock.patch.object(HEX, 'selected_seams', return_value=(self.seams, inputs)):
            with self.assertRaises(ValueError):
                with HEX.selected_oracles(self.program, 'check_patch_file_resources.py', 'translated'):
                    pass
        self.intact()

    def test_current_owner_limits_remain_live(self):
        module = self.seams[0][1]
        with HEX.selected_oracles(self.program, 'check_patch_file_resources.py', 'translated'):
            module.CEILINGS = {'entries': 1, 'hex_bytes': 2}
            self.assertEqual(module.target_refusal({'00': ''}, {'entries': 2, 'hex_bytes': 2}), 'invalid_target_limits')
        self.intact()


class HexCLIControls(unittest.TestCase):
    def command(self, *arguments):
        return subprocess.run([sys.executable, '-I', '-B', str(HERE / 'run_target_hex.py'), *arguments],
                              capture_output=True, timeout=60)

    def test_actual_success_preserves_original_report_and_separate_recipe(self):
        result = self.command('--program', 'check_patch_file_resources.py', '--mode', 'translated',
                              '--source-revision', 'ab' * 20)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stderr, b'')
        reports = [json.loads(row) for row in result.stdout.splitlines()]
        self.assertEqual(len(reports), 2)
        self.assertEqual(reports[0]['recorded_fresh_child_samples'], 180)
        self.assertFalse(reports[0]['resource_measurements_executed_in_checker'])
        recipe = reports[1]
        self.assertEqual(recipe['kind'], 'selected-target-hex-execution')
        self.assertEqual(recipe['mode'], 'translated')
        self.assertEqual(recipe['source_revision'], 'ab' * 20)
        self.assertIsNone(recipe['tests_run'])
        self.assertTrue(recipe['selected_function_identities_restored'])
        self.assertFalse(recipe['binding_manifest']['recorded_producer_source_inputs_rebound'])
        self.assertIn('run_target_hex.py', recipe['binding_manifest']['current_execution_inputs'])

    def test_actual_invalid_revision_refuses_without_success_recipe(self):
        result = self.command('--program', 'check_patch_file_resources.py', '--mode', 'translated',
                              '--source-revision', 'main')
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, b'')

    def test_selected_data_forward_only_original_CLI_arguments(self):
        for selected in ('check_patch_resources.py', 'check_patch_import_comparison.py',
                         'check_tree_import_scale.py', 'check_tree_import_lifecycle.py',
                         'check_tree_driver_resources.py', 'check_patch_tree.py',
                         'check_patch_tree_tail.py', 'check_oracle_projection.py',
                         'check_projected_driver.py', 'check_temp_workspace.py'):
            with self.subTest(program=selected):
                program = RUN.HEX.load('hex_revision_forwarding_fixture', selected)
                seams, _ = RUN.HEX.selected_seams(program, selected)
                output = io.StringIO()
                with mock.patch.object(RUN.HEX, 'load', return_value=program), \
                        mock.patch.object(program, 'main') as main, redirect_stdout(output):
                    RUN.main(['--program', selected, '--mode', 'translated',
                              '--source-revision', 'ab' * 20])
                main.assert_called_once_with([] if selected == 'check_temp_workspace.py'
                                             else ['--source-revision', 'ab' * 20])
                recipe = json.loads(output.getvalue())
                self.assertEqual(recipe['source_revision'], 'ab' * 20)
                self.assertEqual(recipe['program'], selected)
                self.assertIsNone(recipe['tests_run'])
                self.assertEqual(recipe['control_names'], [])
                self.assertTrue(recipe['selected_function_identities_restored'])
                self.assertTrue(all(module.target_refusal is original for _, module, original in seams))

    def test_actual_unknown_program_mode_and_test_filter_refused(self):
        for arguments in (('--program', '../check.py'), ('--mode', 'fast'), ('--case', 'one')):
            result = self.command('--program', 'check_patch_file_resources_test.py', '--mode', 'translated',
                                  '--source-revision', 'ab' * 20, *arguments)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stdout, b'')

    def test_failed_skipped_filtered_and_untyped_suites_emit_no_success_recipe(self):
        program = RUN.HEX.load('hex_failed_suite_fixture', 'check_patch_file_resources_test.py')
        seams, _ = RUN.HEX.selected_seams(program, 'check_patch_file_resources_test.py')
        for success, skipped, count in ((False, [], 23), (True, ['injected'], 23),
                                        (True, [], 22), (True, [], 0), (True, [], True), (True, [], 23.0)):
            result = SimpleNamespace(wasSuccessful=lambda: success, skipped=skipped, testsRun=count)
            output = io.StringIO()
            with mock.patch.object(RUN.HEX, 'load', return_value=program), \
                    mock.patch.object(RUN.unittest.TextTestRunner, 'run', return_value=result), redirect_stdout(output):
                with self.assertRaises(ValueError):
                    RUN.main(['--program', 'check_patch_file_resources_test.py', '--mode', 'translated',
                              '--source-revision', 'ab' * 20])
            self.assertEqual(output.getvalue(), '')
            self.assertTrue(all(module.target_refusal is original for _, module, original in seams))

    def test_driver_failed_skipped_filtered_and_untyped_suites_emit_no_success_recipe(self):
        selected = 'check_tree_driver_resources_test.py'
        program = RUN.HEX.load('hex_failed_driver_suite_fixture', selected)
        seams, _ = RUN.HEX.selected_seams(program, selected)
        for success, skipped, count in ((False, [], 21), (True, ['injected'], 21),
                                        (True, [], 20), (True, [], 0), (True, [], True), (True, [], 21.0)):
            result = SimpleNamespace(wasSuccessful=lambda: success, skipped=skipped, testsRun=count)
            output = io.StringIO()
            with mock.patch.object(RUN.HEX, 'load', return_value=program), \
                    mock.patch.object(RUN.unittest.TextTestRunner, 'run', return_value=result), redirect_stdout(output):
                with self.assertRaises(ValueError):
                    RUN.main(['--program', selected, '--mode', 'translated', '--source-revision', 'ab' * 20])
            self.assertEqual(output.getvalue(), '')
            self.assertTrue(all(module.target_refusal is original for _, module, original in seams))

    def test_tree_handoff_tail_failed_skipped_filtered_and_untyped_suites_emit_no_success_recipe(self):
        for selected, expected in (('check_patch_tree_test.py', 25), ('check_patch_tree_tail_test.py', 24)):
            with self.subTest(program=selected):
                program = RUN.HEX.load('hex_failed_tree_suite_fixture', selected)
                seams, _ = RUN.HEX.selected_seams(program, selected)
                for success, skipped, count in ((False, [], expected), (True, ['injected'], expected),
                                                (True, [], expected - 1), (True, [], 0),
                                                (True, [], True), (True, [], float(expected))):
                    result = SimpleNamespace(wasSuccessful=lambda: success, skipped=skipped, testsRun=count)
                    output = io.StringIO()
                    with mock.patch.object(RUN.HEX, 'load', return_value=program), \
                            mock.patch.object(RUN.unittest.TextTestRunner, 'run', return_value=result), redirect_stdout(output):
                        with self.assertRaises(ValueError):
                            RUN.main(['--program', selected, '--mode', 'translated', '--source-revision', 'ab' * 20])
                    self.assertEqual(output.getvalue(), '')
                    self.assertTrue(all(module.target_refusal is original for _, module, original in seams))

    def test_projection_failed_skipped_filtered_and_untyped_suites_emit_no_success_recipe(self):
        for selected, expected in (('check_oracle_projection_test.py', 28), ('check_projected_driver_test.py', 30)):
            with self.subTest(program=selected):
                program = RUN.HEX.load('hex_failed_projection_suite_fixture', selected)
                seams, _ = RUN.HEX.selected_seams(program, selected)
                for success, skipped, count in ((False, [], expected), (True, ['injected'], expected),
                                                (True, [], expected - 1), (True, [], 0),
                                                (True, [], True), (True, [], float(expected))):
                    result = SimpleNamespace(wasSuccessful=lambda: success, skipped=skipped, testsRun=count)
                    output = io.StringIO()
                    with mock.patch.object(RUN.HEX, 'load', return_value=program), \
                            mock.patch.object(RUN.unittest.TextTestRunner, 'run', return_value=result), redirect_stdout(output):
                        with self.assertRaises(ValueError):
                            RUN.main(['--program', selected, '--mode', 'translated', '--source-revision', 'ab' * 20])
                    self.assertEqual(output.getvalue(), '')
                    self.assertTrue(all(module.target_refusal is original for _, module, original in seams))

    def test_resource_callback_failed_skipped_filtered_and_untyped_suites_emit_no_success_recipe(self):
        for selected, expected in (('check_patch_resources_test.py', 24),
                                   ('check_patch_import_comparison_test.py', 21)):
            with self.subTest(program=selected):
                program = RUN.HEX.load('hex_failed_resource_callback_fixture', selected)
                seams, _ = RUN.HEX.selected_seams(program, selected)
                for success, skipped, count in ((False, [], expected), (True, ['injected'], expected),
                                                (True, [], expected - 1), (True, [], 0),
                                                (True, [], True), (True, [], float(expected))):
                    result = SimpleNamespace(wasSuccessful=lambda: success, skipped=skipped, testsRun=count)
                    output = io.StringIO()
                    with mock.patch.object(RUN.HEX, 'load', return_value=program), \
                            mock.patch.object(RUN.unittest.TextTestRunner, 'run', return_value=result), redirect_stdout(output):
                        with self.assertRaises(ValueError):
                            RUN.main(['--program', selected, '--mode', 'translated', '--source-revision', 'ab' * 20])
                    self.assertEqual(output.getvalue(), '')
                    self.assertTrue(all(module.target_refusal is original for _, module, original in seams))


if __name__ == '__main__':
    unittest.main(verbosity=2)
