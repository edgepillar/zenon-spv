#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Control explicit import CLI dispatch, source binding and actual console evidence."""
from contextlib import contextmanager
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
from types import ModuleType
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('import_child_control_subject', HERE / 'import_resource_child_hex.py')
C = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(C)
REVISION = 'ab' * 20
LIVE_REVISION = REVISION
LIVE_CHILDREN = {}
ORIGINAL_CONSOLES = {
    'check_patch_resources.py': {
        'LF': (1320, 'b1829b3c3f05854d94ecc7ba531da330d7f79c849259bf4e6d82379d3094628d'),
        'CRLF': (1321, 'd33c71048c9d25abca24ea4343a37a3e26101e9248f102902b468fc87523d5f6'),
    },
    'check_patch_import_comparison.py': {
        'LF': (793, 'c4c980304fb7b3ea68680eae927e6e187ce443a2d639029b0d0f35c1d56ac4d2'),
        'CRLF': (794, 'bf2883b24323c5d1ec6f041751bc9cd163980f6131968e2cc90e8304238fa7ec'),
    },
}


def control_module(selected):
    program = ModuleType('synthetic_import_control_dispatch')
    program.__file__ = str(HERE / selected)
    program.subprocess = subprocess
    return program


def arguments(owner):
    return [sys.executable, '-I', '-B', str(HERE / owner.profile['target'])]


def baseline_arguments():
    return [sys.executable, '-I', '-B', str(HERE / 'compare_patch_import.py'),
            '--baseline-import-source', str(HERE / 'unselected.go'),
            '--node-source', str(HERE / 'missing-node'), '--go', str(HERE / 'missing-go'),
            '--output', str(HERE / 'out.json'), '--evidence-directory', str(HERE / 'evidence')]


def recipe(owner, stdout=b'controlled stdout\n', stderr=b''):
    return {'format_version': 1, 'kind': C.KIND, 'execution_revision': REVISION,
            'program': owner.profile['target'], 'mode': owner.mode, 'helper_sha256': owner.tool_pin,
            'declared_exit': 0, 'stdout_sha256': C.sha(stdout), 'stdout_bytes': len(stdout),
            'stderr_sha256': C.sha(stderr), 'stderr_bytes': len(stderr),
            'binding_manifest': copy.deepcopy(owner.expected_bindings),
            'selected_function_identities_restored': True, 'original_entrypoint_guard_executed': True,
            'recorded_producer_source_inputs_rebound': False, 'reference_backend_executed': False,
            'production_acceptance_enabled': False}


@contextmanager
def simulated_child(owner, change=None, code=0, stdout=b'controlled stdout\n', stderr=b''):
    report = recipe(owner, stdout, stderr)
    if change:
        change(report)
    result = subprocess.CompletedProcess(['isolated-unit-fixture'], code, stdout, stderr)
    with mock.patch.object(C.subprocess, 'run', return_value=result) as run, \
            mock.patch.object(C.IO, 'read_report', return_value=report):
        yield run, result


class ImportChildControls(unittest.TestCase):
    def selections(self):
        return tuple(C.PROFILES)

    def test_original_sources_dependencies_and_legacy_helpers_are_pinned(self):
        pins = C.sources()
        self.assertEqual(len(pins), 7)
        for name, value in pins.items():
            self.assertEqual(hashlib.sha256((HERE / name).read_bytes()).hexdigest(), value)
        self.assertEqual(hashlib.sha256((HERE / 'run_target_hex.py').read_bytes()).hexdigest(),
                         '3bf4f6078adba2520bcbf9b750961e9d09569d7a50235447f1812a625c7c5231')

    def test_all_original_control_methods_remain_selected(self):
        for selected, count in zip(self.selections(), (24, 21)):
            with self.subTest(program=selected):
                program = C.load('unchanged_import_controls', selected)
                suite = unittest.defaultTestLoader.loadTestsFromModule(program)
                self.assertEqual(suite.countTestCases(), count)
                self.assertIs(program.subprocess, subprocess)

    def test_parent_scope_is_test_local_and_restores_original_dispatch(self):
        original_run = subprocess.run
        for selected in self.selections():
            program = control_module(selected)
            with C.selected_children(program, selected, 'translated', REVISION) as owner:
                self.assertIs(program.subprocess, owner.facade)
                self.assertIs(program.subprocess.run, owner.replacement)
                self.assertIs(subprocess.run, original_run)
            self.assertIs(program.subprocess, subprocess)
            self.assertIs(subprocess.run, original_run)
            self.assertTrue(owner.closed)

    def test_exception_and_nested_selection_restore_the_owned_parent(self):
        for selected in self.selections():
            program = control_module(selected)
            with self.assertRaisesRegex(RuntimeError, 'owned parent failure'):
                with C.selected_children(program, selected, 'translated', REVISION) as owner:
                    with self.assertRaises(ValueError):
                        with C.selected_children(program, selected, 'translated', REVISION):
                            self.fail('A nested scope entered')
                    self.assertIs(program.subprocess, owner.facade)
                    raise RuntimeError('owned parent failure')
            self.assertIs(program.subprocess, subprocess)

    def test_replaced_dispatch_is_refused_after_original_is_restored(self):
        for selected in self.selections():
            program = control_module(selected)
            with self.assertRaises(ValueError):
                with C.selected_children(program, selected, 'translated', REVISION):
                    program.subprocess = None
            self.assertIs(program.subprocess, subprocess)

    def test_unknown_program_mode_revision_and_module_refuse_before_selection(self):
        selected = self.selections()[0]
        program = control_module(selected)
        for name, mode, revision in (('other.py', 'translated', REVISION),
                                     (selected, 'fast', REVISION), (selected, 'translated', 'main')):
            with self.assertRaises(ValueError):
                C.SelectedChildren(program, name, mode, revision)
            self.assertIs(program.subprocess, subprocess)
        program.__file__ = str(HERE / 'other.py')
        with self.assertRaises(ValueError):
            C.SelectedChildren(program, selected, 'translated', REVISION)

    def test_each_original_source_pin_is_required(self):
        for selected in self.selections():
            for key in ('control_sha256', 'target_sha256'):
                profile = dict(C.PROFILES[selected], **{key: '00' * 32})
                with self.subTest(program=selected, pin=key), mock.patch.dict(C.PROFILES, {selected: profile}):
                    with self.assertRaises(ValueError):
                        C.sources()
        for name in C.DEPENDENCIES:
            with self.subTest(dependency=name), mock.patch.dict(C.DEPENDENCIES, {name: '00' * 32}):
                with self.assertRaises(ValueError):
                    C.sources()

    def test_unknown_arguments_kwargs_types_and_call_order_refuse_before_launch(self):
        for selected in self.selections():
            program = control_module(selected)
            with C.selected_children(program, selected, 'translated', REVISION) as owner:
                with mock.patch.object(C.subprocess, 'run') as run:
                    for argv in (arguments(owner) + ['--case', 'one'], baseline_arguments(),
                                 [sys.executable, '-I', '-B', str(HERE / 'other.py')]):
                        with self.assertRaises(ValueError):
                            owner.invoke(argv, **owner.profile['kwargs'])
                    for patch in ({'capture_output': False}, {'capture_output': 1},
                                  {'timeout': 120.0}, {'check': True}):
                        values = dict(owner.profile['kwargs'], **patch)
                        with self.assertRaises(ValueError):
                            owner.invoke(arguments(owner), **values)
                    run.assert_not_called()
                self.assertEqual(owner.records, [])

    def test_cross_thread_invocation_refuses_without_launch(self):
        for selected in self.selections():
            program = control_module(selected)
            failures = []
            with C.selected_children(program, selected, 'translated', REVISION) as owner:
                def invoke():
                    try:
                        owner.invoke(arguments(owner), **owner.profile['kwargs'])
                    except ValueError:
                        failures.append('refused')
                with mock.patch.object(C.subprocess, 'run') as run:
                    thread = threading.Thread(target=invoke)
                    thread.start()
                    thread.join(timeout=5)
                    self.assertFalse(thread.is_alive())
                    self.assertEqual(failures, ['refused'])
                    run.assert_not_called()

    def test_actual_return_object_streams_and_original_timeout_are_preserved(self):
        for selected in self.selections():
            program = control_module(selected)
            with C.selected_children(program, selected, 'translated', REVISION) as owner:
                with simulated_child(owner) as (run, result):
                    self.assertIs(owner.invoke(arguments(owner), **owner.profile['kwargs']), result)
                self.assertEqual(run.call_args.kwargs, {'capture_output': True, 'timeout': 120})
                self.assertEqual(run.call_args.args[0][:4], [sys.executable, '-I', '-B', str(C.TOOL)])
                self.assertEqual(owner.records[0]['actual_exit'], 0)

    def test_mismatched_untyped_or_missing_recipe_fields_are_refused(self):
        changes = [lambda r: r.update(declared_exit=True), lambda r: r.update(declared_exit=1),
                   lambda r: r.update(stdout_sha256='00' * 32), lambda r: r.update(stderr_bytes=1),
                   lambda r: r.update(stdout_bytes=True), lambda r: r.update(format_version=True),
                   lambda r: r.update(mode='reference'), lambda r: r.update(program='other.py'),
                   lambda r: r.update(execution_revision='cd' * 20), lambda r: r.update(helper_sha256='00' * 32),
                   lambda r: r.update(extra=True), lambda r: r.pop('binding_manifest'),
                   lambda r: r['binding_manifest']['current_execution_inputs'].update({'check.py': '00' * 32}),
                   lambda r: r.update(original_entrypoint_guard_executed=False),
                   lambda r: r.update(selected_function_identities_restored=False),
                   lambda r: r.update(recorded_producer_source_inputs_rebound=True),
                   lambda r: r.update(reference_backend_executed=True),
                   lambda r: r.update(production_acceptance_enabled=True)]
        for selected in self.selections():
            for index, change in enumerate(changes):
                program = control_module(selected)
                with self.subTest(program=selected, case=index), \
                        C.selected_children(program, selected, 'translated', REVISION) as owner:
                    with simulated_child(owner, change):
                        with self.assertRaises((ValueError, KeyError)):
                            owner.invoke(arguments(owner), **owner.profile['kwargs'])
                    self.assertEqual(owner.records, [])

    def test_failed_process_timeout_and_missing_report_cannot_complete(self):
        for selected in self.selections():
            for failure in (subprocess.TimeoutExpired('owned test child', 120), OSError('owned report missing')):
                program = control_module(selected)
                with C.selected_children(program, selected, 'translated', REVISION) as owner:
                    with mock.patch.object(C.subprocess, 'run', side_effect=failure):
                        with self.assertRaises(type(failure)):
                            owner.invoke(arguments(owner), **owner.profile['kwargs'])
                    self.assertEqual(owner.records, [])
                with self.assertRaises(ValueError):
                    owner.report()
            program = control_module(selected)
            with C.selected_children(program, selected, 'translated', REVISION) as owner:
                with simulated_child(owner, code=1):
                    with self.assertRaises(ValueError):
                        owner.invoke(arguments(owner), **owner.profile['kwargs'])
                self.assertEqual(owner.records, [])

    def test_baseline_refusal_uses_the_unchanged_original_command_and_kwargs(self):
        selected = 'check_patch_import_comparison_test.py'
        program = control_module(selected)
        with C.selected_children(program, selected, 'translated', REVISION) as owner:
            with simulated_child(owner):
                owner.invoke(arguments(owner), **owner.profile['kwargs'])
            argv = baseline_arguments()
            actual = subprocess.CompletedProcess(argv, 1, b'', b'owned refusal\n')
            with mock.patch.object(C.subprocess, 'run', return_value=actual) as run:
                self.assertIs(owner.invoke(argv, capture_output=True, timeout=30), actual)
                run.assert_called_once_with(argv, capture_output=True, timeout=30)
            self.assertFalse(owner.records[1]['translated'])
            self.assertTrue(owner.records[1]['original_command_and_kwargs_preserved'])
        report = owner.report()
        self.assertEqual([c['actual_exit'] for c in report['children']], [0, 1])
        self.assertEqual((report['actual_fresh_Python_processes'], report['translated_CLI_processes']), (2, 1))
        report['children'].clear()
        self.assertEqual(len(owner.report()['children']), 2)

    def test_baseline_command_mismatch_and_unexpected_success_refuse(self):
        selected = 'check_patch_import_comparison_test.py'
        for change in ('path', 'arguments', 'kwargs', 'exit'):
            program = control_module(selected)
            with C.selected_children(program, selected, 'translated', REVISION) as owner:
                with simulated_child(owner):
                    owner.invoke(arguments(owner), **owner.profile['kwargs'])
                argv, kwargs = baseline_arguments(), {'capture_output': True, 'timeout': 30}
                if change == 'path':
                    argv[5] = str(HERE / 'selected.go')
                if change == 'arguments':
                    argv[4] = '--other-source'
                if change == 'kwargs':
                    kwargs['timeout'] = 30.0
                with mock.patch.object(C.subprocess, 'run', return_value=subprocess.CompletedProcess(argv, 0, b'', b'')) as run:
                    with self.assertRaises(ValueError):
                        owner.invoke(argv, **kwargs)
                    if change != 'exit':
                        run.assert_not_called()
                self.assertEqual(len(owner.records), 1)

    def test_incomplete_open_or_repeated_selection_cannot_emit_completion(self):
        for selected in self.selections():
            program = control_module(selected)
            with C.selected_children(program, selected, 'translated', REVISION) as owner:
                with self.assertRaises(ValueError):
                    owner.report()
            with self.assertRaises(ValueError):
                owner.report()
        selected = self.selections()[0]
        program = control_module(selected)
        with C.selected_children(program, selected, 'translated', REVISION) as owner:
            with simulated_child(owner):
                owner.invoke(arguments(owner), **owner.profile['kwargs'])
            with mock.patch.object(C.subprocess, 'run') as run:
                with self.assertRaises(ValueError):
                    owner.invoke(arguments(owner), **owner.profile['kwargs'])
                run.assert_not_called()
        report = owner.report()
        self.assertEqual(report['actual_fresh_Python_processes'], 1)
        for field in ('stdio_filtered', 'global_subprocess_patch_installed', 'import_hook_installed',
                      'disk_cache_created', 'reference_backend_executed',
                      'recorded_producer_source_inputs_rebound', 'production_acceptance_enabled'):
            self.assertFalse(report[field])

    def test_actual_translated_default_children_match_complete_original_consoles(self):
        for profile in C.PROFILES.values():
            target = profile['target']
            with self.subTest(target=target), tempfile.TemporaryDirectory(prefix='import-child-console-') as temporary:
                path = Path(temporary).resolve(strict=True) / 'execution.json'
                command = [sys.executable, '-I', '-B', str(C.TOOL), '--program', target,
                           '--mode', 'translated', '--execution-revision', LIVE_REVISION,
                           '--report', str(path), '--']
                result = subprocess.run(command, capture_output=True, timeout=120)
                self.assertEqual(result.returncode, 0, result.stderr.decode())
                self.assertEqual(result.stderr, b'')
                newline = 'CRLF' if sys.platform == 'win32' else 'LF'
                self.assertEqual((len(result.stdout), C.sha(result.stdout)), ORIGINAL_CONSOLES[target][newline])
                report = C.IO.read_report(path)
                self.assertEqual(report['kind'], C.KIND)
                self.assertEqual(report['program'], target)
                self.assertEqual(report['mode'], 'translated')
                self.assertEqual(report['execution_revision'], LIVE_REVISION)
                self.assertEqual(report['declared_exit'], result.returncode)
                self.assertEqual(report['stdout_sha256'], C.sha(result.stdout))
                self.assertEqual(report['stdout_bytes'], len(result.stdout))
                self.assertTrue(report['original_entrypoint_guard_executed'])
                self.assertTrue(report['selected_function_identities_restored'])
                self.assertFalse(report['reference_backend_executed'])
                self.assertFalse(report['recorded_producer_source_inputs_rebound'])
                LIVE_CHILDREN[target] = {'actual_exit': result.returncode,
                    'actual_stdout_bytes': len(result.stdout), 'actual_stdout_sha256': C.sha(result.stdout),
                    'actual_stderr_bytes': len(result.stderr), 'actual_stderr_sha256': C.sha(result.stderr),
                    'matched_original_console_variant': newline, 'recipe': report}

    def test_extra_child_arguments_refuse_without_creating_a_report(self):
        for profile in C.PROFILES.values():
            with self.subTest(target=profile['target']), tempfile.TemporaryDirectory(prefix='import-child-arguments-') as temporary:
                path = Path(temporary).resolve(strict=True) / 'execution.json'
                result = subprocess.run([sys.executable, '-I', '-B', str(C.TOOL), '--program', profile['target'],
                    '--mode', 'translated', '--execution-revision', LIVE_REVISION, '--report', str(path),
                    '--', '--source-revision', REVISION], capture_output=True, timeout=30)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stdout, b'')
                self.assertFalse(path.exists())

    def test_driver_rejects_failed_skipped_partial_or_untyped_original_suites(self):
        from contextlib import nullcontext
        from types import SimpleNamespace
        runner = C.load('controlled_import_driver', 'run_import_resource_controls.py')
        for selected, count in zip(self.selections(), (24, 21)):
            for passed, skipped, tests_run in ((False, [], count), (True, ['owned skip'], count),
                                                (True, [], count - 1), (True, [], True), (True, [], count)):
                program = C.load('unchanged_import_test_program', selected)
                oracle = SimpleNamespace(load=lambda *args: program,
                                         selected_oracles=lambda *args: nullcontext({}))
                outcome = SimpleNamespace(wasSuccessful=lambda: passed, skipped=skipped, testsRun=tests_run)
                with self.subTest(program=selected, passed=passed, skipped=skipped, tests_run=tests_run), \
                        mock.patch.object(runner, 'load', side_effect=[C, oracle]), \
                        mock.patch.object(runner.unittest, 'TextTestRunner') as test_runner:
                    test_runner.return_value.run.return_value = outcome
                    with self.assertRaises(ValueError):
                        runner.main(['--program', selected, '--mode', 'translated', '--source-revision', REVISION])
                self.assertIs(program.subprocess, subprocess)

    def test_missing_recipe_after_successful_process_cannot_complete(self):
        for selected in self.selections():
            program = control_module(selected)
            with C.selected_children(program, selected, 'translated', REVISION) as owner:
                actual = subprocess.CompletedProcess(['isolated-completed-fixture'], 0, b'', b'')
                with mock.patch.object(C.subprocess, 'run', return_value=actual), \
                        mock.patch.object(C.IO, 'read_report', side_effect=OSError('owned missing recipe')):
                    with self.assertRaises(OSError):
                        owner.invoke(arguments(owner), **owner.profile['kwargs'])
                self.assertEqual(owner.records, [])


def recorded_controls(revision):
    import platform
    class TrackedResult(unittest.TextTestResult):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.attempted_names, self.passed_names = [], []

        def startTest(self, test):
            self.attempted_names.append(test.id().split('.', 1)[1])
            super().startTest(test)

        def addSuccess(self, test):
            self.passed_names.append(test.id().split('.', 1)[1])
            super().addSuccess(test)

    suite = unittest.defaultTestLoader.loadTestsFromTestCase(ImportChildControls)
    selected = [test.id().split('.', 1)[1] for test in suite]
    result = unittest.TextTestRunner(verbosity=2, resultclass=TrackedResult).run(suite)
    passed = (result.wasSuccessful() and not result.skipped and result.testsRun == len(selected)
              and result.attempted_names == result.passed_names == selected and len(LIVE_CHILDREN) == 2)
    files = tuple('tools/gen-state-root-vectors/' + name for name in
                  ('import_resource_child_hex.py', 'import_resource_child_hex_test.py',
                   'run_import_resource_controls.py', 'run_target_hex.py', *C.sources())) + ('.github/workflows/ci.yml',)
    root = HERE.parent.parent
    source_pins = {name: {'bytes': len((root / name).read_bytes()),
                          'sha256': hashlib.sha256((root / name).read_bytes()).hexdigest()} for name in files}
    report = {'format': 'zenon-import-resource-child-controls/v1', 'status': 'PASS' if passed else 'FAIL',
              'source_revision': revision, 'source_files': source_pins,
              'platform': {'os': sys.platform, 'machine': platform.machine().lower(),
                           'python': list(sys.version_info[:3])},
              'tests_run': result.testsRun, 'selected_names': selected,
              'attempted_names': result.attempted_names, 'passed_names': result.passed_names,
              'failures': len(result.failures), 'errors': len(result.errors), 'skipped': len(result.skipped),
              'real_child_observations': LIVE_CHILDREN, 'original_consoles': ORIGINAL_CONSOLES,
              'whole_original_parent_suites_executed_by_this_report': False,
              'unit_mock_records_are_process_evidence': False, 'new_node_or_Go_executions': 0,
              'representative_R1_dataset_accepted': False, 'production_acceptance_enabled': False}
    print(json.dumps(report, sort_keys=True, separators=(',', ':')))
    return 0 if passed else 1


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '--source-revision':
        import re
        if re.fullmatch('[0-9a-f]{40}', sys.argv[2]) is None:
            sys.exit(2)
        LIVE_REVISION = sys.argv[2]
        sys.exit(recorded_controls(LIVE_REVISION))
    unittest.main(verbosity=2)
