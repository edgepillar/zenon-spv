#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Check the separate complete-oracle entry point without running a backend."""
from contextlib import redirect_stderr, redirect_stdout
import hashlib
import importlib.util
import io
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('complete_oracle_driver', HERE / 'run_oracle_graphs.py')
DRIVER = importlib.util.module_from_spec(spec)
spec.loader.exec_module(DRIVER)
REVISION = 'a' * 40


def arguments(program=None, reuse=False):
    result = ['--program', program or DRIVER.PROGRAMS[0], '--mode', 'translated',
              '--source-revision', REVISION]
    return result + ['--reuse-graphs'] if reuse else result


class CompleteOracleDriverControls(unittest.TestCase):
    def capture(self, argv, legacy):
        output = io.StringIO()
        with redirect_stdout(output), patch.object(DRIVER, 'load_legacy', return_value=legacy):
            DRIVER.main(argv)
        return [json.loads(line) for line in output.getvalue().splitlines()]

    def test_recorded_legacy_runner_bytes_and_recipe_are_unchanged(self):
        self.assertEqual(hashlib.sha256(DRIVER.LEGACY.read_bytes()).hexdigest(),
                         '3bf4f6078adba2520bcbf9b750961e9d09569d7a50235447f1812a625c7c5231')
        loaded = DRIVER.load_legacy()
        self.assertEqual(loaded.__file__, str(DRIVER.LEGACY))
        self.assertEqual(loaded.main.__code__.co_filename, str(DRIVER.LEGACY))
        self.assertEqual(loaded.HEX.REFERENCE_SHA256,
                         'f0871b4aa89a6b07f99a023029858fe2a7be61455d7968780e836af77db7e2c5')

    def test_altered_legacy_source_is_refused_before_execution(self):
        with patch.object(DRIVER, 'source_bytes', return_value=b'raise AssertionError()'):
            with self.assertRaises(ValueError):
                DRIVER.load_legacy()

    def test_nonregular_or_linked_source_is_refused_before_read(self):
        for regular, linked in ((False, False), (True, True)):
            with self.subTest(regular=regular, linked=linked):
                candidate = Mock()
                candidate.is_file.return_value = regular
                candidate.is_symlink.return_value = linked
                with self.assertRaises(ValueError):
                    DRIVER.source_bytes(candidate)
                candidate.open.assert_not_called()

    def test_source_read_has_an_explicit_byte_cap(self):
        candidate = Mock()
        candidate.is_file.return_value = True
        candidate.is_symlink.return_value = False
        handle = Mock()
        handle.read.return_value = b'x' * ((1 << 20) + 1)
        candidate.open.return_value.__enter__ = Mock(return_value=handle)
        candidate.open.return_value.__exit__ = Mock(return_value=False)
        with self.assertRaises(ValueError):
            DRIVER.source_bytes(candidate)
        handle.read.assert_called_once_with((1 << 20) + 1)

    def test_each_complete_program_preserves_delegate_output_and_arguments(self):
        for program in DRIVER.PROGRAMS:
            with self.subTest(program=program):
                legacy = SimpleNamespace(main=Mock(side_effect=lambda argv: print('{"complete_original_output":true}')))
                reports = self.capture(arguments(program), legacy)
                legacy.main.assert_called_once_with(arguments(program))
                self.assertEqual(reports[0], {'complete_original_output': True})
                self.assertEqual(len(reports), 2)
                self.assertFalse(reports[-1]['reuse_graphs'])
                self.assertEqual(reports[-1]['program'], program)

    def test_reuse_is_explicitly_forwarded_for_every_selection(self):
        for program in DRIVER.PROGRAMS:
            with self.subTest(program=program):
                legacy = SimpleNamespace(main=Mock())
                report, = self.capture(arguments(program, reuse=True), legacy)
                legacy.main.assert_called_once_with(arguments(program, reuse=True))
                self.assertIs(report['reuse_graphs'], True)

    def test_unknown_program_is_refused_before_loading_the_runner(self):
        for program in ('check_tree_driver_resources.py', '../check_oracle_projection.py', 'unknown.py'):
            with self.subTest(program=program), redirect_stderr(io.StringIO()):
                with patch.object(DRIVER, 'load_legacy') as loader:
                    with self.assertRaises(SystemExit) as raised:
                        DRIVER.main(arguments(program))
                    self.assertEqual(raised.exception.code, 2)
                    loader.assert_not_called()

    def test_other_modes_are_refused_before_loading_the_runner(self):
        for mode in ('reference', 'unknown'):
            argv = arguments()
            argv[argv.index('translated')] = mode
            with self.subTest(mode=mode), redirect_stderr(io.StringIO()):
                with patch.object(DRIVER, 'load_legacy') as loader:
                    with self.assertRaises(SystemExit):
                        DRIVER.main(argv)
                    loader.assert_not_called()

    def test_revision_requires_exact_lowercase_full_identity(self):
        for value in ('', 'a' * 39, 'A' * 40, 'g' * 40, REVISION + '\n'):
            argv = arguments()
            argv[-1] = value
            with self.subTest(value=value), redirect_stderr(io.StringIO()):
                with patch.object(DRIVER, 'load_legacy') as loader:
                    with self.assertRaises(SystemExit):
                        DRIVER.main(argv)
                    loader.assert_not_called()

    def test_missing_revision_is_refused_before_loading_the_runner(self):
        with redirect_stderr(io.StringIO()), patch.object(DRIVER, 'load_legacy') as loader:
            with self.assertRaises(SystemExit):
                DRIVER.main(arguments()[:-2])
            loader.assert_not_called()

    def test_delegate_failure_emits_no_wrapper_success_record(self):
        for error in (ValueError('incomplete checks'), SystemExit(1)):
            output = io.StringIO()
            legacy = SimpleNamespace(main=Mock(side_effect=error))
            with self.subTest(error=type(error).__name__), redirect_stdout(output):
                with patch.object(DRIVER, 'load_legacy', return_value=legacy):
                    with self.assertRaises(type(error)):
                        DRIVER.main(arguments())
                self.assertEqual(output.getvalue(), '')

    def test_changed_wrapper_at_completion_emits_no_success_record(self):
        output = io.StringIO()
        with redirect_stdout(output), patch.object(DRIVER, 'source_hash', side_effect=['a' * 64, 'b' * 64]):
            with patch.object(DRIVER, 'load_legacy', return_value=SimpleNamespace(main=Mock())):
                with self.assertRaises(ValueError):
                    DRIVER.main(arguments())
        self.assertEqual(output.getvalue(), '')

    def test_changed_legacy_at_completion_emits_no_success_record(self):
        output = io.StringIO()
        with redirect_stdout(output), patch.object(DRIVER, 'source_hash', side_effect=['a' * 64, 'a' * 64, 'b' * 64]):
            with patch.object(DRIVER, 'load_legacy', return_value=SimpleNamespace(main=Mock())):
                with self.assertRaises(ValueError):
                    DRIVER.main(arguments())
        self.assertEqual(output.getvalue(), '')

    def test_success_provenance_binds_current_wrapper_and_unchanged_legacy(self):
        report, = self.capture(arguments(), SimpleNamespace(main=Mock()))
        self.assertEqual(report, {
            'format_version': 1, 'kind': 'selected-complete-oracle-driver',
            'source_revision': REVISION, 'program': DRIVER.PROGRAMS[0],
            'mode': 'translated', 'reuse_graphs': False,
            'wrapper_sha256': hashlib.sha256((HERE / 'run_oracle_graphs.py').read_bytes()).hexdigest(),
            'legacy_runner_sha256': '3bf4f6078adba2520bcbf9b750961e9d09569d7a50235447f1812a625c7c5231',
            'legacy_runner_source_unchanged': True, 'checks_completed': True,
            'recorded_producer_source_inputs_rebound': False,
            'new_reference_node_or_resource_measurement': False,
            'production_acceptance_enabled': False,
        })


if __name__ == '__main__':
    unittest.main(verbosity=2)
