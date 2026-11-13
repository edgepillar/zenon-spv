#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Table-mode orchestration controls; the long original suite stays separate."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest import mock

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


D = load('table_mode_joint_runner', HERE / 'run_default_retention_checks.py')


class TableModeControls(unittest.TestCase):
    def setUp(self):
        self.reader = load('table_mode_private_reader', HERE / 'check_default_retention_corpus.py')
        self.original = self.reader.expand_table
        self.module = SimpleNamespace(C=self.reader)
        self.scopes = []

    def invoke(self, action):
        output, error = io.StringIO(), io.StringIO()
        def execute(module, revision):
            self.assertIs(module, self.module)
            self.assertEqual(revision, 'a' * 40)
            self.assertIsNot(module.C.expand_table, self.original)
            self.scopes.append(module.C.expand_table.__self__)
            return action(self.scopes[-1])
        with mock.patch.object(D, 'load_controls', return_value=self.module), \
                mock.patch.object(D, 'execute', side_effect=execute), \
                contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
            status = D.main(['--reuse-tables', '--source-revision', 'a' * 40])
        self.assertIs(self.reader.expand_table, self.original)
        return status, output.getvalue(), error.getvalue()

    def test_complete_execution_seam_restores_before_publishing(self):
        status, output, error = self.invoke(lambda _: ('original-report\n', {'original_tests_run': 27}))
        self.assertEqual((status, output), (0, 'original-report\n'))
        prefix = 'recorded-retention-joint '
        self.assertTrue(error.startswith(prefix))
        receipt = json.loads(error[len(prefix):])
        self.assertEqual(receipt['original_tests_run'], 27)
        self.assertTrue(receipt['table_reuse']['restored'] and receipt['table_reuse']['cleared'])
        self.assertEqual(receipt['table_reuse']['retained_entries'], 0)

    def test_execution_failure_suppresses_output_and_restores(self):
        def fail(_): raise ValueError('DO_NOT_ECHO')
        status, output, error = self.invoke(fail)
        self.assertEqual((status, output, error), (1, '', D.REFUSAL + '\n'))
        self.assertTrue(self.scopes[-1].closed and self.scopes[-1].cleared)

    def test_changed_helper_identity_holds_a_returned_report(self):
        def changed(scope):
            scope.tool_pin = '0' * 64
            return 'DO_NOT_PUBLISH\n', {'original_tests_run': 27}
        status, output, error = self.invoke(changed)
        self.assertEqual((status, output, error), (1, '', D.REFUSAL + '\n'))
        self.assertTrue(self.scopes[-1].restored and self.scopes[-1].cleared)

    def test_malformed_revision_does_not_load_original_controls(self):
        with mock.patch.object(D, 'load_controls', side_effect=AssertionError('unexpected load')), \
                contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as caught:
            D.main(['--reuse-tables', '--source-revision', 'main'])
        self.assertEqual(caught.exception.code, 2)

    def test_actual_flag_usage_processes_do_not_run_the_model(self):
        for args, status in ((['--reuse-tables', '--source-revision', 'main'], 2),
                             (['--reuse-tables', '--help'], 0)):
            with self.subTest(args=args):
                result = subprocess.run([sys.executable, '-I', '-B', str(HERE / 'run_default_retention_checks.py'), *args],
                                        capture_output=True, timeout=20)
                self.assertEqual(result.returncode, status)
                self.assertNotIn(b'recorded-retention-joint ', result.stderr)
                self.assertLess(len(result.stdout) + len(result.stderr), 4096)


if __name__ == '__main__':
    unittest.main(verbosity=2)
