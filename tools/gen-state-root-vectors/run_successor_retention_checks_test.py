#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Successor joint-runner controls use tiny graphs, not the long SMT replay."""
import contextlib
import hashlib
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
spec = importlib.util.spec_from_file_location('successor_joint_prior_controls', HERE / 'run_default_retention_checks_test.py')
PRIOR = importlib.util.module_from_spec(spec)
spec.loader.exec_module(PRIOR)
D = PRIOR.D
CORPUS = 'testdata/successor-default-retention.json'


def pairs(rows):
    result = dict(rows)
    if len(result) != len(rows): raise ValueError('duplicate unit key')
    return result


def fixture():
    f = PRIOR.Fixture()
    f.count = f.result.testsRun = 13
    f.raw = PRIOR.encoded(f.document)
    f.reader.M.P = SimpleNamespace(read_regular=lambda *_: f.raw, pairs=pairs)
    f.report['kind'] = 'recorded-successor-source-default-retention-background-check'
    del f.report['native_reference_node_or_CGO_execution']
    f.report.update(new_reference_node_or_CGO_execution=False,
                    corpus_sha256=hashlib.sha256(f.raw).hexdigest())
    return f


@contextlib.contextmanager
def selected(f):
    with f.patched(), mock.patch.dict(D.SUCCESSOR_PINS, {CORPUS: (1024, hashlib.sha256(f.raw).hexdigest())}):
        yield


class SuccessorJointControls(unittest.TestCase):
    def execute(self, f, revision=None):
        with selected(f): return D.execute(f.module, revision, f.runner, cohort='successor')

    def test_original_successor_sources_and_complete_suite_are_cold_and_pinned(self):
        sources = D.pinned_sources('successor')
        self.assertEqual(set(sources), set(D.SUCCESSOR_PINS))
        self.assertEqual(hashlib.sha256(sources['testdata/successor-genesis-input-execution.json']).hexdigest(),
                         '8d80a7160bf0e7ff4fcae8bc4c18ca40b64dd65200c8fd1de5dca8fc16f8c0f0')
        module = D.load_controls('successor')
        self.assertEqual(unittest.defaultTestLoader.loadTestsFromModule(module).countTestCases(), 13)
        self.assertEqual(tuple(D.cache_info(module.C.expected_from_presealed_witnesses))[:2], (0, 0))

    def test_success_reuses_the_admitted_successor_graph_without_relabeling(self):
        f = fixture(); text, receipt = self.execute(f, 'a' * 40)
        self.assertEqual(json.loads(text)['kind'], f.report['kind'])
        self.assertEqual(receipt['format'], 'recorded-successor-retention-joint-controls/v1')
        self.assertEqual((receipt['original_tests_run'], receipt['comparison_cache_hits'], receipt['comparison_cache_misses']), (13, 1, 0))
        self.assertFalse(receipt['node_or_network_execution'] or receipt['comparison_added_history_derivation'])
        self.assertEqual(f.main_calls, 1)

    def test_partial_extra_failed_skipped_or_cold_controls_refuse(self):
        for change in (lambda f: setattr(f, 'count', 12), lambda f: setattr(f, 'count', 14),
                       lambda f: setattr(f.result, 'testsRun', 12), lambda f: setattr(f.result, 'skipped', ['unit']),
                       lambda f: setattr(f.result, 'failures', ['unit']), lambda f: setattr(f, 'warm', False)):
            f = fixture(); change(f)
            with self.assertRaises(ValueError): self.execute(f)
            self.assertEqual(f.main_calls, 0)

    def test_original_kind_and_native_or_trust_escalation_are_refused(self):
        for field, value in (('kind', 'recorded-source-default-retention-background-check'),
                             ('new_reference_node_or_CGO_execution', True), ('accepted_header_root_binding', True)):
            f = fixture(); f.report[field] = value
            with self.assertRaises(ValueError): self.execute(f)

    def test_wrong_successor_corpus_identity_refuses_before_comparison(self):
        f = fixture()
        with selected(f), mock.patch.dict(D.SUCCESSOR_PINS, {CORPUS: (1024, '0' * 64)}), self.assertRaises(ValueError):
            D.execute(f.module, runner=f.runner, cohort='successor')
        self.assertEqual(f.main_calls, 0)

    def test_successor_decoder_rejects_duplicate_json_after_repin(self):
        f = fixture(); f.raw = b'{"key":1,"key":2}'
        with self.assertRaises(ValueError): self.execute(f)
        self.assertEqual(f.main_calls, 0)

    def test_genesis_evidence_is_separately_pinned_without_file_mutation(self):
        key = 'testdata/successor-genesis-input-execution.json'
        with mock.patch.dict(D.SUCCESSOR_PINS, {key: (64 << 10, '0' * 64)}), self.assertRaises(ValueError):
            D.pinned_sources('successor')

    def test_a_comparison_cannot_add_a_new_history_derivation(self):
        f = fixture(); f.extra_model = True
        with self.assertRaises(ValueError): self.execute(f)

    def test_post_comparison_source_failure_holds_all_stdout(self):
        f = fixture(); output, error = io.StringIO(), io.StringIO()
        with selected(f), mock.patch.object(D, 'load_controls', return_value=f.module), \
                mock.patch.object(D.unittest, 'TextTestRunner', return_value=f.runner), \
                mock.patch.object(D, 'pinned_sources', side_effect=ValueError('DO_NOT_ECHO')), \
                contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
            self.assertEqual(D.main(['--cohort', 'successor']), 1)
        self.assertEqual((output.getvalue(), error.getvalue()), ('', D.REFUSAL + '\n'))

    def test_successor_main_emits_one_original_report_and_its_own_receipt(self):
        f = fixture(); output, error = io.StringIO(), io.StringIO()
        with selected(f), mock.patch.object(D, 'load_controls', return_value=f.module), \
                mock.patch.object(D.unittest, 'TextTestRunner', return_value=f.runner), \
                mock.patch.object(D, 'pinned_sources', return_value={}), \
                contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
            self.assertEqual(D.main(['--cohort', 'successor']), 0)
        self.assertEqual(json.loads(output.getvalue()), f.report)
        receipt = json.loads(error.getvalue()[len('recorded-retention-joint '):])
        self.assertEqual((receipt['format'], receipt['original_tests_run']), ('recorded-successor-retention-joint-controls/v1', 13))

    def test_unknown_or_untyped_cohort_refuses_before_selection(self):
        for cohort in ('unknown', '../original', True, None, 0):
            with self.subTest(cohort=cohort), self.assertRaises(ValueError): D.pinned_sources(cohort)
            with self.subTest(cohort=cohort), self.assertRaises(ValueError): D.load_controls(cohort)

    def test_actual_usage_processes_do_not_load_or_replay_the_model(self):
        for args, status in ((['--cohort', 'successor', '--help'], 0),
                             (['--cohort', 'unknown'], 2), (['--cohort', 'successor', '--source-revision', 'main'], 2)):
            with self.subTest(args=args):
                result = subprocess.run([sys.executable, '-I', '-B', str(HERE / 'run_default_retention_checks.py'), *args],
                                        capture_output=True, timeout=20)
                self.assertEqual(result.returncode, status)
                self.assertNotIn(b'recorded-retention-joint ', result.stderr)
                self.assertLess(len(result.stdout) + len(result.stderr), 4096)


if __name__ == '__main__':
    unittest.main(verbosity=2)
