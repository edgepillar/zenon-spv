#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Comparison bindings, reader provenance and actual bounded worker controls."""
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


CHECK = module('read_comparison_test_oracle', 'check_patch_plan_reads.py')
MEASURE = module('read_comparison_test_meter', 'measure_patch_plan_reads.py')


def model(repetitions=1, revision=None):
    # Fake DTO observations exercise schema consistency only, not measurement.
    cases = []
    for profile in CHECK.CHECK.profiles():
        expected = CHECK.CHECK.output_selection(profile, revision)
        samples = [{'repetition': n, 'traced': traced, 'planner_mode': mode, 'elapsed_ns': 100,
            'python_traced_peak_bytes': (4096 if mode == 'reference' else 2048) if traced else None,
            'process_peak_memory': {'bytes': 8192, 'metric': 'process_peak_rss_bytes', 'available': True},
            **expected, 'consumer_result': 'REFUSED'}
            for n in range(1, repetitions + 1) for traced in (False, True) for mode in CHECK.MODES]
        cases.append(profile | expected | {'samples': samples})
    return {'format_version': 1, 'kind': 'read-only-patch-plan-selected-read-comparison',
        'source_revision': revision, 'reference_source': copy.deepcopy(CHECK.REFERENCE),
        'source_files_sha256': {name: hashlib.sha256((HERE / name).read_bytes()).hexdigest() for name in CHECK.FILES},
        'runtime': {'os': 'linux', 'architecture': 'amd64', 'python': '3.13.0', 'implementation': 'CPython'},
        'repetitions': repetitions, 'limits': CHECK.CHECK.LIMITS.copy(), 'scope': CHECK.SCOPE.copy(),
        'measurement_result': 'OBSERVED', 'consumer_result': 'REFUSED', 'cases': cases}


class ReadComparisonTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.document = model()

    def change(self, edit):
        doc = copy.deepcopy(self.document)
        edit(doc)
        with self.assertRaises((ValueError, KeyError, TypeError)):
            CHECK.validate_report(doc)

    def command(self, path, mode, *extra):
        return subprocess.run([sys.executable, '-I', '-B', str(HERE / 'measure_patch_plan_reads.py'),
            '--worker', 'empty', '--raw', str(path), '--sample', '1', '--traced', '1',
            '--planner-mode', mode, *extra], capture_output=True, timeout=20)

    def test_selected_historical_reader_and_shared_functions_are_pinned(self):
        self.assertEqual(CHECK.reference_pins(), CHECK.REFERENCE)
        self.assertEqual(CHECK.REFERENCE['revision'], '47b859b2b32979b166d1d138da65cf0236951040')
        self.assertEqual(CHECK.REFERENCE['plan_sha256'], '226383a309ed96f8b2fbc96480dfa7348d8861c95bf84bdc3303ea269fbc27fd')

    def test_changed_historical_function_or_shared_helper_pin_refuses(self):
        actual = CHECK.selected_function_hashes
        for filename, function in (('measure_patch_plan_reads.py', 'read_raw'), ('plan_patch.py', 'make_plan')):
            def changed(path):
                values = actual(path)
                if path.name == filename:
                    values[function] = '00' * 32
                return values
            with patch.object(CHECK, 'selected_function_hashes', side_effect=changed):
                with self.assertRaises(ValueError):
                    CHECK.reference_pins()

    def test_reference_metadata_cannot_select_another_source(self):
        for key in ('revision', 'plan_sha256', 'read_function_sha256'):
            self.change(lambda d: d['reference_source'].update({key: '00' * 32}))
        self.change(lambda d: d['reference_source']['shared_functions_sha256'].update(validate='00' * 32))

    def test_fake_comparison_is_consistency_only_not_speedup_or_budget(self):
        result = CHECK.validate_report(self.document)
        self.assertEqual(result['fresh_worker_samples'], 24)
        self.assertTrue(result['empty_and_64_record_python_peaks_reduced'])
        self.assertFalse(result['production_budget_qualified'])
        self.assertFalse(result['latency_speedup_qualified'])
        self.assertFalse(result['NodeTree_or_retention_measured'])

    def test_nonreduced_peaks_are_reported_without_filtering_or_budget_acceptance(self):
        doc = copy.deepcopy(self.document)
        for case in doc['cases']:
            for sample in case['samples']:
                if sample['planner_mode'] == 'candidate' and sample['traced']:
                    sample['python_traced_peak_bytes'] = 8192
        result = CHECK.validate_report(doc)
        self.assertFalse(result['empty_and_64_record_python_peaks_reduced'])
        self.assertFalse(result['production_budget_qualified'])

    def test_case_and_mode_sample_inventory_order_and_count_are_exact(self):
        for edit in (lambda d: d['cases'].pop(), lambda d: d['cases'].reverse(),
                     lambda d: d['cases'][0]['samples'].pop(),
                     lambda d: d['cases'][0]['samples'].reverse(),
                     lambda d: d['cases'][0]['samples'].__setitem__(1, d['cases'][0]['samples'][0])):
            self.change(edit)

    def test_modes_repetitions_and_trace_flags_require_exact_types(self):
        for field, value in (('planner_mode', True), ('planner_mode', 'other'), ('repetition', True), ('traced', 0)):
            self.change(lambda d: d['cases'][0]['samples'][0].update({field: value}))
        for repetitions in (0, 4, True, 1.0):
            self.change(lambda d: d.update(repetitions=repetitions))

    def test_both_mode_outputs_are_bound_to_complete_independent_plan_bytes(self):
        for index in range(4):
            self.change(lambda d: d['cases'][0]['samples'][index].update(plan_sha256='00' * 32))
            self.change(lambda d: d['cases'][0]['samples'][index].update(plan_bytes=1))
        self.change(lambda d: d['cases'][0].update(input_sha256='00' * 32))

    def test_projected_sample_metrics_keep_positive_units_and_trace_boundaries(self):
        for index in range(4):
            self.change(lambda d: d['cases'][0]['samples'][index].update(elapsed_ns=True))
        self.change(lambda d: d['cases'][0]['samples'][0].update(python_traced_peak_bytes=1))
        self.change(lambda d: d['cases'][0]['samples'][2].update(python_traced_peak_bytes=None))
        self.change(lambda d: d['cases'][0]['samples'][1]['process_peak_memory'].update(metric='peak_working_set_bytes'))

    def test_unavailable_memory_remains_explicit_null_in_both_modes(self):
        doc = copy.deepcopy(self.document)
        for sample in doc['cases'][0]['samples']:
            sample['process_peak_memory'] = {'bytes': None, 'metric': 'unavailable', 'available': False}
        CHECK.validate_report(doc)
        doc['cases'][0]['samples'][0]['process_peak_memory']['bytes'] = 0
        with self.assertRaises(ValueError):
            CHECK.validate_report(doc)

    def test_current_code_input_fingerprints_and_revision_label_are_bound(self):
        for name in CHECK.FILES:
            self.change(lambda d: d['source_files_sha256'].update({name: '00' * 32}))
        self.change(lambda d: d.update(source_revision='a' * 40))
        result = CHECK.validate_report(model(revision='a' * 40), 'a' * 40)
        self.assertTrue(result['all_complete_plan_bytes_bound'])

    def test_all_scope_flags_and_results_prevent_false_acceptance_claims(self):
        for name, value in CHECK.SCOPE.items():
            self.change(lambda d: d['scope'].update({name: not value}))
        self.change(lambda d: d.update(consumer_result='ACCEPTED'))
        self.change(lambda d: d.update(measurement_result='QUALIFIED'))
        self.change(lambda d: d['cases'][0]['samples'][0].update(consumer_result='ACCEPTED'))

    def test_unknown_report_case_and_sample_fields_refuse(self):
        self.change(lambda d: d.update(extra=True))
        self.change(lambda d: d['cases'][0].update(extra=True))
        self.change(lambda d: d['cases'][0]['samples'][0].update(extra=True))

    def test_actual_workers_bind_same_empty_plan_and_selected_revision(self):
        revision = 'a' * 40
        expected = CHECK.CHECK.output_selection(CHECK.CHECK.profiles()[0], revision)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'private-input'
            path.write_bytes(b'')
            for mode in CHECK.MODES:
                run = self.command(path, mode, '--source-revision', revision)
                self.assertEqual((run.returncode, run.stderr), (0, b''))
                result = json.loads(run.stdout)
                self.assertEqual({key: result[key] for key in expected}, expected)
                self.assertEqual(result['planner_mode'], mode)
                self.assertEqual(result['consumer_result'], 'REFUSED')
                self.assertGreater(result['python_traced_peak_bytes'], 0)
                self.assertNotIn(str(path).encode(), run.stdout)

    def test_actual_unselected_tail_refuses_in_both_modes_without_private_path(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'private-input'
            path.write_bytes(b'\x00')
            for mode in CHECK.MODES:
                run = self.command(path, mode)
                self.assertEqual((run.returncode, run.stdout), (1, b''))
                self.assertNotIn(str(path).encode(), run.stderr)
                self.assertNotIn(b'Traceback', run.stderr)

    def test_worker_entry_does_not_construct_large_fixture_oracle_inputs(self):
        sink = types.SimpleNamespace(buffer=io.BytesIO())
        with (patch.object(MEASURE.COMPARE.CHECK, 'profiles', side_effect=AssertionError('oracle in worker')),
              patch.object(MEASURE.COMPARE.CHECK, 'reference_raw', side_effect=AssertionError('oracle in worker')),
              patch.object(MEASURE, 'worker', return_value={'worker-control': True}),
              patch.object(MEASURE.sys, 'stdout', sink)):
            MEASURE.main(['--worker', 'empty', '--raw', 'input', '--sample', '1', '--traced', '0', '--planner-mode', 'candidate'])
        self.assertEqual(json.loads(sink.buffer.getvalue()), {'worker-control': True})

    def test_failed_worker_cannot_publish_a_partial_comparison_report(self):
        sink = types.SimpleNamespace(buffer=io.BytesIO())
        failed = types.SimpleNamespace(returncode=1, stdout=b'partial', stderr=b'private details')
        with (patch.object(MEASURE.subprocess, 'run', return_value=failed), patch.object(MEASURE.sys, 'stdout', sink)):
            with self.assertRaises(ValueError):
                MEASURE.main(['--repetitions', '1'])
        self.assertEqual(sink.buffer.getvalue(), b'')

    def test_cli_invalid_options_size_and_duplicate_fields_refuse_privately(self):
        run = subprocess.run([sys.executable, '-I', '-B', str(HERE / 'measure_patch_plan_reads.py'),
                              '--repetitions', '0', '--source-revision', 'private endpoint'], capture_output=True, timeout=20)
        self.assertEqual((run.returncode, run.stdout), (1, b''))
        self.assertNotIn(b'private endpoint', run.stderr)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'private-report'
            for raw in (b'{"kind":1,"kind":2}', b' ' * ((64 << 10) + 1)):
                path.write_bytes(raw)
                run = subprocess.run([sys.executable, '-I', '-B', str(HERE / 'check_patch_plan_reads.py'),
                                      '--report', str(path)], capture_output=True, timeout=20)
                self.assertEqual((run.returncode, run.stdout), (1, b''))
                self.assertNotIn(str(path).encode(), run.stderr)
                self.assertNotIn(b'Traceback', run.stderr)


if __name__ == '__main__':
    unittest.main(verbosity=2)
