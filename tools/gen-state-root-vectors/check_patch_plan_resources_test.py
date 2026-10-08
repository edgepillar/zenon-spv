#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Adversarial report/input bindings and bounded worker controls."""
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
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


CHECK = module('resource_checker_tests', 'check_patch_plan_resources.py')
MEASURE = module('resource_measure_tests', 'measure_patch_plan.py')


def model(repetitions=1, source_revision=None):
    # Deliberately synthetic DTO values exercise validation, not measurements.
    cases = []
    for profile in CHECK.profiles():
        output = CHECK.output_selection(profile, source_revision)
        samples = [{'repetition': n, 'traced': traced, 'elapsed_ns': 100,
            'python_traced_peak_bytes': 4096 if traced else None,
            'process_peak_memory': {'bytes': 8192, 'metric': 'process_peak_rss_bytes', 'available': True},
            **output, 'consumer_result': 'REFUSED'}
            for n in range(1, repetitions + 1) for traced in (False, True)]
        cases.append(profile | output | {'samples': samples})
    names = ('plan_patch.py', 'measure_patch_plan.py', 'check_patch_plan_resources.py', 'testdata/patch-plan-resource-inputs.json')
    return {'format_version': 1, 'kind': 'read-only-patch-plan-resource-observations',
        'source_revision': source_revision, 'source_files_sha256': {n: hashlib.sha256((HERE / n).read_bytes()).hexdigest() for n in names},
        'runtime': {'os': 'linux', 'architecture': 'amd64', 'python': '3.13.0', 'implementation': 'CPython'},
        'repetitions': repetitions, 'limits': CHECK.LIMITS.copy(), 'scope': CHECK.SCOPE.copy(),
        'measurement_result': 'OBSERVED', 'consumer_result': 'REFUSED', 'cases': cases}


class ResourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.document = model()

    def change(self, edit):
        document = copy.deepcopy(self.document)
        edit(document)
        with self.assertRaises((ValueError, KeyError, TypeError)):
            CHECK.validate_report(document)

    def worker_command(self, path, *extra):
        return subprocess.run([sys.executable, '-I', '-B', str(HERE / 'measure_patch_plan.py'),
            '--worker', 'empty', '--raw', str(path), '--sample', '1', '--traced', '1', *extra],
            capture_output=True, timeout=20)

    def test_fixed_inventory_binds_size_record_and_digest_selection(self):
        rows = CHECK.profiles()
        self.assertEqual([r['raw_bytes'] for r in rows], [0, 64384, 257536, 1030144, 1048576, 1045755])
        self.assertEqual([r['record_count'] for r in rows], [0, 64, 256, 1024, 16, 255])

    def test_generated_bytes_match_independent_ordered_unsigned_oracle(self):
        for profile in CHECK.profiles():
            raw = MEASURE.fixture(profile)
            self.assertEqual(raw, CHECK.reference_raw(profile['name']))
            events, refusal = CHECK.ORACLE.preflight(raw, CHECK.LIMITS)
            self.assertEqual((events, refusal), (CHECK.events(profile['name']), ''))

    def test_model_is_only_a_consistency_control(self):
        result = CHECK.validate_report(self.document)
        self.assertEqual(result['fresh_worker_samples'], 12)
        self.assertFalse(result['production_budget_qualified'])
        self.assertFalse(result['NodeTree_or_retention_measured'])

    def test_case_inventory_omission_extra_reorder_and_duplicate_refuse(self):
        for edit in (lambda d: d['cases'].pop(), lambda d: d['cases'].append(d['cases'][0]),
                     lambda d: d['cases'].reverse(), lambda d: d['cases'].__setitem__(1, d['cases'][0])):
            self.change(edit)

    def test_input_bytes_digest_count_and_family_are_bound(self):
        for field, value in (('raw_bytes', 1), ('record_count', 1), ('changes_hash', '00' * 32),
                             ('input_sha256', '00' * 32), ('family', 'records'), ('name', 'records-64')):
            self.change(lambda d: d['cases'][0].update({field: value}))

    def test_complete_plan_bytes_hash_and_consumer_result_are_bound(self):
        for field, value in (('plan_bytes', 1), ('plan_sha256', '00' * 32), ('consumer_result', 'ACCEPTED')):
            self.change(lambda d: d['cases'][0]['samples'][0].update({field: value}))
        self.change(lambda d: d['cases'][0].update(plan_sha256='00' * 32))

    def test_repetition_and_trace_sample_order_are_bound(self):
        self.change(lambda d: d['cases'][0]['samples'].reverse())
        self.change(lambda d: d['cases'][0]['samples'].pop())
        self.change(lambda d: d['cases'][0]['samples'][1].update(repetition=2))
        self.change(lambda d: d['cases'][0]['samples'][0].update(traced=True))

    def test_repetition_counts_require_bounded_integers(self):
        for count in (0, 4, True, '1', 1.0):
            self.change(lambda d: d.update(repetitions=count))

    def test_elapsed_observations_require_positive_bounded_integers(self):
        for value in (0, -1, True, '1', 1.0, 1 << 63):
            self.change(lambda d: d['cases'][0]['samples'][0].update(elapsed_ns=value))

    def test_trace_peak_is_absent_for_plain_and_positive_for_traced(self):
        self.change(lambda d: d['cases'][0]['samples'][0].update(python_traced_peak_bytes=1))
        for value in (None, 0, -1, True, '1', 1.0, 1 << 63):
            self.change(lambda d: d['cases'][0]['samples'][1].update(python_traced_peak_bytes=value))

    def test_process_memory_shape_units_metric_and_availability_are_bound(self):
        for value in (0, True, 1.0, -1, 1 << 63):
            self.change(lambda d: d['cases'][0]['samples'][0]['process_peak_memory'].update(bytes=value))
        self.change(lambda d: d['cases'][0]['samples'][0]['process_peak_memory'].update(metric='peak_working_set_bytes'))
        self.change(lambda d: d['cases'][0]['samples'][0]['process_peak_memory'].update(available=1))

    def test_unavailable_memory_is_explicit_not_zero(self):
        document = copy.deepcopy(self.document)
        memory = document['cases'][0]['samples'][0]['process_peak_memory']
        memory.update(bytes=None, metric='unavailable', available=False)
        CHECK.validate_report(document)
        memory['bytes'] = 0
        with self.assertRaises(ValueError):
            CHECK.validate_report(document)

    def test_code_and_input_manifest_fingerprints_are_bound(self):
        for name in self.document['source_files_sha256']:
            self.change(lambda d: d['source_files_sha256'].update({name: '00' * 32}))
        self.change(lambda d: d['source_files_sha256'].update(extra='00' * 32))

    def test_runtime_identity_cannot_masquerade_as_other_metrics(self):
        for field, value in (('os', 'other'), ('architecture', 'other'), ('python', 'private build path'),
                             ('implementation', 'other')):
            self.change(lambda d: d['runtime'].update({field: value}))
        self.change(lambda d: d['runtime'].update(os='windows'))

    def test_source_revision_is_selected_not_a_binary_authentication(self):
        self.change(lambda d: d.update(source_revision='a' * 40))
        for value in ('main', 'A' * 40, 123):
            with self.assertRaises(ValueError):
                CHECK.revision(value)

    def test_observation_cannot_claim_budget_whole_pipeline_or_proof_acceptance(self):
        for flag, value in CHECK.SCOPE.items():
            self.change(lambda d: d['scope'].update({flag: not value}))
        self.change(lambda d: d.update(consumer_result='ACCEPTED'))
        self.change(lambda d: d.update(measurement_result='QUALIFIED'))

    def test_report_and_sample_extra_keys_and_boolean_aliases_refuse(self):
        self.change(lambda d: d.update(extra=True))
        self.change(lambda d: d['cases'][0]['samples'][0].update(extra=True))
        self.change(lambda d: d.update(format_version=True))
        self.change(lambda d: d['limits'].update(raw_bytes=1048575))

    def test_actual_empty_worker_binds_complete_plan_and_keeps_refusal(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'private-input'
            path.write_bytes(b'')
            run = self.worker_command(path)
        self.assertEqual((run.returncode, run.stderr), (0, b''))
        result = json.loads(run.stdout)
        expected = CHECK.output_selection(CHECK.profiles()[0], None)
        self.assertEqual({k: result[k] for k in expected}, expected)
        self.assertEqual(result['consumer_result'], 'REFUSED')
        self.assertGreater(result['python_traced_peak_bytes'], 0)
        self.assertNotIn(str(path).encode(), run.stdout)

    def test_actual_mutated_worker_input_refuses_without_private_path(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'private-input'
            path.write_bytes(b'\x00')
            run = self.worker_command(path)
        self.assertEqual((run.returncode, run.stdout), (1, b''))
        self.assertNotIn(str(path).encode(), run.stderr)
        self.assertNotIn(b'Traceback', run.stderr)

    def test_actual_worker_revision_label_binds_complete_output(self):
        revision = 'a' * 40
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'private-input'
            path.write_bytes(b'')
            run = self.worker_command(path, '--source-revision', revision)
        self.assertEqual((run.returncode, run.stderr), (0, b''))
        result = json.loads(run.stdout)
        expected = CHECK.output_selection(CHECK.profiles()[0], revision)
        self.assertEqual({k: result[k] for k in expected}, expected)
        self.assertNotEqual(expected, CHECK.output_selection(CHECK.profiles()[0], None))
        self.assertEqual(result['consumer_result'], 'REFUSED')

    def test_report_cli_bounds_duplicate_fields_and_private_diagnostics(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'private-report'
            for raw in (b'{"kind":1,"kind":2}', b' ' * ((64 << 10) + 1)):
                path.write_bytes(raw)
                run = subprocess.run([sys.executable, '-I', '-B', str(HERE / 'check_patch_plan_resources.py'),
                                      '--report', str(path)], capture_output=True, timeout=20)
                self.assertEqual((run.returncode, run.stdout), (1, b''))
                self.assertNotIn(str(path).encode(), run.stderr)
                self.assertNotIn(b'Traceback', run.stderr)

    def test_worker_does_not_construct_large_independent_oracle_inputs(self):
        sink = types.SimpleNamespace(buffer=io.BytesIO())
        with (patch.object(MEASURE.CHECK, 'profiles', side_effect=AssertionError('oracle in worker')),
              patch.object(MEASURE.CHECK, 'reference_raw', side_effect=AssertionError('oracle in worker')),
              patch.object(MEASURE, 'worker', return_value={'worker-control': True}),
              patch.object(MEASURE.sys, 'stdout', sink)):
            MEASURE.main(['--worker', 'empty', '--raw', 'input', '--sample', '1', '--traced', '0'])
        self.assertEqual(json.loads(sink.buffer.getvalue()), {'worker-control': True})

    def test_unix_peak_unit_normalization_uses_self_and_correct_multiplier(self):
        fake = types.SimpleNamespace(RUSAGE_SELF=0, getrusage=lambda who: types.SimpleNamespace(ru_maxrss=123))
        with patch.dict(sys.modules, {'resource': fake}):
            for name, expected in (('linux', 123 * 1024), ('darwin', 123)):
                with patch.object(MEASURE.sys, 'platform', name):
                    self.assertEqual(MEASURE.process_peak(), {'bytes': expected, 'metric': 'process_peak_rss_bytes', 'available': True})

    def test_failed_worker_cannot_publish_complete_parent_report(self):
        sink = types.SimpleNamespace(buffer=io.BytesIO())
        failed = types.SimpleNamespace(returncode=1, stdout=b'partial', stderr=b'private details')
        with patch.object(MEASURE.subprocess, 'run', return_value=failed), patch.object(MEASURE.sys, 'stdout', sink):
            with self.assertRaises(ValueError):
                MEASURE.main(['--repetitions', '1'])
        self.assertEqual(sink.buffer.getvalue(), b'')

    def test_cli_invalid_arguments_refuse_without_echoing_private_values(self):
        run = subprocess.run([sys.executable, '-I', '-B', str(HERE / 'measure_patch_plan.py'),
                              '--repetitions', '0', '--source-revision', 'private endpoint'], capture_output=True, timeout=20)
        self.assertEqual((run.returncode, run.stdout), (1, b''))
        self.assertNotIn(b'private endpoint', run.stderr)
        self.assertNotIn(b'Traceback', run.stderr)


if __name__ == '__main__':
    unittest.main(verbosity=2)
