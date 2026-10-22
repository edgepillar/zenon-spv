#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Adversarial controls for complete file operations and unsigned sample bindings."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('file_resources_check', HERE / 'check_patch_file_resources.py')
CHECK = importlib.util.module_from_spec(spec)
spec.loader.exec_module(CHECK)


class FileResourceControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw, cls.corpus = CHECK.BYTE.read_corpus(HERE / 'testdata/candidate-patch-file-resources.json')
        _, cls.samples = CHECK.BYTE.read_corpus(HERE / 'testdata/candidate-patch-file-resource-samples.json')

    def bad_corpus(self, change):
        document = copy.deepcopy(self.corpus)
        change(document)
        with self.assertRaises((ValueError, KeyError, TypeError)):
            CHECK.check_corpus(document)

    def bad_samples(self, change):
        report = copy.deepcopy(self.samples)
        change(report)
        with self.assertRaises((ValueError, KeyError, TypeError)):
            CHECK.check_samples(report, self.raw, self.corpus)

    def case(self, name, document=None):
        return next(c for c in (document or self.corpus)['cases'] if c['name'] == name)

    def test_all_literal_families_and_closed_consumers(self):
        report = CHECK.check_corpus(self.corpus)
        self.assertEqual(report['patch_file_resource_cases'], 15)
        self.assertEqual(report['research_imports_staged'], 7)
        self.assertEqual(report['consumer_refusals'], 15)
        self.assertEqual(report['file_read_bound_maximum'], (1 << 20) + 1)

    def test_actual_CLI_success_and_invalid_revision_refusal(self):
        command = [sys.executable, '-I', '-B', str(HERE / 'check_patch_file_resources.py')]
        result = subprocess.run(command + ['--source-revision', 'ab' * 20], capture_output=True)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stderr, b'')
        self.assertEqual(json.loads(result.stdout)['recorded_fresh_child_samples'], 180)
        self.assertFalse(json.loads(result.stdout)['resource_measurements_executed_in_checker'])
        result = subprocess.run(command + ['--source-revision', 'invalid'], capture_output=True)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, b'')
        self.assertEqual(result.stderr.strip(), b'Candidate file resource evidence failed; production acceptance remains disabled.')

    def test_actual_CLI_tampered_corpus_refusal(self):
        document = copy.deepcopy(self.corpus)
        document['cases'][0]['consumer_result'] = 'ACCEPTED'
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'tampered.json'
            path.write_text(json.dumps(document))
            result = subprocess.run([sys.executable, '-I', '-B', str(HERE / 'check_patch_file_resources.py'),
                                     '--corpus', str(path)], capture_output=True)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, b'')

    def test_missing_extra_and_reordered_families_refused(self):
        self.bad_corpus(lambda d: d['cases'].pop())
        self.bad_corpus(lambda d: d['cases'].append(copy.deepcopy(d['cases'][0])))
        self.bad_corpus(lambda d: d['cases'].reverse())

    def test_exact_source_and_research_input_pins_bound(self):
        self.bad_corpus(lambda d: d['source'].update(tree='00' * 20))
        self.bad_corpus(lambda d: d['research_source_inputs'].update({'patch_file.go': '00' * 32}))
        self.bad_corpus(lambda d: d['research_source_inputs'].pop('patch_file_resources_test.go'))

    def test_file_bytes_digest_and_read_counters_bound(self):
        for field in ('file_before_sha256', 'file_after_sha256', 'file_before_bytes', 'file_read_bytes',
                      'file_stat_calls', 'file_read_calls', 'file_buffer_bytes'):
            self.bad_corpus(lambda d: self.case('records-256-owned-1024', d).update({field: None}))

    def test_early_file_refusals_do_not_read_or_allocate_buffer(self):
        for name, reason, stats in (('file-wrong-byte-count', 'file_selection_size', 1),
                                   ('file-over-raw-cap', 'file_size_limit', 1),
                                   ('file-selection-over-cap', 'file_selection_limit', 0)):
            case = self.case(name)
            self.assertEqual(case['refusal'], reason)
            self.assertEqual((case['file_stat_calls'], case['file_read_calls'], case['file_buffer_bytes'],
                              case['raw_copies'], case['target_clone_calls']), (stats, 0, 0, 0, 0))
            self.bad_corpus(lambda d: self.case(name, d).update(file_read_calls=1))

    def test_initial_target_cap_precedes_file_IO(self):
        case = self.case('target-entries-4097-noop')
        self.assertEqual((case['file_stat_calls'], case['file_read_calls'], case['raw_copies']), (0, 0, 0))
        self.bad_corpus(lambda d: self.case(case['name'], d).update(file_stat_calls=1))

    def test_selection_refusal_after_read_precedes_constructor_and_clone(self):
        case = self.case('selection-mismatch-before-clone')
        self.assertEqual((case['file_stat_calls'], case['file_read_calls'], case['raw_copies']), (2, 1, 1))
        self.assertEqual((case['constructor_calls'], case['target_clone_calls']), (0, 0))
        self.bad_corpus(lambda d: self.case(case['name'], d).update(target_clone_calls=1))

    def test_raw_ceiling_transient_refusal_and_original_alias_bound(self):
        case = self.case('raw-ceiling-transient-hex-refusal')
        self.assertEqual(case['file_read_bytes'], 1 << 20)
        self.assertEqual(case['refusal'], 'target_hex_limit')
        self.assertEqual(case['target_before'], case['target_after'])
        self.bad_corpus(lambda d: self.case(case['name'], d)['original_alias_after'].update(manifest_sha256='00' * 32))

    def test_complete_ordered_callback_and_staging_map_bindings(self):
        for field in ('staging_callbacks', 'staging_target', 'target_after', 'target_before'):
            self.bad_corpus(lambda d: self.case('records-1024-owned-4096', d)[field].update(manifest_sha256='00' * 32))
        case = self.case('injected-replay-error-complete')
        self.assertNotEqual(case['staging_target'], case['target_after'])
        self.assertEqual(case['target_after'], case['original_alias_after'])

    def test_borrowed_read_only_cursor_and_scope_cannot_be_promoted(self):
        self.bad_corpus(lambda d: d['cases'][0].update(source_cursor_preserved=False))
        for field in ('cold_disk_behavior_qualified', 'atomic_filesystem_snapshot', 'shared_writer_atomicity',
                      'authenticated_snapshot_import', 'actual_NodeTree_executed', 'runtime_state_proof_acceptance'):
            self.bad_corpus(lambda d: d['scope'].update({field: True}))

    def test_exact_shapes_and_integer_types_required(self):
        self.bad_corpus(lambda d: d['cases'][0].update(file_read_calls=True))
        self.bad_corpus(lambda d: d['cases'][0].update(target_replacements=1.0))
        self.bad_corpus(lambda d: d['cases'][0].update(extra=1))

    def test_all_180_samples_and_command_outcomes_checked(self):
        report = CHECK.check_samples(self.samples, self.raw, self.corpus)
        self.assertEqual(report['recorded_fresh_child_samples'], 180)
        self.assertTrue(report['all_samples_and_command_outcomes_bound'])
        self.assertFalse(report['execution_provenance_authenticated'])

    def test_sample_inventory_cannot_be_filtered_or_reordered(self):
        self.bad_samples(lambda r: r['samples'].pop())
        self.bad_samples(lambda r: r['samples'][0].pop())
        self.bad_samples(lambda r: r['samples'][0].reverse())
        self.bad_samples(lambda r: r['commands'][0].pop())

    def test_mode_repetition_and_complete_conformance_hash_bound(self):
        for field, value in (('mode', 'allocation'), ('repetition', True), ('case', 'other'), ('conformance_sha256', '00' * 32)):
            self.bad_samples(lambda r: r['samples'][0][0].update({field: value}))

    def test_elapsed_and_lifetime_RSS_are_positive_unsigned_integers(self):
        for field in ('elapsed_ns', 'process_peak_rss_bytes'):
            for value in (0, -1, True, 1.0, 1 << 64, None):
                self.bad_samples(lambda r: r['samples'][0][0].update({field: value}))

    def test_plain_mode_does_not_claim_allocation_sampling(self):
        for field in ('go_total_alloc_delta_bytes', 'go_mallocs_delta', 'go_gc_cycles'):
            self.bad_samples(lambda r: r['samples'][0][0].update({field: 0}))

    def test_cumulative_allocation_is_distinct_from_peak_memory(self):
        for field in ('go_total_alloc_delta_bytes', 'go_mallocs_delta', 'go_gc_cycles'):
            for value in (None, -1, True, 0.5, 1 << 64):
                self.bad_samples(lambda r: r['samples'][0][1].update({field: value}))
        self.bad_samples(lambda r: r['samples'][0][1].update(go_peak_alloc_bytes=1))
        self.bad_samples(lambda r: r['samples'][0][0].update(process_peak_rss_method='operation allocation peak'))

    def test_every_recorded_child_completion_and_exit_bound(self):
        for field, value in (('actual_exit', 1), ('actual_exit', False), ('completed', False), ('label', 'retry')):
            self.bad_samples(lambda r: r['commands'][0][0].update({field: value}))
        self.bad_samples(lambda r: r['commands'][0][0].update(stderr_sha256='00' * 32))

    def test_child_result_binds_its_variable_measurement(self):
        self.bad_samples(lambda r: r['samples'][0][0].update(elapsed_ns=1))
        self.bad_samples(lambda r: r['commands'][0][0].update(result_sha256='00' * 32))

    def test_reference_binary_platform_and_corpus_binding(self):
        self.bad_samples(lambda r: r.update(reference_binary_sha256='zz' * 32))
        self.bad_samples(lambda r: r.update(source_execution_platform='windows'))
        self.bad_samples(lambda r: r.update(corpus_sha256='00' * 32))
        self.bad_samples(lambda r: r['samples'][0][0].update(go_version='go1.26.1'))

    def test_no_sample_or_scope_claim_establishes_a_production_budget(self):
        self.bad_samples(lambda r: r.update(production_resource_budgets_qualified=True))
        self.bad_samples(lambda r: r.update(measurement_runs_expected_to_vary=False))
        self.bad_samples(lambda r: r.update(conformance_runs=True))
        self.bad_samples(lambda r: r.update(latency_speedup_qualified=True))


if __name__ == '__main__':
    unittest.main(verbosity=2)
