#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Controls for full import bindings and unsigned resource-report boundaries."""
import copy
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('patch_resources_check', HERE / 'check_patch_resources.py')
CHECK = importlib.util.module_from_spec(spec)
spec.loader.exec_module(CHECK)


class PatchResourceControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw, cls.corpus = CHECK.BYTE.read_corpus(HERE / 'testdata/candidate-patch-import-resources.json')
        cls.sample_raw, cls.samples = CHECK.BYTE.read_corpus(HERE / 'testdata/candidate-patch-import-resource-samples.json')

    def change_corpus(self, change):
        document = copy.deepcopy(self.corpus)
        change(document)
        with self.assertRaises((ValueError, KeyError, TypeError)):
            CHECK.check_corpus(document)

    def change_sample(self, change):
        report = copy.deepcopy(self.samples)
        change(report)
        with self.assertRaises((ValueError, KeyError, TypeError)):
            CHECK.check_samples(report, self.raw, self.corpus)

    def case(self, name, document=None):
        return next(c for c in (document or self.corpus)['cases'] if c['name'] == name)

    def test_complete_literal_inventory_and_closed_consumers(self):
        report = CHECK.check_corpus(self.corpus)
        self.assertEqual(report['patch_import_resource_cases'], 12)
        self.assertEqual(report['consumer_refusals'], 12)
        self.assertEqual(report['research_imports_rejected'], 5)

    def test_literal_raw_ceiling_and_large_owned_maps_are_independent(self):
        rows = {r['name']: r for r in CHECK.inputs()}
        self.assertEqual(len(rows['raw-ceiling-transient-hex-refusal']['raw']), 1 << 20)
        self.assertEqual(len(rows['records-1024-owned-4096']['target']), 4096)
        self.assertEqual(len(rows['target-entries-4097-noop']['target']), 4097)
        self.assertEqual(rows['target-hex-ceiling-noop']['target'], {'': '00' * (1 << 19)})

    def test_missing_extra_reordered_cases_refused(self):
        self.change_corpus(lambda d: d['cases'].pop())
        self.change_corpus(lambda d: d['cases'].append(copy.deepcopy(d['cases'][0])))
        self.change_corpus(lambda d: d['cases'].reverse())

    def test_complete_source_bytes_and_selected_digest_bound(self):
        for field in ('raw_sha256', 'source_after_sha256', 'raw_bytes'):
            self.change_corpus(lambda d: self.case('records-256-owned-1024', d).update({field: 0}))
        self.change_corpus(lambda d: d['cases'][1]['selection'].update(changes_hash='00' * 32))

    def test_ordered_callbacks_bound_and_no_prefix_acceptance(self):
        self.change_corpus(lambda d: self.case('records-1024-owned-4096', d)['staging_callbacks'].update(manifest_sha256='00' * 32))
        self.change_corpus(lambda d: self.case('records-1024-owned-4096', d)['staging_callbacks'].update(count=1))

    def test_complete_output_and_original_alias_bound(self):
        for field in ('target_after', 'target_before', 'original_alias_after'):
            self.change_corpus(lambda d: self.case('records-256-owned-1024', d)[field].update(manifest_sha256='00' * 32))

    def test_complete_staging_target_bound_on_replay_error(self):
        case = self.case('injected-replay-error-complete')
        self.assertEqual(case['refusal'], 'replay_error')
        self.assertNotEqual(case['staging_target'], case['target_after'])
        self.assertEqual(case['target_after'], case['original_alias_after'])
        self.change_corpus(lambda d: self.case(case['name'], d).update(target_replacements=1))

    def test_initial_cap_refusal_precedes_raw_copy_and_clone(self):
        case = self.case('target-entries-4097-noop')
        self.assertEqual((case['raw_copies'], case['constructor_calls'], case['target_clone_calls']), (0, 0, 0))
        self.change_corpus(lambda d: self.case(case['name'], d).update(target_clone_calls=1))

    def test_transient_hex_refusal_preserves_whole_original(self):
        case = self.case('raw-ceiling-transient-hex-refusal')
        self.assertEqual(case['refusal'], 'target_hex_limit')
        self.assertGreater(case['staging_target']['entries'], 0)
        self.assertEqual(case['target_after'], case['target_before'])
        self.change_corpus(lambda d: self.case(case['name'], d).update(refusal=''))

    def test_delete_capacity_and_put_before_delete_remain_distinct(self):
        self.assertEqual(self.case('put-then-delete')['refusal'], 'target_entry_limit')
        self.assertEqual(self.case('delete-then-put')['research_import_result'], 'STAGED')
        self.change_corpus(lambda d: self.case('put-then-delete', d).update(research_import_result='STAGED'))

    def test_selection_failure_never_clones_or_replays(self):
        case = self.case('selection-mismatch-before-clone')
        self.assertEqual((case['raw_copies'], case['constructor_calls'], case['target_clone_calls'], case['default_replay_calls']), (1, 0, 0, 0))
        self.change_corpus(lambda d: self.case(case['name'], d).update(constructor_calls=1))

    def test_source_scope_budget_and_trust_promotion_refused(self):
        for field in ('actual_NodeTree_executed', 'authenticated_snapshot_import', 'production_resource_budgets_qualified',
                      'shared_writer_atomicity', 'map_clone_deep_copies_string_payloads', 'runtime_state_proof_acceptance'):
            self.change_corpus(lambda d: d['scope'].update({field: True}))
        self.change_corpus(lambda d: d['source'].update(revision='00' * 20))

    def test_scalar_types_and_extra_fields_refused(self):
        self.change_corpus(lambda d: d['cases'][0].update(target_replacements=True))
        self.change_corpus(lambda d: d['cases'][0]['target_limits'].update(entries=4096.0))
        self.change_corpus(lambda d: d['cases'][0].update(unknown=1))

    def test_all_144_recorded_samples_and_no_live_execution_claim(self):
        report = CHECK.check_samples(self.samples, self.raw, self.corpus)
        self.assertEqual(report['recorded_fresh_child_samples'], 144)
        self.assertFalse(report['resource_measurements_executed_in_checker'])
        self.assertFalse(report['execution_provenance_authenticated'])
        self.assertFalse(report['production_resource_budgets_qualified'])

    def test_sample_runs_and_complete_inventory_cannot_be_filtered(self):
        self.change_sample(lambda r: r['samples'].pop())
        self.change_sample(lambda r: r['samples'][0].pop())
        self.change_sample(lambda r: r['samples'][0].append(copy.deepcopy(r['samples'][0][0])))
        self.change_sample(lambda r: r['samples'][0].reverse())

    def test_case_mode_repetition_and_conformance_binding_selected(self):
        for field, value in (('case', 'other'), ('mode', 'allocation'), ('repetition', True), ('conformance_sha256', '00' * 32)):
            self.change_sample(lambda r: r['samples'][0][0].update({field: value}))

    def test_elapsed_and_rss_are_positive_unsigned_integers(self):
        for field in ('elapsed_ns', 'process_peak_rss_bytes'):
            for value in (0, -1, True, 1.0, 1 << 64, None):
                self.change_sample(lambda r: r['samples'][0][0].update({field: value}))

    def test_plain_mode_never_claims_allocation_sampling(self):
        for field in ('go_total_alloc_delta_bytes', 'go_mallocs_delta', 'go_gc_cycles'):
            self.change_sample(lambda r: r['samples'][0][0].update({field: 0}))

    def test_allocation_mode_is_cumulative_unsigned_not_peak(self):
        for field in ('go_total_alloc_delta_bytes', 'go_mallocs_delta', 'go_gc_cycles'):
            for value in (None, -1, True, 0.5, 1 << 64):
                self.change_sample(lambda r: r['samples'][0][1].update({field: value}))
        self.change_sample(lambda r: r['samples'][0][1].update(go_peak_alloc_bytes=1))

    def test_process_high_water_method_cannot_be_relabelled(self):
        self.change_sample(lambda r: r['samples'][0][0].update(process_peak_rss_method='operation peak allocation'))
        self.change_sample(lambda r: r.update(production_resource_budgets_qualified=True))

    def test_runtime_and_reference_binary_metadata_bound(self):
        self.change_sample(lambda r: r['samples'][0][0].update(platform='windows/amd64'))
        self.change_sample(lambda r: r['samples'][0][0].update(go_version='go1.26.1'))
        self.change_sample(lambda r: r.update(source_execution_platform='windows'))
        self.change_sample(lambda r: r.update(reference_binary_sha256='zz' * 32))

    def test_failed_command_or_coherent_report_substitution_refused(self):
        self.change_sample(lambda r: r['commands'][0].update(actual_exit=1))
        self.change_sample(lambda r: r['commands'][1].update(completed=False))
        self.change_sample(lambda r: r.update(corpus_sha256='00' * 32))
        self.change_sample(lambda r: r.update(unknown=1))

    def test_duplicate_trailing_json_and_missing_samples_refused(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / 'record.json'
            for raw in (b'{"samples":[],"samples":[]}', self.sample_raw + b'{}'):
                path.write_bytes(raw)
                with self.assertRaises((ValueError, KeyError, TypeError)):
                    CHECK.BYTE.read_corpus(path)
            with self.assertRaises(OSError):
                CHECK.BYTE.read_corpus(Path(root) / 'missing.json')

    def test_cli_consumes_recorded_samples_without_reference_execution(self):
        result = subprocess.run([sys.executable, '-I', '-B', str(HERE / 'check_patch_resources.py')],
            capture_output=True, check=False, timeout=120)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertIn(b'"recorded_fresh_child_samples":144', result.stdout)
        self.assertIn(b'"resource_measurements_executed_in_checker":false', result.stdout)


if __name__ == '__main__':
    unittest.main(verbosity=2)
