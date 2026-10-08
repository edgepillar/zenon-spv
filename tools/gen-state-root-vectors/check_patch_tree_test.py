#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Adversarial controls for finite complete-map seeding and unsigned phase data."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('patch_tree_check', HERE / 'check_patch_tree.py')
CHECK = importlib.util.module_from_spec(spec)
spec.loader.exec_module(CHECK)


class PatchTreeControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw, cls.corpus = CHECK.BYTE.read_corpus(HERE / 'testdata/candidate-patch-tree.json')
        _, cls.samples = CHECK.BYTE.read_corpus(HERE / 'testdata/candidate-patch-tree-samples.json')

    def case(self, name, document=None):
        return next(c for c in (document or self.corpus)['cases'] if c['name'] == name)

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

    def test_complete_inventory_with_closed_consumers(self):
        report = CHECK.check_corpus(self.corpus)
        self.assertEqual((report['patch_tree_cases'], report['research_seed_commits'], report['refusals_before_database_creation']), (11, 4, 7))
        self.assertEqual((report['logical_snapshots'], report['root_and_proof_cells'], report['consumer_refusals']), (16, 512, 11))
        self.assertFalse(report['NodeTree_execution_in_checker'])

    def test_actual_CLI_success_and_invalid_revision(self):
        command = [sys.executable, '-I', '-B', str(HERE / 'check_patch_tree.py')]
        result = subprocess.run(command + ['--source-revision', 'ab' * 20], capture_output=True)
        self.assertEqual((result.returncode, result.stderr), (0, b''))
        self.assertEqual(json.loads(result.stdout)['recorded_fresh_child_samples'], 132)
        result = subprocess.run(command + ['--source-revision', 'invalid'], capture_output=True)
        self.assertEqual((result.returncode, result.stdout), (1, b''))
        self.assertEqual(result.stderr.strip(), b'Candidate tree handoff evidence failed; production acceptance remains disabled.')

    def test_actual_CLI_tampered_case_refuses(self):
        document = copy.deepcopy(self.corpus)
        document['cases'][0]['consumer_result'] = 'ACCEPTED'
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'tampered.json'
            path.write_text(json.dumps(document))
            result = subprocess.run([sys.executable, '-I', '-B', str(HERE / 'check_patch_tree.py'), '--corpus', str(path)], capture_output=True)
        self.assertEqual((result.returncode, result.stdout), (1, b''))

    def test_case_inventory_cannot_be_filtered_or_reordered(self):
        self.bad_corpus(lambda d: d['cases'].pop())
        self.bad_corpus(lambda d: d['cases'].reverse())
        self.bad_corpus(lambda d: d['cases'].append(copy.deepcopy(d['cases'][0])))

    def test_exact_node_and_all_transitive_research_sources_bound(self):
        self.bad_corpus(lambda d: d['source'].update(revision='00' * 20))
        self.bad_corpus(lambda d: d['research_source_inputs'].pop('check_retention.py'))
        self.bad_corpus(lambda d: d['research_source_inputs'].update({'patch_tree_test.go': '00' * 32}))

    def test_input_selection_refusal_precedes_map_clone_and_storage(self):
        case = self.case('file-selection-refusal')
        self.assertEqual(case['handoff_refusal'], 'import_selection_mismatch')
        self.assertEqual((case['import']['constructor_calls'], case['import']['target_clone_calls'], case['database_open_calls']), (0, 0, 0))
        self.assertIsNone(case['preflight_root'])
        self.bad_corpus(lambda d: self.case(case['name'], d).update(database_open_calls=1))

    def test_transient_refusal_preserves_original_and_never_opens_storage(self):
        case = self.case('transient-cap-refusal')
        self.assertEqual(case['handoff_refusal'], 'import_target_entry_limit')
        self.assertEqual(case['import']['target_before'], case['import']['target_after'])
        self.assertEqual(case['import']['staging_callbacks']['count'], 1)
        self.assertEqual((case['tree_update_calls'], case['tree_bulk_commit_calls'], len(case['snapshots'])), (0, 0, 0))
        self.bad_corpus(lambda d: self.case(case['name'], d)['import'].update(target_replacements=1))

    def test_excluded_key_and_empty_value_cannot_seed_a_balance_tree(self):
        for name, reason in (('unsupported-key-refusal', 'unsupported_balance_key'), ('empty-value-refusal', 'unsupported_balance_value')):
            case = self.case(name)
            self.assertEqual(case['import']['research_import_result'], 'STAGED')
            self.assertEqual((case['handoff_refusal'], case['database_open_calls']), (reason, 0))
            self.assertIsNone(case['preflight_root'])
            self.bad_corpus(lambda d: self.case(name, d).update(handoff_refusal=''))

    def test_coherent_omissions_fail_separately_selected_complete_root(self):
        for name in ('omitted-zero-refusal', 'omitted-delete-refusal', 'wrong-selected-root-refusal'):
            case = self.case(name)
            self.assertEqual(case['import']['research_import_result'], 'STAGED')
            self.assertNotEqual(case['preflight_root'], case['selected_root'])
            self.assertEqual((case['handoff_refusal'], case['database_open_calls']), ('selected_root_mismatch', 0))
            self.bad_corpus(lambda d: self.case(name, d).update(selected_root=self.case(name)['preflight_root']))

    def test_stored_zero_has_inclusion_and_is_distinct_from_absence(self):
        rows = self.case('complete-stored-zero')['snapshots'][2]['reads']
        zero = next(r for r in rows if r['identifier']['height'] == 3 and r['key'] == CHECK.GUARD.key(0).hex())
        absent = next(r for r in rows if r['identifier']['height'] == 3 and r['key'] == CHECK.GUARD.key(256).hex())
        self.assertEqual(zero['value'], '00' * 32)
        self.assertIsNone(absent['value'])
        self.assertNotEqual(zero['proof'], absent['proof'])
        self.bad_corpus(lambda d: next(r for r in self.case('complete-stored-zero', d)['snapshots'][2]['reads']
            if r['identifier']['height'] == 3 and r['key'] == CHECK.GUARD.key(0).hex()).update(value=None))

    def test_empty_seed_retains_zero_root_version_without_physical_nodes(self):
        case = self.case('empty-complete')
        self.assertEqual(case['selected_root'], '00' * 32)
        storage = case['snapshots'][2]['storage']
        self.assertEqual(storage['family_counts'], {'frontier': 1, 'format': 1, 'node': 0, 'refcount': 0, 'version': 1})
        self.assertEqual(storage['retained_heights'], [3])
        self.bad_corpus(lambda d: self.case('empty-complete', d)['snapshots'][2]['storage'].update(retained_heights=[]))

    def test_delete_reinsert_builds_complete_final_seed_not_delta(self):
        case = self.case('delete-reinsert')
        self.assertEqual(case['import']['staging_callbacks']['count'], 6)
        self.assertEqual(case['tree_staging_callbacks']['count'], 8)
        self.assertEqual(case['selected_complete_map']['present_keys'], 8)
        self.bad_corpus(lambda d: self.case('delete-reinsert', d)['tree_staging_callbacks'].update(manifest_sha256='00' * 32))

    def test_staging_has_no_stored_version_until_bulk_commit(self):
        case = self.case('complete-256')
        self.assertEqual(case['snapshots'][0]['storage'], case['snapshots'][1]['storage'])
        self.assertEqual(case['snapshots'][1]['storage']['family_counts']['node'], 0)
        self.assertEqual(case['snapshots'][2]['storage']['retained_heights'], [3])
        self.bad_corpus(lambda d: self.case('complete-256', d)['snapshots'][1]['frontier'].update(height=3))

    def test_clean_reopen_preserves_complete_logical_records_and_proofs(self):
        case = self.case('complete-256')
        for field in ('frontier', 'storage', 'reads'):
            self.assertEqual(case['snapshots'][2][field], case['snapshots'][3][field])
        self.bad_corpus(lambda d: self.case('complete-256', d)['snapshots'][3]['storage'].update(records_sha256='00' * 32))

    def test_full_compressed_graph_refcounts_and_frontier_hash_are_bound(self):
        for field in ('node', 'refcount', 'version'):
            self.bad_corpus(lambda d: self.case('complete-stored-zero', d)['snapshots'][2]['storage']['family_counts'].update({field: 0}))
        self.bad_corpus(lambda d: self.case('complete-stored-zero', d)['snapshots'][2]['frontier'].update(hash='00' * 32))

    def test_missing_height_and_canonical_proof_bytes_are_bound(self):
        for field in ('error', 'proof', 'value'):
            self.bad_corpus(lambda d: self.case('complete-stored-zero', d)['snapshots'][2]['reads'][9].update({field: ''}))
        self.bad_corpus(lambda d: self.case('complete-stored-zero', d)['snapshots'][2]['reads'][17].update(proof='00'))

    def test_file_cursor_and_original_alias_survive_all_storage_phases(self):
        for name in CHECK.NAMES:
            case = self.case(name)
            self.assertEqual(case['import']['target_before'], case['import']['original_alias_after'])
            self.assertTrue(case['import']['source_cursor_preserved'])
            self.assertEqual(case['import']['file_before_sha256'], case['import']['file_after_sha256'])
        self.bad_corpus(lambda d: d['cases'][0]['import'].update(source_cursor_preserved=False))

    def test_exact_shapes_and_scalar_types_required(self):
        self.bad_corpus(lambda d: d['cases'][0].update(tree_update_calls=True))
        self.bad_corpus(lambda d: d['cases'][0].update(clean_reopen_calls=1.0))
        self.bad_corpus(lambda d: d['cases'][0].update(extra=1))

    def test_synthetic_roots_and_green_controls_cannot_promote_trust(self):
        for field in ('authenticated_snapshot_import', 'excluded_state_authenticated', 'retained_Momentum_hash_provenance',
                      'accepted_VerifiedState_binding', 'network_activation_authenticated', 'runtime_state_proof_acceptance', 'production_resource_budgets_qualified'):
            self.bad_corpus(lambda d: d['scope'].update({field: True}))

    def test_all_132_sample_and_command_outcomes_are_required(self):
        report = CHECK.check_samples(self.samples, self.raw, self.corpus)
        self.assertEqual(report['recorded_fresh_child_samples'], 132)
        self.bad_samples(lambda r: r['samples'][0].pop())
        self.bad_samples(lambda r: r['commands'][0].pop())
        self.bad_samples(lambda r: r['samples'][0].reverse())

    def test_exact_phase_sequence_cannot_be_merged_reordered_or_filtered(self):
        self.assertEqual(tuple(r['phase'] for r in self.samples['samples'][0][0]['phase_resources']), CHECK.PHASES)
        self.bad_samples(lambda r: r['samples'][0][0]['phase_resources'].pop())
        self.bad_samples(lambda r: r['samples'][0][0]['phase_resources'].reverse())
        self.bad_samples(lambda r: r['samples'][0][0]['phase_resources'][0].update(phase='entire pipeline'))

    def test_elapsed_RSS_and_phase_allocations_have_strict_metric_types(self):
        for value in (0, -1, True, 1.0, None, 1 << 64):
            self.bad_samples(lambda r: r['samples'][0][0]['phase_resources'][0].update(elapsed_ns=value))
            self.bad_samples(lambda r: r['samples'][0][0].update(process_peak_rss_bytes=value))
        for field in ('go_total_alloc_delta_bytes', 'go_mallocs_delta', 'go_gc_cycles'):
            self.bad_samples(lambda r: r['samples'][0][0]['phase_resources'][0].update({field: 0}))
            self.bad_samples(lambda r: r['samples'][0][1]['phase_resources'][0].update({field: None}))
        self.bad_samples(lambda r: r['samples'][0][1]['phase_resources'][0].update(go_peak_alloc_bytes=1))

    def test_closed_file_inventory_is_variable_and_absent_on_refusal(self):
        self.bad_samples(lambda r: r['samples'][0][0].update(closed_database_files={'regular_files': 0, 'bytes': 1}))
        index = next(i for i, row in enumerate(self.samples['samples'][0]) if row['case'] == 'omitted-zero-refusal')
        self.assertIsNone(self.samples['samples'][0][index]['closed_database_files'])
        self.bad_samples(lambda r: r['samples'][0][index].update(closed_database_files={'regular_files': 1, 'bytes': 1}))
        self.bad_samples(lambda r: r['samples'][0][0].update(process_peak_rss_method='operation allocation peak'))

    def test_actual_exits_and_complete_child_result_binding_required(self):
        for field, value in (('actual_exit', 1), ('actual_exit', False), ('completed', False), ('label', 'retry')):
            self.bad_samples(lambda r: r['commands'][0][0].update({field: value}))
        self.bad_samples(lambda r: r['commands'][0][0].update(stderr_sha256='00' * 32))
        self.bad_samples(lambda r: r['samples'][0][0]['phase_resources'][0].update(elapsed_ns=1))

    def test_platform_binary_corpus_and_scope_cannot_be_substituted(self):
        self.bad_samples(lambda r: r.update(reference_binary_sha256='zz' * 32))
        self.bad_samples(lambda r: r.update(corpus_sha256='00' * 32))
        self.bad_samples(lambda r: r.update(source_execution_platform='windows'))
        self.bad_samples(lambda r: r.update(production_resource_budgets_qualified=True))
        self.bad_samples(lambda r: r.update(latency_speedup_qualified=True))


if __name__ == '__main__':
    unittest.main(verbosity=2)
