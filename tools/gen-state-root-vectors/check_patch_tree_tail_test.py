#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Adversarial controls for recorded file-backed tails and retained graph evidence."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('tree_tail_controls', HERE/'check_patch_tree_tail.py')
CHECK = importlib.util.module_from_spec(spec)
spec.loader.exec_module(CHECK)


class TreeTailControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = (HERE/'testdata/candidate-patch-tree-tail.json').read_bytes()
        cls.corpus = json.loads(cls.raw)
        cls.samples = json.loads((HERE/'testdata/candidate-patch-tree-tail-samples.json').read_bytes())

    def reject_corpus(self, mutate):
        document = copy.deepcopy(self.corpus)
        mutate(document)
        with self.assertRaises((ValueError, KeyError, TypeError, OSError)):
            CHECK.check_corpus(document)

    def reject_samples(self, mutate):
        document = copy.deepcopy(self.samples)
        mutate(document)
        with self.assertRaises((ValueError, KeyError, TypeError, OSError)):
            CHECK.check_samples(document, self.raw, self.corpus)

    def test_complete_recorded_corpus_and_samples(self):
        report = CHECK.check_corpus(self.corpus)
        self.assertEqual((report['patch_tree_tail_cases'], report['research_tail_commits'], report['research_prunes']), (8, 14, 3))
        self.assertEqual(report['refused_tail_handoffs'], 5)
        self.assertEqual(CHECK.check_samples(self.samples, self.raw, self.corpus)['recorded_fresh_child_samples'], 96)

    def test_cli_checks_actual_recorded_inputs(self):
        result = subprocess.run([sys.executable, '-B', str(HERE/'check_patch_tree_tail.py'), '--source-revision', 'a'*40], capture_output=True)
        self.assertEqual(result.returncode, 0)
        self.assertFalse(result.stderr)
        report = json.loads(result.stdout)
        self.assertFalse(report['NodeTree_execution_in_checker'])
        self.assertFalse(report['production_acceptance_enabled'])

    def test_cli_rejects_tampered_actual_report(self):
        document = copy.deepcopy(self.corpus)
        document['scope']['runtime_state_proof_acceptance'] = True
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'corpus.json'
            path.write_text(json.dumps(document))
            result = subprocess.run([sys.executable, '-B', str(HERE/'check_patch_tree_tail.py'), '--corpus', str(path)], capture_output=True)
        self.assertEqual(result.returncode, 1)
        self.assertFalse(result.stdout)

    def test_wrong_source_revision(self):
        result = subprocess.run([sys.executable, '-B', str(HERE/'check_patch_tree_tail.py'), '--source-revision', 'A'*40], capture_output=True)
        self.assertEqual(result.returncode, 1)

    def test_cli_preserves_fixture_byte_limit_and_duplicate_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'corpus.json'
            for raw in (b' '*(CHECK.BYTE.MAX_FILE_BYTES+1), b'{"format_version":1,"format_version":1}'):
                path.write_bytes(raw)
                result = subprocess.run([sys.executable, '-B', str(HERE/'check_patch_tree_tail.py'), '--corpus', str(path)], capture_output=True)
                self.assertEqual(result.returncode, 1)
                self.assertFalse(result.stdout)

    def test_missing_and_duplicate_families(self):
        self.reject_corpus(lambda d: d['cases'].pop())
        self.reject_corpus(lambda d: d['cases'].append(copy.deepcopy(d['cases'][0])))

    def test_root_and_complete_map_bindings(self):
        self.reject_corpus(lambda d: d['cases'][0]['steps'][1].update(selected_root='00'*32))
        self.reject_corpus(lambda d: d['cases'][0]['steps'][1]['selected_complete_map'].update(present_keys=9))

    def test_delete_is_required_in_existing_storage_delta(self):
        events = CHECK.delta({CHECK.GUARD.key(2).hex(): '00'*32}, {})
        self.assertEqual(events, [{'operation': 'Delete', 'key': CHECK.GUARD.key(2).hex(), 'value': None}])
        self.reject_corpus(lambda d: d['cases'][0]['steps'][1]['tree_staging_callbacks'].update(count=0))

    def test_unchanged_leaf_and_noop_root_reuse(self):
        self.assertEqual(CHECK.delta({'x': '00'}, {'x': '00'}), [])
        step = self.corpus['cases'][0]['steps'][3]
        self.assertEqual(step['tree_staging_callbacks']['count'], 0)
        self.assertEqual(step['selected_root'], self.corpus['cases'][0]['steps'][2]['selected_root'])

    def test_stored_zero_and_absence_are_distinct(self):
        case = self.corpus['cases'][2]
        self.assertNotEqual(case['steps'][2]['selected_root'], case['steps'][3]['selected_root'])
        self.assertEqual(case['steps'][2]['selected_complete_map']['present_keys'], 0)
        self.reject_corpus(lambda d: d['cases'][2]['steps'][3]['selected_complete_map'].update(present_keys=0))

    def test_staging_preserves_durable_versions(self):
        case = self.corpus['cases'][0]
        committed = next(s for s in case['snapshots'] if s['label'] == 'committed-3')
        staged = next(s for s in case['snapshots'] if s['label'] == 'staged-4')
        self.assertEqual(committed['storage'], staged['storage'])
        self.assertEqual(committed['reads'], staged['reads'])
        self.reject_corpus(lambda d: d['cases'][0]['snapshots'][3]['storage'].update(records_sha256='00'*32))

    def test_refusal_preserves_previous_committed_tree(self):
        for case in self.corpus['cases'][3:]:
            committed = next(s for s in case['snapshots'] if s['label'] == 'committed-4')
            refused = next(s for s in case['snapshots'] if s['label'] == 'refused-5')
            self.assertEqual((committed['storage'], committed['frontier'], committed['reads']), (refused['storage'], refused['frontier'], refused['reads']))
        self.reject_corpus(lambda d: d['cases'][3].update(tree_tail_commit_calls=2))

    def test_original_aliases_and_source_cursors(self):
        self.reject_corpus(lambda d: d['cases'][0]['original_aliases_after'][0].update(entries=1))
        self.reject_corpus(lambda d: d['cases'][0]['steps'][0]['import'].update(source_cursor_preserved=False))

    def test_actual_file_and_ordered_replay_bindings(self):
        self.reject_corpus(lambda d: d['cases'][0]['steps'][1]['import'].update(file_after_sha256='00'*32))
        self.reject_corpus(lambda d: d['cases'][0]['steps'][1]['import']['staging_callbacks'].update(manifest_sha256='00'*32))

    def test_transient_cap_refusal_and_selected_record_count(self):
        self.assertTrue(self.corpus['cases'][4]['steps'][2]['handoff_refusal'].startswith('import_'))
        self.reject_corpus(lambda d: d['cases'][4]['steps'][2].update(handoff_refusal=''))
        self.reject_corpus(lambda d: d['cases'][3]['steps'][2]['import']['selection'].update(records=2))

    def test_excluded_keys_and_empty_values_refuse(self):
        self.assertEqual(self.corpus['cases'][5]['steps'][2]['handoff_refusal'], 'unsupported_balance_key')
        self.assertEqual(self.corpus['cases'][6]['steps'][2]['handoff_refusal'], 'unsupported_balance_value')
        self.reject_corpus(lambda d: d['cases'][5]['steps'][2].update(consumer_result='ACCEPTED'))

    def test_prune_horizon_and_missing_old_version(self):
        for case in self.corpus['cases'][:3]:
            pruned = next(s for s in case['snapshots'] if s['label'] == 'pruned-5')
            self.assertEqual(pruned['storage']['retained_heights'], [5, 6])
            self.assertEqual(next(r for r in pruned['reads'] if r['identifier']['height'] == 3)['error'], CHECK.GUARD.NO_VERSION)
        self.reject_corpus(lambda d: d['cases'][0]['snapshots'][-2]['storage'].update(retained_heights=[3, 5, 6]))

    def test_shared_refcounts_and_graph_digest(self):
        self.reject_corpus(lambda d: d['cases'][0]['snapshots'][-2]['storage']['family_counts'].update(refcount=0))
        self.reject_corpus(lambda d: d['cases'][0]['snapshots'][-2]['storage'].update(records_sha256='00'*32))

    def test_clean_reopen_preserves_complete_storage_and_queries(self):
        for case in self.corpus['cases']:
            before, after = case['snapshots'][-2:]
            self.assertEqual((before['storage'], before['frontier'], before['reads']), (after['storage'], after['frontier'], after['reads']))
        self.reject_corpus(lambda d: d['cases'][0]['snapshots'][-1]['frontier'].update(hash='00'*32))

    def test_canonical_proof_bytes_and_selected_key(self):
        self.reject_corpus(lambda d: d['cases'][0]['snapshots'][2]['reads'][1].update(proof='00'))
        self.reject_corpus(lambda d: d['cases'][0]['snapshots'][2]['reads'][1].update(key=CHECK.GUARD.key(1).hex()))

    def test_source_hashes_and_scope_cannot_be_promoted(self):
        self.reject_corpus(lambda d: d['research_source_inputs'].update({'patch_tree_tail_test.go': '00'*32}))
        self.reject_corpus(lambda d: d['scope'].update(retained_Momentum_hash_provenance=True))
        self.reject_corpus(lambda d: d['scope'].update(production_resource_budgets_qualified=True))

    def test_all_actual_outcomes_and_generations_required(self):
        self.reject_samples(lambda d: d['commands'][0].pop())
        self.reject_samples(lambda d: d['samples'].pop())
        self.reject_samples(lambda d: d['commands'][0][0].update(actual_exit=1))

    def test_sample_identity_phase_order_and_closed_files(self):
        self.reject_samples(lambda d: d['samples'][0][0].update(repetition=1))
        self.reject_samples(lambda d: d['samples'][0][0]['phase_resources'].reverse())
        self.reject_samples(lambda d: d['samples'][0][0].update(closed_database_files=None))

    def test_plain_allocation_scalar_and_RSS_boundaries(self):
        self.reject_samples(lambda d: d['samples'][0][0]['phase_resources'][0].update(go_total_alloc_delta_bytes=0))
        self.reject_samples(lambda d: d['samples'][0][1]['phase_resources'][0].update(elapsed_ns=True))
        self.reject_samples(lambda d: d['samples'][0][0].update(process_peak_rss_method='phase allocation'))
        self.reject_samples(lambda d: d.update(reference_binary_sha256='bad'))


if __name__ == '__main__':
    unittest.main(verbosity=2)
