#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Controls for independently reconstructed staging and fault boundaries."""
import copy
import importlib.util
from pathlib import Path
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('staging_boundary_check', HERE / 'check_staging_boundary.py')
CHECK = importlib.util.module_from_spec(spec)
spec.loader.exec_module(CHECK)


class StagingBoundaryControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw, cls.corpus = CHECK.BYTE.read_corpus(HERE / 'testdata/candidate-staging-boundary.json')

    def change(self, function):
        document = copy.deepcopy(self.corpus)
        function(document)
        with self.assertRaises((ValueError, KeyError, TypeError)):
            CHECK.check_corpus(document)

    def step(self, document, case, label):
        return next(row for row in document['cases'][case]['steps'] if row['label'] == label)

    def foreign_snapshot(self, document, case, label, versions):
        row = self.step(document, case, label)
        name = document['cases'][case]['name']
        row['reads'] = CHECK.reads(name, versions)
        row['storage'] = CHECK.storage(name, row['frontier']['height'], versions)

    def test_complete_counterexamples_default_control_and_refusal(self):
        report = CHECK.check_corpus(self.corpus)
        self.assertEqual((report['staging_boundary_cases'], report['logical_store_snapshots'], report['read_api_observations']), (7, 50, 1000))
        self.assertEqual((report['custom_Replay_error_returns'], report['default_Batch_Replay_success_returns']), (7, 9))
        self.assertEqual((report['successful_commits_immediately_after_Replay_error'], report['not_staged_commit_refusals']), (4, 3))
        self.assertEqual((report['own_root_boundary_proof_matches'], report['selected_fixture_boundary_proof_mismatches']), (28, 16))
        self.assertEqual((report['root_matches_selected_fixture_cases'], report['consumer_refusals']), (3, 7))
        self.assertFalse(report['default_Batch_Replay_failure_observed'])
        self.assertFalse(report['production_acceptance_enabled'])

    def test_update_failure_keeps_the_previous_replacement_stage(self):
        self.change(lambda d: self.foreign_snapshot(d, 0, 'commit-after-error', {1: CHECK.selected_state(CHECK.NAMES[0])}))

    def test_initial_update_error_before_callbacks_leaves_no_stage(self):
        self.change(lambda d: self.step(d, 2, 'commit-empty-error-refused').update(operation_error=None))

    def test_initial_update_prefix_error_also_leaves_no_stage(self):
        self.change(lambda d: self.step(d, 2, 'commit-first-put-error-refused').update(operation_error=None))

    def test_accumulation_error_retains_the_delivered_prefix(self):
        self.change(lambda d: self.foreign_snapshot(d, 1, 'bulk-after-error', {10: CHECK.complete()}))

    def test_empty_accumulation_error_initializes_a_committable_stage(self):
        self.change(lambda d: self.step(d, 3, 'commit-empty-error').update(operation_error=CHECK.NOT_STAGED))

    def test_first_put_accumulation_error_cannot_commit_the_unreplayed_tail(self):
        self.change(lambda d: self.foreign_snapshot(d, 3, 'commit-first-put-error', {1: {}, 2: CHECK.selected_state(CHECK.NAMES[3])}))

    def test_delivered_delete_changes_the_compressed_graph_and_proof(self):
        def mutate(d):
            state = CHECK.complete(); state[1] = (91).to_bytes(32, 'big')
            self.foreign_snapshot(d, 1, 'bulk-after-error', {10: state})
        self.change(mutate)

    def test_successful_update_replaces_previous_accumulation(self):
        self.change(lambda d: self.foreign_snapshot(d, 4, 'bulk-after-replacement', {10: CHECK.selected_state(CHECK.NAMES[4])}))

    def test_default_accumulation_control_merges_the_complete_sequence(self):
        self.change(lambda d: self.foreign_snapshot(d, 6, 'bulk-after-default-replay', {10: CHECK.selected_state(CHECK.NAMES[3])}))

    def test_clean_reopen_does_not_persist_the_partial_stage(self):
        self.change(lambda d: self.step(d, 5, 'commit-after-reopen-refused').update(operation_error=None))

    def test_recovery_retry_preserves_the_committed_historical_base(self):
        self.change(lambda d: self.foreign_snapshot(d, 5, 'commit-after-retry', {1: CHECK.selected_state(CHECK.NAMES[5]), 2: CHECK.selected_state(CHECK.NAMES[5])}))

    def test_fault_cut_and_recorded_callbacks_are_separately_bound(self):
        self.change(lambda d: self.step(d, 1, 'accumulate-prefix-error').update(fault_after_callbacks=3))
        self.change(lambda d: self.step(d, 3, 'accumulate-empty-error').update(replay_callbacks=[{'operation': 'Put', 'key': CHECK.key(1).hex(), 'value': (91).to_bytes(32, 'big').hex()}]))

    def test_callback_order_and_raw_key_value_binding(self):
        self.change(lambda d: self.step(d, 1, 'accumulate-prefix-error')['replay_callbacks'].reverse())
        self.change(lambda d: self.step(d, 1, 'accumulate-prefix-error')['replay_callbacks'][0].update(key=CHECK.key(2).hex()))
        self.change(lambda d: self.step(d, 1, 'accumulate-prefix-error')['replay_callbacks'][0].update(value=(92).to_bytes(32, 'big').hex()))

    def test_default_replay_is_not_reported_as_an_injected_failure(self):
        self.change(lambda d: self.step(d, 6, 'changes-accumulation').update(operation_error=CHECK.REPLAY_FAILURE))
        self.change(lambda d: d['scope'].update(default_Batch_Replay_failure_observed=True))

    def test_observed_self_consistent_root_cannot_select_the_expected_state(self):
        def mutate(d):
            boundary = d['cases'][1]['boundary']
            boundary['selected_fixture_root'] = boundary['observed_root']
            boundary['root_matches_selected_fixture'] = True
            for proof in boundary['proof_checks']:
                proof['selected_fixture_result'] = proof['own_root_result']
        self.change(mutate)

    def test_matching_healthy_proofs_never_promote_consumer_acceptance(self):
        for index in range(len(CHECK.NAMES)):
            with self.subTest(case=index):
                self.change(lambda d: d['cases'][index]['boundary'].update(consumer_result='ACCEPTED'))

    def test_scalar_types_closed_shapes_and_case_inventory(self):
        self.change(lambda d: d['cases'][0]['steps'][0]['frontier'].update(height=False))
        self.change(lambda d: self.step(d, 3, 'accumulate-empty-error').update(fault_after_callbacks=False))
        self.change(lambda d: d['cases'][0]['boundary'].update(root_matches_selected_fixture=0))
        self.change(lambda d: d['cases'].append(copy.deepcopy(d['cases'][0])))
        self.change(lambda d: d['cases'][0]['steps'][0]['storage'].update(unplanned=True))

    def test_read_json_duplicate_trailing_and_size_bounds(self):
        for raw in (b'{"cases":[],"cases":[]}', self.raw + b'{}', b' ' * (2 * 1024 * 1024 + 1)):
            with self.subTest(bytes=len(raw)), tempfile.TemporaryDirectory() as temporary:
                file = Path(temporary) / 'untrusted.json'
                file.write_bytes(raw)
                with self.assertRaises(ValueError):
                    CHECK.BYTE.read_corpus(file)

    def test_trust_failure_reachability_and_execution_gates_remain_closed(self):
        for field in ('profile_agreed', 'network_activation_authenticated', 'runtime_state_proof_acceptance',
                      'authenticated_retained_version_provenance_qualified', 'production_replay_failure_qualified',
                      'resource_measurements_executed', 'full_node_started', 'network_execution', 'production_crash_recovery_qualified'):
            with self.subTest(field=field):
                self.change(lambda d: d['scope'].update({field: True}))
        self.change(lambda d: d['scope'].update(custom_Patch_Replay_errors_injected=False))
        self.change(lambda d: d['cases'][0]['boundary'].update(production_replay_failure_qualified=True))


if __name__ == '__main__':
    unittest.main(verbosity=2)
