#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Controls for finite bulk guards and independently selected complete fixtures."""
import copy
import importlib.util
from pathlib import Path
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('bulk_guard_check', HERE / 'check_bulk_guards.py')
CHECK = importlib.util.module_from_spec(spec)
spec.loader.exec_module(CHECK)


class BulkGuardControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw, cls.corpus = CHECK.BYTE.read_corpus(HERE / 'testdata/candidate-bulk-guards.json')

    def refused(self, document):
        with self.assertRaises((ValueError, KeyError, TypeError)):
            CHECK.check_corpus(document)

    def change(self, function):
        document = copy.deepcopy(self.corpus)
        function(document)
        self.refused(document)

    def step(self, document, case, label):
        return next(row for row in document['cases'][case]['steps'] if row['label'] == label)

    def foreign_snapshot(self, document, case, label, state):
        row = self.step(document, case, label)
        name = document['cases'][case]['name']
        height = row['frontier']['height']
        row['reads'] = CHECK.reads(name, {height: state})
        row['storage'] = CHECK.storage(name, height, {height: state})

    def test_positive_guards_fold_and_incomplete_root_refusal(self):
        report = CHECK.check_corpus(self.corpus)
        self.assertEqual((report['bulk_guard_cases'], report['logical_store_snapshots'], report['read_api_observations']), (4, 47, 1880))
        self.assertEqual((report['operation_guard_refusals'], report['incomplete_fixture_root_refusals']), (7, 2))
        self.assertEqual((report['own_root_boundary_proof_matches'], report['selected_complete_fixture_proof_refusals']), (16, 8))
        self.assertFalse(report['production_acceptance_enabled'])
        self.assertFalse(report['native_reference_node_execution'])

    def test_unstaged_commit_cannot_be_promoted_to_success(self):
        self.change(lambda d: self.step(d, 0, 'unstaged-bulk').update(operation_error=None))

    def test_same_and_backward_bulk_heights_are_not_success(self):
        for label in ('origin-bulk-refused', 'same-height-refused', 'backward-height-refused'):
            with self.subTest(label=label):
                self.change(lambda d: self.step(d, 0, label).update(operation_error=None))

    def test_regular_seed_gap_requires_refusal(self):
        self.change(lambda d: self.step(d, 0, 'regular-gap-refused').update(operation='CommitBulk', operation_error=None))

    def test_failed_bulk_does_not_write_frontier(self):
        self.change(lambda d: self.step(d, 0, 'same-height-refused').update(frontier=CHECK.identifier(CHECK.NAMES[0], 5)))

    def test_guard_refusal_preserves_stage_for_retry(self):
        self.change(lambda d: self.foreign_snapshot(d, 0, 'retry-seed-as-bulk', {}))

    def test_success_consumes_staging(self):
        for label in ('consumed-bulk-stage', 'consumed-regular-stage'):
            with self.subTest(label=label):
                self.change(lambda d: self.step(d, 0, label).update(operation_error=None))

    def test_update_cannot_persist_before_commit(self):
        def mutate(d):
            row = self.step(d, 0, 'replace-with-complete-seed')
            row['storage'] = CHECK.storage(CHECK.NAMES[0], 3, {3: CHECK.complete()})
        self.change(mutate)

    def test_no_op_versions_reuse_one_physical_graph(self):
        def mutate(d):
            row = self.step(d, 0, 'retry-empty-bulk')['storage']
            row['family_counts']['node'] *= 2
            row['family_counts']['refcount'] *= 2
        self.change(mutate)

    def test_shared_version_root_references_affect_exact_record_digest(self):
        def mutate(d):
            row = self.step(d, 0, 'regular-no-op-tail')['storage']
            before = self.step(d, 0, 'retry-empty-bulk')['storage']
            row['records_sha256'] = before['records_sha256']
        self.change(mutate)

    def test_pruning_shared_roots_preserves_latest_reachable_nodes(self):
        def mutate(d):
            row = self.step(d, 0, 'prune-shared-roots')
            row['storage'] = CHECK.storage(CHECK.NAMES[0], 6, {3: CHECK.complete(), 5: CHECK.complete(), 6: CHECK.complete()})
        self.change(mutate)

    def test_last_delete_and_reinsert_fold_cannot_be_reversed(self):
        def mutate(d):
            wrong = CHECK.selected_state(CHECK.NAMES[1])
            wrong[1] = (17).to_bytes(32, 'big')
            del wrong[2]
            self.foreign_snapshot(d, 1, 'prune-shared-tail', wrong)
        self.change(mutate)

    def test_stored_zero_is_not_absence_even_with_coherent_foreign_proof(self):
        def mutate(d):
            wrong = CHECK.complete()
            del wrong[0]
            self.foreign_snapshot(d, 0, 'prune-shared-roots', wrong)
        self.change(mutate)

    def test_absence_is_not_stored_zero(self):
        def mutate(d):
            wrong = CHECK.complete()
            wrong[8] = bytes(32)
            self.foreign_snapshot(d, 0, 'prune-shared-roots', wrong)
        self.change(mutate)

    def test_incomplete_seed_may_not_select_its_own_root_as_expected(self):
        def mutate(d):
            row = d['cases'][2]['boundary']
            row['selected_complete_fixture_root'] = row['observed_root']
            row['root_matches_selected_complete_fixture'] = True
            for proof in row['proof_checks']:
                proof['selected_complete_fixture_result'] = 'match'
        self.change(mutate)

    def test_omitted_delete_does_not_authenticate_complete_fixture(self):
        self.change(lambda d: d['cases'][3]['boundary'].update(root_matches_selected_complete_fixture=True))

    def test_selected_raw_map_manifest_cannot_bind_observed_incomplete_map(self):
        def mutate(d):
            partial = CHECK.complete()
            del partial[0]
            d['cases'][2]['boundary']['selected_complete_fixture_manifest'] = CHECK.manifest(partial)
        self.change(mutate)

    def test_scalar_types_closed_shapes_and_case_inventory(self):
        self.change(lambda d: d['cases'][0]['boundary'].update(root_matches_selected_complete_fixture=1))
        self.change(lambda d: d['cases'][0]['steps'][0]['frontier'].update(height=False))
        self.change(lambda d: d['cases'].append(copy.deepcopy(d['cases'][0])))
        self.change(lambda d: d['scope'].update(resource_measurements_executed=True))

    def test_read_json_duplicate_trailing_and_size_bounds(self):
        for raw in (b'{"cases":[],"cases":[]}', self.raw + b'{}', b' ' * (2 * 1024 * 1024 + 1)):
            with self.subTest(bytes=len(raw)), tempfile.TemporaryDirectory() as temporary:
                file = Path(temporary) / 'untrusted.json'
                file.write_bytes(raw)
                with self.assertRaises(ValueError):
                    CHECK.BYTE.read_corpus(file)

    def test_explicit_trust_and_execution_gates_cannot_be_promoted(self):
        for field in ('profile_agreed', 'network_activation_authenticated', 'runtime_state_proof_acceptance',
                      'authenticated_retained_version_provenance_qualified', 'full_node_started', 'network_execution'):
            with self.subTest(field=field):
                self.change(lambda d: d['scope'].update({field: True}))


if __name__ == '__main__':
    unittest.main(verbosity=2)
