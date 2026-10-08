#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Controls distinguish retained empty versions, absence and missing history."""
import copy
import importlib.util
from pathlib import Path
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('empty_version_check', HERE / 'check_empty_versions.py')
CHECK = importlib.util.module_from_spec(spec)
spec.loader.exec_module(CHECK)


class EmptyVersionControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw, cls.corpus = CHECK.BYTE.read_corpus(HERE / 'testdata/candidate-empty-versions.json')

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

    def test_positive_empty_versions_and_reclaimed_graph(self):
        report = CHECK.check_corpus(self.corpus)
        self.assertEqual((report['empty_version_cases'], report['logical_store_snapshots'], report['read_api_observations']), (3, 39, 1560))
        self.assertEqual((report['retained_empty_root_reads'], report['retained_empty_absence_proof_matches']), (29, 116))
        self.assertEqual(report['committed_frontier_without_physical_nodes_snapshots'], 14)
        self.assertEqual(report['selected_fixture_boundary_proof_matches'], 12)
        self.assertFalse(report['production_acceptance_enabled'])

    def test_unstaged_empty_commit_is_not_success(self):
        self.change(lambda d: self.step(d, 0, 'unstaged-bulk').update(operation_error=None))

    def test_empty_root_requires_retained_version_record(self):
        self.change(lambda d: self.foreign_snapshot(d, 0, 'empty-seed', {}))

    def test_folded_gap_cannot_be_promoted_to_empty_version(self):
        self.change(lambda d: self.foreign_snapshot(d, 0, 'empty-seed', {1: {}, 2: {}, 3: {}}))

    def test_pruned_empty_version_cannot_offer_absence(self):
        self.change(lambda d: self.foreign_snapshot(d, 0, 'prune-empty-seeds', {3: {}, 5: {}, 6: {}}))

    def test_delete_all_reaches_empty_root_not_stored_zero(self):
        self.change(lambda d: self.foreign_snapshot(d, 1, 'delete-all-tail', {3: CHECK.complete(), 4: {0: bytes(32)}}))

    def test_empty_frontier_keeps_still_retained_historical_graph(self):
        self.change(lambda d: self.foreign_snapshot(d, 2, 'last-zero-delete-bulk', {6: {}}))

    def test_pruning_last_nonempty_version_reclaims_all_nodes(self):
        self.change(lambda d: self.foreign_snapshot(d, 1, 'prune-last-nonempty', {3: CHECK.complete(), 4: {}, 6: {}}))

    def test_shared_empty_roots_must_not_have_sentinel_refcounts(self):
        def mutate(d):
            row = self.step(d, 0, 'empty-regular-tail')['storage']
            row['family_counts']['refcount'] = 1
            row['records'] += 1
            row['key_bytes'] += 33
            row['value_bytes'] += 8
        self.change(mutate)

    def test_origin_remains_empty_without_version_record(self):
        def mutate(d):
            row = self.step(d, 0, 'prune-empty-seeds')['reads'][0]
            row['error'] = CHECK.NO_VERSION
        self.change(mutate)

    def test_fresh_nonzero_height_refuses_instead_of_absence(self):
        self.change(lambda d: self.foreign_snapshot(d, 0, 'fresh', {1: {}}))

    def test_deleting_absent_key_preserves_zero_leaf_and_shared_graph(self):
        self.change(lambda d: self.foreign_snapshot(d, 2, 'zero-no-op-tail', {3: {0: bytes(32)}, 4: {}}))

    def test_reinserted_stored_zero_cannot_be_absence_with_coherent_proof(self):
        self.change(lambda d: self.foreign_snapshot(d, 2, 'zero-reinsert-tail', {6: {}, 7: {}}))

    def test_reinserted_nonzero_value_is_bound_to_selected_fixture(self):
        self.change(lambda d: self.foreign_snapshot(d, 1, 'reinsert-tail', {4: {}, 6: {}, 7: {0: bytes(32), 1: (92).to_bytes(32, 'big')}}))

    def test_clean_reopen_cannot_resurrect_pruned_last_leaf(self):
        self.change(lambda d: self.foreign_snapshot(d, 2, 'empty-clean-reopen', {3: {0: bytes(32)}, 4: {0: bytes(32)}, 6: {}}))

    def test_compaction_cannot_change_logical_record_digest(self):
        self.change(lambda d: self.step(d, 0, 'compacted-clean-reopen')['storage'].update(records_sha256='00' * 32))

    def test_coherent_observed_root_cannot_select_its_own_fixture(self):
        def mutate(d):
            row = d['cases'][0]['boundary']
            wrong = {0: bytes(32)}
            root = CHECK.tree(tuple(sorted(wrong.items())))[3]
            row['selected_fixture_root'] = row['observed_root'] = root.hex()
            row['selected_fixture_manifest'] = CHECK.manifest(wrong)
            for proof in row['proof_checks']:
                raw = bytes.fromhex(proof['key'])
                state, levels, values, _ = CHECK.tree(tuple(sorted(wrong.items())))
                value = state.get(CHECK.BYTE.digest(raw))
                proof.update(value=None if value is None else value.hex(),
                             proof=CHECK.BYTE.canonical_proof(levels, values, CHECK.BYTE.digest(raw)).hex())
        self.change(mutate)

    def test_scalar_types_closed_shapes_and_case_inventory(self):
        self.change(lambda d: d['cases'][0]['boundary'].update(root_matches_selected_fixture=1))
        self.change(lambda d: d['cases'][0]['steps'][0]['frontier'].update(height=False))
        self.change(lambda d: d['cases'].append(copy.deepcopy(d['cases'][0])))
        self.change(lambda d: d['cases'][0]['steps'][0]['storage'].update(unplanned=True))

    def test_read_json_duplicate_trailing_and_size_bounds(self):
        for raw in (b'{"cases":[],"cases":[]}', self.raw + b'{}', b' ' * (2 * 1024 * 1024 + 1)):
            with self.subTest(bytes=len(raw)), tempfile.TemporaryDirectory() as temporary:
                file = Path(temporary) / 'untrusted.json'
                file.write_bytes(raw)
                with self.assertRaises(ValueError):
                    CHECK.BYTE.read_corpus(file)

    def test_explicit_trust_and_execution_gates_cannot_be_promoted(self):
        for field in ('profile_agreed', 'network_activation_authenticated', 'runtime_state_proof_acceptance',
                      'authenticated_retained_version_provenance_qualified', 'actual_NodeTree_AccumulateFrom_executed',
                      'resource_measurements_executed', 'full_node_started', 'network_execution'):
            with self.subTest(field=field):
                self.change(lambda d: d['scope'].update({field: True}))


if __name__ == '__main__':
    unittest.main(verbosity=2)
