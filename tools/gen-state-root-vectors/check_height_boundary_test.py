#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Controls for maximum-height wrap, origin masking and independent refusal."""
import copy
import importlib.util
from pathlib import Path
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('height_boundary_check', HERE / 'check_height_boundary.py')
CHECK = importlib.util.module_from_spec(spec)
spec.loader.exec_module(CHECK)


class HeightBoundaryControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw, cls.corpus = CHECK.BYTE.read_corpus(HERE / 'testdata/candidate-height-boundary.json')

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

    def test_positive_counterexample_and_consumer_refusals(self):
        report = CHECK.check_corpus(self.corpus)
        self.assertEqual((report['height_boundary_cases'], report['logical_store_snapshots'], report['read_api_observations']), (3, 29, 580))
        self.assertEqual((report['accepted_regular_origin_wraps'], report['wrapped_origin_versions_with_physical_nodes']), (3, 2))
        self.assertEqual((report['own_root_boundary_proof_matches'], report['selected_fixture_boundary_proof_mismatches']), (12, 8))
        self.assertEqual((report['consumer_refusals'], report['root_matches_selected_fixture_cases']), (3, 1))
        self.assertFalse(report['production_acceptance_enabled'])

    def test_regular_wrap_is_observed_success_not_a_claimed_fix(self):
        self.change(lambda d: self.step(d, 0, 'regular-origin-wrap').update(operation_error=CHECK.REGULAR_ORDER))

    def test_maximum_bulk_height_is_not_rounded_to_float(self):
        self.change(lambda d: self.step(d, 0, 'maximum-bulk').update(target_height=float(CHECK.MAXIMUM)))

    def test_bulk_origin_refusal_preserves_staged_changes(self):
        self.change(lambda d: self.step(d, 0, 'bulk-origin-refused').update(operation_error=None))

    def test_bulk_maximum_duplicate_refuses(self):
        self.change(lambda d: self.step(d, 0, 'bulk-maximum-refused').update(operation_error=None))

    def test_regular_one_at_maximum_refuses_without_consuming_stage(self):
        self.change(lambda d: self.step(d, 0, 'regular-one-refused').update(operation_error=None))

    def test_wrapped_origin_keeps_nonempty_physical_version_record(self):
        self.change(lambda d: self.foreign_snapshot(d, 0, 'regular-origin-wrap', {CHECK.MAXIMUM: CHECK.complete(), 0: {}}))

    def test_origin_reads_cannot_expose_the_unreachable_written_root(self):
        def mutate(d):
            row = self.step(d, 0, 'regular-origin-wrap')['reads'][0]
            row['root'] = CHECK.tree(tuple(sorted(CHECK.complete().items())))[3].hex()
        self.change(mutate)

    def test_origin_absence_is_path_bound(self):
        def mutate(d):
            rows = self.step(d, 0, 'regular-origin-wrap')['reads']
            rows[1]['proof'] = rows[2]['proof']
        self.change(mutate)

    def test_next_commit_restarts_from_origin_instead_of_written_version_zero(self):
        def mutate(d):
            changed = CHECK.selected_state(CHECK.NAMES[0])
            self.foreign_snapshot(d, 0, 'regular-one-after-wrap', {CHECK.MAXIMUM: CHECK.complete(), 0: changed, 1: changed})
        self.change(mutate)

    def test_historical_maximum_version_is_still_readable(self):
        self.change(lambda d: self.foreign_snapshot(d, 0, 'regular-one-after-wrap', {0: CHECK.complete(), 1: {8: (9).to_bytes(32, 'big')}}))

    def test_regular_maximum_tail_uses_the_preceding_committed_base(self):
        self.change(lambda d: self.foreign_snapshot(d, 1, 'maximum-regular', {CHECK.MAXIMUM-1: CHECK.complete(), CHECK.MAXIMUM: {1: (91).to_bytes(32, 'big')}}))

    def test_clean_reopen_preserves_masking_and_physical_records(self):
        self.change(lambda d: self.foreign_snapshot(d, 0, 'wrapped-clean-reopen', {CHECK.MAXIMUM: CHECK.complete()}))

    def test_compaction_cannot_qualify_a_different_logical_graph(self):
        self.change(lambda d: self.step(d, 1, 'compacted-clean-reopen')['storage'].update(records_sha256='00' * 32))

    def test_empty_root_match_does_not_qualify_monotonicity(self):
        self.change(lambda d: d['cases'][2]['boundary'].update(monotonic_sequence_qualified=True, consumer_result='ACCEPTED'))

    def test_valid_own_root_proofs_cannot_promote_the_consumer_result(self):
        self.change(lambda d: d['cases'][0]['boundary'].update(consumer_result='ACCEPTED'))

    def test_observed_empty_root_cannot_select_the_expected_fixture(self):
        def mutate(d):
            row = d['cases'][1]['boundary']
            row.update(selected_fixture_root=CHECK.ZERO.hex(), selected_fixture_manifest=CHECK.manifest({}), root_matches_selected_fixture=True)
            for proof in row['proof_checks']:
                proof['selected_fixture_result'] = proof['own_root_result']
        self.change(mutate)

    def test_scalar_types_closed_shapes_and_case_inventory(self):
        self.change(lambda d: d['cases'][0]['steps'][0]['frontier'].update(height=False))
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

    def test_trust_reachability_and_execution_gates_cannot_be_promoted(self):
        for field in ('profile_agreed', 'network_activation_authenticated', 'runtime_state_proof_acceptance',
                      'authenticated_retained_version_provenance_qualified', 'production_height_reachability_qualified',
                      'actual_NodeTree_AccumulateFrom_executed', 'resource_measurements_executed', 'full_node_started', 'network_execution'):
            with self.subTest(field=field):
                self.change(lambda d: d['scope'].update({field: True}))


if __name__ == '__main__':
    unittest.main(verbosity=2)
