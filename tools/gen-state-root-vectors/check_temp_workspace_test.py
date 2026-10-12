#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Synthetic workspace envelopes around preserved actual conformance bytes.

The synthetic stat rows below are controls, never new resource measurements.
This suite never builds or executes the candidate node or workspace workload.
"""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('workspace_envelope_controls', HERE / 'check_temp_workspace.py')
CHECK = importlib.util.module_from_spec(spec)
spec.loader.exec_module(CHECK)


def point(sequence, boundary, populated=False):
    row = dict.fromkeys(CHECK.OBS.FIELDS, 0)
    if populated:
        row.update(entries=5, directories=3, regular_files=2, file_bytes=40,
                   allocated_file_bytes=8192, largest_file_bytes=23,
                   input_files=1, input_file_bytes=17, database_files=1,
                   database_file_bytes=23, database_allocated_file_bytes=4096)
    row.update(sequence=sequence, boundary=boundary, started_elapsed_ns=sequence * 100 + 1,
               finished_elapsed_ns=sequence * 100 + 3, observation_elapsed_ns=2)
    return row


def model():
    life = json.loads((HERE / 'testdata/candidate-tree-import-lifecycle-samples.json').read_bytes())
    observations = []
    for generation in life['lifecycle']:
        for child in generation:
            points = [point(0, 'before-spawn'), point(1, 'while-waiting', True), point(2, 'after-reap')]
            observations.append({'label': child['label'], 'method': CHECK.OBS.METHOD,
                'capture_platform': life['phase_samples']['source_execution_platform'],
                'interval_ns': CHECK.OBS.INTERVAL_NS, 'maximum_samples': CHECK.OBS.MAX_SAMPLES,
                'maximum_entries': CHECK.OBS.MAX_ENTRIES, 'maximum_depth': CHECK.OBS.MAX_DEPTH,
                'maximum_file_bytes': CHECK.OBS.MAX_FILE_BYTES, 'capture_exception_type': None,
                'capture_actual_exit': 0, 'capture_reaped': True, 'capture_refusal': '',
                'points': points, 'summary': CHECK.OBS.summary(points)})
    return {'format_version': 1, 'kind': 'candidate-input-database-workspace-samples',
        'source': CHECK.LIFE.SCALE.SCALE.SOURCE, 'scope': CHECK.SCOPE,
        'research_source_inputs': CHECK.input_pins(), 'corpus_sha256': life['corpus_sha256'],
        'lifecycle_samples': life, 'observations': observations,
        'consumer_result': 'REFUSED', 'production_acceptance_enabled': False}


class WorkspaceEnvelopeControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw, cls.corpus = CHECK.BYTE.read_corpus(HERE / 'testdata/candidate-tree-import-scale.json')
        cls.document = model()

    def check(self, document):
        roots = {'lifecycle': CHECK.load('workspace_test_lifecycle', 'reproduce_tree_import_lifecycle.py'),
                 'checks': CHECK.LEGACY.LEGACY}
        with CHECK.LEGACY.PROJECTOR.selected_oracles(roots, 'projected'):
            return CHECK.check_samples(document, self.raw, self.corpus)

    def refusal(self, change):
        document = copy.deepcopy(self.document)
        change(document)
        with self.assertRaises((ValueError, KeyError, TypeError)):
            self.check(document)

    def test_complete_old_bytes_bound_with_new_observation_scope(self):
        report = self.check(self.document)
        self.assertEqual(report['workspace_children_bound'], 24)
        self.assertEqual(report['workspace_stat_observations'], 72)
        self.assertFalse(report['peak_disk_measured'])
        self.assertFalse(report['instantaneous_footprint_measured'])
        self.assertFalse(report['production_acceptance_enabled'])

    def test_unknown_fields_and_peak_or_production_claims_refused(self):
        for key in ('peak_disk_measured', 'instantaneous_footprint_measured',
                    'compiler_peak_memory_measured', 'execution_provenance_authenticated',
                    'production_acceptance_enabled'):
            self.refusal(lambda d, k=key: d['scope'].update({k: True}))
        self.refusal(lambda d: d.update(authenticated_snapshot=True))
        self.refusal(lambda d: d.update(consumer_result='ACCEPTED'))

    def test_child_inventory_failure_and_empty_sampling_refused(self):
        self.refusal(lambda d: d['observations'].pop())
        self.refusal(lambda d: d['observations'][0].update(label='unknown'))
        self.refusal(lambda d: d['observations'][0].update(capture_actual_exit=1))
        self.refusal(lambda d: d['observations'][0].update(capture_exception_type='ValueError'))
        self.refusal(lambda d: d['observations'][0].update(capture_reaped=False))
        self.refusal(lambda d: d['observations'][0]['points'].pop(1))

    def test_summary_source_and_old_conformance_binding_refused(self):
        self.refusal(lambda d: d['observations'][0]['summary'].update(maximum_observed_regular_file_bytes=41))
        self.refusal(lambda d: d['research_source_inputs'].update({'observe_temp_workspace.py': '00' * 32}))
        self.refusal(lambda d: d['lifecycle_samples'].update(corpus_sha256='00' * 32))

    def test_row_types_arithmetic_order_caps_and_other_files_refused(self):
        for change in ({'file_bytes': True}, {'file_bytes': 41}, {'regular_files': 3},
                       {'allocated_file_bytes': 8193}, {'database_allocated_file_bytes': 12288},
                       {'observation_elapsed_ns': 1}, {'sequence': 2},
                       {'entries': CHECK.OBS.MAX_ENTRIES + 1},
                       {'file_bytes': CHECK.OBS.MAX_FILE_BYTES + 1},
                       {'other_files': 1}, {'started_elapsed_ns': 0}):
            row = point(1, 'while-waiting', True)
            row.update(change)
            with self.assertRaises((ValueError, KeyError, TypeError)):
                CHECK.check_row(row, 1, 3)


if __name__ == '__main__':
    unittest.main()
