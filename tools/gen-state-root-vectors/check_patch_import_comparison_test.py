#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Adversarial controls for selected prior/candidate import evidence."""
import copy
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('owned_import_comparison', HERE / 'check_patch_import_comparison.py')
CHECK = importlib.util.module_from_spec(spec)
spec.loader.exec_module(CHECK)


class ImportComparisonControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw, cls.record = CHECK.RESOURCE.BYTE.read_corpus(HERE / 'testdata/candidate-patch-import-comparison.json')

    def changed(self, change):
        record = copy.deepcopy(self.record)
        change(record)
        with self.assertRaises((ValueError, KeyError, TypeError)):
            CHECK.check(record)

    def test_complete_comparison_and_closed_production_boundary(self):
        report = CHECK.check(self.record)
        self.assertEqual(report['recorded_fresh_child_samples'], 288)
        self.assertEqual(report['recorded_local_Go_ownership_controls'], 36)
        self.assertFalse(report['execution_provenance_authenticated'])
        self.assertFalse(report['resource_measurements_executed_in_checker'])
        self.assertFalse(report['production_acceptance_enabled'])

    def test_prior_revision_blob_and_bytes_are_fixed(self):
        for key, value in (('revision', '00' * 20), ('git_blob', '00' * 20), ('sha256', '00' * 32), ('bytes', 0)):
            self.changed(lambda r: r['baseline_source'].update({key: value}))

    def test_selected_candidate_and_harness_bytes_are_bound(self):
        for name in ('patch_import.go', 'patch_resources.go', 'patch_import_ownership_test.go', 'source-pins.json'):
            self.changed(lambda r: r['selected_input_pins'][name].update(sha256='00' * 32))
        self.changed(lambda r: r['selected_input_pins'].pop('go.sum'))

    def test_missing_extra_or_relabelled_roles_refused(self):
        self.changed(lambda r: r['reports'].pop('baseline'))
        self.changed(lambda r: r['reports'].update(other=r['reports']['candidate']))
        self.changed(lambda r: r['ownership_controls'].pop('candidate'))

    def test_generation_or_sample_discard_refused(self):
        self.changed(lambda r: r['reports']['baseline']['samples'].pop())
        self.changed(lambda r: r['reports']['candidate']['samples'][0].pop())

    def test_execution_order_and_sample_order_bound(self):
        self.changed(lambda r: r['execution_order'].reverse())
        self.changed(lambda r: r['reports']['baseline']['samples'][0].reverse())

    def test_complete_callback_and_map_conformance_binding_bound(self):
        self.changed(lambda r: r['reports']['candidate']['samples'][0][0].update(conformance_sha256='00' * 32))

    def test_same_binary_cannot_stand_for_two_selected_importers(self):
        self.changed(lambda r: r['reports']['candidate'].update(reference_binary_sha256=r['reports']['baseline']['reference_binary_sha256']))

    def test_runtime_mismatch_between_roles_refused(self):
        self.changed(lambda r: r['reports']['candidate'].update(go_version='go version go1.25.15 darwin/arm64'))

    def test_budget_speedup_and_authentication_promotion_refused(self):
        for name in ('latency_speedup_qualified', 'production_resource_budgets_qualified', 'execution_provenance_authenticated',
                     'actual_NodeTree_executed', 'authenticated_snapshot_import', 'runtime_state_proof_acceptance'):
            self.changed(lambda r: r['scope'].update({name: True}))

    def test_failed_or_incomplete_local_Go_controls_refused(self):
        self.changed(lambda r: r['ownership_controls']['baseline']['command'].update(actual_exit=1))
        self.changed(lambda r: r['ownership_controls']['candidate']['command'].update(completed=False))

    def test_missing_or_extra_ownership_test_refused(self):
        self.changed(lambda r: r['ownership_controls']['candidate']['tests'].pop())
        self.changed(lambda r: r['ownership_controls']['baseline']['tests'].append('unselected'))

    def test_duplicated_role_report_refused(self):
        self.changed(lambda r: r['reports'].update(candidate=copy.deepcopy(r['reports']['baseline'])))

    def test_integer_and_boolean_substitution_refused(self):
        self.changed(lambda r: r.update(format_version=True))
        self.changed(lambda r: r['ownership_controls']['candidate']['command'].update(actual_exit=False))

    def test_selected_corpus_cannot_be_substituted(self):
        self.changed(lambda r: r.update(corpus_sha256='00' * 32))
        self.changed(lambda r: r['reports']['baseline'].update(corpus_sha256='00' * 32))

    def test_metrics_and_allocation_nullability_remain_separate(self):
        self.changed(lambda r: r['reports']['candidate']['samples'][0][0].update(go_total_alloc_delta_bytes=0))
        self.changed(lambda r: r['reports']['baseline']['samples'][0][1].update(go_total_alloc_delta_bytes=-1))

    def test_command_output_digest_spelling_bound(self):
        self.changed(lambda r: r['ownership_controls']['baseline']['command'].update(stdout_sha256='zz' * 32))
        self.changed(lambda r: r['reports']['candidate']['commands'][0].update(stderr_sha256=None))

    def test_unknown_fields_and_false_completed_generation_refused(self):
        self.changed(lambda r: r.update(unknown=1))
        self.changed(lambda r: r['reports']['candidate']['commands'][1].update(completed=False))

    def test_duplicate_or_trailing_JSON_refused(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / 'report.json'
            for raw in (b'{"reports":{},"reports":{}}', self.raw + b'{}'):
                path.write_bytes(raw)
                with self.assertRaises((ValueError, TypeError, KeyError)):
                    CHECK.RESOURCE.BYTE.read_corpus(path)

    def test_unselected_baseline_is_rejected_before_any_Go_execution(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            path = root / 'unselected.go'
            path.write_bytes(b'package main\n')
            result = subprocess.run([sys.executable, '-I', '-B', str(HERE / 'compare_patch_import.py'),
                '--baseline-import-source', str(path), '--node-source', str(root / 'missing-node'),
                '--go', str(root / 'missing-go'), '--output', str(root / 'out.json'),
                '--evidence-directory', str(root / 'evidence')], capture_output=True, timeout=30)
            self.assertEqual(result.returncode, 1)
            self.assertFalse((root / 'out.json').exists())
            self.assertFalse((root / 'evidence').exists())

    def test_cli_checks_recorded_evidence_without_reference_execution(self):
        result = subprocess.run([sys.executable, '-I', '-B', str(HERE / 'check_patch_import_comparison.py')],
            capture_output=True, timeout=120)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertIn(b'"recorded_fresh_child_samples":288', result.stdout)
        self.assertIn(b'"resource_measurements_executed_in_checker":false', result.stdout)


if __name__ == '__main__':
    unittest.main(verbosity=2)
