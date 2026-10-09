#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Portable complete-driver controls; synthetic envelopes are not measurements.

No source build, NodeTree child or resource observer executes. Complete stock
bytes and old lifecycle contracts stay mandatory beneath the new envelope.
"""
import copy
import hashlib
import importlib.util
from pathlib import Path
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('projected_driver_controls', HERE / 'check_projected_driver.py')
CHECK = importlib.util.module_from_spec(spec)
spec.loader.exec_module(CHECK)
OLD_CONTROLS = CHECK.load('explicit_driver_DTO_only', 'check_tree_driver_resources_test.py')


def bind_stdout(document):
    for sample in document['samples']:
        raw = CHECK.encoded(CHECK.worker_document(sample, document))
        sample['command']['stdout_sha256'] = hashlib.sha256(raw).hexdigest()


def model_document(life, raw):
    samples = []
    for generation, mode in CHECK.inventory():
        previous = OLD_CONTROLS.model_document(copy.deepcopy(life))
        name = CHECK.label(generation, mode)
        previous['driver']['label'] = name
        previous['build']['label'] = 'selected-go-build'
        samples.append({'generation': generation, 'mode': mode, 'oracle_bindings': CHECK.bindings(),
            'result_bytes': len(raw), 'result_sha256': hashlib.sha256(raw).hexdigest(),
            'delegate_stdout_sha256': hashlib.sha256(CHECK.DELEGATE_STDOUT).hexdigest(),
            'lifecycle_samples': previous['lifecycle_samples'], 'driver': previous['driver'],
            'build': previous['build'], 'build_command': previous['build_command'],
            'command': {'label': name, 'completed': True, 'actual_exit': 0,
                'stdout_sha256': '00' * 32, 'stderr_sha256': hashlib.sha256(b'').hexdigest()}})
    document = {'format_version': 1, 'kind': 'selected-complete-driver-projection-comparison',
        'source': CHECK.LEGACY.LIFE.SCALE.SCALE.SOURCE, 'reference': CHECK.REFERENCE,
        'scope': copy.deepcopy(CHECK.SCOPE), 'corpus_sha256': hashlib.sha256(raw).hexdigest(),
        'research_source_inputs': CHECK.input_pins(), 'runtime': {'os': 'darwin', 'architecture': 'arm64',
            'python': '3.9.6', 'implementation': 'CPython'}, 'python_executable_sha256': '11' * 32,
        'go_executable_sha256': '22' * 32, 'cache_policy': CHECK.LEGACY.CACHE_POLICY,
        'samples': samples, 'consumer_result': 'REFUSED', 'production_acceptance_enabled': False}
    bind_stdout(document)
    return document


class CompleteDriverProjectionControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw, cls.corpus = CHECK.BYTE.read_corpus(HERE / 'testdata/candidate-tree-import-scale.json')
        _, life = CHECK.BYTE.read_corpus(HERE / 'testdata/candidate-tree-import-lifecycle-samples.json')
        cls.model = model_document(life, cls.raw)
        CHECK.check_contract(cls.model, cls.raw, cls.corpus)
        cls.lifecycle = CHECK.load('control_isolated_lifecycle_no_execution', 'reproduce_tree_import_lifecycle.py')
        cls.roots = {'lifecycle': cls.lifecycle, 'checks': CHECK.LEGACY}

    def refuse(self, change, rebind=True):
        document = copy.deepcopy(self.model)
        change(document)
        if rebind:
            bind_stdout(document)
        with self.assertRaises((ValueError, KeyError, TypeError)):
            CHECK.check_contract(document, self.raw, self.corpus)

    def test_complete_stock_bytes_and_all_96_lifecycle_children_required(self):
        report = CHECK.check_samples(self.model, self.raw, self.corpus)
        self.assertEqual(report['recorded_reference_children'], 96)
        self.assertEqual(report['recorded_build_commands'], 4)
        self.assertTrue(report['independent_stock_complete_byte_oracle_required'])
        self.assertFalse(report['new_resource_measurements'])

    def test_all_three_seams_and_both_literal_query_sets_selected(self):
        self.assertEqual(CHECK.PROJECTOR.binding_manifest(self.roots), CHECK.bindings())
        paths = CHECK.PROJECTOR.selected_paths()
        self.assertEqual(len(paths), 7)
        for selection in CHECK.PROJECTOR.PROJECT.IMPORT.SELECTIONS:
            self.assertLessEqual(set(CHECK.PROJECTOR.PROJECT.selected_paths(selection)), set(paths))

    def test_projected_context_changes_and_restores_every_original_identity(self):
        seams = CHECK.PROJECTOR.selected_seams(self.roots)
        with CHECK.PROJECTOR.selected_oracles(self.roots, 'projected'):
            for _, module, original in seams:
                self.assertIsNot(module.scale_levels, original)
        for _, module, original in seams:
            self.assertIs(module.scale_levels, original)

    def test_reference_context_preserves_original_identities(self):
        seams = CHECK.PROJECTOR.selected_seams(self.roots)
        with CHECK.PROJECTOR.selected_oracles(self.roots, 'reference'):
            for _, module, original in seams:
                self.assertIs(module.scale_levels, original)

    def test_actual_exception_restores_all_seams(self):
        seams = CHECK.PROJECTOR.selected_seams(self.roots)
        with self.assertRaises(RuntimeError):
            with CHECK.PROJECTOR.selected_oracles(self.roots, 'projected'):
                raise RuntimeError('selected control failure')
        for _, module, original in seams:
            self.assertIs(module.scale_levels, original)

    def test_unexpected_in_context_replacement_restores_every_seam_before_refusal(self):
        seams = CHECK.PROJECTOR.selected_seams(self.roots)
        with self.assertRaises(ValueError):
            with CHECK.PROJECTOR.selected_oracles(self.roots, 'projected'):
                seams[1][1].scale_levels = lambda state: None
        for _, module, original in seams:
            self.assertIs(module.scale_levels, original)

    def test_unknown_preexisting_seam_is_refused_before_any_mutation(self):
        seams = CHECK.PROJECTOR.selected_seams(self.roots)
        with mock.patch.object(seams[-1][1], 'scale_levels', lambda state: None):
            with self.assertRaises(ValueError):
                with CHECK.PROJECTOR.selected_oracles(self.roots, 'projected'):
                    self.fail('unselected function accepted')
            for _, module, original in seams[:-1]:
                self.assertIs(module.scale_levels, original)

    def test_nested_concurrent_projection_and_unknown_mode_are_refused(self):
        with CHECK.PROJECTOR.selected_oracles(self.roots, 'projected'):
            with self.assertRaises(ValueError):
                with CHECK.PROJECTOR.selected_oracles(self.roots, 'projected'):
                    self.fail('nested mutation accepted')
        for mode in ('other', True, None):
            with self.assertRaises(ValueError):
                with CHECK.PROJECTOR.selected_oracles(self.roots, mode):
                    self.fail('unselected mode accepted')

    def test_unknown_roots_module_graph_ceiling_or_extra_seam_are_refused(self):
        with self.assertRaises(ValueError):
            CHECK.PROJECTOR.selected_seams({'checks': CHECK.LEGACY})
        with mock.patch.object(CHECK.PROJECTOR, 'MAX_MODULES', 2):
            with self.assertRaises(ValueError):
                CHECK.PROJECTOR.selected_seams(self.roots)
        extra = CHECK.load('control_extra_scale_seam', 'check_tree_scale.py')
        with mock.patch.object(self.lifecycle, 'unselected_extra', extra, create=True):
            with self.assertRaises(ValueError):
                CHECK.PROJECTOR.selected_seams(self.roots)

    def test_identity_alias_deduplication_does_not_duplicate_selected_seams(self):
        with mock.patch.object(self.lifecycle, 'z_alias', self.lifecycle.CHECK, create=True):
            self.assertEqual(CHECK.PROJECTOR.binding_manifest(self.roots), CHECK.bindings())

    def test_projected_driver_seams_hash_unselected_leaves_and_refuse_unknown_queries(self):
        paths = CHECK.PROJECTOR.selected_paths()
        state = {p: bytes(32) for p in paths[:2]}
        state[CHECK.BYTE.digest(b'unselected-driver-leaf')] = bytes(32)
        with CHECK.PROJECTOR.selected_oracles(self.roots, 'projected'):
            for _, module, _ in self.original_seams():
                levels, values = module.scale_levels(state)
                self.assertEqual(levels[0].get(0, CHECK.BYTE.ZERO), CHECK.RET.graph(state)[1])
                for path in paths:
                    proof = CHECK.BYTE.canonical_proof(levels, values, path)
                    self.assertEqual(CHECK.BYTE.proof_result(levels[0].get(0, CHECK.BYTE.ZERO),
                        path, state.get(path, b''), proof, path in state), 'match')
                with self.assertRaises(ValueError):
                    CHECK.BYTE.canonical_proof(levels, values, CHECK.BYTE.digest(b'unknown-driver-query'))

    def original_seams(self):
        # A selected context is active; retrieve module identities via fixed roots.
        return [(CHECK.PROJECTOR.SEAM_PATHS[0], CHECK.LEGACY.LIFE.SCALE.SCALE, None),
            (CHECK.PROJECTOR.SEAM_PATHS[1], self.lifecycle.CHECK.SCALE.SCALE, None),
            (CHECK.PROJECTOR.SEAM_PATHS[2], self.lifecycle.ORIGINAL.CHECK.SCALE, None)]

    def test_counterbalanced_order_missing_duplicate_or_extra_worker_refused(self):
        self.assertEqual([(s['generation'], s['mode']) for s in self.model['samples']], CHECK.inventory())
        self.refuse(lambda d: d['samples'].reverse())
        self.refuse(lambda d: d['samples'].pop())
        self.refuse(lambda d: d['samples'].append(copy.deepcopy(d['samples'][0])))

    def test_boolean_generation_or_relabelled_mode_refused(self):
        self.refuse(lambda d: d['samples'][0].update(generation=True))
        self.refuse(lambda d: d['samples'][0].update(mode='projected'))

    def test_corpus_result_full_size_hash_and_partial_delegate_output_required(self):
        for changes in ({'result_bytes': 1}, {'result_sha256': '00' * 32}, {'delegate_stdout_sha256': '00' * 32}):
            self.refuse(lambda d: d['samples'][0].update(changes))

    def test_coherent_forged_corpus_requires_unchanged_stock_oracle(self):
        corpus = copy.deepcopy(self.corpus)
        corpus['cases'][0]['steps'][0]['preflight_root'] = '00' * 32
        raw = CHECK.encoded(corpus)
        forged = model_document(self.model['samples'][0]['lifecycle_samples'], raw)
        for sample in forged['samples']:
            sample['lifecycle_samples']['corpus_sha256'] = hashlib.sha256(raw).hexdigest()
            sample['lifecycle_samples']['phase_samples']['corpus_sha256'] = hashlib.sha256(raw).hexdigest()
        bind_stdout(forged)
        CHECK.check_contract(forged, raw, corpus)
        with self.assertRaises(ValueError):
            CHECK.check_samples(forged, raw, corpus)

    def test_original_child_stdout_binding_still_required(self):
        document = copy.deepcopy(self.model)
        document['samples'][0]['lifecycle_samples']['lifecycle'][0][0]['stdout_sha256'] = '00' * 32
        bind_stdout(document)
        with self.assertRaises(ValueError):
            CHECK.check_samples(document, self.raw, self.corpus)

    def test_build_exit_boolean_stderr_or_extra_inventory_refused(self):
        for changes in ({'actual_exit': 1}, {'actual_exit': False}, {'stderr_sha256': '00' * 32}, {'builds': 2}):
            self.refuse(lambda d: d['samples'][0]['build_command'].update(changes))

    def test_worker_actual_stdout_not_replaceable_by_partial_reencoding(self):
        self.refuse(lambda d: d['samples'][0]['command'].update(stdout_sha256='00' * 32), rebind=False)

    def test_worker_exit_stderr_and_incomplete_recording_refused(self):
        for changes in ({'actual_exit': 2}, {'actual_exit': False}, {'completed': False}, {'stderr_sha256': '00' * 32}):
            self.refuse(lambda d: d['samples'][0]['command'].update(changes))

    def test_unreturned_call_exception_or_negative_boolean_counters_refused(self):
        for changes in ({'call_returned': False}, {'exception_type': 'TimeoutExpired'}, {'elapsed_ns': True},
                        {'elapsed_ns': -1}, {'self_user_cpu_delta_ns': -1}):
            self.refuse(lambda d: d['samples'][0]['driver'].update(changes))

    def test_selected_wall_cannot_exclude_build_or_children(self):
        self.refuse(lambda d: d['samples'][0]['driver'].update(elapsed_ns=1))
        self.refuse(lambda d: d['samples'][0]['driver'].update(elapsed_ns=CHECK.LEGACY.MAX_DRIVER_WALL_NS + 1))

    def test_build_counters_and_lifetime_RSS_must_be_nested(self):
        self.refuse(lambda d: d['samples'][0]['build']['before']['self'].update(user_cpu_ns=999_999_999))
        self.refuse(lambda d: d['samples'][0]['build']['after']['self'].update(native_peak_rss=999_999_999))

    def test_RSS_unit_conversion_and_counter_delta_cannot_be_substituted(self):
        self.refuse(lambda d: d['samples'][0]['driver']['after']['self'].update(native_rss_unit='KiB'))
        self.refuse(lambda d: d['samples'][0]['driver']['after']['self'].update(process_peak_rss_bytes=1))
        self.refuse(lambda d: d['samples'][0]['build'].update(waited_children_user_cpu_delta_ns=1))

    def test_reference_source_new_inputs_and_seam_bindings_required(self):
        self.refuse(lambda d: d['reference'].update(revision='00' * 20))
        self.refuse(lambda d: d['research_source_inputs'].update({'project_driver_oracles.py': '00' * 32}))
        self.refuse(lambda d: d['samples'][0]['oracle_bindings']['level_seams'].pop())
        self.refuse(lambda d: d['samples'][0]['oracle_bindings']['selected_paths'].pop())

    def test_different_binaries_or_Go_versions_are_refused(self):
        self.refuse(lambda d: d['samples'][1]['lifecycle_samples']['phase_samples'].update(reference_binary_sha256='33' * 32))
        self.refuse(lambda d: d['samples'][1]['lifecycle_samples']['phase_samples'].update(go_version='go version go1.25.15 darwin/arm64'))

    def test_python_or_Go_executable_and_runtime_shape_are_bound(self):
        self.refuse(lambda d: d.update(python_executable_sha256='unknown'))
        self.refuse(lambda d: d.update(go_executable_sha256='unknown'))
        self.refuse(lambda d: d['runtime'].update(os='win32'))
        self.refuse(lambda d: d['runtime'].update(architecture='x86_64'))

    def test_preparation_final_checks_and_controller_scopes_cannot_be_relabelled(self):
        for k in ('expected_corpus_preparation_delegation_final_checks_encoding_and_inner_persistence_in_observed_call',
                  'all_three_level_seams_selected_in_each_driver', 'projected_mode_changes_all_three_level_seams'):
            self.refuse(lambda d: d['scope'].update({k: False}))
        for k in ('controller_stock_oracle_check_or_memory_measured', 'hard_whole_worker_deadline_enforced',
                  'final_resource_report_encoding_persistence_and_exit_measured'):
            self.refuse(lambda d: d['scope'].update({k: True}))

    def test_methods_cannot_claim_interval_RSS_or_nanosecond_CPU_precision(self):
        self.refuse(lambda d: d['samples'][0]['driver'].update(self_method='interval RSS difference'))
        self.refuse(lambda d: d['samples'][0]['build'].update(cpu_storage_method='native nanosecond precision'))

    def test_cold_cache_hardware_pipeline_memory_or_production_budget_stay_unqualified(self):
        self.refuse(lambda d: d.update(cache_policy='authenticated cold compiler cache'))
        for k in ('cold_or_warm_cache_state_qualified', 'execution_provenance_authenticated',
                  'target_hardware_identity_authenticated', 'compiler_peak_memory_measured',
                  'whole_pipeline_memory_measured', 'peak_disk_measured', 'production_resource_budgets_qualified'):
            self.refuse(lambda d: d['scope'].update({k: True}))

    def test_real_snapshot_header_activation_finality_or_state_value_claims_refused(self):
        self.refuse(lambda d: d.update(consumer_result='ACCEPTED'))
        self.refuse(lambda d: d.update(production_acceptance_enabled=True))
        for k in ('real_chain_archive_or_snapshot_executed', 'accepted_header_profile_activation_or_state_value_qualified',
                  'canonicality_finality_freshness_qualified', 'network_wallet_signing_or_transactions_executed'):
            self.refuse(lambda d: d['scope'].update({k: True}))


if __name__ == '__main__':
    unittest.main(verbosity=2)
