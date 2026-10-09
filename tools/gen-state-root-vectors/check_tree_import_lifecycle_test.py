#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Portable lifecycle contract controls; model DTOs are not measurements.

Use the preserved real phase corpus and explicit synthetic outer envelopes
for adversarial controls. The separate checker CLI validates the newly recorded
actual lifecycle file. These controls never execute a node or measurement run.
"""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('lifecycle_portable_controls', HERE / 'check_tree_import_lifecycle.py')
CHECK = importlib.util.module_from_spec(spec)
spec.loader.exec_module(CHECK)


def model_control_document(raw, phases):
    """Unsigned contract DTO only; never export it as an actual sample file."""
    capture = CHECK.CAPTURE
    platform = phases['source_execution_platform']
    unit, factor = capture.native_rss_unit(platform)
    count = 394 + len(CHECK.SCALE.BUILD_NAMES) + 1
    workspace = {'method': capture.WORKSPACE_METHOD, 'regular_files': count,
                 'file_bytes': count * 1024, 'largest_file_bytes': 1024,
                 'allocated_file_bytes': count * 4096}
    rows = []
    for generation in range(2):
        group = []
        for measurement, command in zip(phases['samples'][generation], phases['commands'][generation]):
            native = (measurement['process_peak_rss_bytes'] + factor - 1) // factor
            elapsed = sum(x['elapsed_ns'] for x in measurement['phase_resources'])
            elapsed += sum(x['root_elapsed_ns'] + x['proof_elapsed_ns'] for x in measurement['query_timings']) + 1
            group.append({'label': command['label'], 'completed': True, 'process_reaped': True,
                'actual_exit': 0, 'wait_status': 0, 'refusal': '', 'elapsed_ns': elapsed,
                'wall_method': capture.WALL_METHOD, 'poll_ns': capture.POLL_NS,
                'timeout_ns': capture.TIMEOUT_NS, 'rss_method': capture.RSS_METHOD,
                'native_rss_unit': unit, 'native_peak_rss': native, 'process_peak_rss_bytes': native * factor,
                'capture_platform': platform, 'output_method': capture.OUTPUT_METHOD,
                'stdout_bytes': 1024, 'stderr_bytes': 0, 'stdout_ceiling_bytes': capture.OUTPUT_CEILING,
                'stderr_ceiling_bytes': capture.OUTPUT_CEILING, 'captured_regular_files': 2,
                'captured_allocated_file_bytes': 4096, 'stdout_sha256': command['stdout_sha256'],
                'stderr_sha256': command['stderr_sha256'], 'parent_memory_measured': False,
                'source_build_cost_measured': False, 'input_temp_workspace_peak_measured': False,
                'peak_disk_measured': False, 'workspace_before': workspace.copy(), 'workspace_after': workspace.copy()})
        rows.append(group)
    return {'format_version': 1, 'kind': 'candidate-tree-import-lifecycle-samples',
        'source': CHECK.SCALE.SCALE.SOURCE, 'scope': CHECK.SCOPE.copy(),
        'corpus_sha256': CHECK.hashlib.sha256(raw).hexdigest(), 'research_source_inputs': CHECK.input_pins(),
        'phase_samples': phases, 'lifecycle': rows, 'consumer_result': 'REFUSED',
        'production_acceptance_enabled': False}


class TreeImportLifecycleControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw, cls.corpus = CHECK.BYTE.read_corpus(HERE / 'testdata/candidate-tree-import-scale.json')
        _, phases = CHECK.BYTE.read_corpus(HERE / 'testdata/candidate-tree-import-scale-samples.json')
        cls.model = model_control_document(cls.raw, phases)
        CHECK.check_samples(cls.model, cls.raw, cls.corpus)

    def refuse(self, change):
        document = copy.deepcopy(self.model)
        change(document)
        with self.assertRaises((ValueError, KeyError, TypeError)):
            CHECK.check_samples(document, self.raw, self.corpus)

    def change_row(self, **changes):
        self.refuse(lambda d: d['lifecycle'][0][0].update(changes))

    def test_complete_contract_and_preserved_import_query_counts(self):
        report = CHECK.check_samples(self.model, self.raw, self.corpus)
        self.assertEqual(report['recorded_lifecycle_children'], 24)
        self.assertEqual(report['recorded_file_import_calls'], 420)
        self.assertEqual(report['recorded_query_API_calls'], 3024)
        self.assertFalse(report['execution_provenance_authenticated'])

    def test_missing_generation_refused(self):
        self.refuse(lambda d: d['lifecycle'].pop())

    def test_missing_child_refused(self):
        self.refuse(lambda d: d['lifecycle'][1].pop())

    def test_child_reordering_refused(self):
        self.refuse(lambda d: d['lifecycle'][0].reverse())

    def test_child_identity_and_mode_substitution_refused(self):
        self.change_row(label='0-import-4096-16-retain8-0-allocation')

    def test_actual_nonzero_exit_refused(self):
        self.change_row(actual_exit=7)

    def test_boolean_exit_not_zero_refused(self):
        self.change_row(actual_exit=False)

    def test_timeout_or_unreaped_child_refused(self):
        self.change_row(completed=False)
        self.change_row(process_reaped=False)

    def test_raw_wait_status_and_refusal_not_erased(self):
        self.change_row(wait_status=9)
        self.change_row(refusal='output-ceiling')

    def test_elapsed_negative_boolean_or_shorter_than_phases_refused(self):
        for value in (-1, True, 1):
            self.change_row(elapsed_ns=value)

    def test_elapsed_outside_deadline_contract_refused(self):
        self.change_row(elapsed_ns=CHECK.CAPTURE.TIMEOUT_NS * 2)

    def test_wall_scope_cannot_be_rebranded_as_minimum_verifier(self):
        self.change_row(wall_method='minimum verifier import latency')

    def test_poll_or_deadline_policy_mutation_refused(self):
        self.change_row(poll_ns=1)
        self.change_row(timeout_ns=1)

    def test_RSS_below_pre_output_self_observation_refused(self):
        self.change_row(native_peak_rss=1, process_peak_rss_bytes=CHECK.CAPTURE.native_rss_unit(self.model['phase_samples']['source_execution_platform'])[1])

    def test_RSS_negative_or_boolean_refused(self):
        self.change_row(native_peak_rss=-1)
        self.change_row(process_peak_rss_bytes=True)

    def test_RSS_conversion_mismatch_refused(self):
        self.change_row(process_peak_rss_bytes=self.model['lifecycle'][0][0]['process_peak_rss_bytes'] + 1024)

    def test_RSS_native_unit_or_platform_substitution_refused(self):
        self.change_row(native_rss_unit='kilobytes')
        self.change_row(capture_platform='windows')

    def test_RSS_scope_excludes_parent_and_compiler(self):
        self.change_row(rss_method='parent plus compiler peak memory')
        self.change_row(parent_memory_measured=True)
        self.change_row(source_build_cost_measured=True)

    def test_actual_stdout_hash_binding_refused(self):
        self.change_row(stdout_sha256='00' * 32)

    def test_stderr_cannot_be_filtered(self):
        self.change_row(stderr_bytes=1)
        self.change_row(stderr_sha256='00' * 32)

    def test_output_acceptance_ceiling_is_not_removed(self):
        self.change_row(stdout_bytes=CHECK.CAPTURE.OUTPUT_CEILING + 1)
        self.change_row(stdout_ceiling_bytes=CHECK.CAPTURE.OUTPUT_CEILING * 2)

    def test_output_allocated_blocks_are_not_lengths_or_peak_disk(self):
        self.change_row(captured_allocated_file_bytes=1)
        self.change_row(captured_regular_files=1)
        self.change_row(output_method='peak disk of complete workflow')

    def test_copied_build_file_inventory_count_refused(self):
        self.refuse(lambda d: d['lifecycle'][0][0]['workspace_before'].update(regular_files=1))

    def test_copied_build_logical_footprint_changes_refused(self):
        self.refuse(lambda d: d['lifecycle'][0][0]['workspace_after'].update(file_bytes=1))

    def test_workspace_scope_and_unknown_fields_refused(self):
        self.refuse(lambda d: d['lifecycle'][0][0]['workspace_before'].update(method='whole system peak disk'))
        self.refuse(lambda d: d['lifecycle'][0][0]['workspace_after'].update(parent_heap_bytes=1))

    def test_old_phase_sample_binding_stays_required(self):
        self.refuse(lambda d: d['phase_samples']['commands'][0][0].update(result_sha256='00' * 32))

    def test_old_live_harness_heap_scope_stays_separate(self):
        self.refuse(lambda d: d['phase_samples']['samples'][0][0].update(post_gc_heap_method='minimum consumer heap'))

    def test_old_corpus_digest_stays_required(self):
        self.refuse(lambda d: d.update(corpus_sha256='00' * 32))

    def test_new_wrapper_source_is_selected_and_bound(self):
        self.refuse(lambda d: d['research_source_inputs'].update({'capture_child_lifecycle.py': '00' * 32}))

    def test_unknown_source_or_observation_fields_refused(self):
        self.refuse(lambda d: d['research_source_inputs'].update({'unselected.py': '00' * 32}))
        self.change_row(unmeasured_parent_peak_bytes=1)

    def test_parent_whole_pipeline_or_peak_disk_claim_refused(self):
        for key in ('parent_parsing_hashing_or_memory_measured', 'whole_pipeline_memory_measured', 'peak_disk_measured'):
            self.refuse(lambda d: d['scope'].update({key: True}))

    def test_snapshot_header_or_target_budget_claim_refused(self):
        for key in ('real_chain_archive_or_snapshot_executed', 'accepted_header_profile_activation_or_state_value_qualified', 'production_resource_budgets_qualified'):
            self.refuse(lambda d: d['scope'].update({key: True}))

    def test_state_value_acceptance_or_authenticated_execution_refused(self):
        self.refuse(lambda d: d.update(consumer_result='ACCEPTED'))
        self.refuse(lambda d: d.update(production_acceptance_enabled=True))
        self.refuse(lambda d: d['scope'].update(execution_provenance_authenticated=True))

    def test_retry_filtering_or_minimum_consumer_claim_refused(self):
        for key in ('within_batch_retries', 'filtered_samples'):
            self.refuse(lambda d: d['scope'].update({key: 1}))
        self.refuse(lambda d: d['scope'].update(minimum_consumer_memory_qualified=True))


if __name__ == '__main__':
    unittest.main()
