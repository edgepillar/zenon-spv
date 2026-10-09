#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Portable adversarial driver envelope controls; DTOs are not measurements.

Use explicit synthetic parent/build counters around preserved actual child
bytes. The checker CLI separately validates the actual newly recorded report.
No resource observation, Go build or reference child executes in this suite.
"""
import copy
import importlib.util
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('driver_portable_controls', HERE / 'check_tree_driver_resources.py')
CHECK = importlib.util.module_from_spec(spec)
spec.loader.exec_module(CHECK)


def model_document(lifecycle):
    platform = lifecycle['phase_samples']['source_execution_platform']
    unit, factor = CHECK.OBS.native_rss_unit(platform)

    def snapshot(counter):
        native = (16 << 20) // factor + counter
        return {'self': {'native_peak_rss': native, 'native_rss_unit': unit,
                'process_peak_rss_bytes': native * factor,
                'user_cpu_ns': counter * 1000, 'system_cpu_ns': counter * 2000},
                'waited_children_cpu': {'user_cpu_ns': counter * 3000, 'system_cpu_ns': counter * 4000}}

    def observation(label, start, end, elapsed):
        return {'label': label, 'call_returned': True, 'exception_type': None,
            'capture_platform': platform, 'elapsed_ns': elapsed,
            'wall_method': CHECK.OBS.WALL_METHOD, 'self_method': CHECK.OBS.SELF_METHOD,
            'child_cpu_method': CHECK.OBS.CHILD_CPU_METHOD, 'cpu_storage_method': CHECK.OBS.CPU_METHOD,
            'before': snapshot(start), 'after': snapshot(end),
            'self_user_cpu_delta_ns': (end - start) * 1000,
            'self_system_cpu_delta_ns': (end - start) * 2000,
            'waited_children_user_cpu_delta_ns': (end - start) * 3000,
            'waited_children_system_cpu_delta_ns': (end - start) * 4000}

    build_wall = 1_000_000_000
    child_wall = sum(r['elapsed_ns'] for g in lifecycle['lifecycle'] for r in g)
    empty_hash = CHECK.hashlib.sha256(b'').hexdigest()
    return {'format_version': 1, 'kind': 'candidate-tree-driver-resource-samples',
        'source': CHECK.LIFE.SCALE.SCALE.SOURCE, 'scope': CHECK.SCOPE.copy(),
        'corpus_sha256': lifecycle['corpus_sha256'], 'research_source_inputs': CHECK.input_pins(),
        'cache_policy': CHECK.CACHE_POLICY, 'lifecycle_samples': lifecycle,
        'driver': observation('lifecycle-driver', 0, 10, child_wall + build_wall + 1),
        'build': observation('go-build-tests', 2, 4, build_wall),
        'build_command': {'label': 'go-build-tests', 'completed': True, 'actual_exit': 0,
                          'stdout_sha256': empty_hash, 'stderr_sha256': empty_hash},
        'consumer_result': 'REFUSED', 'production_acceptance_enabled': False}


class TreeDriverResourceControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw, cls.corpus = CHECK.BYTE.read_corpus(HERE / 'testdata/candidate-tree-import-scale.json')
        _, life = CHECK.BYTE.read_corpus(HERE / 'testdata/candidate-tree-import-lifecycle-samples.json')
        cls.model = model_document(life)
        CHECK.check_driver_contract(cls.model, life)

    def refuse(self, change):
        document = copy.deepcopy(self.model)
        change(document)
        with self.assertRaises((ValueError, KeyError, TypeError)):
            CHECK.check_driver_contract(document, document['lifecycle_samples'])

    def row(self, **changes):
        self.refuse(lambda d: d['driver'].update(changes))

    def test_complete_child_byte_oracle_and_query_counts_remain_required(self):
        report = CHECK.check_samples(self.model, self.raw, self.corpus)
        self.assertEqual(report['recorded_driver_calls'], 1)
        self.assertEqual(report['recorded_build_commands'], 1)
        self.assertEqual(report['recorded_lifecycle_children'], 24)
        self.assertEqual(report['recorded_file_import_calls'], 420)
        self.assertEqual(report['recorded_query_API_calls'], 3024)
        self.assertFalse(report['execution_provenance_authenticated'])

    def test_parallel_waited_CPU_may_exceed_build_wall(self):
        row = copy.deepcopy(self.model['build'])
        row['elapsed_ns'] = 1
        CHECK.check_observation(row, 'go-build-tests', row['capture_platform'])
        self.assertGreater(row['waited_children_user_cpu_delta_ns'], row['elapsed_ns'])

    def test_explicit_linux_SELF_unit_conversion(self):
        row = copy.deepcopy(self.model['driver'])
        row['capture_platform'] = 'linux'
        for point in ('before', 'after'):
            own = row[point]['self']
            own.update(native_rss_unit='KiB', process_peak_rss_bytes=own['native_peak_rss'] * 1024)
        CHECK.check_observation(row, 'lifecycle-driver', 'linux')

    def test_incomplete_call_and_actual_exception_refused(self):
        self.row(call_returned=False)
        self.row(exception_type='TimeoutExpired')

    def test_identity_or_platform_substitution_refused(self):
        self.row(label='go-build-tests')
        self.row(capture_platform='win32')

    def test_unknown_waited_child_memory_cannot_be_parent_memory(self):
        self.refuse(lambda d: d['driver']['after']['waited_children_cpu'].update(peak_rss=1))
        self.row(process_tree_peak_rss_bytes=1)

    def test_wall_cannot_exclude_selected_child_or_build_interval(self):
        self.row(elapsed_ns=self.model['build']['elapsed_ns'])

    def test_wall_negative_boolean_float_or_outside_selected_ceiling_refused(self):
        for value in (-1, True, 1.0, CHECK.MAX_DRIVER_WALL_NS + 1):
            self.row(elapsed_ns=value)

    def test_parent_lifetime_RSS_must_not_be_an_interval_delta(self):
        self.refuse(lambda d: d['driver']['after']['self'].update(native_peak_rss=1, process_peak_rss_bytes=1))
        self.row(self_method='after RSS minus before RSS is the parent peak')

    def test_SELF_RSS_negative_boolean_or_conversion_mismatch_refused(self):
        for value in (-1, True, 1):
            self.refuse(lambda d: d['driver']['after']['self'].update(process_peak_rss_bytes=value))

    def test_native_unit_substitution_refused(self):
        self.refuse(lambda d: d['build']['after']['self'].update(native_rss_unit='kilobytes'))

    def test_CPU_counter_decrease_or_boolean_refused(self):
        self.refuse(lambda d: d['build']['after']['waited_children_cpu'].update(user_cpu_ns=0))
        self.refuse(lambda d: d['driver']['before']['self'].update(user_cpu_ns=False))

    def test_CPU_delta_must_bind_exact_snapshots(self):
        self.row(self_user_cpu_delta_ns=1)
        self.row(waited_children_system_cpu_delta_ns=1)

    def test_nested_build_CPU_and_RSS_must_be_inside_driver_observations(self):
        self.refuse(lambda d: d['build']['before']['self'].update(user_cpu_ns=999_999_999))
        self.refuse(lambda d: d['build']['after']['self'].update(native_peak_rss=999_999_999))

    def test_scope_methods_cannot_claim_through_exit_or_tree_memory(self):
        self.row(wall_method='whole interpreter through exit')
        self.row(child_cpu_method='total simultaneous compiler memory')
        self.row(cpu_storage_method='measured with native nanosecond CPU precision')

    def test_only_one_driver_and_build_selected_without_retries(self):
        for key in ('driver_repetitions', 'build_repetitions', 'within_batch_retries', 'filtered_samples'):
            self.refuse(lambda d: d['scope'].update({key: 2}))

    def test_cache_state_must_remain_unqualified(self):
        self.refuse(lambda d: d.update(cache_policy='authenticated cold compiler cache'))
        self.refuse(lambda d: d['scope'].update(cold_or_warm_cache_state_qualified=True))

    def test_build_actual_exit_stderr_or_incomplete_outcome_refused(self):
        for changes in ({'actual_exit': 7}, {'actual_exit': False}, {'completed': False}, {'stderr_sha256': '00' * 32}):
            self.refuse(lambda d: d['build_command'].update(changes))

    def test_old_raw_child_hash_binding_remains_required(self):
        document = copy.deepcopy(self.model)
        document['lifecycle_samples']['lifecycle'][0][0]['stdout_sha256'] = '00' * 32
        with self.assertRaises(ValueError):
            CHECK.check_samples(document, self.raw, self.corpus)

    def test_selected_new_source_and_unknown_fields_refused(self):
        self.refuse(lambda d: d['research_source_inputs'].update({'observe_driver_resources.py': '00' * 32}))
        self.refuse(lambda d: d.update(unmeasured_compiler_memory=1))

    def test_production_or_authentication_claims_remain_refused(self):
        self.refuse(lambda d: d.update(consumer_result='ACCEPTED'))
        self.refuse(lambda d: d.update(production_acceptance_enabled=True))
        for key in ('execution_provenance_authenticated', 'target_hardware_identity_authenticated',
                    'compiler_or_build_process_tree_peak_memory_measured',
                    'whole_pipeline_simultaneous_peak_memory_measured',
                    'canonicality_finality_or_freshness_qualified'):
            self.refuse(lambda d: d['scope'].update({key: True}))


if __name__ == '__main__':
    unittest.main(verbosity=2)
