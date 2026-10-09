#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Adversarial projection/evidence controls; synthetic rows are not samples."""
import copy
import hashlib
import importlib.util
from pathlib import Path
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('projection_controls', HERE / 'check_oracle_projection.py')
CHECK = importlib.util.module_from_spec(spec)
spec.loader.exec_module(CHECK)
PROJECT, BYTE = CHECK.PROJECT, CHECK.BYTE


def bind_stdout(document):
    for sample in document['samples']:
        raw = CHECK.encoded(CHECK.worker_document(sample, document['runtime'],
            document['research_source_inputs'], document['python_executable_sha256']))
        sample['command']['stdout_sha256'] = hashlib.sha256(raw).hexdigest()


def model_document(corpus, raw):
    platform = 'darwin'
    def point(counter):
        return {'self': {'native_peak_rss': (32 << 20) + counter, 'native_rss_unit': 'bytes',
            'process_peak_rss_bytes': (32 << 20) + counter, 'user_cpu_ns': counter * 1000,
            'system_cpu_ns': counter * 2000}, 'waited_children_cpu': {'user_cpu_ns': 0, 'system_cpu_ns': 0}}
    samples = []
    for g, selection, repetition, mode in CHECK.inventory():
        name = CHECK.label(g, selection, repetition, mode)
        body = CHECK.encoded(next(c for c in corpus['cases'] if c['input']['name'] == selection[0]))
        row = {'label': name, 'call_returned': True, 'exception_type': None, 'capture_platform': platform,
            'elapsed_ns': 1_000_000, 'wall_method': CHECK.OBS.WALL_METHOD, 'self_method': CHECK.OBS.SELF_METHOD,
            'child_cpu_method': CHECK.OBS.CHILD_CPU_METHOD, 'cpu_storage_method': CHECK.OBS.CPU_METHOD,
            'before': point(0), 'after': point(1), 'self_user_cpu_delta_ns': 1000,
            'self_system_cpu_delta_ns': 2000, 'waited_children_user_cpu_delta_ns': 0,
            'waited_children_system_cpu_delta_ns': 0}
        samples.append({'generation': g, 'case': selection[0], 'repetition': repetition, 'mode': mode,
            'result_bytes': len(body), 'result_sha256': hashlib.sha256(body).hexdigest(), 'resource': row,
            'command': {'label': name, 'completed': True, 'actual_exit': 0,
                        'stdout_sha256': '00' * 32, 'stderr_sha256': hashlib.sha256(b'').hexdigest()}})
    document = {'format_version': 1, 'kind': 'selected-sparse-oracle-comparison',
        'source': CHECK.IMPORT.SCALE.SOURCE, 'reference': CHECK.REFERENCE, 'scope': copy.deepcopy(CHECK.SCOPE),
        'corpus_sha256': hashlib.sha256(raw).hexdigest(), 'research_source_inputs': CHECK.input_pins(),
        'runtime': {'os': platform, 'architecture': 'arm64', 'python': '3.13.7', 'implementation': 'CPython'},
        'python_executable_sha256': '11' * 32, 'samples': samples, 'consumer_result': 'REFUSED',
        'production_acceptance_enabled': False}
    bind_stdout(document)
    return document


class OracleProjectionControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw, cls.corpus = BYTE.read_corpus(HERE / 'testdata/candidate-tree-import-scale.json')
        cls.model = model_document(cls.corpus, cls.raw)
        CHECK.check_contract(cls.model, cls.raw, cls.corpus)

    def refuse(self, change, rebind=True):
        document = copy.deepcopy(self.model)
        change(document)
        if rebind:
            bind_stdout(document)
        with self.assertRaises((ValueError, KeyError, TypeError)):
            CHECK.check_contract(document, self.raw, self.corpus)

    def compare(self, state, paths):
        levels, values = PROJECT.projected_levels(state, paths)
        full, complete = BYTE.tree_levels([{'path': p.hex(), 'value': v.hex()} for p, v in state.items()])
        root = levels[0].get(0, BYTE.ZERO)
        self.assertEqual(root, full[0].get(0, BYTE.ZERO))
        self.assertEqual(root, PROJECT.RET.graph(state)[1])
        for path in paths:
            proof = BYTE.canonical_proof(levels, values, path)
            self.assertEqual(proof, BYTE.canonical_proof(full, complete, path))
            self.assertEqual(BYTE.proof_result(root, path, state.get(path, b''), proof, path in state), 'match')
        return levels, values

    def test_every_small_subset_preserves_present_absent_and_zero_proofs(self):
        paths = tuple(i.to_bytes(32, 'big') for i in (0, 1, 1 << 255, (1 << 256) - 1))
        for bitmap in range(16):
            state = {p: (bytes(32) if i % 2 == 0 else i.to_bytes(32, 'big'))
                     for i, p in enumerate(paths) if bitmap & (1 << i)}
            with self.subTest(subset=bitmap):
                self.compare(state, paths + ((2).to_bytes(32, 'big'),))

    def test_unselected_leaf_still_changes_root_and_selected_siblings(self):
        a, b = BYTE.digest(b'query'), BYTE.digest(b'unqueried-leaf')
        before = self.compare({a: bytes(32)}, (a,))[0][0].get(0, BYTE.ZERO)
        after = self.compare({a: bytes(32), b: bytes(32)}, (a,))[0][0].get(0, BYTE.ZERO)
        self.assertNotEqual(before, after)

    def test_empty_query_selection_still_computes_full_root(self):
        state = {BYTE.digest(b'leaf'): bytes(32)}
        self.compare(state, ())

    def test_query_order_does_not_change_canonical_bytes(self):
        paths = tuple(BYTE.digest(str(i).encode()) for i in range(4))
        state = {p: bytes(32) for p in paths}
        a, av = PROJECT.projected_levels(state, paths)
        b, bv = PROJECT.projected_levels(state, tuple(reversed(paths)))
        for path in paths:
            self.assertEqual(BYTE.canonical_proof(a, av, path), BYTE.canonical_proof(b, bv, path))

    def test_unknown_query_and_uncomputed_sibling_are_refused_as_empty(self):
        a, b = BYTE.digest(b'selected'), BYTE.digest(b'unknown')
        levels, values = PROJECT.projected_levels({a: bytes(32)}, (a,))
        with self.assertRaises(ValueError):
            BYTE.canonical_proof(levels, values, b)
        with self.assertRaises(ValueError):
            levels[256].get(int.from_bytes(b, 'big') ^ 1, BYTE.ZERO)

    def test_missing_sibling_cannot_use_zero_default(self):
        layer = PROJECT.SelectedLayer({0: BYTE.ZERO})
        with self.assertRaises(ValueError):
            layer.get(1, BYTE.ZERO)

    def test_path_width_duplicate_mutable_and_query_ceiling_refused(self):
        for paths in ((b'bad',), (bytes(32), bytes(32)), [bytes(32)], (bytearray(32),),
                      tuple(i.to_bytes(32, 'big') for i in range(17))):
            with self.assertRaises(ValueError):
                PROJECT.projected_levels({}, paths)

    def test_leaf_width_type_and_4097_ceiling_refused(self):
        for state in ({b'bad': bytes(32)}, {bytes(32): b'bad'}, {bytes(32): bytearray(32)},
                      {i.to_bytes(32, 'big'): bytes(32) for i in range(4097)}):
            with self.assertRaises(ValueError):
                PROJECT.projected_levels(state, ())

    def test_projection_views_preserve_borrowed_input_and_refuse_mutation(self):
        path = BYTE.digest(b'leaf')
        state = {path: bytes(32)}
        before = state.copy()
        levels, values = PROJECT.projected_levels(state, (path,))
        self.assertEqual(state, before)
        with self.assertRaises(TypeError):
            levels[0] = PROJECT.SelectedLayer({0: BYTE.ZERO})
        # Some CPython versions attempt index conversion before rejecting an
        # assignment to a mapping proxy with a 256-bit integer key.
        with self.assertRaises((TypeError, IndexError)):
            values._present[int.from_bytes(path, 'big')] = b'bad'
        self.assertEqual(values.get(int.from_bytes(path, 'big'), b''), bytes(32))

    def test_boolean_lookup_and_malformed_layer_refused(self):
        layer = PROJECT.SelectedLayer({0: BYTE.ZERO})
        with self.assertRaises(ValueError):
            layer.get(False, BYTE.ZERO)
        with self.assertRaises(ValueError):
            PROJECT.SelectedLayer({0: b'bad'})

    def test_function_seam_restored_after_actual_exception(self):
        original = PROJECT.SCALE.scale_levels
        with mock.patch.object(PROJECT.IMPORT, 'expected_case', side_effect=RuntimeError('selected failure')):
            with self.assertRaises(RuntimeError):
                PROJECT.complete_case(PROJECT.IMPORT.SELECTIONS[0])
        self.assertIs(PROJECT.SCALE.scale_levels, original)

    def test_unselected_or_malformed_case_parameters_refused(self):
        for selection in (('other', 512, 16, 8), ('import-512-16-retain8', 512, True, 8),
                          ['import-512-16-retain8', 512, 16, 8]):
            with self.assertRaises(ValueError):
                PROJECT.selected_paths(selection)

    def test_complete_ordered_contract_and_24_samples_required(self):
        CHECK.check_contract(self.model, self.raw, self.corpus)
        self.assertEqual(len(self.model['samples']), 24)
        self.refuse(lambda d: d['samples'].pop())
        self.refuse(lambda d: d['samples'].reverse())

    def test_all_selected_labels_cross_observer_preflight_and_bad_label_stops_before_snapshot(self):
        # Explicit DTO snapshots exercise the actual observer call path;
        # these are controls, never resource measurements or exported samples.
        point = copy.deepcopy(self.model['samples'][0]['resource']['before'])
        with mock.patch.object(CHECK.OBS, 'preflight'), mock.patch.object(CHECK.OBS, 'snapshot', return_value=point) as snapshot:
            call, retain = mock.Mock(return_value='selected'), mock.Mock()
            with self.assertRaises(ValueError):
                CHECK.OBS.observe_call('0-invalid', call, retain)
            call.assert_not_called()
            retain.assert_not_called()
            snapshot.assert_not_called()
            for g, selection, repetition, mode in CHECK.inventory():
                rows = []
                self.assertEqual(CHECK.OBS.observe_call(CHECK.label(g, selection, repetition, mode),
                    lambda: 'selected', rows.append), 'selected')
                self.assertEqual(len(rows), 1)
                self.assertTrue(rows[0]['call_returned'])

    def test_generations_modes_and_repetitions_cannot_be_relabelled(self):
        for field, value in (('generation', True), ('mode', 'projected'), ('repetition', 1), ('case', 'other')):
            self.refuse(lambda d: d['samples'][0].update({field: value}))

    def test_complete_result_size_and_bytes_are_bound(self):
        self.refuse(lambda d: d['samples'][0].update(result_bytes=1))
        self.refuse(lambda d: d['samples'][0].update(result_sha256='00' * 32))

    def test_coherent_forged_corpus_still_requires_independent_reconstruction(self):
        corpus = copy.deepcopy(self.corpus)
        corpus['cases'][0]['steps'][0]['preflight_root'] = '00' * 32
        raw = CHECK.encoded(corpus)
        model = model_document(corpus, raw)
        # All result/stream hashes are coherent; complete independent bytes must refuse.
        CHECK.check_contract(model, raw, corpus)
        with self.assertRaises(ValueError):
            CHECK.check_samples(model, raw, corpus)

    def test_actual_stdout_not_replaceable_with_reencoded_partial_row(self):
        self.refuse(lambda d: d['samples'][0]['command'].update(stdout_sha256='00' * 32), rebind=False)

    def test_actual_exit_stderr_incomplete_and_boolean_outcomes_refused(self):
        for changes in ({'actual_exit': 1}, {'actual_exit': False}, {'completed': False}, {'stderr_sha256': '00' * 32}):
            self.refuse(lambda d: d['samples'][0]['command'].update(changes))

    def test_call_exception_and_unreturned_work_refused(self):
        for changes in ({'call_returned': False}, {'exception_type': 'TimeoutExpired'}):
            self.refuse(lambda d: d['samples'][0]['resource'].update(changes))

    def test_counter_delta_negative_boolean_and_wall_ceiling_refused(self):
        for changes in ({'self_user_cpu_delta_ns': 0}, {'elapsed_ns': -1}, {'elapsed_ns': True},
                        {'elapsed_ns': CHECK.MAX_WORKER_WALL_NS + 1}):
            self.refuse(lambda d: d['samples'][0]['resource'].update(changes))

    def test_native_SELF_unit_and_lifetime_peak_cannot_be_relabelled(self):
        self.refuse(lambda d: d['samples'][0]['resource']['after']['self'].update(native_rss_unit='KiB'))
        self.refuse(lambda d: d['samples'][0]['resource'].update(self_method='interval RSS delta'))

    def test_waited_descendant_CPU_is_not_expected_in_childless_worker(self):
        self.refuse(lambda d: d['samples'][0]['resource']['before']['waited_children_cpu'].update(user_cpu_ns=1))

    def test_reference_and_all_new_source_inputs_required(self):
        self.refuse(lambda d: d['reference'].update(revision='00' * 20))
        self.refuse(lambda d: d['research_source_inputs'].update({'project_sparse_oracle.py': '00' * 32}))

    def test_runtime_or_executable_shape_substitution_refused(self):
        self.refuse(lambda d: d['runtime'].update(os='win32'))
        self.refuse(lambda d: d.update(python_executable_sha256='unknown'))

    def test_production_trust_and_snapshot_claims_remain_refused(self):
        self.refuse(lambda d: d.update(consumer_result='ACCEPTED'))
        for field in ('execution_provenance_authenticated', 'target_hardware_identity_authenticated',
                      'real_archive_snapshot_or_NodeTree_executed', 'production_resource_budgets_qualified'):
            self.refuse(lambda d: d['scope'].update({field: True}))

    def test_retry_filter_and_through_exit_scope_substitution_refused(self):
        for field in ('within_batch_retries', 'filtered_samples'):
            self.refuse(lambda d: d['scope'].update({field: 1}))
        self.refuse(lambda d: d['scope'].update(final_resource_report_encoding_and_exit_measured=True))

    def test_unknown_fields_and_raw_JSON_duplicate_keys_refused(self):
        self.refuse(lambda d: d['samples'][0].update(pipeline_peak_memory=1))
        with self.assertRaises(ValueError):
            __import__('json').loads('{"a":0,"a":1}', object_pairs_hook=BYTE.object_pairs)


if __name__ == '__main__':
    unittest.main(verbosity=2)
