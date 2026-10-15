#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Independent byte, ownership and lifetime controls for graph-only reuse."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
import threading
from types import ModuleType
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('graph_reuse_controls', HERE / 'conformance_graph_reuse.py')
GRAPH = importlib.util.module_from_spec(spec)
spec.loader.exec_module(GRAPH)


def program(selected='check_tree_driver_resources.py'):
    GRAPH.verify_sources()
    spec = importlib.util.spec_from_file_location('graph_reuse_selected_program', GRAPH.HERE / selected)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def state(offset=0):
    return {bytes([1 + offset]) * 32: bytes([11 + offset]) * 32,
            bytes([127 + offset]) * 32: bytes(32)}


def single(offset=0):
    return {offset.to_bytes(32, 'big'): bytes([7]) * 32}


class GraphReuseControls(unittest.TestCase):
    def setUp(self):
        self.program = program()
        self.seams, _ = GRAPH.selected_seams(self.program, 'check_tree_driver_resources.py')
        self.originals = [(module, original) for _, module, original, _ in self.seams]

    def scope(self, **limits):
        return GRAPH.selected_graphs(self.program, 'check_tree_driver_resources.py', **limits)

    def assert_restored(self):
        self.assertTrue(all(module.graph is original for module, original in self.originals))

    def test_one_computation_shared_by_four_selected_module_instances(self):
        expected = GRAPH.REFERENCE.graph(state())
        actual_calls = []
        previous = sys.getprofile()

        def profile(frame, event, unused):
            if event == 'call' and frame.f_code == GRAPH.REFERENCE.graph.__code__:
                actual_calls.append(frame.f_globals['__name__'])

        try:
            sys.setprofile(profile)
            with self.scope() as scope:
                for _, module, _, _ in self.seams:
                    self.assertEqual(module.graph(state()), expected)
        finally:
            sys.setprofile(previous)
        report = scope.report()
        self.assertEqual(len(actual_calls), 1)
        self.assertEqual((report['graph_requests'], report['original_graph_calls'], report['cache_hits']), (4, 1, 3))
        self.assert_restored()

    def test_every_path_and_value_bit_keeps_complete_reference_result(self):
        base_path, base_value = bytes([37]) * 32, bytes([91]) * 32
        count = 0
        with self.scope() as scope:
            for field in ('path', 'value'):
                for bit in range(256):
                    path, value = bytearray(base_path), bytearray(base_value)
                    changed = path if field == 'path' else value
                    changed[bit // 8] ^= 1 << (bit % 8)
                    selected = {bytes(path): bytes(value)}
                    expected = GRAPH.REFERENCE.graph(selected)
                    self.assertEqual(self.program.RET.graph(selected), expected)
                    self.assertEqual(self.program.RET.graph(dict(selected)), expected)
                    count += 1
        self.assertEqual(count, 512)
        self.assertEqual(scope.report()['cache_hits'], 512)
        print('graph-reuse-byte-equivalence ' + json.dumps({
            'schema_version': 1, 'bit_mutations': count,
            'complete_roots_nodes_and_edges_compared': True,
            'new_reference_node_execution': False}, sort_keys=True), flush=True)

    def test_empty_stored_zero_and_multiple_branch_graphs_match(self):
        cases = [{}, {bytes(32): b''}, {bytes(32): bytes(32)}]
        for count in (1, 2, 4, 8, 16):
            cases.append({(index * 65537).to_bytes(32, 'big'): bytes([index]) * 32 for index in range(count)})
        with self.scope():
            for selected in cases:
                expected = GRAPH.REFERENCE.graph(selected)
                self.assertEqual(self.program.RET.graph(selected), expected)
                self.assertEqual(self.program.RET.graph(dict(selected)), expected)

    def test_commitment_matches_separate_full_sparse_level_oracle(self):
        selected = state()
        levels, _ = GRAPH.REFERENCE.BYTE.tree_levels([
            {'path': path.hex(), 'value': value.hex()} for path, value in selected.items()])
        with self.scope():
            result = self.program.RET.graph(selected)
            self.assertEqual(result[1], levels[0].get(0, bytes(32)))

    def test_input_value_mutation_cannot_reuse_previous_root(self):
        selected = state()
        with self.scope() as scope:
            first = self.program.RET.graph(selected)
            selected[next(iter(selected))] = bytes([99]) * 32
            second = self.program.RET.graph(selected)
            self.assertNotEqual(first[1], second[1])
            self.assertEqual(second, GRAPH.REFERENCE.graph(selected))
        self.assertEqual(scope.report()['original_graph_calls'], 2)

    def test_input_path_mutation_cannot_reuse_previous_root(self):
        selected = state()
        with self.scope() as scope:
            first = self.program.RET.graph(selected)
            selected[bytes([98]) * 32] = selected.pop(next(iter(selected)))
            second = self.program.RET.graph(selected)
            self.assertNotEqual(first[1], second[1])
            self.assertEqual(second, GRAPH.REFERENCE.graph(selected))
        self.assertEqual(scope.report()['original_graph_calls'], 2)

    def test_result_mutation_on_miss_and_hit_never_changes_retained_bytes(self):
        selected = state()
        before = copy.deepcopy(selected)
        expected = GRAPH.REFERENCE.graph(selected)
        with self.scope():
            first = self.program.RET.graph(selected)
            first[2].clear()
            first[3].clear()
            second = self.program.RET.graph(selected)
            self.assertEqual(second, expected)
            second[2][bytes(32)] = b'changed private result'
            second[3][bytes(32)] = (bytes(32), bytes(32))
            third = self.seams[-1][1].graph(selected)
            self.assertEqual(third, expected)
            self.assertIsNot(first[2], second[2])
            self.assertIsNot(second[2], third[2])
            self.assertIsNot(second[3], third[3])
        self.assertEqual(selected, before)

    def test_ordered_input_maps_preserve_reference_dictionary_order(self):
        original = state()
        reversed_map = dict(reversed(tuple(original.items())))
        with self.scope() as scope:
            for selected in (original, reversed_map):
                expected = GRAPH.REFERENCE.graph(selected)
                actual = self.program.RET.graph(selected)
                self.assertEqual(actual, expected)
                self.assertEqual(list(actual[2].items()), list(expected[2].items()))
                self.assertEqual(list(actual[3].items()), list(expected[3].items()))
        self.assertEqual(scope.report()['original_graph_calls'], 2)

    def test_entry_bound_evicts_and_recomputes_complete_original_graph(self):
        with self.scope(max_entries=1) as scope:
            for selected in (state(0), state(1), state(0)):
                self.assertEqual(self.program.RET.graph(selected), GRAPH.REFERENCE.graph(selected))
        report = scope.report()
        self.assertEqual((report['original_graph_calls'], report['cache_hits'], report['evictions']), (3, 0, 2))
        self.assertEqual(report['peak_entries'], 1)

    def test_logical_byte_bound_evicts_without_losing_a_result(self):
        with self.scope(max_bytes=300) as scope:
            for selected in (single(0), single(1), single(1)):
                self.assertEqual(self.program.RET.graph(selected), GRAPH.REFERENCE.graph(selected))
        report = scope.report()
        self.assertEqual((report['original_graph_calls'], report['cache_hits'], report['evictions']), (2, 1, 1))
        self.assertLessEqual(report['peak_logical_cached_bytes'], 300)

    def test_oversized_results_fall_back_without_retention(self):
        with self.scope(max_bytes=128) as scope:
            for unused in range(2):
                self.assertEqual(self.program.RET.graph(single()), GRAPH.REFERENCE.graph(single()))
        report = scope.report()
        self.assertEqual((report['original_graph_calls'], report['cache_hits'], report['unretained_results']), (2, 0, 2))
        self.assertEqual(report['peak_logical_cached_bytes'], 0)

    def test_state_entry_boundary_and_oversized_input_keep_full_computation(self):
        selected = {index.to_bytes(32, 'big'): b'' for index in range(4096)}
        with self.scope() as scope:
            for unused in range(2):
                self.assertEqual(self.program.RET.graph(selected), GRAPH.REFERENCE.graph(selected))
            selected[(4096).to_bytes(32, 'big')] = b''
            for unused in range(2):
                self.assertEqual(self.program.RET.graph(selected), GRAPH.REFERENCE.graph(selected))
        report = scope.report()
        self.assertEqual((report['original_graph_calls'], report['cache_hits'], report['bypassed_inputs']), (3, 1, 2))

    def test_value_byte_boundary_preserves_uncached_reference_behavior(self):
        with self.scope() as scope:
            for length in (4096, 4097):
                selected = {bytes(32): bytes([7]) * length}
                for unused in range(2):
                    self.assertEqual(self.program.RET.graph(selected), GRAPH.REFERENCE.graph(selected))
        self.assertEqual((scope.report()['cache_hits'], scope.report()['bypassed_inputs']), (1, 2))

    def test_nonbuiltin_mapping_keeps_original_iteration_behavior(self):
        calls = []

        class Mapping(dict):
            def __bool__(self):
                calls.append('bool')
                return dict.__len__(self) != 0

            def items(self):
                calls.append('items')
                return dict.items(self)

        selected = Mapping(state())
        expected = GRAPH.REFERENCE.graph(selected)
        original_calls = list(calls)
        calls.clear()
        with self.scope() as scope:
            self.assertEqual(self.program.RET.graph(selected), expected)
        self.assertEqual(calls, original_calls)
        self.assertEqual(scope.report()['bypassed_inputs'], 1)

    def test_original_exception_type_and_message_are_preserved(self):
        selected = {bytes(32): None}
        try:
            GRAPH.REFERENCE.graph(selected)
        except TypeError as error:
            message = str(error)
        else:
            self.fail('Pinned reference unexpectedly accepted a non-byte value')
        with self.scope() as scope:
            for unused in range(2):
                with self.assertRaises(TypeError) as actual:
                    self.program.RET.graph(selected)
                self.assertEqual(str(actual.exception), message)
        self.assertEqual((scope.report()['original_graph_calls'], scope.report()['cache_hits']), (2, 0))
        self.assert_restored()

    def test_context_exception_restores_every_slot_and_clears_retention(self):
        with self.assertRaisesRegex(RuntimeError, 'selected control failure'):
            with self.scope() as scope:
                self.program.RET.graph(state())
                raise RuntimeError('selected control failure')
        self.assertTrue(scope.report()['cache_cleared'])
        self.assert_restored()

    def test_separate_contexts_never_reuse_an_earlier_result(self):
        reports = []
        for unused in range(2):
            with self.scope() as scope:
                self.program.RET.graph(state())
            reports.append(scope.report())
        self.assertEqual([row['original_graph_calls'] for row in reports], [1, 1])
        self.assertEqual([row['cache_hits'] for row in reports], [0, 0])

    def test_unknown_program_and_unbound_module_shapes_are_refused(self):
        for selected, selected_program in (('unknown.py', self.program),
                ('check_tree_driver_resources.py', None),
                ('check_tree_driver_resources.py', ModuleType('unbound'))):
            with self.assertRaises(ValueError):
                GRAPH.selected_seams(selected_program, selected)
        self.assert_restored()

    def test_source_pin_mismatch_is_refused_before_selecting_functions(self):
        previous = GRAPH.SOURCE_PINS
        try:
            GRAPH.SOURCE_PINS = dict(previous, **{'check.py': '00' * 32})
            with self.assertRaises(ValueError):
                with self.scope():
                    self.fail('Mismatched source entered a graph context')
        finally:
            GRAPH.SOURCE_PINS = previous
        self.assert_restored()

    def test_preexisting_replaced_graph_is_refused_without_adoption(self):
        module, original = self.originals[0]
        replacement = lambda selected: GRAPH.REFERENCE.graph(selected)
        try:
            module.graph = replacement
            with self.assertRaises(ValueError):
                with self.scope():
                    self.fail('Replaced function entered a graph context')
            self.assertIs(module.graph, replacement)
        finally:
            module.graph = original

    def test_warm_cache_refuses_replaced_byte_dependency(self):
        byte = self.program.RET.BYTE
        original = byte.parent
        with self.scope() as scope:
            self.program.RET.graph(state())
            try:
                byte.parent = lambda left, right: bytes(32)
                with self.assertRaises(ValueError):
                    self.program.RET.graph(state())
            finally:
                byte.parent = original
        self.assertEqual(scope.report()['cache_hits'], 0)

    def test_warm_cache_refuses_changed_zero_constant(self):
        module = self.program.RET
        original = module.ZERO
        with self.scope() as scope:
            module.graph(state())
            try:
                module.ZERO = bytes([1]) * 32
                with self.assertRaises(ValueError):
                    module.graph(state())
            finally:
                module.ZERO = original
        self.assertEqual(scope.report()['cache_hits'], 0)

    def test_exit_refuses_a_replaced_slot_but_restores_all_original_slots(self):
        with self.assertRaises(ValueError):
            with self.scope() as scope:
                self.program.RET.graph(state())
                self.program.RET.graph = lambda selected: None
        self.assertTrue(scope.closed)
        self.assertFalse(scope._cache)
        self.assert_restored()

    def test_nested_context_is_refused_without_disturbing_outer_selection(self):
        with self.scope() as scope:
            with self.assertRaises(ValueError):
                with self.scope():
                    self.fail('Nested context entered selected slots')
            self.program.RET.graph(state())
            self.program.RET.graph(state())
        self.assertEqual(scope.report()['cache_hits'], 1)

    def test_different_thread_is_refused_before_using_cached_bytes(self):
        failures = []
        with self.scope() as scope:
            self.program.RET.graph(state())

            def request():
                try:
                    self.program.RET.graph(state())
                except ValueError:
                    failures.append('serial caller refusal')

            worker = threading.Thread(target=request, daemon=True)
            worker.start()
            worker.join(5)
            self.assertFalse(worker.is_alive())
            self.assertEqual(failures, ['serial caller refusal'])
        self.assertEqual(scope.report()['cache_hits'], 0)

    def test_unselected_original_callback_is_refused_before_execution(self):
        called = []
        with self.scope() as scope:
            with self.assertRaises(ValueError):
                scope.call(lambda selected: called.append(selected), state())
        self.assertEqual(called, [])
        self.assertEqual(scope.report()['original_graph_calls'], 0)

    def test_replacement_preserves_the_single_state_argument_contract(self):
        selected = state()
        with self.scope() as scope:
            with self.assertRaises(TypeError):
                self.program.RET.graph(selected, GRAPH.REFERENCE.graph)
            with self.assertRaises(TypeError):
                self.program.RET.graph(selected, original=GRAPH.REFERENCE.graph)
            self.assertEqual(self.program.RET.graph(state=selected), GRAPH.REFERENCE.graph(selected))
        self.assertEqual(scope.report()['original_graph_calls'], 1)

    def test_input_change_during_original_return_is_refused_before_retention(self):
        selected = state()
        previous = sys.getprofile()
        changed = []

        def profile(frame, event, unused):
            if event == 'return' and frame.f_code == GRAPH.REFERENCE.graph.__code__ and not changed:
                selected[next(iter(selected))] = bytes([88]) * 32
                changed.append(True)

        try:
            with self.scope() as scope:
                sys.setprofile(profile)
                with self.assertRaises(ValueError):
                    self.program.RET.graph(selected)
                sys.setprofile(previous)
                self.assertFalse(scope._cache)
        finally:
            sys.setprofile(previous)
        self.assertEqual(changed, [True])
        self.assertEqual(scope.report()['peak_entries'], 0)

    def test_input_change_after_cache_lookup_snapshot_cannot_return_stale_graph(self):
        selected = state()
        previous = sys.getprofile()
        changed = []

        def profile(frame, event, unused):
            if event == 'return' and frame.f_code == GRAPH.cache_key.__code__ and not changed:
                selected[next(iter(selected))] = bytes([89]) * 32
                changed.append(True)

        try:
            with self.scope() as scope:
                self.program.RET.graph(selected)
                sys.setprofile(profile)
                with self.assertRaises(ValueError):
                    self.program.RET.graph(selected)
                sys.setprofile(previous)
                self.assertEqual(self.program.RET.graph(selected), GRAPH.REFERENCE.graph(selected))
        finally:
            sys.setprofile(previous)
        self.assertEqual(changed, [True])
        self.assert_restored()

    def test_limits_reject_boolean_float_zero_and_outside_ceiling(self):
        for key, cap in (('max_bytes', GRAPH.MAX_BYTES), ('max_entries', GRAPH.MAX_ENTRIES)):
            for value in (True, False, 0, -1, 1.0, cap + 1):
                with self.assertRaises(ValueError):
                    with self.scope(**{key: value}):
                        self.fail('Invalid cache limit entered a context')
        self.assert_restored()

    def test_both_complete_driver_program_selections_have_four_slots(self):
        selected = 'check_tree_driver_resources_test.py'
        controls = program(selected)
        with GRAPH.selected_graphs(controls, selected) as scope:
            expected = GRAPH.REFERENCE.graph(state())
            for _, module, _, _ in scope.seams:
                self.assertEqual(module.graph(state()), expected)
        self.assertEqual(len(scope.report()['selected_graph_seams']), 4)
        self.assertEqual(scope.report()['cache_hits'], 3)

    def test_later_imports_keep_their_original_graph_function(self):
        with self.scope() as scope:
            later = program()
            original = later.RET.graph
            self.assertTrue(GRAPH.same_function(original, GRAPH.REFERENCE.graph, later.RET))
            later.RET.graph(state())
            self.assertIs(later.RET.graph, original)
            self.assertEqual(scope.requests, 0)
        self.assert_restored()

    def test_report_requires_closed_scope_and_contains_no_cached_payload(self):
        with self.scope() as scope:
            self.program.RET.graph(state())
            with self.assertRaises(ValueError):
                scope.report()
        report = scope.report()
        self.assertEqual(report['graph_requests'], report['original_graph_calls'] + report['cache_hits'])
        self.assertTrue(report['complete_ordered_byte_maps_are_keys'])
        self.assertTrue(report['mutable_results_are_independent'])
        self.assertTrue(report['cache_cleared'])
        for key in ('disk_cache_created', 'cross_process_or_context_reuse',
                    'recorded_producer_source_inputs_rebound', 'new_reference_node_or_resource_execution',
                    'process_RSS_or_whole_CI_speedup_qualified', 'production_acceptance_enabled'):
            self.assertFalse(report[key])
        self.assertNotIn('cached_results', report)
        self.assertNotIn('cached_inputs', report)


if __name__ == '__main__':
    unittest.main(verbosity=2)
