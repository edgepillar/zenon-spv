#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Compare optional leaf reuse with the original complete graph byte-for-byte."""
import importlib.util
import hashlib
import json
from pathlib import Path
import platform
import re
import sys
import threading
from types import ModuleType
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


REUSE = load('leaf_reuse_controls', HERE / 'conformance_leaf_reuse.py')


def state(count):
    return {REUSE.REFERENCE.BYTE.digest(i.to_bytes(4, 'big')): i.to_bytes(32, 'big')
            for i in range(count)}


class LeafReuseControls(unittest.TestCase):
    def setUp(self):
        self.program = load('leaf_controls_scale', REUSE.HERE / 'check_tree_scale.py')
        self.module = self.program.RET
        self.original = self.module.graph

    def scope(self, **kwargs):
        return REUSE.selected_leaves(self.program, 'check_tree_scale.py', **kwargs)

    def test_complete_graph_bytes_and_dictionary_order_match_reference(self):
        cases = [{}, *[state(n) for n in (1, 2, 8, 64)]]
        expected = [self.original(value) for value in cases]
        with self.scope() as scope:
            for _ in range(2):
                for value, want in zip(cases, expected):
                    got = self.module.graph(value)
                    self.assertEqual(got, want)
                    self.assertEqual(list(got[2].items()), list(want[2].items()))
                    self.assertEqual(list(got[3].items()), list(want[3].items()))
        report = scope.report()
        self.assertGreater(report['cache_hits'], 0)
        self.assertGreater(report['leaf_parent_calls_avoided'], report['leaf_parent_calls'])
        self.assertEqual(report['bypassed_inputs'], 0)

    def test_depth_path_value_and_presence_are_distinct_inputs(self):
        path = bytes(32)
        cases = [{path: b''}, {path: bytes(32)}, {path: b'\x01' + bytes(31)}, {},
                 {path: b'', (1).to_bytes(32, 'big'): bytes(32)},
                 {path: b'', (1 << 255).to_bytes(32, 'big'): bytes(32)}]
        expected = [self.original(value) for value in cases]
        self.assertNotEqual(expected[0][1], expected[1][1])
        self.assertNotEqual(expected[0][1], expected[3][1])
        with self.scope() as scope:
            for _ in range(2):
                for value, want in zip(cases, expected):
                    self.assertEqual(self.module.graph(value), want)
        self.assertGreater(scope.report()['cache_hits'], 0)

    def test_input_edits_and_reordered_maps_are_recounted(self):
        value = state(16)
        with self.scope():
            self.assertEqual(self.module.graph(value), self.original(value))
            first = next(iter(value))
            value[first] = b''
            self.assertEqual(self.module.graph(value), self.original(value))
            value.pop(first)
            self.assertEqual(self.module.graph(value), self.original(value))
            value[first] = bytes(32)
            self.assertEqual(self.module.graph(value), self.original(value))
            reversed_value = dict(reversed(list(value.items())))
            self.assertEqual(self.module.graph(reversed_value), self.original(reversed_value))

    def test_callers_receive_independent_mutable_graphs(self):
        value = state(8)
        expected = self.original(value)
        with self.scope():
            first = self.module.graph(value)
            first[2].clear()
            first[3][bytes(32)] = (bytes(32), bytes(32))
            second = self.module.graph(value)
            self.assertEqual(second, expected)
            self.assertIsNot(first[2], second[2])
            self.assertIsNot(first[3], second[3])

    def test_entry_and_logical_payload_limits_evict_without_changing_bytes(self):
        value = state(8)
        expected = self.original(value)
        for caps in ({'max_entries': 2}, {'max_bytes': 260}):
            with self.subTest(caps=caps):
                with self.scope(**caps) as scope:
                    for _ in range(2):
                        self.assertEqual(self.module.graph(value), expected)
                report = scope.report()
                self.assertLessEqual(report['peak_entries'], report['maximum_entries'])
                self.assertLessEqual(report['peak_logical_cached_bytes'], report['maximum_logical_cached_bytes'])
                self.assertGreater(report['evictions'], 0)

    def test_unretainable_leaf_is_computed_each_time(self):
        value = state(1)
        with self.scope(max_bytes=1) as scope:
            for _ in range(2):
                self.assertEqual(self.module.graph(value), self.original(value))
        report = scope.report()
        self.assertEqual(report['unretained_results'], 2)
        self.assertEqual(report['cache_hits'], 0)
        self.assertEqual(report['peak_logical_cached_bytes'], 0)

    def test_parent_call_counters_describe_actual_leaf_chain_work(self):
        path, zero, changed = bytes(32), bytes(32), b'\x01' * 32
        with self.scope() as scope:
            for value in (zero, zero, changed, zero):
                selected = {path: value}
                self.assertEqual(self.module.graph(selected), self.original(selected))
        report = scope.report()
        self.assertEqual((report['graph_requests'], report['leaf_requests']), (4, 4))
        self.assertEqual((report['cache_misses'], report['cache_hits']), (2, 2))
        self.assertEqual((report['leaf_parent_calls'], report['leaf_parent_calls_avoided']), (512, 512))

    def test_value_byte_ceiling_is_inclusive_and_oversize_bypasses(self):
        with self.scope() as scope:
            for size in (REUSE.MAX_VALUE_BYTES, REUSE.MAX_VALUE_BYTES + 1):
                selected = {bytes(32): b'x' * size}
                for _ in range(2):
                    self.assertEqual(self.module.graph(selected), self.original(selected))
        report = scope.report()
        self.assertEqual((report['cache_hits'], report['bypassed_inputs']), (1, 2))

    def test_nonbuiltin_and_oversize_inputs_use_original_function(self):
        class Custom(dict):
            pass
        cases = [Custom(state(2)), {bytes(32): b'x' * (REUSE.MAX_VALUE_BYTES + 1)},
                 {b'bad': bytes(32)}, {bytes(32): bytearray(32)},
                 {i.to_bytes(32, 'big'): b'' for i in range(REUSE.MAX_STATE_ENTRIES + 1)}]
        with self.scope() as scope:
            for value in cases:
                self.assertEqual(self.module.graph(value), self.original(value))
        self.assertEqual(scope.report()['bypassed_inputs'], len(cases))

    def test_invalid_original_inputs_keep_their_original_exception(self):
        for value in (1, [b'bad'], {b'bad': object()}):
            with self.subTest(kind=type(value).__name__):
                try:
                    self.original(value)
                except Exception as error:
                    exception = type(error)
                else:
                    self.fail('fixture must select an original error')
                with self.scope() as scope:
                    with self.assertRaises(exception):
                        self.module.graph(value)
                report = scope.report()
                self.assertEqual((report['graph_requests'], report['completed_graphs'], report['failed_graphs']),
                                 (1, 0, 1))
                self.assertFalse(report['every_graph_traversal_completed'])

    def test_budgets_reject_bool_zero_negative_and_overflow(self):
        for key, maximum in (('max_entries', REUSE.MAX_ENTRIES), ('max_bytes', REUSE.MAX_BYTES)):
            for value in (True, 0, -1, maximum + 1, 1.0):
                with self.subTest(key=key, value=value):
                    with self.assertRaises(ValueError):
                        with self.scope(**{key: value}):
                            self.fail('invalid budget admitted')
                    self.assertIs(self.module.graph, self.original)

    def test_cache_is_cleared_on_success_and_exception_and_not_shared(self):
        value = state(1)
        for broken in (False, True):
            with self.subTest(broken=broken):
                try:
                    with self.scope() as scope:
                        self.module.graph(value)
                        self.module.graph(value)
                        if broken:
                            raise RuntimeError('controlled body failure')
                except RuntimeError:
                    self.assertTrue(broken)
                self.assertEqual(scope.report()['cache_hits'], 1)
                self.assertTrue(scope.report()['cache_cleared'])
                self.assertFalse(scope._cache)
                self.assertIs(self.module.graph, self.original)
        with self.scope() as scope:
            self.module.graph(value)
        self.assertEqual(scope.report()['cache_hits'], 0)

    def test_closed_scope_and_other_thread_refuse_before_cache_use(self):
        errors = []
        with self.scope() as scope:
            def use():
                try:
                    self.module.graph(state(1))
                except ValueError:
                    errors.append('refused')
            thread = threading.Thread(target=use)
            thread.start()
            thread.join(timeout=2)
            self.assertFalse(thread.is_alive())
            self.assertEqual(errors, ['refused'])
            self.assertEqual(scope.graph_requests, 0)
        with self.assertRaises(ValueError):
            scope.replacement(state(1))

    def test_dependency_or_installed_function_changes_refuse_and_restore(self):
        for changed in ('digest', 'parent', 'require', 'ZERO', 'graph'):
            with self.subTest(changed=changed):
                owner = self.module if changed == 'graph' else self.module.BYTE
                original = getattr(owner, changed)
                try:
                    with self.assertRaises(ValueError):
                        with self.scope() as scope:
                            setattr(owner, changed, object())
                            with self.assertRaises((ValueError, TypeError)):
                                self.module.graph(state(1))
                finally:
                    setattr(owner, changed, original)
                self.assertIs(self.module.graph, self.original)
                self.assertFalse(scope._cache)

    def test_nested_scope_and_replaced_reference_code_are_refused(self):
        with self.scope():
            with self.assertRaises(ValueError):
                with self.scope():
                    self.fail('nested seam admitted')
        with mock.patch.object(self.module, 'graph', lambda value: self.original(value)):
            with self.assertRaises(ValueError):
                with self.scope():
                    self.fail('replacement function admitted')

    def test_program_selection_requires_pinned_module_and_explicit_name(self):
        fake = ModuleType('unselected')
        fake.__file__ = str(REUSE.HERE / 'check_tree_scale.py')
        for program, selected in ((fake, 'check_tree_scale.py'), (self.program, '../check_tree_scale.py'),
                                  (self.program, 'check_tree_scale_test.py'), ({}, 'check_tree_scale.py')):
            with self.subTest(selected=selected):
                with self.assertRaises(ValueError):
                    REUSE.selected_module(program, selected)
        self.assertEqual(REUSE.verify_sources(), REUSE.SOURCE_PINS)

    def test_graph_calls_create_no_disk_cache(self):
        expected = self.original(state(4))
        with self.scope() as scope:
            with mock.patch('builtins.open', side_effect=AssertionError('unexpected file access')):
                self.assertEqual(self.module.graph(state(4)), expected)
                self.assertEqual(self.module.graph(state(4)), expected)
        self.assertFalse(scope.report()['disk_cache_created'])


class ControlResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.attempted, self.passed = [], []

    def name(self, test):
        return '.'.join(test.id().split('.')[-2:])

    def startTest(self, test):
        self.attempted.append(self.name(test))
        super().startTest(test)

    def addSuccess(self, test):
        self.passed.append(self.name(test))
        super().addSuccess(test)


def run_controls():
    args, revision = list(sys.argv[1:]), None
    if '--source-revision' in args:
        try:
            if args.count('--source-revision') != 1:
                raise ValueError
            index = args.index('--source-revision')
            revision = args[index + 1]
            if re.fullmatch('[0-9a-f]{40}', revision) is None:
                raise ValueError
            del args[index:index + 2]
        except (IndexError, ValueError):
            sys.stderr.write('leaf-reuse-controls: invalid source revision\n')
            return 64
    runner = unittest.TextTestRunner(verbosity=2, resultclass=ControlResult)
    result = unittest.main(argv=[sys.argv[0], *args], testRunner=runner, exit=False).result
    if revision is not None:
        paths = ('tools/conformance_leaf_reuse.py', 'tools/conformance_leaf_reuse_test.py',
                 'tools/gen-state-root-vectors/run_retention_leaves.py', '.github/workflows/ci.yml')
        pins = {}
        for name in paths:
            with (HERE.parent / name).open('rb') as handle:
                raw = handle.read((256 << 10) + 1)
            if len(raw) > 256 << 10:
                return 70
            pins[name] = {'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw)}
        report = {'format': 'zenon-retention-leaf-reuse-controls/v1',
                  'status': 'PASS' if result.wasSuccessful() and not result.skipped else 'FAILURE',
                  'source_revision': revision, 'source_pins': pins, 'reference_sources': REUSE.verify_sources(),
                  'runtime': {'os': sys.platform, 'machine': platform.machine().lower(),
                              'python': platform.python_version(), 'implementation': platform.python_implementation()},
                  'tests': result.testsRun, 'failures': len(result.failures), 'errors': len(result.errors),
                  'skipped': len(result.skipped), 'attempted_names': sorted(result.attempted),
                  'passed_names': sorted(result.passed),
                  'failed_or_unfinished_names': sorted(set(result.attempted) - set(result.passed)),
                  'fixture_files_created': False, 'new_node_execution': False,
                  'runtime_qualification_transferred': False}
        raw = json.dumps(report, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n'
        if len(raw.encode('utf-8')) > 64 << 10:
            return 70
        try:
            if sys.stdout.write(raw) != len(raw):
                return 70
            sys.stdout.flush()
        except (OSError, ValueError):
            return 70
    return 0 if result.wasSuccessful() and not result.skipped else 1


if __name__ == '__main__':
    raise SystemExit(run_controls())
