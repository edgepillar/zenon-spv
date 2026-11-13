#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Exact-byte, bounds and ownership controls; no node or history replay."""
from copy import deepcopy
import hashlib
import importlib.util
from pathlib import Path
import sys
import threading
import unittest
from unittest import mock

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('tested_table_reuse', HERE / 'conformance_table_reuse.py')
H = importlib.util.module_from_spec(spec)
spec.loader.exec_module(H)


def reader():
    spec = importlib.util.spec_from_file_location('private_table_reader', H.HERE / 'check_default_retention_corpus.py')
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def table(policy='pruned'):
    return {'policy': policy, 'snapshot': {'format': 'unit-table/v1', 'logical_records': 3,
            'logical_key_value_bytes': 99, 'logical_records_sha256': 'e' * 64,
            'record_prefix_counts': {'unit': 3}}, 'queries': {'unit': [{'value': '0f', 'present': True}]}}


class TableReuseControls(unittest.TestCase):
    def assertBytesEqual(self, actual, expected):
        # A failure must not dump multi-megabyte tables into CI stderr.
        self.assertIs(type(actual), bytes)
        self.assertIs(type(expected), bytes)
        self.assertEqual(len(actual), len(expected), 'expanded byte count differs')
        self.assertEqual(hashlib.sha256(actual).hexdigest(), hashlib.sha256(expected).hexdigest())
        self.assertTrue(actual == expected, 'complete expanded bytes differ')

    def setUp(self):
        self.reader = reader()
        self.original = self.reader.expand_table
        self.table, self.roots = table(), ['ab' * 32] * H.ROOT_COUNT

    def test_pinned_selection_and_original_code(self):
        self.assertEqual(H.verify_sources(), H.SOURCE_PINS)
        with H.reuse(self.reader) as scope: self.assertTrue(scope.intact())
        self.assertIs(self.reader.expand_table, self.original)

    def test_equal_complete_inputs_reuse_immutable_exact_bytes(self):
        expected = self.original(self.table, self.roots)
        with H.reuse(self.reader) as scope:
            first = self.reader.expand_table(self.table, self.roots)
            second = self.reader.expand_table(deepcopy(self.table), list(self.roots))
            self.assertBytesEqual(first, expected)
            self.assertTrue(first is second, 'equal immutable result was not reused')
            self.assertIs(type(first), bytes)
            self.assertEqual((scope.calls, scope.computations, scope.hits), (2, 1, 1))

    def test_every_root_byte_and_order_remains_in_key(self):
        with H.reuse(self.reader) as scope:
            before = self.reader.expand_table(self.table, self.roots)
            self.roots[20000] = 'cd' * 32
            changed = self.reader.expand_table(self.table, self.roots)
            self.roots.reverse()
            reordered = self.reader.expand_table(self.table, self.roots)
            self.assertTrue(before != changed, 'retained root mutation did not change the output')
            self.assertTrue(changed != reordered, 'root order did not change the output')
            self.assertBytesEqual(reordered, self.original(self.table, self.roots))
            self.assertEqual(scope.hits, 0)

    def test_valid_pruned_prefix_change_still_forces_original_validation(self):
        with H.reuse(self.reader) as scope:
            before = self.reader.expand_table(self.table, self.roots)
            self.roots[12345] = 'cd' * 32
            self.assertBytesEqual(self.reader.expand_table(self.table, self.roots), before)
            self.assertEqual((scope.computations, scope.hits), (2, 0))

    def test_table_fields_nested_values_and_bool_int_are_distinct(self):
        variants = []
        for field in ('policy', 'snapshot', 'queries'):
            value = deepcopy(self.table)
            if field == 'policy': value[field] = 'archive'
            elif field == 'snapshot': value[field]['logical_records'] += 1
            else: value[field]['unit'][0]['present'] = 1
            variants.append(value)
        with H.reuse(self.reader) as scope:
            before = self.reader.expand_table(self.table, self.roots)
            for value in variants:
                result = self.reader.expand_table(value, self.roots)
                self.assertBytesEqual(result, self.original(value, self.roots))
                self.assertTrue(result != before, 'changed complete table input was ignored')
            self.assertEqual(scope.hits, 0)

    def test_dictionary_order_is_preserved_conservatively(self):
        with H.reuse(self.reader) as scope:
            self.assertBytesEqual(self.reader.expand_table(self.table, self.roots),
                                  self.reader.expand_table(dict(reversed(list(self.table.items()))), self.roots))
            self.assertEqual(scope.computations, 2)

    def test_later_input_mutation_does_not_change_retained_bytes(self):
        with H.reuse(self.reader):
            before = self.reader.expand_table(self.table, self.roots)
            pin = hashlib.sha256(before).hexdigest()
            self.table['queries']['unit'][0]['value'] = 'ff'
            self.assertTrue(self.reader.expand_table(self.table, self.roots) != before, 'later input change ignored')
            self.assertEqual(hashlib.sha256(before).hexdigest(), pin)

    def test_unsupported_float_preserves_original_without_retention(self):
        self.table['queries']['float'] = 0.5
        expected = self.original(self.table, self.roots)
        with H.reuse(self.reader) as scope:
            for _ in range(2): self.assertBytesEqual(self.reader.expand_table(self.table, self.roots), expected)
            self.assertEqual((scope.bypassed, scope.hits, len(scope.cache)), (2, 0, 0))

    def test_original_errors_are_not_cached(self):
        missing, extra = deepcopy(self.table), deepcopy(self.table)
        del missing['snapshot']['format']; extra['unexpected'] = True
        invalid = list(self.roots); invalid[0] = 'zz' * 32
        with H.reuse(self.reader) as scope:
            for value, roots in ((None, self.roots), (None, self.roots), (missing, self.roots),
                                 (extra, self.roots), (self.table, invalid), (self.table, self.roots[:-1])):
                with self.assertRaises(ValueError): self.reader.expand_table(value, roots)
            self.assertEqual((scope.errors, scope.hits, len(scope.cache)), (6, 0, 0))

    def test_oversize_result_keeps_original_and_is_not_retained(self):
        with H.reuse(self.reader, max_bytes=1) as scope:
            self.assertBytesEqual(self.reader.expand_table(self.table, self.roots), self.original(self.table, self.roots))
            self.assertEqual((scope.unretained, scope.bytes, len(scope.cache)), (1, 0, 0))

    def test_entry_pressure_evicts_and_recomputes(self):
        with H.reuse(self.reader, max_entries=1) as scope:
            for value in (self.table, table('archive'), self.table):
                self.assertBytesEqual(self.reader.expand_table(value, self.roots), self.original(value, self.roots))
            self.assertEqual((scope.computations, scope.hits, scope.evictions), (3, 0, 2))
            self.assertEqual(scope.peak_entries, 1)

    def test_byte_pressure_counts_full_inputs_and_output(self):
        other = table('archive')
        weight = H.snapshot(other, self.roots)[1] + len(self.original(other, self.roots))
        with H.reuse(self.reader, max_bytes=weight) as scope:
            self.reader.expand_table(self.table, self.roots)
            self.reader.expand_table(other, self.roots)
            self.assertLessEqual(scope.peak_bytes, weight)
            self.assertGreater(scope.evictions, 0)

    def test_invalid_limits_do_not_install_anything(self):
        for args in ({'max_entries': True}, {'max_entries': 0}, {'max_entries': H.MAX_ENTRIES + 1},
                     {'max_bytes': False}, {'max_bytes': 0}, {'max_bytes': H.MAX_BYTES + 1}):
            with self.subTest(args=args), self.assertRaises(ValueError):
                with H.reuse(self.reader, **args): self.fail('invalid scope entered')
            self.assertIs(self.reader.expand_table, self.original)
        with H.reuse(self.reader) as scope: self.assertTrue(scope.intact())

    def test_snapshot_limits_and_cycles_use_original_fallback(self):
        for value in ('x' * (H.MAX_TABLE_BYTES + 1), [None] * (H.MAX_TABLE_NODES + 1)):
            changed = deepcopy(self.table); changed['queries'] = value
            self.assertTrue(H.snapshot(changed, self.roots) is None, 'oversize snapshot was admitted')
        cyclic = deepcopy(self.table); cyclic['queries'] = cyclic
        self.assertTrue(H.snapshot(cyclic, self.roots) is None, 'cyclic snapshot was admitted')

    def test_large_byte_assertion_failure_has_bounded_diagnostics(self):
        with self.assertRaises(AssertionError) as caught:
            self.assertBytesEqual(b'a' * (1 << 20), b'b' * (1 << 20))
        self.assertLess(len(str(caught.exception)), 512)

    def test_unselected_and_changed_original_are_refused(self):
        with self.assertRaises(ValueError):
            with H.reuse(H): self.fail('unselected module admitted')
        with mock.patch.object(self.reader, 'expand_table', lambda *_: b'forged'):
            with self.assertRaises(ValueError):
                with H.reuse(self.reader): self.fail('changed function admitted')

    def test_dependency_change_cannot_return_a_cached_result(self):
        with H.reuse(self.reader) as scope:
            self.reader.expand_table(self.table, self.roots)
            dependencies = ((self.reader.C, 'identifier'), (self.reader.C, 'digest'), (self.reader.M, 'encoded'),
                            (self.reader, 'require'), (self.reader.C.hashlib, 'sha3_256'),
                            (self.reader.C.re, 'fullmatch'), (self.reader.M.json, 'dumps'))
            for owner, name in dependencies:
                with mock.patch.object(owner, name, lambda *_: None):
                    with self.assertRaises(ValueError): self.reader.expand_table(self.table, self.roots)
            self.assertEqual(scope.hits, 0)

    def test_replaced_snapshot_function_cannot_change_cache_keys(self):
        with H.reuse(self.reader):
            self.reader.expand_table(self.table, self.roots)
            with mock.patch.object(H, 'snapshot', lambda *_: ('forged', 1)):
                with self.assertRaises(ValueError): self.reader.expand_table(self.table, self.roots)

    def test_nested_scope_refuses_without_disturbing_owner(self):
        with H.reuse(self.reader) as scope:
            with self.assertRaises(ValueError):
                with H.reuse(reader()): self.fail('nested scope entered')
            self.assertTrue(scope.intact())

    def test_unowned_active_marker_is_not_replaced_on_admission_failure(self):
        marker = object()
        with mock.patch.object(H, '_ACTIVE', marker):
            with self.assertRaises(ValueError):
                with H.reuse(self.reader): self.fail('unowned active marker admitted')
            self.assertIs(H._ACTIVE, marker)

    def test_other_thread_refuses_before_cache_access(self):
        errors = []
        with H.reuse(self.reader) as scope:
            def other():
                try: self.reader.expand_table(self.table, self.roots)
                except ValueError: errors.append('refused')
            child = threading.Thread(target=other); child.start(); child.join(5)
            self.assertFalse(child.is_alive())
            self.assertEqual(errors, ['refused'])
            self.assertEqual(scope.calls, 0)

    def test_concurrent_entry_is_refused_during_first_constructor(self):
        constructing, release = threading.Event(), threading.Event()
        original_constructor, results = H.TableReuse, []
        def blocked_constructor(*args, **kwargs):
            constructing.set()
            if not release.wait(5): raise ValueError('constructor control timed out')
            return original_constructor(*args, **kwargs)
        def first_owner():
            try:
                with H.reuse(self.reader) as scope: results.append(scope.intact())
            except BaseException as error: results.append(type(error).__name__)
        with mock.patch.object(H, 'TableReuse', side_effect=blocked_constructor):
            child = threading.Thread(target=first_owner); child.start()
            try:
                self.assertTrue(constructing.wait(5))
                with self.assertRaises(ValueError):
                    with H.reuse(reader()): self.fail('concurrent scope entered')
            finally:
                release.set(); child.join(10)
        self.assertFalse(child.is_alive())
        self.assertEqual(results, [True])
        self.assertIs(self.reader.expand_table, self.original)

    def test_exception_and_interrupt_restore_and_clear(self):
        for exception in (RuntimeError, KeyboardInterrupt):
            with self.subTest(exception=exception), self.assertRaises(exception):
                with H.reuse(self.reader) as scope:
                    self.reader.expand_table(self.table, self.roots)
                    raise exception('owned control')
            self.assertIs(self.reader.expand_table, self.original)
            self.assertTrue(scope.restored and scope.cleared and scope.closed)
            self.assertEqual((scope.bytes, len(scope.cache)), (0, 0))

    def test_source_failure_on_exit_also_restores_and_clears(self):
        with self.assertRaises(ValueError):
            with mock.patch.object(H, 'verify_sources', side_effect=[dict(H.SOURCE_PINS), ValueError('changed')]):
                with H.reuse(self.reader) as scope: self.reader.expand_table(self.table, self.roots)
        self.assertIs(self.reader.expand_table, self.original)
        self.assertTrue(scope.restored and scope.cleared)

    def test_replaced_wrapper_is_refused_and_restored(self):
        with self.assertRaises(ValueError):
            with H.reuse(self.reader) as scope: self.reader.expand_table = lambda *_: b'forged'
        self.assertIs(self.reader.expand_table, self.original)
        self.assertTrue(scope.restored and scope.cleared)

    def test_later_import_stays_unmodified_and_report_has_no_authority(self):
        with H.reuse(self.reader) as scope:
            later = reader()
            self.assertTrue(H.same_function(later.expand_table, H.REFERENCE.expand_table, later))
            self.reader.expand_table(self.table, self.roots)
        report = scope.report()
        self.assertTrue(report['complete_typed_input_keys'] and report['restored'] and report['cleared'])
        self.assertFalse(report['disk_cache_created'] or report['original_history_or_observation_checks_skipped'])
        self.assertEqual((report['retained_entries'], report['retained_logical_bytes']), (0, 0))


if __name__ == '__main__':
    unittest.main(verbosity=2)
