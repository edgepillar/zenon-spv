#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Adverse controls for bounded complete-map hex translation batching."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('batch_hex_controls', HERE / 'project_target_hex.py')
HEX = importlib.util.module_from_spec(spec)
spec.loader.exec_module(HEX)
FINITE_CASES = 2610


def target(count=32):
    return {'%08x' % index: '00' * 32 for index in range(count)}


def outcome(function, value, limits):
    try:
        return 'RETURN', function(value, limits)
    except Exception as error:
        return 'RAISE', type(error).__name__, str(error)


def candidate(value, limits):
    return HEX.target_refusal(value, limits, HEX.REFERENCE.CEILINGS)


class BatchHexControls(unittest.TestCase):
    def compare(self, value, limits=None):
        limits = HEX.REFERENCE.CEILINGS if limits is None else limits
        before = copy.deepcopy(value)
        self.assertEqual(outcome(HEX.REFERENCE.target_refusal, value, limits),
                         outcome(candidate, value, limits))
        self.assertEqual(value, before)

    def test_2610_finite_ascii_unicode_and_field_boundary_cases(self):
        count = 0
        for char in [chr(index) for index in range(256)] + ['\u0660', '\uff10', '\U0001f600', '\ud800', '\u200b']:
            for text in ('', char, char * 2, '00' + char * 2, char * 2 + '00'):
                for field in ('key', 'value'):
                    value = target()
                    key = next(iter(value))
                    if field == 'key':
                        del value[key]
                        value[text] = '00'
                    else:
                        value[key] = text
                    self.assertEqual(len(value), 32)
                    self.compare(value)
                    count += 1
        self.assertEqual(count, FINITE_CASES)

    def test_batch_entry_boundaries_preserve_complete_validation(self):
        for count in (0, 1, 31, 32, 33, 4095, 4096):
            value = target(count)
            total = sum(len(key) + len(text) for key, text in value.items())
            self.assertIs(HEX.batched_encoding(value, total), False if count >= 32 else None)
            self.compare(value)
        self.compare(target(4097))
        value = target(4097)
        limits = HEX.REFERENCE.CEILINGS | {'entries': 4097}
        self.assertIsNone(HEX.batched_encoding(value, sum(len(k) + len(v) for k, v in value.items())))
        self.assertEqual(HEX.target_refusal(value, limits, limits), '')

    def test_exact_character_ceiling_and_independent_hard_batch_cap(self):
        value = target()
        key = next(iter(value))
        total = sum(len(k) + len(v) for k, v in value.items())
        value[key] += '00' * ((HEX.MAX_BATCH_HEX_BYTES - total) // 2)
        self.assertEqual(sum(len(k) + len(v) for k, v in value.items()), 1 << 20)
        self.assertIs(HEX.batched_encoding(value, 1 << 20), False)
        self.compare(value)
        value[key] += '00'
        self.assertIsNone(HEX.batched_encoding(value, (1 << 20) + 2))
        self.compare(value)
        limits = HEX.REFERENCE.CEILINGS | {'hex_bytes': (1 << 20) + 2}
        self.assertEqual(HEX.target_refusal(value, limits, limits), '')

    def test_two_odd_fields_cannot_cancel_across_a_join_boundary(self):
        for same_entry in (False, True):
            value = target()
            first, second = list(value)[:2]
            value[first] = '0'
            if same_entry:
                value[first + '0'] = value.pop(first)
            else:
                value[second] = 'f'
            self.assertEqual(sum(len(k) + len(v) for k, v in value.items()) % 2, 0)
            self.assertEqual(candidate(value, HEX.REFERENCE.CEILINGS), 'invalid_target_encoding')
            self.compare(value)

    def test_first_middle_and_last_corruption_cannot_hide_in_aggregation(self):
        for index in (0, 16, 31):
            for text in ('GG', 'Aa', '  ', '\n\t', '\x00\x00', '0', '\uff10\uff10'):
                value = target()
                value[list(value)[index]] = text
                self.compare(value)
                self.assertEqual(candidate(value, HEX.REFERENCE.CEILINGS), 'invalid_target_encoding')

    def test_limit_then_entry_then_bytes_then_encoding_refusal_order(self):
        value = target()
        value[next(iter(value))] = 'GG'
        total = sum(len(k) + len(v) for k, v in value.items())
        for limits, expected in (({'entries': False, 'hex_bytes': 1}, 'invalid_target_limits'),
                                 ({'entries': 31, 'hex_bytes': 1}, 'target_entry_limit'),
                                 ({'entries': 32, 'hex_bytes': total - 1}, 'target_hex_limit'),
                                 ({'entries': 32, 'hex_bytes': total}, 'invalid_target_encoding')):
            self.compare(value, limits)
            self.assertEqual(candidate(value, limits), expected)

    def test_repeated_map_identity_still_rechecks_all_current_fields_and_limits(self):
        value = target()
        key = list(value)[-1]
        self.assertEqual(candidate(value, HEX.REFERENCE.CEILINGS), '')
        value[key] = 'GG'
        self.assertEqual(candidate(value, HEX.REFERENCE.CEILINGS), 'invalid_target_encoding')
        value[key] = '00'
        self.assertEqual(candidate(value, HEX.REFERENCE.CEILINGS), '')
        self.assertEqual(candidate(value, {'entries': 31, 'hex_bytes': 1 << 20}), 'target_entry_limit')
        value['ff' * 8] = '00'
        self.assertEqual(candidate(value, {'entries': 32, 'hex_bytes': 1 << 20}), 'target_entry_limit')

    def test_string_subclasses_keep_exact_length_iteration_and_exception_traces(self):
        for preceding in ('00', 'GG', '0'):
            for raises in (False, True):
                def execute(function):
                    events = []
                    class Text(str):
                        def __len__(self):
                            events.append('length')
                            return super().__len__()
                        def __iter__(self):
                            events.append('iteration')
                            if raises:
                                raise RuntimeError('selected subclass iteration')
                            return iter('GG')
                        def translate(self, _):
                            raise AssertionError('Subclass translation is outside the reference path')
                    value = target()
                    first, last = list(value)[0], list(value)[-1]
                    value[first] = preceding
                    value[last] = Text('00')
                    return outcome(function, value, HEX.REFERENCE.CEILINGS), events
                self.assertEqual(execute(HEX.REFERENCE.target_refusal), execute(candidate))

    def test_nonbuiltin_mapping_keeps_items_and_length_call_order(self):
        def execute(function):
            events = []
            class Mapping(dict):
                def __len__(self):
                    events.append('mapping-length')
                    return super().__len__()
                def items(self):
                    events.append('mapping-items')
                    return super().items()
            result = outcome(function, Mapping(target()), HEX.REFERENCE.CEILINGS)
            return result, events
        self.assertEqual(execute(HEX.REFERENCE.target_refusal), execute(candidate))

    def test_nonbuiltin_limits_keep_lookup_order_and_failures(self):
        for raises in (False, True):
            def execute(function):
                events = []
                class Limits(dict):
                    def __getitem__(self, key):
                        events.append(key)
                        if raises and len(events) == 4:
                            raise KeyError('selected lookup')
                        return super().__getitem__(key)
                return outcome(function, target(), Limits(HEX.REFERENCE.CEILINGS)), events
            self.assertEqual(execute(HEX.REFERENCE.target_refusal), execute(candidate))

    def test_custom_value_types_are_not_hashed_or_compared_for_admission(self):
        class Meta(type):
            def __hash__(cls):
                raise AssertionError('Admission must not hash a user type')
            def __eq__(cls, other):
                raise AssertionError('Admission must not compare a user type')
        class Text(str, metaclass=Meta):
            pass
        value = target()
        value[next(iter(value))] = Text('00')
        self.assertEqual(outcome(HEX.REFERENCE.target_refusal, value, HEX.REFERENCE.CEILINGS),
                         outcome(candidate, value, HEX.REFERENCE.CEILINGS))

    def test_changed_translation_tables_retain_prior_pointwise_results(self):
        value = target()
        key = list(value)[-1]
        for table, text, expected in ((HEX.DELETE_HEX | {ord('G'): None}, 'GG', ''),
                                      ({k: v for k, v in HEX.DELETE_HEX.items() if k != ord('f')}
                                       | {ord('G'): None}, 'GG', 'invalid_target_encoding'),
                                      (HEX.DELETE_HEX | {ord('0'): 'x'}, '00', 'invalid_target_encoding'),
                                      ({k: v for k, v in HEX.DELETE_HEX.items() if k != ord('f')}, 'ff', 'invalid_target_encoding')):
            value[key] = text
            with mock.patch.object(HEX, 'DELETE_HEX', table):
                self.assertIsNone(HEX.batched_encoding(value, 4096))
                self.assertEqual(candidate(value, HEX.REFERENCE.CEILINGS), expected)
        with mock.patch.object(HEX, 'DELETE_HEX', HEX.DELETE_HEX | {ord('0'): object()}):
            with self.assertRaises(TypeError):
                candidate(value, HEX.REFERENCE.CEILINGS)

    def test_custom_translation_mapping_keeps_pointwise_lookup_trace(self):
        def execute(use_candidate):
            events = []
            class Table(dict):
                def __getitem__(self, key):
                    events.append(key)
                    return super().__getitem__(key)
            value = target()
            value[list(value)[-1]] = 'ff'
            table = Table(HEX.DELETE_HEX)
            with mock.patch.object(HEX, 'DELETE_HEX', table):
                if use_candidate:
                    result = candidate(value, HEX.REFERENCE.CEILINGS)
                else:
                    result = 'invalid_target_encoding' if any(
                        len(text) % 2 or bool(text.translate(table))
                        for item in value.items() for text in item) else ''
            return result, events
        self.assertEqual(execute(False), execute(True))

    def test_nonbuiltin_field_fallback_keeps_encoding_error_precedence(self):
        for invalid_first in (False, True):
            value = target()
            first, last = list(value)[0], list(value)[-1]
            value[first] = 'GG' if invalid_first else '00'
            value[last] = 1
            self.compare(value)
        for field in (None, True, b'00', ['0', '0']):
            value = target()
            value[list(value)[-1]] = field
            self.compare(value)

    def postcount_mutation(self, kind):
        def execute(use_candidate):
            value = target()
            first, last = list(value)[0], list(value)[-1]
            events, observed = [], []
            class Limits(dict):
                def __getitem__(self, key):
                    if key == 'hex_bytes':
                        events.append('hex-lookup')
                        if events.count('hex-lookup') == 3:
                            value[first] = '00' * (1 << 20)
                    return super().__getitem__(key)
            class Text(str):
                def __len__(self):
                    events.append('field-length')
                    value[first], value[last] = '00' * (1 << 20), '00'
                    return super().__len__()
            limits = Limits(HEX.REFERENCE.CEILINGS) if kind == 'limit' else HEX.REFERENCE.CEILINGS
            if kind == 'field':
                value[last] = Text('00')
            original = HEX.batched_encoding
            def inspect(current, total):
                admitted = original(current, total)
                observed.append((total, sum(len(k) + len(v) for k, v in current.items()), admitted))
                return admitted
            with mock.patch.object(HEX, 'batched_encoding', side_effect=inspect):
                result = outcome(candidate if use_candidate else HEX.REFERENCE.target_refusal, value, limits)
            return result, events, observed
        reference, selected = execute(False), execute(True)
        self.assertEqual(reference[:2], selected[:2])
        self.assertEqual(selected[0], ('RETURN', ''))
        self.assertEqual(len(selected[2]), 1)
        before, after, admission = selected[2][0]
        self.assertLess(before, HEX.MAX_BATCH_HEX_BYTES)
        self.assertGreater(after, HEX.MAX_BATCH_HEX_BYTES)
        self.assertIsNone(admission)

    def test_mutating_limit_lookup_cannot_admit_postcount_aggregate_growth(self):
        self.postcount_mutation('limit')

    def test_self_replacing_length_hook_cannot_hide_postcount_aggregate_growth(self):
        self.postcount_mutation('field')


if __name__ == '__main__':
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(BatchHexControls)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful() or result.skipped:
        raise SystemExit(1)
    print(json.dumps({
        'kind': 'complete-map-hex-batch-controls', 'controls_run': result.testsRun,
        'finite_equivalence_cases': FINITE_CASES, 'complete_map_checks_preserved': True,
        'minimum_batch_entries': HEX.MIN_BATCH_ENTRIES, 'maximum_batch_entries': HEX.MAX_BATCH_ENTRIES,
        'maximum_batch_hex_characters': HEX.MAX_BATCH_HEX_BYTES,
        'per_field_parity_preserved': True, 'nonbuiltin_pointwise_behavior_preserved': True,
        'actual_aggregate_character_bound_rechecked': True,
        'cache_or_incremental_counters_used': False, 'production_acceptance_enabled': False,
        'source_inputs': {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                          for path in (Path(__file__), HERE / 'project_target_hex.py', HERE / 'check_patch_targets.py')},
    }, sort_keys=True))
