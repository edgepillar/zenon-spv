#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Adversarial controls for the read-only research patch planner."""
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('patch_plan', HERE / 'plan_patch.py')
PLAN = importlib.util.module_from_spec(spec)
spec.loader.exec_module(PLAN)
LIMITS = {'raw_bytes': 1024, 'records': 8, 'key_bytes': 64, 'value_bytes': 128, 'plan_bytes': 4096}
RAW = bytes.fromhex('0101610162000163')


def selected(raw=RAW, count=2):
    return {'bytes': len(raw), 'records': count, 'changes_hash': hashlib.sha3_256(raw).hexdigest()}


class PatchPlanTests(unittest.TestCase):
    def plan(self, raw=RAW, count=2, limits=None):
        return PLAN.make_plan(raw, selected(raw, count), limits or LIMITS)

    def cli(self, raw=RAW, changed=(), extra=(), present=True):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'private-consumer-input.dump'
            if present:
                path.write_bytes(raw)
            fields = {'raw': str(path), 'changes-hash': selected(raw)['changes_hash'],
                      'expected-bytes': str(len(raw)), 'expected-records': '2'}
            fields.update({'max-' + k.replace('_', '-'): str(v) for k, v in LIMITS.items()})
            fields.update(dict(changed))
            argv = [sys.executable, '-I', '-B', str(HERE / 'plan_patch.py')]
            for key, value in fields.items():
                argv.extend(['--' + key, value])
            return subprocess.run(argv + list(extra), capture_output=True, timeout=20), path

    def rejected(self, raw, count=1, limits=None):
        with self.assertRaises(PLAN.Refused):
            self.plan(raw, count, limits)

    def test_arbitrary_raw_plan_preserves_order_and_delete(self):
        self.assertEqual(self.plan()['events'], [
            {'operation': 'Put', 'key': '61', 'value': '62'},
            {'operation': 'Delete', 'key': '63', 'value': None}])

    def test_all_264_candidate_inputs_match_unsigned_preflight(self):
        accepted = 0
        for name, raw, limits, selection, fault in PLAN.ORACLE.inputs():
            expected, refusal = PLAN.ORACLE.preflight(raw, limits)
            matches = (len(raw) == selection['bytes'] and len(expected) == selection['records'] and
                       hashlib.sha3_256(raw).hexdigest() == selection['changes_hash'])
            with self.subTest(case=name):
                if refusal or not matches:
                    with self.assertRaises(PLAN.Refused):
                        PLAN.make_plan(raw, {k: v for k, v in selection.items() if k != 'name'}, limits | {'plan_bytes': 4096})
                else:
                    document = PLAN.make_plan(raw, {k: v for k, v in selection.items() if k != 'name'}, limits | {'plan_bytes': 4096})
                    self.assertEqual(document['events'], expected)
                    accepted += 1
        self.assertEqual(accepted, 18)  # Fault injection is not executed by this parser.

    def test_empty_raw_requires_selected_zero_counts(self):
        self.assertEqual(self.plan(b'', 0)['events'], [])
        self.rejected(b'', 1)

    def test_empty_put_is_distinct_from_delete(self):
        self.assertEqual(self.plan(b'\x01\x00\x00\x00\x00', 2)['events'], [
            {'operation': 'Put', 'key': '', 'value': ''},
            {'operation': 'Delete', 'key': '', 'value': None}])

    def test_duplicate_writes_are_not_normalized(self):
        raw = b'\x01\x01a\x01b\x01\x01a\x01c'
        self.assertEqual([r['value'] for r in self.plan(raw)['events']], ['62', '63'])

    def test_nonminimal_varints_require_their_raw_digest(self):
        raw = b'\x01\x81\x00a\x81\x00b'
        self.assertEqual(self.plan(raw, 1)['events'], self.plan(RAW[:5], 1)['events'])
        with self.assertRaises(PLAN.Refused):
            PLAN.make_plan(raw, selected(RAW[:5], 1), LIMITS)

    def test_every_unselected_complete_patch_prefix_refuses(self):
        for end in range(len(RAW)):
            with self.assertRaises(PLAN.Refused):
                PLAN.make_plan(RAW[:end], selected(), LIMITS)

    def test_invalid_record_types_refuse(self):
        for raw in (b'\x02', b'\xff', RAW + b'\x02'):
            self.rejected(raw)

    def test_varint_overflow_and_continuations_refuse(self):
        for length in (b'\xff' * 9 + b'\x02', b'\x80' * 10, b'\x80' * 11, b'\x80'):
            self.rejected(b'\x00' + length)

    def test_large_unsigned_lengths_refuse_before_slicing(self):
        for raw in (b'\x00' + b'\xff' * 9 + b'\x01', b'\x01\x00' + b'\xff' * 8 + b'\x7f'):
            self.rejected(raw)

    def test_truncated_key_and_value_refuse(self):
        for raw in (b'\x00\x03a', b'\x01\x01a\x03b', b'\x01\x01a\x80'):
            self.rejected(raw)

    def test_exact_raw_record_key_value_limits_succeed(self):
        limits = LIMITS | {'raw_bytes': 8, 'records': 2, 'key_bytes': 1, 'value_bytes': 1}
        self.assertEqual(self.plan(limits=limits)['events'], self.plan()['events'])

    def test_each_short_limit_refuses(self):
        for field, value in (('raw_bytes', 7), ('records', 1)):
            self.rejected(RAW, 2, LIMITS | {field: value})
        self.rejected(b'\x00\x02ab', 1, LIMITS | {'key_bytes': 1})
        self.rejected(b'\x01\x00\x02ab', 1, LIMITS | {'value_bytes': 1})

    def test_invalid_limit_shapes_types_and_ceiling_refuse(self):
        for field, ceiling in PLAN.CEILINGS.items():
            for value in (0, -1, True, 1.0, '1', ceiling + 1):
                self.rejected(RAW, 2, LIMITS | {field: value})
        for limits in ({}, LIMITS | {'extra': 1}, list(LIMITS)):
            with self.assertRaises(PLAN.Refused):
                PLAN.make_plan(RAW, selected(), limits)

    def test_invalid_selection_schema_refuses(self):
        for selection in ({}, selected() | {'name': 'untrusted'}, list(selected())):
            with self.assertRaises(PLAN.Refused):
                PLAN.make_plan(RAW, selection, LIMITS)

    def test_selected_byte_and_record_counts_are_exact_integers(self):
        for field in ('bytes', 'records'):
            for value in (-1, True, 1.0, '2', 1025):
                with self.assertRaises(PLAN.Refused):
                    PLAN.make_plan(RAW, selected() | {field: value}, LIMITS)

    def test_wrong_selected_hash_bytes_and_records_refuse(self):
        for field, value in (('bytes', 7), ('records', 1), ('changes_hash', '00' * 32)):
            with self.assertRaises(PLAN.Refused):
                PLAN.make_plan(RAW, selected() | {field: value}, LIMITS)

    def test_hash_alphabet_width_and_case_refuse(self):
        for value in ('', 'f' * 63, 'f' * 65, 'G' * 64, selected()['changes_hash'].upper(), 123):
            with self.assertRaises(PLAN.Refused):
                PLAN.make_plan(RAW, selected() | {'changes_hash': value}, LIMITS)

    def test_mutable_raw_aliases_refuse(self):
        for raw in (bytearray(RAW), memoryview(RAW), RAW.hex()):
            with self.assertRaises(PLAN.Refused):
                PLAN.make_plan(raw, selected(), LIMITS)

    def test_plan_owns_metadata_and_detached_hex_events(self):
        selection, limits = selected(), LIMITS.copy()
        document = PLAN.make_plan(RAW, selection, limits)
        before = copy.deepcopy(document)
        selection['changes_hash'] = '00' * 32
        limits['raw_bytes'] = 1
        self.assertEqual(document, before)

    def test_source_revision_is_explicit_and_strict(self):
        revision = 'a' * 40
        self.assertEqual(PLAN.make_plan(RAW, selected(), LIMITS, revision)['source_revision'], revision)
        for revision in ('main', 'a' * 39, 'A' * 40, 123):
            with self.assertRaises(PLAN.Refused):
                PLAN.make_plan(RAW, selected(), LIMITS, revision)

    def test_output_limit_includes_newline_and_no_partial_result(self):
        document = self.plan()
        raw = PLAN.encode_plan(document, 4096)
        self.assertEqual(PLAN.encode_plan(document, len(raw)), raw)
        for cap in (len(raw) - 1, 1, 0, True, PLAN.CEILINGS['plan_bytes'] + 1):
            with self.assertRaises(PLAN.Refused):
                PLAN.encode_plan(document, cap)

    def test_regular_file_read_is_bounded_and_read_only(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'input.dump'
            path.write_bytes(RAW)
            self.assertEqual(PLAN.read_raw(path, selected(), LIMITS), RAW)
            self.assertEqual(path.read_bytes(), RAW)
            with patch.object(PLAN.os, 'open', side_effect=AssertionError('must not open oversized file')):
                with self.assertRaises(PLAN.Refused):
                    PLAN.read_raw(path, selected(), LIMITS | {'raw_bytes': 7})

    def test_directory_and_symlink_refuse(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(PLAN.Refused):
                PLAN.read_raw(Path(directory), selected(), LIMITS)
            link = Path(directory) / 'link'
            # Windows symlink creation may require privileges; the lstat boundary
            # is exercised with a descriptor-free mock on every native platform.
            with patch.object(PLAN.Path, 'lstat', return_value=type('Info', (), {'st_mode': 0o120777})()):
                with self.assertRaises(PLAN.Refused):
                    PLAN.read_raw(link, selected(), LIMITS)

    def test_file_growth_read_uses_cap_plus_one(self):
        stream = io.BytesIO(b'x' * (LIMITS['raw_bytes'] + 1))
        stream.fileno = lambda: 99
        observed = []
        read = stream.read
        stream.read = lambda size: (observed.append(size), read(size))[1]
        regular = type('Info', (), {'st_mode': 0o100600, 'st_size': 8})()
        with patch.object(PLAN.Path, 'lstat', return_value=regular), patch.object(PLAN.os, 'open', return_value=99), \
                patch.object(PLAN.os, 'fdopen', return_value=stream), patch.object(PLAN.os, 'fstat', return_value=regular):
            with self.assertRaises(PLAN.Refused):
                PLAN.read_raw('input', selected(), LIMITS)
        self.assertEqual(observed, [LIMITS['raw_bytes'] + 1])

    def test_cli_roundtrip_emits_only_complete_plan(self):
        result, path = self.cli()
        self.assertEqual((result.returncode, result.stderr), (0, b''))
        self.assertEqual(json.loads(result.stdout), self.plan())
        self.assertNotIn(str(path).encode(), result.stdout)

    def test_cli_failures_are_private_and_emit_no_partial_plan(self):
        for changes, extra, present in (([('changes-hash', '00' * 32)], (), True),
                ([('max-plan-bytes', '1')], (), True), ((), (), False),
                ((), ('--expected-records', '1'), True),
                ((), ('--private-unknown-option', 'sensitive-endpoint'), True)):
            result, path = self.cli(changed=changes, extra=extra, present=present)
            self.assertEqual((result.returncode, result.stdout), (1, b''))
            self.assertNotIn(str(path).encode(), result.stderr)
            self.assertNotIn(b'sensitive-endpoint', result.stderr)
            self.assertNotIn(b'Traceback', result.stderr)

    def test_cli_requires_explicit_canonical_limits(self):
        for value in ('01', '+1', '1.0', '-1', 'true', '99999999999'):
            result, _ = self.cli(changed=[('max-records', value)])
            self.assertEqual((result.returncode, result.stdout), (1, b''))

    def test_production_and_backend_scope_remain_closed(self):
        document = self.plan()
        self.assertEqual(document['consumer_result'], 'REFUSED')
        self.assertEqual({key for key, value in document['scope'].items() if value},
                         {'read_only_unsigned_byte_parsing_executed', 'independently_selected_raw_bytes_required'})
        self.assertNotIn('target', document)
        self.assertNotIn('endpoint', document)


if __name__ == '__main__':
    unittest.main(verbosity=2)
