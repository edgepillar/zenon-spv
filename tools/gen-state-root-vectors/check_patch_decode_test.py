#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Adversarial controls for selected bytes, partial replay and exception scope."""
import copy
import importlib.util
from pathlib import Path
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('patch_decode_check', HERE / 'check_patch_decode.py')
CHECK = importlib.util.module_from_spec(spec)
spec.loader.exec_module(CHECK)


class PatchDecodeControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw, cls.corpus = CHECK.BYTE.read_corpus(HERE / 'testdata/candidate-patch-decode.json')

    def change(self, function):
        document = copy.deepcopy(self.corpus)
        function(document)
        with self.assertRaises((ValueError, KeyError, TypeError)):
            CHECK.check_corpus(document)

    def row(self, document, name):
        return next(row for row in document['cases'] if row['name'] == name)

    def test_all_selected_bytes_prefixes_and_refusals(self):
        report = CHECK.check_corpus(self.corpus)
        self.assertEqual((report['patch_decode_cases'], report['all_byte_prefix_cases'], report['valid_prefix_decodes']), (232, 169, 4))
        self.assertEqual(report['consumer_refusals'], 232)
        self.assertGreater(report['returned_partial_patches_after_error'], 0)
        self.assertGreater(report['decode_runtime_bounds_panics'], 0)
        self.assertGreater(report['diagnostic_replay_runtime_bounds_panics'], 0)
        self.assertFalse(report['production_corruption_reachability_qualified'])

    def test_prefix_inventory_cannot_omit_duplicate_or_reorder(self):
        self.change(lambda d: d['cases'].pop(17))
        self.change(lambda d: d['cases'].append(copy.deepcopy(d['cases'][0])))
        self.change(lambda d: d['cases'].reverse())

    def test_selected_raw_bytes_bound_separately_from_outcomes(self):
        self.change(lambda d: self.row(d, 'prefix-067').update(input=CHECK.complete().hex()))

    def test_record_boundary_truncation_is_valid_but_incomplete(self):
        self.change(lambda d: self.row(d, 'prefix-067').update(diagnostic_state_matches_selected_fixture=True))
        self.change(lambda d: self.row(d, 'prefix-101').update(load_error='truncated'))

    def test_mid_record_truncation_must_report_the_error(self):
        self.change(lambda d: self.row(d, 'prefix-068').update(load_error=None))

    def test_error_returned_patch_preserves_the_completed_prefix(self):
        self.change(lambda d: self.row(d, 'after-one/type-02').update(patch_returned=False, indexed_records=None, replay_callbacks=[]))

    def test_error_is_never_reported_as_a_default_replay_error(self):
        self.change(lambda d: self.row(d, 'after-one/type-02').update(replay_error='synthetic Patch.Replay failure'))

    def test_invalid_type_ordinary_error_and_runtime_panic_are_distinct(self):
        self.change(lambda d: self.row(d, 'fresh/type-ff').update(load_panic='runtime_bounds'))

    def test_missing_and_overflowing_varints_are_rejected(self):
        for name in ('key-truncated-varint', 'key-overflow-varint', 'key-ten-continuations', 'key-eleven-continuations', 'value-overflow-varint'):
            with self.subTest(name=name):
                self.change(lambda d: self.row(d, 'fresh/' + name).update(load_error=None))

    def test_signed_length_arithmetic_load_panics_are_bound(self):
        self.change(lambda d: self.row(d, 'fresh/put-key-length-9223372036854775807').update(load_panic=None))

    def test_load_exception_prevents_patch_return(self):
        self.change(lambda d: self.row(d, 'fresh/put-key-length-9223372036854775807').update(patch_returned=True, dump=''))

    def test_diagnostic_replay_exception_is_not_a_load_exception(self):
        self.change(lambda d: self.row(d, 'fresh/delete-key-length-18446744073709551615').update(replay_panic=None))

    def test_replay_exception_cannot_erase_prior_callback_delivery(self):
        self.change(lambda d: self.row(d, 'after-one/delete-key-length-18446744073709551615').update(replay_callbacks=[]))

    def test_completed_record_count_is_independently_bound(self):
        self.change(lambda d: self.row(d, 'after-one/type-02').update(indexed_records=3))

    def test_dump_and_hash_cover_all_bytes_even_on_load_error(self):
        for field, result in [('dump', CHECK.complete()[:67].hex()), ('patch_hash', CHECK.BYTE.digest(CHECK.complete()[:67]).hex())]:
            with self.subTest(field=field):
                self.change(lambda d: self.row(d, 'after-one/type-02').update({field: result}))

    def test_overlong_equivalent_encoding_changes_the_dump_hash(self):
        a = self.row(self.corpus, 'prefix-168')
        b = self.row(self.corpus, 'valid-overlong-complete')
        self.assertEqual(a['replay_callbacks'], b['replay_callbacks'])
        self.assertNotEqual(a['patch_hash'], b['patch_hash'])
        self.change(lambda d: self.row(d, 'valid-overlong-complete').update(patch_hash=a['patch_hash']))

    def test_duplicate_write_order_and_last_value_are_bound(self):
        self.change(lambda d: self.row(d, 'valid-duplicate-put-10')['replay_callbacks'].reverse())
        self.change(lambda d: self.row(d, 'valid-duplicate-put-10').update(diagnostic_state_matches_selected_fixture=True))

    def test_empty_keys_and_values_are_syntax_not_typed_proof_acceptance(self):
        self.change(lambda d: self.row(d, 'valid-empty-put')['replay_callbacks'][0].update(value=None))

    def test_complete_manifest_cannot_be_selected_from_partial_output(self):
        self.change(lambda d: d.update(selected_complete_manifest=self.row(d, 'prefix-067')['diagnostic_manifest']))

    def test_decode_error_with_matching_state_is_still_rejected(self):
        a = self.row(self.corpus, 'after-complete/type-02')
        self.assertTrue(a['diagnostic_state_matches_selected_fixture'])
        self.assertIsNotNone(a['load_error'])
        self.change(lambda d: self.row(d, 'after-complete/type-02').update(consumer_result='ACCEPTED'))

    def test_matching_valid_state_also_keeps_trust_gates_closed(self):
        self.change(lambda d: self.row(d, 'prefix-168').update(consumer_result='ACCEPTED'))

    def test_scalar_types_closed_shapes_and_dependency_pin(self):
        self.change(lambda d: self.row(d, 'prefix-000').update(indexed_records=False))
        self.change(lambda d: d['scope'].update(reference_64_bit_integers=1))
        self.change(lambda d: d['dependency'].update(version='main'))
        self.change(lambda d: self.row(d, 'prefix-000').update(unplanned=True))

    def test_duplicate_trailing_and_oversized_json_rejected(self):
        for raw in (b'{"cases":[],"cases":[]}', self.raw + b'{}', b' ' * (2 * 1024 * 1024 + 1)):
            with self.subTest(bytes=len(raw)), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'input.json'
                path.write_bytes(raw)
                with self.assertRaises(ValueError):
                    CHECK.BYTE.read_corpus(path)

    def test_production_execution_reachability_and_activation_remain_unqualified(self):
        for field in ('production_caller_execution', 'production_corruption_reachability_qualified', 'node_database_opened',
                      'actual_NodeTree_executed', 'resource_measurements_executed', 'network_execution',
                      'full_node_started', 'profile_agreed', 'network_activation_authenticated', 'runtime_state_proof_acceptance'):
            with self.subTest(field=field):
                self.change(lambda d: d['scope'].update({field: True}))


if __name__ == '__main__':
    unittest.main(verbosity=2)
