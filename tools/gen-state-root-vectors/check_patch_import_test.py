#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Adversarial controls for bounded bytes, detached staging and refusal gates."""
import copy
import importlib.util
from pathlib import Path
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('patch_import_check', HERE / 'check_patch_import.py')
CHECK = importlib.util.module_from_spec(spec)
spec.loader.exec_module(CHECK)


class PatchImportControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw, cls.corpus = CHECK.BYTE.read_corpus(HERE / 'testdata/candidate-patch-import.json')

    def row(self, document, name):
        return next(r for r in document['cases'] if r['name'] == name)

    def change(self, function):
        document = copy.deepcopy(self.corpus)
        function(document)
        with self.assertRaises((ValueError, KeyError, TypeError)):
            CHECK.check_corpus(document)

    def test_inventory_and_independent_complete_selection(self):
        report = CHECK.check_corpus(self.corpus)
        self.assertEqual((report['patch_import_cases'], report['reused_decode_cases']), (264, 232))
        self.assertEqual(report['consumer_refusals'], 264)
        self.assertGreater(report['rejected_after_staging_callbacks'], 0)

    def test_missing_duplicate_reordered_cases_rejected(self):
        self.change(lambda d: d['cases'].pop(17))
        self.change(lambda d: d['cases'].append(copy.deepcopy(d['cases'][0])))
        self.change(lambda d: d['cases'].reverse())

    def test_every_incomplete_prefix_rejected_before_constructor(self):
        for cut in range(168):
            row = self.row(self.corpus, 'prefix-%03d' % cut)
            self.assertEqual((row['constructor_calls'], row['default_replay_calls'], row['target_replacements']), (0, 0, 0))
        self.change(lambda d: self.row(d, 'prefix-067').update(research_import_result='STAGED', target_replacements=1))

    def test_boundary_prefixes_need_selected_length_count_and_hash(self):
        for name in ('prefix-000', 'prefix-067', 'prefix-101'):
            self.assertEqual(self.row(self.corpus, name)['refusal'], 'selection_mismatch')
        self.change(lambda d: self.row(d, 'prefix-067')['selection'].update(bytes=67, records=1))

    def test_malformed_suffix_cannot_publish_matching_prefix_state(self):
        self.change(lambda d: self.row(d, 'after-complete/type-02').update(target_replacements=1))

    def test_huge_unsigned_lengths_are_rejected_before_candidate(self):
        for prefix in ('fresh/', 'after-one/', 'after-complete/'):
            for field in ('delete-key', 'put-key', 'put-value'):
                for number in ((1 << 63) - 1, 1 << 63, (1 << 64) - 1):
                    row = self.row(self.corpus, prefix + field + '-length-%d' % number)
                    self.assertEqual(row['constructor_calls'], 0)
        self.change(lambda d: self.row(d, 'fresh/put-key-length-9223372036854775807').update(constructor_calls=1))

    def test_invalid_types_varints_and_truncated_bytes_bound(self):
        for name in ('type-02', 'type-ff', 'key-overflow-varint', 'key-ten-continuations', 'key-eleven-continuations',
                     'key-truncated-varint', 'key-short-bytes', 'value-overflow-varint', 'value-truncated-varint', 'value-short-bytes'):
            self.change(lambda d: self.row(d, 'fresh/' + name).update(refusal='selection_mismatch'))

    def test_exact_limits_allow_complete_replay(self):
        row = self.row(self.corpus, 'exact-all-bounds')
        self.assertEqual((row['preflight_records'], row['constructor_calls'], row['default_replay_calls'], row['target_replacements']), (3, 1, 1, 1))
        self.change(lambda d: self.row(d, 'exact-all-bounds').update(refusal='raw_limit'))

    def test_raw_limit_enforced_before_constructor(self):
        self.change(lambda d: self.row(d, 'raw-limit-short').update(constructor_calls=1))

    def test_record_key_value_limits_enforced_before_constructor(self):
        for name in ('record-limit-short', 'key-limit-short', 'value-limit-short'):
            self.change(lambda d: self.row(d, name).update(constructor_calls=1))

    def test_zero_and_oversized_limit_configuration_rejected(self):
        for row in self.corpus['cases']:
            if row['name'].startswith('invalid-limit-'):
                self.assertEqual((row['refusal'], row['constructor_calls']), ('invalid_limits', 0))
        self.change(lambda d: self.row(d, 'invalid-limit-0-0').update(refusal=''))

    def test_independent_dump_byte_count_hash_and_record_count_bound(self):
        for name in ('wrong-byte-count', 'wrong-changes-hash', 'wrong-record-count'):
            self.change(lambda d: self.row(d, name).update(constructor_calls=1))

    def test_constructor_error_with_patch_discards_it(self):
        self.change(lambda d: self.row(d, 'load-error').update(default_replay_calls=1))
        self.change(lambda d: self.row(d, 'load-error').update(injected_fault='none'))

    def test_nil_constructor_patch_rejected_without_replay(self):
        self.change(lambda d: self.row(d, 'load-nil').update(default_replay_calls=1))

    def test_replay_error_after_first_callback_does_not_publish(self):
        row = self.row(self.corpus, 'replay-error-first')
        self.assertEqual(len(row['staging_callbacks']), 1)
        self.assertEqual(row['target_after'], row['target_before'])
        self.change(lambda d: self.row(d, 'replay-error-first').update(target_replacements=1))

    def test_error_after_all_callbacks_still_rejects(self):
        self.assertEqual(len(self.row(self.corpus, 'replay-error-complete')['staging_callbacks']), 3)
        self.change(lambda d: self.row(d, 'replay-error-complete').update(refusal='', research_import_result='STAGED'))

    def test_missing_extra_or_changed_callback_rejected(self):
        for name in ('replay-omit-last', 'replay-extra', 'replay-wrong-value'):
            self.change(lambda d: self.row(d, name).update(target_replacements=1, research_import_result='STAGED'))

    def test_callback_order_and_delete_semantics_bound(self):
        self.change(lambda d: self.row(d, 'prefix-168')['staging_callbacks'].reverse())
        self.change(lambda d: self.row(d, 'prefix-168')['staging_callbacks'][1].update(operation='Put', value=''))

    def test_every_rejected_target_preserves_the_full_initial_map(self):
        for row in self.corpus['cases']:
            if row['research_import_result'] == 'REJECTED':
                self.assertEqual(row['target_before'], row['target_after'])
                self.assertEqual(row['target_replacements'], 0)
        self.change(lambda d: self.row(d, 'replay-error-first')['target_after'].pop())

    def test_success_preserves_unrelated_key_and_publishes_once(self):
        self.change(lambda d: self.row(d, 'prefix-168')['target_after'].pop())
        self.change(lambda d: self.row(d, 'prefix-168').update(target_replacements=2))

    def test_input_alias_is_detached_before_candidate_loading(self):
        row = self.row(self.corpus, 'mutate-source-after-load')
        self.assertNotEqual(row['input'], row['source_after'])
        self.assertEqual(row['target_after'], self.row(self.corpus, 'prefix-168')['target_after'])
        self.change(lambda d: self.row(d, 'mutate-source-after-load').update(source_after=row['input']))

    def test_owned_dump_mutation_rejected_before_replay(self):
        self.change(lambda d: self.row(d, 'mutate-owned-after-load').update(default_replay_calls=1))

    def test_nonminimal_varints_need_their_own_raw_selection(self):
        a, b = self.row(self.corpus, 'prefix-168'), self.row(self.corpus, 'overlong-complete-selected')
        self.assertEqual(a['target_after'], b['target_after'])
        self.assertNotEqual(a['selection']['changes_hash'], b['selection']['changes_hash'])
        self.assertEqual(self.row(self.corpus, 'valid-overlong-complete')['constructor_calls'], 0)
        self.change(lambda d: self.row(d, 'overlong-complete-selected')['selection'].update(changes_hash=a['selection']['changes_hash']))

    def test_duplicate_order_and_last_write_need_complete_raw_selection(self):
        self.assertEqual(self.row(self.corpus, 'valid-duplicate-put-9')['constructor_calls'], 0)
        self.change(lambda d: self.row(d, 'duplicate-10-selected').update(target_after=self.row(d, 'duplicate-9-selected')['target_after']))

    def test_empty_syntax_does_not_authenticate_typed_state(self):
        self.change(lambda d: self.row(d, 'empty-put-selected')['staging_callbacks'][0].update(value=None))
        self.change(lambda d: self.row(d, 'empty-selected').update(consumer_result='ACCEPTED'))

    def test_strict_scalar_shape_source_pin_and_scope(self):
        self.change(lambda d: self.row(d, 'prefix-168').update(target_replacements=True))
        self.change(lambda d: d.update(unplanned=True))
        self.change(lambda d: d['source'].update(revision='main'))
        self.change(lambda d: d['scope'].update(single_exclusive_caller=1))

    def test_duplicate_trailing_and_oversized_json_rejected(self):
        for raw in (b'{"cases":[],"cases":[]}', self.raw + b'{}', b' ' * (CHECK.BYTE.MAX_FILE_BYTES + 1)):
            with self.subTest(bytes=len(raw)), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'input.json'
                path.write_bytes(raw)
                with self.assertRaises(ValueError):
                    CHECK.BYTE.read_corpus(path)

    def test_production_snapshot_durability_and_trust_gates_remain_closed(self):
        for field, value in CHECK.SCOPE.items():
            if not value:
                self.change(lambda d: d['scope'].update({field: True}))
        self.change(lambda d: self.row(d, 'prefix-168').update(consumer_result='ACCEPTED'))


if __name__ == '__main__':
    unittest.main(verbosity=2)
