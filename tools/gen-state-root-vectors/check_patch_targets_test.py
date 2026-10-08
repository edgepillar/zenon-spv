#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Adversarial fixture controls for bounded target cloning and ordered replay."""
import copy
import importlib.util
from pathlib import Path
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('patch_target_check', HERE / 'check_patch_targets.py')
CHECK = importlib.util.module_from_spec(spec)
spec.loader.exec_module(CHECK)


class PatchTargetControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw, cls.document = CHECK.BYTE.read_corpus(HERE / 'testdata/candidate-patch-targets.json')

    def row(self, name, document=None):
        return next(r for r in (document or self.document)['cases'] if r['name'] == name)

    def change(self, action):
        document = copy.deepcopy(self.document)
        action(document)
        with self.assertRaises((ValueError, KeyError, TypeError)):
            CHECK.check_corpus(document)

    def test_full_literal_inventory_and_closed_consumers(self):
        report = CHECK.check_corpus(self.document)
        self.assertEqual(report['patch_target_cases'], len(CHECK.inputs()))
        self.assertEqual(report['original_aliases_unchanged'], report['patch_target_cases'])
        self.assertEqual(report['consumer_refusals'], report['patch_target_cases'])

    def test_missing_extra_reordered_cases_rejected(self):
        self.change(lambda d: d['cases'].pop())
        self.change(lambda d: d['cases'].append(copy.deepcopy(d['cases'][0])))
        self.change(lambda d: d['cases'].reverse())

    def test_initial_entry_and_hex_caps_precede_raw_copy(self):
        for name in ('initial-entry-short', 'initial-hex-short', 'target-entries-4097', 'target-hex-bytes-1048578'):
            row = self.row(name)
            self.assertEqual((row['raw_copies'], row['constructor_calls'], row['target_clone_calls']), (0, 0, 0))
            self.change(lambda d: self.row(name, d).update(raw_copies=1))

    def test_zero_and_above_ceiling_target_limits_rejected(self):
        for row in self.document['cases']:
            if row['name'].startswith('invalid-target-limit-'):
                self.assertEqual(row['refusal'], 'invalid_target_limits')
                self.change(lambda d: self.row(row['name'], d).update(target_clone_calls=1))

    def test_odd_uppercase_and_nonhex_target_strings_rejected(self):
        for field in ('key', 'value'):
            for spelling in ('0', 'GG', 'Aa'):
                name = 'invalid-' + field + '-' + spelling
                self.assertEqual(self.row(name)['raw_copies'], 0)
                self.change(lambda d: self.row(name, d).update(refusal=''))

    def test_exact_initial_target_and_empty_target_allowed(self):
        for name in ('exact-target-bounds', 'empty-initial-target'):
            self.assertEqual(self.row(name)['target_replacements'], 1)
            self.change(lambda d: self.row(name, d).update(research_import_result='REJECTED'))

    def test_hard_target_ceilings_executed_and_complete_maps_bound(self):
        for name, entries, size in (('target-entries-4096', 4096, 32768), ('target-hex-bytes-1048576', 1, 1048576)):
            row = self.row(name)
            self.assertEqual((row['target_after']['entries'], row['target_after']['hex_bytes']), (entries, size))
            self.assertEqual((row['target_clone_calls'], row['target_cloned_entries']), (1, entries))
            self.change(lambda d: self.row(name, d)['target_after'].update(manifest_sha256='00' * 32))

    def test_transient_entry_overflow_rejected_even_when_final_map_fits(self):
        row = self.row('put-then-delete')
        self.assertEqual((row['refusal'], len(row['staging_callbacks']), row['target_replacements']), ('target_entry_limit', 1, 0))
        self.assertEqual(row['staging_target'], row['target_before'])
        self.change(lambda d: self.row('put-then-delete', d).update(target_replacements=1, refusal=''))

    def test_transient_hex_overflow_rejected_before_stage_mutation(self):
        row = self.row('grow-then-delete')
        self.assertEqual((row['refusal'], len(row['staging_callbacks'])), ('target_hex_limit', 1))
        self.assertEqual(row['staging_target'], row['target_before'])
        self.change(lambda d: self.row('grow-then-delete', d).update(target_after=self.row('value-growth-with-room', d)['target_after']))

    def test_delete_reclaims_capacity_before_later_put(self):
        row = self.row('delete-then-put')
        self.assertEqual([r['operation'] for r in row['staging_callbacks']], ['Delete', 'Put'])
        self.assertEqual(row['target_after']['entries'], 3)
        self.change(lambda d: self.row('delete-then-put', d)['staging_callbacks'].reverse())

    def test_replacement_subtracts_prior_value_payload(self):
        row = self.row('replace-smaller-then-grow')
        self.assertEqual(row['target_replacements'], 1)
        self.assertEqual(row['target_after']['hex_bytes'], 384)
        self.change(lambda d: self.row('replace-smaller-then-grow', d)['target_after'].update(hex_bytes=448))

    def test_empty_put_delete_and_noop_remain_distinct(self):
        put, delete = self.row('empty-put-selected'), self.row('empty-delete-selected')
        self.assertEqual(put['staging_callbacks'][0]['value'], '')
        self.assertIsNone(delete['staging_callbacks'][0]['value'])
        self.assertEqual(put['target_after']['entries'], 4)
        self.assertEqual(delete['target_after']['entries'], 3)
        self.assertEqual(self.row('empty-key-put-delete-selected')['target_after'], delete['target_after'])
        self.change(lambda d: self.row('empty-put-selected', d)['staging_callbacks'][0].update(value=None))

    def test_nonminimal_varints_keep_distinct_complete_selection(self):
        a, b = self.row('default-complete'), self.row('overlong-complete-selected')
        self.assertEqual(a['target_after'], b['target_after'])
        self.assertNotEqual(a['selection']['changes_hash'], b['selection']['changes_hash'])
        self.change(lambda d: self.row('overlong-complete-selected', d)['selection'].update(changes_hash=a['selection']['changes_hash']))

    def test_duplicate_last_write_and_order_are_bound(self):
        a, b = self.row('duplicate-9-selected'), self.row('duplicate-10-selected')
        self.assertNotEqual(a['target_after']['manifest_sha256'], b['target_after']['manifest_sha256'])
        self.change(lambda d: self.row('duplicate-10-selected', d).update(target_after=a['target_after']))

    def test_bad_raw_and_selection_never_clone_target(self):
        for name in ('malformed-raw-before-clone', 'wrong-selection-before-clone', 'raw-cap-before-copy', 'invalid-raw-limit-before-copy'):
            self.assertEqual(self.row(name)['target_clone_calls'], 0)
            self.change(lambda d: self.row(name, d).update(target_clone_calls=1))

    def test_constructor_failures_and_owned_mutation_never_clone(self):
        for name in ('load-error', 'load-nil', 'mutate-owned-after-load'):
            self.assertEqual((self.row(name)['target_clone_calls'], self.row(name)['default_replay_calls']), (0, 0))
            self.change(lambda d: self.row(name, d).update(target_clone_calls=1))

    def test_replay_errors_omissions_extra_and_changed_callbacks_never_publish(self):
        for name in ('replay-error-first', 'replay-error-complete', 'replay-omit-last', 'replay-extra', 'replay-wrong-value'):
            row = self.row(name)
            self.assertEqual(row['target_after'], row['target_before'])
            self.assertEqual(row['target_replacements'], 0)
            self.change(lambda d: self.row(name, d).update(target_replacements=1))

    def test_every_original_alias_preserved_on_success_and_failure(self):
        for row in self.document['cases']:
            self.assertEqual(row['original_alias_after'], row['target_before'])
        self.change(lambda d: self.row('default-complete', d).update(original_alias_after=self.row('default-complete', d)['target_after']))

    def test_caller_raw_alias_mutation_does_not_change_owned_import(self):
        row = self.row('mutate-source-after-load')
        self.assertNotEqual(row['source_after'], row['input'])
        self.assertEqual(row['target_after'], self.row('default-complete')['target_after'])
        self.change(lambda d: self.row('mutate-source-after-load', d).update(source_after=row['input']))

    def test_exact_types_source_pins_and_complete_shape(self):
        self.change(lambda d: self.row('default-complete', d).update(target_clone_calls=True))
        self.change(lambda d: d['source'].update(revision='main'))
        self.change(lambda d: d.update(unplanned=True))

    def test_duplicate_trailing_and_oversized_json_rejected(self):
        for raw in (b'{"cases":[],"cases":[]}', self.raw + b'{}', b' ' * (CHECK.BYTE.MAX_FILE_BYTES + 1)):
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'input.json'
                path.write_bytes(raw)
                with self.assertRaises(ValueError):
                    CHECK.BYTE.read_corpus(path)

    def test_process_budget_snapshot_and_production_gates_remain_closed(self):
        for field, value in CHECK.SCOPE.items():
            if not value:
                self.change(lambda d: d['scope'].update({field: True}))
        self.change(lambda d: self.row('default-complete', d).update(consumer_result='ACCEPTED'))


if __name__ == '__main__':
    unittest.main(verbosity=2)
