#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Adversarial controls for unsigned opened-file handoff evidence bindings."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('file_handoff_check', HERE / 'check_patch_file.py')
CHECK = importlib.util.module_from_spec(spec)
spec.loader.exec_module(CHECK)


class FileHandoffControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw, cls.document = CHECK.BYTE.read_corpus(HERE / 'testdata/candidate-patch-file.json')

    def row(self, name, document=None):
        return next(row for row in (document or self.document)['cases'] if row['name'] == name)

    def change(self, action):
        document = copy.deepcopy(self.document)
        action(document)
        with self.assertRaises((ValueError, KeyError, TypeError)):
            CHECK.check_corpus(document)

    def test_complete_finite_inventory_and_closed_consumers(self):
        report = CHECK.check_corpus(self.document)
        self.assertEqual(report['patch_file_cases'], 67)
        self.assertEqual(report['reused_target_cases'], 46)
        self.assertEqual(report['original_aliases_unchanged'], 67)
        self.assertEqual(report['consumer_refusals'], 67)

    def test_missing_extra_or_reordered_cases_rejected(self):
        self.change(lambda d: d['cases'].pop())
        self.change(lambda d: d['cases'].append(copy.deepcopy(d['cases'][0])))
        self.change(lambda d: d['cases'].reverse())

    def test_selection_ceiling_precedes_io_and_integer_conversion(self):
        for name in ('selection-over-cap', 'selection-uint64-max', 'raw-cap-before-copy'):
            row = self.row(name)
            self.assertEqual((row['file_stat_calls'], row['file_read_calls'], row['file_buffer_bytes']), (0, 0, 0))
            self.change(lambda d: self.row(name, d).update(file_buffer_bytes=1))

    def test_initial_target_caps_precede_file_io(self):
        for name in ('initial-entry-short', 'initial-hex-short', 'target-entries-4097', 'target-hex-bytes-1048578'):
            self.assertEqual(self.row(name)['file_stat_calls'], 0)
            self.change(lambda d: self.row(name, d).update(file_stat_calls=1))

    def test_invalid_limits_and_target_encoding_preserved(self):
        for row in self.document['cases']:
            if row['refusal'] in ('invalid_limits', 'invalid_target_limits', 'invalid_target_encoding'):
                self.assertEqual((row['file_read_calls'], row['raw_copies']), (0, 0))
                self.change(lambda d: self.row(row['name'], d).update(refusal=''))

    def test_missing_closed_and_directory_sources_refused(self):
        for fault in ('nil-source', 'closed-source', 'directory-source'):
            name = 'source-' + fault
            self.assertEqual(self.row(name)['file_read_calls'], 0)
            self.change(lambda d: self.row(name, d).update(target_replacements=1))

    def test_stat_failures_preserve_alias_and_skip_constructor(self):
        for fault in ('stat-error', 'nil-stat-info', 'negative-size', 'second-stat-error'):
            name = 'source-' + fault
            self.assertEqual(self.row(name)['constructor_calls'], 0)
            self.change(lambda d: self.row(name, d).update(target_after=CHECK.TARGET.summary({})))

    def test_read_errors_and_invalid_callback_counts_cannot_import(self):
        for fault in ('read-error', 'negative-read-count', 'excess-read-count', 'short-eof-read'):
            name = 'source-' + fault
            self.assertEqual(self.row(name)['raw_copies'], 0)
            self.change(lambda d: self.row(name, d).update(raw_copies=1))

    def test_growth_and_truncation_during_read_are_observed(self):
        for fault, count in (('grow-before-read', 169), ('shrink-before-read', 167)):
            name = 'source-' + fault
            self.assertEqual(self.row(name)['file_read_bytes'], count)
            self.assertEqual(self.row(name)['refusal'], 'file_read_size')
            self.change(lambda d: self.row(name, d).update(file_read_bytes=168))

    def test_size_change_after_read_precedes_owned_import(self):
        for fault in ('grow-after-read', 'shrink-after-read'):
            name = 'source-' + fault
            self.assertEqual(self.row(name)['refusal'], 'file_changed_size')
            self.change(lambda d: self.row(name, d).update(constructor_calls=1))

    def test_same_size_change_still_needs_original_digest(self):
        row = self.row('source-same-size-mutation')
        self.assertEqual((row['file_read_bytes'], row['preflight_records'], row['refusal']), (168, 3, 'selection_mismatch'))
        self.assertNotEqual(row['file_before_sha256'], row['file_after_sha256'])
        self.change(lambda d: self.row('source-same-size-mutation', d)['selection'].update(changes_hash='00' * 32))

    def test_record_count_and_raw_spelling_remain_independent(self):
        self.assertEqual(self.row('wrong-record-count')['refusal'], 'selection_mismatch')
        a, b = self.row('default-complete'), self.row('overlong-complete-selected')
        self.assertEqual(a['target_after'], b['target_after'])
        self.assertNotEqual(a['selection']['changes_hash'], b['selection']['changes_hash'])
        self.change(lambda d: self.row('overlong-complete-selected', d)['selection'].update(changes_hash=a['selection']['changes_hash']))

    def test_file_size_and_selected_count_fail_before_read(self):
        for name in ('file-over-cap', 'wrong-byte-count', 'malformed-raw-before-clone'):
            self.assertEqual(self.row(name)['file_buffer_bytes'], 0)
            self.change(lambda d: self.row(name, d).update(file_read_calls=1))

    def test_borrowed_cursor_and_opened_descriptor_scope_bound(self):
        self.assertTrue(self.row('default-complete')['source_cursor_preserved'])
        self.change(lambda d: self.row('default-complete', d).update(source_cursor_preserved=False))
        self.change(lambda d: d['scope'].update(path_opener_added=True))

    def test_original_aliases_and_complete_maps_bound(self):
        for row in self.document['cases']:
            self.assertEqual(row['original_alias_after'], row['target_before'])
        self.change(lambda d: self.row('default-complete', d)['original_alias_after'].update(manifest_sha256='00' * 32))
        self.change(lambda d: self.row('default-complete', d)['target_after'].update(manifest_sha256='00' * 32))

    def test_replay_failures_cannot_publish_partial_target(self):
        for fault in ('load-error', 'load-nil', 'replay-error-first', 'replay-error-complete', 'replay-omit-last', 'replay-extra', 'replay-wrong-value'):
            self.assertEqual(self.row(fault)['target_replacements'], 0)
            self.change(lambda d: self.row(fault, d).update(target_replacements=1))

    def test_transient_caps_replacement_and_delete_order_bound(self):
        self.assertEqual(self.row('put-then-delete')['refusal'], 'target_entry_limit')
        self.assertEqual(self.row('grow-then-delete')['refusal'], 'target_hex_limit')
        self.assertEqual(self.row('delete-then-put')['target_replacements'], 1)
        self.change(lambda d: self.row('delete-then-put', d)['staging_callbacks'].reverse())

    def test_empty_put_and_delete_have_distinct_values(self):
        self.assertEqual(self.row('empty-put-selected')['staging_callbacks'][0]['value'], '')
        self.assertIsNone(self.row('empty-delete-selected')['staging_callbacks'][0]['value'])
        self.change(lambda d: self.row('empty-put-selected', d)['staging_callbacks'][0].update(value=None))

    def test_raw_source_and_plan_mutation_preserve_file_binding(self):
        self.assertEqual(self.row('mutate-owned-after-load')['refusal'], 'patch_bytes_mismatch')
        row = self.row('mutate-source-after-load')
        self.assertEqual(row['file_before_sha256'], row['file_after_sha256'])
        self.assertEqual(row['target_replacements'], 1)
        self.change(lambda d: self.row('mutate-source-after-load', d).update(file_after_sha256='00' * 32))

    def test_selected_research_source_and_node_hashes_bound(self):
        self.change(lambda d: d['research_source_inputs'].update(patch_file='00' * 32))
        self.change(lambda d: d['research_source_inputs'].update({'patch_file.go': '00' * 32}))
        self.change(lambda d: d['source'].update(tree='00' * 20))

    def test_scalar_types_extra_fields_and_gate_promotion_rejected(self):
        self.change(lambda d: self.row('default-complete', d).update(file_read_calls=True))
        self.change(lambda d: d.update(unselected_field=1))
        for name in ('atomic_filesystem_snapshot', 'authenticated_snapshot_import', 'actual_NodeTree_executed',
                     'resource_measurements_executed', 'execution_provenance_authenticated', 'runtime_state_proof_acceptance'):
            self.change(lambda d: d['scope'].update({name: True}))

    def test_report_contains_no_private_file_paths_or_credentials(self):
        for marker in (b'/' + b'Users' + b'/', b'/' + b'home' + b'/', b'/' + b'private' + b'/',
                       b'file' + b'://', b'ghp' + b'_', b'github' + b'_pat_'):
            self.assertNotIn(marker, self.raw)

    def test_actual_cli_report_and_revision_refusal(self):
        command = [sys.executable, '-I', '-B', str(HERE / 'check_patch_file.py')]
        result = subprocess.run(command + ['--source-revision', 'ab' * 20], capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stderr, b'')
        report = json.loads(result.stdout)
        self.assertEqual(report['source_revision'], 'ab' * 20)
        self.assertEqual(report['patch_file_cases'], 67)
        self.assertFalse(report['file_handoff_executed_in_checker'])
        result = subprocess.run(command + ['--source-revision', 'not-a-revision'], capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, b'')
        self.assertNotIn(str(HERE).encode(), result.stderr)


if __name__ == '__main__':
    unittest.main(verbosity=2)
