#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Adversarial controls for recorded larger imports; no reference execution."""
import copy
import importlib.util
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('import_scale_controls', HERE / 'check_tree_import_scale.py')
CHECK = importlib.util.module_from_spec(spec)
spec.loader.exec_module(CHECK)


class TreeImportScaleControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw, cls.corpus = CHECK.BYTE.read_corpus(HERE / 'testdata/candidate-tree-import-scale.json')
        _, cls.samples = CHECK.BYTE.read_corpus(HERE / 'testdata/candidate-tree-import-scale-samples.json')
        CHECK.check_samples(cls.samples, cls.raw, cls.corpus)

    def refuse_corpus(self, change):
        changed = copy.deepcopy(self.corpus)
        change(changed)
        with self.assertRaises((ValueError, KeyError, TypeError)):
            CHECK.check_corpus(changed)

    def refuse_samples(self, change):
        changed = copy.deepcopy(self.samples)
        change(changed)
        with self.assertRaises((ValueError, KeyError, TypeError)):
            CHECK.check_samples(changed, self.raw, self.corpus)

    def test_complete_evidence_and_all_twenty_four_children(self):
        self.assertEqual(CHECK.check_samples(self.samples, self.raw, self.corpus)['recorded_file_import_calls'], 420)

    def test_seed_chunks_preserve_1024_record_ceiling(self):
        self.assertEqual([len(c) for c in CHECK.chunks(4096, 1)], [1024] * 4)
        self.assertEqual(CHECK.FILE.IMP.CEILINGS['records'], 1024)
        self.assertEqual(CHECK.FILE.TARGET.CEILINGS['entries'], 4096)

    def test_seed_chunk_omission_refused(self):
        self.refuse_corpus(lambda d: d['cases'][1]['steps'][0]['imports'].pop())

    def test_seed_chunk_reordering_refused(self):
        self.refuse_corpus(lambda d: d['cases'][1]['steps'][0]['imports'].reverse())

    def test_selection_digest_refused(self):
        self.refuse_corpus(lambda d: d['cases'][0]['steps'][0]['imports'][0]['selection'].update(changes_hash='00' * 32))

    def test_raw_file_digest_refused(self):
        self.refuse_corpus(lambda d: d['cases'][1]['steps'][0]['imports'][0].update(raw_sha256='00' * 32))

    def test_clone_count_refused(self):
        self.refuse_corpus(lambda d: d['cases'][1]['steps'][0]['imports'][1].update(cloned_entries=0))

    def test_borrowed_source_cursor_and_map_mutation_refused(self):
        for key in ('source_cursor_preserved', 'original_alias_preserved'):
            self.refuse_corpus(lambda d: d['cases'][0]['steps'][0]['imports'][0].update({key: False}))

    def test_file_read_and_extra_byte_bound_refused(self):
        self.refuse_corpus(lambda d: d['cases'][0]['steps'][0]['imports'][0].update(buffer_bytes=1))

    def test_complete_map_manifest_refused(self):
        self.refuse_corpus(lambda d: d['cases'][1]['steps'][0]['complete_map'].update(manifest_sha256='00' * 32))

    def test_delta_deletion_or_stored_zero_omission_refused(self):
        for index in (2, 3):
            self.refuse_corpus(lambda d: d['cases'][0]['steps'][index]['delta_callbacks'].update(count=0))

    def test_selected_preflight_root_refused(self):
        self.refuse_corpus(lambda d: d['cases'][1]['steps'][0].update(preflight_root='00' * 32))

    def test_retained_refcount_graph_digest_refused(self):
        self.refuse_corpus(lambda d: d['cases'][1]['rounds'][0]['storage'].update(records_sha256='00' * 32))

    def test_canonical_proof_byte_mutation_refused(self):
        def mutate(d):
            row = next(r for r in d['cases'][1]['rounds'][0]['reads'] if r['proof'])
            raw = bytearray.fromhex(row['proof']); raw[-1] ^= 1; row['proof'] = raw.hex()
        self.refuse_corpus(mutate)

    def test_production_or_snapshot_scope_broadening_refused(self):
        self.refuse_corpus(lambda d: d['scope'].update(file_digest_is_authenticated_snapshot=True))

    def test_false_consumer_acceptance_refused(self):
        self.refuse_corpus(lambda d: d['cases'][1].update(consumer_result='ACCEPTED'))

    def test_research_source_mutation_refused(self):
        self.refuse_corpus(lambda d: d['research_source_inputs'].update({'patch_file.go': '00' * 32}))

    def test_missing_generation_or_sample_refused(self):
        self.refuse_samples(lambda d: d['samples'].pop())
        self.refuse_samples(lambda d: d['samples'][0].pop())

    def test_filtered_or_reordered_mode_refused(self):
        self.refuse_samples(lambda d: d['samples'][0].reverse())

    def test_actual_failed_child_is_not_success_refused(self):
        self.refuse_samples(lambda d: d['commands'][0][0].update(actual_exit=1))

    def test_child_output_binding_refused(self):
        self.refuse_samples(lambda d: d['commands'][0][0].update(result_sha256='00' * 32))

    def test_plain_and_allocation_observations_not_interchangeable(self):
        self.refuse_samples(lambda d: d['samples'][0][0]['phase_resources'][0].update(go_total_alloc_delta_bytes=0))

    def test_allocation_phase_missing_or_reordered_refused(self):
        self.refuse_samples(lambda d: d['samples'][0][1]['phase_resources'].pop())

    def test_heap_and_RSS_method_relabeling_refused(self):
        for field in ('post_gc_heap_method', 'process_peak_rss_method'):
            self.refuse_samples(lambda d: d['samples'][0][0].update({field: 'whole pipeline memory'}))

    def test_allocated_storage_is_not_a_file_length(self):
        self.refuse_samples(lambda d: d['samples'][0][0]['closed_storage'][0].update(allocated_file_bytes=1))

    def test_negative_or_boolean_resource_value_refused(self):
        for value in (-1, True):
            self.refuse_samples(lambda d: d['samples'][0][1].update(post_gc_heap_alloc_bytes=value))

    def test_whole_pipeline_or_peak_disk_claim_refused(self):
        for field in ('whole_pipeline_time_measured', 'whole_pipeline_memory_measured', 'peak_disk_measured'):
            self.refuse_samples(lambda d: d['samples'][0][0].update({field: True}))

    def test_unknown_fields_and_budget_acceptance_refused(self):
        self.refuse_samples(lambda d: d.update(production_resource_budgets_qualified=True))
        self.refuse_samples(lambda d: d['samples'][0][0].update(peak_disk_bytes=1))


if __name__ == '__main__':
    unittest.main()
