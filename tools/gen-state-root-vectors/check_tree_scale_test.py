#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Portable controls for recorded larger tree bytes; no reference execution."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('scale_controls_checker', HERE / 'check_tree_scale.py')
CHECK = importlib.util.module_from_spec(spec)
spec.loader.exec_module(CHECK)


class TreeScaleControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw, cls.corpus = CHECK.BYTE.read_corpus(HERE / 'testdata/candidate-tree-scale.json')
        _, cls.samples = CHECK.BYTE.read_corpus(HERE / 'testdata/candidate-tree-scale-samples.json')
        CHECK.check_corpus(cls.corpus)
        CHECK.check_samples(cls.samples, cls.raw, cls.corpus)

    def refuse_corpus(self, mutate):
        changed = copy.deepcopy(self.corpus)
        mutate(changed)
        with self.assertRaises((ValueError, KeyError, TypeError)):
            CHECK.check_corpus(changed)

    def refuse_samples(self, mutate):
        changed = copy.deepcopy(self.samples)
        mutate(changed)
        with self.assertRaises((ValueError, KeyError, TypeError)):
            CHECK.check_samples(changed, self.raw, self.corpus)

    def test_complete_recorded_conformance_and_all_twelve_children(self):
        self.assertEqual(CHECK.check_corpus(self.corpus)['root_and_proof_cells'], 252)
        self.assertEqual(CHECK.check_samples(self.samples, self.raw, self.corpus)['actual_recorded_fresh_children'], 12)

    def test_small_bottom_up_tree_and_proofs_match_original_byte_oracle(self):
        state = {CHECK.BYTE.digest(CHECK.RET.key(i)): i.to_bytes(32, 'big') for i in range(4)}
        levels, values = CHECK.scale_levels(state)
        old_levels, old_values = CHECK.BYTE.tree_levels([{'path': p.hex(), 'value': v.hex()} for p, v in state.items()])
        self.assertEqual((levels, values), (old_levels, old_values))
        for index in (0, 3, 4):
            path = CHECK.BYTE.digest(CHECK.RET.key(index))
            self.assertEqual(CHECK.BYTE.canonical_proof(levels, values, path),
                             CHECK.BYTE.canonical_proof(old_levels, old_values, path))

    def test_old_1024_leaf_ceiling_is_preserved(self):
        state = {CHECK.BYTE.digest(CHECK.RET.key(i)): bytes(32) for i in range(1025)}
        with self.assertRaises(ValueError):
            CHECK.BYTE.tree_levels([{'path': p.hex(), 'value': v.hex()} for p, v in state.items()])
        self.assertEqual(CHECK.scale_levels(state)[0][0][0], CHECK.RET.graph(state)[1])

    def test_new_scale_leaf_ceiling_refuses_4097(self):
        with self.assertRaises(ValueError):
            CHECK.scale_levels({i.to_bytes(32, 'big'): bytes(32) for i in range(4097)})

    def test_scale_path_and_value_widths_are_closed(self):
        for state in ({b'bad': bytes(32)}, {bytes(32): b'bad'}, {bytes(32): bytearray(32)}):
            with self.subTest(state_type=str(type(next(iter(state.values()))))):
                with self.assertRaises(ValueError):
                    CHECK.scale_levels(state)

    def test_case_and_parameter_selection_are_fixed(self):
        for key, value in (('name', 'unselected'), ('keys', 513), ('versions', 65), ('retain', 17), ('keys', True)):
            with self.subTest(field=key, value=value):
                self.refuse_corpus(lambda d: d['cases'][0]['input'].__setitem__(key, value))

    def test_frontier_identifier_is_bound(self):
        self.refuse_corpus(lambda d: d['cases'][0]['rounds'][0]['frontier'].__setitem__('hash', 'ff' * 32))

    def test_selected_roots_and_canonical_proof_bytes_are_bound(self):
        self.refuse_corpus(lambda d: d['cases'][0]['rounds'][0]['reads'][0].__setitem__('root', 'ff' * 32))
        self.refuse_corpus(lambda d: d['cases'][0]['rounds'][0]['reads'][1].__setitem__('proof', '00' * 99))

    def test_coherent_incomplete_fixture_cannot_replace_complete_selection(self):
        self.refuse_corpus(lambda d: d['cases'][0]['input'].__setitem__('keys', 511))
        changed = copy.deepcopy(self.corpus)
        row = next(r for r in changed['cases'][0]['rounds'][0]['reads'] if r['identifier']['height'] == 64 and r['key'] is None)
        state = dict(CHECK.RET.states(512, 64)[64])
        state.pop(next(iter(state)))
        row['root'] = CHECK.scale_levels(state)[0][0][0].hex()
        with self.assertRaises(ValueError):
            CHECK.check_corpus(changed)

    def test_refcount_graph_and_retained_height_inventory_are_bound(self):
        self.refuse_corpus(lambda d: d['cases'][1]['rounds'][0]['storage'].__setitem__('records_sha256', 'ff' * 32))
        self.refuse_corpus(lambda d: d['cases'][0]['rounds'][0]['storage']['retained_heights'].append(48))

    def test_clean_reopen_and_compaction_rounds_are_required(self):
        self.refuse_corpus(lambda d: d['cases'][0]['rounds'].pop())

    def test_trust_scope_and_refusal_cannot_be_elevated(self):
        self.refuse_corpus(lambda d: d['scope'].__setitem__('runtime_state_proof_acceptance', True))
        self.refuse_corpus(lambda d: d.__setitem__('consumer_result', 'ACCEPTED'))

    def test_node_and_research_source_pins_are_required(self):
        self.refuse_corpus(lambda d: d['source'].__setitem__('revision', '0' * 40))
        self.refuse_corpus(lambda d: d['research_source_inputs'].__setitem__('retention_resources.go', '0' * 64))

    def test_missing_generation_or_repetition_is_refused(self):
        self.refuse_samples(lambda d: d['samples'].pop())
        self.refuse_samples(lambda d: d['samples'][1].pop())
        self.refuse_samples(lambda d: d['samples'][0][0].__setitem__('repetition', 1))

    def test_every_actual_command_outcome_is_required(self):
        self.refuse_samples(lambda d: d['commands'][1][-1].__setitem__('actual_exit', 1))
        self.refuse_samples(lambda d: d['commands'][1][-1].__setitem__('completed', False))
        self.refuse_samples(lambda d: d['commands'][1][-1].__setitem__('stderr_sha256', 'f' * 64))
        self.refuse_samples(lambda d: d['commands'][1].pop())

    def test_result_and_conformance_bindings_cannot_be_forged(self):
        self.refuse_samples(lambda d: d['commands'][0][0].__setitem__('result_sha256', '0' * 64))
        self.refuse_samples(lambda d: d['samples'][0][0].__setitem__('conformance_sha256', '0' * 64))

    def test_platform_toolchain_and_binary_hash_shape_are_closed(self):
        self.refuse_samples(lambda d: d.__setitem__('go_version', 'go version go1.25.14 windows/amd64'))
        self.refuse_samples(lambda d: d['samples'][0][0].__setitem__('go_version', 'go1.25.0'))
        self.refuse_samples(lambda d: d.__setitem__('reference_binary_sha256', 'unknown'))

    def test_query_call_inventory_and_negative_time_are_refused(self):
        self.refuse_samples(lambda d: d['samples'][0][0]['measurement']['query_timings'][0].__setitem__('proof_calls', 34))
        self.refuse_samples(lambda d: d['samples'][0][0]['measurement']['query_timings'][0].__setitem__('root_elapsed_ns', -1))
        self.refuse_samples(lambda d: d['samples'][0][0]['measurement']['query_timings'].pop())

    def test_timing_integers_exclude_bool_float_and_overflow(self):
        for value in (True, 1.0, 1 << 63):
            self.refuse_samples(lambda d: d['samples'][0][0]['measurement'].__setitem__('commit_elapsed_ns', value))

    def test_build_phase_aggregate_cannot_be_less_than_components(self):
        self.refuse_samples(lambda d: d['samples'][0][0]['measurement'].__setitem__('patch_build_update_commit_prune_elapsed_ns', 0))

    def test_closed_file_lengths_and_RSS_method_are_not_substitutable(self):
        self.refuse_samples(lambda d: d['samples'][0][0]['measurement']['closed_after_final_reopen'].__setitem__('largest_file_bytes', 1 << 60))
        self.refuse_samples(lambda d: d['samples'][0][0]['measurement'].__setitem__('peak_rss_method', 'live Go heap'))

    def test_unknown_fields_and_production_budget_acceptance_are_refused(self):
        self.refuse_samples(lambda d: d.__setitem__('production_resource_budgets_qualified', True))
        self.refuse_samples(lambda d: d['samples'][0][0]['measurement'].__setitem__('allocated_disk_bytes', 0))

    def test_programmatic_raw_corpus_and_decoded_document_are_rebound(self):
        changed = copy.deepcopy(self.corpus)
        changed['cases'][0]['input']['versions'] = True
        with self.assertRaises(ValueError):
            CHECK.check_samples(self.samples, CHECK.encoded(changed), self.corpus)
        with self.assertRaises(ValueError):
            CHECK.check_samples(self.samples, self.raw + b'\n' * CHECK.BYTE.MAX_FILE_BYTES, self.corpus)

    def test_duplicate_raw_JSON_fields_are_refused(self):
        with self.assertRaises(ValueError):
            json.loads('{"a":0,"a":1}', object_pairs_hook=CHECK.BYTE.object_pairs)


if __name__ == '__main__':
    unittest.main()
