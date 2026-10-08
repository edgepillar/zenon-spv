#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Negative controls for selected startup state and retained-root provenance."""

import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("startup_check", HERE / "check_chain_startup.py")
CHECK = importlib.util.module_from_spec(spec)
spec.loader.exec_module(CHECK)


class StartupControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _, cls.corpus = CHECK.BYTE.read_corpus(HERE / "testdata/candidate-chain-startup.json")

    def refused(self, document):
        with self.assertRaises((ValueError, KeyError, TypeError)):
            CHECK.check_corpus(document)

    def row(self, name, round_number=1):
        return copy.deepcopy(next(r for r in self.corpus["cases"] if r["input"]["name"] == name)["rounds"][round_number - 1])

    def selection(self, fork="A", height=2):
        root, value, _, _ = CHECK.state_bytes(fork, height)
        return CHECK.identifier(fork, height), root, value

    def test_finite_reference_inventory_matches_independent_roots_proofs_and_traces(self):
        report = CHECK.check_corpus(self.corpus)
        self.assertEqual((report["startup_cases"], report["component_initializations"], report["read_api_observations"], report["patch_lookups"]), (10, 11, 66, 13))
        self.assertEqual(report["consumer_decision_counts"], {"reference_not_ready": 3, "retained_root_provenance_refusal": 3, "synthetic_selected_state_match": 5})

    def test_startup_tail_bound_and_plus_one_preserve_readiness_refusal(self):
        ready, pending = self.row("empty-tail-bound"), self.row("empty-tail-plus-one")
        self.assertTrue(ready["ready"])
        self.assertFalse(pending["ready"])
        self.assertIsNone(pending["init_error"])
        self.assertTrue(all(q["error"] == CHECK.NOT_READY for q in pending["queries"]))
        self.assertFalse(any(e["method"] == "GetPatch" for e in pending["manager_trace"]))

    def test_equal_height_different_hash_is_not_a_ready_tree(self):
        row = self.row("same-height-other-hash")
        self.assertEqual(row["init_error"], CHECK.WRONG_ANCESTRY)
        self.assertFalse(row["ready"])
        self.assertNotEqual(row["retained_frontier"], row["selected_identifier"])
        self.assertEqual(CHECK.consumer_decision(row, *self.selection("B")), "reference_not_ready")

    def test_below_frontier_checks_ancestor_before_requesting_patches(self):
        row = self.row("below-other-ancestor")
        self.assertEqual(row["init_error"], CHECK.WRONG_ANCESTRY)
        self.assertFalse(any(e["method"] == "GetPatch" for e in row["manager_trace"]))
        good = self.row("below-matching-ancestor")
        self.assertEqual([e for e in good["manager_trace"] if e["method"] == "GetPatch"], [{"method": "GetPatch", "identifier": CHECK.identifier("A", 2)}])

    def test_above_frontier_retargets_identifier_without_replacing_retained_root(self):
        row = self.row("above-divergent-retained")
        self.assertTrue(row["ready"])
        self.assertEqual(row["retained_frontier"], CHECK.identifier("B", 2))
        self.assertEqual(row["queries"][0]["root"], CHECK.state_bytes("A", 2)[0].hex())
        self.assertNotEqual(row["queries"][0]["root"], CHECK.state_bytes("B", 2)[0].hex())
        self.assertEqual(CHECK.consumer_decision(row, *self.selection("B")), "retained_root_provenance_refusal")

    def test_clean_reopen_does_not_repair_retargeted_root_provenance(self):
        first, reopened = self.row("reopened-divergent-retained"), self.row("reopened-divergent-retained", 2)
        self.assertEqual(first["queries"], reopened["queries"])
        self.assertTrue(reopened["ready"])
        self.assertEqual(CHECK.consumer_decision(reopened, *self.selection("B")), "retained_root_provenance_refusal")

    def test_height_only_reads_do_not_authenticate_the_requested_hash(self):
        row = self.row("matching-prebuild")
        self.assertEqual(row["queries"][0]["root"], row["queries"][1]["root"])
        self.assertEqual(row["queries"][2]["proof"], row["queries"][3]["proof"])
        row["queries"][0] = row["queries"][1]
        self.assertEqual(CHECK.consumer_decision(row, *self.selection()), "selected_identifier_refusal")

    def test_matching_prebuild_and_valid_rollback_preserve_selected_state(self):
        for name in ("empty-short", "matching-prebuild", "below-matching-ancestor", "above-matching-retained"):
            self.assertEqual(CHECK.consumer_decision(self.row(name), *self.selection()), "synthetic_selected_state_match")

    def test_present_balance_and_absent_token_have_distinct_canonical_bytes(self):
        row = self.row("matching-prebuild")
        balance, absent = row["queries"][2], row["queries"][4]
        self.assertIsNotNone(balance["value"])
        self.assertIsNone(absent["value"])
        self.assertNotEqual(balance["key"], absent["key"])
        root = CHECK.state_bytes("A", 2)[0]
        self.assertEqual(CHECK.BYTE.proof_result(root, CHECK.BYTE.digest(CHECK.selected_key(True)), b"", bytes.fromhex(absent["proof"]), False), "match")

    def test_compute_root_observations_leave_persisted_frontier_selected(self):
        for row in self.corpus["cases"]:
            for observed in row["rounds"]:
                if observed["ready"]:
                    self.assertEqual(observed["queries"][5]["root"], CHECK.state_bytes("A", 99)[0].hex())
                    self.assertEqual(observed["retained_frontier"], observed["selected_identifier"])

    def test_coherent_provider_root_value_and_proof_cannot_replace_selection(self):
        row = self.row("above-divergent-retained")
        self.assertEqual(CHECK.BYTE.proof_result(bytes.fromhex(row["queries"][0]["root"]), CHECK.BYTE.digest(CHECK.selected_key()), bytes.fromhex(row["queries"][2]["value"]), bytes.fromhex(row["queries"][2]["proof"]), True), "match")
        self.assertEqual(CHECK.consumer_decision(row, *self.selection("B")), "retained_root_provenance_refusal")

    def test_coherent_expected_chain_answer_cannot_replace_reference_observations(self):
        doc = copy.deepcopy(self.corpus)
        row = doc["cases"][8]["rounds"][0]
        root, value, levels, values = CHECK.state_bytes("B", 2)
        row["queries"][0]["root"] = root.hex()
        row["queries"][2]["value"] = value.hex()
        row["queries"][2]["proof"] = CHECK.BYTE.canonical_proof(levels, values, CHECK.BYTE.digest(CHECK.selected_key())).hex()
        self.assertEqual(CHECK.consumer_decision(row, *self.selection("B")), "synthetic_selected_state_match")
        self.refused(doc)

    def test_method_identifiers_raw_keys_and_proof_paths_are_bound(self):
        for field, replacement in (("identifier", CHECK.identifier("X", 2)), ("key", CHECK.selected_key(True).hex()), ("proof", "00")):
            doc = copy.deepcopy(self.corpus)
            doc["cases"][0]["rounds"][0]["queries"][2][field] = replacement
            self.refused(doc)

    def test_out_of_scope_key_prefix_is_never_a_balance_selection(self):
        row = self.row("matching-prebuild")
        row["queries"][2]["key"] = "07" + row["queries"][2]["key"][2:]
        self.assertEqual(CHECK.consumer_decision(row, *self.selection()), "selected_value_refusal")

    def test_trace_cannot_hide_genesis_transaction_insertion_or_missing_patches(self):
        for field, replacement in (("genesis_trace", ["GetGenesisTransaction"]), ("cache_trace", ["Add"]), ("manager_trace", [{"method": "Add"}])):
            doc = copy.deepcopy(self.corpus)
            doc["cases"][0]["rounds"][0][field] = replacement
            self.refused(doc)

    def test_case_order_inventory_rounds_and_closed_fields_are_fixed(self):
        doc = copy.deepcopy(self.corpus);doc["cases"].reverse();self.refused(doc)
        doc = copy.deepcopy(self.corpus);doc["cases"].append(doc["cases"][0]);self.refused(doc)
        doc = copy.deepcopy(self.corpus);doc["cases"][9]["rounds"].pop();self.refused(doc)
        doc = copy.deepcopy(self.corpus);doc["cases"][0]["extra"] = True;self.refused(doc)

    def test_exact_uint64_scalar_types_cannot_be_boolean_float_or_text(self):
        for value in (True, 2.0, "2", None, -1, 1 << 64):
            doc = copy.deepcopy(self.corpus);doc["cases"][0]["input"]["chain_height"] = value;self.refused(doc)
        for value in (1, "true", None):
            doc = copy.deepcopy(self.corpus);doc["cases"][0]["rounds"][0]["ready"] = value;self.refused(doc)

    def test_source_scope_activation_and_production_claims_are_closed(self):
        for field in ("runtime_state_proof_acceptance", "network_activation_authenticated", "profile_agreed", "chain_Start_executed", "full_node_started", "crash_recovery_qualified", "pruning_qualified"):
            doc = copy.deepcopy(self.corpus);doc["scope"][field] = True;self.refused(doc)
        doc = copy.deepcopy(self.corpus);doc["source"]["revision"] = "00" * 20;self.refused(doc)

    def test_file_bounds_duplicate_fields_and_trailing_json_are_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.json"
            for raw in (b"{} {}", b'{"format_version":1,"format_version":2}', b" " * (CHECK.BYTE.MAX_FILE_BYTES + 1)):
                path.write_bytes(raw)
                with self.assertRaises((ValueError, json.JSONDecodeError)):
                    CHECK.BYTE.read_corpus(path)

    def test_value_proof_bounds_and_no_native_reference_execution_claims(self):
        row = self.row("matching-prebuild")
        for field, value in (("value", "01" * (CHECK.BYTE.MAX_VALUE_BYTES + 1)), ("proof", "01" * (CHECK.BYTE.MAX_PROOF_BYTES + 1))):
            doc = copy.deepcopy(self.corpus);doc["cases"][0]["rounds"][0]["queries"][2][field] = value;self.refused(doc)
        report = CHECK.check_corpus(self.corpus)
        self.assertFalse(report["reference_execution_in_checker"])
        self.assertFalse(report["production_acceptance_enabled"])
        self.assertFalse(report["authenticated_retained_version_provenance_qualified"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
