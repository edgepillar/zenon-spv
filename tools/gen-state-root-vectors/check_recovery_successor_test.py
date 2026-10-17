#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Offline controls for separately derived successor expectations; no backend runs."""
import copy
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("selected_successor_checker", HERE / "check_recovery_successor.py")
C = importlib.util.module_from_spec(spec)
spec.loader.exec_module(C)


class SuccessorOracleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.document = C.expected_bundle()

    def changed(self):
        return copy.deepcopy(self.document)

    def case(self, document, name, variant="hash-bound"):
        return next(row for row in document["variants"][variant]["chain_cases"] if row["input"]["name"] == name)

    def phase(self, document, name="above-divergent-retained", variant="hash-bound", round=0, phase=0):
        return self.case(document, name, variant)["rounds"][round]["phases"][phase]

    def low(self, document, name="queries", variant="hash-bound"):
        return next(row for row in document["variants"][variant]["low_level_cases"] if row["name"] == name)

    def refused(self, document):
        with self.assertRaises((ValueError, KeyError, TypeError, IndexError)):
            C.check_expected_bundle(document)

    def test_complete_expected_component_inventory(self):
        report = C.check_expected_bundle(self.document)
        self.assertEqual(report["component_initializations"], 64)
        self.assertEqual(report["read_api_observations"], 946)
        self.assertEqual(report["complete_logical_database_snapshots"], 322)
        self.assertEqual(report["chain_cases_per_variant"], 26)
        self.assertEqual(report["low_level_cases_per_variant"], 11)
        self.assertEqual(report["consumer_result"], "REFUSED")

    def test_matching_ahead_recovery_restores_availability(self):
        phase = self.phase(self.document, "above-matching-retained")
        self.assertIsNone(phase["init_error"])
        self.assertIs(phase["ready"], True)
        self.assertEqual(phase["retained_frontier"], C.identifier("A", 2))
        self.assertEqual(phase["queries"][0]["root"], C.root(C.patch("A", 2)).hex())

    def test_divergent_target_preserves_records_across_reopen(self):
        case = self.case(self.document, "reopened-divergent-retained")
        for round in case["rounds"]:
            p = round["phases"][0]
            self.assertEqual(p["init_error"], "version-hash-mismatch")
            self.assertIs(p["ready"], False)
            self.assertEqual(p["records_before"], p["records_after_init"])
            self.assertEqual(p["records_before"], round["records_after_close_reopen"])
            self.assertTrue(all(q["error"] == "not-ready" for q in p["queries"]))

    def test_hash_height_binding_applies_to_every_public_query(self):
        for name in ("root-wrong-hash", "balance-wrong-hash", "compute-wrong-hash", "origin-wrong-hash"):
            row = next(q for q in self.low(self.document)["queries"] if q["name"] == name)
            self.assertEqual(row["error"], "version-hash-mismatch")
        baseline = self.low(self.document, variant="baseline")
        self.assertTrue(all(q["error"] is None for q in baseline["queries"]))

    def test_format_mismatch_never_wipes_candidate_records(self):
        for name in ("legacy-format-2", "foreign-format-4"):
            for round in self.case(self.document, name)["rounds"]:
                p = round["phases"][0]
                self.assertEqual(p["init_error"], "format-mismatch")
                self.assertIs(p["handle_open"], False)
                self.assertIsNone(p["retained_frontier"])
                self.assertEqual(p["records_before"], p["records_after_init"])
                self.assertEqual(p["records_before"], round["records_after_close_reopen"])
        for name in ("candidate-format-3", "foreign-format-4"):
            old = self.phase(self.document, name, "baseline")
            self.assertEqual(old["init_error"], "format-mismatch")
            self.assertIs(old["handle_open"], False)
            self.assertEqual(old["records_before"], old["records_after_init"])
            self.assertTrue(all(q["error"] == "not-ready" for q in old["queries"]))

    def test_readiness_and_ancestry_reset_on_reinitialization(self):
        for name in ("previously-ready-divergent", "previously-ready-equal-height", "previously-ready-behind-wrong-ancestor"):
            row = self.phase(self.document, name, phase=1)
            self.assertIsNotNone(row["init_error"])
            self.assertIs(row["ready"], False)
            self.assertTrue(all(q["error"] == "not-ready" for q in row["queries"]))
        old = self.phase(self.document, "previously-ready-behind-wrong-ancestor", "baseline", phase=1)
        self.assertIs(old["ready"], True)
        self.assertIsNone(old["init_error"])

    def test_hash_metadata_collected_with_root_versions(self):
        row = self.low(self.document, "prune-retained")
        before = {r["key"] for r in row["records_before"]}
        after = {r["key"] for r in row["records_after"]}
        for family in ("03", "06"):
            old = family + "0000000000000001"
            self.assertIn(old, before)
            self.assertNotIn(old, after)
        self.assertEqual(row["frontier"], C.identifier("A", 3))

    def test_empty_retained_root_still_requires_exact_identity(self):
        row = self.low(self.document, "empty-version")
        self.assertEqual(row["queries"][0]["root"], C.ZERO.hex())
        self.assertIsNone(row["queries"][0]["error"])
        self.assertEqual(row["queries"][1]["error"], "version-hash-mismatch")
        self.assertTrue(any(r["key"] == "06" + "0000000000000001" for r in row["records_after"]))

    def test_cache_cannot_reuse_pruned_truncated_or_closed_base(self):
        for case in ("warm-cache-pruned-base", "warm-cache-truncated-base", "warm-cache-closed-backend"):
            p = self.phase(self.document, case)
            computed = [q for q in p["queries"] if q["name"] in ("compute", "compute-repeat")]
            self.assertTrue(all(q["error"] in ("no-version", "database-closed") for q in computed))
            self.assertTrue(all(q["patch_callbacks"] == {"dump": 0, "replay": 0} for q in computed))
            old = self.phase(self.document, case, "baseline")
            self.assertTrue(all(q["error"] is None for q in old["queries"] if q["name"] in ("compute", "compute-repeat")))

    def test_closed_tree_error_still_stops_other_managers(self):
        for variant in C.VARIANTS:
            row = self.case(self.document, "warm-cache-closed-backend", variant)["rounds"][0]
            self.assertEqual(row["stop_error"], "database-closed")
            self.assertEqual(row["final_cache_trace"], ["DB", "Stop"])
            self.assertEqual(row["final_manager_trace"][-1], {"method": "Stop"})

    def test_missing_referenced_node_refuses_queried_path(self):
        p = self.phase(self.document, "missing-primary-node")
        self.assertIs(p["ready"], True)  # The unvisited right child is not scanned at startup.
        self.assertIsNone(p["queries"][0]["error"])
        self.assertEqual(p["queries"][2]["error"], "corrupt")
        self.assertTrue(all(q["error"] == "corrupt" for q in p["queries"] if q["name"] in ("compute", "compute-repeat")))
        self.assertIs(self.document["derivation"]["full_descendant_integrity_scan"], False)

    def test_missing_root_or_representative_fails_initialization(self):
        for name in ("missing-root-node", "missing-secondary-node"):
            p = self.phase(self.document, name)
            self.assertEqual(p["init_error"], "corrupt")
            self.assertIs(p["ready"], False)
            self.assertEqual(p["records_before"], p["records_after_init"])

    def test_maximum_height_guard_does_not_traverse_a_height_gap(self):
        row = self.low(self.document, "commit-origin-after-max")
        self.assertEqual(row["frontier"]["height"], (1 << 64) - 1)
        self.assertEqual(row["operations"][0]["error"], "commit-order")
        self.assertEqual(row["records_before"], row["records_after"])
        self.assertLess(len(row["records_after"]), 10)

    def test_failed_compute_does_not_replace_pending_staging(self):
        for variant, error, callbacks in (("baseline", "injected-replay", 1), ("hash-bound", "version-hash-mismatch", 0)):
            row = self.low(self.document, "failed-compute-preserves-staging", variant)
            self.assertEqual(row["operations"][0]["error"], error)
            self.assertEqual(row["operations"][0]["patch_callbacks"]["replay"], callbacks)
            self.assertIsNone(row["operations"][1]["error"])
            self.assertEqual(row["queries"][2]["value"], C.value(99).hex())

    def test_low_level_frontier_cannot_be_pruned(self):
        row = self.low(self.document, "prune-frontier")
        self.assertEqual(row["operations"][0]["error"], "prune-frontier")
        self.assertEqual(row["records_before"], row["records_after"])
        old = self.low(self.document, "prune-frontier", "baseline")
        self.assertEqual(old["frontier_root_error"], "no-version")
        self.assertNotEqual(old["records_before"], old["records_after"])

    def test_unknown_case_refused(self):
        doc = self.changed()
        doc["variants"]["hash-bound"]["chain_cases"].append(copy.deepcopy(doc["variants"]["hash-bound"]["chain_cases"][0]))
        self.refused(doc)

    def test_missing_case_or_generation_refused(self):
        for mode in ("case", "reopen", "prime"):
            doc = self.changed()
            if mode == "case":
                doc["variants"]["baseline"]["chain_cases"].pop()
            elif mode == "reopen":
                self.case(doc, "reopened-divergent-retained")["rounds"].pop()
            else:
                self.case(doc, "previously-ready-divergent")["rounds"][0]["phases"].pop(0)
            self.refused(doc)

    def test_coherent_wrong_fork_state_cannot_select_expectations(self):
        doc = self.changed()
        p = self.phase(doc, "above-matching-retained")
        alternate = C.patch("B", 2)
        p["queries"][0]["root"] = C.root(alternate).hex()
        p["queries"][2]["value"], p["queries"][2]["proof"] = C.proof(alternate, C.PRIMARY)
        self.refused(doc)

    def test_selected_or_retained_identity_substitution_refused(self):
        for field in ("selected_identifier", "retained_frontier", "query_identifier"):
            doc = self.changed()
            self.phase(doc)[field] = C.identifier("X", 2)
            self.refused(doc)

    def test_context_splicing_refused(self):
        doc = self.changed()
        p = self.phase(doc, "above-matching-retained")
        p["queries"][0]["identifier"] = C.identifier("X", 2)
        self.refused(doc)

    def test_frontier_record_relabelling_refused(self):
        doc = self.changed()
        row = next(r for r in self.phase(doc)["records_after_init"] if r["key"] == "00")
        row["value"] = C.ZERO.hex() + "0000000000000002"
        self.refused(doc)

    def test_hash_metadata_deletion_or_substitution_refused(self):
        for replacement in (None, "00" * 32):
            doc = self.changed()
            rows = self.phase(doc)["records_before"]
            row = next(r for r in rows if r["key"] == "06" + "0000000000000002")
            if replacement is None:
                rows.remove(row)
            else:
                row["value"] = replacement
            self.refused(doc)

    def test_refcount_or_node_bytes_substitution_refused(self):
        for prefix in ("01", "02", "03", "05"):
            doc = self.changed()
            row = next(r for r in self.phase(doc)["records_before"] if r["key"].startswith(prefix))
            row["value"] = "ff" + row["value"][2:]
            self.refused(doc)

    def test_reopen_drift_refused(self):
        doc = self.changed()
        self.case(doc, "reopened-divergent-retained")["rounds"][0]["records_after_close_reopen"].pop()
        self.refused(doc)

    def test_stale_cache_result_or_callback_claim_refused(self):
        for mode in ("stale", "callbacks"):
            doc = self.changed()
            q = next(q for q in self.phase(doc, "warm-cache-pruned-base")["queries"] if q["name"] == "compute")
            if mode == "stale":
                q["root"], q["error"] = C.root(C.patch("A", 99)).hex(), None
            else:
                q["patch_callbacks"]["dump"] = 1
            self.refused(doc)

    def test_replaced_proof_or_value_refused(self):
        for field in ("proof", "value"):
            doc = self.changed()
            row = self.phase(doc, "matching-prebuild")["queries"][2]
            row[field] = "00" * (len(row[field]) // 2)
            self.refused(doc)

    def test_missing_error_or_false_readiness_refused(self):
        for field, replacement in (("init_error", None), ("ready", True), ("handle_open", False)):
            doc = self.changed()
            self.phase(doc)[field] = replacement
            self.refused(doc)

    def test_boolean_and_numeric_fields_are_not_interchangeable(self):
        doc = self.changed()
        self.phase(doc)["ready"] = 0
        self.refused(doc)
        doc = self.changed()
        doc["source"]["blob_count"] = True
        self.refused(doc)
        doc = self.changed()
        self.phase(doc)["queries"][0]["patch_callbacks"]["dump"] = False
        self.refused(doc)

    def test_source_or_runtime_patch_pin_substitution_refused(self):
        for field in ("revision", "tree", "modified_node_tree_without_probe", "source_manifest_sha256", "patch_sha256"):
            doc = self.changed()
            doc["source"][field] = "00" * (len(doc["source"][field]) // 2)
            self.refused(doc)

    def test_producer_pin_substitution_refused(self):
        for name in ("hash_bound_versions_successor_probe_test.go", "prepare_recovery_successor.py", "check_recovery_successor.py"):
            doc = self.changed()
            doc["source"]["producer_inputs"][name] = "00" * 32
            self.refused(doc)

    def test_variant_swap_or_historical_rebinding_refused(self):
        doc = self.changed()
        doc["variants"]["baseline"], doc["variants"]["hash-bound"] = doc["variants"]["hash-bound"], doc["variants"]["baseline"]
        self.refused(doc)
        doc = self.changed()
        doc["source"]["historical_source_patch_or_records_rebound"] = True
        self.refused(doc)

    def test_execution_or_production_claims_refused(self):
        for name in C.DERIVATION:
            if C.DERIVATION[name] is False:
                doc = self.changed()
                doc["derivation"][name] = True
                self.refused(doc)

    def test_unknown_fields_and_consumer_acceptance_refused(self):
        doc = self.changed()
        self.phase(doc)["canonical"] = True
        self.refused(doc)
        doc = self.changed()
        doc["consumer_result"] = "MATCH"
        self.refused(doc)

    def test_duplicate_json_fields_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "duplicate.json"
            path.write_bytes(b'{"format_version":1,"format_version":1}')
            with self.assertRaises(ValueError):
                C.read_corpus(path)

    def test_raw_size_limit_is_checked_before_json_parsing(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bounded.json"
            path.write_bytes(b"{}" + b" " * (C.MAX_FILE_BYTES - 2))
            self.assertEqual(C.read_corpus(path)[1], {})
            with path.open("ab") as stream:
                stream.write(b" ")
            with self.assertRaises(ValueError):
                C.read_corpus(path)

    def test_oracle_executes_no_child_or_network(self):
        with mock.patch.object(subprocess, "run", side_effect=AssertionError("child")), \
             mock.patch.object(subprocess, "Popen", side_effect=AssertionError("child")), \
             mock.patch.object(socket, "create_connection", side_effect=AssertionError("network")):
            C.check_expected_bundle(self.document)

    def test_content_comparison_infers_no_process_evidence(self):
        result = C.compare(self.document["variants"]["baseline"], self.document["variants"]["hash-bound"])
        self.assertIs(result["process_exit_freshness_and_binary_provenance_inferred"], False)
        self.assertIs(result["reference_execution_performed_in_checker"], False)
        self.assertIs(result["production_state_value_accepted"], False)

    def test_recorded_tables_match_independent_model_and_source_pins(self):
        record = json.loads((HERE / "testdata/successor-recovery-execution.json").read_bytes(),
                            object_pairs_hook=C.BYTE.object_pairs)
        C.exact(record["source"], C.source_pins())
        for variant in C.VARIANTS:
            pin = record["variant_recordings"][variant]
            raw, document = C.read_corpus(HERE / pin["path"])
            self.assertEqual((len(raw), C.hashlib.sha256(raw).hexdigest()), (pin["bytes"], pin["sha256"]))
            C.check_variant(document, variant)
            self.assertEqual(len(record["generation_commands"][variant]), 2)
            for command in record["generation_commands"][variant]:
                C.exact({key: command[key] for key in ("state", "actual_exit", "output_complete", "reason")},
                        {"state": "COMPLETE", "actual_exit": 0, "output_complete": True, "reason": None})
        # Rechecking recorded data executes no backend on the CI host.
        self.assertIs(record["hosted_backend_execution_qualified"], False)
        self.assertIs(record["production_state_value_accepted"], False)
        self.assertEqual(record["consumer_result"], "REFUSED")

    def test_legacy_observation_cannot_be_relabelled_as_successor(self):
        legacy = json.loads((HERE / "testdata/candidate-hash-bound-versions.json").read_bytes())
        # A revision/kind-only relabel still carries the old wiping behavior.
        baseline = legacy["variants"]["baseline"]
        baseline["source_revision"] = C.REVISION
        baseline["kind"] = "successor-node-hash-bound-version-research"
        with self.assertRaises(ValueError):
            C.check_variant(baseline, "baseline")

    def test_comparison_refuses_partial_or_substituted_groups(self):
        for a, b in (({}, {}), (self.document["variants"]["hash-bound"], self.document["variants"]["baseline"])):
            with self.assertRaises(ValueError):
                C.compare(a, b)

    def test_historical_model_and_fixtures_are_unchanged(self):
        historical = json.loads((HERE / "testdata/candidate-hash-bound-versions.json").read_bytes())
        for name, digest in historical["source"]["producer_inputs"].items():
            self.assertEqual(C.hashlib.sha256((HERE / name).read_bytes()).hexdigest(), digest, name)

    def test_cli_refuses_missing_inputs_without_success_record(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "incomplete.json"
            path.write_text("{}", encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(io.StringIO()) as err:
                result = C.main(["--baseline", str(path), "--hash-bound", str(path)])
            self.assertEqual(result, 1)
            self.assertEqual(out.getvalue(), "")
            self.assertIn("refused", err.getvalue())


if __name__ == "__main__":
    unittest.main()
