#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Recorded evidence boundaries; this suite never starts a reference backend."""
import copy
import importlib.util
from pathlib import Path
import sys
import unittest

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("snapshot_recorded_controls", HERE / "check_patch_snapshot_lifetime.py")
C = importlib.util.module_from_spec(spec)
spec.loader.exec_module(C)


class PatchSnapshotRecordedTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = C.P.read_regular(HERE / "testdata" / C.CORPUS, C.MAX_BYTES)
        cls.corpus = C.document(cls.raw)

    def rows(self, phase="candidate_component"):
        return copy.deepcopy(self.corpus["observations"][phase])

    def test_pinned_recording_qualifies_without_native_execution(self):
        report = C.check_file(HERE / "testdata" / C.CORPUS)
        self.assertEqual(report["recorded_snapshot_cases"], 36)
        self.assertEqual(report["recorded_component_parent_pass_results"], 13)
        self.assertEqual(report["recorded_component_candidate_pass_results"], 15)
        self.assertEqual(report["recorded_integrated_pass_results"], 73)
        self.assertEqual(report["recorded_original_DB_pass_results"], 27)
        self.assertEqual(report["recorded_Chain_Init_Stop_cases"], 5)
        self.assertEqual(report["recorded_chain_events"], 130)
        self.assertEqual(report["recorded_chain_Init_panics"], 0)
        self.assertEqual(report["recorded_chain_prewrite_refusals"], 2)
        self.assertEqual(report["reference_processes_executed_by_this_check"], 0)
        self.assertEqual(report["consumer_result"], "REFUSED")

    def test_original_failure_and_uncaptured_random_seed_remain_explicit(self):
        execution = self.corpus["execution"]
        self.assertEqual(execution["parent_caller_outcome"], "FAILURE")
        self.assertEqual(execution["parent_native_exit"], 0)
        self.assertIs(execution["native_parent_reexecuted_for_parser_repair"], False)
        observation = execution["original_DB_observation"]
        self.assertEqual(observation["stress_put_operations_declared_by_source"], 3000000)
        for key in ("stress_random_seed_captured", "exact_random_stress_vector_reproducible",
                    "aggregate_process_tree_peak_qualified", "representative_production_budget_qualified"):
            self.assertIs(observation[key], False)

    def test_missing_duplicate_or_extra_observation_refuses(self):
        for mode in ("missing", "duplicate", "extra"):
            rows = self.rows()
            if mode == "missing":
                rows.pop()
            elif mode == "duplicate":
                rows[1] = copy.deepcopy(rows[0])
            else:
                rows.append(copy.deepcopy(rows[0]))
            with self.assertRaises(ValueError):
                C.check_observations(rows, True)

    def test_candidate_cannot_retain_a_snapshot(self):
        rows = self.rows()
        rows[0]["snapshots_after_reads"] = 1
        with self.assertRaises(ValueError):
            C.check_observations(rows, True)

    def test_parent_no_GC_control_requires_all_64_snapshots(self):
        rows = self.rows("parent_component")
        rows[0]["snapshots_after_reads"] = 63
        with self.assertRaises(ValueError):
            C.check_observations(rows, False)

    def test_parent_finalizer_control_must_return_to_zero(self):
        rows = self.rows("parent_component")
        rows[0]["snapshots_after_explicit_gc"] = 1
        with self.assertRaises(ValueError):
            C.check_observations(rows, False)

    def test_parent_and_candidate_source_expectations_are_distinct(self):
        with self.assertRaises(ValueError):
            C.check_observations(self.rows("parent_component"), True)
        with self.assertRaises(ValueError):
            C.check_observations(self.rows(), False)

    def test_boolean_is_not_an_integer_counter(self):
        for field in ("reads", "snapshots_before", "snapshots_after_reads", "snapshots_after_explicit_gc",
                      "explicit_gc_rounds", "decode_panics", "returned_nil", "returned_expected_patch", "gc_percent"):
            rows = self.rows()
            rows[0][field] = True
            with self.assertRaises(ValueError):
                C.check_observations(rows, True)

    def test_wrong_gc_policy_or_source_flag_refuses(self):
        for field, value in (("gc_percent", 0), ("gc_policy", "automatic"), ("explicit_release_source_expected", False)):
            rows = self.rows()
            rows[0][field] = value
            with self.assertRaises(ValueError):
                C.check_observations(rows, True)

    def test_negative_and_out_of_range_counters_refuse(self):
        for field, value in (("snapshots_after_reads", -1), ("snapshots_after_reads", 65),
                             ("explicit_gc_rounds", -1), ("explicit_gc_rounds", 10001), ("reads", 63)):
            rows = self.rows("parent_component")
            rows[0][field] = value
            with self.assertRaises(ValueError):
                C.check_observations(rows, False)

    def test_patch_put_and_delete_dump_bytes_are_independently_checked(self):
        rows = self.rows()
        rows[0]["patch_dump_hex"] = "00" + rows[0]["patch_dump_hex"][2:]
        with self.assertRaises(ValueError):
            C.check_observations(rows, True)

    def test_stored_invalid_dump_byte_is_checked(self):
        rows = self.rows()
        rows[4]["stored_value_hex"] = "00"
        with self.assertRaises(ValueError):
            C.check_observations(rows, True)

    def test_database_counter_and_frame_substitutions_refuse(self):
        for field, value in (("records", 2), ("records", True), ("key_bytes", 8), ("value_bytes", 16),
                             ("ordered_length_framed_sha256", "0" * 64)):
            rows = self.rows()
            rows[0]["logical_database_before"][field] = value
            rows[0]["logical_database_after"][field] = value
            with self.assertRaises(ValueError):
                C.check_observations(rows, True)

    def test_patch_and_rollback_key_namespaces_are_distinct(self):
        rows = self.rows()
        rows[0]["logical_database_before"] = copy.deepcopy(rows[6]["logical_database_before"])
        rows[0]["logical_database_after"] = copy.deepcopy(rows[6]["logical_database_after"])
        with self.assertRaises(ValueError):
            C.check_observations(rows, True)

    def test_decode_panic_nil_and_patch_outcomes_are_not_interchangeable(self):
        for field, value in (("decode_panics", 1), ("returned_nil", 1), ("returned_expected_patch", 63)):
            rows = self.rows()
            rows[0][field] = value
            with self.assertRaises(ValueError):
                C.check_observations(rows, True)

    def test_scope_and_consumer_upgrades_refuse(self):
        for field, value in (("permanent_leak_claimed", True), ("representative_load_or_hardware_budget_qualified", True),
                             ("full_node_or_network_executed", True), ("accepted_header_binding", True),
                             ("consumer_result", "ACCEPT")):
            rows = self.rows()
            rows[0][field] = value
            with self.assertRaises(ValueError):
                C.check_observations(rows, True)

    def test_unknown_row_fields_refuse(self):
        rows = self.rows()
        rows[0]["unexpected"] = 1
        with self.assertRaises(ValueError):
            C.check_observations(rows, True)

    def test_unit_inventory_rejects_missing_extra_skip_and_failure(self):
        original = self.corpus["unit_runs"]["candidate_component"]
        for mutate in (lambda v: v["test_pass_names"].pop(),
                       lambda v: v["test_pass_names"].append("TestUnexpected"),
                       lambda v: v.update(explicit_skips=["TestCandidateSnapshotAcquisitionError"]),
                       lambda v: v.update(failed_tests=["TestCandidateSnapshotReturnedPatchLifetime"]),
                       lambda v: v.update(race_detector=False), lambda v: v.update(build_tree="0" * 40)):
            value = copy.deepcopy(original)
            mutate(value)
            with self.assertRaises(ValueError):
                C.check_units(value, original["root_tests"], original["test_pass_names"],
                              original["package_pass_names"], original["build_tree"])

    def test_incomplete_or_failed_native_command_refuses(self):
        original = self.corpus["unit_runs"]["candidate_component"]["command"]
        for field, value in (("state", "RUNNING"), ("actual_exit", 1), ("actual_exit", False),
                             ("output_complete", False), ("reason", "UNKNOWN")):
            changed = copy.deepcopy(original)
            changed[field] = value
            with self.assertRaises(ValueError):
                C.command(changed)

    def test_reference_bounds_and_digest_syntax_refuse(self):
        for value in ({"bytes": True, "sha256": "0" * 64}, {"bytes": -1, "sha256": "0" * 64},
                      {"bytes": 1, "sha256": "unknown"}, {"bytes": 0, "sha256": "0" * 64}):
            with self.assertRaises(ValueError):
                C.ref(value)

    def test_duplicate_nonfinite_and_oversized_documents_refuse(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":Infinity}', b"x" * (C.MAX_BYTES + 1)):
            with self.assertRaises(ValueError):
                C.document(raw)

    def test_chain_payload_reuse_requires_exact_command_stdout_digest(self):
        rows = copy.deepcopy(self.corpus["chain_cases"])
        rows[0]["command"]["stdout"]["sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            C.check_chain_cases(rows, C.prior_corpus())

    def test_no_chain_payload_is_duplicated_in_the_new_corpus(self):
        for row in self.corpus["chain_cases"]:
            self.assertEqual(set(row), {"case", "command", "recorded_stdout"})
        self.assertNotIn("stdout_utf8", self.raw.decode())

    def test_source_and_acceptance_scope_substitutions_refuse(self):
        for field in ("source", "scope"):
            value = copy.deepcopy(self.corpus)
            if field == "source":
                value[field]["integrated_candidate_build_tree"] = "0" * 40
            else:
                value[field]["accepted_header_binding"] = True
            with self.assertRaises(ValueError):
                C.check_corpus(value)

    def test_experimental_observation_does_not_erase_failed_caller(self):
        value = copy.deepcopy(self.corpus)
        value["execution"]["parent_caller_outcome"] = "SUCCESS"
        with self.assertRaises(ValueError):
            C.check_corpus(value)


if __name__ == "__main__":
    unittest.main()
