#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Portable recorded-data controls; these execute no reference node or workload."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("recorded_proof_workload_controls", HERE / "check_public_chain_proof_workload.py")
C = importlib.util.module_from_spec(spec)
spec.loader.exec_module(C)


def alter_rows(document, change, index=0):
    case = document["cases"][index]
    rows = [json.loads(line) for line in case["stdout_utf8"].splitlines()]
    change(rows)
    raw = b"".join(C.M.encoded(row) for row in rows)
    case["stdout_utf8"] = raw.decode()
    case["command"].update(stdout_sha256=hashlib.sha256(raw).hexdigest(), stdout_bytes=len(raw))


class RecordedProofWorkloadControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        raw = C.P.P.read_regular(HERE / "testdata/native-public-chain-proof-workload.json", C.MAX_CORPUS)
        cls.corpus = C.decoded(raw, C.MAX_CORPUS)
        C.check_corpus(cls.corpus)

    def refuse(self, change):
        value = copy.deepcopy(self.corpus)
        change(value)
        with self.assertRaises((ValueError, KeyError, TypeError, AssertionError)):
            C.check_corpus(value)

    def test_four_actual_records_remain_recorded_evidence(self):
        result = C.check_corpus(self.corpus)
        self.assertEqual(result["recorded_real_manager_processes"], 4)
        self.assertEqual(result["timed_request_pairs"], 16384)
        self.assertEqual(result["timed_root_and_proof_API_calls"], 32768)
        self.assertEqual(result["separate_post_Stop_refusal_API_calls"], 8)
        self.assertEqual(result["new_reference_backend_executions"], 0)
        self.assertFalse(result["execution_provenance_authenticated"])

    def test_runtime_probe_and_input_substitution_refused(self):
        self.refuse(lambda d: d["source"].update(runtime_tree="00"*20))
        self.refuse(lambda d: d["source"]["probe"].update(sha256="00"*32))
        self.refuse(lambda d: d["source"]["selection"].update(sha256="00"*32))
        self.refuse(lambda d: d["source"]["expectations"].update(bytes=1))

    def test_consistently_renamed_binary_still_refused(self):
        def change(d):
            d["execution"]["binary"]["sha256"] = "00"*32
            d["execution"]["commands"]["binary_capture"]["stdout_sha256"] = "00"*32
        self.refuse(change)

    def test_real_exit_and_completeness_are_required(self):
        for changes in ({"actual_exit": 1}, {"actual_exit": False}, {"completed": False}, {"output_complete": False}):
            self.refuse(lambda d: d["cases"][0]["command"].update(changes))
            self.refuse(lambda d: d["execution"]["commands"]["build"].update(changes))

    def test_first_case_is_not_reexecuted_or_relabelled_success(self):
        self.refuse(lambda d: d["execution"].update(initial_collector_outcome="SUCCESS"))
        self.refuse(lambda d: d["execution"].update(initial_failure_preserved=False))
        self.refuse(lambda d: d["execution"].update(first_case_reexecuted=True))
        self.refuse(lambda d: d["execution"].update(original_binary_rebuilt=True))
        self.refuse(lambda d: d["cases"][0].update(reused_complete_actual_execution=False))

    def test_preselected_cases_and_fresh_process_reopen_cannot_be_dropped(self):
        self.refuse(lambda d: d["cases"].pop())
        self.refuse(lambda d: d["cases"].reverse())
        self.refuse(lambda d: d["cases"][-1].update(reopen=False))

    def test_sha_and_byte_count_bind_both_streams(self):
        self.refuse(lambda d: d["cases"][0]["command"].update(stdout_sha256="00"*32))
        self.refuse(lambda d: d["cases"][0]["command"].update(stderr_bytes=0))
        self.refuse(lambda d: d["cases"][0]["command"].update(stdout_bytes=True))

    def test_known_source_diagnostic_is_preserved_not_suppressed(self):
        def change(d):
            case = d["cases"][0]
            case["stderr_utf8"] = ""
            case["command"].update(stderr_sha256=hashlib.sha256(b"").hexdigest(), stderr_bytes=0)
        self.refuse(change)
        self.refuse(lambda d: d["cases"][0].update(stderr_utf8="extra diagnostic\n"))

    def test_rehashed_root_value_or_proof_digest_substitution_refused(self):
        for field, value in (("root", "00"*32), ("value_hex", "ff"*32), ("proof_sha256", "00"*32), ("row_sha256", "00"*32)):
            self.refuse(lambda d: alter_rows(d, lambda rows: rows[3]["first_cycle_observations"][0].update({field: value})))

    def test_ordered_request_digest_and_counts_are_not_self_selected(self):
        self.refuse(lambda d: alter_rows(d, lambda r: r[3].update(ordered_request_rows_sha256="00"*32)))
        for value in (True, 4096.0, 4095):
            self.refuse(lambda d: alter_rows(d, lambda r: r[3].update(root_calls=value)))
            self.refuse(lambda d: alter_rows(d, lambda r: r[3].update(proof_calls=value)))

    def test_native_rss_units_and_conversions_are_exact(self):
        self.refuse(lambda d: alter_rows(d, lambda r: r[3]["usage_after"].update(native_peak_rss_unit="KiB")))
        self.refuse(lambda d: alter_rows(d, lambda r: r[3]["usage_after"].update(SELF_lifetime_peak_rss_through_capture_bytes=1)))
        usage = copy.deepcopy(self.corpus["cases"][0])
        rows = [json.loads(line) for line in usage["stdout_utf8"].splitlines()]
        row = rows[3]["usage_after"]
        row.update(native_peak_rss_unit="KiB", SELF_lifetime_peak_rss_through_capture_bytes=row["native_peak_rss"]*1024)
        C.check_usage(row, "linux")  # Unit conversion control, not a new Linux measurement.

    def test_decreasing_counters_and_invalid_latency_order_refused(self):
        self.refuse(lambda d: alter_rows(d, lambda r: r[3]["usage_after"].update(SELF_user_cpu_ns=0)))
        self.refuse(lambda d: alter_rows(d, lambda r: r[3]["heap_after"].update(total_alloc_bytes=0)))
        self.refuse(lambda d: alter_rows(d, lambda r: r[3].update(api_pair_p95_ns=1)))
        self.refuse(lambda d: alter_rows(d, lambda r: r[3].update(batch_elapsed_ns=True)))

    def test_parallel_cpu_is_not_bounded_by_single_wall_interval(self):
        usage = json.loads(self.corpus["cases"][0]["stdout_utf8"].splitlines()[3])["usage_after"]
        usage["SELF_user_cpu_ns"] = 10**12
        C.check_usage(usage, "darwin")

    def test_context_and_source_genesis_cannot_be_replaced(self):
        self.refuse(lambda d: alter_rows(d, lambda r: r[1]["identifier"].update(hash="00"*32)))
        self.refuse(lambda d: alter_rows(d, lambda r: r[1].update(header_state_root="ff"*32)))
        self.refuse(lambda d: alter_rows(d, lambda r: r[0].update(selection_sha256="00"*32)))

    def test_partial_measurements_cannot_be_full_process_or_pipeline_peaks(self):
        self.refuse(lambda d: d["execution"]["resource_scope"].update(process_peak_RSS_through_exit_measured=True))
        self.refuse(lambda d: d["execution"]["resource_scope"].update(whole_pipeline_peak_memory_measured=True))
        self.refuse(lambda d: alter_rows(d, lambda r: r[3].update(heap_snapshots_are_not_phase_peaks=False)))
        self.refuse(lambda d: alter_rows(d, lambda r: r[4].update(process_peak_RSS_through_exit_measured=True)))

    def test_file_lengths_cannot_claim_physical_allocation_or_reclaim(self):
        self.refuse(lambda d: d["cases"][0].update(physical_allocated_bytes_measured=True))
        self.refuse(lambda d: d["execution"]["resource_scope"].update(physical_disk_reclaim_measured=True))
        self.refuse(lambda d: d["cases"][0]["closed_file_lengths"]["tree"].update(sum_file_lengths=0))

    def test_unknown_fields_and_unselected_backend_claims_refused(self):
        self.refuse(lambda d: d.update(live_network_qualified=True))
        self.refuse(lambda d: alter_rows(d, lambda r: r[3].update(full_process_memory=1)))
        self.refuse(lambda d: d["scope"].update(portable_checker_executes_reference_backend=True))
        self.refuse(lambda d: d["scope"].update(full_node_qualified=True))
        self.refuse(lambda d: d["execution"].update(whole_module_archive_graph_verification="QUALIFIED"))

    def test_production_state_values_and_header_authentication_remain_refused(self):
        self.refuse(lambda d: d.update(consumer_result="ACCEPT"))
        self.refuse(lambda d: d.update(production_state_value_accepted=True))
        self.refuse(lambda d: d.update(proven=["STATE_VALUE_INCLUSION"]))
        self.refuse(lambda d: d["scope"].update(accepted_header_binding=True))
        self.refuse(lambda d: alter_rows(d, lambda r: r[4].update(production_state_value_accepted=True)))

    def test_nonfinite_and_duplicate_json_fields_refused(self):
        for raw in (b'{"a":1,"a":2}', b'{"a":NaN}'):
            with self.assertRaises(ValueError):
                C.decoded(raw, 256)


if __name__ == "__main__":
    unittest.main(verbosity=2)
