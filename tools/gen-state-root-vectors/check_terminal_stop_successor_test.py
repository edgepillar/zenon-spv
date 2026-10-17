#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Adverse controls for the recorded, checkpoint-controlled stop comparison."""
import contextlib
import copy
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
spec = importlib.util.spec_from_file_location("selected_successor_lifecycle_checker", HERE / "check_terminal_stop_successor.py")
C = importlib.util.module_from_spec(spec)
spec.loader.exec_module(C)


class SuccessorLifecycleStopTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _, cls.document = C.read_corpus(HERE / "testdata/successor-lifecycle-stop.json")

    def changed(self):
        return copy.deepcopy(self.document)

    def case(self, document, name="stop-before-init", variant="monotonic-stop"):
        return next(row for row in document["variants"][variant]["cases"] if row["name"] == name)

    def phase(self, document, case="pending-stop-lock", name="stop-intent", variant="monotonic-stop"):
        return next(row for row in self.case(document, case, variant)["phases"] if row["name"] == name)

    def refused(self, document):
        with self.assertRaises((ValueError, KeyError, TypeError, IndexError)):
            C.check_corpus(document)

    def test_complete_recorded_comparison(self):
        result = C.check_corpus(self.document)
        self.assertEqual(result["phase_observations"], 34)
        self.assertEqual(result["selected_read_observations"], 82)
        self.assertEqual(result["logical_record_snapshots"], 46)
        self.assertEqual(result["component_initializations"], 14)
        self.assertEqual(result["stop_calls"], 14)
        self.assertEqual(result["build_launch_calls"], 6)

    def test_stopped_empty_instance_cannot_reopen(self):
        guarded = self.case(self.document)
        self.assertEqual(guarded["init_errors"], ["stopped"])
        self.assertTrue(all(p["ready"] is False and p["handle_assigned"] is False for p in guarded["phases"]))
        self.assertEqual(guarded["records_after_close_reopen"], [])
        self.assertIs(guarded["harness_extra_close_required"], False)
        baseline = self.case(self.document, variant="hash-bound")
        self.assertEqual(baseline["init_errors"], [None])
        self.assertIs(baseline["harness_extra_close_required"], True)
        self.assertIsNone(baseline["backend_after_final_stop"]["error"])

    def test_stop_intent_revokes_new_reads_before_changes_lock(self):
        for case in ("pending-stop-lock", "pending-compute-stop"):
            guarded = self.phase(self.document, case)
            self.assertIs(guarded["quit_closed"], True)
            self.assertIs(guarded["ready"], False)
            self.assertTrue(all(r["error"] == "not-ready" for r in guarded["reads"]))
            old = self.phase(self.document, case, variant="hash-bound")
            self.assertIs(old["ready"], True)
            self.assertTrue(all(r["error"] is None for r in old["reads"]))

    def test_already_admitted_compute_finishes_before_close(self):
        for variant in C.VARIANTS:
            row = self.case(self.document, "pending-compute-stop", variant)
            self.assertIsNone(row["inflight_compute"]["error"])
            self.assertEqual(row["inflight_compute"]["root"], C.H.root(C.H.patch("A", 99)).hex())
            self.assertEqual(row["inflight_compute"]["patch_callbacks"], {"dump": 1, "replay": 1})
            self.assertEqual(row["backend_after_final_stop"]["error"], "database-closed")

    def test_pending_init_cannot_fold_after_stop_intent(self):
        guarded = self.case(self.document, "pending-init-stop")
        self.assertEqual(guarded["init_errors"], ["stopped"])
        self.assertEqual(guarded["records_after_close_reopen"], [{"key": "05", "value": "03"}])
        self.assertEqual(guarded["manager_trace"], [{"method": "Frontier"}])
        baseline = self.case(self.document, "pending-init-stop", "hash-bound")
        self.assertEqual(baseline["init_errors"], [None])
        self.assertGreater(len(baseline["records_after_close_reopen"]), 1)

    def test_stopped_open_instance_returns_terminal_error(self):
        guarded = self.case(self.document, "init-before-stop")
        baseline = self.case(self.document, "init-before-stop", "hash-bound")
        self.assertEqual(guarded["init_errors"], [None, "stopped"])
        self.assertEqual(baseline["init_errors"], [None, "database-closed"])
        self.assertEqual(guarded["records_after_close_reopen"], baseline["records_after_close_reopen"])

    def test_held_launches_cannot_publish_after_stop(self):
        guarded = self.case(self.document, "held-launches-stop")
        baseline = self.case(self.document, "held-launches-stop", "hash-bound")
        self.assertEqual(guarded["checkpoints"], {"launch_entry": 2, "launch_snapshot": 1, "worker_claimed": 0})
        self.assertEqual(baseline["checkpoints"], {"launch_entry": 2, "launch_snapshot": 2, "worker_claimed": 2})
        self.assertIs(guarded["launch_admission"]["published_after_stop_returned"], False)
        self.assertIs(baseline["launch_admission"]["published_after_stop_returned"], True)
        self.assertEqual(baseline["launch_admission"]["workers_awaited_by_harness"], 2)

    def test_worker_control_is_not_a_background_batch_qualification(self):
        scope = self.document["scope"]
        self.assertIs(scope["test_only_source_checkpoints_injected"], True)
        self.assertIs(scope["background_build_batches_executed"], False)
        self.assertIs(scope["production_concurrency_qualified"], False)
        self.assertEqual(self.document["consumer_result"], "REFUSED")

    def test_substituted_case_inventory_refused(self):
        doc = self.changed()
        doc["variants"]["monotonic-stop"]["cases"].pop()
        self.refused(doc)
        doc = self.changed()
        doc["variants"]["hash-bound"]["cases"].append(copy.deepcopy(self.case(doc)))
        self.refused(doc)

    def test_missing_phase_refused(self):
        doc = self.changed()
        self.case(doc, "pending-stop-lock")["phases"].pop(1)
        self.refused(doc)

    def test_reopened_backend_claim_refused(self):
        doc = self.changed()
        self.phase(doc, "stop-before-init", "init-after-stop")["handle_assigned"] = True
        self.refused(doc)

    def test_false_ready_or_lost_stop_intent_refused(self):
        for key, replacement in (("ready", True), ("quit_closed", False)):
            doc = self.changed()
            self.phase(doc)[key] = replacement
            self.refused(doc)

    def test_integer_boolean_substitution_refused(self):
        doc = self.changed()
        self.phase(doc)["ready"] = 0
        self.refused(doc)
        doc = self.changed()
        self.case(doc, "held-launches-stop")["checkpoints"]["worker_claimed"] = False
        self.refused(doc)

    def test_missing_stop_or_init_error_refused(self):
        doc = self.changed()
        self.case(doc)["init_errors"] = [None]
        self.refused(doc)
        doc = self.changed()
        self.case(doc)["stop_errors"].pop()
        self.refused(doc)

    def test_inflight_result_or_callbacks_substitution_refused(self):
        for key, replacement in (("root", "00" * 32), ("error", "not-ready"), ("patch_callbacks", {"dump": 0, "replay": 0})):
            doc = self.changed()
            self.case(doc, "pending-compute-stop")["inflight_compute"][key] = replacement
            self.refused(doc)

    def test_suppressed_parent_orphan_observation_refused(self):
        doc = self.changed()
        row = self.case(doc, "held-launches-stop", "hash-bound")
        row["launch_admission"]["published_after_stop_returned"] = False
        row["checkpoints"]["worker_claimed"] = 0
        self.refused(doc)

    def test_claimed_guarded_worker_or_extra_close_refused(self):
        doc = self.changed()
        self.case(doc, "held-launches-stop")["checkpoints"]["worker_claimed"] = 1
        self.refused(doc)
        doc = self.changed()
        self.case(doc)["harness_extra_close_required"] = True
        self.refused(doc)

    def test_stored_metadata_frontier_or_refcount_drift_refused(self):
        for prefix in ("00", "01", "02", "03", "05", "06"):
            doc = self.changed()
            p = self.phase(doc, "init-before-stop", "initialized")
            row = next(r for r in p["records"] if r["key"].startswith(prefix))
            row["value"] = "ff" + row["value"][2:]
            self.refused(doc)

    def test_reopen_drift_refused(self):
        doc = self.changed()
        self.case(doc, "init-before-stop")["records_after_close_reopen"].pop()
        self.refused(doc)

    def test_source_hash_height_or_value_substitution_refused(self):
        for field, replacement in (("identifier", C.H.identifier("B", 2)), ("root", "00" * 32)):
            doc = self.changed()
            self.phase(doc, "init-before-stop", "initialized")["reads"][0][field] = replacement
            self.refused(doc)
        doc = self.changed()
        self.phase(doc, "init-before-stop", "initialized")["reads"][1]["value"] = C.H.value(91).hex()
        self.refused(doc)

    def test_proof_and_blocked_callback_substitution_refused(self):
        doc = self.changed()
        self.phase(doc, "init-before-stop", "initialized")["reads"][1]["proof"] = ""
        self.refused(doc)
        doc = self.changed()
        self.phase(doc, "pending-stop-lock", "after-stop")["reads"][2]["patch_callbacks"]["replay"] = 1
        self.refused(doc)

    def test_trace_or_retained_frontier_substitution_refused(self):
        doc = self.changed()
        self.case(doc, "pending-init-stop")["manager_trace"].append({"method": "Frontier"})
        self.refused(doc)
        doc = self.changed()
        self.phase(doc, "init-before-stop", "initialized")["retained_frontier"] = C.H.identifier("B", 2)
        self.refused(doc)

    def test_source_tree_or_pin_substitution_refused(self):
        for field in ("node_revision", "hash_identity_parent_tree", "monotonic_stop_tree"):
            doc = self.changed()
            doc["source"][field] = "00" * 20
            self.refused(doc)
        doc = self.changed()
        doc["source"]["producer_and_oracle_inputs"]["lifecycle_stop_successor_probe_test.go"] = "00" * 32
        self.refused(doc)

    def test_historical_rebinding_or_hidden_instrumentation_refused(self):
        for field, replacement in (("historical_source_records_rebound", True), ("checkpoint_source_is_separate_from_uninstrumented_proposal", False)):
            doc = self.changed()
            doc["source"][field] = replacement
            self.refused(doc)

    def test_stronger_production_scope_refused(self):
        for field in ("production_concurrency_qualified", "physical_crash_or_power_loss_qualified", "full_node_started",
                      "background_build_batches_executed", "header_authentication_executed", "profile_agreed",
                      "network_activation_authenticated", "runtime_state_value_acceptance"):
            doc = self.changed()
            doc["scope"][field] = True
            self.refused(doc)

    def test_swapped_variants_unknown_fields_or_acceptance_refused(self):
        doc = self.changed()
        doc["variants"]["hash-bound"], doc["variants"]["monotonic-stop"] = doc["variants"]["monotonic-stop"], doc["variants"]["hash-bound"]
        self.refused(doc)
        doc = self.changed()
        self.case(doc)["canonical"] = True
        self.refused(doc)
        doc = self.changed()
        doc["consumer_result"] = "MATCH"
        self.refused(doc)

    def test_duplicate_json_and_raw_size_limit_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bounded.json"
            path.write_bytes(b'{"format_version":1,"format_version":1}')
            with self.assertRaises(ValueError):
                C.read_corpus(path)
            path.write_bytes(b" " * (C.MAX_FILE_BYTES + 1))
            with self.assertRaises(ValueError):
                C.read_corpus(path)

    def test_source_label_and_one_report_record(self):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            C.main(["--source-revision", "12" * 20])
        self.assertEqual(len(output.getvalue().splitlines()), 1)
        report = json.loads(output.getvalue())
        self.assertEqual(report["source_revision"], "12" * 20)
        self.assertEqual(report["local_node_revision"], C.H.REVISION)
        self.assertEqual(report["corpus_sha256"], C.hashlib.sha256((HERE / "testdata/successor-lifecycle-stop.json").read_bytes()).hexdigest())
        self.assertIs(report["reference_execution_in_checker"], False)

    def test_invalid_source_labels_refused_before_read(self):
        for label in ("", "AB" * 20, "00" * 19):
            with self.assertRaises(ValueError):
                C.main(["--source-revision", label, "--corpus", "unread-unselected-path"])

    def test_oracle_executes_no_process_or_network(self):
        with mock.patch.object(subprocess, "run", side_effect=AssertionError("child")), \
             mock.patch.object(subprocess, "Popen", side_effect=AssertionError("child")), \
             mock.patch.object(socket, "create_connection", side_effect=AssertionError("network")):
            C.check_corpus(self.document)


if __name__ == "__main__":
    unittest.main()

