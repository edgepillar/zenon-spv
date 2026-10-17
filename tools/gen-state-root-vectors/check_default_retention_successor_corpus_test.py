#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Recorded-data refusal controls; execute no node or native resource observer."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("successor_retention_recorded_controls", HERE / "check_default_retention_successor_corpus.py")
C = importlib.util.module_from_spec(spec)
spec.loader.exec_module(C)


class RecordedSuccessorRetentionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.document = json.loads((HERE / "testdata/successor-default-retention.json").read_bytes(),
                                  object_pairs_hook=C.M.P.pairs)

    def refused(self, document):
        with self.assertRaises((ValueError, AssertionError, TypeError, KeyError)):
            C.check_corpus(document)

    def test_all_six_recorded_cases_reconstruct_complete_payloads(self):
        result = C.check_corpus(self.document)
        self.assertEqual(result["normal_reference_processes"], 6)
        self.assertEqual(result["reference_binaries"], 1)
        self.assertEqual(result["recorded_matched_proof_observations"], 900)
        self.assertEqual(result["recorded_pruned_proof_refusals"], 180)
        self.assertEqual(result["node_revision"], C.M.P.REVISION)
        self.assertEqual(result["consumer_result"], "REFUSED")
        self.assertFalse(result["new_resource_measurements"])
        self.assertFalse(result["new_reference_node_or_CGO_execution"])

    def test_historical_observation_cannot_be_relabelled(self):
        old = json.loads((HERE / "testdata/candidate-default-retention.json").read_bytes())
        self.refused(old)
        doc = dict(self.document, source=dict(self.document["source"], node_revision="33d7d1ee1b6a915c40aea196e2a10f1e893d171f"))
        self.refused(doc)

    def test_source_runtime_module_and_unknown_field_changes_are_refused(self):
        for field in ("node_revision", "node_tree", "runtime_tree", "module_sha256", "sum_sha256", "PRIVATE_FIELD"):
            doc = dict(self.document, source=dict(self.document["source"], **{field: "PRIVATE"}))
            with self.subTest(field=field):
                self.refused(doc)

    def test_native_execution_and_trust_scope_cannot_escalate(self):
        for field in ("production_resources_qualified", "profile_agreed", "network_activation_authenticated",
                      "accepted_header_root_binding", "runtime_SPV_acceptance_changed", "old_node_process_results_relabelled"):
            doc = dict(self.document, scope=dict(self.document["scope"], **{field: True}))
            with self.subTest(field=field):
                self.refused(doc)

    def test_missing_extra_reordered_or_filtered_samples_are_refused(self):
        runs = self.document["runs"]
        for changed in (runs[:-1], runs + runs[:1], list(reversed(runs)), [runs[0]] * 6):
            self.refused(dict(self.document, runs=changed))

    def test_fresh_source_genesis_manifest_is_digest_bound(self):
        with mock.patch.object(C, "GENESIS_SHA256", "00" * 32), self.assertRaises(ValueError):
            C.genesis_execution()

    def test_genesis_skipped_failed_bool_exit_or_scope_escalation_is_refused_after_repin(self):
        original = C.genesis_execution()
        read = C.M.P.read_regular
        changes = (
            lambda d: d["actual_compile"].__setitem__("actual_exit", False),
            lambda d: d["fresh_generations"][0]["actual_command"].__setitem__("actual_exit", 1),
            lambda d: d["fresh_generations"][1]["actual_command"].__setitem__("output_complete", False),
            lambda d: d["fresh_generations"][0]["metadata"].__setitem__("NodeTree_executed", True),
            lambda d: d["fresh_generations"][1]["metadata"].__setitem__("height", True),
            lambda d: d.__setitem__("network_authenticated_genesis", True),
        )
        for change in changes:
            doc = copy.deepcopy(original)
            change(doc)
            raw = C.M.encoded(doc)
            def selected(path, limit):
                return raw if Path(path).name == "successor-genesis-input-execution.json" else read(path, limit)
            with mock.patch.object(C.M.P, "read_regular", side_effect=selected), mock.patch.object(
                    C, "GENESIS_SHA256", hashlib.sha256(raw).hexdigest()), self.assertRaises(ValueError):
                C.genesis_execution()

    def test_root_codec_and_one_observed_root_cannot_be_substituted(self):
        self.refused(dict(self.document, observed_root_codec="implicit"))
        roots = list(self.document["observed_archive_roots"])
        roots[15387] = "00" * 32
        self.refused(dict(self.document, observed_archive_roots=roots))

    def test_equal_but_unsealed_witness_change_is_refused_before_replay(self):
        base = copy.deepcopy(self.document["presealed_expectations_without_history"])
        base["initial_witnesses"][0]["proof"] += "00"
        self.refused(dict(self.document, presealed_expectations_without_history=base))

    def test_byte_payload_length_cannot_be_changed_after_manifest_repin(self):
        runs = copy.deepcopy(self.document["runs"])
        runs[0]["payload"]["bytes"] += 1
        with mock.patch.object(C, "RUNS_SHA256", hashlib.sha256(C.M.encoded(runs)).hexdigest()):
            self.refused(dict(self.document, runs=runs))

    def test_cleanup_and_actual_process_status_are_required_even_after_repin(self):
        for field, value in (("owned_workspace_removed", False), ("worker_actual_exit", False),
                             ("worker_output_complete", False), ("cleanup_method", "unknown")):
            runs = copy.deepcopy(self.document["runs"])
            runs[0][field] = value
            with self.subTest(field=field), mock.patch.object(C, "RUNS_SHA256", hashlib.sha256(C.M.encoded(runs)).hexdigest()):
                self.refused(dict(self.document, runs=runs))

    def test_failed_incomplete_or_race_scope_process_is_refused_after_repin(self):
        for field, value in (("process_exit", 1), ("output_complete", False),
                             ("measurement_scope", "race_process"), ("peak_rss_bytes", True)):
            runs = copy.deepcopy(self.document["runs"])
            runs[0]["process"][field] = value
            with self.subTest(field=field), mock.patch.object(C, "RUNS_SHA256", hashlib.sha256(C.M.encoded(runs)).hexdigest()):
                self.refused(dict(self.document, runs=runs))

    def test_invalid_receipt_is_refused_before_expensive_replay_or_expansion(self):
        runs = copy.deepcopy(self.document["runs"])
        runs[0]["owned_workspace_removed"] = False
        with mock.patch.object(C, "RUNS_SHA256", hashlib.sha256(C.M.encoded(runs)).hexdigest()), mock.patch.object(
                C, "expected_from_presealed_witnesses") as replay, mock.patch.object(C.R, "expand_table") as expand:
            with self.assertRaises(ValueError):
                C.check_corpus(dict(self.document, runs=runs))
            replay.assert_not_called()
            expand.assert_not_called()


if __name__ == "__main__":
    unittest.main()
