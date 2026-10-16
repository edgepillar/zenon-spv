#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Adverse controls for reversible recorded source-default retention evidence."""
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("recorded_default_retention_controls", HERE / "check_default_retention_corpus.py")
C = importlib.util.module_from_spec(spec)
spec.loader.exec_module(C)


class RecordedDefaultRetentionControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw, cls.document = C.read_corpus(HERE / "testdata/candidate-default-retention.json")

    def change(self, action):
        document = copy.deepcopy(self.document)
        action(document)
        with self.assertRaises((ValueError, KeyError, TypeError, IndexError, AssertionError)):
            C.check_corpus(document)

    def test_complete_six_case_recording_and_presealed_model(self):
        report = C.check_corpus(self.document)
        self.assertEqual(report["recorded_component_processes"], 6)
        self.assertEqual(report["reference_binaries"], 1)
        self.assertEqual(report["independently_replayed_history_heights"], 32768)
        self.assertEqual(report["recorded_matched_proof_observations"], 900)
        self.assertEqual(report["recorded_pruned_proof_refusals"], 180)
        self.assertEqual(report["consumer_result"], "REFUSED")

    def test_source_defaults_and_inclusive_horizon(self):
        table = next(v for v in self.document["shared_observed_tables"].values() if v["policy"] == "pruned")
        actual = json.loads(C.expand_table(table, self.document["observed_archive_roots"]))
        roots = actual["snapshot"]["retained_roots"]
        self.assertEqual((len(roots), roots[0]["height"], roots[-1]["height"]), (17381, 15388, 32768))
        self.assertEqual(roots[0]["hash"], C.C.identifier("G", 15388)["hash"])

    def test_all_archive_roots_are_expanded_with_observed_payload_digest(self):
        for digest, table in self.document["shared_observed_tables"].items():
            expanded = C.expand_table(table, self.document["observed_archive_roots"])
            self.assertEqual(hashlib.sha256(expanded).hexdigest(), digest)
            expected = 32768 if table["policy"] == "archive" else 17381
            self.assertEqual(len(json.loads(expanded)["snapshot"]["retained_roots"]), expected)

    def test_root_omission_duplication_and_reordering_refuse(self):
        self.change(lambda d: d["observed_archive_roots"].pop(73))
        self.change(lambda d: d["observed_archive_roots"].append(d["observed_archive_roots"][-1]))
        self.change(lambda d: d["observed_archive_roots"].reverse())

    def test_changed_intermediate_root_refuses(self):
        self.change(lambda d: d["observed_archive_roots"].__setitem__(12345, "00" * 32))

    def test_hash_height_codec_is_explicit_and_not_relabelable(self):
        self.change(lambda d: d.update(observed_root_codec="height_only"))
        self.assertNotEqual(C.C.identifier("G", 32768), C.C.identifier("X", 32768))

    def test_observed_tables_cannot_be_replaced_by_unbound_expectations(self):
        def corrupt(document):
            table = next(iter(document["shared_observed_tables"].values()))
            table["snapshot"]["logical_records_sha256"] = "00" * 32
        self.change(corrupt)

    def test_table_bytes_length_cannot_be_rebound(self):
        self.change(lambda d: d["runs"][0]["payload"].update(bytes=d["runs"][0]["payload"]["bytes"] + 1))

    def test_queries_and_canonical_proofs_remain_observed_bytes(self):
        def corrupt(document):
            table = next(v for v in document["shared_observed_tables"].values() if v["policy"] == "archive")
            table["queries"][0]["proofs"][0]["proof"] = "00"
        self.change(corrupt)

    def test_exact_query_scope_does_not_claim_every_mutated_key(self):
        report = C.check_corpus(self.document)
        self.assertEqual((report["distinct_mutation_addresses"], report["selected_proof_keys"]), (256, 15))
        self.assertIs(report["all_mutated_keys_individually_queried"], False)

    def test_all_mutation_keys_and_presealed_witnesses_are_bound(self):
        self.change(lambda d: d["presealed_expectations_without_history"]["selection"]["mutation_keys"].reverse())
        self.change(lambda d: d["presealed_expectations_without_history"]["initial_witnesses"][0].update(value="00" * 32))

    def test_changed_witnesses_refuse_before_expensive_model_replay(self):
        altered = copy.deepcopy(self.document["presealed_expectations_without_history"])
        altered["initial_witnesses"][0]["proof"] = "00"
        with mock.patch.object(C.M, "history", side_effect=AssertionError("must refuse before model")), self.assertRaises(ValueError):
            C.expected_from_presealed_witnesses(C.M.encoded(altered))

    def test_full_history_mutation_frame_and_counts_are_bound(self):
        self.change(lambda d: d["history_summary"].update(mutation_frame_sha256="00" * 32))
        self.change(lambda d: d["history_summary"]["mutation_counts"].update(Delete=0))

    def test_complete_source_and_proposal_pins_are_required(self):
        self.change(lambda d: d["source"].update(runtime_tree_without_probes="00" * 20))
        self.change(lambda d: d["source"]["source_inputs"].update(default_retention_probe_test_go="00" * 32))

    def test_evidence_receipts_are_fixed_without_authentication_claim(self):
        self.change(lambda d: d["evidence"].update(ordinary_binary_sha256="00" * 32))
        self.change(lambda d: d["evidence"].update(receipt_hashes_authenticate_distribution=True))

    def test_no_sample_is_omitted_duplicated_or_reordered(self):
        self.change(lambda d: d["runs"].pop())
        self.change(lambda d: d["runs"].append(copy.deepcopy(d["runs"][0])))
        self.change(lambda d: d["runs"].reverse())

    def test_actual_exit_output_and_workspace_result_are_required(self):
        for field, value in (("worker_actual_exit", 1), ("worker_actual_exit", False),
                             ("worker_output_complete", False), ("owned_workspace_removed", False)):
            with self.subTest(field=field, value=value):
                self.change(lambda d: d["runs"][0].update({field: value}))

    def test_original_cleanup_erratum_is_preserved(self):
        self.change(lambda d: d["evidence"].update(first_case_cleanup_erratum_sha256="00" * 32))
        self.change(lambda d: d["runs"][0].update(cleanup_method="supervised_after_durable_CAS_ack_and_absence_check"))

    def test_closed_sample_manifest_prevents_resource_or_stream_substitution(self):
        self.change(lambda d: d["runs"][0]["process"].update(peak_rss_bytes=12345))
        self.change(lambda d: d["runs"][0]["capture"].update(child_stdout_sha256="00" * 32))

    def test_resource_shape_has_explicit_units_and_exact_process_scope(self):
        original = self.document["runs"][0]
        for field, value in (("elapsed_ns", 0), ("peak_rss_bytes", False), ("peak_rss_bytes", -1),
                             ("sampled_child_RSS_peak_bytes", (2 << 30) + 1), ("child_RSS_samples", 0),
                             ("sample_interval_seconds", True), ("major_page_faults", -1),
                             ("user_cpu_seconds", float("nan")), ("process_exit", False),
                             ("output_complete", False), ("reason", "UNKNOWN"),
                             ("measurement_scope", "node_only"), ("descendant_process_memory_included", True),
                             ("sampling_is_not_an_OS_memory_quota", False), ("child_deadline_seconds", 0)):
            with self.subTest(field=field, value=value):
                row = copy.deepcopy(original["process"])
                row[field] = value
                with self.assertRaises(ValueError):
                    C.process_resource(row, original["component"])

    def test_resource_sample_includes_fixture_and_query_cost(self):
        for record in self.document["runs"]:
            C.process_resource(record["process"], record["component"])
            self.assertGreaterEqual(record["process"]["elapsed_ns"],
                                    sum(record["component"][name] for name in C.C.TIMERS))

    def test_unknown_or_orphan_table_is_not_an_extra_sample(self):
        self.change(lambda d: d["shared_observed_tables"].update({"00" * 32: copy.deepcopy(next(iter(d["shared_observed_tables"].values())))}))

    def test_policy_table_rebinding_is_refused(self):
        def corrupt(document):
            table = next(iter(document["shared_observed_tables"].values()))
            table["policy"] = "archive" if table["policy"] == "pruned" else "pruned"
        self.change(corrupt)

    def test_closed_shapes_and_production_gates_cannot_expand(self):
        self.change(lambda d: d.update(production_qualified=True))
        for field in C.SCOPE:
            with self.subTest(field=field):
                self.change(lambda d: d["scope"].update({field: not d["scope"][field]}))

    def test_duplicate_trailing_and_oversized_json_refuse(self):
        for raw in (b'{"kind":1,"kind":2}', self.raw + b"{}", b" " * (C.MAX_FILE_BYTES + 1)):
            with self.subTest(bytes=len(raw)), tempfile.TemporaryDirectory(dir=os.environ.get("SPV_TASK_SCRATCH")) as temporary:
                path = Path(temporary) / "untrusted.json"
                path.write_bytes(raw)
                with self.assertRaises(ValueError):
                    C.read_corpus(path)

    def test_recorded_checker_has_no_node_network_or_resource_execution(self):
        with mock.patch.object(socket, "socket", side_effect=AssertionError("network forbidden")), \
                mock.patch.object(subprocess, "Popen", side_effect=AssertionError("process forbidden")):
            report = C.check_corpus(self.document)
        for field in ("native_reference_node_or_CGO_execution", "new_resource_measurements",
                      "network_executed", "source_initial_full_projection_recomputed_in_this_checker",
                      "all_node_record_bytes_independently_reconstructed", "production_resources_qualified"):
            self.assertIs(report[field], False)

    def test_cli_labels_exact_source_revision_and_corpus_digest(self):
        captured = io.StringIO()
        with contextlib.redirect_stdout(captured):
            C.main(["--source-revision", "ab" * 20])
        report = json.loads(captured.getvalue())
        self.assertEqual(report["corpus_sha256"], hashlib.sha256(self.raw).hexdigest())
        self.assertEqual(report["source_revision"], "ab" * 20)
        with self.assertRaises(ValueError):
            C.main(["--source-revision", "main"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
