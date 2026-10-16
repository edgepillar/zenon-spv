#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Adverse controls for recorded source-genesis background component evidence."""
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
spec = importlib.util.spec_from_file_location("genesis_background_recorded_controls", HERE / "check_genesis_background_corpus.py")
C = importlib.util.module_from_spec(spec)
spec.loader.exec_module(C)


class GenesisBackgroundControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw, cls.document = C.read_corpus(HERE / "testdata/candidate-genesis-background.json")

    def change(self, action):
        document = copy.deepcopy(self.document)
        action(document)
        with self.assertRaises((ValueError, KeyError, TypeError, IndexError, AssertionError)):
            C.check_corpus(document)

    def test_all_nine_processes_and_independent_fixture_roots(self):
        report = C.check_corpus(self.document)
        self.assertEqual(report["recorded_component_processes"], 9)
        self.assertEqual((report["normal_reference_processes"], report["race_reference_processes"]), (6, 3))
        self.assertEqual(report["independently_replayed_history_heights"], 4096)
        self.assertEqual(report["selected_proof_observations"], 1350)
        self.assertEqual(report["consumer_result"], "REFUSED")

    def test_prune_horizon_is_inclusive_and_retains_257_roots(self):
        rows = self.document["root_tables"]["pruned"]
        self.assertEqual((len(rows), rows[0]["height"], rows[-1]["height"]), (257, 3840, 4096))
        self.change(lambda d: d["root_tables"]["pruned"].pop(0))

    def test_archive_cannot_omit_duplicate_or_reorder_a_version(self):
        self.change(lambda d: d["root_tables"]["archive"].pop(31))
        self.change(lambda d: d["root_tables"]["archive"].append(copy.deepcopy(d["root_tables"]["archive"][-1])))
        self.change(lambda d: d["root_tables"]["archive"].reverse())

    def test_full_identity_is_bound_separately_from_height(self):
        self.change(lambda d: d["root_tables"]["archive"][4095].update(hash="00" * 32))
        self.assertEqual(C.C.identifier("G", 4096)["hash"],
                         "87907b59baa934a73d0e09c9cb1652502ef725171bba58e1632be5282afe9559")
        for fork, height in (("A", 1), ("G", 0), ("G", True), ("G", 4097)):
            with self.subTest(fork=fork, height=height), self.assertRaises(ValueError):
                C.C.identifier(fork, height)

    def test_root_metadata_is_prefix_03_not_node_prefix_01(self):
        def corrupt(document):
            for key in ("snapshot_before_stop", "closed_snapshot", "reopened_snapshot"):
                document["runs"][0]["observation"][key]["record_prefix_counts"]["03"] = 41925
        self.change(corrupt)

    def test_one_changed_phase_cannot_look_like_a_clean_reopen(self):
        self.change(lambda d: d["runs"][0]["observation"]["reopened_snapshot"].update(logical_records_sha256="00" * 32))

    def test_independent_root_table_cannot_be_substituted(self):
        self.change(lambda d: d["root_tables"]["archive"][1234].update(root="00" * 32))
        self.change(lambda d: d["history_summary"].update(final_root="00" * 32))

    def test_presealed_initial_witnesses_and_source_input_are_bound(self):
        self.change(lambda d: d["initial_expectations"]["selected_proofs"][0].update(value="00" * 32))
        self.change(lambda d: d["initial_expectations"]["raw_input"].update(sha256="00" * 32))

    def test_canonical_proof_bytes_cannot_be_replaced(self):
        self.change(lambda d: d["query_tables"]["archive"][0]["proofs"][0].update(proof="00" * 99))

    def test_present_zero_and_missing_balance_are_distinct(self):
        rows = self.document["query_tables"]["archive"][4]["proofs"]
        zero = next(row for row in rows if row["value"] == "00" * 32)
        missing = next(row for row in rows if row["value"] is None)
        self.assertNotEqual(zero["proof"], missing["proof"])
        self.change(lambda d: next(row for row in d["query_tables"]["archive"][4]["proofs"]
                                  if row["value"] == "00" * 32).update(value=None))

    def test_excluded_ledger_key_absence_does_not_prove_ledger_absence(self):
        row = next(row for row in self.document["initial_expectations"]["selected_proofs"]
                   if row["selection"] == "excluded_ledger_key")
        self.assertIs(row["ledger_raw_input_has_key"], True)
        self.assertIs(row["present_in_projection"], False)
        self.assertIs(row["typed_domain_refused"], True)
        self.change(lambda d: d["query_tables"]["archive"][0]["proofs"][-1].update(consumer_result="ACCEPTED"))

    def test_pruned_and_wrong_identity_refusals_remain_distinct(self):
        self.change(lambda d: d["query_tables"]["pruned"][0].update(root_error=None))
        self.change(lambda d: d["query_tables"]["archive"][6].update(root_error="no-version"))

    def test_controlled_stop_restarts_from_committed_height_one(self):
        row = self.document["runs"][-1]["observation"]["interrupted"]
        self.assertEqual(row["frontier"], C.C.identifier("G", 1))
        self.assertIs(row["ready"], False)
        self.assertEqual(row["direct_closed_error"], "database-closed")
        self.change(lambda d: d["runs"][-1]["observation"]["interrupted"].update(ready=True))

    def test_stop_revokes_public_and_backend_reads(self):
        self.change(lambda d: d["runs"][0]["observation"].update(post_stop_public_error=None))
        self.change(lambda d: d["runs"][0]["observation"].update(post_stop_direct_error=None))

    def test_no_completed_sample_can_be_omitted_duplicated_or_reordered(self):
        self.change(lambda d: d["runs"].pop())
        self.change(lambda d: d["runs"].append(copy.deepcopy(d["runs"][0])))
        self.change(lambda d: d["runs"].reverse())

    def test_actual_exit_and_completeness_are_required(self):
        for field, value in (("actual_exit", 1), ("actual_exit", False), ("output_complete", False)):
            with self.subTest(field=field, value=value):
                self.change(lambda d: d["runs"][0].update({field: value}))

    def test_race_measurement_is_not_a_normal_resource_sample(self):
        self.change(lambda d: d["runs"][-1].update(normal_resource_measurement=True))

    def test_resource_scope_includes_fixture_and_queries(self):
        self.change(lambda d: d["runs"][0]["process_resource"].update(measurement_scope="node_only"))
        self.change(lambda d: d["runs"][0]["process_resource"].update(descendant_process_memory_included=True))

    def test_resource_and_elapsed_numbers_have_explicit_units_and_types(self):
        for field, value in (("peak_rss_bytes", False), ("peak_rss_bytes", -1),
                             ("elapsed_ns", 0), ("user_cpu_seconds", float("nan")),
                             ("minor_page_faults", -1)):
            with self.subTest(field=field):
                self.change(lambda d: d["runs"][0]["process_resource"].update({field: value}))

    def test_logical_bytes_do_not_replace_measured_file_bytes(self):
        self.change(lambda d: d["runs"][0].update(physical_file_bytes=7503024))

    def test_physical_file_inventory_does_not_allow_paths_aliases_or_invalid_hashes(self):
        for field, value in (("name", "../node"), ("name", "/private/input"), ("sha256", "x" * 64)):
            with self.subTest(field=field):
                self.change(lambda d: d["runs"][0]["observation"]["physical_files_after_final_close"][0].update({field: value}))

    def test_shared_tables_are_explicit_and_cannot_be_rebound(self):
        self.change(lambda d: d["runs"][0]["observation"]["snapshot_before_stop"].update(retained_roots_table="archive"))
        self.change(lambda d: d["runs"][0]["observation"].update(queries_table="archive"))

    def test_source_proposal_and_receipt_hashes_are_pinned(self):
        self.change(lambda d: d["source"].update(runtime_tree_without_probes="00" * 20))
        self.change(lambda d: d["evidence"].update(normal_binary_sha256="00" * 32))
        self.change(lambda d: d["harness_history"].pop(0))

    def test_empirical_metrics_and_stream_references_cannot_be_rebound(self):
        self.change(lambda d: d["runs"][0]["stdout"].update(sha256="ab" * 32))
        self.change(lambda d: d["runs"][0]["process_resource"].update(peak_rss_bytes=128 << 20))

    def test_closed_shapes_and_scalar_types_prevent_extra_claims(self):
        self.change(lambda d: d.update(production_qualified=True))
        self.change(lambda d: d["runs"][0]["observation"].update(signature_verified=True))
        self.change(lambda d: d["runs"][0]["observation"].update(patch_heights_requested=True))

    def test_full_node_profile_and_production_gates_remain_closed(self):
        for field, value in C.SCOPE.items():
            if value is False:
                with self.subTest(field=field):
                    self.change(lambda d: d["scope"].update({field: True}))

    def test_recorded_checker_does_not_execute_a_node_or_network(self):
        with mock.patch.object(socket, "socket", side_effect=AssertionError("network forbidden")), \
                mock.patch.object(subprocess, "Popen", side_effect=AssertionError("process forbidden")):
            result = C.check_corpus(self.document)
        self.assertIs(result["native_reference_node_or_CGO_execution"], False)
        self.assertIs(result["source_initial_full_projection_recomputed_in_this_checker"], False)

    def test_duplicate_trailing_and_oversized_json_are_refused(self):
        for raw in (b'{"kind":1,"kind":2}', self.raw + b"{}", b" " * (C.MAX_FILE_BYTES + 1)):
            with self.subTest(bytes=len(raw)), tempfile.TemporaryDirectory(dir=os.environ.get("SPV_TASK_SCRATCH")) as temporary:
                file = Path(temporary) / "untrusted.json"
                file.write_bytes(raw)
                with self.assertRaises(ValueError):
                    C.read_corpus(file)

    def test_cli_source_label_and_corpus_digest_are_explicit(self):
        captured = io.StringIO()
        with contextlib.redirect_stdout(captured):
            C.main(["--source-revision", "ab" * 20])
        report = json.loads(captured.getvalue())
        self.assertEqual(report["corpus_sha256"], hashlib.sha256(self.raw).hexdigest())
        self.assertEqual(report["source_revision"], "ab" * 20)
        with self.assertRaises(ValueError):
            C.main(["--source-revision", "latest"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
