#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Portable failed-Init source and recording controls; no node execution."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("failed_init_controls", HERE / "check_core_init_failure.py")
C = importlib.util.module_from_spec(spec)
spec.loader.exec_module(C)
P, M = C.P, C.M


class FailedInitSourceControls(unittest.TestCase):
    def test_plan_keeps_the_selected_runtime_and_binds_all_build_sources(self):
        plan = P.plan("NEW_OWNED_WORKSPACE", "PINNED_GO")
        self.assertEqual(plan["runtime_tree"], P.K.CANDIDATE_TREE)
        self.assertEqual(plan["source_blobs"], 487)
        self.assertEqual(plan["build_tree"], P.P.UTIL.reconstruct_tree(P.build_pins()))
        self.assertFalse(plan["additional_runtime_patch_selected"])
        self.assertFalse(plan["reference_backend_executed"])

    def test_only_three_build_tagged_probes_extend_the_parent_build(self):
        base, pins = P.K.build_pins("candidate"), P.build_pins()
        self.assertEqual({name: pins[name] for name in base}, base)
        self.assertEqual(set(pins) - set(base), {row[1] for row in P.EXTRAS})
        for name, target, size, digest in P.EXTRAS:
            raw = P.pinned(name, size, digest)
            self.assertTrue(raw.startswith(b"//go:build candidate_core_init_failure\n"))
            self.assertEqual(pins[target]["sha256"], hashlib.sha256(raw).hexdigest())

    def test_source_pin_substitution_refuses(self):
        name, _, size, digest = P.EXTRAS[0]
        for wrong_size, wrong_digest in ((size + 1, digest), (size, "0" * 64)):
            with self.subTest(size=wrong_size), self.assertRaises((ValueError, OSError)):
                P.pinned(name, wrong_size, wrong_digest)

    def test_go_selection_and_limits_are_explicit(self):
        for go in (None, True, [], "", "go\x00other"):
            with self.subTest(go=go), self.assertRaises((ValueError, TypeError)):
                P.plan("NEW_OWNED_WORKSPACE", go)
        plan = P.plan("NEW_OWNED_WORKSPACE", "PINNED_GO")
        self.assertEqual(plan["minimum_free_floor_bytes"], 10 << 30)
        self.assertEqual(plan["expected_allocation_bytes"], 2 << 30)
        self.assertEqual(plan["suggested_task_quota_bytes"], 4 << 30)
        self.assertEqual(plan["case_timeout_seconds"], 120)
        self.assertEqual(plan["stdout_limit_bytes"], 64 << 10)
        self.assertEqual(plan["within_case_retries"], 0)
        self.assertFalse(plan["new_dependency_transports_permitted"])

    def test_plan_selects_two_fresh_keyless_processes_and_no_Start(self):
        plan = P.plan("NEW_OWNED_WORKSPACE", "PINNED_GO")
        self.assertEqual(plan["selected_manager_faults"], list(P.CASES))
        self.assertEqual(len(plan["run_argv_templates"]), 2)
        self.assertTrue(plan["fresh_process_per_case_required"])
        self.assertFalse(plan["core_Start_selected"])
        self.assertFalse(plan["full_node_or_network_execution_selected"])
        self.assertFalse(plan["production_state_value_accepted"])
        self.assertEqual(plan["consumer_result"], "REFUSED")

    def test_existing_workspace_is_preserved(self):
        with tempfile.TemporaryDirectory() as root:
            workspace = Path(root).resolve() / "existing"
            workspace.mkdir()
            marker = workspace / "keep"
            marker.write_bytes(b"existing input")
            with self.assertRaises((ValueError, OSError)):
                P.prepare(Path(root).resolve() / "missing-source", workspace, "PINNED_GO")
            self.assertEqual(marker.read_bytes(), b"existing input")

    def test_source_overlap_refuses_before_staging(self):
        with tempfile.TemporaryDirectory() as root:
            source = Path(root).resolve() / "source"
            source.mkdir()
            workspace = source / "child"
            with self.assertRaises((ValueError, OSError)):
                P.prepare(source, workspace, "PINNED_GO")
            self.assertFalse(workspace.exists())

    def test_missing_or_corrupt_source_never_creates_a_workspace(self):
        with tempfile.TemporaryDirectory() as root:
            source = Path(root).resolve() / "source"
            workspace = Path(root).resolve() / "new"
            with self.assertRaises((ValueError, OSError)):
                P.prepare(source, workspace, "PINNED_GO")
            source.mkdir()
            (source / "go.mod").write_bytes(b"wrong bytes")
            with self.assertRaises((ValueError, OSError)):
                P.prepare(source, workspace, "PINNED_GO")
            self.assertFalse(workspace.exists())

    def test_unknown_workspace_entries_are_preserved_and_refused(self):
        with tempfile.TemporaryDirectory() as root:
            workspace = Path(root).resolve()
            (workspace / "node").mkdir()
            marker = workspace / "unknown"
            marker.write_bytes(b"preserve")
            with self.assertRaises((ValueError, OSError)):
                P.verify(workspace, "PINNED_GO")
            self.assertEqual(marker.read_bytes(), b"preserve")

    def test_plans_execute_no_commands(self):
        with mock.patch.object(subprocess, "run", side_effect=AssertionError("unexpected execution")), \
                mock.patch.object(subprocess, "check_output", side_effect=AssertionError("unexpected execution")):
            self.assertEqual(P.plan("NEW_OWNED_WORKSPACE", "PINNED_GO")["source_blobs"], 487)


class FailedInitRecordingControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.document = json.loads((HERE / "testdata" / C.CORPUS).read_bytes())

    def altered(self, change):
        value = copy.deepcopy(self.document)
        change(value)
        raw = P.encoded(value)
        # Rebind only the recording checksum so the semantic check is reached.
        with mock.patch.object(C, "CORPUS_BYTES", len(raw)), mock.patch.object(
                C, "CORPUS_SHA256", hashlib.sha256(raw).hexdigest()), self.assertRaises((ValueError, TypeError, KeyError)):
            C.check_corpus(value)

    def bad_observation(self, change, case=None):
        case = P.CASES[0] if case is None else case
        row = next(row for row in self.document["streams"] if row["case"] == case)
        value = json.loads(row["jsonl"])
        change(value)
        raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        with self.assertRaises((ValueError, TypeError, KeyError)):
            C.observation(raw, case)

    def test_recorded_native_scope_stays_separate_from_portable_reader_execution(self):
        result = C.check_file()
        self.assertEqual((result["ordinary_builds"], result["ordinary_processes"]), (1, 2))
        self.assertEqual((result["race_builds"], result["race_processes"]), (0, 0))
        self.assertEqual(result["source_blobs"], 487)
        self.assertEqual(result["linked_modules"], 30)
        self.assertEqual(result["capture_platform"], "darwin/arm64")
        self.assertEqual(result["reader_reference_backend_executions"], 0)
        self.assertEqual(result["reader_downloads"], 0)
        self.assertEqual(result["consumer_result"], "REFUSED")
        self.assertFalse(result["production_state_value_accepted"])

    def test_both_real_streams_match_the_independently_selected_fault_contract(self):
        for row in self.document["streams"]:
            with self.subTest(case=row["case"]):
                result = C.observation(row["jsonl"].encode(), row["case"])["observation"]
                self.assertNotEqual(result["Init"]["error"], "none")
                self.assertEqual(result["Stop"], {"error": "none", "panic": False})
                self.assertFalse(result["after_Stop"]["ledger_open"])
                self.assertFalse(result["after_Stop"]["cache_open"])
                self.assertEqual(result["after_Stop"]["consensus"], "leveldb-closed")

    def test_a_successful_Init_cannot_replace_the_selected_failure(self):
        for case in P.CASES:
            self.bad_observation(lambda value: value["observation"]["Init"].update(error="none"), case)

    def test_failing_or_panicking_Stop_cannot_be_hidden(self):
        for change in (lambda value: value["observation"]["Stop"].update(error="other-error"),
                       lambda value: value["observation"]["Stop"].update(panic=True)):
            self.bad_observation(change)

    def test_each_same_handle_must_be_closed_after_Stop(self):
        for key, wrong in (("ledger_open", True), ("cache_open", True),
                           ("consensus", "none"), ("tree_ready", True)):
            with self.subTest(key=key):
                self.bad_observation(lambda value: value["observation"]["after_Stop"].update({key: wrong}))

    def test_all_three_existing_store_paths_must_reopen_successfully(self):
        for name in ("nom", "cache", "consensus"):
            with self.subTest(store=name):
                self.bad_observation(lambda value: value["observation"]["store_reopen"][name].update(error="other-error"))
        self.bad_observation(lambda value: value["observation"]["store_reopen"].pop("nom"))

    def test_original_fault_setup_and_pre_Init_handles_cannot_be_changed(self):
        self.bad_observation(lambda value: value["observation"]["fault_setup"].update(error="other-error"))
        self.bad_observation(lambda value: value["observation"]["before_Init"].update(ledger_open=True))
        self.bad_observation(lambda value: value["observation"]["after_Init"].update(cache_open=False))

    def test_fault_marker_must_retain_bytes_hash_and_identity(self):
        for key, wrong in (("before_sha256", "0" * 64), ("after_sha256", "0" * 64),
                           ("same_file", False), ("bytes_matched", False)):
            with self.subTest(key=key):
                self.bad_observation(lambda value: value["observation"]["marker"].update({key: wrong}), P.CASES[1])

    def test_second_Stop_and_unselected_teardown_cannot_be_substituted(self):
        self.bad_observation(lambda value: value["observation"]["second_Stop"].update(error="stop-incomplete"))
        self.bad_observation(lambda value: value["observation"].update(explicit_teardown=[]))

    def test_unknown_status_and_inexact_primitive_types_refuse(self):
        self.bad_observation(lambda value: value.update(status="UNKNOWN"))
        self.bad_observation(lambda value: value["observation"]["Stop"].update(panic=0))
        self.bad_observation(lambda value: value["observation"]["after_Stop"].update(ledger_open=0))
        self.bad_observation(lambda value: value["genesis"].update(height=True))
        self.bad_observation(lambda value: value["observation"].update(extra=False))

    def test_network_or_state_acceptance_cannot_be_promoted(self):
        for key in ("core_Start_selected", "network_or_wallet_or_signing_selected",
                    "accepted_header_binding", "production_state_value_accepted"):
            with self.subTest(key=key):
                self.bad_observation(lambda value: value.update({key: True}))
        self.altered(lambda value: value["scope"].update(full_node_or_network_qualified=True))
        self.altered(lambda value: value["scope"].update(independent_human_acceptance=True))

    def test_framing_duplicate_keys_nonfinite_and_truncation_refuse(self):
        raw = self.document["streams"][0]["jsonl"].encode()
        for item in (raw[:-1], raw + raw, b"x" * (C.MAX_STREAM + 1), b"\xff\n", raw.decode(),
                     raw.replace(b'"schema":', b'"schema":"duplicate","schema":', 1),
                     raw.replace(b'"height":1', b'"height":NaN')):
            with self.subTest(size=len(item)), self.assertRaises((ValueError, TypeError, KeyError)):
                C.observation(item, P.CASES[0])

    def test_fault_selection_must_come_from_the_caller(self):
        raw = self.document["streams"][0]["jsonl"].encode()
        for case in (None, True, "unselected", P.CASES[1]):
            with self.subTest(case=case), self.assertRaises((ValueError, TypeError, KeyError)):
                C.observation(raw, case)

    def test_command_actual_exit_and_completeness_are_required(self):
        for key, wrong in (("actual_exit", None), ("actual_exit", False), ("actual_exit", 1),
                           ("state", "RUNNING"), ("output_complete", 1),
                           ("output_complete", False), ("reason", "unknown")):
            with self.subTest(key=key):
                self.altered(lambda value: value["streams"][0]["command"].update({key: wrong}))

    def test_stream_bytes_and_binary_capture_cannot_be_detached(self):
        self.altered(lambda value: value["streams"][0].update(jsonl="{}\n"))
        self.altered(lambda value: value["binding"]["capture"]["stdout"].update(bytes=0))
        self.altered(lambda value: value["binding"]["binary"].update(sha256="0" * 64))

    def test_source_tree_probe_and_module_inputs_cannot_be_substituted(self):
        self.altered(lambda value: value["source"].update(runtime_tree="0" * 40))
        self.altered(lambda value: value["source"].update(build_tree="0" * 40))
        self.altered(lambda value: value["source"]["extras"][P.EXTRAS[0][0]].update(bytes=0))
        self.altered(lambda value: value["linked_module_inputs"][0].update(h1="h1:changed"))

    def test_missing_duplicate_or_reordered_cases_refuse(self):
        self.altered(lambda value: value["streams"].pop())
        self.altered(lambda value: value["streams"].append(copy.deepcopy(value["streams"][0])))
        self.altered(lambda value: value["streams"].reverse())

    def test_original_controller_failure_cannot_be_erased(self):
        self.assertEqual(C.check_file()["initial_controller_outcome"], "FAILURE")
        self.altered(lambda value: value["native"].update(initial_controller_outcome="SUCCESS"))
        self.altered(lambda value: value["native"].update(additional_native_executions=2))
        self.bad_observation(lambda value: value["observation"]["Init"].update(error="not-directory"), P.CASES[1])

    def test_cache_verification_and_build_scope_remain_bound(self):
        self.altered(lambda value: value["native"]["cache_verification"].update(actual_exit=1))
        self.altered(lambda value: value["native"].update(ordinary_processes=True))
        self.altered(lambda value: value["native"].update(race_builds=1))
        self.altered(lambda value: value["native"]["build_settings"].update(CGO_ENABLED="0"))
        self.altered(lambda value: value["native"].update(source_map_matches_actual_build=False))

    def test_reader_executes_no_backend_download_or_preparation(self):
        with mock.patch.object(subprocess, "run", side_effect=AssertionError("unexpected execution")), \
                mock.patch.object(subprocess, "check_output", side_effect=AssertionError("unexpected execution")), \
                mock.patch.object(P, "prepare", side_effect=AssertionError("unexpected preparation")):
            self.assertEqual(C.check_file()["reader_reference_backend_executions"], 0)

    def test_invalid_source_revision_refuses_without_output(self):
        with self.assertRaises(ValueError):
            C.main(["--source-revision", "not-a-revision"])


if __name__ == "__main__":
    unittest.main()
