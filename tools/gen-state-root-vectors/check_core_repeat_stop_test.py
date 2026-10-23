#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Finite source, retained-output and refusal controls; no reference backend."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("core_repeat_stop_controls", HERE / "check_core_repeat_stop.py")
C = importlib.util.module_from_spec(spec)
spec.loader.exec_module(C)
P, M = C.PREP, C.M

def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()

class RepeatedStopControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.document = json.loads((HERE / "testdata" / C.CORPUS).read_bytes())

    def altered(self, change):
        value = copy.deepcopy(self.document)
        change(value)
        raw = M.encoded(value)
        # Repair only the outer container pin to exercise semantic checks.
        with mock.patch.object(C, "CORPUS_BYTES", len(raw)), mock.patch.object(
                C, "CORPUS_SHA256", hashlib.sha256(raw).hexdigest()), self.assertRaises((ValueError, TypeError, KeyError)):
            C.check_corpus(value)

    def model_bad(self, change, variant="candidate", mode="both-closed"):
        row = next(row for row in self.document["variants"][variant]["streams"] if row["case"] == mode)
        value = json.loads(row["jsonl"])
        change(value)
        with self.assertRaises((ValueError, TypeError, KeyError)):
            M.check(encoded(value), variant, mode)

    def test_complete_record_has_expected_native_and_refusal_scope(self):
        report = C.check_file()
        self.assertEqual((report["baseline_repeated_Stop_panics"], report["candidate_repeated_Stop_panics"]), (3, 0))
        self.assertEqual((report["native_root_tests"], report["native_pass_results"]), (58, 71))
        self.assertEqual((report["race_root_tests"], report["race_pass_results"]), (5, 9))
        self.assertEqual(report["native_test_skips"], 0)
        self.assertFalse(report["reference_backend_reexecuted"])
        self.assertFalse(report["production_state_value_accepted"])
        self.assertEqual(report["consumer_result"], "REFUSED")

    def test_every_actual_stream_matches_independent_model(self):
        for variant, body in self.document["variants"].items():
            for row in body["streams"]:
                with self.subTest(variant=variant, case=row["case"]):
                    report = M.check(row["jsonl"].encode(), variant, row["case"])
                    self.assertFalse(report["after_repeated_stop"]["ready"])
                    self.assertEqual(report["final_consensus_status"], "closed")

    def test_candidate_preserves_first_call_result_fields(self):
        for row in self.document["variants"]["candidate"]["streams"]:
            report = M.check(row["jsonl"].encode(), "candidate", row["case"])
            self.assertEqual(report["stop"], report["repeated_stop"])
            self.assertFalse(report["repeated_stop"]["panic"])

    def test_error_or_panic_cannot_be_erased_or_invented(self):
        for field in ("stop", "repeated_stop"):
            for name, value in (("error", ""), ("panic", "unexpected"), ("closed_error", False), ("leaf_classes", [])):
                with self.subTest(field=field, name=name):
                    self.model_bad(lambda v: v[field].update({name: value}))

    def test_second_close_error_cannot_be_lost(self):
        self.model_bad(lambda v: v["repeated_stop"].update(error="leveldb: closed", leaf_classes=["leveldb-closed"]))

    def test_parent_channel_panic_origin_is_required(self):
        for value in ("", "pillar.(*worker).Stop", "zenon.(*zenon).Stop", "protocol.(*ProtocolManager).Stop"):
            with self.subTest(value=value):
                self.model_bad(lambda v: v["repeated_stop"].update(panic_stack=value), "baseline")
        self.model_bad(lambda v: v["repeated_stop"].update(panic=""), "baseline")

    def test_expected_root_value_proof_and_foreign_refusal_are_not_from_child(self):
        for name in ("root", "value", "proof", "foreign_root", "foreign_error"):
            with self.subTest(name=name):
                self.model_bad(lambda v: v["before_stop"].update({name: "unexpected"}))

    def test_after_stop_and_repeat_must_remain_not_ready(self):
        for stage in ("after_stop", "after_repeated_stop"):
            for name, value in (("ready", True), ("root_error", "none"), ("proof_error", "none"), ("value", "01")):
                with self.subTest(stage=stage, name=name):
                    self.model_bad(lambda v: v[stage].update({name: value}))

    def test_privilege_and_state_acceptance_flags_cannot_be_promoted(self):
        for name in ("wallet_manager_created", "core_started", "node_wrapper_created", "p2p_server_created",
                     "RPC_listener_started", "external_peer_configured", "producing_key_configured",
                     "production_state_value_accepted", "header_authentication_executed"):
            with self.subTest(name=name):
                self.model_bad(lambda v: v.update({name: True}))
        self.model_bad(lambda v: v.update(consumer_result="ACCEPT"))

    def test_exact_types_and_complete_fields_are_required(self):
        self.model_bad(lambda v: v.update(initialized=1))
        self.model_bad(lambda v: v["after_repeated_stop"].update(ready=0))
        self.model_bad(lambda v: v["genesis_identifier"].update(height=True))
        self.model_bad(lambda v: v.update(extra=False))
        self.model_bad(lambda v: v.pop("repeated_stop"))

    def test_truncated_duplicate_or_oversized_json_is_refused(self):
        raw = self.document["variants"]["candidate"]["streams"][0]["jsonl"].encode()
        bad = (raw[:-1], raw + raw, b"x" * (M.MAX_STREAM + 1), raw.decode(), b"\xff\n",
               raw.replace(b'"case":', b'"case":"healthy","case":', 1),
               raw.replace(b'"genesis_patch_bytes":10849399', b'"genesis_patch_bytes":NaN'))
        for value in bad:
            with self.subTest(size=len(value)), self.assertRaises((ValueError, TypeError, KeyError)):
                M.check(value, "candidate", "healthy")

    def test_case_and_variant_selection_are_external_to_observation(self):
        raw = self.document["variants"]["baseline"]["streams"][0]["jsonl"].encode()
        for variant, mode in (("candidate", "healthy"), ("baseline", "cache-closed"), (True, "healthy"),
                              ("baseline", []), ("unknown", "healthy"), (None, "healthy")):
            with self.subTest(variant=variant, mode=mode), self.assertRaises((ValueError, TypeError, KeyError)):
                M.check(raw, variant, mode)

    def test_command_completion_and_exact_types_are_required(self):
        original = self.document["native"]["race"]["command"]
        for name, value in (("actual_exit", None), ("actual_exit", False), ("actual_exit", 1),
                            ("state", "RUNNING"), ("reason", "unknown"), ("output_complete", 1), ("output_complete", False)):
            changed = dict(original, **{name: value})
            with self.subTest(name=name), self.assertRaises((ValueError, TypeError, KeyError)):
                C.command(changed)

    def test_native_output_cannot_be_detached_from_command_pin(self):
        self.altered(lambda v: v["native"]["regressions"].update(jsonl="{}\n"))
        self.altered(lambda v: v["native"]["race"]["command"]["stdout"].update(bytes=0))

    def test_missing_native_pass_is_rejected_even_with_repaired_stream_digest(self):
        def change(value):
            recording = value["native"]["regressions"]
            events = [json.loads(line) for line in recording["jsonl"].splitlines()]
            index = next(i for i, event in enumerate(events) if event.get("Action") == "pass" and "Test" in event)
            events.pop(index)
            raw = b"".join(encoded(event) for event in events)
            recording["jsonl"] = raw.decode()
            recording["command"]["stdout"] = {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}
        self.altered(change)

    def test_native_skip_is_not_a_pass(self):
        def change(value):
            recording = value["native"]["race"]
            events = [json.loads(line) for line in recording["jsonl"].splitlines()]
            next(event for event in events if event.get("Action") == "pass" and "Test" in event)["Action"] = "skip"
            raw = b"".join(encoded(event) for event in events)
            recording["jsonl"] = raw.decode()
            recording["command"]["stdout"] = {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}
        self.altered(change)

    def test_container_digest_scope_and_source_trees_are_bound(self):
        changed = copy.deepcopy(self.document)
        changed["scope"]["full_node_or_network_qualified"] = True
        with self.assertRaises(ValueError):
            C.check_corpus(changed)
        for name in ("full_node_or_network_qualified", "concurrent_Init_Start_Stop_qualified",
                     "profile_agreement", "network_activation_authenticated", "accepted_header_binding",
                     "production_state_value_accepted", "distribution_authenticated"):
            with self.subTest(name=name):
                self.altered(lambda v: v["scope"].update({name: True}))
        self.altered(lambda v: v["source"]["runtime_trees"].update(candidate="0" * 40))

    def test_source_recipe_preserves_preceding_runtime_and_only_changes_core_Stop_file(self):
        baseline = P.selection("baseline")[2]
        candidate = P.selection("candidate")[2]
        self.assertEqual(set(baseline), set(candidate))
        self.assertEqual(len(candidate), 471)
        self.assertEqual([name for name in baseline if baseline[name] != candidate[name]], ["zenon/zenon.go"])
        self.assertEqual(P.P.UTIL.reconstruct_tree(baseline), P.PARENT_TREE)
        self.assertEqual(P.P.UTIL.reconstruct_tree(candidate), P.CANDIDATE_TREE)

    def test_other_runtime_method_bodies_are_unchanged(self):
        change = P.patch()
        def methods(raw):
            return {match.group(1): match.group(0).rstrip() for match in
                    re.finditer(r"(?ms)^func ([^\n]+)\n.*?(?=^func |\Z)", raw)}
        before, after = methods(change["before"]), methods(change["after"])
        self.assertEqual(set(before), set(after))
        for name in before:
            if not name.startswith("(z *zenon) Stop()"):
                with self.subTest(method=name):
                    self.assertEqual(before[name], after[name])

    def test_source_views_and_test_inventory_match_recorded_source(self):
        self.assertEqual((len(P.build_pins("baseline")), len(P.build_pins("candidate"))), (480, 482))
        self.assertEqual((len(P.roots()), len(P.new_roots()), len(C.new_passes())), (58, 5, 9))
        self.assertEqual(P.selected_input(), P.BASE.selected_input())

    def test_finite_plan_retains_resource_floor_and_never_launches_backend(self):
        with mock.patch.object(subprocess, "run", side_effect=AssertionError("unexpected backend launch")), mock.patch.object(
                subprocess, "check_output", side_effect=AssertionError("unexpected backend launch")):
            result = P.plan("owned-workspace", "selected-go")
        self.assertEqual((result["minimum_free_floor_bytes"], result["expected_allocation_bytes"],
                          result["suggested_task_quota_bytes"]), (10 << 30, 2 << 30, 3 << 30))
        self.assertIn("-mod=readonly", result["build_argv"])
        self.assertIn("-race", result["native_race_argv"])
        self.assertEqual(result["native_race_timeout_seconds"], 600)
        self.assertEqual(len(result["run_argv_templates"]), 3)
        self.assertIs(result["expected_values_not_supplied_to_child"], True)
        self.assertFalse(result["production_state_value_accepted"])
        self.assertFalse(result["new_dependency_transports_permitted"])
        self.assertEqual(result["consumer_result"], "REFUSED")

    def test_wrong_variants_and_go_arguments_are_refused(self):
        for value in (None, True, 1, [], "unknown"):
            with self.subTest(value=value), self.assertRaises((ValueError, TypeError, KeyError)):
                P.selection(value)
        for value in (None, True, 1, "", "go\x00bad"):
            with self.subTest(value=value), self.assertRaises((ValueError, TypeError, KeyError)):
                P.plan("owned-workspace", value)

if __name__ == "__main__":
    unittest.main()
