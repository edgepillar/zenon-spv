#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Independent lifecycle semantics and retained-capture controls; no backend."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("worker_stop_record_controls", HERE / "check_zenon_worker_stop.py")
C = importlib.util.module_from_spec(spec)
spec.loader.exec_module(C)
M = C.M

def stream(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()

class WorkerStopModelControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.document = json.loads((HERE / "testdata" / C.CORPUS).read_bytes())
        cls.raw = cls.document["variants"]["candidate"]["streams"][1]["jsonl"].encode()

    def changed(self, change):
        value = json.loads(self.raw)
        change(value)
        return stream(value)

    def refused(self, raw=None, variant="candidate", mode="init-stop"):
        with self.assertRaises((ValueError, TypeError, KeyError)):
            M.check(self.raw if raw is None else raw, variant, mode)

    def test_all_six_actual_streams_match_independent_expectations(self):
        for variant, body in self.document["variants"].items():
            for row in body["streams"]:
                result = M.check(row["jsonl"].encode(), variant, row["case"])
                self.assertIs(result["final_tree_ready"], False)
                self.assertEqual(result["consumer_result"], "REFUSED")

    def test_baseline_panic_and_downstream_cleanup_are_distinct(self):
        row = self.document["variants"]["baseline"]["streams"][1]
        result = M.check(row["jsonl"].encode(), "baseline", "init-stop")
        self.assertEqual(result["stop"]["panic"], "close of nil channel")
        self.assertTrue(result["after_stop"]["ready"])
        self.assertEqual(len(result["caller_teardown_after_observation"]), 5)
        self.assertFalse(result["final_tree_ready"])

    def test_candidate_prestart_Stop_has_no_caller_teardown(self):
        result = M.check(self.raw, "candidate", "init-stop")
        self.assertEqual(result["stop"], {"error": "", "panic": ""})
        self.assertEqual(result["caller_teardown_after_observation"], [])
        self.assertFalse(result["after_stop"]["ready"])

    def test_keyless_start_control_is_not_mislabeled_as_no_services(self):
        for variant in C.PREP.VARIANTS:
            raw = self.document["variants"][variant]["streams"][2]["jsonl"].encode()
            result = M.check(raw, variant, "reopen-start-stop")
            self.assertTrue(result["core_started"])
            self.assertTrue(result["before_stop"]["ready"])
            self.assertFalse(result["node_wrapper_created"])
            self.assertFalse(result["after_stop"]["ready"])

    def test_stop_error_or_panic_cannot_be_ignored(self):
        for key in ("error", "panic"):
            with self.subTest(key=key):
                self.refused(self.changed(lambda value: value["stop"].update({key: "unexpected"})))

    def test_expected_root_value_and_proof_do_not_come_from_child(self):
        for key in ("root", "value", "proof"):
            with self.subTest(key=key):
                self.refused(self.changed(lambda value: value["before_stop"].update({key: "00"})))

    def test_foreign_identifier_cannot_be_promoted_to_success(self):
        self.refused(self.changed(lambda value: value["before_stop"].update(foreign_error="none")))
        self.refused(self.changed(lambda value: value["before_stop"].update(foreign_root="11" * 32)))

    def test_post_stop_ready_or_value_is_refused(self):
        self.refused(self.changed(lambda value: value["after_stop"].update(ready=True)))
        self.refused(self.changed(lambda value: value["after_stop"].update(value="00")))

    def test_stopped_root_and_proof_errors_are_required(self):
        for key in ("root_error", "proof_error", "foreign_error"):
            with self.subTest(key=key):
                self.refused(self.changed(lambda value: value["after_stop"].update({key: "none"})))

    def test_unrequested_teardown_cannot_mask_candidate_failure(self):
        self.refused(self.changed(lambda value: value.update(caller_teardown_after_observation=[
            {"component": "chain", "error": "", "panic": ""}])))

    def test_baseline_teardown_outcome_cannot_be_lost(self):
        raw = self.document["variants"]["baseline"]["streams"][1]["jsonl"].encode()
        value = json.loads(raw)
        value["caller_teardown_after_observation"].pop()
        self.refused(stream(value), "baseline")

    def test_selection_genesis_and_patch_are_bound(self):
        for key, selected in (("selection_sha256", "00" * 32), ("genesis_patch_bytes", 0),
                              ("genesis_patch_sha256", "00" * 32), ("genesis_identifier", {"hash": "00" * 32, "height": 1})):
            with self.subTest(key=key):
                self.refused(self.changed(lambda value: value.update({key: selected})))

    def test_initialization_and_start_flags_are_bound(self):
        for key in ("initialized", "core_started", "final_tree_ready"):
            with self.subTest(key=key):
                self.refused(self.changed(lambda value: value.update({key: not value[key]})))

    def test_wallet_network_and_acceptance_scopes_cannot_be_promoted(self):
        for key in ("wallet_manager_created", "node_wrapper_created", "p2p_server_created",
                    "RPC_listener_started", "external_peer_configured", "producing_key_configured",
                    "production_state_value_accepted", "header_authentication_executed"):
            with self.subTest(key=key):
                self.refused(self.changed(lambda value: value.update({key: True})))
        self.refused(self.changed(lambda value: value.update(consumer_result="ACCEPT")))

    def test_exact_types_prevent_boolean_integer_aliases(self):
        self.refused(self.changed(lambda value: value.update(initialized=1)))
        self.refused(self.changed(lambda value: value["before_stop"].update(ready=1)))
        self.refused(self.changed(lambda value: value["genesis_identifier"].update(height=True)))

    def test_unknown_and_missing_fields_refused(self):
        self.refused(self.changed(lambda value: value.update(extra=False)))
        self.refused(self.changed(lambda value: value.pop("consumer_result")))

    def test_duplicate_JSON_key_refused(self):
        raw = self.raw.replace(b'"case":', b'"case":"init-stop","case":', 1)
        self.assertNotEqual(raw, self.raw)
        self.refused(raw)

    def test_extra_truncated_or_oversized_stream_refused(self):
        for raw in (self.raw + self.raw, self.raw[:-1], b"x" * (M.MAX_STREAM + 1), self.raw.decode()):
            with self.subTest(size=len(raw)):
                self.refused(raw)

    def test_nonfinite_and_invalid_UTF8_refused(self):
        self.refused(self.raw.replace(b'"genesis_patch_bytes":10849399', b'"genesis_patch_bytes":NaN'))
        self.refused(b"\xff\n")

    def test_variant_and_case_cannot_be_selected_by_observation(self):
        self.refused(variant="baseline")
        self.refused(mode="construct-stop")
        for selected in (None, True, 1, "other", []):
            with self.subTest(value=repr(selected)):
                self.refused(variant=selected)
                self.refused(mode=selected)

class WorkerStopRecordedControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.document = json.loads((HERE / "testdata" / C.CORPUS).read_bytes())

    def bad(self, change, repair_container_pin=False):
        value = copy.deepcopy(self.document)
        change(value)
        if repair_container_pin:
            raw = M.encoded(value)
            with mock.patch.object(C, "CORPUS_BYTES", len(raw)), mock.patch.object(
                    C, "CORPUS_SHA256", hashlib.sha256(raw).hexdigest()), self.assertRaises((ValueError, TypeError, KeyError)):
                C.check_corpus(value)
        else:
            with self.assertRaises((ValueError, TypeError, KeyError)):
                C.check_corpus(value)

    def test_exact_corpus_and_inventory_complete(self):
        result = C.check_file()
        self.assertEqual((result["observed_baseline_API_panics"], result["observed_candidate_API_panics"]), (2, 0))
        self.assertEqual((result["root_value_proof_observations"], result["successful_root_value_proof_observations"]), (12, 5))
        self.assertEqual((result["selected_native_root_tests"], result["selected_native_pass_results"]), (50, 59))
        self.assertFalse(result["reference_backend_reexecuted"])
        self.assertEqual(result["consumer_result"], "REFUSED")

    def test_interrupted_attempt_stays_unknown(self):
        self.assertIsNone(self.document["interrupted_attempt"]["actual_exit"])
        self.bad(lambda value: value["interrupted_attempt"].update(actual_exit=0), True)
        self.bad(lambda value: value["interrupted_attempt"].update(output_complete=True), True)

    def test_actual_command_exit_completeness_and_types_required(self):
        original = self.document["recorded_native"]["commands"]["selected_native_units"]
        for key, value in (("state", "RUNNING"), ("actual_exit", None), ("actual_exit", False),
                           ("actual_exit", 1), ("output_complete", False), ("output_complete", 1), ("reason", "stopped")):
            changed = dict(original, **{key: value})
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                C.command(changed)

    def test_output_pin_types_are_strict(self):
        for pin in ({"sha256": "ab" * 32, "bytes": True}, {"sha256": "AB" * 32, "bytes": 1},
                    {"sha256": "ab" * 32, "bytes": -1}, {"sha256": "ab" * 32, "bytes": 1, "extra": 0}):
            with self.subTest(pin=pin), self.assertRaises(ValueError):
                C.pin(pin)

    def test_source_trees_and_instrumentation_remain_bound(self):
        self.bad(lambda value: value["source"].update(candidate_runtime_tree="00" * 20), True)
        self.bad(lambda value: value["source"]["build_trees"].update(candidate="00" * 20), True)
        self.bad(lambda value: value["source"]["model"].update(sha256="00" * 32), True)

    def test_native_inventory_cannot_drop_or_promote_passes(self):
        self.bad(lambda value: value["recorded_native"]["native_unit_passes"].pop(), True)
        self.bad(lambda value: value["recorded_native"].update(native_unit_pass_results=True), True)
        self.bad(lambda value: value["recorded_native"].update(platform="linux/amd64"), True)

    def test_wrong_binary_is_refused_after_repinning_container(self):
        self.bad(lambda value: value["variants"]["candidate"]["binary"].update(sha256="00" * 32), True)

    def test_stream_semantics_refused_even_after_repairing_hashes(self):
        def change(value):
            row = value["variants"]["candidate"]["streams"][1]
            report = json.loads(row["jsonl"])
            report["before_stop"]["proof"] = "00"
            row["jsonl"] = stream(report).decode()
            row["command"]["stdout"] = {"bytes": len(row["jsonl"]),
                "sha256": hashlib.sha256(row["jsonl"].encode()).hexdigest()}
        self.bad(change, True)

    def test_missing_extra_or_reordered_cases_refused(self):
        self.bad(lambda value: value["variants"]["candidate"]["streams"].pop(), True)
        self.bad(lambda value: value["variants"]["candidate"]["streams"].reverse(), True)

    def test_consensus_and_distribution_are_not_inferred(self):
        for key in ("consensus_validity_qualified", "full_node_recovery_qualified",
                    "private_capture_or_distribution_authenticated", "production_state_value_accepted"):
            with self.subTest(key=key):
                self.bad(lambda value: value["scope"].update({key: True}), True)

    def test_unselected_corpus_bytes_refused(self):
        self.bad(lambda value: value.update(extra=False))
        self.bad(lambda value: value["recorded_native"].update(ordinary_builds=3))

    def test_actual_CLI_success_and_bad_source_revision(self):
        argv = [sys.executable, "-I", "-B", str(HERE / "check_zenon_worker_stop.py")]
        success = subprocess.run(argv + ["--source-revision", "ab" * 20], capture_output=True, timeout=30)
        self.assertEqual(success.returncode, 0, success.stderr.decode())
        result = json.loads(success.stdout)
        self.assertEqual(result["source_revision"], "ab" * 20)
        self.assertEqual(result["unknown_interrupted_attempts"], 1)
        refused = subprocess.run(argv + ["--source-revision", "invalid"], capture_output=True, timeout=30)
        self.assertEqual(refused.returncode, 1)
        self.assertEqual(refused.stdout, b"")

    def test_actual_CLI_refuses_changed_file_without_partial_report(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "changed.json"
            path.write_text("{}\n")
            result = subprocess.run([sys.executable, "-I", "-B", str(HERE / "check_zenon_worker_stop.py"),
                                     "--file", str(path)], capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, b"")

if __name__ == "__main__":
    unittest.main(verbosity=2)
