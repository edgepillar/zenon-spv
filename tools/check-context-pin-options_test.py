#!/usr/bin/env python3
"""Controls for finite compiled pin checks and private failure evidence."""

import importlib.util
import json
from pathlib import Path
import subprocess
import unittest
from unittest import mock


spec = importlib.util.spec_from_file_location("pin_options", Path(__file__).with_name("check-context-pin-options.py"))
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)


class ContextPinOptionControls(unittest.TestCase):
    def result(self, report=None, code=64, stderr=b""):
        if report is None:
            report = {"schema_version": 1, "command": "verify-commitment", "exit_code": 64,
                      "error": {"stage": "arguments", "category": "usage"}, "verification_context": None,
                      "state_trust": [], "outcome": None, "verification_tip": None, "results": []}
        return subprocess.CompletedProcess([], code, json.dumps(report).encode(), stderr)

    def test_selected_contexts_and_finite_inventory(self):
        programs = check.selected_programs()
        self.assertEqual([p["context"]["schema_version"] for p in programs], [1, 2])
        self.assertEqual([p["id"] for p in programs], ["direct_legacy", "delayed_retained"])
        self.assertEqual(len(check.selected_ids(programs)), 210)
        self.assertTrue(all(p["context"]["fingerprint"] == check.node.oracle.context_fingerprint(p["context"]) for p in programs))

    def test_usage_refusal_has_no_proof_or_context(self):
        self.assertTrue(check.report_matches(self.result(), "verify-commitment", 64, stage="arguments"))

    def test_watch_pin_probe_has_one_selected_poisoned_anchor(self):
        config = ["--json", "--genesis-config", "PRIVATE_SELECTED", "--state", "PRIVATE_STATE"]
        original = list(config)
        options = ["--expect-context", "PRIVATE_FIRST_PIN", "--expect-context", "PRIVATE_LAST_PIN"]
        for command in ("watch", "watch-once"):
            runner = mock.Mock()
            runner.child.return_value = subprocess.CompletedProcess([], 64, b"", check.DUPLICATE_ERROR)
            check.duplicate(runner, "case", command, config, options, "PRIVATE_QUERY", "PRIVATE_MISSING")
            args = runner.child.call_args.args[1]
            self.assertEqual(args.count("--genesis-config"), 1)
            self.assertEqual(args[args.index("--genesis-config") + 1], "PRIVATE_MISSING")
            self.assertEqual(args.count("--expect-context"), 2)
            self.assertEqual(args.count("--rpc"), 1)
            self.assertEqual(args.count("--once"), int(command == "watch-once"))
            runner.check.assert_called_once_with("case", True)
            self.assertEqual(config, original)

    def test_actual_exit_cannot_be_replaced_by_diagnostic(self):
        self.assertFalse(check.report_matches(self.result(code=0), "verify-commitment", 64, stage="arguments"))

    def test_proof_outcome_cannot_accompany_usage_refusal(self):
        report = json.loads(self.result().stdout)
        report["outcome"] = "ACCEPT"
        self.assertFalse(check.report_matches(self.result(report), "verify-commitment", 64, stage="arguments"))

    def test_context_cannot_accompany_usage_refusal(self):
        report = json.loads(self.result().stdout)
        report["verification_context"] = {}
        self.assertFalse(check.report_matches(self.result(report), "verify-commitment", 64, stage="arguments"))

    def test_truth_value_is_not_a_schema_integer(self):
        report = json.loads(self.result().stdout)
        report["schema_version"] = True
        self.assertFalse(check.report_matches(self.result(report), "verify-commitment", 64, stage="arguments"))

    def test_duplicate_fields_are_refused(self):
        result = self.result()
        result.stdout = result.stdout[:-1] + b',"exit_code":64}'
        self.assertFalse(check.report_matches(result, "verify-commitment", 64, stage="arguments"))

    def test_trailing_report_is_refused(self):
        result = self.result()
        result.stdout += result.stdout
        self.assertFalse(check.report_matches(result, "verify-commitment", 64, stage="arguments"))

    def test_private_diagnostics_are_refused(self):
        self.assertFalse(check.report_matches(self.result(stderr=b"PRIVATE_PIN"), "verify-commitment", 64, stage="arguments"))

    def test_inspection_refusal_uses_retained_window_and_no_context(self):
        report = json.loads(self.result().stdout)
        report.update(command="inspect-state", status="error", retained_window=None, persistence="read_only")
        self.assertTrue(check.report_matches(self.result(report), "inspect-state", 64, stage="arguments"))
        report["retained_window"] = {}
        self.assertFalse(check.report_matches(self.result(report), "inspect-state", 64, stage="arguments"))

    def test_real_exit_and_stream_hashes_precede_failed_decision(self):
        runner = check.Runner(Path("PRIVATE_BINARY"), ["case"])
        with mock.patch.object(check.subprocess, "run", return_value=self.result(code=70, stderr=b"PRIVATE_PIN")):
            result = runner.child("case", ["PRIVATE_ARGUMENT"])
        with self.assertRaises(check.Failure) as caught:
            runner.check("case", check.report_matches(result, "verify-commitment", 64, stage="arguments"))
        details = caught.exception.details
        self.assertEqual(details["counts"]["completed"], 1)
        self.assertEqual(details["counts"]["matched"], 0)
        self.assertEqual(details["process_outcomes"][0]["actual_exit"], 70)
        self.assertEqual(details["process_outcomes"][0]["stderr_sha256"], check.sha(b"PRIVATE_PIN"))
        self.assertNotIn("PRIVATE", json.dumps(details))

    def test_failed_spawn_is_attempted_without_invented_exit(self):
        runner = check.Runner(Path("PRIVATE_BINARY"), ["case"])
        with mock.patch.object(check.subprocess, "run", side_effect=OSError("PRIVATE_REASON")), self.assertRaises(check.Failure) as caught:
            runner.child("case", [])
        self.assertEqual(caught.exception.details["counts"]["attempted"], 1)
        self.assertEqual(caught.exception.details["counts"]["completed"], 0)
        self.assertIsNone(caught.exception.details["process_outcomes"][0]["actual_exit"])
        self.assertNotIn("PRIVATE", json.dumps(caught.exception.details))

    def test_timeout_is_preserved_without_retry_or_invented_exit(self):
        runner = check.Runner(Path("PRIVATE_BINARY"), ["case"])
        with mock.patch.object(check.subprocess, "run", side_effect=subprocess.TimeoutExpired("PRIVATE_BINARY", 15, output=b"PRIVATE_PARTIAL", stderr=b"PRIVATE_ERROR")), self.assertRaises(check.Failure) as caught:
            runner.child("case", [])
        self.assertEqual(caught.exception.details["counts"]["retries"], 0)
        self.assertIsNone(caught.exception.details["process_outcomes"][0]["actual_exit"])
        self.assertEqual(caught.exception.details["process_outcomes"][0]["stdout_sha256"], check.sha(b"PRIVATE_PARTIAL"))
        self.assertNotIn("PRIVATE", json.dumps(caught.exception.details))


if __name__ == "__main__":
    unittest.main()
