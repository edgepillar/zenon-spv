#!/usr/bin/env python3
"""Controls for preselection and failure handling of the offline node workflow."""

import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock


spec = importlib.util.spec_from_file_location("node_workflow", Path(__file__).with_name("check-node-query-consumer.py"))
workflow = importlib.util.module_from_spec(spec)
spec.loader.exec_module(workflow)


class NodeWorkflowControls(unittest.TestCase):
    def test_preselected_context_and_schedule_golden_bytes(self):
        selected = workflow.programs()
        self.assertEqual([p["context"]["fingerprint"] for p in selected], [
            "6851c99ffa3fa2363c5c4030de96691de5966eb8b1c92d9d5c87870758d29989",
            "64585d9efc8c37a43cf750edb383dbd8c095b69e09ec9eec82ca4b148601c4f5",
            "0f15a4dec1f1b8e169618b9be38f306c5e08dba4631348d2a931532758dfec8d",
        ])
        self.assertEqual(selected[-1]["schedule"]["schedule_hash"],
                         "ff5891ffed9a1b1cca3f6e133e272abde8c8801cc2dc60cd688ad4546a956d1d")
        self.assertEqual([p["context"]["schema_version"] for p in selected], [1, 2, 2])
        self.assertEqual([len(p["bundle"]["commitments"]) for p in selected], [5, 5, 6])
        self.assertEqual(workflow.programs(), selected)

    def test_all_expectations_precede_process_execution(self):
        with mock.patch.object(workflow.subprocess, "run", side_effect=AssertionError("child before selection")):
            selected = workflow.programs()
        for p in selected:
            for (height, command), expected in p["expectations"].items():
                self.assertEqual(expected["context_fingerprint"], p["context"]["fingerprint"])
                self.assertEqual(expected["verification_tip"]["height"], height)
                self.assertEqual(expected["command"], command)
                self.assertTrue(workflow.oracle.valid_expectations(expected))
        self.assertEqual(len(selected[-1]["expectations"]), 8)

    def test_confirmation_is_not_account_acknowledgement(self):
        p = workflow.programs()[-1]
        refs = p["expectations"][(5017, "verify-commitment")]["targets"]
        self.assertEqual([r["momentum_height"] for r in refs], [5003, 5003, 5007, 5007, 5011, 5011])
        by_identity = {(r["account_header"]["address"], r["account_header"]["height"]): r["momentum_height"] for r in refs}
        for segment in p["bundle"]["segments"]:
            for block in segment["blocks"]:
                self.assertEqual(by_identity[(block["address"], block["height"])], block["momentumAcknowledged"]["height"] + 1)
        targets = p["expectations"][(5017, "verify-segment")]["targets"]
        self.assertEqual([(r["index"], r["block_index"]) for r in targets],
                         [(0, 0), (0, 1), (0, 2), (1, 0), (1, 1), (1, 2)])

    def test_fixture_mutation_refuses_before_any_child(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            dest = root / "internal/testdata/conformance"
            dest.mkdir(parents=True)
            for name in workflow.CORPUS_PINS:
                raw = (workflow.ROOT / "internal/testdata/conformance" / name).read_bytes()
                (dest / name).write_bytes(raw + b" ")
            with mock.patch.object(workflow, "ROOT", root), mock.patch.object(workflow.subprocess, "run") as run:
                with self.assertRaises(workflow.oracle.Invalid):
                    workflow.programs()
            run.assert_not_called()

    def test_schedule_change_changes_independent_context(self):
        corpus = copy.deepcopy(workflow.load_corpora()["delayed-inclusion.json"])
        original = workflow.select_program("fixed", corpus, retain=16, delayed=True)
        corpus["chain"]["vectors"][-1]["header"]["timestamp"] += 1
        changed = workflow.select_program("fixed", corpus, retain=16, delayed=True)
        self.assertNotEqual(original["schedule"]["schedule_hash"], changed["schedule"]["schedule_hash"])
        self.assertNotEqual(original["context"]["fingerprint"], changed["context"]["fingerprint"])
        self.assertEqual(original["expectations"][(5017, "verify-segment")]["targets"],
                         changed["expectations"][(5017, "verify-segment")]["targets"])

    def test_finite_case_selection_has_no_duplicates(self):
        ids = workflow.selected_case_ids()
        self.assertEqual(len(ids), 60)
        self.assertEqual(len(set(ids)), 60)
        for p in workflow.programs():
            for command in workflow.COMMANDS:
                prefix = p["id"] + "_" + command.removeprefix("verify-") + "_"
                self.assertTrue(all(prefix + v in ids for v in workflow.VARIANTS))

    def test_timeout_is_attempted_but_not_completed_and_private(self):
        runner = workflow.Runner(Path("PRIVATE_VERIFIER"), Path("PRIVATE_CONSUMER"))
        with mock.patch.object(workflow.subprocess, "run", side_effect=subprocess.TimeoutExpired("PRIVATE_COMMAND", 15)):
            with self.assertRaises(workflow.WorkflowFailure) as failed:
                runner.child("direct_legacy_commitment_actual", "verifier", [])
        self.assertEqual(runner.counts["verifier_attempted"], 1)
        self.assertEqual(runner.counts["verifier_completed"], 0)
        self.assertEqual(failed.exception.details["stage"], "child_run")
        self.assertNotIn("PRIVATE", json.dumps(failed.exception.details))

    def test_actual_nonzero_process_overrides_earlier_report(self):
        runner = workflow.Runner(Path("PRIVATE_VERIFIER"), Path("PRIVATE_CONSUMER"))
        expected = workflow.programs()[0]["expectations"][(4009, "verify-commitment")]
        wanted = workflow.oracle.summary("process_failure")
        raw = b'{"exit_code":0,"outcome":"ACCEPT","PRIVATE_REPORT":"PRIVATE_VALUE"}'
        completed = subprocess.CompletedProcess([], 2, wanted[1], b"")
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(workflow.subprocess, "run", return_value=completed) as run:
            runner.compare("direct_legacy_commitment_prior_report_failed_process", raw, expected, 70,
                           "process_failure", Path(directory))
        arguments = run.call_args[0][0]
        self.assertEqual(arguments[-2:], ["--verifier-exit-code", "70"])
        self.assertEqual(runner.rows[0]["process_exit"], 70)
        self.assertNotIn("PRIVATE", json.dumps(runner.rows))

    def test_completed_wrong_consumer_fails_without_success(self):
        runner = workflow.Runner(Path("PRIVATE_VERIFIER"), Path("PRIVATE_CONSUMER"))
        expected = workflow.programs()[0]["expectations"][(4009, "verify-commitment")]
        completed = subprocess.CompletedProcess([], 0, b"PRIVATE_UNEXPECTED_RESULT", b"")
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(workflow.subprocess, "run", return_value=completed):
            with self.assertRaises(workflow.WorkflowFailure) as failed:
                runner.compare("direct_legacy_commitment_pin_failure", b"PRIVATE_REPORT", expected, 70,
                               "process_failure", Path(directory))
        self.assertEqual(runner.counts["reference_checked"], 1)
        self.assertEqual(runner.counts["consumer_compared"], 1)
        self.assertEqual(runner.rows, [])
        self.assertEqual(failed.exception.details["stage"], "compiled_decision")
        self.assertNotIn("PRIVATE", json.dumps(failed.exception.details))

    def test_modified_input_fails_after_actual_comparison(self):
        runner = workflow.Runner(Path("PRIVATE_VERIFIER"), Path("PRIVATE_CONSUMER"))
        expected = workflow.programs()[0]["expectations"][(4009, "verify-commitment")]
        wanted = workflow.oracle.summary("process_failure")

        def child(arguments, **_):
            Path(arguments[2]).write_bytes(b"changed")
            return subprocess.CompletedProcess([], 2, wanted[1], b"")

        with tempfile.TemporaryDirectory() as directory, mock.patch.object(workflow.subprocess, "run", side_effect=child):
            with self.assertRaises(workflow.WorkflowFailure) as failed:
                runner.compare("direct_legacy_commitment_pin_failure", b"PRIVATE_REPORT", expected, 70,
                               "process_failure", Path(directory))
        self.assertEqual(failed.exception.details["stage"], "input_changed")
        self.assertEqual(runner.counts["consumer_compared"], 1)
        self.assertEqual(runner.rows, [])


if __name__ == "__main__":
    unittest.main()
