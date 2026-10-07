#!/usr/bin/env python3
"""Controls for preselection and failure handling of the offline node workflow."""

import copy
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
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

    def test_completed_output_refusal_retains_exit_and_byte_hashes(self):
        runner = workflow.Runner(Path("PRIVATE_VERIFIER"), Path("PRIVATE_CONSUMER"))
        result = subprocess.CompletedProcess([], 70, b"PRIVATE_STDOUT", b"PRIVATE_STDERR")
        with mock.patch.object(workflow.subprocess, "run", return_value=result):
            with self.assertRaises(workflow.WorkflowFailure) as failed:
                runner.child("direct_legacy_seed_9", "verifier", ["PRIVATE_ARGUMENT"])
        details = failed.exception.details
        self.assertEqual(details["stage"], "child_output")
        self.assertEqual(details["comparison_counts"]["verifier_completed"], 1)
        self.assertEqual(details["process_outcomes"], [{
            "case_id": "direct_legacy_seed_9", "role": "verifier", "completed": True,
            "actual_exit": 70, "stdout_bytes": 14, "stderr_bytes": 14,
            "stdout_sha256": workflow.sha(result.stdout), "stderr_sha256": workflow.sha(result.stderr),
        }])
        self.assertNotIn("PRIVATE", json.dumps(details))

    def test_incomplete_process_ledger_has_no_completed_exit_or_partial_bytes(self):
        errors = [OSError("PRIVATE_ERROR"), subprocess.TimeoutExpired("PRIVATE_COMMAND", 15,
                  output=b"PRIVATE_PARTIAL", stderr=b"PRIVATE_PARTIAL"), subprocess.SubprocessError("PRIVATE_ERROR")]
        for error in errors:
            with self.subTest(error=type(error).__name__):
                runner = workflow.Runner(Path("PRIVATE_VERIFIER"), Path("PRIVATE_CONSUMER"))
                with mock.patch.object(workflow.subprocess, "run", side_effect=error):
                    with self.assertRaises(workflow.WorkflowFailure) as failed:
                        runner.child("direct_legacy_commitment_actual", "consumer", [])
                details = failed.exception.details
                self.assertEqual(details["comparison_counts"]["consumer_attempted"], 1)
                self.assertEqual(details["comparison_counts"]["consumer_compared"], 0)
                self.assertEqual(details["process_outcomes"], [{"case_id": "direct_legacy_commitment_actual",
                                 "role": "consumer", "completed": False, "actual_exit": None}])
                self.assertNotIn("PRIVATE", json.dumps(details))

    def test_malformed_seed_keeps_completed_verifier_evidence(self):
        runner = workflow.Runner(Path("PRIVATE_VERIFIER"), Path("PRIVATE_CONSUMER"))
        result = subprocess.CompletedProcess([], 0, b'{"PRIVATE_REPORT":', b"")
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(workflow.subprocess, "run", return_value=result):
            with self.assertRaises(workflow.WorkflowFailure) as failed:
                runner.program(workflow.programs()[0], Path(directory) / "program")
        self.assertEqual(failed.exception.details["stage"], "seed_diagnostic")
        self.assertEqual(failed.exception.details["comparison_counts"]["verifier_completed"], 1)
        self.assertEqual(failed.exception.details["process_outcomes"][0]["stdout_sha256"], workflow.sha(result.stdout))
        self.assertNotIn("PRIVATE", json.dumps(failed.exception.details))

    def test_query_shape_failure_keeps_both_completed_verifiers(self):
        for raw in (b"null", b"[]", b'"PRIVATE_VALUE"', b"{}", b"{", b"[" * 1100):
            with self.subTest(raw_sha256=workflow.sha(raw)):
                runner = workflow.Runner(Path("PRIVATE_VERIFIER"), Path("PRIVATE_CONSUMER"))
                calls = []
                def child(arguments, **_):
                    calls.append(arguments)
                    if len(calls) == 1:
                        Path(arguments[arguments.index("--state") + 1]).write_bytes(b"state")
                        return subprocess.CompletedProcess([], 0, b'{"outcome":"ACCEPT","exit_code":0}', b"")
                    return subprocess.CompletedProcess([], 0, raw, b"")
                with tempfile.TemporaryDirectory() as directory, mock.patch.object(workflow.subprocess, "run", side_effect=child):
                    with self.assertRaises(workflow.WorkflowFailure) as failed:
                        runner.program(workflow.programs()[0], Path(directory) / "program")
                details = failed.exception.details
                self.assertIn(details["stage"], ("query_diagnostic", "input_or_shape"))
                self.assertEqual(details["comparison_counts"]["verifier_completed"], 2)
                self.assertEqual(len(details["process_outcomes"]), 2)
                self.assertEqual(details["process_outcomes"][-1]["stdout_sha256"], workflow.sha(raw))
                self.assertNotIn("PRIVATE", json.dumps(details))

    def test_deleted_consumer_input_keeps_completed_consumer_evidence(self):
        runner = workflow.Runner(Path("PRIVATE_VERIFIER"), Path("PRIVATE_CONSUMER"))
        expected = workflow.programs()[0]["expectations"][(4009, "verify-commitment")]
        wanted = workflow.oracle.summary("process_failure")
        def child(arguments, **_):
            Path(arguments[2]).unlink()
            return subprocess.CompletedProcess([], 2, wanted[1], b"")
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(workflow.subprocess, "run", side_effect=child):
            with self.assertRaises(workflow.WorkflowFailure) as failed:
                runner.compare("direct_legacy_commitment_pin_failure", b"PRIVATE_REPORT", expected, 70,
                               "process_failure", Path(directory))
        details = failed.exception.details
        self.assertEqual(details["stage"], "input_or_shape")
        self.assertEqual(details["comparison_counts"]["consumer_compared"], 1)
        self.assertEqual(details["process_outcomes"][0]["actual_exit"], 2)
        self.assertEqual(runner.rows, [])
        self.assertNotIn("PRIVATE", json.dumps(details))

    def test_input_permission_failure_precedes_consumer_attempt(self):
        runner = workflow.Runner(Path("PRIVATE_VERIFIER"), Path("PRIVATE_CONSUMER"))
        expected = workflow.programs()[0]["expectations"][(4009, "verify-commitment")]
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(Path, "chmod", side_effect=PermissionError("PRIVATE_MODE")), \
                mock.patch.object(workflow.subprocess, "run") as run:
            with self.assertRaises(workflow.WorkflowFailure) as failed:
                runner.compare("direct_legacy_commitment_pin_failure", b"PRIVATE_REPORT", expected, 70,
                               "process_failure", Path(directory))
        run.assert_not_called()
        self.assertEqual(failed.exception.details["comparison_counts"]["reference_checked"], 1)
        self.assertEqual(failed.exception.details["comparison_counts"]["consumer_attempted"], 0)
        self.assertEqual(failed.exception.details["process_outcomes"], [])

    def compare_fault(self, program, cleanup_error=None, creation_error=None):
        with tempfile.TemporaryDirectory() as directory:
            verifier, consumer = Path(directory) / "verifier", Path(directory) / "consumer"
            verifier.write_bytes(b"verifier"); consumer.write_bytes(b"consumer")
            runner = workflow.Runner(verifier, consumer)
            class Temporary:
                name = directory
                def __enter__(self): return self.name
                def __exit__(self, *_): self.cleanup()
                def cleanup(self):
                    if cleanup_error is not None:
                        raise cleanup_error
            factory = mock.Mock(side_effect=creation_error, return_value=Temporary())
            with mock.patch.object(workflow, "Runner", return_value=runner), \
                    mock.patch.object(type(runner), "program", program), \
                    mock.patch.object(workflow.tempfile, "TemporaryDirectory", factory), \
                    mock.patch.object(workflow.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, b"{}", b"")):
                try:
                    workflow.compare(verifier, consumer, "0" * 40)
                except BaseException as error:
                    return error, runner, factory
            self.fail("fault did not interrupt qualification")

    def test_final_fixture_read_keeps_completed_process_evidence(self):
        def program(runner, selected, _):
            if runner.rows: return
            runner.child("direct_legacy_seed_9", "verifier", [])
            runner.rows = [{"id": case} for case in workflow.selected_case_ids()]
        original = Path.read_bytes
        reads = []
        def read(path):
            if path.name == "contract-batches.json":
                reads.append(path)
                if len(reads) == 2: raise OSError("PRIVATE_PIN_READ")
            return original(path)
        with mock.patch.object(Path, "read_bytes", read):
            error, runner, _ = self.compare_fault(program)
        self.assertIsInstance(error, workflow.WorkflowFailure)
        self.assertEqual(error.details["comparison_counts"]["verifier_completed"], 1)
        self.assertEqual(len(error.details["process_outcomes"]), 1)
        self.assertEqual(error.details["stage"], "input_or_shape")
        self.assertNotIn("PRIVATE", json.dumps(error.details))

    def test_cleanup_failure_after_completed_process_has_structured_counts(self):
        def program(runner, selected, _):
            if not runner.counts["verifier_attempted"]:
                runner.child("direct_legacy_seed_9", "verifier", [])
        error, runner, _ = self.compare_fault(program, cleanup_error=PermissionError("PRIVATE_CLEANUP"))
        self.assertIsInstance(error, workflow.WorkflowFailure)
        self.assertEqual(error.details["stage"], "temporary_cleanup")
        self.assertEqual(error.details["comparison_counts"]["verifier_completed"], 1)
        self.assertEqual(error.details["process_outcomes"][0]["actual_exit"], 0)
        self.assertEqual(error.details["cleanup_failures"], [])

    def test_cleanup_cannot_mask_primary_refusal_or_change_snapshot(self):
        def program(runner, selected, _):
            runner.child("direct_legacy_seed_9", "verifier", [])
            runner.require("direct_legacy_seed_9", "seed_diagnostic", False)
        error, runner, _ = self.compare_fault(program, cleanup_error=OSError("PRIVATE_CLEANUP"))
        self.assertIsInstance(error, workflow.WorkflowFailure)
        self.assertEqual(error.details["case_id"], "direct_legacy_seed_9")
        self.assertEqual(error.details["stage"], "seed_diagnostic")
        self.assertEqual(error.details["cleanup_failures"], ["temporary_cleanup"])
        runner.counts["verifier_completed"] = 99
        runner.process_outcomes[0]["actual_exit"] = 99
        self.assertEqual(error.details["comparison_counts"]["verifier_completed"], 1)
        self.assertEqual(error.details["process_outcomes"][0]["actual_exit"], 0)
        self.assertNotIn("PRIVATE", json.dumps(error.details))

    def test_cleanup_preserves_cancellation_and_unexpected_programming_error(self):
        for original in (KeyboardInterrupt(), RuntimeError("PRIVATE_PROGRAMMING_ERROR")):
            with self.subTest(error=type(original).__name__):
                def program(runner, selected, _): raise original
                error, _, _ = self.compare_fault(program, cleanup_error=OSError("PRIVATE_CLEANUP"))
                self.assertIs(error, original)

    def test_temporary_creation_failure_has_zero_attempts(self):
        error, runner, factory = self.compare_fault(mock.Mock(), creation_error=PermissionError("PRIVATE_SETUP"))
        self.assertIsInstance(error, workflow.WorkflowFailure)
        self.assertEqual(error.details["comparison_counts"]["verifier_attempted"], 0)
        self.assertEqual(error.details["process_outcomes"], [])
        factory.assert_called_once()

    def test_cli_emits_only_structured_failure_after_completed_process(self):
        stderr = io.StringIO()
        def compare(verifier, consumer, revision):
            runner = workflow.Runner(verifier, consumer)
            with runner.boundary("direct_legacy_seed_9"):
                runner.child("direct_legacy_seed_9", "verifier", [])
                raise OSError("PRIVATE_LATE_IO")
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "PRIVATE_BINARY"; binary.write_bytes(b"fixed")
            arguments = ["checker", "--verifier", str(binary), "--consumer", str(binary), "--source-revision", "0" * 40]
            with mock.patch.object(sys, "argv", arguments), mock.patch.object(workflow, "compare", compare), \
                    mock.patch.object(workflow.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, b"PRIVATE_STDOUT", b"")), \
                    contextlib.redirect_stderr(stderr):
                with self.assertRaises(SystemExit) as failed: workflow.main()
        self.assertEqual(failed.exception.code, 1)
        details = json.loads(stderr.getvalue())
        self.assertEqual(details["status"], "node_consumer_comparison_failed")
        self.assertEqual(details["comparison_counts"]["verifier_completed"], 1)
        self.assertEqual(details["process_outcomes"][0]["stdout_sha256"], workflow.sha(b"PRIVATE_STDOUT"))
        self.assertNotIn("PRIVATE", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
