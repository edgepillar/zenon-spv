#!/usr/bin/env python3
"""Controls for preselection, joined fixture lifetime and qualification failures."""

import copy
import contextlib
from http.client import HTTPConnection
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


spec = importlib.util.spec_from_file_location("observer_workflow", Path(__file__).with_name("check-observer-report-consumer.py"))
workflow = importlib.util.module_from_spec(spec)
spec.loader.exec_module(workflow)


class ObserverWorkflowControls(unittest.TestCase):
    def test_expected_identities_and_context_precede_processes(self):
        with mock.patch.object(workflow.subprocess, "run", side_effect=AssertionError("child before selection")):
            program, corpus, expectations = workflow.selected_inputs()
        self.assertEqual(program["context"]["fingerprint"], "0f15a4dec1f1b8e169618b9be38f306c5e08dba4631348d2a931532758dfec8d")
        self.assertEqual([len(expectations[c]["targets"]) for c in workflow.COMMANDS], [6, 6])
        self.assertEqual([expectations[c]["verification_tip"]["height"] for c in workflow.COMMANDS], [5017, 5017])
        self.assertTrue(all(workflow.node.oracle.valid_expectations(value) for value in expectations.values()))

    def test_pinned_corpus_mutation_refuses_before_children(self):
        with mock.patch.object(workflow.node, "load_corpora", side_effect=workflow.node.oracle.Invalid("PRIVATE_PATH")), mock.patch.object(workflow.subprocess, "run") as run:
            with self.assertRaises(workflow.node.oracle.Invalid):
                workflow.selected_inputs()
        run.assert_not_called()

    def test_timeout_preserves_attempted_but_not_completed(self):
        runner = workflow.Runner({"zenon-spv": Path("PRIVATE_EXECUTABLE")})
        with mock.patch.object(workflow.subprocess, "run", side_effect=subprocess.TimeoutExpired("PRIVATE_COMMAND", 30)):
            with self.assertRaises(workflow.Failure) as failed:
                runner.child("seed", [])
        self.assertEqual(failed.exception.stage, "child_completion")
        self.assertEqual(failed.exception.counts["seed_attempted"], 1)
        self.assertEqual(failed.exception.counts["seed_completed"], 0)
        self.assertEqual(failed.exception.outcomes, [{"role": "seed", "completed": False, "actual_exit": None}])
        self.assertNotIn("PRIVATE", str(failed.exception))

    def test_completed_private_stderr_is_not_promoted(self):
        runner = workflow.Runner({"observe-block": Path("PRIVATE_EXECUTABLE")})
        result = subprocess.CompletedProcess([], 0, b"{}", b"PRIVATE_PATH")
        with mock.patch.object(workflow.subprocess, "run", return_value=result):
            with self.assertRaises(workflow.Failure) as failed:
                runner.child("observer", [])
        self.assertEqual(failed.exception.stage, "private_child_output")
        self.assertEqual(runner.counts["observer_completed"], 1)
        self.assertEqual(failed.exception.outcomes[0]["actual_exit"], 0)
        self.assertEqual(failed.exception.outcomes[0]["stderr_sha256"], workflow.sha(b"PRIVATE_PATH"))

    def test_later_failure_preserves_prior_completed_outcomes(self):
        runner = workflow.Runner({"observe-block": Path("PRIVATE_EXECUTABLE")})
        result = subprocess.CompletedProcess([], 2, b"{}", b"")
        with mock.patch.object(workflow.subprocess, "run", return_value=result):
            runner.child("observer", [])
        with self.assertRaises(workflow.Failure) as failed:
            workflow.require(False, "later_boundary", runner.counts)
        self.assertEqual(len(failed.exception.outcomes), 1)
        self.assertEqual(failed.exception.outcomes[0]["actual_exit"], 2)
        self.assertEqual(failed.exception.outcomes[0]["stdout_sha256"], workflow.sha(b"{}"))
        self.assertNotIn("PRIVATE", json.dumps(failed.exception.outcomes))

    def test_bad_completed_seed_output_retains_main_failure_ledger(self):
        cases = (b'{"outcome":', b"PRIVATE malformed output", b"\xff", b"[]", b"null", b"true", b"0",
                 b"{}", b'{"outcome":"ACCEPT"}', b'{"exit_code":0}',
                 b'{"outcome":"ACCEPT","exit_code":false}', b'{"outcome":"ACCEPT","exit_code":0.0}',
                 b'{"outcome":"ACCEPT","exit_code":"0"}', b'{"outcome":"ACCEPT","exit_code":1}',
                 b'{"outcome":"REFUSE","exit_code":0}')
        with tempfile.TemporaryDirectory(prefix="observer-ledger-control-") as directory:
            binary = Path(directory) / "PRIVATE_INERT_BINARY"
            binary.write_bytes(b"fixed inert bytes; no executable is launched")
            arguments = ["qualification", "--source-revision", "1" * 40]
            for name in ("observer", "verifier", "consumer", "collector"):
                arguments.extend(["--" + name, str(binary)])
            for raw in cases:
                with self.subTest(raw_sha256=workflow.sha(raw)):
                    result = subprocess.CompletedProcess([], 0, raw, b"")
                    output = io.StringIO()
                    with mock.patch.object(sys, "argv", arguments), mock.patch.object(workflow.subprocess, "run", return_value=result) as run, mock.patch.object(workflow, "Fixture") as fixture, contextlib.redirect_stdout(output):
                        code = workflow.main()
                    self.assertEqual(code, 2)
                    self.assertEqual(run.call_count, 1)
                    fixture.assert_not_called()
                    failure = json.loads(output.getvalue())
                    self.assertEqual(failure["stage"], "seed_report")
                    self.assertEqual(failure["process_counts"], {role + "_" + state: (1 if role == "seed" else 0)
                        for role in ("seed", "observer", "reader") for state in ("attempted", "completed")})
                    self.assertEqual(failure["process_outcomes"], [{"role": "seed", "completed": True, "actual_exit": 0,
                        "stdout_sha256": workflow.sha(raw), "stderr_sha256": workflow.sha(b""),
                        "stdout_bytes": len(raw), "stderr_bytes": 0}])
                    self.assertNotIn("PRIVATE", output.getvalue())
                    self.assertIs(failure["network_pilot"], False)

    def test_completed_reader_decode_failure_retains_prior_outcomes(self):
        for raw in (b'{"schema_version":', b"PRIVATE malformed summary", b"\xff", b"[" * 1000):
            with self.subTest(raw_sha256=workflow.sha(raw)):
                runner = workflow.Runner({"zenon-spv": Path("PRIVATE_EXECUTABLE")})
                seed = subprocess.CompletedProcess([], 0, b'{"outcome":"ACCEPT","exit_code":0}', b"")
                reader = subprocess.CompletedProcess([], 2, raw, b"")
                with mock.patch.object(workflow.subprocess, "run", side_effect=[seed, reader]):
                    first = runner.child("seed", [])
                    self.assertEqual(runner.document(first, "seed_report")["exit_code"], 0)
                    second = runner.child("reader", [])
                    with self.assertRaises(workflow.Failure) as failed:
                        runner.document(second, "reader_summary")
                self.assertEqual(failed.exception.stage, "reader_summary")
                self.assertEqual(len(failed.exception.outcomes), 2)
                self.assertEqual([row["actual_exit"] for row in failed.exception.outcomes], [0, 2])
                self.assertEqual(failed.exception.counts["seed_completed"], 1)
                self.assertEqual(failed.exception.counts["reader_completed"], 1)
                self.assertEqual(failed.exception.outcomes[1]["stdout_sha256"], workflow.sha(raw))
                runner.counts.events.clear()
                self.assertEqual(len(failed.exception.outcomes), 2)
                self.assertNotIn("PRIVATE", str(failed.exception))

    def test_missing_state_after_completed_seed_retains_main_ledger(self):
        with tempfile.TemporaryDirectory(prefix="observer-io-control-") as directory:
            binary = Path(directory) / "PRIVATE_INERT_BINARY"
            binary.write_bytes(b"fixed inert bytes; no executable is launched")
            arguments = ["qualification", "--source-revision", "1" * 40]
            for name in ("observer", "verifier", "consumer", "collector"):
                arguments.extend(["--" + name, str(binary)])
            raw = b'{"outcome":"ACCEPT","exit_code":0}'
            output = io.StringIO()
            with mock.patch.object(sys, "argv", arguments), mock.patch.object(workflow.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, raw, b"")) as run, mock.patch.object(workflow, "Fixture") as fixture, contextlib.redirect_stdout(output):
                code = workflow.main()
            failure = json.loads(output.getvalue())
            self.assertEqual(code, 2)
            self.assertEqual(run.call_count, 1)
            fixture.assert_not_called()
            self.assertEqual(failure["stage"], "input_or_shape")
            self.assertEqual(failure["cleanup_failures"], [])
            self.assertEqual(failure["process_counts"]["seed_completed"], 1)
            self.assertEqual(failure["process_outcomes"][0]["stdout_sha256"], workflow.sha(raw))
            self.assertEqual(failure["process_outcomes"][0]["actual_exit"], 0)
            self.assertNotIn("PRIVATE", output.getvalue())
            self.assertIs(failure["network_pilot"], False)

    def test_known_failure_boundary_retains_empty_or_completed_ledger(self):
        for error_type in (OSError, ValueError, KeyError, TypeError, RecursionError, workflow.node.oracle.Invalid):
            for completed in (False, True):
                with self.subTest(error_type=error_type.__name__, completed=completed):
                    runner = workflow.Runner({"zenon-spv": Path("PRIVATE_EXECUTABLE")})
                    if completed:
                        with mock.patch.object(workflow.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, b"{}", b"")):
                            runner.child("seed", [])
                    with self.assertRaises(workflow.Failure) as failed:
                        with runner.boundary():
                            raise error_type("PRIVATE failure detail")
                    self.assertEqual(failed.exception.stage, "input_or_shape")
                    self.assertEqual(failed.exception.counts["seed_completed"], int(completed))
                    self.assertEqual(len(failed.exception.outcomes), int(completed))
                    runner.counts.events.clear()
                    self.assertEqual(len(failed.exception.outcomes), int(completed))
                    self.assertNotIn("PRIVATE", str(failed.exception))

    def test_cleanup_failure_alone_refuses_with_completed_ledger(self):
        for error_type in (None, OSError, ValueError, KeyError, TypeError, RecursionError, workflow.node.oracle.Invalid):
            with self.subTest(error_type=error_type.__name__ if error_type else "false_result"):
                runner = workflow.Runner({"zenon-spv": Path("PRIVATE_EXECUTABLE")})
                with mock.patch.object(workflow.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, b"{}", b"")):
                    runner.child("seed", [])
                close = mock.Mock(return_value=False, side_effect=error_type("PRIVATE cleanup detail") if error_type else None)
                with self.assertRaises(workflow.Failure) as failed:
                    with runner.cleanup(close, "fixture_completion"):
                        pass
                close.assert_called_once_with()
                self.assertEqual(failed.exception.stage, "fixture_completion")
                self.assertEqual(failed.exception.cleanup_failures, [])
                self.assertEqual(failed.exception.outcomes[0]["actual_exit"], 0)
                self.assertEqual(failed.exception.counts["seed_completed"], 1)
                self.assertNotIn("PRIVATE", str(failed.exception))

    def test_cleanup_keeps_primary_failure_and_records_secondary_stages(self):
        for error_type in (None, OSError, ValueError, KeyError, TypeError, RecursionError, workflow.node.oracle.Invalid):
            with self.subTest(error_type=error_type.__name__ if error_type else "false_result"):
                runner = workflow.Runner({"observe-block": Path("PRIVATE_EXECUTABLE")})
                with mock.patch.object(workflow.subprocess, "run", return_value=subprocess.CompletedProcess([], 2, b"{}", b"")):
                    runner.child("observer", [])
                primary = workflow.Failure("reader_summary", runner.counts)
                close = mock.Mock(return_value=False, side_effect=error_type("PRIVATE cleanup detail") if error_type else None)
                with self.assertRaises(workflow.Failure) as failed:
                    with runner.cleanup(lambda: False, "temporary_cleanup"):
                        with runner.cleanup(close, "fixture_completion"):
                            raise primary
                close.assert_called_once_with()
                self.assertIs(failed.exception, primary)
                self.assertEqual(primary.stage, "reader_summary")
                self.assertEqual(primary.cleanup_failures, ["fixture_completion", "temporary_cleanup"])
                self.assertEqual(primary.outcomes[0]["actual_exit"], 2)
                runner.counts.events.clear()
                self.assertEqual(len(primary.outcomes), 1)
                self.assertNotIn("PRIVATE", str(primary))

    def test_cleanup_does_not_replace_cancellation_or_unexpected_exception(self):
        for error_type in (KeyboardInterrupt, RuntimeError, AssertionError):
            for close_raises in (False, True):
                with self.subTest(error_type=error_type.__name__, close_raises=close_raises):
                    runner = workflow.Runner({})
                    primary = error_type("PRIVATE original detail")
                    close = mock.Mock(return_value=False, side_effect=OSError("PRIVATE cleanup detail") if close_raises else None)
                    with self.assertRaises(error_type) as failed:
                        with runner.cleanup(close, "fixture_completion"):
                            raise primary
                    self.assertIs(failed.exception, primary)
                    close.assert_called_once_with()

    def test_temporary_cleanup_failure_retains_primary_or_refuses_alone(self):
        for primary_stage in (None, "seed_report"):
            with self.subTest(primary_stage=primary_stage):
                runner = workflow.Runner({"zenon-spv": Path("PRIVATE_EXECUTABLE")})
                with mock.patch.object(workflow.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, b"{}", b"")):
                    runner.child("seed", [])
                temporary = mock.Mock(name="private_directory")
                temporary.name = "PRIVATE_DIRECTORY"
                temporary.cleanup.side_effect = OSError("PRIVATE cleanup detail")
                with mock.patch.object(workflow.tempfile, "TemporaryDirectory", return_value=temporary), self.assertRaises(workflow.Failure) as failed:
                    with runner.directory() as directory:
                        self.assertEqual(directory, temporary.name)
                        if primary_stage:
                            raise workflow.Failure(primary_stage, runner.counts)
                temporary.cleanup.assert_called_once_with()
                self.assertEqual(failed.exception.stage, primary_stage or "temporary_cleanup")
                self.assertEqual(failed.exception.cleanup_failures, ["temporary_cleanup"] if primary_stage else [])
                self.assertEqual(failed.exception.counts["seed_completed"], 1)
                self.assertEqual(failed.exception.outcomes[0]["actual_exit"], 0)
                self.assertNotIn("PRIVATE", str(failed.exception))

    def test_io_failures_after_completed_work_retain_main_ledger(self):
        # Inert processes isolate bookkeeping failures. Actual four-binary
        # interoperability and the reader's decisions are qualified separately.
        for point in ("staging", "fixture", "state", "binary", "reader", "checker", "node_selector"):
            with self.subTest(point=point), tempfile.TemporaryDirectory(prefix="observer-io-control-") as directory:
                binary = Path(directory) / "PRIVATE_INERT_BINARY"
                binary.write_bytes(b"fixed inert bytes; no executable is launched")
                arguments = ["qualification", "--source-revision", "1" * 40]
                for name in ("observer", "verifier", "consumer", "collector"):
                    arguments.extend(["--" + name, str(binary)])
                fixture = mock.Mock()
                fixture.requests = {"ledger.getMomentumsByHeight": 0, "ledger.getAccountBlocksByHeight": 0}
                fixture.unexpected, fixture.url = 0, "http://PRIVATE_UNCONTACTED_FIXTURE"
                fixture.settled.return_value = fixture.close.return_value = True
                outcomes, states = [], []
                read_bytes, mkdir = Path.read_bytes, Path.mkdir

                def execute(command, **options):
                    if "--observer-exit-code" in command:
                        role = "reader"
                        try:
                            report = json.loads(options["input"])
                            match = (command[command.index("--observer-exit-code") + 1] == "0" and
                                     command[command.index("--expected-targets") + 1] == "6" and
                                     command[command.index("--mode") + 1] == report["mode"] and report["exit"] == 0)
                        except ValueError:
                            match = False
                        code = 0 if match else 2
                        raw = workflow.encoded({"schema_version": 1, "status": "matched" if match else "not_matched",
                                                "category": None if match else "report_mismatch", "checked_targets": 6 if match else 0})
                    elif "verify-headers" in command:
                        role, code, raw = "seed", 0, b'{"outcome":"ACCEPT","exit_code":0}'
                        state = Path(command[command.index("--state") + 1])
                        state.write_bytes(b"inert selected state bytes")
                        states.append(state)
                    else:
                        role = "observer"
                        mode = "collected" if "--collector" in command else "local-file"
                        expected_path = command[command.index("--expectations") + 1]
                        pin = command[command.index("--expect-context") + 1]
                        code = 2 if "wrong-target" in expected_path or pin != "0f15a4dec1f1b8e169618b9be38f306c5e08dba4631348d2a931532758dfec8d" else 0
                        raw = workflow.encoded({"mode": mode, "exit": code})
                        if mode == "collected":
                            fixture.requests["ledger.getMomentumsByHeight"] += 1
                            if "verify-segment" in command:
                                fixture.requests["ledger.getAccountBlocksByHeight"] += 2
                    outcomes.append({"role": role, "completed": True, "actual_exit": code,
                                     "stdout_sha256": workflow.sha(raw), "stderr_sha256": workflow.sha(b""),
                                     "stdout_bytes": len(raw), "stderr_bytes": 0})
                    return subprocess.CompletedProcess([], code, raw, b"")

                def read(path):
                    late_paths = {"binary": binary.resolve(), "reader": workflow.READER, "checker": Path(workflow.__file__), "node_selector": workflow.NODE_PATH}
                    if ((point == "state" and path.name == "state.json" and len(outcomes) == 2) or
                            (len(outcomes) == 49 and point in late_paths and path == late_paths[point])):
                        raise OSError("PRIVATE read detail")
                    return read_bytes(path)

                def make_directory(path, *args, **options):
                    if point == "staging" and path.name == "staging":
                        raise OSError("PRIVATE mkdir detail")
                    return mkdir(path, *args, **options)

                output = io.StringIO()
                with mock.patch.object(sys, "argv", arguments), mock.patch.object(workflow.subprocess, "run", side_effect=execute) as run, mock.patch.object(workflow, "Fixture", return_value=fixture, side_effect=OSError("PRIVATE fixture detail") if point == "fixture" else None), mock.patch.object(Path, "read_bytes", read), mock.patch.object(Path, "mkdir", make_directory), contextlib.redirect_stdout(output):
                    code = workflow.main()
                failure = json.loads(output.getvalue())
                self.assertEqual(code, 2)
                self.assertEqual(run.call_count, 1 if point in ("staging", "fixture") else 2 if point == "state" else 49)
                self.assertEqual(failure["stage"], "input_or_shape")
                self.assertEqual(failure["cleanup_failures"], [])
                self.assertEqual(failure["process_outcomes"], outcomes)
                self.assertEqual(failure["process_counts"], {role + "_" + state: sum(row["role"] == role for row in outcomes)
                    for role in ("seed", "observer", "reader") for state in ("attempted", "completed")})
                self.assertTrue(states and all(not state.parent.exists() for state in states))
                if point in ("staging", "fixture"):
                    fixture.close.assert_not_called()
                else:
                    fixture.close.assert_called_once_with()
                self.assertNotIn("PRIVATE", output.getvalue())
                self.assertIs(failure["network_pilot"], False)

    def test_runtime_inherited_endpoints_and_proxies_are_excluded(self):
        with mock.patch.dict(workflow.os.environ, {"ZENON_SPV_RPC": "PRIVATE_ENDPOINT", "HTTP_PROXY": "PRIVATE_PROXY", "https_proxy": "PRIVATE_PROXY"}):
            runner = workflow.Runner({})
        self.assertTrue(all(not key.startswith("ZENON_SPV_") and key.upper() not in {"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"} for key in runner.environment))

    def test_fixture_returns_unmodified_node_values_and_joins(self):
        _, corpus, _ = workflow.selected_inputs()
        before = copy.deepcopy(corpus)
        fixture = workflow.Fixture(corpus)
        try:
            connection = HTTPConnection("127.0.0.1", fixture.server.server_address[1], timeout=5)
            body = workflow.encoded({"jsonrpc": "2.0", "id": 1, "method": "ledger.getMomentumsByHeight", "params": [5017, 1]})
            connection.request("POST", "/", body=body, headers={"Content-Type": "application/json"})
            response = connection.getresponse()
            self.assertEqual(response.status, 200)
            self.assertEqual(json.loads(response.read())["result"]["list"], [corpus["chain"]["vectors"][16]["momentum"]])
            connection.close()
            self.assertTrue(fixture.settled())
            self.assertEqual(fixture.unexpected, 0)
        finally:
            self.assertTrue(fixture.close())
        self.assertEqual(corpus, before)

    def test_unselected_frontier_is_recorded_and_never_supplied(self):
        _, corpus, _ = workflow.selected_inputs()
        fixture = workflow.Fixture(corpus)
        try:
            connection = HTTPConnection("127.0.0.1", fixture.server.server_address[1], timeout=5)
            connection.request("POST", "/", body=workflow.encoded({"jsonrpc": "2.0", "id": 1, "method": "ledger.getFrontierMomentum", "params": []}))
            response = connection.getresponse()
            self.assertEqual(response.status, 400)
            response.read(); connection.close()
            self.assertTrue(fixture.settled())
            self.assertEqual(fixture.unexpected, 1)
            self.assertEqual(sum(fixture.requests.values()), 0)
        finally:
            self.assertTrue(fixture.close())


if __name__ == "__main__":
    unittest.main(verbosity=2)
