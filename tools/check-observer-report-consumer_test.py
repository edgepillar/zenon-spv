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
