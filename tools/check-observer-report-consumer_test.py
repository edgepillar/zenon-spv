#!/usr/bin/env python3
"""Controls for preselection, joined fixture lifetime and qualification failures."""

import copy
from http.client import HTTPConnection
import importlib.util
import json
from pathlib import Path
import subprocess
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
        self.assertNotIn("PRIVATE", str(failed.exception))

    def test_completed_private_stderr_is_not_promoted(self):
        runner = workflow.Runner({"observe-block": Path("PRIVATE_EXECUTABLE")})
        result = subprocess.CompletedProcess([], 0, b"{}", b"PRIVATE_PATH")
        with mock.patch.object(workflow.subprocess, "run", return_value=result):
            with self.assertRaises(workflow.Failure) as failed:
                runner.child("observer", [])
        self.assertEqual(failed.exception.stage, "private_child_output")
        self.assertEqual(runner.counts["observer_completed"], 1)

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
