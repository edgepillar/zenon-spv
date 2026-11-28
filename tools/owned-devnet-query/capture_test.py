# SPDX-License-Identifier: GPL-3.0-only
"""Synthetic headers, process closure and isolated loopback transport controls."""
from __future__ import annotations

import base64
from copy import deepcopy
import hashlib
import io
import json
import os
from pathlib import Path
import socket
import struct
import sys
import tempfile
import threading
import unittest
from unittest import mock
import zipfile

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import capture
import closed_reader
import model
from process import CommandFailed, Recorder, capture as capture_process
import query_checks
from query_checks_test import OPENING_BATCH_KEY, opening_absence_fixture, opening_present_fixture
import review
import runner

CONTRACT = model.read_contract(HERE / "contract.json")


def consumer_failure_fixture(code=2, stage="query", category="required_row_absent", **changes):
    report = {"schema_version": 1, "command": "query-experimental-batch-context",
        "scope": "EXPERIMENTAL_CONFIGURED_HEADER_THREE_ROW_MEMBERSHIP",
        "status": "refused" if code == 2 else "rejected", "exit_code": code,
        "error": {"stage": stage, "category": category},
        "headers": {"outcome": "ACCEPT", "reason": "ReasonOK", "failed_at": -1},
        "header_context": None, "query_context": None, "result": None, "gateway_comparison": None,
        "persistence": "read_only", "rpc_requests": 0, "production_state_value_guarantee": False,
        "gateway_comparison_requested": True, "caveats": capture.CONSUMER_CAVEATS}
    report.update(changes)
    return model.canonical(report)


def review_exported(root, index, execution, contract=CONTRACT):
    packed = io.BytesIO()
    with zipfile.ZipFile(packed, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for entry in index["files"]:
            archive.writestr(entry["path"], (root / entry["path"]).read_bytes())
        archive.writestr(review.INDEX, model.canonical(index))
    packed.seek(0)
    raw = packed.getvalue()
    return review.review_stream(packed,
        {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()},
        execution.source_revision, execution.run_id, contract, HERE.parents[1])


class ConsumerFailureTests(unittest.TestCase):
    def test_selected_failure_types_have_exact_exit_and_header_diagnostics(self):
        for code, stage, category, headers in (
                (1, "headers", "not_accepted", {"outcome": "REJECT", "reason": "ReasonInvalidSignature", "failed_at": 0}),
                (2, "headers", "not_accepted", {"outcome": "REFUSED", "reason": "ReasonProtocolProfileCoverage", "failed_at": -1}),
                (2, "witness", "unavailable", None), (2, "gateway", "unavailable", None)):
            with self.subTest(code=code, stage=stage):
                report = capture.consumer_failure(consumer_failure_fixture(code, stage, category, headers=headers), code)
                self.assertEqual(report, {"actual_exit": code, "error": {"stage": stage, "category": category},
                                          "headers": headers})

    def test_incomplete_or_unrecognized_report_is_not_exportable(self):
        receipt = {"actual_exit": 2, "label": "consume-query", "launch_outcome": "STARTED",
                   "output_complete": True, "process_group_quiescent": True, "reason": None}
        for updates, changes in (({"output_complete": False}, {}), ({"actual_exit": 70}, {}),
                ({"launch_outcome": "UNKNOWN"}, {}), ({"process_group_quiescent": False}, {}),
                ({"reason": "timeout"}, {}), ({}, {"result": {"value": "private"}}),
                ({}, {"caveats": ["private"]}), ({}, {"extra": "private"}),
                ({}, {"headers": {"outcome": "ACCEPT", "reason": "private", "failed_at": -1}}),
                ({}, {"exit_code": 1}), ({}, {"error": {"stage": "query", "category": "private"}})):
            with self.subTest(receipt=updates, fields=sorted(changes)):
                result = mock.Mock(receipt={**receipt, **updates}, stdout_name=capture.CONSUMER_STDOUT,
                                   stdout=mock.Mock(return_value=consumer_failure_fixture(**changes)))
                self.assertFalse(capture.retainable_consumer_failure(result))
                if updates:
                    result.stdout.assert_not_called()


class StartupSyncTests(unittest.TestCase):
    def setUp(self):
        self.payloads = {}
        self.recorder = mock.Mock(names=set())
        self.guard = mock.Mock()
        self.raw = model.canonical({"jsonrpc": "2.0", "id": 1,
            "result": {"state": 3, "currentHeight": 1, "targetHeight": 0}})

        def seal(name, raw):
            self.assertNotIn(name, self.payloads)
            self.payloads[name] = raw
            self.recorder.names.add(name)

        def transport(label, argv, cwd, environment, **options):
            self.recorder.names.add(options["stdout_name"])
            self.payloads[options["stdout_name"]] = self.raw
            return mock.Mock(stdout=lambda cap: self.raw)

        self.recorder.seal.side_effect = seal
        self.recorder.run.side_effect = transport
        self.rpc = capture.LocalRpc(CONTRACT, self.recorder, Path("unused"),
                                    "unused-curl", {}, self.guard)

    def summary(self):
        return json.loads(self.payloads[capture.SYNC_REPORT])

    def test_sync_dto_accepts_three_bounded_integer_fields(self):
        for state in range(4):
            with self.subTest(state=state):
                self.assertEqual(capture.sync_info({"state": state, "currentHeight": 1, "targetHeight": 0}),
                    {"state": state, "current_height": 1, "target_height": 0})
        self.assertEqual(capture.sync_info({"state": 2, "currentHeight": (1 << 64) - 1,
                                         "targetHeight": (1 << 64) - 1})["target_height"], (1 << 64) - 1)

    def test_sync_dto_refuses_unknown_fields_and_coerced_or_unbounded_integers(self):
        original = {"state": 3, "currentHeight": 1, "targetHeight": 0}
        bad = [[], {}, {**original, "private": "unselected"}]
        for field, values in (("state", (-1, 4, True, "3")),
                              ("currentHeight", (0, -1, True, "1", 1 << 64)),
                              ("targetHeight", (-1, True, "0", 1 << 64))):
            bad.extend({**original, field: value} for value in values)
        for row in bad:
            with self.subTest(row=row), self.assertRaises(model.Refused):
                capture.sync_info(row)

    def test_one_fixed_request_preserves_original_bytes_and_cannot_be_repeated(self):
        self.rpc.capture_startup_sync()
        argv = self.recorder.run.call_args.args[1]
        options = self.recorder.run.call_args.kwargs
        self.assertEqual(json.loads(argv[argv.index("--data-binary") + 1]),
            {"jsonrpc": "2.0", "id": 1, "method": "stats.syncInfo", "params": []})
        self.assertEqual(argv[-1], capture.RPC_URL)
        self.assertEqual((options["timeout"], options["stdout_cap"], options["stderr_cap"]), (7, 8192, 4096))
        self.assertEqual(self.payloads["rpc-01.sync-info.json"], self.raw)
        self.assertEqual(self.summary()["status"], "OBSERVED")
        self.assertFalse(self.summary()["accepted_header_authority"])
        self.assertEqual(runner.startup_sync_evidence_files(self.rpc),
            {capture.SYNC_REPORT, "rpc-01.request.json", "rpc-01.sync-info.json"})
        before = dict(self.payloads)
        with self.assertRaisesRegex(model.Refused, "startup_sync_already_attempted"):
            self.rpc.capture_startup_sync()
        self.assertEqual(self.recorder.run.call_count, 1)
        self.assertEqual(self.payloads, before)

    def test_final_shared_call_slot_is_used_without_reset(self):
        self.rpc.calls = 95
        self.raw = self.raw.replace(b'"id": 1', b'"id": 96')
        self.rpc.capture_startup_sync()
        self.assertEqual(self.rpc.calls, 96)
        self.assertEqual(self.summary()["request_id"], 96)
        self.assertIn("rpc-96.request.json", runner.startup_sync_evidence_files(self.rpc))

    def test_exhausted_shared_limit_and_budget_refusal_launch_no_command(self):
        for exhausted in (True, False):
            with self.subTest(exhausted=exhausted):
                self.setUp()
                if exhausted:
                    self.rpc.calls = 96
                else:
                    self.guard.side_effect = model.Refused("unit_budget_refusal")
                self.rpc.capture_startup_sync()
                self.recorder.run.assert_not_called()
                self.assertEqual(self.summary()["status"], "NOT_ATTEMPTED")
                self.assertEqual(self.summary()["reason"], "shared_call_limit" if exhausted else "budget_refused")
                self.assertIsNone(self.summary()["request_id"])
                self.assertEqual(runner.startup_sync_evidence_files(self.rpc), {capture.SYNC_REPORT})

    def test_failed_incomplete_and_interrupted_commands_keep_honest_status(self):
        for actual_exit, complete, reason, status in ((7, True, None, "FAILURE"),
                (0, False, "timeout", "UNKNOWN"), (None, False, "launch_failed", "UNKNOWN"),
                (-15, False, "interrupted", "UNKNOWN")):
            with self.subTest(actual_exit=actual_exit, reason=reason):
                self.setUp()
                receipt = {"actual_exit": actual_exit, "output_complete": complete, "reason": reason}
                self.recorder.run.side_effect = CommandFailed(mock.Mock(receipt=receipt))
                if reason == "interrupted":
                    with self.assertRaises(KeyboardInterrupt):
                        self.rpc.capture_startup_sync()
                else:
                    self.rpc.capture_startup_sync()
                self.assertEqual(self.summary()["status"], status)
                self.assertIsNone(self.summary()["response_file"])
                self.assertEqual(runner.startup_sync_evidence_files(self.rpc),
                                 {capture.SYNC_REPORT, "rpc-01.request.json"})

    def test_invalid_identity_fields_or_oversize_body_are_not_exported(self):
        for raw in (b"{", self.raw.replace(b'"id": 1', b'"id": 2'),
                    self.raw.replace(b'"targetHeight": 0', b'"targetHeight": true'),
                    model.canonical({"jsonrpc": "2.0", "id": 1, "result": {
                        "state": 3, "currentHeight": 1, "targetHeight": 0, "private": "unselected"}}),
                    b" " * (capture.SYNC_INFO_BYTES + 1)):
            with self.subTest(bytes=len(raw)):
                self.setUp()
                self.raw = raw
                self.rpc.capture_startup_sync()
                self.assertEqual((self.summary()["status"], self.summary()["reason"]), ("REFUSED", "capture_refused"))
                self.assertEqual(runner.startup_sync_evidence_files(self.rpc),
                                 {capture.SYNC_REPORT, "rpc-01.request.json"})

    def test_interruption_before_sealing_a_request_remains_unknown(self):
        self.guard.side_effect = KeyboardInterrupt
        with self.assertRaises(KeyboardInterrupt):
            self.rpc.capture_startup_sync()
        self.recorder.run.assert_not_called()
        self.assertEqual((self.summary()["status"], self.summary()["reason"]), ("UNKNOWN", "capture_interrupted"))
        self.assertIsNone(self.summary()["request_id"])

    def test_diagnostic_selection_requires_one_bounded_matching_pair(self):
        for selected in (set(), {capture.SYNC_REPORT}, {capture.SYNC_REPORT, "rpc-96.request.json"},
                         {capture.SYNC_REPORT, "rpc-96.request.json", "rpc-96.sync-info.json"}):
            self.assertEqual(runner.startup_sync_evidence_files(mock.Mock(startup_sync_evidence=selected)), selected)
        for selected in ({"rpc-01.request.json"}, {capture.SYNC_REPORT, "rpc-01.sync-info.json"},
                         {capture.SYNC_REPORT, "rpc-01.request.json", "rpc-02.sync-info.json"},
                         {capture.SYNC_REPORT, "rpc-00.request.json"},
                         {capture.SYNC_REPORT, "rpc-97.request.json"}, {capture.SYNC_REPORT, "../private.json"},
                         {capture.SYNC_REPORT, 1}):
            with self.subTest(selected=selected), self.assertRaises(model.Refused):
                runner.startup_sync_evidence_files(mock.Mock(startup_sync_evidence=selected))

    def test_only_initial_readiness_deadline_allows_one_diagnostic(self):
        rpc = mock.Mock()
        value = object()
        rpc.wait_height.return_value = value
        self.assertIs(runner.wait_for_initial_height(rpc, 3), value)
        rpc.wait_height.assert_called_once_with(3, starting=True)
        rpc.capture_startup_sync.assert_not_called()
        for reason in ("observed_chain", "owned_rpc_call_bound", "unit_budget_refusal",
                       "owned_rpc_readiness_deadline"):
            with self.subTest(reason=reason):
                rpc = mock.Mock()
                error = model.Refused(reason)
                rpc.wait_height.side_effect = error
                with self.assertRaises(model.Refused) as observed:
                    runner.wait_for_initial_height(rpc, 3)
                self.assertIs(observed.exception, error)
                self.assertEqual(rpc.capture_startup_sync.call_count,
                                 1 if reason == "owned_rpc_readiness_deadline" else 0)

    def test_probe_interruption_is_not_hidden_by_the_initial_refusal(self):
        rpc = mock.Mock()
        rpc.wait_height.side_effect = model.Refused("owned_rpc_readiness_deadline")
        rpc.capture_startup_sync.side_effect = KeyboardInterrupt
        with self.assertRaises(KeyboardInterrupt):
            runner.wait_for_initial_height(rpc, 3)
        rpc.capture_startup_sync.assert_called_once_with()

    def test_frontier_export_rejects_names_outside_the_bounded_rpc_selection(self):
        self.assertEqual(runner.frontier_evidence_files(mock.Mock(retained_frontiers=set())), set())
        self.assertEqual(runner.frontier_evidence_files(mock.Mock(
            retained_frontiers={"rpc-01.frontier.json", "rpc-96.frontier.json"})),
            {"rpc-01.frontier.json", "rpc-01.request.json",
             "rpc-96.frontier.json", "rpc-96.request.json"})
        for name in ("rpc-00.frontier.json", "rpc-97.frontier.json", "rpc-1.frontier.json",
                     "../rpc-01.frontier.json", "rpc-01.request.json", "private.json", 1):
            with self.subTest(name=name), self.assertRaises(model.Refused):
                runner.frontier_evidence_files(mock.Mock(retained_frontiers={name}))


class PostSyncFrontierTests(unittest.TestCase):
    def setUp(self):
        StartupSyncTests.setUp(self)
        self.sync = self.rpc.capture_startup_sync()
        self.raw = model.canonical({"jsonrpc": "2.0", "id": 2, "result": synthetic_window()[1][3]})

    def summary(self):
        return json.loads(self.payloads[capture.POST_SYNC_REPORT])

    def test_one_later_frontier_is_bounded_and_keeps_the_original_body(self):
        self.rpc.capture_post_sync_frontier(1)
        args = self.recorder.run.call_args.args[1]
        options = self.recorder.run.call_args.kwargs
        self.assertEqual(json.loads(args[args.index("--data-binary") + 1]),
            {"jsonrpc": "2.0", "id": 2, "method": "ledger.getFrontierMomentum", "params": []})
        self.assertEqual((options["timeout"], options["stdout_cap"], args[-1]),
                         (7, 128 << 10, capture.RPC_URL))
        self.assertEqual(self.payloads["rpc-02.frontier.json"], self.raw)
        self.assertEqual(self.summary()["status"], "OBSERVED")
        self.assertEqual(self.summary()["after_sync_request_id"], 1)
        self.assertFalse(self.summary()["accepted_header_authority"])
        self.assertEqual(runner.post_sync_frontier_evidence_files(self.rpc),
                         {capture.POST_SYNC_REPORT, "rpc-02.request.json"})
        self.assertEqual(runner.frontier_evidence_files(self.rpc),
                         {"rpc-02.request.json", "rpc-02.frontier.json"})
        with self.assertRaisesRegex(model.Refused, "post_sync_frontier_scope"):
            self.rpc.capture_post_sync_frontier(1)
        self.assertEqual(self.recorder.run.call_count, 2)

    def test_only_the_last_successfully_observed_sync_request_can_select_the_read(self):
        for value in (True, 0, 2, 97):
            with self.subTest(value=value), self.assertRaises(model.Refused):
                self.rpc.capture_post_sync_frontier(value)
        self.rpc.startup_sync_observed_request = None
        with self.assertRaises(model.Refused):
            self.rpc.capture_post_sync_frontier(1)
        self.assertNotIn(capture.POST_SYNC_REPORT, self.payloads)
        self.assertEqual(self.recorder.run.call_count, 1)

    def test_budget_refusal_and_final_sync_slot_launch_no_frontier_command(self):
        for exhausted in (False, True):
            with self.subTest(exhausted=exhausted):
                StartupSyncTests.setUp(self)
                if exhausted:
                    self.rpc.calls = 95
                    self.raw = self.raw.replace(b'"id": 1', b'"id": 96')
                sync = self.rpc.capture_startup_sync()
                self.guard.side_effect = model.Refused("unit_budget_refusal")
                self.rpc.capture_post_sync_frontier(sync["request_id"])
                self.assertEqual(self.recorder.run.call_count, 1)
                self.assertEqual(self.summary()["status"], "NOT_ATTEMPTED")
                self.assertEqual(self.summary()["reason"], "shared_call_limit" if exhausted else "budget_refused")
                self.assertIsNone(self.summary()["request_id"])
                self.assertEqual(runner.post_sync_frontier_evidence_files(self.rpc), {capture.POST_SYNC_REPORT})
                self.guard.side_effect = None
                with self.assertRaisesRegex(model.Refused, "post_sync_frontier_scope"):
                    self.rpc.capture_post_sync_frontier(sync["request_id"])
                self.assertEqual(self.recorder.run.call_count, 1)

    def test_failed_incomplete_and_interrupted_frontier_commands_keep_their_status(self):
        for actual_exit, complete, reason in ((7, True, None), (-15, False, "timeout"),
                                            (None, False, "launch_failed"), (-15, False, "interrupted")):
            with self.subTest(actual_exit=actual_exit, reason=reason):
                self.setUp()
                receipt = {"actual_exit": actual_exit, "output_complete": complete, "reason": reason}
                self.recorder.run.side_effect = CommandFailed(mock.Mock(receipt=receipt))
                if reason == "interrupted":
                    with self.assertRaises(KeyboardInterrupt):
                        self.rpc.capture_post_sync_frontier(1)
                else:
                    self.rpc.capture_post_sync_frontier(1)
                self.assertEqual(self.summary()["status"], "FAILURE" if complete else "UNKNOWN")
                self.assertIsNone(self.summary()["response_file"])
                self.assertEqual(runner.post_sync_frontier_evidence_files(self.rpc),
                                 {capture.POST_SYNC_REPORT, "rpc-02.request.json"})
                self.assertEqual(self.rpc.retained_frontiers, set())

    def test_unvalidated_or_oversized_frontier_bodies_are_excluded(self):
        for raw in (b"{", self.raw.replace(b'"id": 2', b'"id": 3'), b" " * ((128 << 10) + 1)):
            with self.subTest(bytes=len(raw)):
                self.setUp()
                self.raw = raw
                self.rpc.capture_post_sync_frontier(1)
                self.assertEqual(self.summary()["status"], "REFUSED")
                self.assertIsNone(self.summary()["response_file"])
                self.assertFalse(runner.frontier_evidence_files(self.rpc))

    def test_prelaunch_interruption_retains_unknown_without_a_request(self):
        self.guard.side_effect = KeyboardInterrupt
        with self.assertRaises(KeyboardInterrupt):
            self.rpc.capture_post_sync_frontier(1)
        self.assertEqual((self.summary()["status"], self.summary()["reason"]), ("UNKNOWN", "capture_interrupted"))
        self.assertIsNone(self.summary()["request_id"])
        self.assertEqual(self.recorder.run.call_count, 1)

    def test_followup_can_use_the_last_shared_slot_without_resetting_the_counter(self):
        StartupSyncTests.setUp(self)
        self.rpc.calls = 94
        self.raw = self.raw.replace(b'"id": 1', b'"id": 95')
        sync = self.rpc.capture_startup_sync()
        self.raw = model.canonical({"jsonrpc": "2.0", "id": 96, "result": synthetic_window()[1][3]})
        self.rpc.capture_post_sync_frontier(sync["request_id"])
        self.assertEqual(self.rpc.calls, 96)
        self.assertEqual(self.summary()["request_id"], 96)
        self.assertIn("rpc-96.frontier.json", self.rpc.retained_frontiers)

    def test_selection_allows_only_one_bounded_request_and_the_fixed_summary(self):
        for selected in (set(), {capture.POST_SYNC_REPORT}, {capture.POST_SYNC_REPORT, "rpc-96.request.json"}):
            self.assertEqual(runner.post_sync_frontier_evidence_files(mock.Mock(post_sync_evidence=selected)), selected)
        for selected in ({"rpc-01.request.json"}, {capture.POST_SYNC_REPORT, "rpc-00.request.json"},
                         {capture.POST_SYNC_REPORT, "rpc-97.request.json"},
                         {capture.POST_SYNC_REPORT, "rpc-01.frontier.json"},
                         {capture.POST_SYNC_REPORT, "rpc-01.request.json", "rpc-02.request.json"},
                         {capture.POST_SYNC_REPORT, "../private.json"}, {capture.POST_SYNC_REPORT, 1}):
            with self.subTest(selected=selected), self.assertRaises(model.Refused):
                runner.post_sync_frontier_evidence_files(mock.Mock(post_sync_evidence=selected))

    def test_only_an_observed_sync_allows_the_followup_and_the_original_refusal_wins(self):
        for sync in (None, {"status": "FAILURE"}, {"status": "NOT_ATTEMPTED"},
                     {"status": "OBSERVED", "request_id": 31}):
            with self.subTest(sync=sync):
                rpc = mock.Mock()
                error = model.Refused("owned_rpc_readiness_deadline")
                rpc.wait_height.side_effect = error
                rpc.capture_startup_sync.return_value = sync
                with self.assertRaises(model.Refused) as observed:
                    runner.wait_for_initial_height(rpc, 3)
                self.assertIs(observed.exception, error)
                self.assertEqual(rpc.capture_post_sync_frontier.call_count,
                                 1 if sync is not None and sync["status"] == "OBSERVED" else 0)
                if sync is not None and sync["status"] == "OBSERVED":
                    rpc.capture_post_sync_frontier.assert_called_once_with(31)

    def test_followup_interruption_keeps_controller_interruption_visible(self):
        rpc = mock.Mock()
        rpc.wait_height.side_effect = model.Refused("owned_rpc_readiness_deadline")
        rpc.capture_startup_sync.return_value = {"status": "OBSERVED", "request_id": 31}
        rpc.capture_post_sync_frontier.side_effect = KeyboardInterrupt
        with self.assertRaises(KeyboardInterrupt):
            runner.wait_for_initial_height(rpc, 3)


class StartupPeerFrontierTests(unittest.TestCase):
    def setUp(self):
        PostSyncFrontierTests.setUp(self)
        post = self.rpc.capture_post_sync_frontier(1)
        self.after = post["request_id"]
        transport = self.recorder.run.side_effect
        rows = synthetic_window()[1]

        def peer_transport(label, argv, cwd, environment, **options):
            request = json.loads(argv[argv.index("--data-binary") + 1])
            self.raw = model.canonical({"jsonrpc": "2.0", "id": request["id"],
                                        "result": rows[2 if argv[-1] == capture.STARTUP_FRONTIER_URLS["pillar"] else 0]})
            return transport(label, argv, cwd, environment, **options)

        self.recorder.run.reset_mock()
        self.recorder.run.side_effect = peer_transport

    def test_two_owned_reads_fit_in_the_shared_budget_and_keep_exact_bytes(self):
        report = self.rpc.capture_startup_peer_frontiers(self.after)
        self.assertEqual(report["after_rpc_request_id"], 2)
        self.assertEqual([(row["role"], row["request_id"], row["status"]) for row in report["observations"]],
                         [("pillar", 3, "OBSERVED"), ("rpc", 4, "OBSERVED")])
        self.assertFalse(report["accepted_header_authority"])
        from engine import PORTS
        for call, role in zip(self.recorder.run.call_args_list, ("pillar", "rpc")):
            label, argv = call.args[:2]
            port = next(host for host, container in PORTS[role] if container == 35997)
            self.assertEqual((label, argv[-1]), (f"startup-{role}-frontier", f"http://127.0.0.1:{port}"))
            self.assertEqual((call.kwargs["stdout_cap"], call.kwargs["timeout"]), (128 << 10, 7))
            name = label + ".json"
            self.assertEqual(json.loads(self.payloads[name])["id"], 3 if role == "pillar" else 4)
        self.assertEqual(self.rpc.calls, 4)
        self.assertEqual(self.rpc.retained_frontiers, {"rpc-02.frontier.json"})
        self.assertEqual(runner.startup_peer_evidence_files(self.rpc), {
            capture.STARTUP_FRONTIERS_REPORT, "startup-pillar-frontier.request.json",
            "startup-pillar-frontier.json", "startup-rpc-frontier.request.json", "startup-rpc-frontier.json"})
        with self.assertRaisesRegex(model.Refused, "startup_frontier_scope"):
            self.rpc.capture_startup_peer_frontiers(self.after)

    def test_bracket_requires_the_observed_parent_and_two_slots(self):
        with self.assertRaisesRegex(model.Refused, "startup_frontier_scope"):
            self.rpc.capture_startup_peer_frontiers(1)
        self.rpc.calls = self.rpc.post_sync_observed_request = 95
        report = self.rpc.capture_startup_peer_frontiers(95)
        self.assertEqual(report["observations"], [{"role": "pillar", "status": "NOT_ATTEMPTED",
            "reason": "shared_call_limit", "request_id": None, "response_file": None}])
        self.recorder.run.assert_not_called()
        self.assertEqual(runner.startup_peer_evidence_files(self.rpc), {capture.STARTUP_FRONTIERS_REPORT})

    def test_partial_bracket_retains_first_read_when_budget_refuses_followup(self):
        self.guard.side_effect = [None, model.Refused("budget_refused")]
        report = self.rpc.capture_startup_peer_frontiers(self.after)
        self.assertEqual([row["status"] for row in report["observations"]], ["OBSERVED", "NOT_ATTEMPTED"])
        self.assertEqual(report["observations"][1]["reason"], "budget_refused")
        self.assertEqual(self.recorder.run.call_count, 1)
        self.assertEqual(runner.startup_peer_evidence_files(self.rpc), {
            capture.STARTUP_FRONTIERS_REPORT, "startup-pillar-frontier.request.json", "startup-pillar-frontier.json"})

    def test_unvalidated_pillar_body_stops_before_final_rpc(self):
        self.recorder.run.side_effect = lambda *args, **kwargs: mock.Mock(stdout=lambda cap: b"not a response")
        report = self.rpc.capture_startup_peer_frontiers(self.after)
        self.assertEqual(report["observations"], [{"role": "pillar", "status": "REFUSED",
            "reason": "capture_refused", "request_id": 3, "response_file": None}])
        self.assertEqual(self.recorder.run.call_count, 1)
        self.assertEqual(runner.startup_peer_evidence_files(self.rpc),
                         {capture.STARTUP_FRONTIERS_REPORT, "startup-pillar-frontier.request.json"})

    def test_publication_requires_the_request_and_fixed_role(self):
        for selected in ({capture.STARTUP_FRONTIERS_REPORT, "startup-rpc-frontier.json"},
                         {capture.STARTUP_FRONTIERS_REPORT, "startup-other-frontier.request.json"},
                         {"startup-pillar-frontier.request.json"}):
            with self.subTest(selected=selected), self.assertRaises(model.Refused):
                runner.startup_peer_evidence_files(mock.Mock(startup_frontier_evidence=selected))

    def test_configuration_timeout_reads_the_primary_once_and_reserves_the_frozen_rpc_slot(self):
        label = capture.CONFIGURATION_TIMEOUT_PILLAR
        self.rpc.calls = capture.RPC_CALL_LIMIT - 2
        with mock.patch.object(capture.time, "monotonic", return_value=100):
            self.rpc.capture_configuration_timeout_pillar(deadline=130)
        call = self.recorder.run.call_args
        self.assertEqual((call.args[0], call.args[1][-1]), (label, capture.STARTUP_FRONTIER_URLS["pillar"]))
        argv = call.args[1]
        self.assertEqual(argv[argv.index("--max-time") + 1], "2.000")
        self.assertEqual((call.kwargs["timeout"], call.kwargs["stdout_cap"]), (4, capture.FRONTIER_BYTES))
        request = {"jsonrpc": "2.0", "id": 95, "method": "ledger.getFrontierMomentum", "params": []}
        self.assertEqual(json.loads(self.payloads[label + ".request.json"]), request)
        self.assertEqual(json.loads(self.payloads[label + ".json"])["id"], 95)
        self.assertEqual(self.rpc.configuration_timeout_pillar_evidence, {label + ".request.json", label + ".json"})
        with self.assertRaisesRegex(model.Refused, "configuration_timeout_pillar_already_attempted"):
            self.rpc.capture_configuration_timeout_pillar(deadline=130)
        self.assertEqual(self.recorder.run.call_count, 1)
        self.rpc.frontier()
        self.assertEqual(self.rpc.calls, capture.RPC_CALL_LIMIT)

    def test_configuration_timeout_observation_leaves_the_frozen_read_available_on_failure(self):
        label = capture.CONFIGURATION_TIMEOUT_PILLAR
        for calls, deadline, guard, reached in ((95, 104, None, False),
                (94, 100, None, False), (94, 104, model.Refused("budget_refused"), False),
                (94, 104, None, True)):
            with self.subTest(calls=calls, deadline=deadline, guard=guard):
                self.setUp()
                self.rpc.calls = calls
                self.guard.side_effect = [guard]
                self.recorder.run.side_effect = lambda *args, **kwargs: mock.Mock(stdout=lambda cap: b"incomplete")
                with mock.patch.object(capture.time, "monotonic", return_value=100):
                    self.rpc.capture_configuration_timeout_pillar(deadline=deadline)
                self.assertEqual(self.rpc.calls, calls + int(reached))
                self.assertEqual(self.rpc.configuration_timeout_pillar_evidence,
                                 {label + ".request.json"} if reached else set())
                self.assertEqual(self.recorder.run.call_count, int(reached))

    def test_readiness_uses_only_observed_post_sync_and_keeps_original_refusal(self):
        for after in (None, {"status": "REFUSED"}, {"status": "OBSERVED", "request_id": 32}):
            with self.subTest(after=after):
                rpc, inspect_nodes = mock.Mock(), mock.Mock()
                error = model.Refused("owned_rpc_readiness_deadline")
                rpc.wait_height.side_effect = error
                rpc.capture_startup_sync.return_value = {"status": "OBSERVED", "request_id": 31}
                rpc.capture_post_sync_frontier.return_value = after
                with self.assertRaises(model.Refused) as observed:
                    runner.wait_for_initial_height(rpc, 3, observe_nodes=inspect_nodes)
                self.assertIs(observed.exception, error)
                if after is not None and after["status"] == "OBSERVED":
                    rpc.capture_startup_peer_frontiers.assert_called_once_with(32)
                else:
                    rpc.capture_startup_peer_frontiers.assert_not_called()
                inspect_nodes.assert_called_once_with()


def synthetic_window(last=4, state_root=bytes([77]) * 32, *, opening_root=None):
    rows = []
    chain = CONTRACT.data["selection"]["chain_id"]
    previous = bytes(32)
    pub = bytes(range(32))
    empty = hashlib.sha3_256(b"").digest()
    for height in range(1, last + 1):
        version = 1 if height < 3 else 3
        timestamp = 1739923200 + height * 10
        root = state_root if version == 3 else bytes(32)
        if height == 3 and opening_root is not None:
            root = opening_root
        encoded = struct.pack(">QQ", version, chain) + previous + struct.pack(">QQ", height, timestamp)
        encoded += empty + empty + bytes(32)
        if version == 3:
            encoded += bytes(16) + root
        digest = hashlib.sha3_256(encoded).digest()
        rows.append({"version": version, "chainIdentifier": chain, "height": height,
            "timestamp": timestamp, "hash": digest.hex(), "previousHash": previous.hex(),
            "stateRoot": root.hex(), "changesHash": "0" * 64,
            "nextFusionPrice": 0, "nextWorkPrice": 0, "data": "", "content": [],
            "publicKey": None if height == 1 else base64.b64encode(pub).decode("ascii"),
            "signature": None if height == 1 else base64.b64encode(bytes(64)).decode("ascii"),
            "producer": query_checks.address_text(b"\0" + hashlib.sha3_256(pub).digest()[:19])})
        previous = digest
    # Use synthetic genesis only in these byte and orchestration controls.
    data = CONTRACT.data
    data["selection"]["genesis_h1_hash"] = rows[0]["hash"]
    raw = model.canonical(data)
    contract = model.Contract(raw, hashlib.sha256(raw).hexdigest())
    opening = capture.opening_headers(contract, rows[:3])
    query, tip = (capture.Header.read(row, chain) for row in rows[-2:])
    provider = {"version": 1, "momentums": rows[2:], "witnesses": {}, "gateway": {}}
    headers = capture.captured_headers(contract, opening, query, tip, provider)
    return contract, rows, capture.Window(headers, query, provider, None)


def synthetic_reports(contract, window, *, separate_opening=False):
    for raw, targets in capture.oracle_requests(contract, window.headers, separate_opening=separate_opening):
        genesis, tip = window.headers[0], window.headers[-1]
        rows = []
        for header in targets:
            parent = window.headers[header.height - 2]
            slot = {"timestamp": header.timestamp, "tick": 0, "slot_start": header.timestamp,
                "slot_end": header.timestamp + 10, "name": "fixture",
                "producer": query_checks.address_text(bytes.fromhex(header.producing_addr)),
                "proof_time": genesis.timestamp, "proof_block": genesis.identifier(),
                "proof_block_timestamp": genesis.timestamp}
            rows.append({"header": header.identifier(), "parent": parent.identifier(),
                "version": header.version, "state_root": header.root, "timestamp": header.timestamp,
                "producing_addr": header.producing_addr, "source_parent_slot": slot,
                "matches_stored_key_producer": True})
        yield {"format": "zenon-closed-devnet-parent-slots/v1",
            "node_revision": model.SOURCE_PINS["node"][1],
            "genesis": genesis.identifier(), "frontier": tip.identifier(),
            "request_sha256": hashlib.sha256(raw).hexdigest(), "rows": rows,
            **dict.fromkeys(capture.ORACLE_TRUE, True), **dict.fromkeys(capture.ORACLE_FALSE, False)}


class CaptureTests(unittest.TestCase):
    def test_rpc_envelope_requires_exact_integer_identity(self):
        raw = b'{"jsonrpc":"2.0","id":1,"result":{"height":3}}'
        self.assertEqual(capture.rpc_result(raw, 1, 128), {"height": 3})
        for changed in (raw.replace(b'"id":1', b'"id":true'), raw.replace(b'"id":1', b'"id":2'),
                        raw.replace(b'"id":1', b'"id":1,"id":1'),
                        raw.replace(b'"result":{"height":3}', b'"result":null'),
                        raw[:-1] + b',"error":null}'):
            with self.subTest(changed=changed), self.assertRaises(model.Refused):
                capture.rpc_result(changed, 1, 128)

    def test_opening_requires_selected_genesis_and_real_version_boundary(self):
        contract, rows, _ = synthetic_window()
        with self.assertRaises(model.Refused):
            capture.opening_headers(CONTRACT, rows[:3])
        for order in ([0, 2, 1], [0, 1, 3]):
            with self.assertRaises(model.Refused):
                capture.opening_headers(contract, [rows[index] for index in order])
        changed = deepcopy(rows[:3])
        changed[1]["publicKey"] = None
        with self.assertRaises(model.Refused):
            capture.opening_headers(contract, changed)

    def test_provider_never_moves_the_selected_window(self):
        contract, rows, window = synthetic_window(5)
        opening = capture.opening_headers(contract, rows[:3])
        for query, tip, provider in (
                (window.headers[-1], window.headers[-1], window.provider),
                (window.query, window.headers[-2], window.provider),
                (window.query, window.headers[-1], dict(window.provider, momentums=rows[3:])),
                (window.query, window.headers[-1], dict(window.provider, momentums=list(reversed(rows[2:]))))):
            with self.assertRaises(model.Refused):
                capture.captured_headers(contract, opening, query, tip, provider)

    def test_retains_valid_collector_output_before_rechecking_the_frontier(self):
        contract, _, window = synthetic_window(5)
        opening, tip = window.headers[:3], window.headers[-1]
        for outcome in ("same", "moved", "interrupted", "invalid"):
            with self.subTest(outcome=outcome), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "evidence"
                root.mkdir()
                recorder = mock.Mock(directory=root, names=set(), records=())

                def seal(name, raw):
                    with (root / name).open("xb") as stream:
                        stream.write(raw)
                    recorder.names.add(name)
                    return {"file": name, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}

                recorder.seal.side_effect = seal
                provider = dict(window.provider)
                if outcome == "invalid":
                    provider["version"] = 2
                raw = model.canonical(provider)
                selected = contract.data["qualified_components"]["consumer"]["binaries"]
                binaries = mock.Mock(directory=root)
                binaries.verify.return_value = selected
                rpc = mock.Mock(calls=7)
                result = mock.Mock()
                result.stdout.return_value = raw

                def collect(label, command, *args, stdout_name, **kwargs):
                    self.assertEqual(label, "collect-provider")
                    self.assertIn("--compare-gateway", command)
                    self.assertEqual(stdout_name, capture.PROVIDER_FILE)
                    result.receipt = {"outputs": {"stdout": recorder.seal(stdout_name, raw)}}
                    return result

                def recheck():
                    if rpc.frontier.call_count == 1:
                        return tip
                    self.assertIn(capture.PROVIDER_CAPTURE, recorder.names)
                    self.assertIn(capture.PROVIDER_FILE, recorder.names)
                    if outcome == "interrupted":
                        raise KeyboardInterrupt
                    return window.query if outcome == "moved" else tip

                rpc.frontier.side_effect = recheck
                with mock.patch.object(recorder, "run", side_effect=collect):
                    args = (contract, recorder, rpc, binaries, opening, window.query, root, {}, mock.Mock())
                    if outcome == "same":
                        self.assertIs(capture.collect(*args).provider_result, result)
                    elif outcome == "interrupted":
                        with self.assertRaises(KeyboardInterrupt):
                            capture.collect(*args)
                    else:
                        reason = "capture_frontier_moved" if outcome == "moved" else "owned_provider_version"
                        with self.assertRaisesRegex(model.Refused, reason):
                            capture.collect(*args)
                paths = {entry["path"] for entry in runner.evidence_index((recorder,), {})}
                retained = {"evidence/" + capture.PROVIDER_FILE, "evidence/" + capture.PROVIDER_CAPTURE}
                if outcome == "invalid":
                    self.assertEqual(rpc.frontier.call_count, 1)
                    self.assertTrue(paths.isdisjoint(retained))
                else:
                    self.assertEqual(rpc.frontier.call_count, 2)
                    self.assertTrue(retained <= paths)
                    marker = json.loads((root / capture.PROVIDER_CAPTURE).read_bytes())
                    self.assertEqual(marker["frontier_request_id"], 7)
                    self.assertEqual(marker["provider"], result.receipt["outputs"]["stdout"])
                    self.assertEqual((root / capture.PROVIDER_FILE).read_bytes(), raw)

    def test_closed_oracle_chunks_cover_anchor_and_all_v3_parents(self):
        contract, _, window = synthetic_window(67)
        chunks = list(capture.oracle_requests(contract, window.headers))
        self.assertEqual([len(targets) for _, targets in chunks], [64, 2])
        self.assertEqual(chunks[0][1][0].height, 2)
        self.assertEqual(chunks[-1][1][-1].height, 67)
        for raw, _ in chunks:
            self.assertTrue(raw.startswith(b'{"expected_frontier":{"hash":'))
            self.assertTrue(raw.endswith(b'],"version":1}\n'))
        schedule = capture.oracle_schedule(contract, window.headers, synthetic_reports(contract, window))
        self.assertEqual(schedule["coverage"], [{"from_height": 3, "through_height": 67}])
        self.assertEqual([row["height"] for row in schedule["entries"]], list(range(3, 68)))

    def test_closed_reader_reuses_completed_opening_and_launches_only_the_suffix(self):
        contract, _, window = synthetic_window(67)
        opening, frontier = window.headers[:3], window.headers[-1].identifier()
        ledger = "/var/lib/docker/volumes/spv-" + "a" * 32 + "-rpc-data/_data/nom"
        trace = mock.Mock()
        trace.engine.closed_ledger.return_value = ledger
        trace.engine.owned = {"rpc": mock.Mock(identity="b" * 64)}
        trace.engine.admission.engine_id = "c" * 64
        trace.binaries.directory = HERE
        trace.binaries.verify.return_value = contract.data["qualified_components"]["parent_oracle"]["binaries"]
        trace.sources.paths = {"node": HERE}
        trace.record.directory = HERE
        selection = contract.data["selection"]
        genesis = {"sha256": selection["genesis_file_sha256"], "bytes": selection["genesis_file_bytes"]}

        def pin(name, raw):
            return {"file": name, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}

        def runner_for(reports):
            frames = iter(reports)

            def run(label, *args, **kwargs):
                raw = model.canonical(next(frames))
                name = label + ".stdout"
                result = mock.Mock(directory=HERE, stdout_name=name,
                                   receipt={"outputs": {"stdout": pin(name, raw)}})
                result.stdout.return_value = raw
                return result
            return run

        def read(headers, **kwargs):
            return capture.read_closed_parent_schedule(contract, trace.record, trace.engine, ledger, headers,
                frontier, trace.sources, trace.binaries, HERE, {}, trace.guard, "selected reader", **kwargs)

        trace.record.seal.side_effect = pin
        with mock.patch.object(capture, "regular_pin", return_value=genesis), \
                mock.patch.object(capture.os, "stat", return_value=mock.Mock(st_ino=1)):
            trace.record.run.side_effect = runner_for(synthetic_reports(contract, window))
            original, _, _ = read(window.headers)
            self.assertEqual(trace.record.run.call_count, 2)
            trace.record.run.reset_mock()
            trace.record.seal.reset_mock()

            trace.record.run.side_effect = runner_for(synthetic_reports(contract, window, separate_opening=True))
            _, early, early_result = read(opening)
            replay, provenance, _ = read(window.headers, label_prefix=capture.DEPOSIT_TIMEOUT_ORACLE,
                                         reuse_opening=(early, early_result))
            self.assertEqual(original, replay)
            self.assertEqual(trace.record.run.call_count, 2)
            self.assertEqual(provenance["oracle_reports"][0], early["oracle_reports"][0])
            targets = [json.loads(args.args[1])["targets"] for args in trace.record.seal.call_args_list]
            self.assertEqual([[row["height"] for row in group] for group in targets],
                             [[2, 3], list(range(4, 68))])
            self.assertEqual([item.args[0] for item in trace.record.run.call_args_list],
                             ["parent-oracle-01", "timeout-parent-oracle-01"])

            trace.record.run.reset_mock()
            with self.assertRaisesRegex(model.Refused, "closed_oracle_opening_reuse_scope"):
                read(window.headers, reuse_opening=({**early, "engine_id": "d" * 64}, early_result))
            early_result.stdout.return_value = model.canonical(next(synthetic_reports(contract, window)))
            with self.assertRaisesRegex(model.Refused, "closed_oracle_provenance"):
                read(window.headers, reuse_opening=(early, early_result))
            trace.record.run.assert_not_called()

    def test_oracle_rejects_mismatch_before_reading_the_next_chunk(self):
        contract, _, window = synthetic_window(67)
        first = next(synthetic_reports(contract, window))
        first["rows"][0]["parent"]["hash"] = "f" * 64

        def reports():
            yield first
            self.fail("a later ledger read ran after a mismatched parent")

        with self.assertRaisesRegex(model.Refused, "closed_oracle_header_or_parent_binding"):
            capture.oracle_schedule(contract, window.headers, reports())

    def test_closed_opening_freezes_one_frontier_then_reads_two_original_parent_slots(self):
        contract, rows, window = synthetic_window(5)
        opening, frontier = window.headers[:3], window.headers[-1]
        record, sources, oracle, workspace, environment = (mock.sentinel.record, mock.sentinel.sources,
            mock.sentinel.oracle, mock.sentinel.workspace, mock.sentinel.environment)
        trace = mock.Mock()
        trace.rpc.calls = 9
        trace.rpc.frontier_with_row.return_value = frontier, rows[-1]
        trace.engine.close_rpc.return_value = mock.sentinel.ledger
        trace.read_parent.return_value = mock.sentinel.schedule, mock.sentinel.provenance, mock.sentinel.opening_result
        trace.budget.started, trace.budget.reserve, trace.budget.diagnostic_deadline = 0, 300, 120
        for services in (model.NODE_SERVICES, model.SERVICES):
            with self.subTest(services=services):
                trace.reset_mock()
                trace.rpc.deposit_timeout_batch.side_effect = model.Refused("no_candidate_batch")
                batch_inputs = (mock.sentinel.descriptor, mock.sentinel.profile) if services == model.SERVICES else None
                with mock.patch.object(capture, "read_closed_parent_schedule", trace.read_parent):
                    result, batch, replay = runner.closed_opening_after_timeout(contract, record, trace.engine, trace.rpc,
                        opening, sources, oracle, workspace, environment, trace.budget, "selected reader",
                        services=services, opening_row=rows[2], batch_inputs=batch_inputs)
                expected = [mock.call.budget.cap_diagnostic_time(120)]
                if services == model.NODE_SERVICES:
                    expected.append(mock.call.rpc.capture_configuration_timeout_pillar(deadline=110))
                expected.extend([mock.call.engine.stop_producers_and_clients(services=services),
                                 mock.call.rpc.frontier_with_row()])
                if batch_inputs is not None:
                    expected.append(mock.call.rpc.deposit_timeout_batch(frontier, *batch_inputs))
                expected.extend([
                    mock.call.engine.close_rpc(services=services),
                    mock.call.read_parent(contract, record, trace.engine, mock.sentinel.ledger, opening,
                        frontier.identifier(), sources, oracle, workspace, environment, trace.budget.check,
                        "selected reader", services=services), mock.call.budget.check(force=True)])
                self.assertEqual(trace.mock_calls, expected)
                self.assertEqual(result, {"format": "owned-devnet-closed-opening-authorization/v1",
                    "frontier_request_id": 9, "closed_ledger": mock.sentinel.provenance})
                self.assertIsNone(batch)
                self.assertIsNone(replay)
        capture.require_opening_frontier(opening, opening[2].identifier(), 3, opening[2].timestamp)
        for marker in (opening[1], opening[2]):
            identifier = marker.identifier()
            identifier["hash"] = "f" * 64
            with self.assertRaisesRegex(model.Refused, "closed_opening_frontier"):
                capture.require_opening_frontier(opening, identifier, marker.version, marker.timestamp)

    def test_deposit_timeout_batch_skips_the_opening_and_other_proofs_after_absence(self):
        witness = opening_absence_fixture()
        contract, rows, window = synthetic_window(5, bytes.fromhex(witness["root"]))
        descriptor, profile = capture.selected_profile(contract, HERE.parents[1])
        rpc = capture.LocalRpc(contract, mock.Mock(), HERE, "unused-curl", {}, mock.Mock())
        rpc.calls = 8
        with mock.patch.object(rpc, "_read", side_effect=[{"count": 1, "list": rows[3:4]}, witness]) as read:
            with self.assertRaisesRegex(model.Refused, "deposit_timeout_no_later_target"):
                rpc.deposit_timeout_batch(window.headers[3], descriptor, profile)
            read.assert_not_called()
            report = rpc.deposit_timeout_batch(window.headers[-1], descriptor, profile).report
        expected_params = capture.state_proof_parameters(window.headers[3], bytes.fromhex(OPENING_BATCH_KEY))
        self.assertEqual(read.call_args_list, [
            mock.call("ledger.getMomentumsByHeight", [4, 1], capture.FRONTIER_BYTES,
                      stdout_name=capture.DEPOSIT_TIMEOUT_HEADER),
            mock.call("ledger.getProof", expected_params, capture.OPENING_PROOF_BYTES,
                      stdout_name=capture.DEPOSIT_TIMEOUT_PROOFS["batch_entry"])])
        self.assertEqual(report["header"], window.headers[3].identifier())
        self.assertEqual(report["batch_witness"]["presence"], "absent")
        self.assertIsNone(report["context_proof_totals"])
        rpc.calls = capture.RPC_CALL_LIMIT - 1
        with mock.patch.object(rpc, "_read") as read, self.assertRaisesRegex(model.Refused, "deposit_timeout_rpc_budget"):
            rpc.deposit_timeout_batch(window.headers[-1], descriptor, profile)
        read.assert_not_called()

    def test_deposit_timeout_window_reuses_all_three_rows_at_the_final_rpc_slot(self):
        contract, rows, source = synthetic_window(5)
        rpc = capture.LocalRpc(contract, mock.Mock(), HERE, "unused-curl", {}, mock.Mock())
        rpc.calls = capture.RPC_CALL_LIMIT
        for gateway in ({"domainId": 1, "batchId": 0}, None):
            with self.subTest(gateway=gateway), mock.patch.object(rpc, "_read") as read:
                batch = capture.DepositTimeoutBatch({"frontier_request_id": rpc.calls - 5},
                    source.query, rows[-2], {"batch_entry": {}}, gateway)
                window, request_id = rpc.deposit_timeout_window(source.headers[:3], source.headers[-1], batch,
                    opening_row=rows[2], frontier_row=rows[-1], deadline=90)
                self.assertEqual(window.headers, source.headers)
                self.assertEqual(window.query, source.query)
                self.assertEqual(window.provider["momentums"], rows[2:])
                for expected, captured in zip(rows[2:], window.provider["momentums"]):
                    self.assertIs(captured, expected)
                self.assertIs(window.provider["witnesses"], batch.witnesses)
                if gateway is not None:
                    self.assertIs(window.provider["gateway"], gateway)
                else:
                    self.assertNotIn("gateway", window.provider)
                self.assertIsNone(request_id)
                read.assert_not_called()

    def test_deposit_timeout_window_reads_only_missing_rows_and_enforces_the_bound(self):
        contract, rows, source = synthetic_window(7)
        opening, frontier = source.headers[:3], source.headers[-1]
        rpc = capture.LocalRpc(contract, mock.Mock(), HERE, "unused-curl", {}, mock.Mock())
        middle = rows[3:-2]
        for calls, response, error in (
                (14, {"count": 7, "list": middle}, None),
                (14, {"count": 1, "list": middle}, "integer_bounds"),
                (14, {"count": 7, "list": middle[:-1]}, "deposit_timeout_middle_range"),
                (14, {"count": 7, "list": list(reversed(middle))}, "observed_header_continuity"),
                (15, None, "deposit_timeout_replay_rpc_budget"),
                (capture.RPC_CALL_LIMIT, None, "deposit_timeout_replay_rpc_budget")):
            rpc.calls = calls
            after = calls - 5 if calls == capture.RPC_CALL_LIMIT else 9
            batch = capture.DepositTimeoutBatch({"frontier_request_id": after}, source.query,
                                               rows[-2], {"batch_entry": {}})

            def read_middle(*args, **kwargs):
                rpc.calls += 1
                return response

            with self.subTest(calls=calls, error=error), mock.patch.object(rpc, "_read", side_effect=read_middle) as read:
                if error is None:
                    window, request_id = rpc.deposit_timeout_window(opening, frontier, batch,
                        opening_row=rows[2], frontier_row=rows[-1], deadline=90)
                    self.assertEqual(window.headers, source.headers)
                    self.assertEqual(window.provider["momentums"], rows[2:])
                    self.assertEqual(request_id, 15)
                else:
                    with self.assertRaisesRegex(model.Refused, error):
                        rpc.deposit_timeout_window(opening, frontier, batch,
                            opening_row=rows[2], frontier_row=rows[-1], deadline=90)
                if response is not None:
                    read.assert_called_once_with("ledger.getMomentumsByHeight", [4, 2],
                        contract.data["limits"]["stdout_bytes"], stdout_name=capture.DEPOSIT_TIMEOUT_RANGE,
                        deadline=90)
                else:
                    read.assert_not_called()

    def test_timeout_native_query_runs_after_the_same_ledger_closes(self):
        contract, rows, window = synthetic_window(5)
        opening, target, frontier = window.headers[:3], window.headers[-2], window.headers[-1]
        record, sources, oracle, consumer, workspace, environment = (
            mock.sentinel.record, mock.sentinel.sources, mock.sentinel.oracle, mock.sentinel.consumer,
            mock.sentinel.workspace, mock.sentinel.environment)
        inputs = (mock.sentinel.descriptor, mock.sentinel.profile)
        for dto, failure in (({"domainId": 1}, None), (None, None), (None, "reader"), (None, "consumer")):
            batch = capture.DepositTimeoutBatch({"frontier_request_id": 9}, target, rows[-2], {"batch_entry": {}}, dto)
            with self.subTest(has_gateway=dto is not None, failure=failure):
                trace = mock.Mock()
                trace.rpc.calls = 9
                trace.rpc.frontier_with_row.return_value = frontier, rows[-1]
                trace.rpc.deposit_timeout_batch.return_value = batch
                trace.rpc.deposit_timeout_window.return_value = window, None
                trace.engine.close_rpc.return_value = mock.sentinel.ledger
                tail = (mock.sentinel.full_schedule, mock.sentinel.full_evidence, mock.sentinel.opening_result)
                trace.read_parent.side_effect = [
                    (mock.sentinel.opening_schedule, mock.sentinel.opening_evidence, mock.sentinel.opening_result),
                    model.Refused("suffix_unavailable") if failure == "reader" else tail]
                trace.budget.started, trace.budget.reserve, trace.budget.diagnostic_deadline = 0, 300, 120
                trace.replay.side_effect = [model.Refused("native_replay") if failure == "consumer"
                                            else mock.sentinel.provider_pin]
                with mock.patch.multiple(capture, read_closed_parent_schedule=trace.read_parent,
                                         replay_deposit_timeout=trace.replay):
                    closed, captured, replay = runner.closed_opening_after_timeout(contract, record, trace.engine,
                        trace.rpc, opening, sources, oracle, workspace, environment, trace.budget, "selected reader",
                        services=model.SERVICES, opening_row=rows[2], batch_inputs=inputs, consumer=consumer)
                self.assertEqual(trace.mock_calls, [
                    mock.call.budget.cap_diagnostic_time(120),
                    mock.call.engine.stop_producers_and_clients(services=model.SERVICES),
                    mock.call.rpc.frontier_with_row(), mock.call.rpc.deposit_timeout_batch(frontier, *inputs),
                    mock.call.rpc.deposit_timeout_window(opening, frontier, batch,
                        opening_row=rows[2], frontier_row=rows[-1], deadline=110),
                    mock.call.engine.close_rpc(services=model.SERVICES),
                    mock.call.read_parent(contract, record, trace.engine, mock.sentinel.ledger, opening,
                        frontier.identifier(), sources, oracle, workspace, environment, trace.budget.check,
                        "selected reader", services=model.SERVICES), mock.call.budget.check(force=True),
                    mock.call.read_parent(contract, record, trace.engine, mock.sentinel.ledger, window.headers,
                        frontier.identifier(), sources, oracle, workspace, environment, trace.budget.check,
                        "selected reader", services=model.SERVICES, label_prefix=capture.DEPOSIT_TIMEOUT_ORACLE,
                        reuse_opening=(mock.sentinel.opening_evidence, mock.sentinel.opening_result)),
                    *([mock.call.replay(contract, record, window, mock.sentinel.full_schedule, *inputs, consumer,
                                       workspace, environment, trace.budget.check)] if failure != "reader" else []),
                    *([mock.call.budget.check(force=True)] if failure is None else []),
                ])
                self.assertEqual(closed["closed_ledger"], mock.sentinel.opening_evidence)
                self.assertIs(captured, batch)
                if failure is None:
                    self.assertEqual(replay, {"format": capture.DEPOSIT_TIMEOUT_REPLAY_REUSING_HEADERS_FORMAT,
                        "header_range_request_id": None, "provider": mock.sentinel.provider_pin,
                        "closed_ledger": mock.sentinel.full_evidence})
                else:
                    self.assertIsNone(replay)

    def test_oracle_refuses_wrong_source_frontier_proof_block_and_missing_row(self):
        contract, _, window = synthetic_window()
        original = next(synthetic_reports(contract, window))
        for mutate in (lambda row: row.update(request_sha256="f" * 64),
                       lambda row: row.update(node_revision="f" * 40),
                       lambda row: row.update(read_only_ledger=1),
                       lambda row: row["frontier"].update(hash="f" * 64),
                       lambda row: row["rows"][0]["source_parent_slot"]["proof_block"].update(height=2),
                       lambda row: row["rows"].pop()):
            row = deepcopy(original)
            mutate(row)
            with self.assertRaises(model.Refused):
                capture.oracle_schedule(contract, window.headers, [row])
        for reports in ([], [original, original]):
            with self.assertRaises(model.Refused):
                capture.oracle_schedule(contract, window.headers, reports)

    def test_local_context_binds_v2_profile_and_retains_exact_depth(self):
        contract, _, window = synthetic_window()
        descriptor, profile = capture.selected_profile(CONTRACT, HERE.parents[1])
        schedule = capture.oracle_schedule(contract, window.headers, synthetic_reports(contract, window))
        config, request, pins = capture.query_inputs(contract, window, schedule, profile)
        self.assertEqual(config["header_policy"], {"w": 1, "retain_headers": 2, "max_batch_headers": 2})
        self.assertEqual(config["header_profile"]["anchor"]["header_hash"], window.headers[1].hash)
        self.assertEqual(descriptor["consumer"]["domain_id"], 1)
        self.assertEqual(request["batch_id"], 0)
        self.assertEqual(request["context"], pins["context"])
        self.assertNotEqual(pins["context"], pins["header_context"])


class ReadinessTests(unittest.TestCase):
    def setUp(self):
        self.recorder = mock.Mock()
        self.guard = mock.Mock()
        self.rpc = capture.LocalRpc(CONTRACT, self.recorder, HERE, "unused-curl", {}, self.guard)

    @staticmethod
    def failure(code=56, **changes):
        receipt = {"actual_exit": code, "output_complete": True, "launch_outcome": "STARTED",
                   "process_group_quiescent": True, "reason": None, "outputs": {"stdout": {"bytes": 0}}}
        receipt.update(changes)
        return CommandFailed(mock.Mock(receipt=receipt))

    @staticmethod
    def response(row, request_id):
        return mock.Mock(stdout=mock.Mock(return_value=model.canonical(
            {"jsonrpc": "2.0", "id": request_id, "result": row})))

    def test_empty_startup_receive_failure_keeps_its_receipt_and_next_request_identity(self):
        _, rows, _ = synthetic_window()
        failure = self.failure()
        before = deepcopy(failure.result.receipt)
        self.recorder.run.side_effect = [failure, self.response(rows[-1], 2)]
        with mock.patch.object(capture.time, "monotonic", return_value=0), \
                mock.patch.object(capture.time, "sleep") as sleep:
            header = self.rpc.wait_height(3, starting=True)
        self.assertEqual(header.height, 4)
        self.assertEqual(failure.result.receipt, before)
        self.assertEqual([call.args[0] for call in self.recorder.run.call_args_list], ["rpc-01", "rpc-02"])
        requests = [json.loads(call.args[1]) for call in self.recorder.seal.call_args_list]
        self.assertEqual([row["id"] for row in requests], [1, 2])
        self.assertEqual([row["method"] for row in requests], ["ledger.getFrontierMomentum"] * 2)
        self.assertEqual(self.rpc.calls, 2)
        sleep.assert_called_once()
        self.assertAlmostEqual(sleep.call_args.args[0], 179 / 29)

    def test_empty_startup_connect_and_timeout_failures_remain_bounded_candidates(self):
        for code in (7, 28):
            with self.subTest(code=code), mock.patch.object(capture.time, "sleep") as sleep:
                read = mock.Mock(side_effect=[self.failure(code), "ready"])
                self.assertEqual(self.rpc._wait(read, lambda value: value == "ready", starting=True), "ready")
                self.assertEqual(read.call_count, 2)
                sleep.assert_called_once_with(3)

    def test_gateway_uses_the_same_empty_response_startup_boundary(self):
        self.recorder.run.side_effect = [self.failure(), self.response({"status": "OK"}, 2)]
        with mock.patch.object(capture.time, "sleep") as sleep:
            self.assertEqual(self.rpc.wait_gateway(), {"status": "OK"})
        for call in self.recorder.run.call_args_list:
            self.assertEqual(call.args[1][-1], capture.GATEWAY_URL)
        sleep.assert_called_once_with(3)

    def test_transport_failures_outside_startup_are_terminal(self):
        for code in (7, 28, 56):
            with self.subTest(code=code), mock.patch.object(capture.time, "sleep") as sleep:
                failure = self.failure(code)
                read = mock.Mock(side_effect=failure)
                with self.assertRaises(CommandFailed) as observed:
                    self.rpc._wait(read, lambda _: True, starting=False)
                self.assertIs(observed.exception, failure)
                read.assert_called_once_with()
                sleep.assert_not_called()

    def test_other_exits_partial_responses_and_uncertain_captures_never_retry(self):
        failures = [self.failure(code) for code in (0, 22, 23, 52, 137, -9, None, False)]
        failures.extend(self.failure(**change) for change in (
            {"output_complete": False}, {"output_complete": 1}, {"launch_outcome": "UNKNOWN"},
            {"process_group_quiescent": False}, {"process_group_quiescent": None},
            {"reason": "guard_refused"}, {"reason": "timeout"},
            {"outputs": {"stdout": {"bytes": 1}}}, {"outputs": {"stdout": {"bytes": False}}}))
        failures.extend(self.failure(code, outputs={"stdout": {"bytes": 1}}) for code in (7, 28))
        for failure in failures:
            with self.subTest(receipt=failure.result.receipt), mock.patch.object(capture.time, "sleep") as sleep:
                read = mock.Mock(side_effect=failure)
                with self.assertRaises(CommandFailed) as observed:
                    self.rpc._wait(read, lambda _: True, starting=True)
                self.assertIs(observed.exception, failure)
                read.assert_called_once_with()
                sleep.assert_not_called()

    def test_invalid_successful_response_is_terminal_without_another_read(self):
        _, rows, _ = synthetic_window()
        changed = deepcopy(rows[-1])
        changed["chainIdentifier"] += 1
        for raw in (b"{", b'{"jsonrpc":"2.0","id":1,"result":null}',
                    b'{"jsonrpc":"2.0","id":2,"result":{}}',
                    model.canonical({"jsonrpc": "2.0", "id": 1, "result": changed})):
            with self.subTest(raw=raw), mock.patch.object(capture.time, "sleep") as sleep:
                recorder = mock.Mock()
                recorder.run.return_value.stdout.return_value = raw
                rpc = capture.LocalRpc(CONTRACT, recorder, HERE, "unused-curl", {}, self.guard)
                with self.assertRaises(model.Refused):
                    rpc.wait_height(3, starting=True)
                self.assertEqual(recorder.run.call_count, 1)
                self.assertEqual(rpc.retained_frontiers, set())
                sleep.assert_not_called()

    def test_a_valid_low_frontier_remains_available_after_the_deadline(self):
        _, rows, _ = synthetic_window()
        clock = 0

        def low_frontier(*args, **kwargs):
            nonlocal clock
            clock = 180
            return self.response(rows[1], 1)

        self.recorder.run.side_effect = low_frontier
        with mock.patch.object(capture.time, "monotonic", side_effect=lambda: clock), \
                mock.patch.object(capture.time, "sleep") as sleep:
            with self.assertRaisesRegex(model.Refused, "owned_rpc_readiness_deadline"):
                self.rpc.wait_height(3, starting=True)
        self.assertEqual(self.rpc.retained_frontiers, {"rpc-01.frontier.json"})
        self.assertEqual(self.rpc.calls, 1)
        sleep.assert_not_called()

    def test_initial_readiness_can_observe_a_late_height_with_slow_responses(self):
        _, rows, _ = synthetic_window()
        clock = 1000.0
        starts = []

        def observed(label, argv, *args, **kwargs):
            nonlocal clock
            starts.append(clock - 1000)
            request_id = len(starts)
            self.assertEqual(label, f"rpc-{request_id:02d}")
            if starts[-1] >= 174:
                clock += 0.25
                return self.response(rows[2], request_id)
            clock += 4.75
            return self.response(rows[1], request_id)

        def sleep(seconds):
            nonlocal clock
            clock += seconds

        self.recorder.run.side_effect = observed
        with mock.patch.object(capture.time, "monotonic", side_effect=lambda: clock), \
                mock.patch.object(capture.time, "sleep", side_effect=sleep):
            self.assertEqual(self.rpc.wait_height(3, starting=True).height, 3)

        self.assertEqual(self.rpc.calls, 30)
        self.assertEqual(len(self.rpc.retained_frontiers), 30)
        for attempt, start in enumerate(starts):
            self.assertAlmostEqual(start, attempt * 179 / 29)
        self.assertAlmostEqual(clock, 1179.25)

    def test_initial_readiness_skips_elapsed_slots_and_keeps_the_next_request_id(self):
        _, rows, _ = synthetic_window()
        clock = 0
        starts = []

        def observed(label, argv, *args, **kwargs):
            nonlocal clock
            starts.append(clock)
            if label == "rpc-01":
                clock = 25
                return self.response(rows[1], 1)
            self.assertEqual(label, "rpc-02")
            return self.response(rows[2], 2)

        self.recorder.run.side_effect = observed
        with mock.patch.object(capture.time, "monotonic", side_effect=lambda: clock), \
                mock.patch.object(capture.time, "sleep") as sleep:
            self.assertEqual(self.rpc.wait_height(3, starting=True).height, 3)
        self.assertEqual(starts, [0, 25])
        self.assertEqual(self.rpc.retained_frontiers, {"rpc-01.frontier.json", "rpc-02.frontier.json"})
        sleep.assert_not_called()

    def test_initial_final_read_uses_the_existing_attempt_and_time_budgets(self):
        _, rows, _ = synthetic_window()
        deadline = capture.INITIAL_HEIGHT_WAIT_SECONDS
        for case in ("ready", "late", "missed"):
            with self.subTest(case=case):
                self.setUp()
                clock = 0.0

                def sleep(seconds):
                    nonlocal clock
                    clock += seconds
                    if case == "missed" and clock >= deadline - capture.INITIAL_FINAL_PROBE_SECONDS:
                        clock = deadline

                def observed(label, argv, *args, **kwargs):
                    nonlocal clock
                    request_id = int(label.removeprefix("rpc-"))
                    http_seconds = float(argv[argv.index("--max-time") + 1])
                    connect_seconds = float(argv[argv.index("--connect-timeout") + 1])
                    if request_id < capture.READINESS_ATTEMPTS:
                        self.assertEqual((connect_seconds, http_seconds, kwargs["timeout"]), (2, 5, 7))
                        clock += 0.01
                        return self.response(rows[1], request_id)
                    self.assertEqual(clock, deadline - capture.INITIAL_FINAL_PROBE_SECONDS)
                    self.assertEqual((connect_seconds, http_seconds, kwargs["timeout"]), (1, 1, 3))
                    clock = deadline if case == "late" else clock + 0.01
                    return self.response(rows[2], request_id)

                self.recorder.run.side_effect = observed
                with mock.patch.object(capture.time, "monotonic", side_effect=lambda: clock), \
                        mock.patch.object(capture.time, "sleep", side_effect=sleep):
                    if case == "ready":
                        self.assertEqual(self.rpc.wait_height(3, starting=True).height, 3)
                    else:
                        with self.assertRaisesRegex(model.Refused, "owned_rpc_readiness_deadline"):
                            self.rpc.wait_height(3, starting=True)
                expected = capture.READINESS_ATTEMPTS - (case == "missed")
                self.assertEqual(self.recorder.run.call_count, expected)
                self.assertEqual(len(self.rpc.retained_frontiers), expected)
                self.assertEqual(self.rpc.calls, expected)
                self.assertEqual([row.args[0] for row in self.recorder.seal.call_args_list],
                                 [f"rpc-{i:02d}.request.json" for i in range(1, expected + 1)])

    def test_deadline_limited_read_with_sub_millisecond_remaining_allocates_no_rpc(self):
        with mock.patch.object(capture.time, "monotonic", return_value=179.9995):
            with self.assertRaisesRegex(model.Refused, "owned_rpc_readiness_deadline"):
                self.rpc.frontier(deadline=180)
        self.assertEqual(self.rpc.calls, 0)
        self.recorder.seal.assert_not_called()
        self.recorder.run.assert_not_called()

    def test_ready_frontier_returned_at_the_deadline_remains_only_an_observation(self):
        _, rows, _ = synthetic_window()
        for starting, deadline in ((False, 90), (True, 180)):
            with self.subTest(starting=starting):
                self.setUp()
                self.recorder.run.return_value = self.response(rows[2], 1)
                clock = [0, 0, 0, deadline] if starting else [0, 0, deadline]
                with mock.patch.object(capture.time, "monotonic", side_effect=clock), \
                        mock.patch.object(capture.time, "sleep") as sleep:
                    with self.assertRaisesRegex(model.Refused, "owned_rpc_readiness_deadline"):
                        self.rpc.wait_height(3, starting=starting)
                self.assertEqual(self.rpc.retained_frontiers, {"rpc-01.frontier.json"})
                self.assertEqual(self.rpc.calls, 1)
                sleep.assert_not_called()

    def test_persistent_empty_receive_failures_exhaust_the_existing_attempt_bound(self):
        failure = self.failure()
        read = mock.Mock(side_effect=failure)
        with mock.patch.object(capture.time, "monotonic", return_value=0), \
                mock.patch.object(capture.time, "sleep") as sleep:
            with self.assertRaisesRegex(model.Refused, "owned_rpc_readiness_deadline"):
                self.rpc._wait(read, lambda _: True, starting=True)
        self.assertEqual(read.call_count, 30)
        self.assertEqual(sleep.call_count, 29)
        self.assertEqual(self.guard.call_count, 30)

    def test_expired_deadline_and_guard_refusal_launch_no_read(self):
        read = mock.Mock()
        with mock.patch.object(capture.time, "monotonic", side_effect=[0, 90]), \
                mock.patch.object(capture.time, "sleep") as sleep:
            with self.assertRaisesRegex(model.Refused, "owned_rpc_readiness_deadline"):
                self.rpc._wait(read, lambda _: True, starting=True)
        read.assert_not_called()
        sleep.assert_not_called()
        self.guard.side_effect = model.Refused("test_budget_refusal")
        with self.assertRaisesRegex(model.Refused, "test_budget_refusal"):
            self.rpc._wait(read, lambda _: True, starting=True)
        read.assert_not_called()

    def test_retry_cannot_bypass_a_later_budget_refusal(self):
        read = mock.Mock(side_effect=self.failure())
        self.guard.side_effect = [None, model.Refused("test_budget_refusal")]
        with mock.patch.object(capture.time, "sleep") as sleep:
            with self.assertRaisesRegex(model.Refused, "test_budget_refusal"):
                self.rpc._wait(read, lambda _: True, starting=True)
        read.assert_called_once_with()
        sleep.assert_called_once_with(3)

    def test_valid_low_height_still_waits_for_the_selected_height(self):
        read = mock.Mock(side_effect=[2, 3])
        with mock.patch.object(capture.time, "sleep") as sleep:
            self.assertEqual(self.rpc._wait(read, lambda height: height >= 3, starting=False), 3)
        self.assertEqual(read.call_count, 2)
        sleep.assert_called_once_with(3)

    def test_startup_failure_does_not_reset_the_shared_rpc_call_budget(self):
        self.rpc.calls = 95
        self.recorder.run.side_effect = self.failure()
        with mock.patch.object(capture.time, "monotonic", return_value=0), \
                mock.patch.object(capture.time, "sleep") as sleep:
            with self.assertRaisesRegex(model.Refused, "owned_rpc_call_bound"):
                self.rpc.wait_height(3, starting=True)
        self.assertEqual(self.rpc.calls, 97)
        self.assertEqual(self.recorder.run.call_count, 1)
        sleep.assert_called_once()
        self.assertAlmostEqual(sleep.call_args.args[0], 179 / 29)


@unittest.skipUnless(os.name == "posix", "POSIX descriptor and recorder controls")
class HostBoundaryTests(unittest.TestCase):
    def test_system_curl_preserves_a_reset_failure_before_loopback_startup_recovery(self):
        # Kernel TCP sockets only: no filesystem socket or fixed/shared port.
        # The server returns synthetic headers and never contacts a chain node.
        curl = Path("/usr/bin/curl")
        self.assertTrue(curl.is_file() and os.access(curl, os.X_OK))
        _, rows, _ = synthetic_window()
        requests, errors = [], []
        with tempfile.TemporaryDirectory(prefix="owned-curl-regular-control-") as temporary, \
                socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            root = Path(temporary).resolve(strict=True)
            record = Recorder(root / "evidence")
            listener.bind(("127.0.0.1", 0))
            listener.listen(2)
            listener.settimeout(5)
            endpoint = "http://127.0.0.1:" + str(listener.getsockname()[1])

            def serve():
                try:
                    for index in (1, 2):
                        connection, _ = listener.accept()
                        with connection:
                            connection.settimeout(2)
                            raw = bytearray()
                            while b"\r\n\r\n" not in raw:
                                part = connection.recv(4096)
                                self.assertTrue(part)
                                raw.extend(part)
                                self.assertLessEqual(len(raw), 8192)
                            head, body = bytes(raw).split(b"\r\n\r\n", 1)
                            lines = head.split(b"\r\n")
                            self.assertEqual(lines[0], b"POST / HTTP/1.1")
                            headers = {}
                            for line in lines[1:]:
                                name, value = line.split(b":", 1)
                                self.assertNotIn(name.lower(), headers)
                                headers[name.lower()] = value.strip()
                            self.assertEqual(headers[b"content-type"], b"application/json")
                            length = int(headers[b"content-length"])
                            self.assertTrue(0 < length <= 4096)
                            while len(body) < length:
                                part = connection.recv(length - len(body))
                                self.assertTrue(part)
                                body += part
                            self.assertEqual(len(body), length)
                            request = json.loads(body)
                            self.assertEqual(request, {"jsonrpc": "2.0", "id": index,
                                "method": "ledger.getFrontierMomentum", "params": []})
                            requests.append(request)
                            if index == 1:
                                # Abort only this accepted, fully read test request.
                                connection.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                                                      struct.pack("ii", 1, 0))
                            else:
                                payload = model.canonical({"jsonrpc": "2.0", "id": index,
                                                           "result": rows[-1]})
                                connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                                    b"Connection: close\r\nContent-Length: " + str(len(payload)).encode("ascii")
                                    + b"\r\n\r\n" + payload)
                except BaseException as error:
                    errors.append(type(error).__name__ + ": " + str(error))

            server = threading.Thread(target=serve, name="owned-loopback-control")
            server.start()
            try:
                rpc = capture.LocalRpc(CONTRACT, record, root, str(curl), {},
                                       lambda: self.assertEqual(errors, []))
                # The clock controls cover the full wait. Keep this TCP test
                # within the listener's five-second accept timeout.
                with mock.patch.object(capture, "RPC_URL", endpoint), \
                        mock.patch.object(capture, "INITIAL_HEIGHT_WAIT_SECONDS", 30):
                    self.assertEqual(rpc.wait_height(3, starting=True).height, 4)
            except BaseException:
                # Preserve actual command/stream evidence in the enclosing test
                # capture before TemporaryDirectory removes this test's files.
                diagnostic = {path.name: path.read_text() for path in (root / "evidence").iterdir()
                              if path.name.endswith((".complete.json", ".stderr"))}
                sys.stderr.write("Loopback transport diagnostics: " + json.dumps(diagnostic) + "\n")
                raise
            finally:
                listener.close()
                server.join(timeout=6)
                self.assertFalse(server.is_alive(), "owned loopback server did not stop")
            self.assertEqual(errors, [])
            self.assertEqual([row["id"] for row in requests], [1, 2])
            receipts = [json.loads((root / "evidence" / f"rpc-{index:02d}.complete.json").read_bytes())
                        for index in (1, 2)]
            self.assertEqual([row["actual_exit"] for row in receipts], [56, 0])
            self.assertTrue(all(row["output_complete"] and row["process_group_quiescent"] for row in receipts))
            self.assertEqual(receipts[0]["outputs"]["stdout"]["bytes"], 0)
            self.assertEqual([row["outcome"] for row in record.records], ["FAILURE", "SUCCESS"])
            names = {row["path"] for row in runner.evidence_index(
                (record,), {"evidence": runner.frontier_evidence_files(rpc)})}
            self.assertIn("evidence/rpc-02.frontier.json", names)
            self.assertIn("evidence/rpc-02.request.json", names)
            self.assertNotIn("evidence/rpc-01.frontier.json", names)
            self.assertNotIn("evidence/rpc-01.request.json", names)
            self.assertEqual((root / "evidence/rpc-02.frontier.json").read_bytes(),
                             model.canonical({"jsonrpc": "2.0", "id": 2, "result": rows[-1]}))
            if os.environ.get("SPV_RECORD_LOOPBACK_CONTROL") == "1":
                # The qualification caller retains this bounded stdout report;
                # ordinary preparation controls keep their usual output.
                report = {"format": "owned-loopback-startup-control/v1", "requests": requests,
                          "receipts": receipts, "actual_stdout": [
                              (root / "evidence" / f"rpc-{index:02d}.frontier.json").read_text()
                              for index in (1, 2)], "owned_server_thread_joined": True,
                          "real_node_or_state_acceptance": False}
                sys.stdout.write(model.canonical(report).decode("ascii"))

    def test_real_process_receive_failure_receipt_survives_a_synthetic_startup_recovery(self):
        _, rows, _ = synthetic_window()
        with tempfile.TemporaryDirectory(prefix="owned-rpc-regular-control-") as temporary:
            root = Path(temporary).resolve(strict=True)
            record = Recorder(root / "evidence")
            actual_run = record.run
            attempt = 0

            def simulated_transport(label, argv, cwd, environment, **options):
                nonlocal attempt
                attempt += 1
                request = json.loads(argv[argv.index("--data-binary") + 1])
                code = "raise SystemExit(56)" if attempt == 1 else "print(" + repr(
                    model.canonical({"jsonrpc": "2.0", "id": request["id"], "result": rows[-1]}).decode()) + ")"
                return actual_run(label, [sys.executable, "-I", "-B", "-c", code], cwd, {}, **options)

            rpc = capture.LocalRpc(CONTRACT, record, root, "unused-curl", {}, lambda: None)
            with mock.patch.object(record, "run", side_effect=simulated_transport), \
                    mock.patch.object(capture.time, "sleep"):
                self.assertEqual(rpc.wait_height(3, starting=True).height, 4)
            receipts = [json.loads((root / "evidence" / f"rpc-{index:02d}.complete.json").read_bytes())
                        for index in (1, 2)]
            self.assertEqual([row["actual_exit"] for row in receipts], [56, 0])
            self.assertTrue(all(row["output_complete"] and row["process_group_quiescent"] for row in receipts))
            self.assertEqual(receipts[0]["outputs"]["stdout"]["bytes"], 0)
            self.assertEqual([row["outcome"] for row in record.records], ["FAILURE", "SUCCESS"])

    def test_invalid_runtime_files_refuse_before_package_or_image_preparation(self):
        execution = model.ExecutionIdentity("a" * 40, 1, 1, "edgepillar")
        with tempfile.TemporaryDirectory(prefix="owned-runtime-input-control-") as temporary:
            root = Path(temporary).resolve(strict=True)
            with mock.patch.multiple(runner, dispatch=mock.DEFAULT, Budget=mock.DEFAULT,
                                     Engine=mock.DEFAULT, Artifacts=mock.DEFAULT, Installer=mock.DEFAULT,
                                     Sources=mock.DEFAULT, Packages=mock.DEFAULT, Builder=mock.DEFAULT,
                                     publish_paths=mock.DEFAULT) as dependencies:
                dependencies["dispatch"].return_value = CONTRACT, execution
                dependencies["Budget"].return_value.report.return_value = {}
                engine = dependencies["Engine"].return_value
                engine.docker_root = CONTRACT.data["runtime"]["closed_oracle_readonly_docker_root"]
                engine.prepare_files.side_effect = model.Refused("fixture_source_default")
                engine.cleanup.return_value = []
                env = {"GH_TOKEN": "unused-test-value", "GITHUB_OUTPUT": str(root / "output")}
                self.assertEqual(runner.execute(env, root, HERE.parents[1]), 1)
                dependencies["Artifacts"].return_value.preflight.assert_called_once_with()
                dependencies["Artifacts"].return_value.fetch.assert_not_called()
                dependencies["Packages"].assert_not_called()
                dependencies["Builder"].assert_not_called()
                engine.create_layout.assert_not_called()
            terminal = json.loads((root / "evidence/terminal.json").read_bytes())
            self.assertEqual((terminal["stage"], terminal["outcome"], terminal["reason"]),
                             ("runtime-inputs", "REFUSED", "fixture_source_default"))

    def test_query_inputs_and_packages_follow_opening_validation(self):
        proof_key = base64.b64encode(bytes.fromhex(OPENING_BATCH_KEY)).decode("ascii")
        execution = model.ExecutionIdentity("a" * 40, 1, 1, "edgepillar")
        for case, stage, reason in (
                ("bad-opening", "nodes", "opening_header_count"),
                ("bad-proof", "opening-proof", "opening_proof_root_or_response"),
                ("version-unavailable", "opening-proof", capture.OPENING_PROOF_VERSION_UNAVAILABLE),
                ("batch-already-present", "opening-proof", capture.OPENING_BATCH_ALREADY_PRESENT),
                ("other-proof-error", "opening-proof", "owned_rpc_result_envelope"),
                ("bad-signature", "opening-signatures", "command_failed"),
                ("bad-oracle", "query-inputs", "test_oracle_input_refusal"),
                ("bad-toolchain", "node-toolchain", "test_node_toolchain_refusal"),
                ("bad-packages", "packages", "test_package_refusal"),
                ("ready", "fixture-configuration", "test_fixture_boundary"),
                ("configure-timeout", "fixture-configuration", "command_incomplete"),
                ("deposit-timeout", "fixture-deposit", "command_incomplete"),
                ("bad-consumer", "consumer", "consumer_reported_failure")):
            trace = mock.Mock()
            consumer_failed = case == "bad-consumer"
            deposit_timed_out = case == "deposit-timeout"
            timeout_phase = {"configure-timeout": "configure", "deposit-timeout": "deposit"}.get(case)
            batch_present = case == "batch-already-present"
            witness = opening_present_fixture() if batch_present else opening_absence_fixture()
            contract, rows, window = synthetic_window(state_root=bytes.fromhex(witness["root"]))
            if timeout_phase is not None:
                data = contract.data
                ref_gas = model.read_contract(HERE / "reference-gas-renewal-1-contract.json")
                data["sources"]["devnet"] = ref_gas.data["sources"]["devnet"]
                raw = model.canonical(data)
                contract = model.Contract(raw, hashlib.sha256(raw).hexdigest())
            opening_failed = batch_present or case in ("bad-opening", "bad-proof", "version-unavailable", "other-proof-error")
            signature_failed = case == "bad-signature"
            queries_admitted = not opening_failed and not signature_failed

            def rpc_factory(contract, record, root, curl, environment, guard):
                rpc = actual_rpc(contract, record, root, curl, environment, guard)
                trace.wait_height.side_effect = rpc.wait_height
                rpc.wait_height = trace.wait_height
                if consumer_failed or deposit_timed_out:
                    rpc.wait_gateway = trace.wait_gateway
                if consumer_failed:
                    initial_wait = trace.wait_height.side_effect
                    trace.wait_height.side_effect = lambda height, starting=False: (
                        initial_wait(height, starting=True) if starting else None)
                    rpc.select_query_header = mock.Mock(return_value=window.query)
                actual_run = record.run

                def local_transport(label, argv, cwd, env, **options):
                    if label == "consume-query":
                        return actual_run(label, argv, cwd, env, **options)
                    if label in capture.OPENING_SIGNATURE_LABELS:
                        height = capture.OPENING_SIGNATURE_LABELS.index(label) + 2
                        trace.opening_signature(height)
                        self.assertEqual(argv[:4], ["/usr/bin/openssl", "pkeyutl", "-verify", "-rawin"])
                        self.assertEqual(Path(env["OPENSSL_CONF"]).read_bytes(), b"")
                        row = rows[height - 1]
                        self.assertEqual((cwd / "message.bin").read_bytes(), bytes.fromhex(row["hash"]))
                        self.assertEqual((cwd / "public-key.der").read_bytes(),
                                         capture.ED25519_SPKI_PREFIX + base64.b64decode(row["publicKey"]))
                        self.assertEqual((cwd / "signature.bin").read_bytes(), base64.b64decode(row["signature"]))
                        code = 1 if height == 3 and signature_failed else 0
                        output = b"Signature Verification Failure\n" if code else capture.OPENING_SIGNATURE_OK
                        return actual_run(label, [sys.executable, "-I", "-B", "-c",
                            "import sys; sys.stdout.buffer.write(" + repr(output) + "); sys.exit(" + str(code) + ")"],
                            cwd, {}, **options)
                    request = json.loads(argv[argv.index("--data-binary") + 1])
                    if label == capture.CONFIGURATION_TIMEOUT_PILLAR:
                        self.assertEqual(request, {"jsonrpc": "2.0", "id": 4,
                            "method": "ledger.getFrontierMomentum", "params": []})
                        self.assertEqual(argv[-1], capture.STARTUP_FRONTIER_URLS["pillar"])
                        result = rows[-1]
                    elif request["method"] == "ledger.getFrontierMomentum":
                        self.assertEqual(request, {"jsonrpc": "2.0", "id": 1,
                            "method": "ledger.getFrontierMomentum", "params": []})
                        result = rows[2]
                    elif request["method"] == "ledger.getMomentumsByHeight":
                        trace.opening()
                        self.assertEqual(request, {"jsonrpc": "2.0", "id": 2,
                            "method": "ledger.getMomentumsByHeight", "params": [1, 3]})
                        result = {"count": 3, "list": rows[:2] if case == "bad-opening" else rows[:3]}
                    else:
                        trace.opening_proof()
                        self.assertEqual(request, {"jsonrpc": "2.0", "id": 3,
                            "method": "ledger.getProof", "params": [3, proof_key]})
                        result = dict(witness)
                        if case == "bad-proof":
                            result["root"] = "1" * 64
                    response = model.canonical({"jsonrpc": "2.0", "id": request["id"], "result": result})
                    if request["method"] == "ledger.getProof":
                        if case == "version-unavailable":
                            response = (b'{"jsonrpc":"2.0","id":3,"error":{"code":-32000,'
                                        b'"message":"trie: no such version"}}\n')
                        elif case == "other-proof-error":
                            response = model.canonical({"jsonrpc": "2.0", "id": 3, "error": {
                                "code": -32000, "message": "trie: no such version", "data": "unselected fixture detail"}})
                    return actual_run(label, [sys.executable, "-I", "-B", "-c",
                        "import sys; sys.stdout.write(" + repr(response.decode()) + ")"], cwd, {}, **options)

                patch = mock.patch.object(record, "run", side_effect=local_transport)
                patch.start()
                self.addCleanup(patch.stop)
                return rpc

            actual_rpc = capture.LocalRpc
            with self.subTest(case=case), tempfile.TemporaryDirectory(prefix="owned-query-input-control-") as temporary:
                root = Path(temporary).resolve(strict=True)
                with mock.patch.multiple(runner, dispatch=mock.DEFAULT, Budget=mock.DEFAULT,
                                         Engine=mock.DEFAULT, Artifacts=mock.DEFAULT, Installer=mock.DEFAULT,
                                         Sources=mock.DEFAULT, Packages=mock.DEFAULT, Builder=mock.DEFAULT,
                                         fixture_flow=mock.DEFAULT, closed_opening_after_timeout=mock.DEFAULT,
                                         publish_paths=mock.DEFAULT) as dependencies, \
                        mock.patch.object(capture, "LocalRpc", side_effect=rpc_factory), \
                        mock.patch.multiple(capture, collect=mock.DEFAULT, read_closed_schedule=mock.DEFAULT,
                                            query=mock.DEFAULT) as post_fixture:
                    dependencies["dispatch"].return_value = contract, execution
                    dependencies["Budget"].return_value.report.return_value = {}
                    engine = dependencies["Engine"].return_value
                    engine.docker_root = contract.data["runtime"]["closed_oracle_readonly_docker_root"]
                    engine.cleanup.return_value = []
                    engine.prepare_files.return_value = mock.Mock(verify=trace.verify_runtime_files)
                    dependencies["Builder"].return_value.prepare = trace.build_images
                    artifacts = dependencies["Artifacts"].return_value
                    artifacts.preflight = trace.preflight
                    artifacts.fetch = trace.fetch
                    consumer = mock.Mock(enable_execution=trace.enable_consumer)
                    oracle = mock.Mock(enable_execution=trace.enable_oracle)
                    trace.fetch.side_effect = [mock.Mock(binaries=consumer),
                        model.Refused(reason) if case == "bad-oracle" else mock.Mock(binaries=oracle)]
                    dependencies["Installer"].return_value.fetch = trace.fetch_node_toolchain
                    trace.fetch_node_toolchain.return_value = mock.sentinel.executable_node
                    if case == "bad-toolchain":
                        trace.fetch_node_toolchain.side_effect = model.Refused(reason)
                    dependencies["Packages"].return_value.prepare = trace.prepare_packages
                    trace.prepare_packages.return_value = mock.sentinel.prepared_packages
                    if case == "bad-packages":
                        trace.prepare_packages.side_effect = model.Refused(reason)

                    def stop_at_fixture(*args):
                        self.assertIs(args[4], mock.sentinel.executable_node)
                        self.assertIs(args[5], mock.sentinel.prepared_packages)
                        phase = args[-2]
                        trace.fixture(phase)
                        if timeout_phase is not None:
                            timed_out = phase == timeout_phase
                            code = "import time; time.sleep(3)" if timed_out else "pass"
                            return Recorder.run(args[1], "fixture-" + phase,
                                [sys.executable, "-I", "-B", "-c", code], root, {},
                                timeout=0.125 if timed_out else 5)
                        if not consumer_failed:
                            raise model.Refused("test_fixture_boundary")

                    def reject_query(contract, record, *args):
                        trace.consume_query()
                        return record.run("consume-query", [sys.executable, "-I", "-B", "-c",
                            "import sys; sys.stdout.buffer.write(" + repr(consumer_failure_fixture()) + "); sys.exit(2)"],
                            root, {}, stdout_cap=capture.CONSUMER_FAILURE_BYTES)

                    def refuse_closed_opening(contract, record, engine, rpc, *args, **kwargs):
                        if timeout_phase == "configure":
                            rpc.capture_configuration_timeout_pillar(deadline=capture.time.monotonic() + 2)
                        raise model.Refused("test_opening_diagnostic")

                    post_fixture["collect"].return_value = window
                    post_fixture["query"].side_effect = reject_query
                    dependencies["fixture_flow"].side_effect = stop_at_fixture
                    dependencies["closed_opening_after_timeout"].side_effect = refuse_closed_opening
                    env = {"GH_TOKEN": "unused-test-value", "GITHUB_OUTPUT": str(root / "output")}
                    self.assertEqual(runner.execute(env, root, HERE.parents[1]), 1)
                    engine.cleanup.assert_called_once_with()
                    if queries_admitted and case != "bad-oracle":
                        self.assertEqual(dependencies["Installer"].call_args.kwargs, {"for_execution": True})
                    if timeout_phase is not None:
                        diagnostic = dependencies["closed_opening_after_timeout"]
                        diagnostic.assert_called_once()
                        self.assertEqual(diagnostic.call_args.kwargs["services"],
                                         model.SERVICES if deposit_timed_out else model.NODE_SERVICES)
                        post_fixture["collect"].assert_not_called()
                    else:
                        dependencies["closed_opening_after_timeout"].assert_not_called()
                expected = [mock.call.preflight(), mock.call.build_images(), mock.call.verify_runtime_files()]
                expected.extend(mock.call.build_images().image_for(role) for role in model.NODE_SERVICES)
                expected.extend((mock.call.wait_height(3, starting=True), mock.call.opening()))
                if case != "bad-opening":
                    expected.append(mock.call.opening_proof())
                if not opening_failed:
                    expected.extend((mock.call.opening_signature(2), mock.call.opening_signature(3)))
                if queries_admitted:
                    expected.extend((mock.call.fetch("consumer"), mock.call.fetch("parent_oracle")))
                if queries_admitted and case != "bad-oracle":
                    expected.extend((mock.call.enable_consumer(), mock.call.enable_oracle(),
                                     mock.call.fetch_node_toolchain()))
                if case in ("bad-packages", "ready", "bad-consumer") or timeout_phase is not None:
                    expected.append(mock.call.prepare_packages())
                if case in ("ready", "bad-consumer") or timeout_phase is not None:
                    expected.extend((mock.call.verify_runtime_files(), mock.call.fixture("configure")))
                if consumer_failed or deposit_timed_out:
                    expected.extend(mock.call.build_images().image_for(role) for role in model.SERVICES[4:])
                    expected.extend((mock.call.wait_gateway(), mock.call.fixture("deposit")))
                if consumer_failed:
                    expected.extend((mock.call.wait_height(window.query.height + contract.data["limits"]["header_depth"]),
                                     mock.call.consume_query()))
                self.assertEqual(trace.mock_calls, expected)
                terminal = json.loads((root / "evidence/terminal.json").read_bytes())
                outcome = "FAILURE" if consumer_failed or signature_failed else "REFUSED"
                if timeout_phase is not None:
                    outcome = "UNKNOWN"
                self.assertEqual((terminal["stage"], terminal["outcome"], terminal["reason"]),
                                 (stage, outcome, reason))
                index = json.loads((root / "evidence/evidence-index.json").read_bytes())
                files = {row["path"]: {key: row[key] for key in ("bytes", "sha256")}
                         for row in index["files"]}
                path = "evidence/opening-momentums.json"
                request = "evidence/rpc-02.request.json"
                self.assertIn("evidence/rpc-02.complete.json", files)
                checked = review_exported(root, index, execution, contract)
                self.assertEqual(checked["recorded_terminal_outcome"], outcome)
                self.assertIsNone(checked["comparison"])
                if timeout_phase is not None:
                    self.assertEqual(checked["recorded_fixture_timeout"]["command"], "fixture-" + timeout_phase)
                    self.assertNotIn("recorded_closed_opening_authorization", checked)
                pillar = checked.get("recorded_configuration_timeout_pillar")
                if timeout_phase == "configure":
                    self.assertEqual(pillar["observation"]["candidate_header"], window.headers[-1].identifier())
                    self.assertEqual((pillar["actual_exit"], pillar["output_complete"]), (0, True))
                    self.assertIsNone(pillar["comparison"])
                else:
                    self.assertIsNone(pillar)
                if consumer_failed:
                    raw = consumer_failure_fixture()
                    name = capture.CONSUMER_STDOUT
                    self.assertEqual((root / "evidence" / name).read_bytes(), raw)
                    self.assertEqual(checked["recorded_consumer_failure"], {**capture.consumer_failure(raw, 2),
                        "stdout": {"file": name, **files["evidence/" + name]}})
                else:
                    self.assertNotIn("recorded_consumer_failure", checked)
                self.assertEqual(checked["candidate_frontier_observations"][0]["request_id"], 1)
                if case == "bad-opening":
                    self.assertNotIn(path, files)
                    self.assertNotIn(request, files)
                    self.assertNotIn("candidate_opening_observation", checked)
                else:
                    observed = checked["candidate_opening_observation"]
                    self.assertEqual(observed["request_id"], 2)
                    self.assertEqual(observed["response"], files[path])
                    self.assertEqual(observed["request"], files[request])
                    self.assertEqual(observed["headers"][-1]["hash"], rows[2]["hash"])
                    self.assertFalse(observed["accepted_header_authority"])
                    self.assertEqual(checked["materialized_bytes"], 0)
                proof_request = "evidence/rpc-03.request.json"
                proof_response = "evidence/" + capture.OPENING_PROOF_FILE
                if case == "bad-opening":
                    self.assertNotIn(proof_request, files)
                else:
                    self.assertIn(proof_request, files)
                if opening_failed and case not in ("version-unavailable", "batch-already-present"):
                    self.assertNotIn(proof_response, files)
                    self.assertNotIn("candidate_opening_proof", checked)
                else:
                    validated = checked["candidate_opening_proof"]
                    self.assertEqual(validated["header"], window.headers[2].identifier())
                    self.assertEqual(validated["ledger_key"], OPENING_BATCH_KEY)
                    self.assertEqual(validated["request"], files[proof_request])
                    self.assertFalse(validated["accepted_header_authority"])
                    if case == "version-unavailable":
                        self.assertEqual(validated["status"], "VERSION_UNAVAILABLE")
                        self.assertEqual(validated["rpc_error_code"], -32000)
                        self.assertNotIn("presence", validated)
                        self.assertEqual(validated["response"],
                                         {"file": capture.OPENING_PROOF_FILE, **files[proof_response]})
                    else:
                        self.assertEqual(validated["presence"], "present" if batch_present else "absent")
                signature_report = "evidence/" + capture.OPENING_SIGNATURE_REPORT
                self.assertEqual(signature_report in files, queries_admitted)
                self.assertEqual("recorded_opening_signatures" in checked, queries_admitted)
                if queries_admitted:
                    self.assertEqual(checked["recorded_opening_signatures"], {
                        "format": "owned-devnet-opening-signatures/v1", "opening_response": files[path],
                        "headers": [header.identifier() for header in window.headers[1:3]],
                        "accepted_header_authority": False, "producer_schedule_verified": False})
                if not opening_failed:
                    for label, actual_exit in zip(capture.OPENING_SIGNATURE_LABELS, (0, int(signature_failed))):
                        receipt = root / "evidence" / (label + ".complete.json")
                        self.assertEqual(json.loads(receipt.read_bytes())["actual_exit"], actual_exit)
                        self.assertIn("evidence/" + receipt.name, files)
                        self.assertNotIn("evidence/" + label + ".stdout", files)
                self.assertEqual(list((root / "scratch").glob("opening-signatures-*")), [])

    def test_runner_refusal_exports_the_valid_frontier_without_other_command_streams(self):
        _, rows, _ = synthetic_window(last=5)
        execution = model.ExecutionIdentity("a" * 40, 1, 1, "edgepillar")
        actual_rpc = capture.LocalRpc

        def rpc_factory(contract, record, root, curl, environment, guard):
            rpc = actual_rpc(contract, record, root, curl, environment, guard)
            actual_run = record.run

            def local_transport(label, argv, cwd, env, **options):
                request = json.loads(argv[argv.index("--data-binary") + 1])
                if request["method"] == "stats.syncInfo":
                    result = {"state": 2, "currentHeight": 99, "targetHeight": 99}
                elif label == "startup-pillar-frontier":
                    self.assertEqual(argv[-1], "http://127.0.0.1:35991")
                    result = rows[4]
                else:
                    self.assertEqual(argv[-1], "http://127.0.0.1:35997")
                    result = rows[1] if request["id"] == 1 else rows[3]
                self.assertIn(request["method"], ("ledger.getFrontierMomentum", "stats.syncInfo"))
                raw = model.canonical({"jsonrpc": "2.0", "id": request["id"], "result": result})
                return actual_run(label, [sys.executable, "-I", "-B", "-c",
                    "import sys; sys.stdout.write(" + repr(raw.decode()) + ")"], cwd, {}, **options)

            patch = mock.patch.object(record, "run", side_effect=local_transport)
            patch.start()
            self.addCleanup(patch.stop)
            rpc.frontier()
            record.seal("rpc-95.request.json", b'{"unselected":"fixture-only"}\n')
            rpc.wait_height = mock.Mock(side_effect=model.Refused("owned_rpc_readiness_deadline"))
            return rpc

        with tempfile.TemporaryDirectory(prefix="owned-frontier-export-control-") as temporary:
            root = Path(temporary).resolve(strict=True)
            with mock.patch.multiple(runner, dispatch=mock.DEFAULT, Budget=mock.DEFAULT,
                                     Engine=mock.DEFAULT, Artifacts=mock.DEFAULT, Installer=mock.DEFAULT,
                                     Sources=mock.DEFAULT, Packages=mock.DEFAULT, Builder=mock.DEFAULT,
                                     publish_paths=mock.DEFAULT) as dependencies, \
                    mock.patch.object(capture, "LocalRpc", side_effect=rpc_factory):
                dependencies["dispatch"].return_value = CONTRACT, execution
                dependencies["Budget"].return_value.report.return_value = {}
                engine = dependencies["Engine"].return_value
                engine.docker_root = CONTRACT.data["runtime"]["closed_oracle_readonly_docker_root"]
                engine.cleanup.return_value = []
                env = {"GH_TOKEN": "unused-test-value", "GITHUB_OUTPUT": str(root / "output")}
                self.assertEqual(runner.execute(env, root, HERE.parents[1]), 1)
                dependencies["Artifacts"].return_value.preflight.assert_called_once_with()
                dependencies["Artifacts"].return_value.fetch.assert_not_called()
                dependencies["Installer"].assert_not_called()
                dependencies["Packages"].assert_not_called()
                engine.cleanup.assert_called_once_with()
            terminal = json.loads((root / "evidence/terminal.json").read_bytes())
            self.assertEqual((terminal["stage"], terminal["outcome"], terminal["reason"]),
                             ("nodes", "REFUSED", "owned_rpc_readiness_deadline"))
            index = json.loads((root / "evidence/evidence-index.json").read_bytes())
            names = {row["path"] for row in index["files"]}
            self.assertIn("evidence/rpc-01.frontier.json", names)
            self.assertIn("evidence/rpc-01.request.json", names)
            self.assertIn("evidence/rpc-01.complete.json", names)
            self.assertNotIn("evidence/rpc-95.request.json", names)
            self.assertNotIn("evidence/rpc-01.stderr", names)
            self.assertIn("evidence/startup-sync.json", names)
            self.assertIn("evidence/rpc-02.request.json", names)
            self.assertIn("evidence/rpc-02.sync-info.json", names)
            self.assertIn("evidence/" + capture.POST_SYNC_REPORT, names)
            self.assertIn("evidence/rpc-03.request.json", names)
            self.assertIn("evidence/rpc-03.frontier.json", names)
            self.assertIn("evidence/" + capture.STARTUP_FRONTIERS_REPORT, names)
            for role in ("pillar", "rpc"):
                label = f"evidence/startup-{role}-frontier"
                self.assertIn(label + ".json", names)
                self.assertIn(label + ".request.json", names)
                self.assertIn(label + ".complete.json", names)
                self.assertNotIn(label + ".stderr", names)
            self.assertFalse(index["raw_service_logs_or_private_configuration_exported"])
            # Inspect exactly the exported index, not the wider recorder directory.
            # The real reader must be able to find the request after a refusal.
            checked = review_exported(root, index, execution)
            self.assertEqual(checked["status"], "RECORDED_NON_ACCEPTING_OUTCOME")
            self.assertEqual(checked["recorded_terminal_outcome"], "REFUSED")
            self.assertEqual(checked["indexed_files"], len(index["files"]))
            self.assertEqual(checked["materialized_bytes"], 0)
            self.assertIsNone(checked["comparison"])
            self.assertFalse(checked["native_consumer_reexecuted"])
            self.assertFalse(checked["new_devnet_acceptance_established"])
            self.assertEqual(checked["startup_sync_diagnostic"]["observation"],
                             {"state": 2, "current_height": 99, "target_height": 99})
            observed = checked["candidate_frontier_observations"]
            self.assertEqual(len(observed), 2)
            self.assertEqual(observed[0]["request_id"], 1)
            self.assertEqual(observed[0]["candidate_header"]["height"], 2)
            self.assertFalse(observed[0]["accepted_header_authority"])
            post = checked["post_sync_frontier_diagnostic"]
            self.assertEqual(post["observation"]["candidate_header"]["height"], 4)
            self.assertEqual((post["after_sync_request_id"], post["request_id"]), (2, 3))
            self.assertFalse(post["atomic_with_sync_observation"])
            self.assertFalse(post["accepted_header_authority"])
            peer = checked["startup_peer_frontier_diagnostic"]
            self.assertEqual(peer["comparison"], "pillar_ahead_of_unchanged_rpc")
            self.assertEqual([row["request_id"] for row in peer["observations"]], [4, 5])
            self.assertFalse(peer["accepted_header_authority"])

    def test_unavailable_sync_keeps_real_exit_and_excludes_unvalidated_body(self):
        for complete in (True, False):
            with self.subTest(complete=complete), tempfile.TemporaryDirectory(
                    prefix="owned-sync-regular-control-") as temporary:
                root = Path(temporary).resolve(strict=True)
                record = Recorder(root / "evidence")
                actual_run = record.run

                def local_transport(label, argv, cwd, env, **options):
                    code = "import sys; sys.stdout.write('unvalidated diagnostic bytes'); sys.stdout.flush(); "
                    code += "raise SystemExit(7)" if complete else "import time; time.sleep(5)"
                    options["timeout"] = 3 if complete else 0.1
                    return actual_run(label, [sys.executable, "-I", "-B", "-c", code], cwd, {}, **options)

                rpc = capture.LocalRpc(CONTRACT, record, root, "unused-curl", {}, lambda: None)
                with mock.patch.object(record, "run", side_effect=local_transport):
                    rpc.capture_startup_sync()
                execution = model.ExecutionIdentity("a" * 40, 1, 1, "edgepillar")
                record.seal("terminal.json", model.canonical({"format": "owned-devnet-query-terminal/v1",
                    "outcome": "REFUSED", "stage": "nodes", "reason": "owned_rpc_readiness_deadline",
                    "source_revision": execution.source_revision, "contract_sha256": CONTRACT.sha256,
                    "run_id": 1, "run_attempt": 1, "owned_runtime_observed_closed": False,
                    "production_qualified": False, "consensus_finality_or_funds_release": False}))
                entries = runner.evidence_index((record,), {"evidence": runner.startup_sync_evidence_files(rpc)})
                index = {"format": "owned-devnet-evidence-index/v1", "files": entries,
                         "transport_archive_copies": 0, "raw_service_logs_or_private_configuration_exported": False}
                self.assertNotIn("evidence/rpc-01.sync-info.json", {row["path"] for row in entries})
                checked = review_exported(root, index, execution)
                diagnostic = checked["startup_sync_diagnostic"]
                receipt = json.loads((root / "evidence/rpc-01.complete.json").read_bytes())
                self.assertEqual(diagnostic["status"], "FAILURE" if complete else "UNKNOWN")
                self.assertEqual(diagnostic["actual_exit"], receipt["actual_exit"])
                self.assertEqual(diagnostic["output_complete"], complete)
                self.assertIsNone(diagnostic["observation"])
                self.assertEqual(checked["recorded_terminal_outcome"], "REFUSED")

    def test_post_sync_failure_keeps_real_exit_and_excludes_unvalidated_body(self):
        for complete in (True, False):
            with self.subTest(complete=complete), tempfile.TemporaryDirectory(
                    prefix="owned-post-sync-child-control-") as temporary:
                root = Path(temporary).resolve(strict=True)
                record = Recorder(root / "evidence")
                actual_run = record.run

                def transport(label, argv, cwd, env, **options):
                    request = json.loads(argv[argv.index("--data-binary") + 1])
                    if request["method"] == "stats.syncInfo":
                        raw = model.canonical({"jsonrpc": "2.0", "id": request["id"],
                            "result": {"state": 2, "currentHeight": 2, "targetHeight": 2}})
                        code = "import sys; sys.stdout.write(" + repr(raw.decode()) + ")"
                    else:
                        self.assertEqual(request["method"], "ledger.getFrontierMomentum")
                        code = "import sys; sys.stdout.write('unvalidated candidate bytes'); sys.stdout.flush(); "
                        code += "raise SystemExit(7)" if complete else "import time; time.sleep(5)"
                        options["timeout"] = 3 if complete else 0.1
                    return actual_run(label, [sys.executable, "-I", "-B", "-c", code], cwd, {}, **options)

                rpc = capture.LocalRpc(CONTRACT, record, root, "unused-curl", {}, lambda: None)
                with mock.patch.object(record, "run", side_effect=transport):
                    sync = rpc.capture_startup_sync()
                    rpc.capture_post_sync_frontier(sync["request_id"])
                execution = model.ExecutionIdentity("a" * 40, 1, 1, "edgepillar")
                record.seal("terminal.json", model.canonical({"format": "owned-devnet-query-terminal/v1",
                    "outcome": "REFUSED", "stage": "nodes", "reason": "owned_rpc_readiness_deadline",
                    "source_revision": execution.source_revision, "contract_sha256": CONTRACT.sha256,
                    "run_id": 1, "run_attempt": 1, "owned_runtime_observed_closed": False,
                    "production_qualified": False, "consensus_finality_or_funds_release": False}))
                selected = (runner.startup_sync_evidence_files(rpc)
                            | runner.post_sync_frontier_evidence_files(rpc) | runner.frontier_evidence_files(rpc))
                entries = runner.evidence_index((record,), {"evidence": selected})
                index = {"format": "owned-devnet-evidence-index/v1", "files": entries,
                         "transport_archive_copies": 0, "raw_service_logs_or_private_configuration_exported": False}
                self.assertNotIn("evidence/rpc-02.frontier.json", {row["path"] for row in entries})
                checked = review_exported(root, index, execution)
                post = checked["post_sync_frontier_diagnostic"]
                receipt = json.loads((root / "evidence/rpc-02.complete.json").read_bytes())
                self.assertEqual(post["status"], "FAILURE" if complete else "UNKNOWN")
                self.assertEqual(post["actual_exit"], receipt["actual_exit"])
                self.assertEqual(post["output_complete"], complete)
                self.assertIsNone(post["observation"])
                self.assertEqual(checked["recorded_terminal_outcome"], "REFUSED")
                self.assertIsNone(checked["comparison"])

    def test_cancelled_reader_exits_after_anonymous_pipe_eof(self):
        command = [sys.executable, "-I", "-B", "-c",
            "import sys; sys.stdout.write('ready\\n'); sys.stdout.flush(); sys.stdin.buffer.read()"]
        output, receipt = capture_process(command, HERE, {}, timeout=0.3, stdin_lease=True)
        self.assertEqual(output["stdout"], b"ready\n")
        self.assertEqual(receipt["actual_exit"], 0)
        self.assertTrue(receipt["stdin_lease_revoked"])
        self.assertFalse(receipt["output_complete"])
        self.assertTrue(receipt["process_group_quiescent"])
        self.assertEqual(receipt["group_signals"], [])

    def test_reader_opens_only_the_exact_binary_bytes(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / closed_reader.ORACLE_NAME
            path.write_bytes(b"test bytes, never executed")
            expected = hashlib.sha256(path.read_bytes()).hexdigest()
            descriptor = closed_reader.verified_oracle(path, path.stat().st_size, expected)
            os.close(descriptor)
            path.write_bytes(b"changed bytes, refused!!!")
            with self.assertRaises(ValueError):
                closed_reader.verified_oracle(path, path.stat().st_size, expected)

    def test_public_index_retains_receipts_without_archives_or_raw_logs(self):
        with tempfile.TemporaryDirectory() as temp:
            record = Recorder(Path(temp) / "evidence")
            output = record.run("fixture", [sys.executable, "-I", "-B", "-c",
                "import sys; sys.stdout.write('test output'); sys.stderr.write('private diagnostic')"], HERE, {})
            record.seal("artifact.zip", b"transport")
            record.seal("terminal.json", b"{}\n")
            rows = runner.evidence_index((record,), {})
            names = {row["path"] for row in rows}
            self.assertIn("evidence/terminal.json", names)
            self.assertIn("evidence/fixture.complete.json", names)
            self.assertNotIn("evidence/artifact.zip", names)
            self.assertNotIn("evidence/" + output.stdout_name, names)
            self.assertNotIn("evidence/" + output.stderr_name, names)


if __name__ == "__main__":
    unittest.main()
