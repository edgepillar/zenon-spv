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
import review
import runner

CONTRACT = model.read_contract(HERE / "contract.json")


def review_exported(root, index, execution):
    packed = io.BytesIO()
    with zipfile.ZipFile(packed, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for entry in index["files"]:
            archive.writestr(entry["path"], (root / entry["path"]).read_bytes())
        archive.writestr(review.INDEX, model.canonical(index))
    packed.seek(0)
    raw = packed.getvalue()
    return review.review_stream(packed,
        {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()},
        execution.source_revision, execution.run_id, CONTRACT, HERE.parents[1])


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


def synthetic_window(last=4, state_root=bytes([77]) * 32):
    rows = []
    chain = CONTRACT.data["selection"]["chain_id"]
    previous = bytes(32)
    pub = bytes(range(32))
    empty = hashlib.sha3_256(b"").digest()
    for height in range(1, last + 1):
        version = 1 if height < 3 else 3
        timestamp = 1739923200 + height * 10
        root = state_root if version == 3 else bytes(32)
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


def synthetic_reports(contract, window):
    for raw, targets in capture.oracle_requests(contract, window):
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

    def test_closed_oracle_chunks_cover_anchor_and_all_v3_parents(self):
        contract, _, window = synthetic_window(67)
        chunks = list(capture.oracle_requests(contract, window))
        self.assertEqual([len(targets) for _, targets in chunks], [64, 2])
        self.assertEqual(chunks[0][1][0].height, 2)
        self.assertEqual(chunks[-1][1][-1].height, 67)
        for raw, _ in chunks:
            self.assertTrue(raw.startswith(b'{"expected_frontier":{"hash":'))
            self.assertTrue(raw.endswith(b'],"version":1}\n'))
        schedule = capture.oracle_schedule(contract, window, synthetic_reports(contract, window))
        self.assertEqual(schedule["coverage"], [{"from_height": 3, "through_height": 67}])
        self.assertEqual([row["height"] for row in schedule["entries"]], list(range(3, 68)))

    def test_oracle_rejects_mismatch_before_reading_the_next_chunk(self):
        contract, _, window = synthetic_window(67)
        first = next(synthetic_reports(contract, window))
        first["rows"][0]["parent"]["hash"] = "f" * 64

        def reports():
            yield first
            self.fail("a later ledger read ran after a mismatched parent")

        with self.assertRaisesRegex(model.Refused, "closed_oracle_header_or_parent_binding"):
            capture.oracle_schedule(contract, window, reports())

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
                capture.oracle_schedule(contract, window, [row])
        for reports in ([], [original, original]):
            with self.assertRaises(model.Refused):
                capture.oracle_schedule(contract, window, reports)

    def test_local_context_binds_v2_profile_and_retains_exact_depth(self):
        contract, _, window = synthetic_window()
        descriptor, profile = capture.selected_profile(CONTRACT, HERE.parents[1])
        schedule = capture.oracle_schedule(contract, window, synthetic_reports(contract, window))
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
        with mock.patch.object(capture.time, "sleep") as sleep:
            header = self.rpc.wait_height(3, starting=True)
        self.assertEqual(header.height, 4)
        self.assertEqual(failure.result.receipt, before)
        self.assertEqual([call.args[0] for call in self.recorder.run.call_args_list], ["rpc-01", "rpc-02"])
        requests = [json.loads(call.args[1]) for call in self.recorder.seal.call_args_list]
        self.assertEqual([row["id"] for row in requests], [1, 2])
        self.assertEqual([row["method"] for row in requests], ["ledger.getFrontierMomentum"] * 2)
        self.assertEqual(self.rpc.calls, 2)
        sleep.assert_called_once_with(3)

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
        self.recorder.run.return_value = self.response(rows[1], 1)
        with mock.patch.object(capture.time, "monotonic", side_effect=[0, 0, 90]), \
                mock.patch.object(capture.time, "sleep"):
            with self.assertRaisesRegex(model.Refused, "owned_rpc_readiness_deadline"):
                self.rpc.wait_height(3, starting=True)
        self.assertEqual(self.rpc.retained_frontiers, {"rpc-01.frontier.json"})
        self.assertEqual(self.rpc.calls, 1)

    def test_persistent_empty_receive_failures_exhaust_the_existing_attempt_bound(self):
        failure = self.failure()
        read = mock.Mock(side_effect=failure)
        with mock.patch.object(capture.time, "monotonic", return_value=0), \
                mock.patch.object(capture.time, "sleep") as sleep:
            with self.assertRaisesRegex(model.Refused, "owned_rpc_readiness_deadline"):
                self.rpc._wait(read, lambda _: True, starting=True)
        self.assertEqual(read.call_count, 30)
        self.assertEqual(sleep.call_count, 30)
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
        with mock.patch.object(capture.time, "sleep") as sleep:
            with self.assertRaisesRegex(model.Refused, "owned_rpc_call_bound"):
                self.rpc.wait_height(3, starting=True)
        self.assertEqual(self.rpc.calls, 97)
        self.assertEqual(self.recorder.run.call_count, 1)
        sleep.assert_called_once_with(3)


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
                with mock.patch.object(capture, "RPC_URL", endpoint):
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
                dependencies["Packages"].assert_not_called()
                dependencies["Builder"].assert_not_called()
                engine.create_layout.assert_not_called()
            terminal = json.loads((root / "evidence/terminal.json").read_bytes())
            self.assertEqual((terminal["stage"], terminal["outcome"], terminal["reason"]),
                             ("runtime-inputs", "REFUSED", "fixture_source_default"))

    def test_runner_refusal_exports_the_valid_frontier_without_other_command_streams(self):
        _, rows, _ = synthetic_window()
        execution = model.ExecutionIdentity("a" * 40, 1, 1, "edgepillar")
        actual_rpc = capture.LocalRpc

        def rpc_factory(contract, record, root, curl, environment, guard):
            rpc = actual_rpc(contract, record, root, curl, environment, guard)
            actual_run = record.run

            def local_transport(label, argv, cwd, env, **options):
                request = json.loads(argv[argv.index("--data-binary") + 1])
                result = rows[1] if request["method"] == "ledger.getFrontierMomentum" else {
                    "state": 2, "currentHeight": 99, "targetHeight": 99}
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
            self.assertEqual(len(observed), 1)
            self.assertEqual(observed[0]["request_id"], 1)
            self.assertEqual(observed[0]["candidate_header"]["height"], 2)
            self.assertFalse(observed[0]["accepted_header_authority"])

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
