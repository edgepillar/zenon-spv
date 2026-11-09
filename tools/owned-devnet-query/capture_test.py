# SPDX-License-Identifier: GPL-3.0-only
"""Synthetic capture and closure counterexamples. No Docker or RPC executes."""
from __future__ import annotations

import base64
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import capture
import closed_reader
import model
from process import Recorder, capture as capture_process
import query_checks
import runner

CONTRACT = model.read_contract(HERE / "contract.json")


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


@unittest.skipUnless(os.name == "posix", "POSIX descriptor and recorder controls")
class HostBoundaryTests(unittest.TestCase):
    def test_invalid_runtime_files_refuse_before_package_or_image_preparation(self):
        execution = model.ExecutionIdentity("a" * 40, 1, 1, "edgepillar")
        with tempfile.TemporaryDirectory(prefix="owned-runtime-input-control-") as temporary:
            root = Path(temporary)
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
