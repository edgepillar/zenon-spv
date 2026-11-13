# SPDX-License-Identifier: GPL-3.0-only
"""Stopped-state evidence controls; no Docker, services or fixture transactions."""
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True
HERE = Path(__file__).absolute().parent
sys.path.insert(0, str(HERE))
import engine
from engine_test import FixtureRecorder
import model
from process import Recorder
import runner


class StopStateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.contract = model.read_contract(HERE / "reference-gas-contract.json")

    def prepare(self, root):
        recorder = FixtureRecorder(self.contract)
        client = engine.Engine(self.contract, model.ExecutionIdentity("e" * 40, 1, 1, "edgepillar"),
            recorder, root / "engine", ["fixture-docker"], {"PATH": "/fixture/bin"}, lambda: None)
        with mock.patch.object(engine.platform, "system", return_value="Linux"), \
             mock.patch.object(engine.platform, "machine", return_value="x86_64"):
            client.probe()
        client.create("buildkit", "sha256:" + "c" * 64)
        client.start("buildkit")
        return client, recorder

    def alter_stop(self, recorder, changes):
        original = recorder.run

        def run(label, argv, *args, **kwargs):
            result = original(label, argv, *args, **kwargs)
            if argv[1:3] == ["container", "stop"]:
                recorder.containers[argv[-1]]["State"].update(deepcopy(changes))
            return result

        return mock.patch.object(recorder, "run", side_effect=run)

    def reports(self, recorder):
        return {name: json.loads(raw) for name, raw in recorder.seals.items()
                if engine.STOP_STATE_FILE.fullmatch(name) is not None}

    def test_forced_builder_exit_is_preserved_and_still_refuses_runtime(self):
        with tempfile.TemporaryDirectory(prefix="stop-state-regular-control-") as temporary:
            client, recorder = self.prepare(Path(temporary))
            with self.alter_stop(recorder, {"ExitCode": 137, "OOMKilled": True, "Status": "exited", "Error": ""}):
                with self.assertRaisesRegex(model.Refused, "builder_not_quiescent_after_stop"):
                    client.close_builder()
                self.assertFalse(client.builder_closed)
                with self.assertRaisesRegex(model.Refused, "builder_must_stop_before_runtime"):
                    client.create("pillar", "sha256:" + "c" * 64)
                first = next(iter(self.reports(recorder).values()))
                self.assertEqual(first["state"]["fields"]["ExitCode"], 137)
                self.assertIs(first["state"]["fields"]["OOMKilled"], True)
                self.assertEqual(first["state"]["error_class"], "empty")
                self.assertFalse(first["cleanup"])
                self.assertFalse(first["runtime_acceptance_established"])
                closure = client.cleanup()
            reports = self.reports(recorder)
            self.assertEqual(len(reports), 2)
            self.assertEqual(sum(report["cleanup"] for report in reports.values()), 1)
            self.assertFalse(closure[0]["observed_closed"])
            self.assertFalse(any(call[:2] == ["container", "rm"] for call in recorder.calls))

    def test_still_running_or_invalid_stop_state_is_not_hidden(self):
        cases = ({"Running": True, "Pid": 42}, {"Restarting": True}, {"Dead": True},
                 {"ExitCode": 137, "OOMKilled": True}, {"ExitCode": "private-value"})
        for changes in cases:
            with self.subTest(changes=changes), tempfile.TemporaryDirectory(prefix="stop-state-regular-control-") as temporary:
                client, recorder = self.prepare(Path(temporary))
                with self.alter_stop(recorder, changes):
                    with self.assertRaisesRegex(model.Refused, "builder_not_quiescent_after_stop"):
                        client.close_builder()
                report = next(iter(self.reports(recorder).values()))
                self.assertEqual(report["state"], engine.stop_state_summary(
                    recorder.containers[client.owned["buildkit"].identity]))
                self.assertNotIn("private-value", json.dumps(report))

    def test_successful_stop_retains_the_exact_inspection_digest(self):
        with tempfile.TemporaryDirectory(prefix="stop-state-regular-control-") as temporary:
            client, recorder = self.prepare(Path(temporary))
            owned = client.owned["buildkit"]
            client.close_builder()
            self.assertTrue(client.builder_closed)
            report = next(iter(self.reports(recorder).values()))
            self.assertEqual(report["container_id"], owned.identity)
            self.assertEqual(report["service"], "buildkit")
            self.assertEqual(report["state"]["fields"]["ExitCode"], 0)
            inspection = deepcopy(client.inspected_at_create["buildkit"])
            inspection["State"].update(Running=False, Pid=0, ExitCode=0, Status="exited")
            raw = model.canonical(inspection)
            self.assertEqual(report["inspection_stdout"], {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})

    def test_changed_engine_does_not_obtain_stop_or_report_authority(self):
        with tempfile.TemporaryDirectory(prefix="stop-state-regular-control-") as temporary:
            client, recorder = self.prepare(Path(temporary))
            recorder.engine_id = "replacement-engine"
            with self.assertRaisesRegex(model.Refused, "engine_changed"):
                client.stop("buildkit")
            self.assertEqual(self.reports(recorder), {})
            self.assertFalse(any(call[:2] == ["container", "stop"] for call in recorder.calls))

    def test_summary_never_exports_paths_labels_errors_or_unknown_text(self):
        value = {"State": {"Running": False, "ExitCode": 1, "OOMKilled": False,
            "Status": "exited", "Error": "/private/service-endpoint", "extra": "private-token"},
            "Mounts": ["/private/ledger"], "Config": {"Labels": {"secret": "private-token"}}}
        summary = engine.stop_state_summary(value)
        raw = json.dumps(summary)
        for private in ("/private/", "private-token", "Mounts", "Labels", "extra"):
            self.assertNotIn(private, raw)
        self.assertEqual(summary["error_class"], "nonempty")
        self.assertEqual(summary["fields"]["ExitCode"], 1)
        self.assertIn("Pid", summary["unavailable_fields"])

    def test_bad_types_are_reported_without_coercion_or_untrusted_values(self):
        for state in (None, [], "private-value", {"Running": 0, "ExitCode": True, "Pid": -1,
                      "Status": "private-value", "Error": {"secret": "private-value"}}):
            with self.subTest(state=state):
                report = engine.stop_state_summary({"State": state})
                self.assertEqual(report["fields"], {})
                self.assertEqual(len(report["unavailable_fields"]), 8)
                self.assertNotIn("private-value", json.dumps(report))

    @unittest.skipUnless(os.name == "posix", "Recorder durability is POSIX-only")
    def test_upload_keeps_stop_diagnostics_and_partial_build_reports_only(self):
        with tempfile.TemporaryDirectory(prefix="stop-state-regular-control-") as temporary:
            root = Path(temporary)
            record, transport = Recorder(root / "evidence"), Recorder(root / "transport")
            stop = "docker-028-inspect-buildkit-stop-state.json"
            for name in (stop, "image-build-node.json", "image-build-executor.json",
                         "docker-028-inspect-buildkit.stdout", "docker-028-inspect-foreign-stop-state.json"):
                record.seal(name, b"{}\n")
            transport.seal(stop, b"{}\n")
            rows = runner.evidence_index((record, transport), {})
            self.assertEqual({row["path"] for row in rows}, {
                "evidence/" + stop, "evidence/image-build-node.json", "evidence/image-build-executor.json"})
            self.assertTrue(all(row["sha256"] == hashlib.sha256(b"{}\n").hexdigest() for row in rows))


if __name__ == "__main__":
    unittest.main()
