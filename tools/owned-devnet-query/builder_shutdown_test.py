# SPDX-License-Identifier: GPL-3.0-only
"""Builder-only exit policy; all daemon replies are in-memory fixtures."""
from copy import deepcopy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True
HERE = Path(__file__).absolute().parent
sys.path.insert(0, str(HERE))
import engine
from engine_test import FixtureRecorder, fixture
import model


class BuilderShutdownTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.contract = model.read_contract(HERE / "reference-gas-contract.json")

    def builder(self):
        return fixture(self.contract, "buildkit")

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

    def test_zero_and_declared_signal_exit_need_the_same_owned_quiescent_builder(self):
        admission, owned, value = self.builder()
        for code in (0, 1):
            with self.subTest(code=code):
                value["State"]["ExitCode"] = code
                self.assertEqual(model.require_stopped_builder(admission, owned, admission.engine_id, value), owned.identity)

    def test_forced_unknown_and_coerced_exit_codes_are_refused(self):
        admission, owned, value = self.builder()
        for code in (True, False, "1", 1.0, -1, 2, 137, 143, 255, None):
            with self.subTest(code=code):
                value["State"]["ExitCode"] = code
                with self.assertRaisesRegex(model.Refused, "builder_not_quiescent_after_stop"):
                    model.require_stopped_builder(admission, owned, admission.engine_id, value)

    def test_alive_oom_error_missing_and_invalid_state_fields_are_refused(self):
        admission, owned, original = self.builder()
        cases = (("Running", True), ("Restarting", True), ("Dead", True), ("Paused", True),
                 ("OOMKilled", True), ("Pid", 1), ("Pid", False), ("Error", "runtime error"),
                 ("Error", None), ("Status", "created"), ("Status", "running"))
        for name, changed in cases:
            value = deepcopy(original)
            value["State"].update(ExitCode=1)
            value["State"][name] = changed
            with self.subTest(field=name, changed=changed):
                with self.assertRaises(model.Refused):
                    model.require_stopped_builder(admission, owned, admission.engine_id, value)
        for name in original["State"]:
            value = deepcopy(original)
            del value["State"][name]
            with self.subTest(missing=name):
                with self.assertRaises(model.Refused):
                    model.require_stopped_builder(admission, owned, admission.engine_id, value)

    def test_all_six_runtime_services_keep_zero_exit_and_cannot_use_builder_scope(self):
        for role in model.SERVICES:
            admission, owned, value = fixture(self.contract, role)
            with self.subTest(role=role):
                model.require_stopped_container(admission, owned, admission.engine_id, value)
                with self.assertRaisesRegex(model.Refused, "builder_stop_scope"):
                    model.require_stopped_builder(admission, owned, admission.engine_id, value)
                value["State"]["ExitCode"] = 1
                with self.assertRaisesRegex(model.Refused, "container_not_gracefully_stopped"):
                    model.require_stopped_container(admission, owned, admission.engine_id, value)

    def test_replaced_owner_container_and_daemon_cannot_use_signal_exit(self):
        admission, owned, original = self.builder()
        for key, changed in (("Id", "d" * 64), ("label", "d" * 32), ("daemon", "foreign-engine")):
            value = deepcopy(original)
            value["State"]["ExitCode"] = 1
            daemon = admission.engine_id
            if key == "label":
                value["Config"]["Labels"][model.LABEL_OWNER] = changed
            elif key == "daemon":
                daemon = changed
            else:
                value[key] = changed
            with self.subTest(changed=key):
                with self.assertRaises(model.Refused):
                    model.require_stopped_builder(admission, owned, daemon, value)

    def test_signal_exit_is_recorded_and_only_the_exact_builder_id_is_removed(self):
        with tempfile.TemporaryDirectory(prefix="builder-stop-regular-control-") as temporary:
            client, recorder = self.prepare(Path(temporary))
            identity = client.owned["buildkit"].identity
            recorder.stop_exit_codes["buildkit"] = 1
            closed = client.close_builder()
            self.assertEqual(closed["exit_code"], 1)
            self.assertIs(closed["runtime_ledger_closure_established"], False)
            self.assertTrue(client.builder_closed)
            self.assertNotIn("buildkit", client.owned)
            self.assertIn(["container", "rm", identity], recorder.calls)
            self.assertFalse(any("--force" in call or "prune" in call for call in recorder.calls))
            reports = [json.loads(value) for name, value in recorder.seals.items()
                       if engine.STOP_STATE_FILE.fullmatch(name)]
            self.assertEqual(len(reports), 2)
            self.assertTrue(all(report["state"]["fields"]["ExitCode"] == 1 for report in reports))

    def test_changed_final_exit_observation_cannot_select_a_favorable_result(self):
        with tempfile.TemporaryDirectory(prefix="builder-stop-regular-control-") as temporary:
            client, recorder = self.prepare(Path(temporary))
            recorder.stop_exit_codes["buildkit"] = 1
            original, reads = recorder.run, []

            def changed(label, argv, *args, **kwargs):
                if argv[1:3] == ["container", "inspect"]:
                    state = recorder.containers[argv[-1]]["State"]
                    if state["Status"] == "exited":
                        reads.append(label)
                        if len(reads) == 2:
                            state["ExitCode"] = 0
                return original(label, argv, *args, **kwargs)

            with mock.patch.object(recorder, "run", side_effect=changed):
                with self.assertRaisesRegex(model.Refused, "builder_stop_observation_changed"):
                    client.close_builder()
            self.assertFalse(client.builder_closed)
            self.assertFalse(any(call[:2] == ["container", "rm"] for call in recorder.calls))
            reports = [json.loads(value) for name, value in recorder.seals.items()
                       if engine.STOP_STATE_FILE.fullmatch(name)]
            self.assertEqual([report["state"]["fields"]["ExitCode"] for report in reports], [1, 0])

    def test_resource_change_in_either_stopped_observation_prevents_handoff(self):
        for changed_read in (1, 2):
            with self.subTest(changed_read=changed_read), tempfile.TemporaryDirectory(prefix="builder-stop-regular-control-") as temporary:
                client, recorder = self.prepare(Path(temporary))
                recorder.stop_exit_codes["buildkit"] = 1
                original, reads = recorder.run, []

                def changed(label, argv, *args, **kwargs):
                    if argv[1:3] == ["container", "inspect"]:
                        value = recorder.containers[argv[-1]]
                        if value["State"]["Status"] == "exited":
                            reads.append(label)
                            if len(reads) == changed_read:
                                value["HostConfig"]["Memory"] += 1
                    return original(label, argv, *args, **kwargs)

                with mock.patch.object(recorder, "run", side_effect=changed):
                    with self.assertRaisesRegex(model.Refused, "container_resource_configuration"):
                        client.close_builder()
                self.assertFalse(client.builder_closed)
                self.assertFalse(any(call[:2] == ["container", "rm"] for call in recorder.calls))

    def test_runtime_nonzero_stop_keeps_the_original_zero_exit_refusal(self):
        with tempfile.TemporaryDirectory(prefix="builder-stop-regular-control-") as temporary:
            client, recorder = self.prepare(Path(temporary))
            client.close_builder()
            client.create_layout()
            client.create("rpc", "sha256:" + "c" * 64)
            client.start("rpc")
            recorder.stop_exit_codes["rpc"] = 1
            with self.assertRaisesRegex(model.Refused, "container_not_gracefully_stopped"):
                client.stop("rpc")
            self.assertTrue(client.builder_closed)


if __name__ == "__main__":
    unittest.main()
