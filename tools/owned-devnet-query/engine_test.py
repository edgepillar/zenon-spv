# SPDX-License-Identifier: GPL-3.0-only
"""Pure lifecycle-policy fixtures. No Docker client or daemon is contacted."""
import argparse
from copy import deepcopy
from pathlib import PurePosixPath
from pathlib import Path
import hashlib
import json
import sys
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True
HERE = __import__("pathlib").Path(__file__).absolute().parent
sys.path.insert(0, str(HERE))
import engine
import model
from process import CommandFailed


def fixture(contract, role="rpc"):
    admission = model.admit_engine(contract, "fixture-engine", "a" * 32, [], [], [])
    labels = model.labels(admission, role)
    memory, cpu = engine.resource_values(contract, role)
    value = {"Id": "b" * 64, "Image": "sha256:" + "c" * 64,
             "Config": {"Labels": labels, "User": "0:0" if role == "executor" else "9999:9999" if role == "gateway" else ""}, "RestartCount": 0,
             "State": {"Running": False, "Restarting": False, "Dead": False, "Pid": 0, "ExitCode": 0,
                       "Paused": False, "OOMKilled": False, "Status": "exited", "Error": ""},
             "HostConfig": {"Memory": memory, "MemorySwap": memory, "NanoCpus": cpu * 1_000_000,
                "PidsLimit": 256, "RestartPolicy": {"Name": "no"}, "AutoRemove": False,
                "Privileged": role in ("executor", "buildkit"), "CgroupnsMode": "private",
                "Init": role in ("executor", "gateway"), "NetworkMode": "fixture-network",
                "PidMode": "", "IpcMode": "private", "UTSMode": "",
                "SecurityOpt": ["no-new-privileges:true"] if role in ("executor", "gateway") else [],
                "PortBindings": {str(port) + "/tcp": [{"HostIp": "127.0.0.1", "HostPort": str(host)}]
                                 for host, port in engine.PORTS.get(role, ())},
                "LogConfig": {"Type": "json-file", "Config": {"max-size": "4m", "max-file": "2"}}},
             "Mounts": [{"Type": "volume", "Name": "spv-" + admission.nonce + "-rpc-data",
                         "Destination": "/root/.znn", "Source": "/owned-volume/_data", "RW": True}]}
    owned = model.record_created_container(admission, admission.engine_id, value,
            {"actual_exit": 0, "output_complete": True, "stdout": (value["Id"] + "\n").encode()})
    return admission, owned, value


class EngineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.contract = model.read_contract(HERE / "contract.json")

    def arguments(self, role):
        admission, _, _ = fixture(self.contract, role)
        volumes = {name: "spv-" + admission.nonce + "-" + name + "-data" for name in model.SERVICES}
        files = engine.RuntimeFiles(PurePosixPath("/owned/executor.json"), PurePosixPath("/owned/gateway.json"),
                                    PurePosixPath("/owned/public-fixture/executor-key"), b"{}", ())
        return engine.create_arguments(self.contract, admission, role, "sha256:" + "c" * 64,
                                       "d" * 64, volumes, files)

    def test_exact_seven_scoped_roles_have_bounded_resources_and_labels(self):
        for role in (*model.SERVICES, "buildkit"):
            with self.subTest(role=role):
                args = self.arguments(role)
                self.assertEqual(args[:2], ["container", "create"])
                self.assertEqual(args[args.index("--restart") + 1], "no")
                self.assertEqual(args[args.index("--memory") + 1], args[args.index("--memory-swap") + 1])
                self.assertEqual(args[args.index("--pids-limit") + 1], "256")
                self.assertIn(model.LABEL_SERVICE + "=" + role, args)
                self.assertIn(model.LABEL_OWNER + "=" + "a" * 32, args)
                self.assertFalse(any("docker.sock" in value for value in args))
                self.assertNotIn("--publish-all", args)

    def test_only_selected_loopback_ports_are_published(self):
        for role in (*model.SERVICES, "buildkit"):
            args = self.arguments(role)
            actual = [args[i + 1] for i, arg in enumerate(args) if arg == "--publish"]
            self.assertEqual(actual, [f"127.0.0.1:{host}:{port}" for host, port in engine.PORTS.get(role, ())])
            self.assertTrue(all(value.startswith("127.0.0.1:") for value in actual))

    def test_executor_and_gateway_keep_different_privilege_and_data_modes(self):
        executor, gateway = self.arguments("executor"), self.arguments("gateway")
        self.assertEqual(executor[executor.index("--user") + 1], "0:0")
        self.assertIn("--privileged", executor)
        self.assertEqual(executor[executor.index("--cgroupns") + 1], "private")
        self.assertIn("no-new-privileges:true", executor)
        self.assertEqual(gateway[gateway.index("--user") + 1], "9999:9999")
        self.assertNotIn("--privileged", gateway)
        self.assertIn("no-new-privileges:true", gateway)
        self.assertTrue(any("target=/var/lib/executor,readonly" in value for value in gateway))

    def test_extra_services_and_other_images_are_refused(self):
        admission, _, _ = fixture(self.contract)
        for role in ("console", "explorer", "executor-b", "observer"):
            with self.assertRaises(model.Refused):
                engine.create_arguments(self.contract, admission, role, "sha256:" + "c" * 64)
        with self.assertRaisesRegex(model.Refused, "service_image_identity"):
            engine.create_arguments(self.contract, admission, "buildkit", "moby/buildkit:latest")

    def test_bind_paths_cannot_inject_mount_csv_fields(self):
        for path in ("relative", "/owned,file", "/owned\nfile", "/owned\0file"):
            with self.subTest(path=repr(path)):
                with self.assertRaises(model.Refused):
                    engine._mount(PurePosixPath(path), "/target")

    def test_docker_environment_avoids_user_contexts_and_credentials(self):
        environment = engine.docker_environment({"PATH": "/system/bin", "HOME": "/foreign",
            "DOCKER_CONTEXT": "foreign", "DOCKER_HOST": "tcp://foreign", "GH_TOKEN": "fixture-token",
            "DOCKER_AUTH_CONFIG": "fixture-auth", "SSH_AUTH_SOCK": "/foreign-agent"}, "/owned/docker-config")
        for key in ("HOME", "DOCKER_CONTEXT", "GH_TOKEN", "DOCKER_AUTH_CONFIG", "SSH_AUTH_SOCK"):
            self.assertNotIn(key, environment)
        self.assertEqual(environment["DOCKER_HOST"], "unix:///var/run/docker.sock")
        self.assertEqual(environment["DOCKER_CONFIG"], "/owned/docker-config")

    def test_source_fixture_default_never_uses_an_environment_override(self):
        raw = b"#!/bin/sh\nexport EXECUTOR_KEY=" + b"1" * 64 + b"\n"
        self.assertEqual(engine.public_fixture_default(raw), b"1" * 64 + b"\n")
        for changed in (b"", raw + raw, raw.replace(b"1" * 64, b"0" * 64),
                        raw.replace(b"export EXECUTOR_KEY=", b"export EXECUTOR_KEY=${EXECUTOR_KEY:-") + b"}\n"):
            with self.assertRaises(model.Refused):
                engine.public_fixture_default(changed)

    def test_configured_limits_match_all_selected_roles(self):
        for role in (*model.SERVICES, "buildkit"):
            admission, owned, value = fixture(self.contract, role)
            self.assertTrue(engine.require_configured_limits(self.contract, admission, owned, value))

    def test_limit_restart_and_external_port_changes_refuse(self):
        admission, owned, original = fixture(self.contract, "executor")
        for keys, changed in ((["RestartCount"], 1), (["HostConfig", "Memory"], True),
                (["HostConfig", "MemorySwap"], 0), (["HostConfig", "NanoCpus"], 0),
                (["HostConfig", "PidsLimit"], 0), (["HostConfig", "Privileged"], False),
                (["HostConfig", "CgroupnsMode"], "host"), (["HostConfig", "SecurityOpt"], []),
                (["HostConfig", "Init"], False), (["Config", "User"], "another-user"),
                (["HostConfig", "NetworkMode"], "host"), (["HostConfig", "PidMode"], "host"),
                (["HostConfig", "IpcMode"], "host"), (["HostConfig", "UTSMode"], "host"),
                (["HostConfig", "AutoRemove"], True), (["HostConfig", "RestartPolicy", "Name"], "always"),
                (["HostConfig", "PortBindings"], {"80/tcp": [{"HostIp": "0.0.0.0", "HostPort": "80"}]}),
                (["HostConfig", "LogConfig", "Config", "max-size"], "unbounded")):
            value = deepcopy(original)
            selected = value
            for key in keys[:-1]:
                selected = selected[key]
            selected[keys[-1]] = changed
            with self.subTest(keys=keys):
                with self.assertRaises(model.Refused):
                    engine.require_configured_limits(self.contract, admission, owned, value)

    def test_closed_rpc_uses_the_same_owned_mount_and_exact_nom_subdirectory(self):
        admission, owned, value = fixture(self.contract)
        name = value["Mounts"][0]["Name"]
        self.assertEqual(engine.closed_nom_path(admission, owned, value, deepcopy(value), name),
                         "/owned-volume/_data/nom")
        for keys, changed in ((["State", "Running"], True), (["State", "Pid"], 1),
                (["State", "ExitCode"], 137), (["Mounts", 0, "Name"], "foreign"),
                (["Mounts", 0, "Source"], "/changed"), (["Mounts", 0, "RW"], False),
                (["Mounts", 0, "Type"], "bind")):
            closed = deepcopy(value)
            selected = closed
            for key in keys[:-1]:
                selected = selected[key]
            selected[keys[-1]] = changed
            with self.subTest(keys=keys):
                with self.assertRaises(model.Refused):
                    engine.closed_nom_path(admission, owned, value, closed, name)

    def test_changed_daemon_or_container_identity_cannot_authorize_closed_data(self):
        admission, owned, value = fixture(self.contract)
        changed = deepcopy(value)
        changed["Id"] = "d" * 64
        with self.assertRaises(model.Refused):
            engine.closed_nom_path(admission, owned, value, changed, value["Mounts"][0]["Name"])
        with self.assertRaises(model.Refused):
            model.require_owned_container(admission, owned, "another-engine", value)


class FixtureResult:
    def __init__(self, raw, complete=True):
        self.raw = raw
        self.receipt = {"actual_exit": 0, "output_complete": complete,
            "outputs": {"stdout": {"file": "fixture-only.stdout", "sha256": hashlib.sha256(raw).hexdigest(),
                                   "bytes": len(raw)}}}

    def stdout(self, limit=2 << 20):
        assert len(self.raw) <= limit
        return self.raw


class FixtureRecorder:
    """An in-memory response fixture, not execution or a command-evidence writer."""
    def __init__(self, contract):
        self.contract, self.calls, self.seals = contract, [], {}
        self.engine_id = "fixture-engine"
        self.containers, self.volumes, self.extra_ids = {}, set(), set()
        self.next_id = 1
        self.incomplete_create = self.bad_limits = False
        self.stop_exit_codes = {}

    def check(self):
        pass

    def seal(self, name, raw):
        assert name not in self.seals
        self.seals[name] = raw
        return {"file": name, "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}

    def run(self, label, argv, cwd, environment, **options):
        if options.get("guard"):
            options["guard"]()
        arguments = argv[1:]
        self.calls.append(arguments)
        complete = True
        if arguments[0] == "info":
            raw = model.canonical({"ID": self.engine_id, "OSType": "linux", "Architecture": "amd64"})
        elif arguments[:2] == ["container", "ls"]:
            values = sorted(set(self.containers) | self.extra_ids)
            raw = ("\n".join(values) + ("\n" if values else "")).encode()
        elif arguments[:2] in (["volume", "ls"], ["network", "ls"]):
            values = sorted(self.volumes) if arguments[0] == "volume" else []
            raw = ("\n".join(values) + ("\n" if values else "")).encode()
        elif arguments[:2] == ["network", "create"]:
            raw = b"e" * 64 + b"\n"
        elif arguments[:2] == ["volume", "create"]:
            self.volumes.add(arguments[-1])
            raw = (arguments[-1] + "\n").encode()
        elif arguments[:2] == ["container", "create"]:
            labels = dict(arguments[i + 1].split("=", 1) for i, value in enumerate(arguments) if value == "--label")
            role = labels[model.LABEL_SERVICE]
            _, _, value = fixture(self.contract, role)
            identity = f"{self.next_id:064x}"
            self.next_id += 1
            value["Id"], value["Config"]["Labels"] = identity, labels
            value["State"]["Status"] = "created"
            if role == "rpc":
                volume = "spv-" + labels[model.LABEL_OWNER] + "-rpc-data"
                value["Mounts"][0].update(Name=volume, Source="/fixture-volumes/" + volume + "/_data")
            else:
                value["Mounts"] = []
            if self.bad_limits:
                value["HostConfig"]["Memory"] -= 1
            self.containers[identity] = value
            raw = (identity + "\n").encode()
            complete = not self.incomplete_create
        elif arguments[:2] == ["container", "inspect"]:
            raw = model.canonical(self.containers[arguments[-1]])
        elif arguments[:2] == ["container", "start"]:
            value = self.containers[arguments[-1]]
            value["State"].update(Running=True, Pid=123, Status="running")
            raw = (arguments[-1] + "\n").encode()
        elif arguments[:2] == ["container", "stop"]:
            value = self.containers[arguments[-1]]
            role = value["Config"]["Labels"][model.LABEL_SERVICE]
            value["State"].update(Running=False, Pid=0, ExitCode=self.stop_exit_codes.get(role, 0), Status="exited")
            raw = (arguments[-1] + "\n").encode()
        elif arguments[:2] == ["container", "rm"]:
            del self.containers[arguments[-1]]
            raw = (arguments[-1] + "\n").encode()
        else:
            raise AssertionError("unexpected fixture request")
        result = FixtureResult(raw, complete)
        result.receipt["label"] = label
        if options.get("check", True) and not complete:
            raise CommandFailed(result)
        return result


class LifecycleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.contract = model.read_contract(HERE / "contract.json")

    def prepare(self, root):
        recorder = FixtureRecorder(self.contract)
        identity = model.ExecutionIdentity("e" * 40, 1, 1, "edgepillar")
        client = engine.Engine(self.contract, identity, recorder, root / "engine", ["fixture-docker"],
                               {"PATH": "/fixture/bin"}, lambda: None)
        with mock.patch.object(engine.platform, "system", return_value="Linux"), \
             mock.patch.object(engine.platform, "machine", return_value="x86_64"):
            client.probe()
        return client, recorder

    def runtime(self, root, client):
        client.create("buildkit", "sha256:" + "c" * 64)
        client.start("buildkit")
        client.close_builder()
        client.create_layout()
        paths = [root / name for name in ("executor.json", "gateway.json", "fixture-key")]
        for path in paths:
            path.write_bytes(b"synthetic fixture data\n")
        pins = {name: engine.regular_pin(path, 1024) for name, path in
                zip(("executor", "gateway", "fixture"), paths)}
        files = engine.RuntimeFiles(*paths, model.canonical(pins),
                                    tuple(engine._file_identity(path.stat()) for path in paths))
        # Validate the real fixture files on this host and serialize the
        # simulated Linux daemon's bind paths in its own path syntax.
        mount = engine._mount
        with mock.patch.object(engine, "_mount", side_effect=lambda path, target:
                               mount(PurePosixPath("/fixture-runtime", path.name), target)):
            for role in model.SERVICES:
                client.create(role, "sha256:" + "c" * 64, files)
                client.start(role)

    def test_builder_closes_before_six_services_and_rpc_freezes_to_its_own_nom(self):
        with tempfile.TemporaryDirectory(prefix="engine-regular-control-") as temporary:
            root = Path(temporary)
            client, recorder = self.prepare(root)
            self.runtime(root, client)
            self.assertTrue(client.require_running_closure())
            client.stop_producers_and_clients()
            ledger = client.close_rpc()
            self.assertEqual(ledger, "/fixture-volumes/spv-" + client.nonce + "-rpc-data/_data/nom")
            self.assertEqual(len(recorder.containers), 6)
            self.assertTrue(all(value["State"]["Running"] is False for value in recorder.containers.values()))
            self.assertFalse(any(call[:2] in (["volume", "rm"], ["image", "rm"], ["network", "rm"])
                                 for call in recorder.calls))

    def test_runtime_creation_refuses_before_builder_close(self):
        with tempfile.TemporaryDirectory(prefix="engine-regular-control-") as temporary:
            client, recorder = self.prepare(Path(temporary))
            with self.assertRaisesRegex(model.Refused, "builder_must_stop_before_runtime"):
                client.create("pillar", "sha256:" + "c" * 64)
            self.assertFalse(any(call[:2] == ["container", "create"] for call in recorder.calls))

    def test_incomplete_create_never_becomes_stop_authority_or_a_retry(self):
        with tempfile.TemporaryDirectory(prefix="engine-regular-control-") as temporary:
            client, recorder = self.prepare(Path(temporary))
            recorder.incomplete_create = True
            with self.assertRaises(CommandFailed):
                client.create("buildkit", "sha256:" + "c" * 64)
            self.assertEqual(client.owned, {})
            with self.assertRaisesRegex(model.Refused, "service_creation_already_attempted"):
                client.create("buildkit", "sha256:" + "c" * 64)
            client.cleanup()
            self.assertFalse(any(call[:2] == ["container", "stop"] for call in recorder.calls))

    def test_changed_daemon_refuses_stop_of_a_previous_id(self):
        with tempfile.TemporaryDirectory(prefix="engine-regular-control-") as temporary:
            client, recorder = self.prepare(Path(temporary))
            client.create("buildkit", "sha256:" + "c" * 64)
            client.start("buildkit")
            recorder.engine_id = "replacement-engine"
            with self.assertRaisesRegex(model.Refused, "engine_changed"):
                client.stop("buildkit")
            self.assertFalse(any(call[:2] == ["container", "stop"] for call in recorder.calls))

    def test_complete_create_retains_its_id_even_if_resource_validation_fails(self):
        with tempfile.TemporaryDirectory(prefix="engine-regular-control-") as temporary:
            client, recorder = self.prepare(Path(temporary))
            recorder.bad_limits = True
            with self.assertRaisesRegex(model.Refused, "container_resource_configuration"):
                client.create("buildkit", "sha256:" + "c" * 64)
            self.assertIn("buildkit", client.owned)
            client.cleanup()
            stops = [call[-1] for call in recorder.calls if call[:2] == ["container", "stop"]]
            self.assertEqual(stops, [client.owned["buildkit"].identity])

    def test_unowned_container_prevents_source_flow_and_cleanup_leaves_it_alone(self):
        with tempfile.TemporaryDirectory(prefix="engine-regular-control-") as temporary:
            root = Path(temporary)
            client, recorder = self.prepare(root)
            self.runtime(root, client)
            unowned = "f" * 64
            recorder.extra_ids.add(unowned)
            with self.assertRaisesRegex(model.Refused, "unowned_or_extra_container_observed"):
                client.require_running_closure()
            client.cleanup()
            stopped = [call[-1] for call in recorder.calls if call[:2] == ["container", "stop"]]
            self.assertNotIn(unowned, stopped)
            self.assertIn(unowned, recorder.extra_ids)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-revision")
    arguments = parser.parse_args()
    if arguments.source_revision is not None:
        model.digest(arguments.source_revision, model.HEX40)
    result = unittest.TextTestRunner(stream=sys.stderr, verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__]))
    sys.stdout.buffer.write(model.canonical({"format": "owned-devnet-query-engine-controls/v1",
        "source_revision": arguments.source_revision, "root_tests": result.testsRun,
        "errors": len(result.errors), "failures": len(result.failures), "skipped": len(result.skipped),
        "successful": result.wasSuccessful(), "synthetic_engine_inspections_only": True,
        "docker_contacted_or_container_or_wallet_or_signing_started": False}))
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
