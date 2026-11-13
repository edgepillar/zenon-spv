# SPDX-License-Identifier: GPL-3.0-only
"""Causal Docker lifecycle for the selected fresh, explicitly dispatched host.

This is not a host attestation or an operator approval. The outer controller
must check the explicit execution decision and dispatch/host/budget inputs first.
Only IDs returned by complete successful creates become cleanup authority.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path, PurePosixPath
import platform
import re
import secrets
import stat
import time

from artifacts import api_json
import model
from model import Refused, canonical, require
from process import CommandFailed, regular_pin
from sources import PreparedSources

NODE_ROLES = frozenset(("pillar", "pillar2", "pillar3", "rpc"))
ADDRESSES = {"pillar": "172.30.0.10", "rpc": "172.30.0.11",
             "pillar2": "172.30.0.12", "pillar3": "172.30.0.13"}
PORTS = {"pillar": ((35991, 35997),), "rpc": ((35997, 35997), (35998, 35998)),
         "gateway": ((35999, 35999),), "buildkit": ((12340, 1234),)}
GRACE = {"buildkit": 30, "pillar": 30, "pillar2": 30, "pillar3": 30,
         "rpc": 30, "executor": 45, "gateway": 15}
INFO_FORMAT = ('{"ID":{{json .ID}},"OSType":{{json .OSType}},'
               '"Architecture":{{json .Architecture}},"ServerVersion":{{json .ServerVersion}},'
               '"CgroupVersion":{{json .CgroupVersion}},"CgroupDriver":{{json .CgroupDriver}},'
               '"DockerRootDir":{{json .DockerRootDir}}}')
INSPECT_FORMAT = ('{"Id":{{json .Id}},"Image":{{json .Image}},'
                  '"RestartCount":{{json .RestartCount}},"Config":{"Labels":{{json .Config.Labels}},"User":{{json .Config.User}}},'
                  '"State":{{json .State}},"HostConfig":{{json .HostConfig}},'
                  '"Mounts":{{json .Mounts}}}')
STOP_STATE_FILE = re.compile(
    r"docker-[0-9]{3,6}-inspect-(?:buildkit|pillar|pillar2|pillar3|rpc|executor|gateway)-stop-state\.json\Z")


def stop_state_summary(value):
    """Keep bounded state diagnostics without exporting arbitrary inspect text."""
    state = value.get("State")
    fields, unavailable = {}, []
    checks = {name: lambda v: type(v) is bool
              for name in ("Running", "Restarting", "Dead", "OOMKilled", "Paused")}
    checks.update(Pid=lambda v: type(v) is int and 0 <= v <= 2 ** 31 - 1,
                  ExitCode=lambda v: type(v) is int and -1 <= v <= 255,
                  Status=lambda v: type(v) is str and v in (
                      "created", "running", "paused", "restarting", "removing", "exited", "dead"))
    for name, valid in checks.items():
        if type(state) is dict and name in state and valid(state[name]):
            fields[name] = state[name]
        else:
            unavailable.append(name)
    error = "missing"
    if type(state) is dict and "Error" in state:
        error = (("empty" if state["Error"] == "" else "nonempty")
                 if type(state["Error"]) is str else "invalid")
    return {"state_is_object": type(state) is dict, "fields": fields,
            "unavailable_fields": sorted(unavailable), "error_class": error}


def docker_environment(base, configuration):
    require(type(base) is dict and type(base.get("PATH")) is str and base["PATH"],
            "docker_command_environment")
    environment = {key: base[key] for key in ("PATH", "LANG", "LC_ALL", "TMPDIR")
                   if key in base and type(base[key]) is str}
    environment.update({"DOCKER_CONFIG": str(configuration),
                        "DOCKER_HOST": "unix:///var/run/docker.sock",
                        "DOCKER_DEFAULT_PLATFORM": "linux/amd64", "DOCKER_BUILDKIT": "1",
                        "NO_COLOR": "1", "TERM": "dumb"})
    return environment


def public_fixture_default(raw):
    require(type(raw) is bytes and len(raw) <= 64 << 10, "fixture_source_bound")
    matches = re.findall(rb"(?m)^export EXECUTOR_KEY=([0-9a-f]{64})$", raw)
    require(len(matches) == 1 and matches[0] != b"0" * 64, "fixture_source_default")
    # This selects only the committed public fixture. It never consults an
    # inherited EXECUTOR_KEY, keystore, wallet or user-supplied secret.
    return matches[0] + b"\n"


def _file_identity(info):
    return info.st_dev, info.st_ino, info.st_uid, info.st_size, info.st_mtime_ns


@dataclass(frozen=True)
class RuntimeFiles:
    executor: Path
    gateway: Path
    fixture: Path
    pins_raw: bytes
    identities: tuple

    def verify(self):
        import json
        pins = json.loads(self.pins_raw)
        require(type(pins) is dict and set(pins) == {"executor", "gateway", "fixture"}
                and len(self.identities) == 3, "runtime_file_snapshot")
        for name, path, identity in zip(("executor", "gateway", "fixture"),
                                        (self.executor, self.gateway, self.fixture), self.identities):
            require(_file_identity(path.lstat()) == identity, "runtime_file_replaced")
            require(regular_pin(path, 64 << 10) == pins[name], "runtime_file_content")
        return pins


def _mount(path, target):
    text = str(path)
    require(PurePosixPath(text).is_absolute() and all(value not in text for value in (",", "\n", "\r", "\0")),
            "runtime_bind_path")
    return "type=bind,src=" + text + ",target=" + target + ",readonly"


def resource_values(contract, role):
    require(role in (*model.SERVICES, "buildkit"), "service_scope")
    limits = contract.data["limits"]
    prefix = "node" if role in NODE_ROLES else "builder" if role == "buildkit" else role
    return limits[prefix + "_memory_bytes"], limits[prefix + "_cpu_millis"]


def create_arguments(contract, admission, role, image, network=None, volumes=None, files=None):
    memory, cpu = resource_values(contract, role)
    require(type(image) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", image) is not None,
            "service_image_identity")
    labels = model.labels(admission, role)
    name = "spv-" + admission.nonce + "-" + role
    arguments = ["container", "create", "--name", name, "--platform", "linux/amd64",
        "--pull", "never", "--restart", "no", "--memory", str(memory), "--memory-swap", str(memory),
        "--cpus", str(cpu // 1000) if cpu % 1000 == 0 else f"{cpu / 1000:.3f}".rstrip("0"),
        "--pids-limit", str(contract.data["limits"]["pids_per_service"]),
        "--stop-timeout", str(GRACE[role]), "--log-driver", "json-file",
        "--log-opt", "max-size=4m", "--log-opt", "max-file=2"]
    for key, value in sorted(labels.items()):
        arguments.extend(("--label", key + "=" + value))
    for host, container in PORTS.get(role, ()):
        arguments.extend(("--publish", f"127.0.0.1:{host}:{container}"))
    if role == "buildkit":
        arguments += ["--privileged", "--cgroupns", "private", image,
                      "--addr", "tcp://0.0.0.0:1234"]
        return arguments
    require(type(network) is str and re.fullmatch(r"[0-9a-f]{64}", network) is not None
            and type(volumes) is dict and set(volumes) == set(model.SERVICES), "runtime_layout")
    require(all(type(value) is str and value == "spv-" + admission.nonce + "-" + name + "-data"
                for name, value in volumes.items()), "runtime_volume_names")
    arguments += ["--network", network, "--network-alias", role]
    if role in NODE_ROLES:
        arguments += ["--ip", ADDRESSES[role], "--env", "GOMAXPROCS=1", "--env", "ZNND_ROLE=" + role,
                      "--mount", "type=volume,src=" + volumes[role] + ",target=/root/.znn", image]
        return arguments
    require(type(files) is RuntimeFiles, "runtime_files")
    arguments += ["--init", "--security-opt", "no-new-privileges:true"]
    if role == "executor":
        arguments += ["--user", "0:0", "--privileged", "--cgroupns", "private",
            "--mount", "type=volume,src=" + volumes["executor"] + ",target=/var/lib/executor",
            "--mount", _mount(files.executor, "/etc/executor/executor.json"),
            "--mount", _mount(files.fixture, "/run/secrets/executor_key"), image,
            "-config", "/etc/executor/executor.json"]
    else:
        arguments += ["--user", "9999:9999", "--env", "GOMAXPROCS=2", "--entrypoint", "gateway",
            "--mount", "type=volume,src=" + volumes["executor"] + ",target=/var/lib/executor,readonly",
            "--mount", "type=volume,src=" + volumes["gateway"] + ",target=/var/lib/gateway",
            "--mount", _mount(files.gateway, "/etc/gateway/gateway.json"), image,
            "-config", "/etc/gateway/gateway.json"]
    return arguments


def require_configured_limits(contract, admission, owned, value):
    model.require_owned_container(admission, owned, admission.engine_id, value)
    host = value.get("HostConfig")
    require(type(host) is dict, "container_host_configuration")
    memory, cpu = resource_values(contract, owned.service)
    for key, expected in (("Memory", memory), ("MemorySwap", memory), ("NanoCpus", cpu * 1_000_000),
                          ("PidsLimit", contract.data["limits"]["pids_per_service"])):
        require(type(host.get(key)) is int and host[key] == expected, "container_resource_configuration")
    require(type(value.get("RestartCount")) is int and value["RestartCount"] == 0,
            "container_restart_observed")
    require(host.get("RestartPolicy", {}).get("Name") == "no" and host.get("AutoRemove") is False,
            "container_lifecycle_configuration")
    require(host.get("Privileged") is (owned.service in ("executor", "buildkit")),
            "container_privilege_configuration")
    if owned.service in ("executor", "buildkit"):
        require(host.get("CgroupnsMode") == "private", "container_cgroup_namespace")
    if owned.service in ("executor", "gateway"):
        require("no-new-privileges:true" in (host.get("SecurityOpt") or []), "container_no_new_privileges")
        require(host.get("Init") is True and value["Config"].get("User")
                == ("0:0" if owned.service == "executor" else "9999:9999"),
                "container_uid_or_init_configuration")
    require(all(host.get(field) != "host" for field in ("NetworkMode", "PidMode", "IpcMode", "UTSMode")),
            "container_host_namespace")
    require(not any(row.get("Source") in ("/var/run/docker.sock", "/run/docker.sock")
                    or row.get("Destination") in ("/var/run/docker.sock", "/run/docker.sock")
                    for row in value.get("Mounts", [])), "host_docker_socket_mount")
    wanted = {str(container) + "/tcp": [{"HostIp": "127.0.0.1", "HostPort": str(host_port)}]
              for host_port, container in PORTS.get(owned.service, ())}
    require((host.get("PortBindings") or {}) == wanted, "container_port_configuration")
    logging = host.get("LogConfig")
    require(type(logging) is dict and logging.get("Type") == "json-file"
            and logging.get("Config") == {"max-size": "4m", "max-file": "2"},
            "container_log_configuration")
    return True


def closed_nom_path(admission, owned, original, closed, volume_name):
    require(owned.service == "rpc", "closed_rpc_service")
    model.require_stopped_container(admission, owned, admission.engine_id, closed)
    mounts = [row for row in closed.get("Mounts", []) if row.get("Destination") == "/root/.znn"]
    require(len(mounts) == 1 and mounts[0].get("Type") == "volume"
            and mounts[0].get("Name") == volume_name and mounts[0].get("RW") is True
            and mounts[0] in original.get("Mounts", []), "closed_rpc_volume_binding")
    source = mounts[0].get("Source")
    require(type(source) is str and 0 < len(source) <= 1024
            and all(value not in source for value in ("\0", "\n", "\r", "\\")), "closed_rpc_volume_path")
    path = PurePosixPath(source)
    require(path.is_absolute() and ".." not in path.parts, "closed_rpc_volume_path")
    # The pinned app/action_state_tree.go opens <DataPath>/nom directly.
    return str(path / "nom")


class Engine:
    def __init__(self, contract, execution, recorder, directory, command, base_environment, guard):
        require(type(execution) is model.ExecutionIdentity and callable(guard), "engine_execution_context")
        require(type(command) is list and command and all(type(a) is str for a in command), "docker_command")
        self.contract, self.execution, self.recorder = contract, execution, recorder
        self.root = Path(directory)
        require(not self.root.exists() and not self.root.is_symlink(), "engine_workspace_exists")
        self.root.mkdir(mode=0o700)
        root_info = self.root.lstat()
        self.root_identity = root_info.st_dev, root_info.st_ino, root_info.st_uid
        configuration = self.root / "docker-config"
        configuration.mkdir(mode=0o700)
        config_info = configuration.lstat()
        self.configuration_identity = config_info.st_dev, config_info.st_ino, config_info.st_uid
        temporary = self.root / "docker-tmp"
        temporary.mkdir(mode=0o700)
        with (configuration / "config.json").open("xb") as stream:
            stream.write(canonical({"auths": {}}))
        (configuration / "config.json").chmod(0o600)
        self.environment = docker_environment(base_environment, configuration)
        self.environment["TMPDIR"] = str(temporary)
        self.command, self.guard = list(command), guard
        self.nonce, self.counter = secrets.token_hex(16), 0
        self.admission = None
        self.docker_root = None
        self.owned, self.inspected_at_create, self.started, self.attempted = {}, {}, set(), set()
        self.expected_images = {}
        self.volumes, self.network = {}, None
        self.builder_closed = False
        self.probe_attempted = False
        self.layout_attempted = False
        self.cleanup_deadline = None

    def _run(self, label, arguments, *, timeout=60, cleanup=False, check=True,
             stdout_cap=128 << 10, stderr_cap=128 << 10):
        self.recorder.check()
        root_info = self.root.lstat()
        config_info = Path(self.environment["DOCKER_CONFIG"]).lstat()
        require(stat.S_ISDIR(root_info.st_mode) and stat.S_ISDIR(config_info.st_mode)
                and (root_info.st_dev, root_info.st_ino, root_info.st_uid) == self.root_identity
                and (config_info.st_dev, config_info.st_ino, config_info.st_uid) == self.configuration_identity,
                "engine_workspace_changed")
        self.counter += 1
        # Cleanup is a bounded control lane, not permission for new allocation.
        if cleanup:
            require(arguments[:2] in (["container", "inspect"], ["container", "stop"],
                    ["container", "rm"]) or arguments[:1] == ["info"], "cleanup_command_scope")
            if self.cleanup_deadline is not None:
                remaining = self.cleanup_deadline - time.monotonic()
                require(remaining > 0, "owned_cleanup_deadline")
                timeout = min(timeout, remaining)
        return self.recorder.run("docker-" + str(self.counter).zfill(3) + "-" + label,
            [*self.command, *arguments], self.root, self.environment, timeout=timeout,
            stdout_cap=stdout_cap, stderr_cap=stderr_cap,
            guard=None if cleanup else self.guard, check=check)

    def _info(self, cleanup=False):
        result = self._run("engine-info", ["info", "--format", INFO_FORMAT], cleanup=cleanup)
        info = api_json(result.stdout(128 << 10))
        require(info.get("OSType") == "linux" and info.get("Architecture") in ("amd64", "x86_64"),
                "docker_linux_amd64_required")
        if self.admission is not None:
            require(info.get("ID") == self.admission.engine_id, "engine_changed")
        return info

    def probe(self):
        require(not self.probe_attempted, "engine_probe_already_attempted")
        self.probe_attempted = True
        require(platform.system() == "Linux" and platform.machine() in ("x86_64", "amd64"),
                "native_linux_host_required")
        self.guard()
        info = self._info()
        containers = self._run("initial-containers", ["container", "ls", "--all", "--quiet", "--no-trunc"]).stdout()
        require(containers == b"", "fresh_engine_required")
        project = "label=" + model.LABEL_PROJECT + "=" + model.PROJECT
        volumes = self._run("initial-project-volumes", ["volume", "ls", "--quiet", "--filter", project]).stdout()
        networks = self._run("initial-project-networks", ["network", "ls", "--quiet", "--filter", project]).stdout()
        self.admission = model.admit_engine(self.contract, info.get("ID"), self.nonce, [],
            [model.PROJECT] if volumes else [], [model.PROJECT] if networks else [])
        self.docker_root = info.get("DockerRootDir")
        self.recorder.seal("engine-admission.json", canonical({"format": "owned-devnet-engine-admission/v1",
            "engine_id": self.admission.engine_id, "nonce": self.nonce,
            "contract_sha256": self.contract.sha256, "host_attested": False,
            "preexisting_containers": 0, "preexisting_project_resources": 0}))
        return self.admission

    def _inspect(self, owned, cleanup=False, retain_stop=False):
        require(self.admission is not None, "engine_not_admitted")
        self._info(cleanup=cleanup)
        result = self._run("inspect-" + owned.service,
            ["container", "inspect", "--format", INSPECT_FORMAT, owned.identity], cleanup=cleanup)
        raw = result.stdout(128 << 10)
        value = api_json(raw)
        model.require_owned_container(self.admission, owned, self.admission.engine_id, value)
        if retain_stop:
            name = result.receipt["label"] + "-stop-state.json"
            require(STOP_STATE_FILE.fullmatch(name) is not None, "stop_state_filename")
            self.recorder.seal(name, canonical({"format": "owned-devnet-stop-state/v1",
                "service": owned.service, "container_id": owned.identity,
                "inspection_command": result.receipt["label"],
                "inspection_stdout": {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)},
                "cleanup": cleanup, "state": stop_state_summary(value),
                "diagnostic_only": True, "runtime_acceptance_established": False}))
        if not cleanup:
            require(value.get("Image") == self.expected_images[owned.service], "container_image_changed")
        return value

    def prepare_files(self, sources):
        require(self.admission is not None and type(sources) is PreparedSources, "runtime_source_context")
        sources.verify()
        script = sources.paths["devnet"] / "scripts/devnet.sh"
        pin = next(row for row in self.contract.data["source_files"]
                   if row["role"] == "devnet" and row["path"] == "scripts/devnet.sh")
        require(regular_pin(script, 64 << 10) == {k: pin[k] for k in ("sha256", "bytes")},
                "fixture_source_binding")
        raw = public_fixture_default(script.read_bytes())
        self.guard()
        directory = self.root / "public-fixture"
        directory.mkdir(mode=0o700)
        path = directory / "executor-key"
        with path.open("xb") as stream:
            stream.write(raw)
        path.chmod(0o400)
        selected = (sources.paths["devnet"] / "config/executor.json",
                    sources.paths["devnet"] / "config/gateway.json", path)
        pins = {name: regular_pin(value, 64 << 10) for name, value in
                zip(("executor", "gateway", "fixture"), selected)}
        files = RuntimeFiles(*selected, canonical(pins), tuple(_file_identity(p.lstat()) for p in selected))
        files.verify()
        self.recorder.seal("runtime-input-pins.json", canonical({"format": "owned-devnet-runtime-inputs/v1",
            "pins": pins, "fixture_source": {k: pin[k] for k in ("sha256", "bytes", "git_blob")},
            "user_environment_key_selected": False, "fixture_plaintext_published": False}))
        return files

    def create_layout(self):
        require(self.admission is not None and not self.layout_attempted,
                "runtime_layout_already_attempted")
        self.layout_attempted = True
        self._info()
        name = "spv-" + self.nonce + "-devnet"
        created = self._run("create-network", ["network", "create", "--driver", "bridge",
            "--subnet", "172.30.0.0/24", "--label", model.LABEL_OWNER + "=" + self.nonce,
            "--label", model.LABEL_CONTRACT + "=" + self.contract.sha256,
            "--label", model.LABEL_PROJECT + "=" + model.PROJECT, name])
        self.network = model.creation_identity({"actual_exit": created.receipt["actual_exit"],
            "output_complete": created.receipt["output_complete"], "stdout": created.stdout(128)})
        for role in model.SERVICES:
            self._info()
            volume = "spv-" + self.nonce + "-" + role + "-data"
            existing = self._run("volume-inventory", ["volume", "ls", "--quiet"]).stdout().decode("ascii").splitlines()
            require(volume not in existing, "runtime_volume_exists")
            receipt = self._run("create-volume-" + role, ["volume", "create",
                "--label", model.LABEL_OWNER + "=" + self.nonce,
                "--label", model.LABEL_CONTRACT + "=" + self.contract.sha256,
                "--label", model.LABEL_PROJECT + "=" + model.PROJECT, volume])
            require(receipt.stdout(256) == (volume + "\n").encode("ascii"), "runtime_volume_creation")
            self.volumes[role] = volume
        self.recorder.seal("runtime-layout.json", canonical({"format": "owned-devnet-layout/v1",
            "network_id": self.network, "volumes": self.volumes,
            "manual_volume_image_or_network_removal_authorized": False}))

    def create(self, role, image, files=None):
        require(self.admission is not None and role not in self.attempted, "service_creation_already_attempted")
        require(role in (*model.SERVICES, "buildkit"), "service_scope")
        if role in model.SERVICES:
            require(self.builder_closed, "builder_must_stop_before_runtime")
        if role in ("executor", "gateway"):
            require(type(files) is RuntimeFiles, "runtime_files")
            files.verify()
        self.attempted.add(role)
        self._info()
        arguments = create_arguments(self.contract, self.admission, role, image, self.network, self.volumes, files)
        created = self._run("create-" + role, arguments)
        receipt = {"actual_exit": created.receipt["actual_exit"],
                   "output_complete": created.receipt["output_complete"], "stdout": created.stdout(256)}
        identity = model.creation_identity(receipt)
        result = self._run("created-inspect-" + role,
            ["container", "inspect", "--format", INSPECT_FORMAT, identity])
        value = api_json(result.stdout(128 << 10))
        owned = model.record_created_container(self.admission, self._info()["ID"], value, receipt)
        self.owned[role], self.inspected_at_create[role] = owned, value
        self.expected_images[role] = image
        self.recorder.seal("created-" + role + ".json", canonical({"format": "owned-devnet-created-container/v1",
            "id": identity, "service": role, "engine_id": self.admission.engine_id,
            "contract_sha256": self.contract.sha256, "nonce": self.nonce,
            "expected_image_id": image, "creation_stdout": created.receipt["outputs"]["stdout"]}))
        require(value.get("Image") == image, "container_image_changed")
        require_configured_limits(self.contract, self.admission, owned, value)
        return owned

    def start(self, role):
        require(role in self.owned and role not in self.started, "service_start_scope")
        owned = self.owned[role]
        before = self._inspect(owned)
        require(before["State"]["Running"] is False, "service_already_running")
        self._run("start-" + role, ["container", "start", owned.identity])
        value = self._inspect(owned)
        require_configured_limits(self.contract, self.admission, owned, value)
        require(value["State"]["Running"] is True and type(value["State"].get("Pid")) is int
                and value["State"]["Pid"] > 0, "service_not_running")
        self.started.add(role)

    def stop(self, role, cleanup=False):
        require(role in self.owned, "service_stop_scope")
        owned = self.owned[role]
        self._inspect(owned, cleanup=cleanup)
        self._run("stop-" + role, ["container", "stop", "--time", str(GRACE[role]), owned.identity],
                  timeout=GRACE[role] + 15, cleanup=cleanup)
        value = self._inspect(owned, cleanup=cleanup, retain_stop=True)
        stopped = model.require_stopped_builder if role == "buildkit" else model.require_stopped_container
        stopped(self.admission, owned, self.admission.engine_id, value)
        require_configured_limits(self.contract, self.admission, owned, value)
        return value

    def close_builder(self):
        require("buildkit" in self.started and not self.builder_closed, "builder_close_scope")
        stopped = self.stop("buildkit")
        owned = self.owned["buildkit"]
        value = self._inspect(owned, retain_stop=True)
        model.require_stopped_builder(self.admission, owned, self.admission.engine_id, value)
        require_configured_limits(self.contract, self.admission, owned, value)
        require(value["State"]["ExitCode"] == stopped["State"]["ExitCode"], "builder_stop_observation_changed")
        self._run("remove-buildkit", ["container", "rm", owned.identity])
        del self.owned["buildkit"]
        self.builder_closed = True
        return {"policy": "owned-buildkit-quiescence/v1", "exit_code": value["State"]["ExitCode"],
                "runtime_ledger_closure_established": False}

    def stop_producers_and_clients(self):
        require(set(model.SERVICES) <= self.started, "runtime_was_not_fully_started")
        for role in ("gateway", "executor", "pillar3", "pillar2", "pillar"):
            self.stop(role)
        # RPC remains alive only for the bounded final header/proof capture.

    def require_running_closure(self, roles=model.SERVICES):
        selected = frozenset(roles)
        require(selected in (NODE_ROLES, frozenset(model.SERVICES)) and selected <= set(self.owned)
                and selected <= self.started, "running_closure_scope")
        self._info()
        result = self._run("running-closure-inventory", ["container", "ls", "--all", "--quiet", "--no-trunc"])
        raw = result.stdout().decode("ascii").splitlines()
        identities = {model.digest(identity) for identity in raw}
        require(len(identities) == len(raw) and identities == {self.owned[r].identity for r in selected},
                "unowned_or_extra_container_observed")
        for role in roles:
            value = self._inspect(self.owned[role])
            require_configured_limits(self.contract, self.admission, self.owned[role], value)
            state = value.get("State")
            require(type(state) is dict and state.get("Running") is True
                    and type(state.get("Pid")) is int and state["Pid"] > 0,
                    "runtime_service_not_running")
        return True

    def close_rpc(self):
        require(set(model.SERVICES) <= self.started, "runtime_was_not_fully_started")
        self.stop("rpc")
        return self.closed_ledger()

    def closed_ledger(self):
        require(set(self.owned) == set(model.SERVICES)
                and set(model.SERVICES) <= self.started, "runtime_was_not_fully_started")
        roster = self._run("closed-closure-inventory",
                           ["container", "ls", "--all", "--quiet", "--no-trunc"]).stdout()
        rows = roster.decode("ascii").splitlines()
        require(len(rows) == len(model.SERVICES)
                and set(rows) == {item.identity for item in self.owned.values()},
                "closed_runtime_roster_changed")
        values = [self._inspect(self.owned[role]) for role in model.SERVICES]
        model.require_runtime_closure(self.admission, [self.owned[r] for r in model.SERVICES],
                                      self.admission.engine_id, values)
        for role, value in zip(model.SERVICES, values):
            model.require_stopped_container(self.admission, self.owned[role], self.admission.engine_id, value)
        # The pinned node's offline reader opens <DataPath>/nom directly.
        # Do not create, copy, initialize or append another ledger directory.
        return closed_nom_path(self.admission, self.owned["rpc"], self.inspected_at_create["rpc"],
                               values[model.SERVICES.index("rpc")], self.volumes["rpc"])

    def cleanup(self):
        require(self.cleanup_deadline is None, "owned_cleanup_already_attempted")
        self.cleanup_deadline = time.monotonic() + 300
        results = []
        for role in reversed(tuple(self.owned)):
            try:
                self.stop(role, cleanup=True)
                results.append({"service": role, "id": self.owned[role].identity, "observed_closed": True})
            except (Refused, OSError, KeyError, ValueError) as error:
                results.append({"service": role, "id": self.owned[role].identity,
                    "observed_closed": False, "error_type": type(error).__name__})
        self.recorder.seal("owned-container-cleanup.json", canonical({"format": "owned-devnet-cleanup/v1",
            "containers": results, "volume_image_or_network_removal_performed": False,
            "maximum_cleanup_seconds": 300,
            "disposal_boundary": "FRESH_HOSTED_VM", "unresolved_results_remain_unqualified": True}))
        return results
