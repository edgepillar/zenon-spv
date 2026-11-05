#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read-only Linux resource observations for a separately authorized devnet."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import selectors
import shutil
import subprocess
import sys
import time

GIB = 1 << 30
FORMAT = "zenon-devnet-resource-preflight/v1"
SCOPE = "READ_ONLY_RESOURCE_OBSERVATION"
MAX_OUTPUT = 16384


class Refusal(ValueError):
    pass


def integer(raw):
    if type(raw) is not str or re.fullmatch(r"0|[1-9][0-9]{0,18}", raw) is None:
        raise argparse.ArgumentTypeError("invalid integer")
    value = int(raw)
    if value > (1 << 63) - 1:
        raise argparse.ArgumentTypeError("invalid integer")
    return value


def uint(value):
    if type(value) is not int or not 0 <= value <= (1 << 63) - 1:
        raise Refusal("invalid_observation_integer")
    return value


def version(raw):
    if type(raw) is not str or len(raw) > 128:
        raise Refusal("invalid_tool_version")
    match = re.fullmatch(r"v?([0-9]+)\.([0-9]+)\.([0-9]+)(?:[-+][^\r\n]*)?", raw)
    if not match:
        raise Refusal("invalid_tool_version")
    result = tuple(int(value) for value in match.groups())
    if any(value > 65535 for value in result):
        raise Refusal("invalid_tool_version")
    return result


def core(raw):
    return ".".join(str(value) for value in version(raw))


def capture(argv, timeout=10, cap=MAX_OUTPUT, reader=os.read):
    """Bound the two anonymous pipes; never stop a daemon or another process."""
    if os.name != "posix":
        raise Refusal("process_capture_platform_unsupported")
    streams = {name: {"data": bytearray(), "observed": 0, "eof": False}
               for name in ("stdout", "stderr")}
    reason = None
    try:
        child = subprocess.Popen(argv, stdin=subprocess.DEVNULL,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError:
        return {"actual_exit": None, "complete": False, "reason": "launch_failed",
                "stdout": b"", "stderr": b"", "streams": {}}
    deadline = time.monotonic() + timeout
    drain_deadline = None
    with selectors.DefaultSelector() as selector:
        for name in streams:
            selector.register(getattr(child, name), selectors.EVENT_READ, name)
        try:
            while selector.get_map():
                now = time.monotonic()
                if reason is None and now >= deadline:
                    reason = "timeout"
                    child.kill()
                    drain_deadline = now + 2
                if drain_deadline is not None and now >= drain_deadline:
                    break
                for key, _ in selector.select(0.02):
                    row = streams[key.data]
                    chunk = reader(key.fileobj.fileno(), 4096)
                    if not chunk:
                        row["eof"] = True
                        selector.unregister(key.fileobj)
                        continue
                    row["observed"] += len(chunk)
                    remaining = cap - len(row["data"])
                    row["data"].extend(chunk[:max(0, remaining)])
                    if row["observed"] > cap and reason is None:
                        reason = "output_bound"
                        child.kill()
                        drain_deadline = time.monotonic() + 2
        except OSError:
            reason = reason or "capture_read_failed"
        finally:
            child.stdout.close()
            child.stderr.close()
            if child.poll() is None:
                child.kill()
            try:
                child.wait(timeout=2)
            except subprocess.TimeoutExpired:
                reason = "exit_unresolved"
    complete = reason is None and all(row["eof"] for row in streams.values())
    return {"actual_exit": child.returncode, "complete": complete, "reason": reason,
            "stdout": bytes(streams["stdout"]["data"]),
            "stderr": bytes(streams["stderr"]["data"]),
            "streams": {name: {"captured_bytes": len(row["data"]),
                              "observed_bytes": row["observed"], "eof": row["eof"],
                              "sha256": hashlib.sha256(row["data"]).hexdigest()}
                        for name, row in streams.items()}}


def command(name, argv, records):
    result = capture(argv)
    records.append({"name": name, "actual_exit": result["actual_exit"],
                    "capture_complete": result["complete"], "reason": result["reason"],
                    "streams": result["streams"]})
    if type(result["actual_exit"]) is not int or result["actual_exit"] != 0 or not result["complete"]:
        raise Refusal("tool_observation_incomplete")
    return result["stdout"]


def memory(raw):
    wanted = {}
    for line in raw.splitlines():
        match = re.fullmatch(r"(MemTotal|MemAvailable):\s+([0-9]+) kB", line)
        if match:
            if match[1] in wanted:
                raise Refusal("duplicate_memory_observation")
            wanted[match[1]] = uint(int(match[2]) * 1024)
    if set(wanted) != {"MemTotal", "MemAvailable"} or wanted["MemAvailable"] > wanted["MemTotal"]:
        raise Refusal("memory_observation_unavailable")
    return wanted


def collect(workspace, records):
    if platform.system() != "Linux":
        raise Refusal("resource_probe_requires_linux")
    selected = Path(workspace)
    if not selected.is_dir():
        raise Refusal("workspace_unavailable")
    with open("/proc/meminfo", "r", encoding="ascii") as source:
        raw = source.read(65537)
    if len(raw) > 65536:
        raise Refusal("memory_observation_bound")
    mem = memory(raw)
    cpus = len(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else os.cpu_count()
    disk = shutil.disk_usage(selected)
    docker = json.loads(command("docker_version", ["docker", "version", "--format",
        '{"client":{{json .Client.Version}},"server":{{json .Server.Version}}}'], records))
    info = json.loads(command("docker_info", ["docker", "info", "--format",
        '{"cgroup_version":{{json .CgroupVersion}},"containers":{{json .Containers}}}'], records))
    compose = command("compose_version", ["docker", "compose", "version", "--short"], records).decode("ascii").strip()
    return {"platform": "linux", "architecture": platform.machine(),
            "effective_cpus": uint(cpus), "memory_total_bytes": mem["MemTotal"],
            "memory_available_bytes": mem["MemAvailable"],
            "disk_total_bytes": uint(disk.total), "disk_free_bytes": uint(disk.free),
            "docker_client": core(docker["client"]), "docker_server": core(docker["server"]),
            "compose": core(compose), "cgroup_version": info["cgroup_version"],
            "containers": uint(info["containers"])}


def decide(facts, floor, expected):
    uint(floor); uint(expected)
    if floor < 10 * GIB:
        raise Refusal("free_space_floor_below_10_GiB")
    numeric = ("effective_cpus", "memory_total_bytes", "memory_available_bytes",
               "disk_total_bytes", "disk_free_bytes", "containers")
    for field in numeric:
        uint(facts[field])
    if facts["disk_free_bytes"] > facts["disk_total_bytes"] or facts["memory_available_bytes"] > facts["memory_total_bytes"]:
        raise Refusal("inconsistent_resource_observation")
    if facts["platform"] != "linux" or facts["architecture"] not in ("x86_64", "aarch64", "arm64"):
        raise Refusal("unsupported_probe_platform")
    for name in ("docker_client", "docker_server", "compose"):
        version(facts[name])
    if type(facts["cgroup_version"]) is not str or facts["cgroup_version"] not in ("1", "2"):
        raise Refusal("invalid_cgroup_observation")
    uint(floor + expected)
    if set(facts) != {"platform", "architecture", "effective_cpus", "memory_total_bytes",
                     "memory_available_bytes", "disk_total_bytes", "disk_free_bytes",
                     "docker_client", "docker_server", "compose", "cgroup_version", "containers"}:
        raise Refusal("unexpected_observation_fields")
    if any(core(facts[name]) != facts[name] for name in ("docker_client", "docker_server", "compose")):
        raise Refusal("unnormalized_tool_version")
    checks = {"cpu": facts["effective_cpus"] >= 4,
              "memory": facts["memory_available_bytes"] >= 12 * GIB,
              "disk": facts["disk_free_bytes"] >= floor + expected,
              "empty_engine": facts["containers"] == 0,
              "docker": version(facts["docker_server"]) >= (20, 10, 0),
              "compose": version(facts["compose"]) >= (2, 20, 0),
              "cgroup_v2": facts["cgroup_version"] == "2"}
    return checks


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise Refusal("invalid_arguments")


def write_report(raw, path, stdout):
    if path is None:
        written = stdout.write(raw.decode("ascii"))
        if written != len(raw):
            raise Refusal("output_incomplete")
    else:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            if output.write(raw) != len(raw):
                raise Refusal("output_incomplete")


def run(argv, stdout=None, stderr=None, collector=collect, writer=write_report):
    stdout = sys.stdout if stdout is None else stdout
    stderr = sys.stderr if stderr is None else stderr
    parser = Parser(prog="zenon-devnet-resource-preflight", description=__doc__)
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--minimum-free-bytes", type=integer, default=10 * GIB)
    parser.add_argument("--expected-allocation-bytes", type=integer, default=8 * GIB)
    parser.add_argument("--require-eligible", action="store_true")
    parser.add_argument("--report")
    records = []
    try:
        args = parser.parse_args(argv)
        if args.minimum_free_bytes < 10 * GIB:
            raise Refusal("invalid_arguments")
    except Refusal:
        stderr.write("resource preflight: invalid arguments; use --help\n")
        return 64
    report = {"format": FORMAT, "scope": SCOPE, "setup_authorized": False,
              "services_started": False, "signing_or_transactions_started": False,
              "source_revision": None, "tool_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "policy": {"minimum_free_bytes": args.minimum_free_bytes,
                         "expected_allocation_bytes": args.expected_allocation_bytes,
                         "minimum_available_memory_bytes": 12 * GIB, "minimum_cpus": 4},
              "commands": records, "status": "UNKNOWN", "eligible": None,
              "facts": None, "checks": None, "error": None,
              "limits": ["Resource observations do not reserve or enforce future allocations.",
                         "An empty engine does not authenticate ownership.",
                         "Executor enforcement and a real consumer query have not run."]}
    revision = os.environ.get("GITHUB_SHA", "")
    if re.fullmatch("[0-9a-f]{40}", revision):
        report["source_revision"] = revision
    try:
        facts = collector(args.workspace, records)
        checks = decide(facts, args.minimum_free_bytes, args.expected_allocation_bytes)
        report.update(status="COMPLETE", facts=facts, checks=checks, eligible=all(checks.values()))
        code = 2 if args.require_eligible and not report["eligible"] else 0
    except (Refusal, OSError, ValueError, TypeError, KeyError, OverflowError):
        report["error"] = "resource_observation_unavailable"
        code = 70
    raw = (json.dumps(report, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode("ascii")
    try:
        writer(raw, args.report, stdout)
    except (Refusal, OSError, ValueError, TypeError):
        stderr.write("resource preflight: output unavailable\n")
        return 70
    return code


if __name__ == "__main__":
    raise SystemExit(run(sys.argv[1:]))
