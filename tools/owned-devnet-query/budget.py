# SPDX-License-Identifier: GPL-3.0-only
"""Sampled fresh-host admission and a monotonic new-work budget.

This is not an OS aggregate quota or protection against unrelated writers.
Container resource configuration is checked separately by engine.py.
"""
from __future__ import annotations

import argparse
import math
import os
from pathlib import Path
import platform
import re
import stat
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
if __name__ == "__main__":
    sys.path.insert(0, str(HERE))

import model
from model import Refused, require

GIB = 1 << 30


def linux_observation(path):
    require(platform.system() == "Linux", "native_linux_host_required")
    raw = Path("/proc/meminfo").read_bytes()
    require(len(raw) <= 64 << 10, "host_memory_observation_bound")
    matches = re.findall(rb"(?m)^MemAvailable:\s+([0-9]+) kB$", raw)
    require(len(matches) == 1, "host_memory_observation")
    cpus = min(len(os.sched_getaffinity(0)), os.cpu_count() or 1)
    quota = Path("/sys/fs/cgroup/cpu.max")
    if quota.exists():
        fields = quota.read_text(encoding="ascii").strip().split()
        require(len(fields) == 2 and fields[1].isdigit() and int(fields[1]) > 0,
                "host_cpu_quota_observation")
        if fields[0] != "max":
            require(fields[0].isdigit() and int(fields[0]) > 0, "host_cpu_quota_observation")
            cpus = min(cpus, int(fields[0]) // int(fields[1]))
    disk = os.statvfs(path)
    return {"system": platform.system(), "machine": platform.machine(),
            "available_memory_bytes": int(matches[0]) * 1024,
            "effective_cpu_count": cpus, "free_bytes": disk.f_bavail * disk.f_frsize}


def preparation_admission_report(contract, path, source_revision, run_id, run_attempt, *, observe=linux_observation):
    """Compare a read-only preparation sample with the actual admission rules."""
    model.digest(source_revision, model.HEX40)
    model.uint(run_id)
    model.uint(run_attempt)
    minimums = model.host_minimums(contract.data["limits"])
    observations, status, reason = None, "UNAVAILABLE", None
    try:
        observations = observe(path)
        model.admit_host(contract, observations)
        status = "MEETS_THRESHOLDS"
    except Refused as error:
        status = "REFUSED" if observations is not None else "UNAVAILABLE"
        reason = error.reason
    except (OSError, ValueError):
        reason = "observation_failed"
    return {"format": "owned-devnet-host-admission-sample/v1", "status": status, "reason": reason,
            "source_revision": source_revision, "run_id": run_id, "run_attempt": run_attempt,
            "contract_sha256": contract.sha256, "minimums": minimums, "observations": observations,
            "engine_contacted": False, "experiment_executed": False,
            "OS_aggregate_quota_or_runtime_enforcement_proven": False}


def evidence_bytes(directory, identity):
    """Count the recorder's flat regular outputs, including in-flight prefixes."""
    info = directory.lstat()
    require(stat.S_ISDIR(info.st_mode) and (info.st_dev, info.st_ino, info.st_uid)
            == identity, "budget_evidence_directory_changed")
    total = 0
    with os.scandir(directory) as entries:
        for entry in entries:
            child = entry.stat(follow_symlinks=False)
            require(stat.S_ISREG(child.st_mode) and child.st_nlink == 1
                    and child.st_dev == info.st_dev and child.st_uid == info.st_uid,
                    "budget_evidence_file_type")
            total += child.st_size
    return total


class Budget:
    def __init__(self, contract, directory, recorder, *, observe=linux_observation,
                 clock=time.monotonic, cleanup_reserve_seconds=300, interval_seconds=0.25):
        require(callable(observe) and callable(clock), "budget_observers")
        require(type(cleanup_reserve_seconds) is int and 60 <= cleanup_reserve_seconds <= 600,
                "cleanup_time_reserve")
        require(type(interval_seconds) in (int, float) and math.isfinite(interval_seconds)
                and 0 < interval_seconds <= 1, "budget_sample_interval")
        self.contract, self.recorder, self.directory = contract, recorder, Path(directory)
        info = self.directory.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid(), "budget_directory_identity")
        self.identity = info.st_dev, info.st_ino, info.st_uid
        self.evidence_identity = recorder.identity
        require(info.st_dev == self.evidence_identity[0], "budget_filesystem_mismatch")
        self.observe, self.clock = observe, clock
        self.started = self.clock()
        require(math.isfinite(self.started), "budget_monotonic_clock")
        self.reserve, self.interval = cleanup_reserve_seconds, interval_seconds
        self.initial = self.observe(self.directory)
        self.admission = model.admit_host(contract, self.initial)
        self.last_time, self.last = None, None
        self.peak_new_disk, self.peak_evidence, self.samples = 0, 0, 0
        self.failure = None
        self.engine_filesystem_bound = False
        self.check(force=True)

    def bind_engine_filesystem(self, path):
        require(type(path) is str and Path(path).is_absolute() and "\0" not in path,
                "engine_disk_path")
        require(not self.engine_filesystem_bound, "engine_disk_already_bound")
        info = Path(path).stat()
        require(stat.S_ISDIR(info.st_mode) and info.st_dev == self.identity[0],
                "engine_disk_filesystem_mismatch")
        self.engine_filesystem_bound = True

    def check(self, force=False):
        require(self.failure is None, "budget_already_refused")
        try:
            now = self.clock()
            require(math.isfinite(now) and now >= self.started
                    and (self.last_time is None or now >= self.last_time), "budget_monotonic_clock")
            elapsed = now - self.started
            limits = self.contract.data["limits"]
            require(elapsed < limits["max_elapsed_seconds"] - self.reserve, "new_work_deadline")
            if not force and self.last_time is not None and now - self.last_time < self.interval:
                return
            info = self.directory.lstat()
            require(stat.S_ISDIR(info.st_mode) and (info.st_dev, info.st_ino, info.st_uid)
                    == self.identity, "budget_directory_changed")
            current = self.observe(self.directory)
            free = current["free_bytes"]
            require(type(free) is int and free >= 0, "budget_free_space_observation")
            allocated = max(0, self.initial["free_bytes"] - free)
            self.peak_new_disk = max(self.peak_new_disk, allocated)
            self.peak_evidence = max(self.peak_evidence,
                evidence_bytes(self.recorder.directory, self.evidence_identity))
            self.samples += 1
            self.last_time, self.last = now, {"elapsed_seconds": elapsed,
                "free_bytes": free, "observed_new_disk_bytes": allocated,
                "evidence_bytes": self.peak_evidence}
            remaining = max(0, limits["expected_allocation_bytes"] - allocated)
            require(free >= limits["min_free_bytes"] + limits["safety_margin_bytes"] + remaining,
                    "minimum_free_space_with_remaining_allocation")
            require(allocated <= limits["max_new_disk_bytes"], "new_disk_budget")
            require(self.peak_evidence <= limits["max_evidence_bytes"], "evidence_budget")
        except (Refused, OSError, KeyError, TypeError, ValueError) as error:
            self.failure = str(error) if isinstance(error, Refused) else type(error).__name__
            raise

    def report(self):
        return {"format": "owned-devnet-budget-observation/v1", "admission": self.admission,
            "initial": self.initial, "samples": self.samples, "last_sample": self.last,
            "peak_observed_new_disk_bytes": self.peak_new_disk,
            "peak_observed_evidence_bytes": self.peak_evidence, "refusal": self.failure,
            "engine_filesystem_bound": self.engine_filesystem_bound,
            "cleanup_reserve_seconds": self.reserve,
            "OS_aggregate_quota_or_runtime_enforcement_proven": False,
            "unrelated_writer_attribution_established": False,
            "transient_allocations_between_samples_measured": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Record one read-only host admission sample.", allow_abbrev=False)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--run-id", type=int, required=True)
    parser.add_argument("--run-attempt", type=int, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        def git(*arguments):
            return subprocess.check_output(["git", "--no-optional-locks", *arguments],
                                           cwd=HERE, timeout=10, stderr=subprocess.DEVNULL)

        revision = git("rev-parse", "HEAD").decode("ascii").strip()
        require(revision == args.source_revision and not git("status", "--porcelain=v1", "-z",
                "--untracked-files=all"), "host_sample_source_revision")
        contract = model.read_contract(HERE / "contract.json")
        report = preparation_admission_report(contract, args.report.parent, revision, args.run_id, args.run_attempt)
        with args.report.open("xb") as output:
            output.write(model.canonical(report))
        return 0
    except (OSError, ValueError, subprocess.SubprocessError):
        sys.stderr.write("Host admission sample could not be retained.\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
