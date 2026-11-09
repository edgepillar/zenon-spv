# SPDX-License-Identifier: GPL-3.0-only
"""One closed-ledger read inside an isolated hosted runner namespace.

This is the narrow privileged entry point. It runs only the pinned oracle.
The unprivileged controller supplies the owned stopped volume and retains the
original command streams. No repository imports are loaded with host privilege.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import select
import stat
import subprocess
import sys
import time

LEDGER = re.compile(r"/var/lib/docker/volumes/spv-[0-9a-f]{32}-rpc-data/_data/nom\Z")
ORACLE_NAME = "spv-closed-parent-oracle.exe"
ENVIRONMENT = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C",
               "GOMAXPROCS": "2", "GOMEMLIMIT": "384MiB"}


def verify_reader_scope(ledger, oracle, request, genesis):
    if not LEDGER.fullmatch(str(ledger)):
        raise ValueError("ledger_scope")
    if oracle.name != ORACLE_NAME or genesis.name != "genesis.json" or not request.name.endswith(".json"):
        raise ValueError("reader_input_names")
    for path in (ledger, oracle, request, genesis):
        if not path.is_absolute() or path.resolve(strict=True) != path:
            raise ValueError("reader_input_path")
    if not ledger.is_dir() or any(not path.is_file() for path in (oracle, request, genesis)):
        raise ValueError("reader_input_type")


def validate_namespace(parent_mount, parent_network):
    if os.geteuid() != 0 or os.stat("/proc/self/ns/mnt").st_ino == parent_mount \
            or os.stat("/proc/self/ns/net").st_ino == parent_network:
        raise ValueError("reader_namespace")
    if not stat.S_ISFIFO(os.fstat(0).st_mode):
        raise ValueError("reader_pipe_required")


def lease_revoked(wait=0):
    readable, _, _ = select.select([0], [], [], wait)
    # EOF is cancellation. No command data is accepted on this pipe.
    return bool(readable)


def verified_oracle(path, expected_size, expected_hash):
    if not (0 < expected_size <= 32 << 20 and re.fullmatch(r"[0-9a-f]{64}", expected_hash)):
        raise ValueError("reader_binary_pin")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size != expected_size:
            raise ValueError("reader_binary_type")
        digest, read = hashlib.sha256(), 0
        while read < expected_size:
            chunk = os.read(descriptor, min(65536, expected_size - read))
            if not chunk:
                raise ValueError("reader_binary_truncated")
            digest.update(chunk)
            read += len(chunk)
        after = os.fstat(descriptor)
        if os.read(descriptor, 1) or digest.hexdigest() != expected_hash \
                or (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                    after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError("reader_binary_changed")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def mount_ledger(ledger):
    # This bind is visible only in the already private mount namespace. A
    # nonrecursive bind omits any nested mounts from the source.
    before = ledger.stat()
    mount = ["/usr/bin/mount", "-n"]
    subprocess.run([*mount, "--bind", "--", str(ledger), str(ledger)], env=ENVIRONMENT,
                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                   check=True, timeout=2)
    subprocess.run([*mount, "-o", "remount,bind,ro,nosuid,nodev,noexec", "--", str(ledger), str(ledger)],
                   env=ENVIRONMENT, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL, check=True, timeout=2)
    if not os.path.samestat(before, ledger.stat()) or not os.statvfs(ledger).f_flag & os.ST_RDONLY:
        raise ValueError("reader_readonly_bind")


def run(ledger, oracle, request, genesis, expected_size, expected_hash, parent_mount, parent_network):
    validate_namespace(parent_mount, parent_network)
    verify_reader_scope(ledger, oracle, request, genesis)
    if lease_revoked():
        raise ValueError("reader_lease_revoked")
    descriptor = verified_oracle(oracle, expected_size, expected_hash)
    child = None
    try:
        mount_ledger(ledger)
        if lease_revoked():
            raise ValueError("reader_lease_revoked")
        # The helper inherits the root timeout's group and streams directly to
        # the outer recorder. Only the verified descriptor can be executed.
        command = [f"/proc/self/fd/{descriptor}", "--ledger", str(ledger),
                   "--genesis", str(genesis), "--request", str(request)]
        child = subprocess.Popen(command, cwd="/", env=ENVIRONMENT, stdin=subprocess.DEVNULL,
                                 pass_fds=(descriptor,))
        deadline = time.monotonic() + 90
        while child.poll() is None:
            if lease_revoked(0.05) or time.monotonic() >= deadline:
                raise ValueError("reader_lease_or_deadline")
        return child.returncode if child.returncode >= 0 else 128 - child.returncode
    finally:
        os.close(descriptor)
        if child is not None and child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=1)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=1)


def main(argv):
    try:
        if len(argv) != 8:
            raise ValueError("reader_arguments")
        return run(*(Path(value) for value in argv[:4]), int(argv[4]), argv[5],
                   int(argv[6]), int(argv[7]))
    except (OSError, ValueError, subprocess.SubprocessError):
        sys.stderr.write("Closed-ledger reader refused or did not complete.\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
