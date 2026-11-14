# SPDX-License-Identifier: GPL-3.0-only
"""Bounded POSIX commands for the owned devnet controller.

Only the newly created process group is signalled. Docker services are outside
that group and require their separate immutable-ID journal. Session-escaping
descendants, hostile same-user writers and hardware power loss are not covered.
"""

from __future__ import annotations

from dataclasses import dataclass
from contextlib import ExitStack, contextmanager
import hashlib
import json
import math
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import time

from model import Refused, canonical, require

LABEL = re.compile(r"[a-z][a-z0-9-]{0,63}\Z")
FILE = re.compile(r"[a-z0-9][a-z0-9._-]{0,191}\Z")
MAX_STREAM = 64 << 20


def parameters(argv, env, stdout_cap, stderr_cap, timeout, terminate_grace):
    require(os.name == "posix", "process_group_platform_unsupported")
    require(type(argv) is list and 0 < len(argv) <= 128
            and all(type(arg) is str and "\0" not in arg and len(arg) <= 65536 for arg in argv)
            and bool(argv[0]) and sum(map(len, argv)) <= 128 << 10, "command_arguments")
    require(type(env) is dict and all(type(k) is str and bool(k) and "=" not in k
            and "\0" not in k and type(v) is str and "\0" not in v
            for k, v in env.items()), "explicit_command_environment")
    for cap in (stdout_cap, stderr_cap):
        require(type(cap) is int and 0 < cap <= MAX_STREAM, "command_stream_bound")
    for value, ceiling in ((timeout, 3600), (terminate_grace, 5)):
        require(type(value) in (int, float) and math.isfinite(value)
                and 0 < value <= ceiling, "command_time_bound")


def group_alive(group):
    try:
        os.killpg(group, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def _signal_group(child, selected, signals):
    # Popen(start_new_session=True) returned this direct child. Never derive a
    # signal target from input text, a discovered process or a peer response.
    try:
        os.killpg(child.pid, selected)
        signals.append(selected.name)
    except ProcessLookupError:
        pass


def capture(argv, cwd, env, *, stdout_cap=2 << 20, stderr_cap=2 << 20,
            timeout=60, terminate_grace=1, stdout_sink=None, stderr_sink=None,
            guard=None, cancelled=None, on_start=None, reader=os.read, stdin_lease=False):
    parameters(argv, env, stdout_cap, stderr_cap, timeout, terminate_grace)
    require(type(stdin_lease) is bool, "command_stdin_lease")
    sinks = {"stdout": stdout_sink, "stderr": stderr_sink}
    for sink in sinks.values():
        require(sink is None or callable(getattr(sink, "write", None)), "command_sink")
    buffers = {name: bytearray() for name in sinks}
    hashes = {name: hashlib.sha256() for name in sinks}
    streams = {name: {"captured_bytes": 0, "observed_bytes": 0, "eof": False,
                     "truncated": False, "read_error": False, "write_error": False,
                     "captured_bytes_known": True} for name in sinks}
    receipt = {"format": "owned-devnet-command-capture/v1", "actual_exit": None,
               "launch_outcome": "NOT_STARTED", "output_complete": False,
               "reason": None, "process_group": None, "process_group_quiescent": None,
               "group_signals": [], "streams": streams}
    started = time.monotonic()
    child = None
    selector = None
    reason = None
    termination = None
    kill_sent = False
    quiet_deadline = None
    caps = {"stdout": stdout_cap, "stderr": stderr_cap}

    def terminate(selected):
        if stdin_lease:
            # The closed-ledger supervisor owns its worker. EOF revokes the
            # lease without an unprivileged signal to another UID's group.
            if not child.stdin.closed:
                child.stdin.close()
                receipt["stdin_lease_revoked"] = True
        else:
            _signal_group(child, selected, receipt["group_signals"])

    def admit():
        if cancelled is not None and cancelled():
            return "cancelled"
        if guard is not None:
            try:
                guard()
            except BaseException:
                return "guard_refused"
        return None

    reason = admit()
    if reason is not None:
        receipt["reason"] = reason
    else:
        try:
            child = subprocess.Popen(argv, cwd=cwd, env=env,
                                     stdin=subprocess.PIPE if stdin_lease else subprocess.DEVNULL,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     start_new_session=True, close_fds=True, bufsize=0)
            receipt.update(launch_outcome="STARTED", process_group=child.pid)
            if on_start is not None:
                on_start({"pid": child.pid, "process_group": child.pid,
                          "new_session_requested": True})
            selector = selectors.DefaultSelector()
            for name in streams:
                pipe = getattr(child, name)
                os.set_blocking(pipe.fileno(), False)
                selector.register(pipe, selectors.EVENT_READ, name)
            deadline = started + timeout
            while True:
                now = time.monotonic()
                status = child.poll()
                if reason is None:
                    reason = admit()
                    if reason is None and now >= deadline:
                        reason = "timeout"
                if reason is not None and termination is None:
                    terminate(signal.SIGTERM)
                    termination = now
                if termination is not None and now >= termination + terminate_grace and not kill_sent:
                    if group_alive(child.pid):
                        terminate(signal.SIGKILL)
                    kill_sent = True
                if termination is not None and now >= termination + terminate_grace + 2:
                    break
                if status is not None and not selector.get_map():
                    if not group_alive(child.pid):
                        break
                    if quiet_deadline is None:
                        quiet_deadline = now + min(terminate_grace, 1)
                    if reason is None and now >= quiet_deadline:
                        reason = "descendant_group_active"
                    time.sleep(0.01)
                    continue
                for key, _ in selector.select(0.02):
                    name = key.data
                    row = streams[name]
                    try:
                        chunk = reader(key.fileobj.fileno(), 8192)
                    except BlockingIOError:
                        continue
                    except OSError:
                        row["read_error"] = True
                        reason = reason or "read_failed"
                        selector.unregister(key.fileobj)
                        continue
                    if not chunk:
                        row["eof"] = True
                        selector.unregister(key.fileobj)
                        continue
                    row["observed_bytes"] += len(chunk)
                    prefix = chunk[:max(0, caps[name] - row["captured_bytes"])]
                    if prefix and not row["write_error"]:
                        try:
                            count = len(prefix) if sinks[name] is None else sinks[name].write(prefix)
                            if type(count) is not int or not 0 <= count <= len(prefix):
                                row["captured_bytes_known"] = False
                                raise OSError("invalid sink result")
                            if sinks[name] is None:
                                buffers[name].extend(prefix[:count])
                            hashes[name].update(prefix[:count])
                            row["captured_bytes"] += count
                            if count != len(prefix):
                                raise OSError("short sink write")
                        except OSError:
                            row["write_error"] = True
                            # An exception may occur after an unacknowledged
                            # partial write. The file must be rechecked by owner.
                            row["captured_bytes_known"] = False
                            reason = reason or "write_failed"
                    if row["observed_bytes"] > caps[name]:
                        row["truncated"] = True
                        reason = reason or "output_bound"
        except OSError:
            reason = reason or ("launch_failed" if child is None else "capture_failed")
            if child is None:
                receipt["launch_outcome"] = "FAILED"
        except KeyboardInterrupt:
            reason = reason or "interrupted"
        except BaseException as error:
            reason = reason or "capture_failed"
            receipt["error_type"] = type(error).__name__
        finally:
            if child is not None:
                # A callback/reader failure must still stop only this group.
                if child.poll() is None or group_alive(child.pid):
                    terminate(signal.SIGTERM)
                    until = time.monotonic() + terminate_grace
                    while group_alive(child.pid) and time.monotonic() < until:
                        child.poll()
                        time.sleep(0.01)
                    if group_alive(child.pid):
                        terminate(signal.SIGKILL)
                try:
                    receipt["actual_exit"] = child.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    reason = reason or "exit_unresolved"
                for name in streams:
                    getattr(child, name).close()
                if stdin_lease:
                    child.stdin.close()
                receipt["process_group_quiescent"] = not group_alive(child.pid)
                if not receipt["process_group_quiescent"]:
                    reason = reason or "process_group_unresolved"
            if selector is not None:
                selector.close()
    receipt["reason"] = reason
    receipt["elapsed_nanoseconds"] = max(0, int((time.monotonic() - started) * 1_000_000_000))
    for name, row in streams.items():
        row["sha256"] = hashes[name].hexdigest() if row["captured_bytes_known"] else None
    receipt["output_complete"] = (
        child is not None and receipt["actual_exit"] is not None and reason is None
        and receipt["process_group_quiescent"] is True
        and all(row["eof"] and not row["truncated"] and not row["read_error"]
                and not row["write_error"] for row in streams.values()))
    return {name: None if sinks[name] is not None else bytes(value)
            for name, value in buffers.items()}, receipt


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_uid)


def _file_identity(info):
    return (*_identity(info), info.st_size, info.st_mtime_ns)


def _sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def regular_pin(path, limit):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= limit,
            "owned_output_identity")
    digest = hashlib.sha256()
    count = 0
    with path.open("rb") as stream:
        require(os.path.samestat(info, os.fstat(stream.fileno())), "owned_output_replaced")
        for chunk in iter(lambda: stream.read(65536), b""):
            count += len(chunk)
            require(count <= limit, "owned_output_bound")
            digest.update(chunk)
        after = os.fstat(stream.fileno())
    final = path.lstat()
    require(stat.S_ISREG(final.st_mode) and os.path.samestat(info, after)
            and os.path.samestat(info, final)
            and info.st_size == after.st_size == final.st_size == count
            and info.st_mtime_ns == after.st_mtime_ns == final.st_mtime_ns,
            "owned_output_changed")
    return {"sha256": digest.hexdigest(), "bytes": count}


class CommandFailed(Refused):
    def __init__(self, result):
        super().__init__("owned_command_failed_or_incomplete")
        self.result = result


@contextmanager
def owned_lease(recorder, name):
    """Lease one newly recorded inode; do not adopt a discovered lock file."""
    require(os.name == "posix", "artifact_lease_platform")
    import fcntl
    recorder.seal(name, b"")
    path = recorder.directory / name
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, "artifact_lease_identity")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        require(os.path.samestat(before, os.fstat(descriptor)), "artifact_lease_identity")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise Refused("artifact_transport_in_use") from error
        yield
        after = path.lstat()
        require(stat.S_ISREG(after.st_mode) and after.st_nlink == 1
                and os.path.samestat(before, after), "artifact_lease_identity")
    finally:
        os.close(descriptor)


@dataclass(frozen=True)
class Result:
    directory: Path
    stdout_name: str
    stderr_name: str
    receipt_raw: bytes
    stdout_identity: tuple
    stderr_identity: tuple | None = None

    @property
    def receipt(self):
        return json.loads(self.receipt_raw)

    @contextmanager
    def _open_output_for_validation(self, name, expected, identity, limit):
        """Hold an original captured inode while validating its selected bytes."""
        require(identity is not None, "command_result_identity")
        require(expected["bytes"] <= limit, "command_result_read_bound")
        path = self.directory / name
        before = path.lstat()
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and _file_identity(before) == identity, "command_result_changed")
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as stream:
            opened = os.fstat(stream.fileno())
            require(os.path.samestat(before, opened), "command_result_changed")
            try:
                yield stream
            finally:
                after = os.fstat(stream.fileno())
                final = path.lstat()
                require(stat.S_ISREG(final.st_mode) and final.st_nlink == 1
                        and _file_identity(opened) == _file_identity(after)
                        == _file_identity(final) == identity,
                        "command_result_changed")

    @contextmanager
    def open_stdout_for_validation(self, limit):
        """Hold the recorded stdout inode for a reader that checks its digest."""
        with self._open_output_for_validation(self.stdout_name, self.receipt["outputs"]["stdout"],
                                             self.stdout_identity, limit) as stream:
            yield stream

    def stdout(self, limit=2 << 20):
        expected = self.receipt["outputs"]["stdout"]
        with self.open_stdout_for_validation(limit) as stream:
            raw = stream.read(limit + 1)
            require(len(raw) == expected["bytes"]
                    and hashlib.sha256(raw).hexdigest() == expected["sha256"],
                    "command_result_changed")
        return raw

    def stderr(self, limit=2 << 20):
        """Read stderr only when its original inode and complete bytes still match."""
        expected = self.receipt["outputs"]["stderr"]
        with self._open_output_for_validation(self.stderr_name, expected, self.stderr_identity, limit) as stream:
            raw = stream.read(limit + 1)
            require(len(raw) == expected["bytes"]
                    and hashlib.sha256(raw).hexdigest() == expected["sha256"],
                    "command_result_changed")
        return raw

    @contextmanager
    def open_stdout(self, limit):
        """Verify the one original file, then expose its same open descriptor."""
        expected = self.receipt["outputs"]["stdout"]
        with self.open_stdout_for_validation(limit) as stream:
            sha = hashlib.sha256()
            size = 0
            for chunk in iter(lambda: stream.read(65536), b""):
                size += len(chunk)
                require(size <= limit, "command_result_read_bound")
                sha.update(chunk)
            require(size == expected["bytes"] and sha.hexdigest() == expected["sha256"],
                    "command_result_changed")
            stream.seek(0)
            yield stream


class Recorder:
    """A new command directory only. It never adopts, rewrites or cleans one."""

    def __init__(self, directory):
        require(os.name == "posix", "process_group_platform_unsupported")
        self.directory = Path(directory)
        require(not self.directory.exists() and not self.directory.is_symlink(),
                "command_directory_exists")
        self.directory.mkdir(mode=0o700)
        _sync_directory(self.directory.parent)
        self.identity = _identity(self.directory.lstat())
        self.records = []
        self.names = set()

    def check(self):
        info = self.directory.lstat()
        require(stat.S_ISDIR(info.st_mode) and _identity(info) == self.identity,
                "command_directory_replaced")

    def seal(self, name, raw):
        self.check()
        require(FILE.fullmatch(name) is not None and name not in self.names,
                "command_file_selection")
        path = self.directory / name
        with path.open("xb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        path.chmod(0o400)
        _sync_directory(self.directory)
        self.names.add(name)
        return {"file": name, **regular_pin(path, max(len(raw), 1))}

    def run(self, label, argv, cwd, env, *, stdout_cap=2 << 20, stderr_cap=2 << 20,
            timeout=60, terminate_grace=1, stdout_name=None, guard=None,
            cancelled=None, check=True, stdin_lease=False):
        parameters(argv, env, stdout_cap, stderr_cap, timeout, terminate_grace)
        self.check()
        require(LABEL.fullmatch(label) is not None, "command_label")
        stdout_name = stdout_name or label + ".stdout"
        stderr_name = label + ".stderr"
        selected = [label + ".launch.json", label + ".started.json",
                    label + ".complete.json", stdout_name, stderr_name]
        require(len(set(selected)) == len(selected)
                and all(FILE.fullmatch(name) is not None and name not in self.names
                        and not (self.directory / name).exists()
                        and not (self.directory / name).is_symlink() for name in selected),
                "command_files_exist_or_alias")
        launch = self.seal(selected[0], canonical({"format": "owned-devnet-command-launch/v1",
                                                 "label": label, "launch_outcome": "UNKNOWN",
                                                 "actual_exit": None}))
        entry = {"label": label, "launch": launch, "started": None,
                 "receipt": None, "outcome": "UNKNOWN"}
        self.records.append(entry)
        out_path, err_path = self.directory / stdout_name, self.directory / stderr_name
        # Exclusive output creation precedes launch. stdout_name can be the
        # original artifact ZIP, so there is no stdout-to-ZIP copy.
        launched = False
        with ExitStack() as stack:
            # If the second create or either fsync fails, both handles still
            # close. The append-only launch entry remains UNKNOWN.
            out = stack.enter_context(out_path.open("xb", buffering=0))
            self.names.add(stdout_name)
            err = stack.enter_context(err_path.open("xb", buffering=0))
            self.names.add(stderr_name)
            try:
                def on_start(value):
                    nonlocal launched
                    launched = True
                    entry["started"] = self.seal(selected[1], canonical(
                        {"format": "owned-devnet-command-started/v1", "label": label, **value}))
                _, receipt = capture(argv, cwd, env, stdout_cap=stdout_cap, stderr_cap=stderr_cap,
                                     timeout=timeout, terminate_grace=terminate_grace,
                                     stdout_sink=out, stderr_sink=err, guard=guard,
                                     cancelled=cancelled, on_start=on_start, stdin_lease=stdin_lease)
            finally:
                for stream in (out, err):
                    stream.flush()
                    os.fsync(stream.fileno())
        out_path.chmod(0o400)
        err_path.chmod(0o400)
        receipt.update(label=label, outputs={
            "stdout": {"file": stdout_name, **regular_pin(out_path, stdout_cap)},
            "stderr": {"file": stderr_name, **regular_pin(err_path, stderr_cap)}})
        completed = self.seal(selected[2], canonical(receipt))
        entry["receipt"] = completed
        if type(receipt["actual_exit"]) is int:
            if receipt["actual_exit"] != 0:
                entry["outcome"] = "FAILURE"
            elif receipt["output_complete"] is True:
                entry["outcome"] = "SUCCESS"
        result = Result(self.directory, stdout_name, stderr_name, canonical(receipt),
                        _file_identity(out_path.lstat()), _file_identity(err_path.lstat()))
        if check and not (type(receipt["actual_exit"]) is int and receipt["actual_exit"] == 0
                          and receipt["output_complete"] is True):
            raise CommandFailed(result)
        return result
