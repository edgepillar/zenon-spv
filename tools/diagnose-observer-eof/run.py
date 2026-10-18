#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Run one sealed diagnostic generation in caller-selected disposable scratch.

Keep the complete bounded log and actual command receipts externally. No binary
or archive is exported and no historical directory is adopted or collected.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time

sys.dont_write_bytecode = True
import prepare as P

CONTROLS = "^Test(ObserverEOFDiagnostic.*|Observation(StreamEOF|EOFCompletionGate|OutputCompletion|ProcessBoundaries)|Concurrent(File)?ObservationProcessCancellation|ProcessFileCapturePreservesCompletion|FileCaptureWriteFailureStopsAndJoinsLiveChild)$"
WORKLOAD = "^TestCompiledBlockObserverResources$/^K4096_T16_C4$"
FULL_WORKLOAD = "^TestCompiledBlockObserverResources$"


def resource_pattern(full_resource_sequence):
    P.require(type(full_resource_sequence) is bool)
    return FULL_WORKLOAD if full_resource_sequence else WORKLOAD


def image_pin(path):
    path = P.unlinked_path(path)
    before = path.lstat()
    P.require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= 128 << 20)
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for raw in iter(lambda: stream.read(65536), b""):
            digest.update(raw)
    after = path.lstat()
    identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    P.require(identity(before) == identity(after))
    return identity(before), {"sha256": digest.hexdigest(), "bytes": before.st_size}


def remove_control_image(path, selected, timeout=5):
    """Windows-only bounded removal of this exact new diagnostic test image.

    Keep an access-denied result until a later successful removal. Never claim
    which process or scanner held the image, or relax the observer pipe timer.
    """
    P.require(sys.platform == "win32")
    identity, pin = selected
    started, attempts = time.monotonic_ns(), 0
    deadline = time.monotonic() + timeout
    while True:
        try:
            P.require(image_pin(path) == (identity, pin))
        except (OSError, ValueError):
            raise RuntimeError("diagnostic image identity changed; preserve workspace") from None
        attempts += 1
        try:
            path.unlink()
            return {"selected_image": pin, "removal_attempts": attempts, "removed": True,
                    "elapsed_ns": time.monotonic_ns() - started, "timeout_seconds": timeout,
                    "lock_holder": "UNKNOWN", "observer_deadline_or_pipe_wait_changed": False}
        except PermissionError:
            if time.monotonic() >= deadline:
                print("observer-eof-control-image-removal " + json.dumps({"selected_image": pin,
                      "removal_attempts": attempts, "removed": False, "elapsed_ns": time.monotonic_ns() - started,
                      "timeout_seconds": timeout, "lock_holder": "UNKNOWN"}, sort_keys=True), flush=True)
                raise RuntimeError("diagnostic control image remains held; preserve workspace")
            time.sleep(0.02)
        except OSError:
            raise RuntimeError("diagnostic control image removal is uncertain; preserve workspace") from None


def capture(argv, cwd, env, timeout, out_limit=4 << 20, err_limit=1 << 20):
    """Stream once with caps; a nonzero exit never becomes a successful sample."""
    stop = threading.Event()
    results = [{}, {}]
    started = time.monotonic_ns()
    child = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)

    def copy(index, incoming, outgoing, limit):
        digest, observed, emitted, eof, failed = hashlib.sha256(), 0, 0, False, False
        try:
            while True:
                raw = os.read(incoming.fileno(), 65536)
                if not raw:
                    eof = True
                    break
                observed += len(raw)
                digest.update(raw)
                selected = raw[:max(0, limit - emitted)]
                if selected:
                    outgoing.write(selected)
                    outgoing.flush()
                    emitted += len(selected)
                if observed > limit:
                    stop.set()
        except (OSError, ValueError):
            failed = True
            stop.set()
        finally:
            incoming.close()
            results[index].update(bytes=observed, emitted_bytes=emitted, sha256=digest.hexdigest(),
                                  EOF=eof, copy_failed=failed, cap_exceeded=observed > limit)

    threads = [threading.Thread(target=copy, args=(i, stream, sink, limit), daemon=True)
               for i, (stream, sink, limit) in enumerate(((child.stdout, sys.stdout.buffer, out_limit),
                                                         (child.stderr, sys.stderr.buffer, err_limit)))]
    reason, interrupted = None, False
    started_threads = []
    try:
        for thread in threads:
            thread.start()
            started_threads.append(thread)
        deadline = time.monotonic() + timeout
        while child.poll() is None:
            if stop.is_set() or time.monotonic() >= deadline:
                reason = "stream_limit_or_copy_failure" if stop.is_set() else "timeout"
                break
            time.sleep(0.02)
    except BaseException:
        reason, interrupted = "interrupted", True
    finally:
        if child.poll() is None:
            child.kill()
        actual = child.wait(timeout=10)
        for thread in started_threads:
            thread.join(timeout=5)
    settled = not any(thread.is_alive() for thread in threads)
    complete = settled and all(r.get("EOF") and not r.get("copy_failed") and not r.get("cap_exceeded") for r in results)
    receipt = {"actual_exit": actual, "elapsed_ns": time.monotonic_ns() - started,
               "output_complete": complete, "reason": reason, "copy_threads_joined": settled,
               "stdout_limit_bytes": out_limit, "stderr_limit_bytes": err_limit,
               "stdout": results[0], "stderr": results[1]}
    print("observer-eof-command-receipt " + json.dumps(receipt, sort_keys=True), flush=True)
    if not settled or interrupted:
        raise RuntimeError("unsettled diagnostic launch; preserve its workspace")
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", required=True, type=Path)
    parser.add_argument("--scratch-parent", required=True, type=Path)
    parser.add_argument("--go", required=True)
    parser.add_argument("--controls-only", action="store_true")
    parser.add_argument("--full-resource-sequence", action="store_true")
    args = parser.parse_args()
    root, parent = P.unlinked_path(args.source_root), P.unlinked_path(args.scratch_parent)
    P.require(root.is_dir() and parent.is_dir() and root != parent and root not in parent.parents)
    P.require(args.controls_only or sys.platform == "win32")
    P.require(not (args.controls_only and args.full_resource_sequence))
    P.require(shutil.disk_usage(parent).free >= (10 << 30) + (1 << 30))
    # The temporary context owns only this newly created directory. Ordinary
    # Go tests clean their own TempDirs; all output has already streamed once.
    workspace = tempfile.TemporaryDirectory(prefix="observer-eof-diagnostic-", dir=parent)
    try:
        work = Path(workspace.name)
        manifest = P.prepare(root, work / "overlay", full_resource_sequence=args.full_resource_sequence)
        print("observer-eof-overlay-selection " + json.dumps(manifest, sort_keys=True), flush=True)
        env = os.environ.copy()
        env.update(GOTOOLCHAIN="local", GOWORK="off", GOENV="off", GOFLAGS="", PYTHONDONTWRITEBYTECODE="1",
                   SPV_OBSERVER_EOF_OVERLAY=str(work / "overlay/overlay.json"))
        for key, name in (("GOCACHE", "build-cache"), ("GOMODCACHE", "module-cache"), ("GOTMPDIR", "go-temp")):
            path = work / name
            path.mkdir()
            env[key] = str(path)
        for key in ("TMPDIR", "TMP", "TEMP"):
            env[key] = env["GOTMPDIR"]
        commands = [
            ("compiler", [args.go, "version"], 30),
            ("overlay-preparation-controls", [sys.executable, "-I", "-B", str(P.HERE / "prepare_test.py"), "-v"], 60),
            ("bounded-capture-controls", [sys.executable, "-I", "-B", str(P.HERE / "run_test.py"), "-v"], 60),
        ]
        control_image = work / "observer-eof-controls.exe"
        if sys.platform == "win32":
            # Go's implicit test image removal failed in the retained first
            # Windows generation. Compile once and supervise that exact image;
            # keep build, test exit and owned-image removal as separate facts.
            commands.extend([
                ("instrumented-EOF-controls-build", [args.go, "test", "-p", "1", "-overlay", env["SPV_OBSERVER_EOF_OVERLAY"],
                                                     "-c", "-o", str(control_image), "./tools/observe-block"], 240),
                ("instrumented-EOF-controls", [str(control_image), "-test.v", "-test.count=1", "-test.timeout=3m", "-test.run=" + CONTROLS], 240),
            ])
        else:
            commands.append(("instrumented-EOF-controls", [args.go, "test", "-p", "1", "-overlay", env["SPV_OBSERVER_EOF_OVERLAY"],
                                             "-v", "-count=1", "-timeout", "3m", "-run", CONTROLS, "./tools/observe-block"], 240))
        if not args.controls_only:
            label = "instrumented-Windows-resource-full-sequence" if args.full_resource_sequence else "instrumented-Windows-resource-generation"
            commands.append((label, [args.go, "test", "-p", "1", "-overlay",
                             env["SPV_OBSERVER_EOF_OVERLAY"], "-v", "-count=1", "-timeout", "10m", "-run",
                             resource_pattern(args.full_resource_sequence), "./internal/conformance"], 660))
        for label, argv, timeout in commands:
            print("observer-eof-command-selection " + json.dumps({"label": label, "attempt": 1, "timeout_seconds": timeout}), flush=True)
            try:
                selected_image = image_pin(control_image) if label == "instrumented-EOF-controls" and sys.platform == "win32" else None
            except (OSError, ValueError):
                raise RuntimeError("diagnostic image cannot be selected; preserve workspace") from None
            if selected_image is not None:
                print("observer-eof-control-image-selection " + json.dumps(selected_image[1], sort_keys=True), flush=True)
            receipt = capture(argv, root, env, timeout)
            if receipt["reason"] is not None or not receipt["output_complete"]:
                raise RuntimeError("incomplete diagnostic command; preserve its workspace")
            if receipt["actual_exit"] != 0:
                print("observer-eof-generation-result " + json.dumps({"status": "FAILED_RETAIN_ACTUAL_OUTPUT", "failed_phase": label,
                      "ordinary_qualification": False, "retry_performed": False}), flush=True)
                return 1
            if selected_image is not None:
                removal = remove_control_image(control_image, selected_image)
                print("observer-eof-control-image-removal " + json.dumps(removal, sort_keys=True), flush=True)
        P.require(all(P.sha(P.regular(root / name)) == digest for name, digest in P.PINS.items()))
        print("observer-eof-generation-result " + json.dumps({"status": "CONTROLS_PASSED" if args.controls_only else "NOT_REPRODUCED",
              "ordinary_qualification": False, "retry_performed": False, "source_bytes_unchanged": True}), flush=True)
        return 0
    except (RuntimeError, subprocess.SubprocessError, KeyboardInterrupt):
        # Do not remove files that could still be in use by an uncertain child.
        workspace._finalizer.detach()
        raise
    finally:
        if workspace._finalizer.alive:
            workspace.cleanup()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
        print("observer-eof diagnostic refused; retain actual output and inspect owned scratch", file=sys.stderr)
        sys.exit(2)
