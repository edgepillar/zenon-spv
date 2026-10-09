#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Capture one owned Unix child through exit, without interpreting its output.

The wall interval includes spawn and wait polling overhead. Per-child wait4
RSS includes the executable's harness, fixtures, final output and cleanup.
Neither is a minimum consumer footprint or a complete parent/build budget.
Output ceilings are acceptance/periodic termination controls, not peak disk
bounds: a writer can overshoot between polls. Preserve that actual output.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import time

WALL_METHOD = 'monotonic_ns immediately before Popen through per-child wait4 exit; includes spawn, wait polling/scheduling, child fixture, conformance, final output and cleanup; excludes parent parsing/hashing and source build'
RSS_METHOD = 'per-child wait4 ru_maxrss through exit; includes reference harness, fixture and final output; excludes parent and compiler; not minimum consumer memory'
OUTPUT_METHOD = 'closed captured stdout/stderr regular-file lengths and st_blocks*512 after child exit and fsync; not peak disk or input/database workspace'
WORKSPACE_METHOD = 'regular-file lengths and st_blocks*512 in the selected copied node/build directory outside child timing; excludes module/compiler caches, evidence output and child temporary input/database workspace; not peak disk'
POLL_NS = 10_000_000
TIMEOUT_NS = 600_000_000_000
OUTPUT_CEILING = 1 << 20


def require(condition):
    if not condition:
        raise ValueError('Child lifecycle capture refused; preserve owned evidence')


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode('ascii')


def seal(path, raw):
    with path.open('xb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    path.chmod(0o400)


def native_rss_unit(platform):
    require(platform in ('darwin', 'linux'))
    return ('bytes', 1) if platform == 'darwin' else ('KiB', 1024)


def preflight():
    native_rss_unit(sys.platform)
    require(hasattr(os, 'wait4') and hasattr(os, 'waitstatus_to_exitcode'))


def observe_workspace(root):
    root = Path(root)
    require(root.is_dir() and not root.is_symlink())
    sizes, allocated = [], 0
    for path in root.rglob('*'):
        require(not path.is_symlink())
        info = path.stat()
        if stat.S_ISREG(info.st_mode):
            require(hasattr(info, 'st_blocks'))
            sizes.append(info.st_size)
            allocated += info.st_blocks * 512
        else:
            require(stat.S_ISDIR(info.st_mode))
    require(bool(sizes))
    return {'method': WORKSPACE_METHOD, 'regular_files': len(sizes),
            'file_bytes': sum(sizes), 'largest_file_bytes': max(sizes),
            'allocated_file_bytes': allocated}


def capture_command(command, *, cwd, env, directory, label,
                    timeout_ns=TIMEOUT_NS, stdout_ceiling=OUTPUT_CEILING,
                    stderr_ceiling=OUTPUT_CEILING):
    """Reap only this child; seal actual streams and outcome before returning."""
    preflight()
    require(type(label) is str and re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9-]{0,100}', label))
    require(all(type(value) is int and value > 0 for value in
                (timeout_ns, stdout_ceiling, stderr_ceiling)))
    directory = Path(directory)
    require(directory.is_dir() and not directory.is_symlink())
    paths = {key: directory / ('lifecycle-' + label + '.' + key)
             for key in ('stdout', 'stderr', 'json')}
    require(all(not p.exists() and not p.is_symlink() for p in paths.values()))
    process, usage, wait_status, refusal, pending = None, None, None, '', None
    unit, factor = native_rss_unit(sys.platform)
    with paths['stdout'].open('xb') as out, paths['stderr'].open('xb') as err:
        started = time.monotonic_ns()
        try:
            process = subprocess.Popen(command, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                       stdout=out, stderr=err, close_fds=True)
            while True:
                pid, status, observed = os.wait4(process.pid, os.WNOHANG)
                if pid:
                    require(pid == process.pid)
                    wait_status, usage = status, observed
                    process.returncode = os.waitstatus_to_exitcode(status)
                    break
                if os.fstat(out.fileno()).st_size > stdout_ceiling or os.fstat(err.fileno()).st_size > stderr_ceiling:
                    refusal = 'output-ceiling'
                    break
                if time.monotonic_ns() - started >= timeout_ns:
                    refusal = 'timeout'
                    break
                time.sleep(POLL_NS / 1_000_000_000)
        except OSError:
            refusal = 'spawn-error' if process is None else 'capture-error'
        except BaseException as error:
            refusal, pending = 'capture-interrupted', error
        finally:
            if process is not None and process.returncode is None:
                try:
                    os.kill(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                pid, wait_status, usage = os.wait4(process.pid, 0)
                require(pid == process.pid)
                process.returncode = os.waitstatus_to_exitcode(wait_status)
            stopped = time.monotonic_ns()
            for stream in (out, err):
                stream.flush()
                os.fsync(stream.fileno())
    for key in ('stdout', 'stderr'):
        paths[key].chmod(0o400)
    raw_out, raw_err = paths['stdout'].read_bytes(), paths['stderr'].read_bytes()
    if len(raw_out) > stdout_ceiling or len(raw_err) > stderr_ceiling:
        refusal = refusal or 'output-ceiling'
    actual_exit = process.returncode if process is not None else None
    if actual_exit != 0:
        refusal = refusal or 'nonzero-exit'
    native_rss = usage.ru_maxrss if usage is not None else None
    if native_rss is not None:
        require(type(native_rss) is int and native_rss >= 0)
    outcome = {'label': label, 'completed': refusal != 'timeout' and process is not None,
        'process_reaped': wait_status is not None, 'actual_exit': actual_exit,
        'wait_status': wait_status, 'refusal': refusal, 'elapsed_ns': stopped - started,
        'wall_method': WALL_METHOD, 'poll_ns': POLL_NS, 'timeout_ns': timeout_ns,
        'rss_method': RSS_METHOD, 'native_rss_unit': unit,
        'native_peak_rss': native_rss,
        'process_peak_rss_bytes': native_rss * factor if native_rss is not None else None,
        'capture_platform': sys.platform, 'output_method': OUTPUT_METHOD,
        'stdout_bytes': len(raw_out), 'stderr_bytes': len(raw_err),
        'stdout_ceiling_bytes': stdout_ceiling, 'stderr_ceiling_bytes': stderr_ceiling,
        'captured_regular_files': 2,
        'captured_allocated_file_bytes': sum(paths[k].stat().st_blocks * 512 for k in ('stdout', 'stderr')),
        'stdout_sha256': hashlib.sha256(raw_out).hexdigest(),
        'stderr_sha256': hashlib.sha256(raw_err).hexdigest(),
        'parent_memory_measured': False, 'source_build_cost_measured': False,
        'input_temp_workspace_peak_measured': False, 'peak_disk_measured': False}
    seal(paths['json'], encoded(outcome))
    if pending is not None:
        raise pending
    return subprocess.CompletedProcess(command, actual_exit, raw_out, raw_err), outcome
