#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Observe bounded synthetic patch planning in a fresh process per sample.

Python allocation peak, operation elapsed time and OS process high-water memory
are separate observations. No node, storage import or production budget executes.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import struct
import subprocess
import sys
import tempfile
import time
import tracemalloc

HERE = Path(__file__).resolve().parent


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


PLAN = module('measured_patch_plan', 'plan_patch.py')
CHECK = module('patch_resource_oracle', 'check_patch_plan_resources.py')


def variable_length(value):
    result = bytearray()
    while value > 127:
        result.append(128 | (value & 127))
        value >>= 7
    result.append(value)
    return result


def fixture(profile):
    raw = bytearray()
    for index in range(profile['record_count']):
        if profile['family'] == 'records':
            key, value = struct.pack('>H', index), b'v' * 1000
        elif profile['family'] == 'values':
            key, value = bytes([index]), bytes([index]) * (65536 if index != 15 else 65440)
        else:
            key, value = struct.pack('>H', index) + bytearray(4094), b'v'
        raw.append(1)
        raw.extend(variable_length(len(key)))
        raw.extend(key)
        raw.extend(variable_length(len(value)))
        raw.extend(value)
    return bytes(raw)


def process_peak():
    if sys.platform in ('linux', 'darwin'):
        import resource
        amount = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        multiplier = 1024 if sys.platform == 'linux' else 1
        return {'bytes': int(amount * multiplier), 'metric': 'process_peak_rss_bytes', 'available': True}
    if sys.platform == 'win32':
        import ctypes
        from ctypes import wintypes

        class Counters(ctypes.Structure):
            _fields_ = [('cb', wintypes.DWORD), ('faults', wintypes.DWORD)] + [
                (name, ctypes.c_size_t) for name in ('peak_working_set', 'working_set',
                'quota_peak_paged', 'quota_paged', 'quota_peak_nonpaged', 'quota_nonpaged',
                'pagefile', 'peak_pagefile')]

        counters = Counters()
        counters.cb = ctypes.sizeof(counters)
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel.GetCurrentProcess.restype = wintypes.HANDLE
        api = ctypes.WinDLL('psapi', use_last_error=True).GetProcessMemoryInfo
        api.argtypes = (wintypes.HANDLE, ctypes.POINTER(Counters), wintypes.DWORD)
        api.restype = wintypes.BOOL
        if api(kernel.GetCurrentProcess(), ctypes.byref(counters), counters.cb):
            return {'bytes': int(counters.peak_working_set), 'metric': 'peak_working_set_bytes', 'available': True}
    return {'bytes': None, 'metric': 'unavailable', 'available': False}


def worker(profile, path, number, traced, source_revision):
    # Validate selected constants before instrumentation; no input synthesis or
    # independent full-event oracle is part of the measured worker operation.
    selection = {'bytes': profile['raw_bytes'], 'records': profile['record_count'],
                 'changes_hash': profile['changes_hash']}
    PLAN.validate(selection, CHECK.LIMITS)
    if traced:
        tracemalloc.start()
    started = time.perf_counter_ns()
    raw = PLAN.read_raw(path, selection, CHECK.LIMITS)
    document = PLAN.make_plan(raw, selection, CHECK.LIMITS, source_revision)
    output = PLAN.encode_plan(document, CHECK.LIMITS['plan_bytes'])
    elapsed = time.perf_counter_ns() - started
    peak = tracemalloc.get_traced_memory()[1] if traced else None
    if traced:
        tracemalloc.stop()
    result = {'repetition': number, 'traced': traced, 'elapsed_ns': elapsed,
        'python_traced_peak_bytes': peak, 'process_peak_memory': process_peak(),
        'plan_bytes': len(output), 'plan_sha256': hashlib.sha256(output).hexdigest(),
        'consumer_result': document['consumer_result']}
    return result


def runtime():
    architecture = platform.machine().lower()
    architecture = {'x86_64': 'amd64', 'aarch64': 'arm64'}.get(architecture, architecture)
    return {'os': {'win32': 'windows'}.get(sys.platform, sys.platform), 'architecture': architecture,
        'python': '.'.join(str(v) for v in sys.version_info[:3]), 'implementation': platform.python_implementation()}


def main(argv=None):
    parser = PLAN.PrivateParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--source-revision')
    parser.add_argument('--repetitions', default=3, type=PLAN.number)
    parser.add_argument('--worker', choices=[name for name, family, count in CHECK.FAMILIES])
    parser.add_argument('--raw', type=Path)
    parser.add_argument('--sample', type=PLAN.number)
    parser.add_argument('--traced', choices=('0', '1'))
    args = parser.parse_args(argv)
    CHECK.revision(args.source_revision)
    CHECK.require(1 <= args.repetitions <= 3)
    # A worker loads only the tiny fixed manifest. Constructing the large oracle
    # inputs before measurement would contaminate its whole-process high water.
    if args.worker:
        with (HERE / 'testdata/patch-plan-resource-inputs.json').open('rb') as stream:
            manifest_bytes = stream.read((16 << 10) + 1)
        CHECK.require(len(manifest_bytes) <= 16 << 10)
        manifest = json.loads(manifest_bytes, object_pairs_hook=CHECK.ORACLE.BYTE.object_pairs)
        CHECK.require(type(manifest) is dict and set(manifest) == {'format_version', 'kind', 'cases'})
        CHECK.exact(manifest['format_version'], 1)
        CHECK.exact(manifest['kind'], 'patch-plan-resource-input-selection')
        CHECK.require(type(manifest['cases']) is list and len(manifest['cases']) == 6)
        CHECK.require(args.raw is not None and args.sample in (1, 2, 3) and args.traced in ('0', '1'))
        profile = next(row for row in manifest['cases'] if row['name'] == args.worker)
        result = worker(profile, args.raw, args.sample, args.traced == '1', args.source_revision)
    else:
        CHECK.require(args.raw is None and args.sample is None and args.traced is None)
        rows = CHECK.profiles()
        cases = []
        os.umask(0o077)
        with tempfile.TemporaryDirectory(prefix='patch-plan-resource-') as directory:
            for profile in rows:
                raw = fixture(profile)
                CHECK.require(len(raw) == profile['raw_bytes'] and hashlib.sha256(raw).hexdigest() == profile['input_sha256'])
                events, refusal = CHECK.ORACLE.preflight(raw, CHECK.LIMITS)
                CHECK.require(not refusal)
                CHECK.exact(events, CHECK.events(profile['name']))
                path = Path(directory) / (profile['name'] + '.dump')
                path.write_bytes(raw)
                case = profile | CHECK.output_selection(profile, args.source_revision) | {'samples': []}
                for repetition in range(1, args.repetitions + 1):
                    for traced in (False, True):
                        command = [sys.executable, '-I', '-B', str(HERE / 'measure_patch_plan.py'),
                            '--worker', profile['name'], '--raw', str(path), '--sample', str(repetition),
                            '--traced', str(int(traced))]
                        if args.source_revision is not None:
                            command.extend(['--source-revision', args.source_revision])
                        run = subprocess.run(command, capture_output=True, timeout=45)
                        CHECK.require(run.returncode == 0 and not run.stderr and len(run.stdout) <= 8192)
                        case['samples'].append(json.loads(run.stdout, object_pairs_hook=CHECK.ORACLE.BYTE.object_pairs))
                cases.append(case)
        files = ('plan_patch.py', 'measure_patch_plan.py', 'check_patch_plan_resources.py', 'testdata/patch-plan-resource-inputs.json')
        result = {'format_version': 1, 'kind': 'read-only-patch-plan-resource-observations',
            'source_revision': args.source_revision, 'source_files_sha256': {name: hashlib.sha256((HERE / name).read_bytes()).hexdigest() for name in files},
            'runtime': runtime(), 'repetitions': args.repetitions, 'limits': CHECK.LIMITS,
            'scope': CHECK.SCOPE, 'measurement_result': 'OBSERVED', 'consumer_result': 'REFUSED', 'cases': cases}
        CHECK.validate_report(result, args.source_revision)
    encoded = (json.dumps(result, sort_keys=True, separators=(',', ':')) + '\n').encode('ascii')
    CHECK.require(len(encoded) <= 64 << 10)
    sys.stdout.buffer.write(encoded)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, TypeError, KeyError, OSError, StopIteration, subprocess.TimeoutExpired):
        print('Patch resource observation refused; no complete report emitted. Production acceptance remains disabled.', file=sys.stderr)
        sys.exit(1)
