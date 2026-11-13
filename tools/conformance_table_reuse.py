#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Bounded process-local reuse of exact recorded retention table bytes.

Only the pinned table expansion is selected. The original reader still replays
the full history and checks every payload digest, root, proof and process row.
No observation validation result, disk cache or native workload is cached.
"""
from collections import OrderedDict
from contextlib import contextmanager
import hashlib
import importlib.util
from pathlib import Path
import threading
from types import FunctionType, ModuleType

HERE = Path(__file__).resolve().parent / 'gen-state-root-vectors'
TOOL = Path(__file__).resolve()
MAX_ENTRIES = 4
MAX_BYTES = 32 << 20
MAX_TABLE_BYTES = 256 << 10
MAX_TABLE_NODES = 4096
ROOT_COUNT = 32768
SOURCE_PINS = {
    'check_default_retention_corpus.py': 'c658a5ddb5b0f7aeec0a13be05fb433d5fd04b77469ef16feb0c33f4f66c2c40',
    'check_default_retention.py': '37e5208595a69276001257cdde6074867e380edd6aaee3c11374656eb8af3114',
    'default_retention_model.py': 'dd5dcc89eb5357faadc3ed8bcfb1a28f4af1492e73f11e5ac8341011c6e68c8a',
    'check_default_retention_corpus_test.py': '0d1eee52babe7e4156703559f2317e84356cdfa83048cf1b431514b8c56ec2e5',
}


def require(condition):
    if not condition:
        raise ValueError('Bounded recorded-table reuse refused')


def verify_sources():
    result = {}
    for name, expected in SOURCE_PINS.items():
        path = HERE / name
        require(path.is_file() and not path.is_symlink())
        with path.open('rb') as stream:
            raw = stream.read((256 << 10) + 1)
        require(len(raw) <= 256 << 10)
        result[name] = hashlib.sha256(raw).hexdigest()
        require(result[name] == expected)
    return result


verify_sources()
_spec = importlib.util.spec_from_file_location('table_reuse_pinned_reader', HERE / 'check_default_retention_corpus.py')
REFERENCE = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(REFERENCE)


def same_function(actual, reference, owner):
    return (type(actual) is FunctionType and actual.__globals__ is vars(owner)
            and actual.__code__ == reference.__code__ and actual.__closure__ is None
            and actual.__defaults__ == reference.__defaults__
            and actual.__kwdefaults__ == reference.__kwdefaults__)


class UnsupportedInput(Exception):
    pass


def snapshot(table, roots):
    """Keep complete typed builtin inputs; unsupported shapes use the original."""
    if (type(roots) is not list or len(roots) != ROOT_COUNT
            or any(type(v) is not str or len(v) != 64 or not v.isascii() for v in roots)):
        return None
    nodes, size = 0, 0

    def freeze(value, depth=0):
        nonlocal nodes, size
        nodes += 1
        if nodes > MAX_TABLE_NODES or depth > 12:
            raise UnsupportedInput
        kind = type(value)
        if value is None:
            size += 1
            frozen = ('null',)
        elif kind is bool:
            size += 2
            frozen = ('bool', value)
        elif kind is int and value.bit_length() <= 64:
            size += 9
            frozen = ('int', value)
        elif kind is str and len(value) <= MAX_TABLE_BYTES:
            size += 1 + len(value.encode('utf-8'))
            frozen = ('str', value)
        elif kind is list and len(value) <= MAX_TABLE_NODES:
            size += 1
            frozen = ('list', tuple(freeze(v, depth + 1) for v in value))
        elif kind is dict and len(value) <= MAX_TABLE_NODES and all(type(k) is str for k in value):
            size += 1
            frozen = ('dict', tuple((freeze(k, depth + 1), freeze(v, depth + 1))
                                    for k, v in value.items()))
        else:
            raise UnsupportedInput
        if size > MAX_TABLE_BYTES:
            raise UnsupportedInput
        return frozen

    try:
        key = freeze(table), tuple(roots)
    except (UnsupportedInput, UnicodeError, RecursionError):
        return None
    return key, size + ROOT_COUNT * 64


class TableReuse:
    def __init__(self, reader, max_entries=MAX_ENTRIES, max_bytes=MAX_BYTES):
        require(type(max_entries) is int and 0 < max_entries <= MAX_ENTRIES)
        require(type(max_bytes) is int and 0 < max_bytes <= MAX_BYTES)
        require(type(reader) is ModuleType and Path(reader.__file__).resolve()
                == HERE / 'check_default_retention_corpus.py')
        self.reader, self.original = reader, reader.expand_table
        self.c, self.m = reader.C, reader.M
        require(type(self.c) is ModuleType and Path(self.c.__file__).resolve() == HERE / 'check_default_retention.py')
        require(type(self.m) is ModuleType and Path(self.m.__file__).resolve() == HERE / 'default_retention_model.py')
        require(same_function(self.original, REFERENCE.expand_table, reader))
        self.bindings = [(owner, name, getattr(owner, name), reference) for owner, name, reference in (
            (reader, 'require', REFERENCE.require), (self.c, 'require', REFERENCE.C.require),
            (self.c, 'uint', REFERENCE.C.uint), (self.c, 'digest', REFERENCE.C.digest),
            (self.c, 'identifier', REFERENCE.C.identifier), (self.m, 'encoded', REFERENCE.M.encoded))]
        require(all(same_function(actual, reference, owner) for owner, _, actual, reference in self.bindings))
        self.sha3, self.regex, self.dumps = self.c.hashlib.sha3_256, self.c.re.fullmatch, self.m.json.dumps
        self.inputs, self.tool_pin = verify_sources(), hashlib.sha256(TOOL.read_bytes()).hexdigest()
        self.owner = threading.get_ident()
        self.snapshot_function, self.snapshot_code = snapshot, snapshot.__code__
        self.max_entries, self.max_bytes = max_entries, max_bytes
        self.cache, self.bytes = OrderedDict(), 0
        self.calls = self.hits = self.computations = self.errors = self.bypassed = 0
        self.evictions = self.unretained = self.peak_entries = self.peak_bytes = 0
        self.closed = self.restored = self.cleared = False
        self.wrapper = self.expand_table
        self.wrapper_code = self.wrapper.__func__.__code__

    def intact(self):
        return (threading.get_ident() == self.owner and self.reader.expand_table is self.wrapper
                and self.reader.C is self.c and self.reader.M is self.m
                and snapshot is self.snapshot_function and snapshot.__code__ is self.snapshot_code
                and self.wrapper.__func__.__code__ is self.wrapper_code
                and same_function(self.original, REFERENCE.expand_table, self.reader)
                and all(getattr(owner, name) is actual and same_function(actual, reference, owner)
                        for owner, name, actual, reference in self.bindings)
                and self.c.hashlib.sha3_256 is self.sha3 and self.c.re.fullmatch is self.regex
                and self.m.json.dumps is self.dumps)

    def expand_table(self, table, roots):
        require(not self.closed and self.intact())
        self.calls += 1
        selected = snapshot(table, roots)
        if selected is not None and selected[0] in self.cache:
            key = selected[0]
            result, _ = self.cache[key]
            require(snapshot(table, roots) == selected and self.intact())
            self.cache.move_to_end(key)
            self.hits += 1
            return result  # Immutable bytes; no mutable report or table is shared.
        self.computations += 1
        try:
            result = self.original(table, roots)
        except BaseException:
            self.errors += 1
            require(self.intact())
            raise
        require(self.intact())
        if selected is None:
            self.bypassed += 1
            return result
        require(snapshot(table, roots) == selected)
        key, input_bytes = selected
        if type(result) is not bytes or input_bytes + len(result) > self.max_bytes:
            self.unretained += 1
            return result
        weight = input_bytes + len(result)
        while self.cache and (len(self.cache) >= self.max_entries or self.bytes + weight > self.max_bytes):
            _, (_, previous) = self.cache.popitem(last=False)
            self.bytes -= previous
            self.evictions += 1
        self.cache[key] = result, weight
        self.bytes += weight
        self.peak_entries = max(self.peak_entries, len(self.cache))
        self.peak_bytes = max(self.peak_bytes, self.bytes)
        return result

    def report(self):
        return {'format': 'bounded-recorded-table-reuse/v1', 'calls': self.calls,
                'original_computations': self.computations, 'hits': self.hits,
                'original_errors': self.errors, 'unsupported_input_bypasses': self.bypassed,
                'unretained_results': self.unretained, 'evictions': self.evictions,
                'max_entries': self.max_entries, 'max_logical_bytes': self.max_bytes,
                'peak_entries': self.peak_entries, 'peak_logical_bytes': self.peak_bytes,
                'logical_bytes_exclude_python_overhead_and_RSS': True,
                'complete_typed_input_keys': True, 'serial_scope_lease': True, 'source_pins': self.inputs,
                'helper_sha256': self.tool_pin, 'restored': self.restored,
                'cleared': self.cleared, 'retained_entries': len(self.cache),
                'retained_logical_bytes': self.bytes, 'disk_cache_created': False,
                'original_history_or_observation_checks_skipped': False}


_ACTIVE = None
_LEASE = threading.Lock()


@contextmanager
def reuse(reader, max_entries=MAX_ENTRIES, max_bytes=MAX_BYTES):
    global _ACTIVE
    require(_LEASE.acquire(blocking=False))
    session = None
    try:
        require(_ACTIVE is None)
        session = TableReuse(reader, max_entries, max_bytes)
        _ACTIVE = session
        reader.expand_table = session.wrapper
        try:
            yield session
        finally:
            require(session.intact() and verify_sources() == session.inputs
                    and hashlib.sha256(TOOL.read_bytes()).hexdigest() == session.tool_pin)
    finally:
        if session is not None:
            reader.expand_table = session.original
            session.restored = reader.expand_table is session.original
            session.cache.clear()
            session.bytes = 0
            session.closed = True
            session.cleared = not session.cache and session.bytes == 0
            _ACTIVE = None
        _LEASE.release()
