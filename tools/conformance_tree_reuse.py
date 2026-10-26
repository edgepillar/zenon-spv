#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Explicit bounded reuse of pure Git tree reconstruction in portable controls.

Source reads and validation remain fresh. Every admitted miss calls the unchanged
source-pinned implementation. Keys retain the complete ordered builtin pin map;
results are immutable Git object IDs. No source validation, checker, observation
or filesystem result is cached.
"""
from collections import OrderedDict
from contextlib import contextmanager
import hashlib
import importlib.util
from pathlib import Path, PurePosixPath
import threading
from types import FunctionType, ModuleType

HERE = Path(__file__).resolve().parent / "gen-state-root-vectors"
TOOL = Path(__file__).resolve()
MAX_ENTRIES = 32
MAX_BYTES = 8 << 20
MAX_PINS = 4096
MAX_MODULES = 64
SOURCE_PINS = {
    "check_cache_identifier_rollback.py": "4a26f264985732a2083b5abcdf0d63ee2bcb1a48490728007727f68f05364fcc",
    "check_cache_identifier_rollback_test.py": "4e40153dc28746afabfac3f5bae16c58781ed9a4d3745b4d4399b6d007faa996",
    "check_public_chain_lifecycle_successor.py": "1818ba4ce63ef8bfbcd50b2bc3f393904a570f4314774327973ebddbfe57b289",
    "prepare_cache_identifier_rollback.py": "bd7a84b674fc0c468a76da851723fd680660ee8b9a09ec82b1f2a8d54e4e4002",
    "prepare_offline_rebuild_successor.py": "90305012d8d31d1cd2a8d5fcb03645d4651ecad483b3bb23a126c1c98961a6ff",
    "prepare_public_chain_cache_startup.py": "14febb2a87cc7b3fa332cebd8639f76d423535421f39e9152ed1610d538ef2f7",
    "prepare_public_chain_lifecycle_successor.py": "810567fb64e97e9ea14ec1b286419d6f8151c49b498de6d74020a91a49428b7e",
    "prepare_recovery_successor.py": "3e381833a16a11522e70caccb29cb95d82b184fb403c2ece8eb2ec63f6b84315",
    "prepare_terminal_stop_successor.py": "69eaab69ae4e6f4f7c9fc79f5bda94d774f2ea3efcf9ec19808d788656044ee4",
    "regenerate.py": "d761f1b0671c74f0167a5e9aab7c8067e1ee35ad390c1cbd8c3fa151c4300448",
}
PROGRAM = "check_cache_identifier_rollback_test.py"
SEAMS = ("program.C.P.UTIL", "program.C.W.P.UTIL")
PIN_FIELDS = frozenset(("mode", "git_blob", "sha256", "bytes"))
_ACTIVE = None


def require(value):
    if not value:
        raise ValueError("Bounded Git tree reuse refused")


def source_bytes(path):
    require(path.is_file() and not path.is_symlink())
    with path.open("rb") as stream:
        raw = stream.read((1 << 20) + 1)
    require(0 < len(raw) <= 1 << 20)
    return raw


def verify_sources():
    actual = {name: hashlib.sha256(source_bytes(HERE / name)).hexdigest()
              for name in SOURCE_PINS}
    require(actual == SOURCE_PINS)
    return dict(sorted(actual.items()))


verify_sources()
_spec = importlib.util.spec_from_file_location("pinned_git_tree_reference", HERE / "regenerate.py")
REFERENCE = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(REFERENCE)
_SHA1 = hashlib.sha1


def same_function(actual, reference, owner):
    return (type(actual) is FunctionType and actual.__globals__ is vars(owner)
            and actual.__code__ == reference.__code__ and actual.__closure__ is None
            and actual.__defaults__ == reference.__defaults__
            and actual.__kwdefaults__ == reference.__kwdefaults__)


def dependencies(owner, original):
    return (same_function(original, REFERENCE.reconstruct_tree, owner)
            and same_function(getattr(owner, "git_hash", None), REFERENCE.git_hash, owner)
            and same_function(getattr(owner, "require", None), REFERENCE.require, owner)
            and getattr(owner, "PurePosixPath", None) is PurePosixPath
            and getattr(owner, "hashlib", None) is hashlib and hashlib.sha1 is _SHA1)


def selected_seams(program, selected=PROGRAM):
    require(type(selected) is str and selected == PROGRAM and type(program) is ModuleType)
    require(type(getattr(program, "__file__", None)) is str)
    require(Path(program.__file__).resolve() == HERE / selected)
    inputs = verify_sources()
    queue, seen, seams = [("program", program)], set(), []
    while queue:
        name, module = queue.pop(0)
        if id(module) in seen:
            continue
        seen.add(id(module))
        require(len(seen) <= MAX_MODULES)
        file = getattr(module, "__file__", None)
        require(type(file) is str and Path(file).resolve().parent == HERE)
        path = Path(file).resolve()
        require(path.name in inputs)
        if path.name == "regenerate.py":
            original = getattr(module, "reconstruct_tree", None)
            require(dependencies(module, original))
            seams.append((name, module, original))
        for key, value in sorted(vars(module).items()):
            file = getattr(value, "__file__", None) if type(value) is ModuleType else None
            if type(file) is str and Path(file).resolve().parent == HERE:
                queue.append((name + "." + key, value))
    require(tuple(name for name, _, _ in seams) == SEAMS)
    return seams, inputs


def cache_key(pins):
    """Snapshot complete admitted metadata; never replace inputs with a digest."""
    if type(pins) is not dict or len(pins) > MAX_PINS:
        return None
    rows = []
    for name, pin in pins.items():
        if (type(name) is not str or len(name) > 2048 or type(pin) is not dict
                or not 2 <= len(pin) <= 4):
            return None
        fields = tuple(pin.items())
        for key, value in fields:
            if type(key) is not str or key not in PIN_FIELDS:
                return None
            if type(value) is str:
                if len(value) > 4096:
                    return None
            elif type(value) is int:
                if not 0 <= value < 1 << 64:
                    return None
            else:
                return None
        if "mode" not in pin or "git_blob" not in pin:
            return None
        rows.append((name, fields))
    return tuple(rows)


def logical_bytes(key, result):
    try:
        return len(result.encode("ascii")) + sum(
            len(name.encode("utf-8")) + sum(len(field.encode("ascii"))
                + (len(value.encode("utf-8")) if type(value) is str else 8)
                for field, value in fields) for name, fields in key)
    except UnicodeError:
        return None


class TreeCache:
    def __init__(self, max_entries=MAX_ENTRIES, max_bytes=MAX_BYTES):
        require(type(max_entries) is int and 1 <= max_entries <= MAX_ENTRIES)
        require(type(max_bytes) is int and 1 <= max_bytes <= MAX_BYTES)
        self.max_entries, self.max_bytes = max_entries, max_bytes
        self.entries = OrderedDict()
        self.bytes = self.peak_bytes = 0
        self.calls = self.computations = self.hits = self.fallbacks = self.evictions = 0

    def get(self, pins, compute):
        self.calls += 1
        key = cache_key(pins)
        if key is None:
            self.fallbacks += 1
            self.computations += 1
            return compute(pins)
        found = self.entries.get(key)
        if found is not None:
            require(cache_key(pins) == key)
            self.entries.move_to_end(key)
            self.hits += 1
            return found[0]
        self.computations += 1
        result = compute(pins)
        require(cache_key(pins) == key)
        if type(result) is not str or len(result) != 40 or any(c not in "0123456789abcdef" for c in result):
            return result
        size = logical_bytes(key, result)
        if size is None or size > self.max_bytes:
            return result
        while self.entries and (len(self.entries) >= self.max_entries or self.bytes + size > self.max_bytes):
            _, (_, old_size) = self.entries.popitem(last=False)
            self.bytes -= old_size
            self.evictions += 1
        self.entries[key] = (result, size)
        self.bytes += size
        self.peak_bytes = max(self.peak_bytes, self.bytes)
        return result

    def clear(self):
        self.entries.clear()
        self.bytes = 0

    def report(self):
        return {"calls": self.calls, "original_computations": self.computations,
                "lookup_hits": self.hits, "fallbacks": self.fallbacks, "evictions": self.evictions,
                "entries": len(self.entries), "logical_bytes": self.bytes,
                "peak_logical_bytes": self.peak_bytes,
                "max_entries": self.max_entries, "max_logical_bytes": self.max_bytes}


class Session:
    def __init__(self, seams, inputs, max_entries, max_bytes):
        self.seams, self.inputs = seams, inputs
        self.owner = threading.get_ident()
        self.cache = TreeCache(max_entries, max_bytes)
        self.wrappers = []
        self.restored = self.cleared = False

    def wrapper(self, module, original):
        def reused(pins):
            require(threading.get_ident() == self.owner)
            require(module.reconstruct_tree is reused and dependencies(module, original))
            return self.cache.get(pins, original)
        return reused

    def report(self):
        return {"source_pins": dict(self.inputs), "selected_instances": [name for name, _, _ in self.seams],
                "cache": self.cache.report(), "original_functions_restored": self.restored,
                "cache_cleared": self.cleared, "source_validation_cached": False,
                "reference_backend_executions": 0, "production_acceptance_enabled": False}


@contextmanager
def reuse(program, selected=PROGRAM, max_entries=MAX_ENTRIES, max_bytes=MAX_BYTES):
    global _ACTIVE
    require(_ACTIVE is None)
    seams, inputs = selected_seams(program, selected)
    session = Session(seams, inputs, max_entries, max_bytes)
    _ACTIVE = session
    try:
        for _, module, original in seams:
            wrapper = session.wrapper(module, original)
            session.wrappers.append((module, original, wrapper))
            module.reconstruct_tree = wrapper
        try:
            yield session
        finally:
            require(threading.get_ident() == session.owner)
            for module, original, wrapper in session.wrappers:
                require(module.reconstruct_tree is wrapper and dependencies(module, original))
            require(verify_sources() == inputs)
    finally:
        for module, original, _ in session.wrappers:
            module.reconstruct_tree = original
        session.restored = all(module.reconstruct_tree is original for module, original, _ in session.wrappers)
        session.cache.clear()
        session.cleared = not session.cache.entries and session.cache.bytes == 0
        _ACTIVE = None
