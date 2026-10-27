#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Bounded, serial reuse of pure leaf commitments in one recorded tree oracle.

The selected reference graph still visits every leaf and rebuilds every node and
edge dictionary. Only an unchanged leaf's depth/path/value hash chain is reused.
No fixture, producer, database, disk cache or accepted state is changed here.
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
MAX_ENTRIES = 8192
MAX_BYTES = 2 << 20
MAX_STATE_ENTRIES = 4096
MAX_VALUE_BYTES = 4096
SOURCE_PINS = {
    'check.py': 'e12669998c97086abcd6da1d6e70fb3c99e6db5fd8dd9a1be6eb063d343a13e1',
    'check_retention.py': '1ac663522fc16ce96983d9a6fb5e0973fd75ad190d3724c72598f2684c211753',
    'check_tree_scale.py': '558787e3c10a3cff6ea31a1062d2bb7c27c12cc55fc5d390c177783848c278e5',
    'check_tree_scale_test.py': '7fe0b5dab7b6f6b7f990c46cfad40fed933165a393c83c83aa350ae0c4cd6567',
}
PROGRAMS = ('check_tree_scale.py', 'check_tree_scale_test.py')


def require(condition):
    if not condition:
        raise ValueError('Bounded leaf commitment reuse refused')


def verify_sources():
    pins = {}
    for name, expected in SOURCE_PINS.items():
        path = HERE / name
        require(path.is_file() and not path.is_symlink())
        with path.open('rb') as handle:
            raw = handle.read((1 << 20) + 1)
        require(len(raw) <= 1 << 20)
        pins[name] = hashlib.sha256(raw).hexdigest()
        require(pins[name] == expected)
    return pins


verify_sources()
_spec = importlib.util.spec_from_file_location('leaf_reuse_pinned_reference', HERE / 'check_retention.py')
REFERENCE = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(REFERENCE)


def same_function(actual, reference, owner):
    return (type(actual) is FunctionType and actual.__globals__ is vars(owner)
            and actual.__code__ == reference.__code__ and actual.__closure__ is None
            and actual.__defaults__ == reference.__defaults__
            and actual.__kwdefaults__ == reference.__kwdefaults__)


def selected_module(program, selected):
    require(type(selected) is str and selected in PROGRAMS and type(program) is ModuleType)
    require(type(getattr(program, '__file__', None)) is str
            and Path(program.__file__).resolve() == HERE / selected)
    if selected.endswith('_test.py'):
        program = getattr(program, 'CHECK', None)
        require(type(program) is ModuleType and type(getattr(program, '__file__', None)) is str
                and Path(program.__file__).resolve() == HERE / PROGRAMS[0])
    module = getattr(program, 'RET', None)
    require(type(module) is ModuleType and type(getattr(module, '__file__', None)) is str
            and Path(module.__file__).resolve() == HERE / 'check_retention.py')
    require(same_function(module.graph, REFERENCE.graph, module))
    byte = module.BYTE
    require(type(byte) is ModuleType and Path(byte.__file__).resolve() == HERE / 'check.py')
    for name in ('digest', 'parent', 'require'):
        require(same_function(getattr(byte, name), getattr(REFERENCE.BYTE, name), byte))
    require(type(module.ZERO) is bytes and module.ZERO == bytes(32))
    require(type(byte.ZERO) is bytes and byte.ZERO == bytes(32))
    require(byte.hashlib is REFERENCE.BYTE.hashlib)
    return module


def snapshot(state):
    # Unselected types and sizes keep the original function's exact behavior.
    if type(state) is not dict or len(state) > MAX_STATE_ENTRIES:
        return None
    if any(type(path) is not bytes or len(path) != 32 or type(value) is not bytes
           or len(value) > MAX_VALUE_BYTES for path, value in state.items()):
        return None
    return tuple(state.items())


class LeafReuse:
    def __init__(self, module, max_bytes=MAX_BYTES, max_entries=MAX_ENTRIES):
        require(type(max_bytes) is int and 0 < max_bytes <= MAX_BYTES)
        require(type(max_entries) is int and 0 < max_entries <= MAX_ENTRIES)
        self.module, self.original, self.byte = module, module.graph, module.BYTE
        require(same_function(self.original, REFERENCE.graph, module))
        self.inputs, self.tool_pin = verify_sources(), hashlib.sha256(TOOL.read_bytes()).hexdigest()
        self.dependencies = {name: getattr(self.byte, name) for name in ('digest', 'parent', 'require')}
        self.sha3, self.thread = self.byte.hashlib.sha3_256, threading.get_ident()
        self.max_bytes, self.max_entries = max_bytes, max_entries
        self._cache, self._bytes = OrderedDict(), 0
        self.graph_requests = self.completed_graphs = self.failed_graphs = 0
        self.bypassed_inputs = self.leaf_requests = 0
        self.hits = self.misses = self.evictions = self.unretained = 0
        self.parent_calls = self.parent_calls_avoided = self.peak_entries = self.peak_bytes = 0
        self.closed = False
        self.replacement = self.graph

    def intact(self):
        return (threading.get_ident() == self.thread
                and self.module.graph is self.replacement and self.module.BYTE is self.byte
                and same_function(self.original, REFERENCE.graph, self.module)
                and type(self.module.ZERO) is bytes and self.module.ZERO == bytes(32)
                and type(self.byte.ZERO) is bytes and self.byte.ZERO == bytes(32)
                and self.byte.hashlib is REFERENCE.BYTE.hashlib
                and self.byte.hashlib.sha3_256 is self.sha3
                and all(getattr(self.byte, name) is original
                        and same_function(original, getattr(REFERENCE.BYTE, name), self.byte)
                        for name, original in self.dependencies.items()))

    def install(self):
        self.module.graph = self.replacement
        require(self.intact())

    def _leaf(self, depth, path, value):
        key = depth, path, value
        self.leaf_requests += 1
        if key in self._cache:
            self.hits += 1
            self.parent_calls_avoided += 256 - depth
            result, _ = self._cache[key]
            self._cache.move_to_end(key)
            return result
        self.misses += 1
        node = self.byte.digest(path + value)
        result, index, zero = node, int.from_bytes(path, 'big'), bytes(32)
        for level in range(255, depth - 1, -1):
            result = (self.byte.parent(result, zero) if (index >> (255 - level)) & 1 == 0
                      else self.byte.parent(zero, result))
            self.parent_calls += 1
        saved = node, result
        # Logical payload accounting: depth u16, path, value, node and commitment.
        # Python container overhead and total process RSS are separate quantities.
        weight = 2 + len(path) + len(value) + len(node) + len(result)
        if weight > self.max_bytes:
            self.unretained += 1
            return saved
        while self._cache and (len(self._cache) >= self.max_entries or self._bytes + weight > self.max_bytes):
            _, (_, previous) = self._cache.popitem(last=False)
            self._bytes -= previous
            self.evictions += 1
        self._cache[key] = saved, weight
        self._bytes += weight
        self.peak_entries = max(self.peak_entries, len(self._cache))
        self.peak_bytes = max(self.peak_bytes, self._bytes)
        return saved

    def graph(self, state):
        require(not self.closed and self.intact())
        self.graph_requests += 1
        try:
            result = self._graph(state)
        except BaseException:
            self.failed_graphs += 1
            raise
        self.completed_graphs += 1
        return result

    def _graph(self, state):
        selected = snapshot(state)
        if selected is None:
            self.bypassed_inputs += 1
            result = self.original(state)
            require(self.intact())
            return result
        nodes, edges = {}, {}
        zero = bytes(32)

        def build(depth, leaves):
            if not leaves:
                return zero, zero
            if len(leaves) == 1:
                path, value = next(iter(leaves.items()))
                node, commitment = self._leaf(depth, path, value)
                nodes[node] = b'\x00' + path + value
                return node, commitment
            left = {p: v for p, v in leaves.items() if not (int.from_bytes(p, 'big') >> (255 - depth)) & 1}
            right = {p: v for p, v in leaves.items() if (int.from_bytes(p, 'big') >> (255 - depth)) & 1}
            left_id, left_hash = build(depth + 1, left)
            right_id, right_hash = build(depth + 1, right)
            root = self.byte.parent(left_hash, right_hash)
            if left_id == zero:
                return right_id, root
            if right_id == zero:
                return left_id, root
            encoded = b'\x01' + depth.to_bytes(2, 'big') + left_hash + left_id + right_hash + right_id
            self.byte.require(root not in nodes or nodes[root] == encoded, 'graph identifier collision')
            nodes[root], edges[root] = encoded, (left_id, right_id)
            return root, root

        root, commitment = build(0, dict(selected))
        require(snapshot(state) == selected and self.intact())
        return root, commitment, nodes, edges

    def close(self):
        intact = self.intact()
        self.module.graph = self.original
        self._cache.clear()
        self._bytes, self.closed = 0, True
        require(intact and verify_sources() == self.inputs
                and hashlib.sha256(TOOL.read_bytes()).hexdigest() == self.tool_pin)

    def report(self):
        require(self.closed and not self._cache and self._bytes == 0 and self.module.graph is self.original)
        return {'maximum_entries': self.max_entries, 'maximum_logical_cached_bytes': self.max_bytes,
                'maximum_state_entries': MAX_STATE_ENTRIES, 'maximum_value_bytes': MAX_VALUE_BYTES,
                'graph_requests': self.graph_requests, 'completed_graphs': self.completed_graphs,
                'failed_graphs': self.failed_graphs, 'bypassed_inputs': self.bypassed_inputs,
                'leaf_requests': self.leaf_requests, 'cache_hits': self.hits, 'cache_misses': self.misses,
                'evictions': self.evictions, 'unretained_results': self.unretained,
                'leaf_parent_calls': self.parent_calls, 'leaf_parent_calls_avoided': self.parent_calls_avoided,
                'peak_entries': self.peak_entries, 'peak_logical_cached_bytes': self.peak_bytes,
                'key_is_complete_depth_path_value': True,
                'every_graph_traversal_completed': self.graph_requests == self.completed_graphs,
                'mutable_node_and_edge_results_independent': True,
                'reference_graph_replaced_explicitly': True, 'reference_source_bytes_unchanged': self.inputs,
                'helper_sha256': self.tool_pin, 'selected_function_restored': True, 'cache_cleared': True,
                'disk_cache_created': False, 'cross_process_or_context_reuse': False,
                'serial_caller_required': True, 'process_RSS_budget_qualified': False,
                'recorded_producer_source_inputs_rebound': False, 'new_node_execution': False,
                'state_value_acceptance_enabled': False}


@contextmanager
def selected_leaves(program, selected, max_bytes=MAX_BYTES, max_entries=MAX_ENTRIES):
    scope = LeafReuse(selected_module(program, selected), max_bytes, max_entries)
    try:
        scope.install()
        yield scope
    finally:
        scope.close()
