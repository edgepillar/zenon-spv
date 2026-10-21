#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Bounded, serial reuse of complete independently computed fixture graphs.

This optional execution seam changes no recorded producer, fixture or checker.
Every admitted key contains the complete ordered byte map. Cached roots, nodes
and edges are immutable; each caller receives independent mutable dictionaries.
There is no disk cache, observed-root key, cross-process reuse or import hook.
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
MAX_ENTRIES = 64
MAX_BYTES = 64 << 20
MAX_STATE_ENTRIES = 4096
MAX_VALUE_BYTES = 4096
MAX_MODULES = 128
SOURCE_PINS = {
    'capture_child_lifecycle.py': '13236adabb2f29c8a89a96aa8d448d4d5fb5c6a5c7e632b4ce601387034eea77',
    'check.py': 'e12669998c97086abcd6da1d6e70fb3c99e6db5fd8dd9a1be6eb063d343a13e1',
    'check_bulk_guards.py': '1ef972ae64630bbb3b7d0b19c3b1634b0eb5abc1d9e64a635276bcdbb974333c',
    'check_oracle_projection.py': '4a2b7d71d45876897f24d95e59d2e0c67406556290138f17e35788b6c5ff5897',
    'check_patch_decode.py': '8d34e52bf28e7e52c04fe67d6b19ebc4aba8aa84ab587620902e796275068f58',
    'check_patch_file.py': 'd59448135288680ebbd5a3d02dfdb15e12ff3b14c267474ac77d9b286b6bd873',
    'check_patch_import.py': 'e5047c98a124e7a07d4aeffe651df0af8fb84ce26fee1ce230efca8a3d1d61f4',
    'check_patch_resources.py': 'b82587acb9e3c8a8c682735a90e2a23b8c31fdd546d74d15b56dc268d6ea62f9',
    'check_patch_targets.py': 'f0871b4aa89a6b07f99a023029858fe2a7be61455d7968780e836af77db7e2c5',
    'check_patch_tree.py': '446d75f8828c907e01ed5aaf63b3b814d6231dd7c74e1b211d6e4c4f038f16e3',
    'check_patch_tree_tail.py': 'efa116bd77a81318bb83bc69541ebbd7801c7d6f0c4d0cfb207135a540a17981',
    'check_projected_driver.py': '370674f32c1e67667680f676f36b124032637859158c79e5e1cc7b67ebd05d8b',
    'check_projected_driver_test.py': '1f459e0e005ecf3cd626c5a053ff368a0a11bda9fd02b4eb1a8c77f228f573d2',
    'check_retention.py': '1ac663522fc16ce96983d9a6fb5e0973fd75ad190d3724c72598f2684c211753',
    'check_temp_workspace.py': '3b4bed44f6e25089f2c2a37ba935a773d2e476b7c82e1de1ff998095a621ae85',
    'check_temp_workspace_test.py': '162f8265a7bf3f68de6e5727f1d244b5f4e23f809c4f6e7b3a6c638e3da46833',
    'check_tree_driver_resources.py': '65b1399276cb68c86e7645c9c7490aee06711ce6d265d8c0528e98c9458dde97',
    'check_tree_driver_resources_test.py': '7db9a54834f9748818f5ee99b35d7bc65955533752051b7e1ac214fb2fd65862',
    'check_tree_import_lifecycle.py': '070ccb634d25d44640727bdc4bc81caf8c1b9032fa2304f1f20cb3d8d5be2b5c',
    'check_tree_import_scale.py': '81cd5dd12d59d6f5de4970bd362e12b4df40f28e4a258287f0b9822515e9db8e',
    'check_tree_scale.py': '558787e3c10a3cff6ea31a1062d2bb7c27c12cc55fc5d390c177783848c278e5',
    'observe_driver_resources.py': '2228beb965b9aa7ecae2fd011041c6c1bc426ba6ecc06898539b05aa33b1799d',
    'observe_temp_workspace.py': '53378dfd5dcfa1b531f59275cac7245ac6f37e1bd8c4fa5bd868870510a12c39',
    'project_driver_oracles.py': '6abaef95954b815ec974fcc2d48e105940690820f4405a0f275b29f5feb1eae9',
    'project_sparse_oracle.py': '2bb63506fc985126c153a3bd8b45c3512f4573d7118540a3f1f225f0761da6fb',
}
SEAMS = {
    'check_tree_driver_resources.py': (
        'program.RET', 'program.LIFE.SCALE.FILE.DEC.RET',
        'program.LIFE.SCALE.TAIL.GUARD.RET', 'program.LIFE.SCALE.TAIL.RESOURCE.DEC.RET'),
    'check_tree_driver_resources_test.py': (
        'program.CHECK.RET', 'program.CHECK.LIFE.SCALE.FILE.DEC.RET',
        'program.CHECK.LIFE.SCALE.TAIL.GUARD.RET',
        'program.CHECK.LIFE.SCALE.TAIL.RESOURCE.DEC.RET'),
    'check_temp_workspace.py': (
        'program.RET', 'program.LEGACY.PREVIOUS.RET', 'program.LEGACY.PROJECTOR.PROJECT.RET',
        'program.LIFE.SCALE.FILE.DEC.RET', 'program.LIFE.SCALE.TAIL.GUARD.RET',
        'program.LEGACY.PREVIOUS.IMPORT.FILE.DEC.RET',
        'program.LEGACY.PREVIOUS.IMPORT.TAIL.GUARD.RET',
        'program.LIFE.SCALE.TAIL.RESOURCE.DEC.RET',
        'program.LEGACY.PREVIOUS.IMPORT.TAIL.RESOURCE.DEC.RET',
        'program.LEGACY.PROJECTOR.PROJECT.IMPORT.FILE.DEC.RET',
        'program.LEGACY.PROJECTOR.PROJECT.IMPORT.TAIL.GUARD.RET',
        'program.LEGACY.PROJECTOR.PROJECT.IMPORT.TAIL.RESOURCE.DEC.RET'),
    'check_temp_workspace_test.py': (
        'program.CHECK.RET', 'program.CHECK.LEGACY.PREVIOUS.RET',
        'program.CHECK.LEGACY.PROJECTOR.PROJECT.RET',
        'program.CHECK.LIFE.SCALE.FILE.DEC.RET', 'program.CHECK.LIFE.SCALE.TAIL.GUARD.RET',
        'program.CHECK.LEGACY.PREVIOUS.IMPORT.FILE.DEC.RET',
        'program.CHECK.LEGACY.PREVIOUS.IMPORT.TAIL.GUARD.RET',
        'program.CHECK.LIFE.SCALE.TAIL.RESOURCE.DEC.RET',
        'program.CHECK.LEGACY.PREVIOUS.IMPORT.TAIL.RESOURCE.DEC.RET',
        'program.CHECK.LEGACY.PROJECTOR.PROJECT.IMPORT.FILE.DEC.RET',
        'program.CHECK.LEGACY.PROJECTOR.PROJECT.IMPORT.TAIL.GUARD.RET',
        'program.CHECK.LEGACY.PROJECTOR.PROJECT.IMPORT.TAIL.RESOURCE.DEC.RET'),
    'check_projected_driver.py': (
        'program.RET', 'program.PREVIOUS.RET', 'program.PROJECTOR.PROJECT.RET',
        'program.PREVIOUS.IMPORT.FILE.DEC.RET', 'program.PREVIOUS.IMPORT.TAIL.GUARD.RET',
        'program.LEGACY.LIFE.SCALE.FILE.DEC.RET', 'program.LEGACY.LIFE.SCALE.TAIL.GUARD.RET',
        'program.PREVIOUS.IMPORT.TAIL.RESOURCE.DEC.RET',
        'program.PROJECTOR.PROJECT.IMPORT.FILE.DEC.RET',
        'program.PROJECTOR.PROJECT.IMPORT.TAIL.GUARD.RET',
        'program.LEGACY.LIFE.SCALE.TAIL.RESOURCE.DEC.RET',
        'program.PROJECTOR.PROJECT.IMPORT.TAIL.RESOURCE.DEC.RET'),
    'check_projected_driver_test.py': (
        'program.CHECK.RET', 'program.CHECK.PREVIOUS.RET', 'program.OLD_CONTROLS.CHECK.RET',
        'program.CHECK.PROJECTOR.PROJECT.RET',
        'program.CHECK.PREVIOUS.IMPORT.FILE.DEC.RET',
        'program.CHECK.PREVIOUS.IMPORT.TAIL.GUARD.RET',
        'program.CHECK.LEGACY.LIFE.SCALE.FILE.DEC.RET',
        'program.CHECK.LEGACY.LIFE.SCALE.TAIL.GUARD.RET',
        'program.CHECK.PREVIOUS.IMPORT.TAIL.RESOURCE.DEC.RET',
        'program.CHECK.PROJECTOR.PROJECT.IMPORT.FILE.DEC.RET',
        'program.CHECK.PROJECTOR.PROJECT.IMPORT.TAIL.GUARD.RET',
        'program.OLD_CONTROLS.CHECK.LIFE.SCALE.FILE.DEC.RET',
        'program.OLD_CONTROLS.CHECK.LIFE.SCALE.TAIL.GUARD.RET',
        'program.CHECK.LEGACY.LIFE.SCALE.TAIL.RESOURCE.DEC.RET',
        'program.CHECK.PROJECTOR.PROJECT.IMPORT.TAIL.RESOURCE.DEC.RET',
        'program.OLD_CONTROLS.CHECK.LIFE.SCALE.TAIL.RESOURCE.DEC.RET'),
}


def require(condition):
    if not condition:
        raise ValueError('Bounded conformance graph reuse refused')


def verify_sources():
    """Pin reference bytes before importing or selecting their functions."""
    actual = {name: hashlib.sha256((HERE / name).read_bytes()).hexdigest()
              for name in SOURCE_PINS}
    require(actual == SOURCE_PINS)
    return dict(sorted(actual.items()))


verify_sources()
_spec = importlib.util.spec_from_file_location('bounded_graph_pinned_reference', HERE / 'check_retention.py')
REFERENCE = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(REFERENCE)


def same_function(actual, reference, owner):
    return (type(actual) is FunctionType and actual.__globals__ is vars(owner)
            and actual.__code__ == reference.__code__ and actual.__closure__ is None
            and actual.__defaults__ == reference.__defaults__
            and actual.__kwdefaults__ == reference.__kwdefaults__)


def selected_seams(program, selected):
    require(type(selected) is str and selected in SEAMS and type(program) is ModuleType)
    require(type(getattr(program, '__file__', None)) is str)
    require(Path(program.__file__).resolve() == HERE / selected)
    inputs = verify_sources()
    queue, seen, seams = [('program', program)], set(), []
    while queue:
        name, module = queue.pop(0)
        if id(module) in seen:
            continue
        seen.add(id(module))
        require(len(seen) <= MAX_MODULES)
        file = getattr(module, '__file__', None)
        require(type(file) is str and Path(file).resolve().parent == HERE)
        path = Path(file).resolve()
        require(path.name in inputs)
        if path.name == 'check_retention.py':
            require(same_function(getattr(module, 'graph', None), REFERENCE.graph, module))
            byte = getattr(module, 'BYTE', None)
            require(type(byte) is ModuleType and type(getattr(byte, '__file__', None)) is str)
            require(Path(byte.__file__).resolve() == HERE / 'check.py')
            for key in ('digest', 'parent', 'require'):
                require(same_function(getattr(byte, key, None), getattr(REFERENCE.BYTE, key), byte))
            require(type(getattr(module, 'ZERO', None)) is bytes and module.ZERO == bytes(32))
            require(type(getattr(byte, 'ZERO', None)) is bytes and byte.ZERO == bytes(32))
            require(getattr(byte, 'hashlib', None) is REFERENCE.BYTE.hashlib)
            seams.append((name, module, module.graph, byte))
        for key, value in sorted(vars(module).items()):
            file = getattr(value, '__file__', None) if type(value) is ModuleType else None
            if type(file) is str and Path(file).resolve().parent == HERE:
                queue.append((name + '.' + key, value))
    require(tuple(name for name, _, _, _ in seams) == SEAMS[selected])
    return seams, inputs


def cache_key(state):
    # Non-builtin inputs keep the original function's behavior and exceptions.
    if type(state) is not dict or len(state) > MAX_STATE_ENTRIES:
        return None
    if any(type(key) is not bytes or len(key) != 32 or type(value) is not bytes
           or len(value) > MAX_VALUE_BYTES for key, value in state.items()):
        return None
    return tuple(state.items())


def freeze(result):
    if type(result) is not tuple or len(result) != 4:
        return None
    root, commitment, nodes, edges = result
    if (type(root) is not bytes or len(root) != 32 or type(commitment) is not bytes
            or len(commitment) != 32 or type(nodes) is not dict or type(edges) is not dict):
        return None
    if any(type(key) is not bytes or len(key) != 32 or type(value) is not bytes
           for key, value in nodes.items()):
        return None
    if any(type(key) is not bytes or len(key) != 32 or type(value) is not tuple or len(value) != 2
           or any(type(child) is not bytes or len(child) != 32 for child in value)
           for key, value in edges.items()):
        return None
    return root, commitment, tuple(nodes.items()), tuple(edges.items())


def logical_bytes(key, result):
    root, commitment, nodes, edges = result
    return (sum(len(path) + len(value) for path, value in key) + len(root) + len(commitment)
            + sum(len(path) + len(value) for path, value in nodes)
            + sum(len(path) + sum(map(len, children)) for path, children in edges))


class GraphReuse:
    def __init__(self, seams, inputs, max_bytes, max_entries):
        require(type(max_bytes) is int and 0 < max_bytes <= MAX_BYTES)
        require(type(max_entries) is int and 0 < max_entries <= MAX_ENTRIES)
        self.seams, self.inputs = seams, inputs
        self.max_bytes, self.max_entries = max_bytes, max_entries
        self.thread = threading.get_ident()
        self.sha3 = REFERENCE.BYTE.hashlib.sha3_256
        self.tool_pin = hashlib.sha256(TOOL.read_bytes()).hexdigest()
        self._cache, self._bytes = OrderedDict(), 0
        self.requests = self.hits = self.original_calls = 0
        self.bypassed_inputs = self.unretained_results = self.evictions = 0
        self.peak_entries = self.peak_bytes = 0
        self.closed = False
        self.dependencies = [(byte, key, getattr(byte, key)) for _, _, _, byte in seams
                             for key in ('digest', 'parent', 'require')]
        self.replacements = []

        def replacement_for(original):
            def replacement(state):
                return self.call(original, state)
            return replacement

        for _, module, original, _ in seams:
            self.replacements.append(replacement_for(original))

    def intact(self):
        if threading.get_ident() != self.thread or REFERENCE.BYTE.hashlib.sha3_256 is not self.sha3:
            return False
        for (_, module, original, byte), replacement in zip(self.seams, self.replacements):
            if (getattr(module, 'graph', None) is not replacement or getattr(module, 'BYTE', None) is not byte
                    or not same_function(original, REFERENCE.graph, module)
                    or type(getattr(module, 'ZERO', None)) is not bytes or module.ZERO != bytes(32)
                    or type(getattr(byte, 'ZERO', None)) is not bytes or byte.ZERO != bytes(32)
                    or getattr(byte, 'hashlib', None) is not REFERENCE.BYTE.hashlib):
                return False
        return all(getattr(byte, key, None) is original
                   and same_function(original, getattr(REFERENCE.BYTE, key), byte)
                   for byte, key, original in self.dependencies)

    def install(self):
        for (_, module, _, _), replacement in zip(self.seams, self.replacements):
            module.graph = replacement
        require(self.intact())

    def call(self, original, state):
        require(not self.closed and self.intact())
        require(any(original is selected for _, _, selected, _ in self.seams))
        self.requests += 1
        key = cache_key(state)
        if key is not None and key in self._cache:
            self.hits += 1
            result, _ = self._cache[key]
            self._cache.move_to_end(key)
            returned = result[0], result[1], dict(result[2]), dict(result[3])
            require(cache_key(state) == key and self.intact())
            return returned
        self.original_calls += 1
        if key is None:
            self.bypassed_inputs += 1
        result = original(state)
        require(self.intact())
        if key is not None:
            require(cache_key(state) == key)
        saved = freeze(result) if key is not None else None
        if saved is None:
            return result
        weight = logical_bytes(key, saved)
        if weight > self.max_bytes:
            self.unretained_results += 1
            return result
        while self._cache and (len(self._cache) >= self.max_entries or self._bytes + weight > self.max_bytes):
            _, (_, previous_weight) = self._cache.popitem(last=False)
            self._bytes -= previous_weight
            self.evictions += 1
        self._cache[key] = saved, weight
        self._bytes += weight
        self.peak_entries = max(self.peak_entries, len(self._cache))
        self.peak_bytes = max(self.peak_bytes, self._bytes)
        return result

    def close(self):
        intact = self.intact()
        for _, module, original, _ in self.seams:
            module.graph = original
        self._cache.clear()
        self._bytes = 0
        self.closed = True
        require(intact and verify_sources() == self.inputs
                and hashlib.sha256(TOOL.read_bytes()).hexdigest() == self.tool_pin)

    def report(self):
        require(self.closed and not self._cache and self._bytes == 0)
        require(all(module.graph is original for _, module, original, _ in self.seams))
        return {
            'selected_graph_seams': [name for name, _, _, _ in self.seams],
            'pinned_reference_sources': self.inputs,
            'helper_sha256': self.tool_pin,
            'maximum_entries': self.max_entries, 'maximum_logical_cached_bytes': self.max_bytes,
            'maximum_cached_state_entries': MAX_STATE_ENTRIES,
            'graph_requests': self.requests, 'original_graph_calls': self.original_calls,
            'cache_hits': self.hits, 'bypassed_inputs': self.bypassed_inputs,
            'unretained_results': self.unretained_results, 'evictions': self.evictions,
            'peak_entries': self.peak_entries, 'peak_logical_cached_bytes': self.peak_bytes,
            'complete_ordered_byte_maps_are_keys': True,
            'admitted_inputs_rechecked_before_return_or_retention': True,
            'complete_original_graph_computed_on_miss': True,
            'mutable_results_are_independent': True, 'selected_functions_restored': True,
            'cache_cleared': True, 'disk_cache_created': False,
            'cross_process_or_context_reuse': False, 'serial_caller_required': True,
            'recorded_producer_source_inputs_rebound': False,
            'new_reference_node_or_resource_execution': False,
            'process_RSS_or_whole_CI_speedup_qualified': False,
            'production_acceptance_enabled': False,
        }


@contextmanager
def selected_graphs(program, selected, max_bytes=MAX_BYTES, max_entries=MAX_ENTRIES):
    seams, inputs = selected_seams(program, selected)
    scope = GraphReuse(seams, inputs, max_bytes, max_entries)
    try:
        scope.install()
        yield scope
    finally:
        scope.close()
