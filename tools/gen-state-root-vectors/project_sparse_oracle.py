#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Retain selected sparse siblings while hashing every leaf and parent.

An independent research oracle, never a production proof verifier. Keep the
original complete import/map/delta/DAG/refcount reconstruction unchanged. The
selected projection refuses unknown lookups instead of treating missing work
as an empty subtree. No recorded fixture answers enter this calculation.
"""
import importlib.util
from pathlib import Path
from types import MappingProxyType

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('projected_complete_import_oracle', HERE / 'check_tree_import_scale.py')
IMPORT = importlib.util.module_from_spec(spec)
spec.loader.exec_module(IMPORT)
SCALE, BYTE, RET, ZERO = IMPORT.SCALE, IMPORT.BYTE, IMPORT.RET, IMPORT.BYTE.ZERO
REFERENCE_LEVELS = SCALE.scale_levels
MAX_PATHS = 16


def require(condition):
    if not condition:
        raise ValueError('Selected sparse oracle projection refused')


class SelectedLayer:
    """All selected slots are explicit, including computed empty siblings."""
    __slots__ = ('_entries',)

    def __init__(self, entries):
        require(type(entries) is dict and len(entries) <= MAX_PATHS)
        require(all(type(i) is int and i >= 0 and type(v) is bytes and len(v) == 32 for i, v in entries.items()))
        self._entries = MappingProxyType(dict(entries))

    def get(self, index, default):
        require(type(index) is int and index in self._entries)
        require(type(default) is bytes and default == ZERO)
        return self._entries[index]


class SelectedValues:
    __slots__ = ('_allowed', '_present')

    def __init__(self, allowed, present):
        require(type(allowed) is tuple and len(set(allowed)) == len(allowed) <= MAX_PATHS)
        require(all(type(i) is int and 0 <= i < (1 << 256) for i in allowed))
        require(type(present) is dict and set(present) <= set(allowed))
        require(all(type(v) is bytes and len(v) == 32 for v in present.values()))
        self._allowed = frozenset(allowed)
        self._present = MappingProxyType(dict(present))

    def __contains__(self, index):
        require(type(index) is int and index in self._allowed)
        return index in self._present

    def get(self, index, default):
        require(type(index) is int and index in self._allowed)
        require(type(default) is bytes and default == b'')
        return self._present.get(index, default)


def projected_levels(state, paths):
    """Release each full depth after computing the next; retain selected slots.

    Memory still includes current and following full depth dictionaries. This
    is not a proof that an input map is a complete authenticated snapshot.
    """
    require(type(state) is dict and len(state) <= 4096)
    require(type(paths) is tuple and len(paths) <= MAX_PATHS)
    require(all(type(p) is bytes and len(p) == 32 for p in paths))
    require(len(set(paths)) == len(paths))
    selected = tuple(int.from_bytes(p, 'big') for p in paths)
    nodes, present = {}, {}
    for path, value in state.items():
        require(type(path) is bytes and len(path) == 32 and type(value) is bytes and len(value) == 32)
        index = int.from_bytes(path, 'big')
        nodes[index] = BYTE.digest(path + value)
        if index in selected:
            present[index] = value
    levels = {}
    for depth in range(256, -1, -1):
        slots = (0,) if depth == 0 else tuple(sorted({(i >> (256 - depth)) ^ 1 for i in selected}))
        levels[depth] = SelectedLayer({i: nodes.get(i, ZERO) for i in slots})
        if depth:
            parents = {}
            for index in {i >> 1 for i in nodes}:
                result = BYTE.parent(nodes.get(index * 2, ZERO), nodes.get(index * 2 + 1, ZERO))
                if result != ZERO:
                    parents[index] = result
            nodes = parents
    return MappingProxyType(levels), SelectedValues(selected, present)


def selected_paths(selection):
    require(type(selection) is tuple and len(selection) == 4)
    require(type(selection[0]) is str and all(type(n) is int for n in selection[1:]))
    require(selection in IMPORT.SELECTIONS)
    _, keys, versions, _ = selection
    return tuple(BYTE.digest(RET.key(i)) for i in RET.query_indices(keys, versions) if i != -1)


def complete_case(selection):
    """Use the unchanged complete oracle with only its level-retention seam.

    This isolated module is for one serial caller. Restore its function even
    on exceptional completion; do not change files or the stdlib import state.
    """
    paths = selected_paths(selection)
    require(SCALE.scale_levels is REFERENCE_LEVELS)
    SCALE.scale_levels = lambda state: projected_levels(state, paths)
    try:
        return IMPORT.expected_case(selection)
    finally:
        SCALE.scale_levels = REFERENCE_LEVELS
