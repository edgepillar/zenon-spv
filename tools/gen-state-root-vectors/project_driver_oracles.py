#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Project every selected driver's isolated level-retention seam, serially.

Hash all leaves/parents and preserve complete import/map/delta/DAG/refcount and
proof reconstruction. The fixed path union supports both unchanged workloads.
Unknown seams or queries are refused; restore every original identity, even
after an exception. This research helper changes no files or stdlib modules.
"""
from contextlib import contextmanager
import hashlib
import importlib.util
from pathlib import Path
from types import FunctionType, ModuleType

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('driver_selected_sparse_levels', HERE / 'project_sparse_oracle.py')
PROJECT = importlib.util.module_from_spec(spec)
spec.loader.exec_module(PROJECT)
LEVEL_SOURCE_SHA256 = '558787e3c10a3cff6ea31a1062d2bb7c27c12cc55fc5d390c177783848c278e5'
SEAM_PATHS = ('checks.LIFE.SCALE.SCALE', 'lifecycle.CHECK.SCALE.SCALE',
              'lifecycle.ORIGINAL.CHECK.SCALE')
MAX_MODULES = 1024
MODES = ('reference', 'projected')


def require(condition):
    if not condition:
        raise ValueError('Selected complete driver oracle projection refused')


def selected_paths():
    paths = tuple(sorted({p for s in PROJECT.IMPORT.SELECTIONS for p in PROJECT.selected_paths(s)}))
    require(len(paths) == 7 and len(paths) <= PROJECT.MAX_PATHS)
    return paths


def selected_seams(roots):
    """Deterministic, identity-deduplicated traversal of owned module globals.

    Only these two independently loaded roots and three original function
    seams are selected. Traversal does not execute either oracle or a child.
    """
    require(type(roots) is dict and set(roots) == {'checks', 'lifecycle'})
    require(all(type(m) is ModuleType for m in roots.values()))
    require(hashlib.sha256((HERE / 'check_tree_scale.py').read_bytes()).hexdigest() == LEVEL_SOURCE_SHA256)
    queue, seen, seams = sorted(roots.items()), set(), []
    while queue:
        name, module = queue.pop(0)
        if id(module) in seen:
            continue
        seen.add(id(module))
        require(len(seen) <= MAX_MODULES)
        file = getattr(module, '__file__', None)
        require(type(file) is str and Path(file).resolve().parent == HERE)
        if Path(file).name == 'check_tree_scale.py':
            original = getattr(module, 'scale_levels', None)
            require(type(original) is FunctionType and original.__globals__ is vars(module))
            require(original.__name__ == 'scale_levels' and original.__closure__ is None)
            require(original.__code__ == PROJECT.REFERENCE_LEVELS.__code__)
            require(original.__defaults__ == PROJECT.REFERENCE_LEVELS.__defaults__)
            seams.append((name, module, original))
        for key, value in sorted(vars(module).items()):
            file = getattr(value, '__file__', None) if type(value) is ModuleType else None
            if type(file) is str and Path(file).resolve().parent == HERE:
                queue.append((name + '.' + key, value))
    require(tuple(name for name, _, _ in seams) == SEAM_PATHS)
    return seams


def binding_manifest(roots):
    seams = selected_seams(roots)
    return {'level_source_sha256': LEVEL_SOURCE_SHA256,
        'level_seams': [name for name, _, _ in seams],
        'selected_paths': [p.hex() for p in selected_paths()],
        'every_leaf_and_parent_hashed': True, 'complete_oracle_checks_preserved': True,
        'unknown_query_or_seam_refused': True, 'serial_caller_required': True}


@contextmanager
def selected_oracles(roots, mode):
    require(type(mode) is str and mode in MODES)
    seams, paths = selected_seams(roots), selected_paths()
    bindings = binding_manifest(roots)
    replacement = lambda state: PROJECT.projected_levels(state, paths)
    if mode == 'projected':
        for _, module, _ in seams:
            module.scale_levels = replacement
    try:
        yield bindings
    finally:
        # Restore all identities before reporting any unexpected replacement.
        intact = all(module.scale_levels is (replacement if mode == 'projected' else original)
                     for _, module, original in seams)
        for _, module, original in seams:
            module.scale_levels = original
        require(intact)
