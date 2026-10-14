#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Select a pinned, serial hex-validation seam without rebinding old recordings.

The original source and every prospective-map copy, entry count, byte sum and
refusal order stay intact. Only exact builtin str character membership uses
str.translate. Non-builtin strings keep the reference iteration semantics.
This opt-in research seam is separate from recorded producer source inputs.
"""
from contextlib import contextmanager
import hashlib
import importlib.util
from pathlib import Path
from types import FunctionType, ModuleType

HERE = Path(__file__).resolve().parent
REFERENCE_SHA256 = 'f0871b4aa89a6b07f99a023029858fe2a7be61455d7968780e836af77db7e2c5'
DELETE_HEX = {ord(c): None for c in '0123456789abcdef'}
MAX_MODULES = 128
MODES = ('reference', 'translated')
SEAMS = {
    'check_patch_file_resources.py': ('program.FILE.TARGET', 'program.RESOURCE.TARGET'),
    'check_patch_file_resources_test.py': ('program.CHECK.FILE.TARGET', 'program.CHECK.RESOURCE.TARGET'),
    'check_temp_workspace.py': (
        'program.LIFE.SCALE.FILE.TARGET', 'program.LEGACY.PREVIOUS.IMPORT.FILE.TARGET',
        'program.LIFE.SCALE.TAIL.RESOURCE.TARGET', 'program.LEGACY.PREVIOUS.IMPORT.TAIL.RESOURCE.TARGET',
        'program.LEGACY.PROJECTOR.PROJECT.IMPORT.FILE.TARGET',
        'program.LEGACY.PROJECTOR.PROJECT.IMPORT.TAIL.RESOURCE.TARGET'),
    'check_temp_workspace_test.py': (
        'program.CHECK.LIFE.SCALE.FILE.TARGET', 'program.CHECK.LEGACY.PREVIOUS.IMPORT.FILE.TARGET',
        'program.CHECK.LIFE.SCALE.TAIL.RESOURCE.TARGET',
        'program.CHECK.LEGACY.PREVIOUS.IMPORT.TAIL.RESOURCE.TARGET',
        'program.CHECK.LEGACY.PROJECTOR.PROJECT.IMPORT.FILE.TARGET',
        'program.CHECK.LEGACY.PROJECTOR.PROJECT.IMPORT.TAIL.RESOURCE.TARGET'),
    'check_tree_import_scale.py': ('program.FILE.TARGET', 'program.TAIL.RESOURCE.TARGET'),
    'check_tree_import_scale_test.py': ('program.CHECK.FILE.TARGET', 'program.CHECK.TAIL.RESOURCE.TARGET'),
    'check_tree_import_lifecycle.py': ('program.SCALE.FILE.TARGET', 'program.SCALE.TAIL.RESOURCE.TARGET'),
    'check_tree_import_lifecycle_test.py': (
        'program.CHECK.SCALE.FILE.TARGET', 'program.CHECK.SCALE.TAIL.RESOURCE.TARGET'),
    'check_tree_driver_resources.py': (
        'program.LIFE.SCALE.FILE.TARGET', 'program.LIFE.SCALE.TAIL.RESOURCE.TARGET'),
    'check_tree_driver_resources_test.py': (
        'program.CHECK.LIFE.SCALE.FILE.TARGET', 'program.CHECK.LIFE.SCALE.TAIL.RESOURCE.TARGET'),
}


def require(condition):
    if not condition:
        raise ValueError('Selected target hex oracle refused')


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, HERE / file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


REFERENCE = load('unchanged_target_hex_reference', 'check_patch_targets.py')


def target_refusal(target, limits, ceilings):
    if any(type(limits[field]) is not int or not 0 < limits[field] <= cap
           for field, cap in ceilings.items()):
        return 'invalid_target_limits'
    if len(target) > limits['entries']:
        return 'target_entry_limit'
    if sum(len(key) + len(value) for key, value in target.items()) > limits['hex_bytes']:
        return 'target_hex_limit'
    if any(len(text) % 2 or (bool(text.translate(DELETE_HEX)) if type(text) is str
                            else any(c not in '0123456789abcdef' for c in text))
           for item in target.items() for text in item):
        return 'invalid_target_encoding'
    return ''


def selected_seams(program, selected):
    require(type(selected) is str and selected in SEAMS and type(program) is ModuleType)
    require(Path(program.__file__).resolve() == HERE / selected)
    require(hashlib.sha256((HERE / 'check_patch_targets.py').read_bytes()).hexdigest() == REFERENCE_SHA256)
    queue, seen, seams, inputs = [('program', program)], set(), [], {}
    while queue:
        name, module = queue.pop(0)
        if id(module) in seen:
            continue
        seen.add(id(module))
        require(len(seen) <= MAX_MODULES)
        file = getattr(module, '__file__', None)
        require(type(file) is str and Path(file).resolve().parent == HERE)
        path = Path(file).resolve()
        inputs[path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
        if path.name == 'check_patch_targets.py':
            original = getattr(module, 'target_refusal', None)
            require(type(original) is FunctionType and original.__globals__ is vars(module))
            require(original.__name__ == 'target_refusal' and original.__closure__ is None)
            require(original.__code__ == REFERENCE.target_refusal.__code__)
            require(original.__defaults__ == REFERENCE.target_refusal.__defaults__)
            seams.append((name, module, original))
        for key, value in sorted(vars(module).items()):
            file = getattr(value, '__file__', None) if type(value) is ModuleType else None
            if type(file) is str and Path(file).resolve().parent == HERE:
                queue.append((name + '.' + key, value))
    require(tuple(name for name, _, _ in seams) == SEAMS[selected])
    inputs['project_target_hex.py'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    return seams, dict(sorted(inputs.items()))


@contextmanager
def selected_oracles(program, selected, mode):
    """Restore every original function identity on normal exit or an exception.

    Only already loaded, explicitly enumerated instances are selected. Later
    imports and subprocesses retain their original implementation. No global
    import hook, stdlib patch, source rewrite or incremental counter is used.
    """
    require(type(mode) is str and mode in MODES)
    seams, inputs = selected_seams(program, selected)
    replacements = []
    for _, module, _ in seams:
        def replacement(target, limits, owner=module):
            return target_refusal(target, limits, owner.CEILINGS)
        replacements.append(replacement)
    bindings = {
        'reference_target_source_sha256': REFERENCE_SHA256,
        'selected_seams': [name for name, _, _ in seams],
        'current_execution_inputs': inputs,
        'complete_prospective_maps_and_refusal_order_preserved': True,
        'builtin_str_translate_only': mode == 'translated',
        'non_builtin_iteration_preserved': True,
        'recorded_producer_source_inputs_rebound': False,
        'later_imports_and_subprocesses_accelerated': False,
        'serial_caller_required': True,
        'new_reference_node_or_resource_measurement': False,
        'production_acceptance_enabled': False,
    }
    if mode == 'translated':
        for (_, module, _), replacement in zip(seams, replacements):
            module.target_refusal = replacement
    try:
        yield bindings
    finally:
        intact = all(module.target_refusal is (replacement if mode == 'translated' else original)
                     for (_, module, original), replacement in zip(seams, replacements))
        for _, module, original in seams:
            module.target_refusal = original
        unchanged = all(hashlib.sha256((HERE / name).read_bytes()).hexdigest() == pin
                        for name, pin in inputs.items())
        require(intact and unchanged)
