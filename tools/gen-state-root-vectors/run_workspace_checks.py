#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Check selected recorded observations and their controls in one graph scope."""
import argparse
from contextlib import contextmanager, nullcontext
import functools
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
import threading
from types import FunctionType
import unittest

HERE = Path(__file__).resolve().parent
RECORDING = 'check_temp_workspace.py'
CONTROLS = 'check_temp_workspace_test.py'
TREE_CHECKS = {
    'tree-import-scale': 'check_tree_import_scale',
    'tree-import-lifecycle': 'check_tree_import_lifecycle',
    'tree-driver-resources': 'check_tree_driver_resources',
    'oracle-projection': 'check_oracle_projection',
    'projected-driver': 'check_projected_driver',
}


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


HEX = load('workspace_target_hex', HERE / 'project_target_hex.py')
GRAPH = load('workspace_graph_reuse', HERE.parent / 'conformance_graph_reuse.py')
SCALE_CHECK = 'check_tree_import_scale.py'
SCALE_CORPUS = HERE / 'testdata/candidate-tree-import-scale.json'
MAX_SCALE_BYTES = 256 << 10
MAX_SCALE_INPUT_BYTES = 1 << 20


def scale_model_binding(scale):
    require = HEX.require
    require(Path(scale.__file__).resolve() == HERE / SCALE_CHECK)
    paths = scale.INPUT_NAMES
    require(type(paths) is tuple and 0 < len(paths) <= 128
            and all(type(name) is str and Path(name).name == name for name in paths))
    pins = GRAPH.verify_sources()
    for name in paths:
        with (HERE / name).open('rb') as stream:
            data = stream.read(MAX_SCALE_INPUT_BYTES + 1)
        require(0 < len(data) <= MAX_SCALE_INPUT_BYTES)
        pins[name] = hashlib.sha256(data).hexdigest()
    with SCALE_CORPUS.open('rb') as stream:
        raw = stream.read(MAX_SCALE_BYTES + 1)
    require(0 < len(raw) <= MAX_SCALE_BYTES)
    return json.dumps({
        'inputs': pins, 'scale_source': scale.SCALE.SOURCE, 'scope': scale.SCOPE,
        'selections': scale.SELECTIONS, 'corpus_sha256': hashlib.sha256(raw).hexdigest(),
    }, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


class SharedScaleModel:
    """Reuse one independently built scale model for two selected readers."""

    def __init__(self):
        self.binding = self.code = self.document = None
        self.thread = threading.get_ident()
        self.computed = self.reused = 0

    @contextmanager
    def select(self, program):
        require = HEX.require
        require(threading.get_ident() == self.thread)
        scale = program.CHECK.LIFE.SCALE
        original = scale.expected_document
        function = getattr(original, '__wrapped__', None)
        require(type(function) is FunctionType and function.__globals__ is vars(scale)
                and function.__name__ == 'expected_document' and function.__closure__ is None
                and original.cache_info().currsize == 0
                and original.cache_parameters() == {'maxsize': 1, 'typed': False})
        binding = scale_model_binding(scale)
        if self.binding is None:
            self.binding, self.code = binding, function.__code__
        require(binding == self.binding and function.__code__ == self.code)

        @functools.lru_cache(maxsize=1)
        def local_document():
            if self.document is None:
                result = original()
                require(type(result) is dict)
                encoded = json.dumps(result, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
                require(0 < len(encoded) <= MAX_SCALE_BYTES)
                self.document = encoded
                self.computed += 1
                return result
            self.reused += 1
            return json.loads(self.document)

        def expected():
            require(threading.get_ident() == self.thread and scale.expected_document is expected)
            return local_document()

        scale.expected_document = expected
        try:
            yield
        finally:
            intact = scale.expected_document is expected
            scale.expected_document = original
            local_document.cache_clear()
            original.cache_clear()
            require(intact and scale_model_binding(scale) == binding)

    def report(self):
        HEX.require(self.computed == self.reused == 1 and self.document is not None)
        return {
            'independent_scale_models_computed': self.computed,
            'scale_models_reused': self.reused,
            'model_bytes': len(self.document),
            'model_sha256': hashlib.sha256(self.document).hexdigest(),
            'input_binding_sha256': hashlib.sha256(self.binding).hexdigest(),
        }

    def clear(self):
        self.binding = self.code = self.document = None


def control_names(tests):
    for test in tests:
        if isinstance(test, unittest.TestSuite):
            yield from control_names(test)
        else:
            yield test.id().split('.', 1)[1]


def run_pair(revision, tree_check, model=None):
    source = Path(__file__)
    source_pin = hashlib.sha256(source.read_bytes()).hexdigest()
    if tree_check is None:
        recording, controls = RECORDING, CONTROLS
        recording_args = []
        kind = 'recorded-workspace-checks-execution'
    else:
        stem = TREE_CHECKS[tree_check]
        recording, controls = stem + '.py', stem + '_test.py'
        recording_args = ['--source-revision', revision]
        kind = 'recorded-tree-checks-execution'
    program = HEX.load('recorded_observation_controls', controls)
    HEX.require(Path(program.CHECK.__file__).resolve() == HERE / recording)
    suite = unittest.defaultTestLoader.loadTestsFromModule(program)
    names = list(control_names(suite))
    with GRAPH.selected_graphs(program, controls) as reused, \
            HEX.selected_oracles(program, controls, 'translated') as bindings, \
            (model.select(program) if model is not None else nullcontext()):
        # Validate the recording before the controls reuse its reference model.
        program.CHECK.main(recording_args)
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        HEX.require(result.wasSuccessful() and not result.skipped and type(result.testsRun) is int
                    and result.testsRun == len(names) > 0)
    HEX.require(hashlib.sha256(source.read_bytes()).hexdigest() == source_pin)
    bindings['current_execution_inputs'][source.name] = source_pin
    report = {
        'format_version': 1, 'kind': kind,
        'source_revision': revision, 'recording_program': recording,
        'control_program': controls, 'recording_checked_before_controls': True,
        'tests_run': result.testsRun, 'control_names': names, 'checks_completed': True,
        'binding_manifest': bindings, 'graph_reuse': reused.report(),
    }
    print(json.dumps(report, sort_keys=True, separators=(',', ':')))
    return result.testsRun


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-revision', required=True)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--tree-check', choices=TREE_CHECKS)
    mode.add_argument('--shared-scale-model', action='store_true')
    args = parser.parse_args(argv)
    HEX.require(re.fullmatch(r'[0-9a-f]{40}', args.source_revision) is not None)
    if not args.shared_scale_model:
        run_pair(args.source_revision, args.tree_check)
        return
    model = SharedScaleModel()
    try:
        count = run_pair(args.source_revision, None, model)
        count += run_pair(args.source_revision, 'tree-driver-resources', model)
        report = {'format_version': 1, 'kind': 'shared-recorded-scale-model-checks',
                  'source_revision': args.source_revision, 'tests_run': count,
                  'checks_completed': True, **model.report()}
    finally:
        model.clear()
    report['model_cache_cleared'] = True
    print(json.dumps(report, sort_keys=True, separators=(',', ':')))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError, OverflowError, RecursionError):
        print('Recorded observation checks refused.', file=sys.stderr)
        sys.exit(1)
