#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Explicit fresh CLI recipes for two unchanged recorded import checkers.

Only a selected test module's subprocess binding is replaced. Each selected CLI
still runs in a fresh interpreter through its original entrypoint and returns
its actual, unfiltered console streams and exit. The separate recipe is not
execution authentication, a new node measurement or state acceptance.
"""
import argparse
import ast
from contextlib import contextmanager, redirect_stderr, redirect_stdout
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import threading
from types import ModuleType

HERE = Path(__file__).resolve().parent
TOOL = Path(__file__).resolve()
PROFILES = {
    'check_patch_resources_test.py': {
        'target': 'check_patch_resources.py',
        'control_sha256': '944580646deae4e29e2d745f5a7541a6efc169c43e99c904b65749b02521585f',
        'target_sha256': 'b82587acb9e3c8a8c682735a90e2a23b8c31fdd546d74d15b56dc268d6ea62f9',
        'kwargs': {'capture_output': True, 'check': False, 'timeout': 120},
        'order': ('valid-default',),
    },
    'check_patch_import_comparison_test.py': {
        'target': 'check_patch_import_comparison.py',
        'control_sha256': '83f9c9fd61598e9da7c5b21753cc1f1c37d2802d5780d546dde82f34b5c5b1b6',
        'target_sha256': 'fa7231d567a2c28e7397d38ce09352ad452078b8f8acb4ec55a7af4c1a9bd102',
        'kwargs': {'capture_output': True, 'timeout': 120},
        'order': ('valid-default', 'baseline-refusal'),
    },
}
DEPENDENCIES = {
    'selected_child_hex.py': 'c7373439430a22e3240b95d6c5fd2c3ceb27428cedb96bae3490e1acd23be88f',
    'project_target_hex.py': '80624b66ea7f7930c2237bf04b08462e38efe76109084577680b67cde09b2a73',
    'compare_patch_import.py': '96c8916bfcf9e4fd7f357fc63c5aab992727171f041b66df5cb714f29dfe2cb4',
}
KIND = 'selected-import-resource-child-hex-CLI'


def require(value):
    if not value:
        raise ValueError('Selected import resource CLI recipe refused')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sources():
    selected = dict(DEPENDENCIES)
    for control, profile in PROFILES.items():
        selected[control] = profile['control_sha256']
        selected[profile['target']] = profile['target_sha256']
    actual = {}
    for name, expected in selected.items():
        path = HERE / name
        require(path.is_file() and not path.is_symlink())
        with path.open('rb') as handle:
            raw = handle.read((1 << 20) + 1)
        require(len(raw) <= 1 << 20 and sha(raw) == expected)
        actual[name] = expected
    return actual


sources()
IO = load('import_resource_recipe_io', 'selected_child_hex.py')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--program', choices=tuple(p['target'] for p in PROFILES.values()), required=True)
    parser.add_argument('--mode', choices=('reference', 'translated'), required=True)
    parser.add_argument('--execution-revision', required=True)
    parser.add_argument('--report', required=True)
    parser.add_argument('arguments', nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    require(re.fullmatch('[0-9a-f]{40}', args.execution_revision) is not None)
    require(args.arguments == ['--'])
    pins, tool_pin = sources(), sha(TOOL.read_bytes())
    destination = IO.report_destination(args.report)
    raw_target = (HERE / args.program).read_bytes()
    guard = ast.parse(raw_target).body[-1]
    require(isinstance(guard, ast.If)
            and ast.dump(guard.test) == ast.dump(ast.parse('__name__ == "__main__"', mode='eval').body))
    oracle = load('import_child_private_hex_oracle', 'project_target_hex.py')
    program = oracle.load('import_child_original_checker', args.program)
    buffers = [io.BytesIO(), io.BytesIO()]
    wrappers = [io.TextIOWrapper(buffer, encoding=console.encoding or 'utf-8',
                                errors=console.errors or 'strict', newline=None, write_through=True)
                for buffer, console in zip(buffers, (sys.stdout, sys.stderr))]
    previous_argv, previous_name = sys.argv, program.__name__
    status = 0
    try:
        sys.argv, program.__name__ = [str(HERE / args.program)], '__main__'
        with oracle.selected_oracles(program, args.program, args.mode) as bindings:
            with redirect_stdout(wrappers[0]), redirect_stderr(wrappers[1]):
                try:
                    exec(compile(ast.Module(body=[guard], type_ignores=[]), str(HERE / args.program), 'exec'), vars(program))
                except SystemExit as result:
                    require(type(result.code) is int and result.code in (0, 1, 2))
                    status = result.code
    finally:
        sys.argv, program.__name__ = previous_argv, previous_name
    require(sources() == pins and sha(TOOL.read_bytes()) == tool_pin)
    for wrapper in wrappers:
        wrapper.flush()
    output, errors = (buffer.getvalue() for buffer in buffers)
    require(len(output) <= 1 << 20 and len(errors) <= 1 << 20)
    IO.write_report(destination, {
        'format_version': 1, 'kind': KIND, 'execution_revision': args.execution_revision,
        'program': args.program, 'mode': args.mode, 'helper_sha256': tool_pin,
        'declared_exit': status, 'stdout_sha256': sha(output), 'stdout_bytes': len(output),
        'stderr_sha256': sha(errors), 'stderr_bytes': len(errors), 'binding_manifest': bindings,
        'selected_function_identities_restored': True, 'original_entrypoint_guard_executed': True,
        'recorded_producer_source_inputs_rebound': False, 'reference_backend_executed': False,
        'production_acceptance_enabled': False,
    })
    sys.stdout.buffer.write(output)
    sys.stderr.buffer.write(errors)
    return status


class SelectedChildren:
    def __init__(self, program, selected, mode, revision):
        require(type(selected) is str and selected in PROFILES and type(program) is ModuleType)
        require(type(getattr(program, '__file__', None)) is str
                and Path(program.__file__).resolve() == HERE / selected)
        require(getattr(program, 'subprocess', None) is subprocess)
        require(type(mode) is str and mode in ('reference', 'translated')
                and type(revision) is str and re.fullmatch('[0-9a-f]{40}', revision) is not None)
        self.inputs, self.tool_pin = sources(), sha(TOOL.read_bytes())
        self.program, self.selected, self.profile = program, selected, PROFILES[selected]
        self.mode, self.revision = mode, revision
        self.original, self.replacement = program.subprocess, self.invoke
        self.facade = ModuleType('explicit_import_resource_child_dispatch')
        vars(self.facade).update(vars(subprocess))
        self.facade.run = self.replacement
        self.thread, self.records, self.closed = threading.get_ident(), [], False
        oracle = load('import_child_independent_recipe', 'project_target_hex.py')
        target = oracle.load('import_child_independent_target', self.profile['target'])
        with oracle.selected_oracles(target, self.profile['target'], mode) as bindings:
            self.expected_bindings = json.loads(json.dumps(bindings))

    def invoke(self, argv, **kwargs):
        require(not self.closed and threading.get_ident() == self.thread)
        require(self.program.subprocess is self.facade and self.facade.run is self.replacement)
        require(type(argv) is list and all(type(value) is str for value in argv))
        require(len(self.records) < len(self.profile['order']))
        kind = self.profile['order'][len(self.records)]
        if kind == 'baseline-refusal':
            require(kwargs == {'capture_output': True, 'timeout': 30} and len(argv) == 14)
            require(type(kwargs['capture_output']) is bool and type(kwargs['timeout']) is int)
            require(argv[:4] == [sys.executable, '-I', '-B', str(HERE / 'compare_patch_import.py')])
            require(argv[4::2] == ['--baseline-import-source', '--node-source', '--go', '--output', '--evidence-directory'])
            paths = [Path(value) for value in argv[5::2]]
            require(all(path.is_absolute() and path.parent == paths[0].parent for path in paths))
            require([path.name for path in paths] == ['unselected.go', 'missing-node', 'missing-go', 'out.json', 'evidence'])
            result = subprocess.run(argv, **kwargs)
            require(type(result.returncode) is int and result.returncode == 1)
            require(type(result.stdout) is bytes and type(result.stderr) is bytes)
            self.records.append({'selection': kind, 'actual_exit': result.returncode,
                'stdout_sha256': sha(result.stdout), 'stdout_bytes': len(result.stdout),
                'stderr_sha256': sha(result.stderr), 'stderr_bytes': len(result.stderr),
                'original_command_and_kwargs_preserved': True, 'translated': False})
            return result
        require(kind == 'valid-default' and argv == [sys.executable, '-I', '-B', str(HERE / self.profile['target'])])
        require(kwargs == self.profile['kwargs'])
        require(all(type(kwargs[name]) is type(value) for name, value in self.profile['kwargs'].items()))
        with tempfile.TemporaryDirectory(prefix='import-resource-child-') as temporary:
            path = Path(temporary).resolve(strict=True) / 'execution.json'
            command = [sys.executable, '-I', '-B', str(TOOL), '--program', self.profile['target'],
                       '--mode', self.mode, '--execution-revision', self.revision, '--report', str(path), '--']
            result = subprocess.run(command, capture_output=True, timeout=kwargs['timeout'])
            report = IO.read_report(path)
        require(type(report) is dict and set(report) == IO.REPORT_FIELDS)
        require(type(report['format_version']) is int and report['format_version'] == 1
                and report['kind'] == KIND and report['program'] == self.profile['target']
                and report['mode'] == self.mode and report['execution_revision'] == self.revision
                and report['helper_sha256'] == self.tool_pin)
        require(type(result.returncode) is int and type(report['declared_exit']) is int
                and result.returncode == report['declared_exit'] == 0)
        require(report['binding_manifest'] == self.expected_bindings)
        for name in ('stdout', 'stderr'):
            raw = getattr(result, name)
            require(type(raw) is bytes and type(report[name + '_bytes']) is int
                    and len(raw) == report[name + '_bytes'] and sha(raw) == report[name + '_sha256'])
        require(report['selected_function_identities_restored'] is True
                and report['original_entrypoint_guard_executed'] is True
                and report['recorded_producer_source_inputs_rebound'] is False
                and report['reference_backend_executed'] is False
                and report['production_acceptance_enabled'] is False)
        self.records.append({'selection': kind, 'actual_exit': result.returncode,
                             'actual_streams_bound': True, 'translated': self.mode == 'translated', 'recipe': report})
        return result

    def report(self):
        require(self.closed and [r['selection'] for r in self.records] == list(self.profile['order']))
        return {'format_version': 1, 'kind': 'explicit-import-resource-child-hex-execution',
                'execution_revision': self.revision, 'program': self.selected, 'mode': self.mode,
                'helper_sha256': self.tool_pin, 'pinned_sources': self.inputs,
                'actual_fresh_Python_processes': len(self.records), 'translated_CLI_processes': 1 if self.mode == 'translated' else 0,
                'children': json.loads(json.dumps(self.records)), 'test_local_dispatch_restored': True,
                'stdio_filtered': False, 'global_subprocess_patch_installed': False,
                'import_hook_installed': False, 'disk_cache_created': False,
                'reference_backend_executed': False, 'recorded_producer_source_inputs_rebound': False,
                'production_acceptance_enabled': False}


@contextmanager
def selected_children(program, selected, mode, revision):
    owner = SelectedChildren(program, selected, mode, revision)
    program.subprocess = owner.facade
    try:
        yield owner
    finally:
        intact = program.subprocess is owner.facade and owner.facade.run is owner.replacement
        program.subprocess = owner.original
        owner.closed = True
        require(intact and sources() == owner.inputs and sha(TOOL.read_bytes()) == owner.tool_pin)


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (ValueError, KeyError, TypeError, OSError, OverflowError, RecursionError):
        print('Selected import resource CLI refused; no completed recipe is qualified.', file=sys.stderr)
        sys.exit(1)
