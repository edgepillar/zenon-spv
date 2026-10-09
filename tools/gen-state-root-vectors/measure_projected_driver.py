#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Preselect four fresh complete driver workers, four builds and 96 children.

Observe preparation, unchanged offline delegation and complete final checks
inside one call. Only isolated level-retention seams differ by selected mode.
Seal every actual stream, outcome, resource row and complete result; no retries
or filtering. Final resource encoding/exit and controller memory are separate.
"""
from contextlib import redirect_stdout
import argparse
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('selected_complete_driver_contract', HERE / 'check_projected_driver.py')
CHECK = importlib.util.module_from_spec(spec)
spec.loader.exec_module(CHECK)
OBS, encoded = CHECK.OBS, CHECK.encoded


def seal(path, raw):
    CHECK.require(not path.exists() and not path.is_symlink())
    with path.open('xb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    path.chmod(0o400)


def digest(path):
    return hashlib.sha256(path.resolve().read_bytes()).hexdigest()


def runtime():
    return {'os': sys.platform, 'architecture': platform.machine().lower(),
            'python': platform.python_version(), 'implementation': platform.python_implementation()}


def selection(args):
    source = CHECK.load('selected_driver_source_only', 'regenerate.py')
    manifest_raw, manifest = source.source_manifest()
    source.snapshot_source(args.node_source, manifest['files'])
    return {'research_source_inputs': CHECK.input_pins(), 'runtime': runtime(),
        'python_executable_sha256': digest(Path(sys.executable)), 'go_executable_sha256': digest(Path(args.go)),
        'node_revision': source.NODE_REVISION, 'node_tree': source.NODE_TREE,
        'matched_node_blobs': len(manifest['files']),
        'node_manifest_sha256': hashlib.sha256(manifest_raw).hexdigest()}


def worker(args):
    OBS.preflight()
    CHECK.require(type(args.generation) is int and args.generation in (0, 1) and args.mode in CHECK.MODES)
    CHECK.require(not args.evidence_directory.exists() and not args.evidence_directory.is_symlink())
    args.evidence_directory.mkdir(mode=0o700)
    selected = selection(args)
    lifecycle = CHECK.load('selected_driver_unchanged_lifecycle', 'reproduce_tree_import_lifecycle.py')
    roots = {'lifecycle': lifecycle, 'checks': CHECK.LEGACY}
    bindings = CHECK.PROJECTOR.binding_manifest(roots)
    CHECK.RET.exact(bindings, CHECK.bindings())
    name = CHECK.label(args.generation, args.mode)
    seal(args.evidence_directory / 'source-selection.json', encoded(selected | {
        'label': name, 'oracle_bindings': bindings, 'scope': CHECK.SCOPE,
        'driver_calls': 1, 'build_commands': 1, 'reference_children': 24,
        'selected_before_preparation_build_and_children': True}))
    driver_rows, build_rows = [], []

    def retain(label, rows):
        def write(row):
            seal(args.evidence_directory / (label + '-resources.json'), encoded(row))
            rows.append(row)
        return write

    def launch(command, **kwargs):
        if command[1:3] != ['test', '-c']:
            return subprocess.run(command, **kwargs)
        CHECK.require(not build_rows and command[0] == args.go and CHECK.input_pins() == selected['research_source_inputs'])
        CHECK.require(digest(Path(args.go)) == selected['go_executable_sha256'])
        return OBS.observe_call('selected-go-build', lambda: subprocess.run(command, **kwargs),
                                retain('selected-go-build', build_rows))

    original_subprocess = lifecycle.subprocess
    original_phase_subprocess = lifecycle.ORIGINAL.subprocess
    lifecycle.subprocess = SimpleNamespace(run=launch, TimeoutExpired=subprocess.TimeoutExpired)
    inner = args.evidence_directory / 'lifecycle'
    life_path = args.evidence_directory / 'lifecycle-samples.json'

    def complete_driver():
        with CHECK.PROJECTOR.selected_oracles(roots, args.mode):
            # No full expected_document was computed in this worker preflight.
            corpus = CHECK.LEGACY.LIFE.SCALE.expected_document()
            raw = encoded(corpus)
            CHECK.require(len(raw) <= CHECK.BYTE.MAX_FILE_BYTES)
            seal(args.evidence_directory / 'complete-result.json', raw)
            stdout = io.StringIO()
            try:
                with redirect_stdout(stdout):
                    lifecycle.main(['--node-source', str(args.node_source), '--go', args.go,
                        '--output', str(life_path), '--evidence-directory', str(inner)])
            finally:
                # Retain any partial actual delegate output on failure, too.
                seal(args.evidence_directory / 'delegate.stdout', stdout.getvalue().encode('ascii'))
            CHECK.require(stdout.getvalue().encode('ascii') == CHECK.DELEGATE_STDOUT)
            life_raw = life_path.read_bytes()
            life = json.loads(life_raw, object_pairs_hook=CHECK.BYTE.object_pairs)
            CHECK.LEGACY.LIFE.check_samples(life, raw, corpus)
            CHECK.require(life_raw == encoded(life))
            CHECK.require((inner / 'unchanged-conformance.json').read_bytes() == raw)
            # Final selected complete checks, encoding and fsync stay inside.
            seal(args.evidence_directory / 'checked-lifecycle.json', encoded(life))
            seal(args.evidence_directory / 'checked-completion.json', encoded({
                'full_complete_bytes_and_lifecycle_checked': True, 'oracle_bindings': bindings,
                'actual_build_commands': len(build_rows), 'actual_reference_children': 24,
                'consumer_result': 'REFUSED', 'production_acceptance_enabled': False}))

    try:
        OBS.observe_call(name, complete_driver, retain(name, driver_rows))
    finally:
        lifecycle.subprocess = original_subprocess
        lifecycle.ORIGINAL.subprocess = original_phase_subprocess
    CHECK.require(len(driver_rows) == len(build_rows) == 1)
    CHECK.require(selection(args) == selected)
    raw = (args.evidence_directory / 'complete-result.json').read_bytes()
    life = json.loads((args.evidence_directory / 'checked-lifecycle.json').read_bytes(), object_pairs_hook=CHECK.BYTE.object_pairs)
    build_command = json.loads((inner / 'go-build-tests.json').read_bytes(), object_pairs_hook=CHECK.BYTE.object_pairs)
    sample = {'generation': args.generation, 'mode': args.mode, 'oracle_bindings': bindings,
        'result_bytes': len(raw), 'result_sha256': hashlib.sha256(raw).hexdigest(),
        'delegate_stdout_sha256': hashlib.sha256((args.evidence_directory / 'delegate.stdout').read_bytes()).hexdigest(),
        'lifecycle_samples': life, 'driver': driver_rows[0], 'build': build_rows[0], 'build_command': build_command}
    # No unprojected full-oracle work follows the observation in this worker.
    sys.stdout.buffer.write(encoded(CHECK.worker_document(sample, selected)))


def measure(args):
    OBS.preflight()
    CHECK.require(args.output is not None)
    for path in (args.output, args.evidence_directory):
        CHECK.require(not path.exists() and not path.is_symlink())
    CHECK.require(args.output.absolute() != args.evidence_directory.absolute())
    args.evidence_directory.mkdir(mode=0o700)
    (args.evidence_directory / 'workers').mkdir(mode=0o700)
    selected = selection(args)
    raw, corpus = CHECK.BYTE.read_corpus(HERE / 'testdata/candidate-tree-import-scale.json')
    seal(args.evidence_directory / 'preselection.json', encoded(selected | {
        'reference': CHECK.REFERENCE, 'scope': CHECK.SCOPE, 'oracle_bindings': CHECK.bindings(),
        'corpus_sha256': hashlib.sha256(raw).hexdigest(), 'ordered_workers': [CHECK.label(g, m) for g, m in CHECK.inventory()],
        'driver_calls': 4, 'build_commands': 4, 'reference_children': 96,
        'existing_per_command_timeout_seconds': 600, 'hard_whole_worker_deadline_enforced': False,
        'driver_wall_acceptance_ceiling_ns': CHECK.LEGACY.MAX_DRIVER_WALL_NS,
        'cache_policy': CHECK.LEGACY.CACHE_POLICY, 'selected_before_workers': True}))
    # This controller's mandatory stock oracle is outside worker resource scope.
    CHECK.LEGACY.LIFE.SCALE.check_corpus(corpus)
    samples = []
    for generation, mode in CHECK.inventory():
        CHECK.require(selection(args) == selected)
        name = CHECK.label(generation, mode)
        evidence = args.evidence_directory / 'workers' / name
        command = [sys.executable, '-I', '-B', str(HERE / 'measure_projected_driver.py'), '--worker',
            '--generation', str(generation), '--mode', mode, '--node-source', str(args.node_source),
            '--go', args.go, '--evidence-directory', str(evidence)]
        # Retain the legacy finite per-command deadlines, without claiming a
        # new hard whole-worker deadline or silently abandoning descendants.
        result = subprocess.run(command, capture_output=True)
        out, err = result.stdout, result.stderr
        for suffix, data in (('stdout', out), ('stderr', err)):
            seal(args.evidence_directory / (name + '.' + suffix), data)
        outcome = {'label': name, 'completed': True, 'actual_exit': result.returncode,
            'stdout_sha256': hashlib.sha256(out).hexdigest(), 'stderr_sha256': hashlib.sha256(err).hexdigest()}
        seal(args.evidence_directory / (name + '-command.json'), encoded(outcome))
        CHECK.require(result.returncode == 0 and not err)
        CHECK.require((evidence / 'complete-result.json').read_bytes() == raw)
        body = json.loads(out, object_pairs_hook=CHECK.BYTE.object_pairs)
        CHECK.require(out == encoded(body))
        for k in ('runtime', 'research_source_inputs', 'python_executable_sha256', 'go_executable_sha256'):
            CHECK.RET.exact(body.pop(k), selected[k])
        CHECK.RET.exact(body['driver'], json.loads((evidence / (name + '-resources.json')).read_bytes()))
        CHECK.RET.exact(body['build'], json.loads((evidence / 'selected-go-build-resources.json').read_bytes()))
        CHECK.require(encoded(body['lifecycle_samples']) == (evidence / 'checked-lifecycle.json').read_bytes())
        samples.append(body | {'command': outcome})
        print(json.dumps({'completed_driver_worker': name, 'reference_children': 24,
                          'production_acceptance_enabled': False}, sort_keys=True), file=sys.stderr, flush=True)
    CHECK.require(selection(args) == selected)
    document = {'format_version': 1, 'kind': 'selected-complete-driver-projection-comparison',
        'source': CHECK.LEGACY.LIFE.SCALE.SCALE.SOURCE, 'reference': CHECK.REFERENCE, 'scope': CHECK.SCOPE,
        'corpus_sha256': hashlib.sha256(raw).hexdigest(), 'research_source_inputs': selected['research_source_inputs'],
        'runtime': selected['runtime'], 'python_executable_sha256': selected['python_executable_sha256'],
        'go_executable_sha256': selected['go_executable_sha256'], 'cache_policy': CHECK.LEGACY.CACHE_POLICY,
        'samples': samples, 'consumer_result': 'REFUSED', 'production_acceptance_enabled': False}
    CHECK.check_samples(document, raw, corpus)
    seal(args.output, encoded(document))
    seal(args.evidence_directory / 'completed.json', encoded({'actual_driver_workers': 4, 'actual_build_commands': 4,
        'actual_reference_children': 96, 'all_complete_bytes_equal': True,
        'samples_sha256': hashlib.sha256(encoded(document)).hexdigest(), 'no_retries_or_filtering': True,
        'consumer_result': 'REFUSED', 'production_acceptance_enabled': False}))
    print(json.dumps({'actual_driver_workers': 4, 'actual_build_commands': 4, 'actual_reference_children': 96,
        'all_complete_bytes_equal': True, 'production_acceptance_enabled': False}, sort_keys=True))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--worker', action='store_true')
    parser.add_argument('--generation', type=int)
    parser.add_argument('--mode', choices=CHECK.MODES)
    parser.add_argument('--node-source', type=Path, required=True)
    parser.add_argument('--go', required=True)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--evidence-directory', type=Path, required=True)
    args = parser.parse_args(argv)
    os.umask(0o077)
    if args.worker:
        CHECK.require(args.output is None)
        worker(args)
    else:
        CHECK.require(args.generation is None and args.mode is None)
        measure(args)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError, OverflowError, RecursionError):
        print('Driver comparison failed; preserve actual evidence and disabled production acceptance.', file=sys.stderr)
        raise SystemExit(1)
