#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Observe one unchanged offline lifecycle driver and its one Go build.

Preselect all sources, 24 children and cache/method scopes. Retain the actual
driver/build observations on failure; do not retry or filter measurements.
Delegate fixtures, build flags, child capture and complete conformance unchanged.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, HERE / file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ORIGINAL = load('driver_unchanged_lifecycle_reproducer', 'reproduce_tree_import_lifecycle.py')
CHECK = load('driver_independent_resource_checker', 'check_tree_driver_resources.py')
SOURCE, OBS = ORIGINAL.SOURCE, CHECK.OBS


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--node-source', type=Path, required=True)
    parser.add_argument('--go', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--evidence-directory', type=Path, required=True)
    args = parser.parse_args(argv)
    OBS.preflight()
    for path in (args.output, args.evidence_directory):
        SOURCE.require(not path.exists() and not path.is_symlink(), 'preserve existing driver output/evidence')
    SOURCE.require(args.output.absolute() != args.evidence_directory.absolute(), 'select distinct new output paths')
    pins = CHECK.input_pins()
    expected = CHECK.LIFE.SCALE.expected_document()
    raw = CHECK.encoded(expected)
    SOURCE.require(len(raw) <= CHECK.BYTE.MAX_FILE_BYTES, 'preserve compact corpus ceiling')
    inventory = ['%d-%s-%d-%s' % (g, c['input']['name'], r, m) for g in range(2)
                 for c, r, m in CHECK.LIFE.SCALE.inventory(expected)]
    args.evidence_directory.mkdir(mode=0o700)
    SOURCE.seal(args.evidence_directory / 'driver-source-selection.json', SOURCE.encoded({
        'node_revision': SOURCE.NODE_REVISION, 'node_tree': SOURCE.NODE_TREE,
        'research_source_inputs': pins, 'corpus_sha256': hashlib.sha256(raw).hexdigest(),
        'ordered_children': inventory, 'driver_calls': 1, 'build_commands': 1,
        'cache_policy': CHECK.CACHE_POLICY, 'scope': CHECK.SCOPE,
        'wall_method': OBS.WALL_METHOD, 'self_method': OBS.SELF_METHOD,
        'child_cpu_method': OBS.CHILD_CPU_METHOD, 'cpu_storage_method': OBS.CPU_METHOD,
        'driver_wall_acceptance_ceiling_ns': CHECK.MAX_DRIVER_WALL_NS,
        'hard_whole_driver_deadline_enforced': False,
        'selected_before_driver_build_and_children': True}))
    build_rows, driver_rows = [], []

    def retain(label, rows):
        def write(row):
            SOURCE.seal(args.evidence_directory / (label + '-resources.json'), SOURCE.encoded(row))
            rows.append(row)
        return write

    def launch(command, **kwargs):
        if command[1:3] != ['test', '-c']:
            return subprocess.run(command, **kwargs)
        SOURCE.require(not build_rows and command[0] == args.go, 'unexpected extra source build')
        SOURCE.require(CHECK.input_pins() == pins, 'selected wrapper source changed before build')
        return OBS.observe_call('go-build-tests', lambda: subprocess.run(command, **kwargs),
                                retain('go-build-tests', build_rows))

    # Replace only the unchanged lifecycle module's subprocess reference.
    # Its reference-child wait4 capture and the stdlib module remain intact.
    ORIGINAL.subprocess = SimpleNamespace(run=launch, TimeoutExpired=subprocess.TimeoutExpired)
    inner = args.evidence_directory / 'lifecycle'
    lifecycle_path = args.evidence_directory / 'lifecycle-samples.json'
    OBS.observe_call('lifecycle-driver', lambda: ORIGINAL.main([
        '--node-source', str(args.node_source), '--go', args.go, '--output', str(lifecycle_path),
        '--evidence-directory', str(inner)]), retain('lifecycle-driver', driver_rows))
    SOURCE.require(len(build_rows) == len(driver_rows) == 1, 'selected driver/build inventory differs')
    SOURCE.require(CHECK.input_pins() == pins, 'wrapper source changed during driver')
    lifecycle = json.loads(lifecycle_path.read_bytes(), object_pairs_hook=CHECK.BYTE.object_pairs)
    build_command = json.loads((inner / 'go-build-tests.json').read_bytes())
    document = {'format_version': 1, 'kind': 'candidate-tree-driver-resource-samples',
        'source': CHECK.LIFE.SCALE.SCALE.SOURCE, 'scope': CHECK.SCOPE,
        'corpus_sha256': hashlib.sha256(raw).hexdigest(), 'research_source_inputs': pins,
        'cache_policy': CHECK.CACHE_POLICY, 'lifecycle_samples': lifecycle,
        'driver': driver_rows[0], 'build': build_rows[0], 'build_command': build_command,
        'consumer_result': 'REFUSED', 'production_acceptance_enabled': False}
    summary = CHECK.check_samples(document, raw, expected)
    SOURCE.seal(args.output, CHECK.encoded(document))
    SOURCE.seal(args.evidence_directory / 'driver-completed.json', SOURCE.encoded({
        'actual_driver_calls': 1, 'actual_build_commands': 1, 'actual_reference_children': 24,
        'no_retries_or_filtering': True, 'research_source_inputs': pins,
        'reference_binary_sha256': lifecycle['phase_samples']['reference_binary_sha256'],
        'corpus_sha256': document['corpus_sha256'], 'samples_sha256': hashlib.sha256(CHECK.encoded(document)).hexdigest(),
        'compiler_peak_memory_measured': False, 'whole_pipeline_memory_measured': False,
        'peak_disk_measured': False, 'execution_provenance_authenticated': False,
        'production_acceptance_enabled': False, 'summary': summary}))
    print(json.dumps({'actual_driver_calls': 1, 'actual_build_commands': 1, 'actual_reference_children': 24,
                      'compiler_peak_memory_measured': False, 'production_acceptance_enabled': False}, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError, OverflowError, RecursionError):
        print('Reference driver resources failed; preserve actual evidence and disabled production acceptance.', file=sys.stderr)
        sys.exit(1)
