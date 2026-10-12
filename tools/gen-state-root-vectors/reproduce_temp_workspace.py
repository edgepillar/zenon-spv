#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Observe one unchanged offline file/NodeTree driver and 24 child workspaces.

Use separately owned TMPDIRs and add periodic stat work inside child waits.
Retain every actual row, stream, outcome and partial failure. No retries.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('selected_workspace_checker', HERE / 'check_temp_workspace.py')
CHECK = importlib.util.module_from_spec(spec)
spec.loader.exec_module(CHECK)
OBS, SOURCE = CHECK.OBS, CHECK.LEGACY.load('workspace_source_selector', 'regenerate.py')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--node-source', type=Path, required=True)
    parser.add_argument('--go', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--evidence-directory', type=Path, required=True)
    args = parser.parse_args(argv)
    OBS.preflight()
    for path in (args.output, args.evidence_directory):
        SOURCE.require(not path.exists() and not path.is_symlink(), 'preserve existing workspace evidence')
    SOURCE.require(args.output.absolute() != args.evidence_directory.absolute(), 'select distinct output paths')
    pins = CHECK.input_pins()
    manifest_raw, manifest = SOURCE.source_manifest()
    SOURCE.snapshot_source(args.node_source, manifest['files'])
    args.evidence_directory.mkdir(mode=0o700)
    lifecycle = CHECK.load('workspace_unchanged_lifecycle', 'reproduce_tree_import_lifecycle.py')
    roots = {'lifecycle': lifecycle, 'checks': CHECK.LEGACY.LEGACY}
    bindings = CHECK.LEGACY.PROJECTOR.binding_manifest(roots)
    CHECK.RET.exact(bindings, CHECK.LEGACY.bindings())
    SOURCE.seal(args.evidence_directory / 'workspace-source-selection.json', CHECK.encoded({
        'node_revision': SOURCE.NODE_REVISION, 'node_tree': SOURCE.NODE_TREE,
        'matched_node_blobs': len(manifest['files']), 'node_manifest_sha256': hashlib.sha256(manifest_raw).hexdigest(),
        'research_source_inputs': pins, 'oracle_bindings': bindings, 'scope': CHECK.SCOPE,
        'driver_calls': 1, 'build_commands': 1, 'reference_children': 24,
        'interval_ns': OBS.INTERVAL_NS, 'maximum_samples_per_child': OBS.MAX_SAMPLES,
        'maximum_entries_per_traversal': OBS.MAX_ENTRIES, 'maximum_depth': OBS.MAX_DEPTH,
        'maximum_file_bytes_per_traversal': OBS.MAX_FILE_BYTES,
        'source_compiler_caches_and_evidence_outside_child_TMPDIR': True,
        'selected_before_driver_build_and_children': True}))
    observations = []
    original_capture = lifecycle.CAPTURE.capture_command
    original_time = lifecycle.CAPTURE.time

    def capture(command, **kwargs):
        CHECK.require(len(observations) < 24 and CHECK.input_pins() == pins)
        result, outcome, exception_type = None, None, None
        with tempfile.TemporaryDirectory(prefix='candidate-input-database-workspace-') as temporary:
            observer = OBS.Observer(Path(temporary))
            observer.take('before-spawn')
            environment = kwargs['env'].copy()
            environment['TMPDIR'] = temporary
            kwargs['env'] = environment

            def sleep(seconds):
                observer.during_wait()
                original_time.sleep(seconds)

            lifecycle.CAPTURE.time = SimpleNamespace(monotonic_ns=original_time.monotonic_ns, sleep=sleep)
            try:
                result, outcome = original_capture(command, **kwargs)
                return result, outcome
            except BaseException as error:
                exception_type = type(error).__name__
                raise
            finally:
                lifecycle.CAPTURE.time = original_time
                final_observation_error = None
                try:
                    if outcome is not None and outcome['process_reaped']:
                        observer.take('after-reap')
                except BaseException as error:
                    final_observation_error = error
                    exception_type = exception_type or type(error).__name__
                row = {'label': kwargs['label'], 'method': OBS.METHOD, 'capture_platform': sys.platform,
                    'interval_ns': OBS.INTERVAL_NS, 'maximum_samples': OBS.MAX_SAMPLES,
                    'maximum_entries': OBS.MAX_ENTRIES, 'maximum_depth': OBS.MAX_DEPTH,
                    'maximum_file_bytes': OBS.MAX_FILE_BYTES, 'capture_exception_type': exception_type,
                    'capture_actual_exit': result.returncode if result is not None else None,
                    'capture_reaped': outcome['process_reaped'] if outcome is not None else None,
                    'capture_refusal': outcome['refusal'] if outcome is not None else 'capture-exception',
                    'points': observer.points, 'summary': OBS.summary(observer.points)}
                SOURCE.seal(args.evidence_directory / ('workspace-' + kwargs['label'] + '.json'), CHECK.encoded(row))
                observations.append(row)
                if final_observation_error is not None:
                    raise final_observation_error

    lifecycle.CAPTURE.capture_command = capture
    life_path = args.evidence_directory / 'lifecycle-samples.json'
    try:
        with CHECK.LEGACY.PROJECTOR.selected_oracles(roots, 'projected'):
            corpus = CHECK.LIFE.SCALE.expected_document()
            raw = CHECK.encoded(corpus)
            SOURCE.require(len(raw) <= CHECK.BYTE.MAX_FILE_BYTES, 'preflight compact corpus ceiling')
            lifecycle.main(['--node-source', str(args.node_source), '--go', args.go,
                '--output', str(life_path), '--evidence-directory', str(args.evidence_directory / 'lifecycle')])
            document = {'format_version': 1, 'kind': 'candidate-input-database-workspace-samples',
                'source': CHECK.LIFE.SCALE.SCALE.SOURCE, 'scope': CHECK.SCOPE,
                'research_source_inputs': pins, 'corpus_sha256': hashlib.sha256(raw).hexdigest(),
                'lifecycle_samples': json.loads(life_path.read_bytes(), object_pairs_hook=CHECK.BYTE.object_pairs),
                'observations': observations, 'consumer_result': 'REFUSED', 'production_acceptance_enabled': False}
            report = CHECK.check_samples(document, raw, corpus)
            CHECK.require(CHECK.input_pins() == pins)
            SOURCE.seal(args.output, CHECK.encoded(document))
            SOURCE.seal(args.evidence_directory / 'workspace-completed.json', CHECK.encoded(report))
    finally:
        lifecycle.CAPTURE.capture_command = original_capture
        lifecycle.CAPTURE.time = original_time
    print(json.dumps({'actual_reference_children': 24, 'workspace_stat_observations': report['workspace_stat_observations'],
                      'peak_disk_measured': False, 'production_acceptance_enabled': False}, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError, OverflowError, RecursionError):
        print('Temporary workspace observation failed; preserve actual evidence and disabled production acceptance.', file=sys.stderr)
        sys.exit(1)
