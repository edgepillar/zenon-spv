#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Observe 24 unchanged file/NodeTree children through exit, offline.

Delegate source selection, build, literal workload and complete byte checks to
the existing reproducer. Replace only its selected child launcher locally:
retain per-child wait4 wall/RSS, closed output files and copied build storage.
Every actual stream/outcome is sealed before interpretation. No retries.
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


ORIGINAL = load('lifecycle_unchanged_reproducer', 'reproduce_tree_import_scale.py')
CHECK = load('lifecycle_independent_checker', 'check_tree_import_lifecycle.py')
SOURCE, CAPTURE = ORIGINAL.SOURCE, CHECK.CAPTURE


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--node-source', type=Path, required=True)
    parser.add_argument('--go', required=True)
    parser.add_argument('--output', type=Path, required=True, help='New lifecycle sample document')
    parser.add_argument('--evidence-directory', type=Path, required=True)
    args = parser.parse_args(argv)
    CAPTURE.preflight()
    SOURCE.require(not args.output.exists() and not args.output.is_symlink(), 'preserve existing lifecycle output')
    SOURCE.require(args.output.absolute() != args.evidence_directory.absolute(), 'select distinct new output paths')
    pins = CHECK.input_pins()
    expected = CHECK.SCALE.expected_document()
    corpus_raw = CHECK.encoded(expected)
    SOURCE.require(len(corpus_raw) <= CHECK.BYTE.MAX_FILE_BYTES, 'preflight unchanged compact corpus ceiling')
    inventory = [(generation, case, repetition, mode) for generation in range(2)
                 for case, repetition, mode in CHECK.SCALE.inventory(expected)]
    phase_output = args.evidence_directory / 'unchanged-conformance.json'
    phase_samples = args.evidence_directory / 'unchanged-phase-samples.json'
    rows, selected = [], False

    def launch(command, **kwargs):
        nonlocal selected
        if not selected:
            prior = json.loads((args.evidence_directory / 'source-selection.json').read_bytes())
            SOURCE.require(prior['research_source_inputs'] == {n: pins[n] for n in CHECK.SCALE.INPUT_NAMES},
                           'unchanged source selection differs')
            SOURCE.seal(args.evidence_directory / 'lifecycle-source-selection.json', SOURCE.encoded({
                'node_revision': SOURCE.NODE_REVISION, 'node_tree': SOURCE.NODE_TREE,
                'matched_node_blobs': prior['matched_blobs'], 'research_source_inputs': pins,
                'corpus_sha256': hashlib.sha256(corpus_raw).hexdigest(),
                'ordered_children': ['%d-%s-%d-%s' % (g, c['input']['name'], r, m) for g, c, r, m in inventory],
                'reference_children_required': 24, 'generations': 2, 'repetitions': 3,
                'modes': ['plain', 'allocation'], 'scope': CHECK.SCOPE,
                'timeout_ns': CAPTURE.TIMEOUT_NS, 'stdout_ceiling_bytes': CAPTURE.OUTPUT_CEILING,
                'stderr_ceiling_bytes': CAPTURE.OUTPUT_CEILING, 'selected_before_build_and_children': True}))
            selected = True
        if command[-1] != '-test.run=^TestTreeImportScaleChild$':
            return subprocess.run(command, **kwargs)
        SOURCE.require(len(rows) < len(inventory), 'unexpected extra child')
        generation, case, repetition, mode = inventory[len(rows)]
        label = '%d-%s-%d-%s' % (generation, case['input']['name'], repetition, mode)
        SOURCE.require(len(command) == 3 and command[1] == '-test.v', 'unexpected child arguments')
        env = kwargs['env']
        SOURCE.require((env['TREE_IMPORT_SCALE_CASE'], env['TREE_IMPORT_SCALE_REPETITION'], env['TREE_IMPORT_SCALE_MODE'])
                       == (case['input']['name'], str(repetition), mode), 'ordered child selection differs')
        SOURCE.require(kwargs['capture_output'] is True and kwargs['timeout'] == 600, 'existing child launch policy differs')
        SOURCE.require(CHECK.input_pins() == pins, 'selected wrapper source changed before child')
        binary = json.loads((args.evidence_directory / 'binary-selection.json').read_bytes())
        SOURCE.require(hashlib.sha256(Path(command[0]).read_bytes()).hexdigest() == binary['reference_binary_sha256'],
                       'preselected binary changed before child')
        root = Path(kwargs['cwd']).parent
        before = CAPTURE.observe_workspace(root)
        result, outcome = CAPTURE.capture_command(command, cwd=kwargs['cwd'], env=env,
            directory=args.evidence_directory, label=label)
        after = CAPTURE.observe_workspace(root)
        SOURCE.seal(args.evidence_directory / ('lifecycle-' + label + '-workspace.json'),
                    SOURCE.encoded({'before': before, 'after': after}))
        rows.append(outcome | {'workspace_before': before, 'workspace_after': after})
        SOURCE.require(not outcome['refusal'] and result.returncode == 0 and not result.stderr,
                       'lifecycle child failed; preserve all actual evidence and stop')
        return result

    # Replace this module reference only. The stdlib subprocess module and
    # the capture helper keep their original APIs; existing files are untouched.
    ORIGINAL.subprocess = SimpleNamespace(run=launch, TimeoutExpired=subprocess.TimeoutExpired)
    ORIGINAL.main(['--node-source', str(args.node_source), '--go', args.go,
                   '--output', str(phase_output), '--samples', str(phase_samples),
                   '--evidence-directory', str(args.evidence_directory)])
    SOURCE.require(len(rows) == 24 and phase_output.read_bytes() == corpus_raw, 'complete child inventory differs')
    SOURCE.require(CHECK.input_pins() == pins, 'wrapper source changed during children')
    phases = json.loads(phase_samples.read_bytes(), object_pairs_hook=CHECK.BYTE.object_pairs)
    document = {'format_version': 1, 'kind': 'candidate-tree-import-lifecycle-samples',
        'source': CHECK.SCALE.SCALE.SOURCE, 'scope': CHECK.SCOPE,
        'corpus_sha256': hashlib.sha256(corpus_raw).hexdigest(), 'research_source_inputs': pins,
        'phase_samples': phases, 'lifecycle': [rows[:12], rows[12:]],
        'consumer_result': 'REFUSED', 'production_acceptance_enabled': False}
    summary = CHECK.check_samples(document, corpus_raw, expected)
    SOURCE.seal(args.output, CHECK.encoded(document))
    SOURCE.seal(args.evidence_directory / 'lifecycle-completed.json', SOURCE.encoded({
        'actual_reference_children': 24, 'no_child_retries_or_filtering': True,
        'research_source_inputs': pins, 'reference_binary_sha256': phases['reference_binary_sha256'],
        'corpus_sha256': document['corpus_sha256'], 'lifecycle_samples_sha256': hashlib.sha256(CHECK.encoded(document)).hexdigest(),
        'full_reference_child_exit_observed': True, 'old_named_phase_contract_preserved': True,
        'parent_or_compiler_memory_measured': False, 'whole_pipeline_memory_measured': False,
        'peak_disk_measured': False, 'execution_provenance_authenticated': False,
        'production_acceptance_enabled': False, 'summary': summary}))
    print(json.dumps({'actual_reference_children': 24, 'full_selected_child_wall_and_exit_RSS_observed': True,
                      'whole_pipeline_memory_measured': False, 'production_acceptance_enabled': False}, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError, OverflowError, RecursionError):
        print('Reference child lifecycle failed; preserve actual evidence and disabled production acceptance.', file=sys.stderr)
        sys.exit(1)
