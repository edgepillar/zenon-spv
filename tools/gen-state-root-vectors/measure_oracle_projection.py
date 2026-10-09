#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Preselect and retain 24 fresh Python reference/projected oracle workers.

No Go build or NodeTree/database/network execution. Observe each selected
complete reconstruction plus canonical result encoding/persistence. Retain
actual failures, streams and outputs; never retry, filter or overwrite a run.
The parent driver, final metric serialization and interpreter exit are outside
the worker SELF resource scope.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import subprocess
import sys

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('selected_oracle_comparison_contract', HERE / 'check_oracle_projection.py')
CHECK = importlib.util.module_from_spec(spec)
spec.loader.exec_module(CHECK)
OBS, PROJECT, encoded = CHECK.OBS, CHECK.PROJECT, CHECK.encoded


def seal(path, raw):
    CHECK.require(not path.exists() and not path.is_symlink())
    with path.open('xb') as f:
        f.write(raw)
        f.flush()
        os.fsync(f.fileno())
    path.chmod(0o400)


def runtime():
    return {'os': sys.platform, 'architecture': platform.machine().lower(),
            'python': platform.python_version(), 'implementation': platform.python_implementation()}


def interpreter_hash():
    return hashlib.sha256(Path(sys.executable).resolve().read_bytes()).hexdigest()


def worker(args):
    OBS.preflight()
    CHECK.require(args.generation in (0, 1) and args.repetition in (0, 1, 2))
    CHECK.require(args.mode in CHECK.MODES)
    selection = next(s for s in CHECK.IMPORT.SELECTIONS if s[0] == args.case)
    CHECK.require(not args.evidence_directory.exists() and not args.evidence_directory.is_symlink())
    args.evidence_directory.mkdir(mode=0o700)
    pins, selected_runtime, executable = CHECK.input_pins(), runtime(), interpreter_hash()
    CHECK.require(pins['check_tree_scale.py'] == CHECK.REFERENCE['level_source_sha256'])
    rows = []
    name = CHECK.label(args.generation, selection, args.repetition, args.mode)
    seal(args.evidence_directory / 'source-selection.json', encoded({
        'label': name, 'research_source_inputs': pins, 'runtime': selected_runtime,
        'python_executable_sha256': executable, 'scope': CHECK.SCOPE,
        'selected_paths': [p.hex() for p in PROJECT.selected_paths(selection)]}))

    def retain(row):
        seal(args.evidence_directory / 'resources.json', encoded(row))
        rows.append(row)

    def reconstruct():
        result = (PROJECT.IMPORT.expected_case(selection) if args.mode == 'reference'
                  else PROJECT.complete_case(selection))
        raw = encoded(result)
        CHECK.require(len(raw) <= CHECK.BYTE.MAX_FILE_BYTES)
        seal(args.evidence_directory / 'complete-result.json', raw)

    OBS.observe_call(name, reconstruct, retain)
    CHECK.require(len(rows) == 1 and CHECK.input_pins() == pins and interpreter_hash() == executable)
    raw = (args.evidence_directory / 'complete-result.json').read_bytes()
    sample = {'generation': args.generation, 'case': selection[0], 'repetition': args.repetition,
        'mode': args.mode, 'result_bytes': len(raw), 'result_sha256': hashlib.sha256(raw).hexdigest(), 'resource': rows[0]}
    sys.stdout.buffer.write(encoded(CHECK.worker_document(sample, selected_runtime, pins, executable)))


def measure(args):
    OBS.preflight()
    CHECK.require(args.output is not None and args.evidence_directory is not None)
    CHECK.require(not args.output.exists() and not args.output.is_symlink())
    CHECK.require(not args.evidence_directory.exists() and not args.evidence_directory.is_symlink())
    CHECK.require(args.output.absolute() != args.evidence_directory.absolute())
    args.evidence_directory.mkdir(mode=0o700)
    (args.evidence_directory / 'workers').mkdir(mode=0o700)
    raw, corpus = CHECK.BYTE.read_corpus(HERE / 'testdata/candidate-tree-import-scale.json')
    pins, selected_runtime, executable = CHECK.input_pins(), runtime(), interpreter_hash()
    selected = {'research_source_inputs': pins, 'runtime': selected_runtime,
        'python_executable_sha256': executable, 'reference': CHECK.REFERENCE, 'scope': CHECK.SCOPE,
        'corpus_sha256': hashlib.sha256(raw).hexdigest(),
        'ordered_workers': [CHECK.label(g, s, r, m) for g, s, r, m in CHECK.inventory()],
        'worker_timeout_seconds': 600, 'selected_before_workers': True,
        'parent_driver_resources_measured': False, 'Go_builds_or_NodeTree_children_selected': 0}
    seal(args.evidence_directory / 'preselection.json', encoded(selected))
    CHECK.IMPORT.check_corpus(corpus)
    expected = {c['input']['name']: encoded(c) for c in corpus['cases']}
    samples = []
    for g, selection, repetition, mode in CHECK.inventory():
        CHECK.require(CHECK.input_pins() == pins and interpreter_hash() == executable)
        name = CHECK.label(g, selection, repetition, mode)
        evidence = args.evidence_directory / 'workers' / name
        command = [sys.executable, '-I', '-B', str(HERE / 'measure_oracle_projection.py'),
            '--worker', '--generation', str(g), '--case', selection[0], '--repetition', str(repetition),
            '--mode', mode, '--evidence-directory', str(evidence)]
        completed, code = True, None
        try:
            result = subprocess.run(command, capture_output=True, timeout=600)
            out, err, code = result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired as error:
            out, err, completed = error.stdout or b'', error.stderr or b'', False
        for suffix, data in (('stdout', out), ('stderr', err)):
            seal(args.evidence_directory / (name + '.' + suffix), data)
        outcome = {'label': name, 'completed': completed, 'actual_exit': code,
            'stdout_sha256': hashlib.sha256(out).hexdigest(), 'stderr_sha256': hashlib.sha256(err).hexdigest()}
        seal(args.evidence_directory / (name + '-command.json'), encoded(outcome))
        CHECK.require(completed and code == 0 and not err)
        body = (evidence / 'complete-result.json').read_bytes()
        CHECK.require(body == expected[selection[0]])
        document = json.loads(out, object_pairs_hook=CHECK.BYTE.object_pairs)
        CHECK.require(out == encoded(document))
        for k, v in {'runtime': selected_runtime, 'research_source_inputs': pins,
                     'python_executable_sha256': executable}.items():
            CHECK.RET.exact(document.pop(k), v)
        CHECK.RET.exact(document['resource'], json.loads((evidence / 'resources.json').read_bytes()))
        CHECK.require(document['result_bytes'] == len(body) and document['result_sha256'] == hashlib.sha256(body).hexdigest())
        samples.append(document | {'command': outcome})
    CHECK.require(CHECK.input_pins() == pins and interpreter_hash() == executable)
    document = {'format_version': 1, 'kind': 'selected-sparse-oracle-comparison',
        'source': CHECK.IMPORT.SCALE.SOURCE, 'reference': CHECK.REFERENCE, 'scope': CHECK.SCOPE,
        'corpus_sha256': hashlib.sha256(raw).hexdigest(), 'research_source_inputs': pins,
        'runtime': selected_runtime, 'python_executable_sha256': executable, 'samples': samples,
        'consumer_result': 'REFUSED', 'production_acceptance_enabled': False}
    # The complete byte oracle was already computed above in this serial caller.
    CHECK.check_samples(document, raw, corpus)
    seal(args.output, encoded(document))
    seal(args.evidence_directory / 'completed.json', encoded({'workers': 24,
        'samples_sha256': hashlib.sha256(encoded(document)).hexdigest(), 'all_complete_bytes_equal': True,
        'measurement_retries_or_filtering': False, 'node_or_network_execution': False,
        'production_acceptance_enabled': False}))
    print(json.dumps({'fresh_Python_workers': 24, 'all_complete_bytes_equal': True,
                      'production_acceptance_enabled': False}, sort_keys=True))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--worker', action='store_true')
    parser.add_argument('--generation', type=int)
    parser.add_argument('--case', choices=[s[0] for s in CHECK.IMPORT.SELECTIONS])
    parser.add_argument('--repetition', type=int)
    parser.add_argument('--mode', choices=CHECK.MODES)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--evidence-directory', type=Path, required=True)
    args = parser.parse_args(argv)
    os.umask(0o077)
    if args.worker:
        CHECK.require(args.output is None and args.case is not None)
        worker(args)
    else:
        CHECK.require(all(v is None for v in (args.generation, args.case, args.repetition, args.mode)))
        measure(args)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError, StopIteration, subprocess.SubprocessError, OverflowError, RecursionError):
        print('Oracle comparison failed; preserve all actual outcomes and disabled production acceptance.', file=sys.stderr)
        raise SystemExit(1)
