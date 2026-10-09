#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Run twenty-four selected larger opened-file/NodeTree children offline, without retries.

Complete node/research bytes and the built test binary are sealed before any
child. Preflight the compact conformance byte ceiling before building. Preserve
each actual stdout/stderr/exit before interpretation and stop on any failure.
Only owned temporary database and copied build directories are removed.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, HERE / file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SOURCE = load('import_scale_source_selection', 'regenerate.py')
CHECK = load('import_scale_independent_checker', 'check_tree_import_scale.py')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--node-source', type=Path, required=True)
    parser.add_argument('--go', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--samples', type=Path, required=True)
    parser.add_argument('--evidence-directory', type=Path, required=True)
    args = parser.parse_args(argv)
    paths = (args.output, args.samples, args.evidence_directory)
    SOURCE.require(len({p.absolute() for p in paths}) == 3, 'select distinct new output paths')
    for path in paths:
        SOURCE.require(not path.exists() and not path.is_symlink(), 'preserve existing output and evidence')
    manifest_raw, manifest = SOURCE.source_manifest()
    original = SOURCE.snapshot_source(args.node_source, manifest['files'])
    selected = {name: (HERE / name).read_bytes() for name in CHECK.INPUT_NAMES}
    pins = {name: hashlib.sha256(raw).hexdigest() for name, raw in selected.items()}
    expected = CHECK.expected_document()
    expected_raw = CHECK.encoded(expected)
    SOURCE.require(len(expected_raw) <= CHECK.BYTE.MAX_FILE_BYTES, 'preflight compact fixture byte ceiling')
    args.evidence_directory.mkdir(mode=0o700)
    SOURCE.seal(args.evidence_directory / 'source-selection.json', SOURCE.encoded({
        'revision': SOURCE.NODE_REVISION, 'tree': SOURCE.NODE_TREE, 'matched_blobs': len(original),
        'source_manifest_sha256': hashlib.sha256(manifest_raw).hexdigest(), 'research_source_inputs': pins,
        'selected_cases': [list(item) for item in CHECK.SELECTIONS], 'generations': 2, 'repetitions': 3, 'modes': ['plain', 'allocation'],
        'compact_fixture_bytes_preflighted': len(expected_raw),
        'maximum_file_records': 1024, 'maximum_file_raw_bytes': max(r['selection']['bytes'] for c in expected['cases'] for s in c['steps'] for r in s['imports']),
        'maximum_target_entries': 4096, 'maximum_target_hex_payload_bytes': 4096 * 128,
        'selected_owned_input_files_per_pair': 35, 'selected_input_raw_bytes_per_pair': sum(r['selection']['bytes'] for c in expected['cases'] for s in c['steps'] for r in s['imports']), 'network_acquisition': False}))
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith('GO') and not key.startswith('TREE_IMPORT_SCALE_')}
    environment.update(GOTOOLCHAIN='local', GOWORK='off', GOFLAGS='', GOENV='off',
                       GOPROXY='off', GOSUMDB='off', CGO_ENABLED='0')
    all_commands = []

    def execute(label, command, root, selection=None):
        env = environment.copy()
        if selection is not None:
            case, repetition, mode = selection
            env.update(TREE_IMPORT_SCALE_CASE=case['input']['name'], TREE_IMPORT_SCALE_REPETITION=str(repetition), TREE_IMPORT_SCALE_MODE=mode)
        try:
            result = subprocess.run(command, cwd=root, env=env, capture_output=True, timeout=600)
            out, err, code, completed = result.stdout, result.stderr, result.returncode, True
        except subprocess.TimeoutExpired as error:
            out, err, code, completed = error.stdout or b'', error.stderr or b'', None, False
        SOURCE.seal(args.evidence_directory / (label + '.stdout'), out)
        SOURCE.seal(args.evidence_directory / (label + '.stderr'), err)
        record = {'label': label, 'completed': completed, 'actual_exit': code,
                  'stdout_sha256': hashlib.sha256(out).hexdigest(), 'stderr_sha256': hashlib.sha256(err).hexdigest()}
        all_commands.append(record)
        SOURCE.seal(args.evidence_directory / (label + '.json'), SOURCE.encoded(record))
        SOURCE.require(completed and code == 0 and not err, 'reference command failed; preserve actual evidence')
        return out, record

    with tempfile.TemporaryDirectory(prefix='candidate-tree-import-scale-') as temporary:
        root = Path(temporary)
        node, generator = root / 'reference-node', root / 'generator'
        generator.mkdir()
        for name, raw in original.items():
            path = node / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
            path.chmod(0o755 if manifest['files'][name]['mode'] == '100755' else 0o644)
        for name in CHECK.BUILD_NAMES:
            (generator / name).write_bytes(selected[name])
        with (generator / 'go.mod').open('ab') as stream:
            stream.write(b'\nreplace github.com/zenon-network/go-zenon => ../reference-node\n')
        version_raw, _ = execute('go-version', [args.go, 'version'], generator)
        version = version_raw.decode('ascii').strip()
        SOURCE.require(version.startswith('go version go1.25.') and sys.platform in ('darwin', 'linux'),
                       'select a supported offline Go 1.25 platform')
        binary = generator / 'tree-import-scale-reference.test'
        execute('go-build-tests', [args.go, 'test', '-c', '-mod=readonly', '-trimpath',
                                 '-tags', 'candidate_patch_import,candidate_patch_targets,candidate_patch_resources,candidate_patch_file,candidate_bulk_guards,candidate_patch_tree,candidate_patch_tree_tail,candidate_retention,candidate_tree_import_scale', '-o', str(binary), '.'], generator)
        execute('go-buildinfo', [args.go, 'version', '-m', str(binary)], generator)
        binary_sha256 = hashlib.sha256(binary.read_bytes()).hexdigest()
        SOURCE.seal(args.evidence_directory / 'reference-test-binary', binary.read_bytes())
        SOURCE.seal(args.evidence_directory / 'binary-selection.json', SOURCE.encoded({
            'reference_binary_sha256': binary_sha256, 'go_version': version, 'research_source_inputs': pins,
            'selected_before_any_child_execution': True, 'execution_provenance_authenticated': False}))
        documents, samples, commands = [], [], []
        for generation in range(2):
            cases, measured, outcomes = [], [], []
            for case, repetition, mode in CHECK.inventory(expected):
                label = '%d-%s-%d-%s' % (generation, case['input']['name'], repetition, mode)
                stdout, outcome = execute(label, [str(binary), '-test.v', '-test.run=^TestTreeImportScaleChild$'],
                                          generator, (case, repetition, mode))
                marker = b'TREE_IMPORT_SCALE='
                lines = [line[len(marker):] for line in stdout.splitlines() if line.startswith(marker)]
                SOURCE.require(len(lines) == 1 and b'--- PASS: TestTreeImportScaleChild ' in stdout, 'complete import scale child did not pass')
                record = json.loads(lines[0], object_pairs_hook=CHECK.BYTE.object_pairs)
                SOURCE.require(type(record) is dict and set(record) == {'conformance', 'measurement'}, 'invalid import scale child record')
                CHECK.RET.exact(record['conformance'], case)
                CHECK.measurement_contract(record['measurement'], case, version.rsplit(' ', 1)[1], version.split()[2], repetition, mode)
                if repetition == 0 and mode == 'plain':
                    cases.append(record['conformance'])
                measured.append(record['measurement'])
                outcomes.append(outcome | {'result_sha256': CHECK.binding(record)})
            document = {key: value for key, value in expected.items() if key != 'cases'} | {'cases': cases}
            CHECK.check_corpus(document)
            documents.append(CHECK.encoded(document))
            samples.append(measured)
            commands.append(outcomes)
        SOURCE.require(documents[0] == documents[1] == expected_raw, 'complete larger file/tree conformance differs')
        report = {'format_version': 1, 'kind': 'candidate-tree-import-scale-samples', 'source': expected['source'],
            'corpus_sha256': hashlib.sha256(documents[0]).hexdigest(), 'research_source_inputs': pins,
            'conformance_runs': 2, 'measurement_runs_expected_to_vary': True, 'production_resource_budgets_qualified': False,
            'source_execution_platform': sys.platform, 'go_version': version, 'reference_binary_sha256': binary_sha256,
            'samples': samples, 'commands': commands}
        CHECK.check_samples(report, documents[0], document)
        SOURCE.require(SOURCE.snapshot_source(node, manifest['files']) == original, 'copied node source changed')
        SOURCE.require(SOURCE.snapshot_source(args.node_source, manifest['files']) == original, 'selected node source changed')
        SOURCE.require(selected == {name: (HERE / name).read_bytes() for name in CHECK.INPUT_NAMES}, 'research source changed')
        SOURCE.require(hashlib.sha256(binary.read_bytes()).hexdigest() == binary_sha256, 'selected reference binary changed')
        SOURCE.seal(args.output, documents[0])
        SOURCE.seal(args.samples, CHECK.encoded(report))
        SOURCE.seal(args.evidence_directory / 'completed.json', SOURCE.encoded({
            'node_revision': SOURCE.NODE_REVISION, 'node_tree': SOURCE.NODE_TREE, 'matched_source_blobs': len(original),
            'go_version': version, 'source_execution_platform': sys.platform, 'reference_binary_sha256': binary_sha256,
            'deterministic_generations': 2, 'actual_fresh_child_samples': 24, 'no_child_retries_or_filtering': True,
            'research_source_inputs': pins, 'corpus_sha256': report['corpus_sha256'],
            'samples_sha256': hashlib.sha256(CHECK.encoded(report)).hexdigest(), 'commands': all_commands,
            'actual_NodeTree_executed': True, 'actual_retained_graph_pruning_and_clean_reopen_executed': True,
            'variable_query_phase_allocation_heap_RSS_and_closed_allocated_file_measurements_executed': True,
            'source_and_binary_pinned_before_children': True, 'execution_provenance_authenticated': False,
            'production_acceptance_enabled': False}))
    print(json.dumps({'actual_fresh_child_samples': 24, 'selected_cases': 2, 'deterministic_generations': 2,
                      'node_blobs': len(original), 'production_acceptance_enabled': False}, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError, OverflowError, RecursionError):
        print('Larger file/tree reference failed; preserve evidence and disabled production acceptance.', file=sys.stderr)
        sys.exit(1)
