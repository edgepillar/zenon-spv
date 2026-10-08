#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Reproduce a finite opened-file to low-level NodeTree seed handoff offline.

Select complete existing pinned source and local Go 1.25. Each literal family,
repetition and mode runs exactly once in a fresh child with owned temporary
files/storage. Preserve each actual outcome before interpretation; stop on error.
No fetching, service, RPC, signing, transactions or existing-output replacement.
Named file/preflight/storage phases exclude interim conformance queries; process
lifetime RSS includes those queries and setup. Samples are not production budgets.
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


SOURCE = load('tree_source_selection', 'regenerate.py')
CHECK = load('tree_handoff_reference_oracle', 'check_patch_tree.py')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--node-source', type=Path, required=True)
    parser.add_argument('--go', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--samples', type=Path, required=True)
    parser.add_argument('--evidence-directory', type=Path, required=True)
    args = parser.parse_args(argv)
    paths = (args.output, args.samples, args.evidence_directory)
    SOURCE.require(len({p.absolute() for p in paths}) == len(paths), 'select distinct output paths')
    for path in paths:
        SOURCE.require(not path.exists() and not path.is_symlink(), 'preserve existing output and evidence')
    manifest_raw, manifest = SOURCE.source_manifest()
    original = SOURCE.snapshot_source(args.node_source, manifest['files'])
    selected = {name: (HERE / name).read_bytes() for name in CHECK.INPUT_NAMES}
    pins = {name: hashlib.sha256(raw).hexdigest() for name, raw in selected.items()}
    args.evidence_directory.mkdir(mode=0o700)
    SOURCE.seal(args.evidence_directory / 'source-selection.json', SOURCE.encoded({
        'revision': SOURCE.NODE_REVISION, 'tree': SOURCE.NODE_TREE, 'matched_blobs': len(original),
        'source_manifest_sha256': hashlib.sha256(manifest_raw).hexdigest(), 'research_source_inputs': pins, 'network_acquisition': False}))
    environment = {key: value for key, value in os.environ.items() if not key.startswith('GO') and not key.startswith('PATCH_TREE_')}
    environment.update(GOTOOLCHAIN='local', GOWORK='off', GOFLAGS='', GOENV='off', GOPROXY='off', GOSUMDB='off', CGO_ENABLED='0')
    all_commands = []

    def execute(label, command, root, child=None):
        env = environment.copy()
        if child is not None:
            case, repetition, mode = child
            env.update(PATCH_TREE_CASE=case['name'], PATCH_TREE_MODE=mode, PATCH_TREE_REPETITION=str(repetition))
        try:
            result = subprocess.run(command, cwd=root, env=env, capture_output=True, timeout=240)
            stdout, stderr, code, completed = result.stdout, result.stderr, result.returncode, True
        except subprocess.TimeoutExpired as error:
            stdout, stderr, code, completed = error.stdout or b'', error.stderr or b'', None, False
        SOURCE.seal(args.evidence_directory / (label + '.stdout'), stdout)
        SOURCE.seal(args.evidence_directory / (label + '.stderr'), stderr)
        record = {'label': label, 'completed': completed, 'actual_exit': code,
                  'stdout_sha256': hashlib.sha256(stdout).hexdigest(), 'stderr_sha256': hashlib.sha256(stderr).hexdigest()}
        all_commands.append(record)
        SOURCE.seal(args.evidence_directory / (label + '.json'), SOURCE.encoded(record))
        SOURCE.require(completed and code == 0 and not stderr, 'reference command failed; preserve its evidence')
        return stdout, record

    with tempfile.TemporaryDirectory(prefix='candidate-patch-tree-') as temporary:
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
        SOURCE.require(version.startswith('go version go1.25.') and sys.platform in ('darwin', 'linux'), 'select a supported local Go 1.25 platform')
        binary = generator / 'patch-tree-reference.test'
        execute('go-build-tests', [args.go, 'test', '-c', '-mod=readonly', '-trimpath', '-tags',
            'candidate_patch_import,candidate_patch_targets,candidate_patch_resources,candidate_patch_file,candidate_bulk_guards,candidate_patch_tree',
            '-o', str(binary), '.'], generator)
        execute('go-buildinfo', [args.go, 'version', '-m', str(binary)], generator)
        expected = CHECK.expected_document()
        documents, samples, commands = [], [], []
        for generation in range(2):
            cases, measured, outcomes = [], [], []
            for case, repetition, mode in CHECK.inventory(expected):
                label = '%d-%s-%d-%s' % (generation, case['name'], repetition, mode)
                stdout, outcome = execute(label, [str(binary), '-test.v', '-test.run=^TestPatchTreeChild$'], generator, (case, repetition, mode))
                marker = b'PATCH_TREE='
                lines = [line[len(marker):] for line in stdout.splitlines() if line.startswith(marker)]
                SOURCE.require(len(lines) == 1 and b'--- PASS: TestPatchTreeChild ' in stdout, 'complete tree reference test did not pass')
                record = json.loads(lines[0])
                SOURCE.require(type(record) is dict and set(record) == {'conformance', 'measurement'}, 'invalid child record')
                CHECK.DEC.RET.exact(record['conformance'], case)
                if repetition == 0 and mode == 'plain': cases.append(record['conformance'])
                measured.append(record['measurement'])
                outcomes.append(outcome | {'result_sha256': CHECK.RESOURCE.binding(record)})
            document = {key: value for key, value in expected.items() if key != 'cases'} | {'cases': cases}
            CHECK.check_corpus(document)
            documents.append(SOURCE.encoded(document))
            samples.append(measured)
            commands.append(outcomes)
        SOURCE.require(documents[0] == documents[1], 'tree handoff conformance differs')
        report = {'format_version': 1, 'kind': 'candidate-patch-tree-handoff-samples', 'source': expected['source'],
            'corpus_sha256': hashlib.sha256(documents[0]).hexdigest(), 'conformance_runs': 2,
            'measurement_runs_expected_to_vary': True, 'production_resource_budgets_qualified': False,
            'source_execution_platform': sys.platform, 'go_version': version, 'reference_binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
            'samples': samples, 'commands': commands}
        CHECK.check_samples(report, documents[0], document)
        SOURCE.require(SOURCE.snapshot_source(node, manifest['files']) == original, 'copied node source changed')
        SOURCE.require(SOURCE.snapshot_source(args.node_source, manifest['files']) == original, 'selected node source changed')
        SOURCE.require(selected == {name: (HERE / name).read_bytes() for name in CHECK.INPUT_NAMES}, 'research source changed')
        SOURCE.seal(args.output, documents[0])
        SOURCE.seal(args.samples, SOURCE.encoded(report))
        SOURCE.seal(args.evidence_directory / 'completed.json', SOURCE.encoded({
            'node_revision': SOURCE.NODE_REVISION, 'node_tree': SOURCE.NODE_TREE, 'matched_source_blobs': len(original), 'go_version': version,
            'deterministic_generations': 2, 'cases_per_generation': len(expected['cases']), 'actual_fresh_child_samples': sum(map(len, samples)),
            'no_child_retries_or_filtering': True, 'corpus_sha256': report['corpus_sha256'], 'samples_sha256': hashlib.sha256(SOURCE.encoded(report)).hexdigest(),
            'research_source_inputs': pins, 'source_execution_platform': sys.platform, 'reference_binary_sha256': report['reference_binary_sha256'],
            'commands': all_commands, 'resource_measurements_executed': True, 'actual_NodeTree_executed': True,
            'controlled_clean_reopen_executed': True, 'execution_provenance_authenticated': False, 'runtime_state_proof_acceptance': False}))
    print(json.dumps({'deterministic_generations': 2, 'cases_per_generation': len(expected['cases']), 'actual_fresh_child_samples': sum(map(len, samples)),
        'node_blobs': len(original), 'production_acceptance_enabled': False}, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError):
        print('Candidate tree handoff reference failed; preserve evidence and disabled production acceptance.', file=sys.stderr)
        sys.exit(1)
