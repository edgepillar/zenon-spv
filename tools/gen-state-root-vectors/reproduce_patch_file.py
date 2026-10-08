#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Reproduce opened-regular-file research handoffs from a pinned node, offline.

Use a complete already selected source snapshot and Go 1.25. No source fetching,
node startup, RPC, wallet, signing, transactions or existing output replacement.
Only owned temporary raw fixtures and borrowed descriptors are used by the tests.
All command outcomes are kept before interpretation; a failure stops the driver.
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


SOURCE = load('file_source_selection', 'regenerate.py')
CHECK = load('file_reference_oracle', 'check_patch_file.py')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--node-source', type=Path, required=True)
    parser.add_argument('--go', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--evidence-directory', type=Path, required=True)
    args = parser.parse_args(argv)
    for path in (args.output, args.evidence_directory):
        SOURCE.require(not path.exists() and not path.is_symlink(), 'preserve existing output and evidence')
    manifest_raw, manifest = SOURCE.source_manifest()
    original = SOURCE.snapshot_source(args.node_source, manifest['files'])
    selected = {name: (HERE / name).read_bytes() for name in CHECK.INPUT_NAMES}
    pins = {name: hashlib.sha256(raw).hexdigest() for name, raw in selected.items()}
    args.evidence_directory.mkdir(mode=0o700)
    SOURCE.seal(args.evidence_directory / 'source-selection.json', SOURCE.encoded({
        'revision': SOURCE.NODE_REVISION, 'tree': SOURCE.NODE_TREE, 'matched_blobs': len(original),
        'source_manifest_sha256': hashlib.sha256(manifest_raw).hexdigest(), 'research_source_inputs': pins,
        'network_acquisition': False}))
    environment = {key: value for key, value in os.environ.items() if not key.startswith('GO')}
    environment.update(GOTOOLCHAIN='local', GOWORK='off', GOFLAGS='', GOENV='off', GOPROXY='off', GOSUMDB='off',
                       CGO_ENABLED='0', FILE_HANDOFF_INPUT_PINS=json.dumps(pins, sort_keys=True))
    commands = []

    def execute(label, command, root):
        try:
            result = subprocess.run(command, cwd=root, env=environment, capture_output=True, timeout=240)
            stdout, stderr, code, completed = result.stdout, result.stderr, result.returncode, True
        except subprocess.TimeoutExpired as error:
            stdout, stderr, code, completed = error.stdout or b'', error.stderr or b'', None, False
        SOURCE.seal(args.evidence_directory / (label + '.stdout'), stdout)
        SOURCE.seal(args.evidence_directory / (label + '.stderr'), stderr)
        record = {'label': label, 'completed': completed, 'actual_exit': code,
            'stdout_sha256': hashlib.sha256(stdout).hexdigest(), 'stderr_sha256': hashlib.sha256(stderr).hexdigest()}
        commands.append(record)
        SOURCE.seal(args.evidence_directory / (label + '.json'), SOURCE.encoded(record))
        SOURCE.require(completed and code == 0, 'reference command failed; preserve its evidence')
        return stdout

    with tempfile.TemporaryDirectory(prefix='candidate-file-handoff-') as temporary:
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
        version = execute('go-version', [args.go, 'version'], generator).decode('ascii').strip()
        SOURCE.require(version.startswith('go version go1.25.'), 'select a Go 1.25 toolchain')
        binary = generator / ('file-reference.test.exe' if os.name == 'nt' else 'file-reference.test')
        execute('go-build-tests', [args.go, 'test', '-c', '-mod=readonly', '-trimpath', '-tags',
            'candidate_patch_import,candidate_patch_targets,candidate_patch_file', '-o', str(binary), '.'], generator)
        execute('go-buildinfo', [args.go, 'version', '-m', str(binary)], generator)
        documents = []
        for label in ('generate-first', 'generate-second'):
            stdout = execute(label, [str(binary), '-test.v', '-test.run=^TestFileHandoffReferenceCorpus$'], generator)
            lines = [line[len(b'PATCH_FILE_CORPUS='):] for line in stdout.splitlines() if line.startswith(b'PATCH_FILE_CORPUS=')]
            SOURCE.require(len(lines) == 1 and b'--- PASS: TestFileHandoffReferenceCorpus ' in stdout,
                           'complete reference corpus test did not pass')
            document = json.loads(lines[0])
            CHECK.check_corpus(document)
            documents.append(SOURCE.encoded(document))
        SOURCE.require(documents[0] == documents[1], 'reference file conformance differs')
        controls = execute('borrowed-descriptor-and-raw-ceiling', [str(binary), '-test.v',
            '-test.run=^TestFileHandoff(BorrowedReadOnlyDescriptor|RawCeiling)$'], generator)
        for name in ('TestFileHandoffBorrowedReadOnlyDescriptor', 'TestFileHandoffRawCeiling'):
            SOURCE.require(('--- PASS: ' + name + ' ').encode('ascii') in controls, 'local descriptor/ceiling control did not pass')
        SOURCE.require(SOURCE.snapshot_source(node, manifest['files']) == original, 'copied node source changed')
        SOURCE.require(SOURCE.snapshot_source(args.node_source, manifest['files']) == original, 'selected node source changed')
        SOURCE.require(selected == {name: (HERE / name).read_bytes() for name in CHECK.INPUT_NAMES}, 'research source changed')
        SOURCE.seal(args.output, documents[0])
        SOURCE.seal(args.evidence_directory / 'completed.json', SOURCE.encoded({
            'node_revision': SOURCE.NODE_REVISION, 'node_tree': SOURCE.NODE_TREE, 'matched_source_blobs': 394,
            'go_version': version, 'deterministic_generations': 2, 'cases_per_generation': len(CHECK.inputs()),
            'corpus_sha256': hashlib.sha256(documents[0]).hexdigest(), 'research_source_inputs': pins,
            'source_execution_platform': sys.platform, 'reference_binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
            'commands': commands, 'source_descriptor_lifetime_and_cursor_test_executed': True, 'raw_ceiling_test_executed': True,
            'resource_measurements_executed': False, 'execution_provenance_authenticated': False,
            'runtime_state_proof_acceptance': False}))
    print(json.dumps({'deterministic_generations': 2, 'file_handoff_cases_per_generation': len(CHECK.inputs()),
        'node_blobs': 394, 'production_acceptance_enabled': False}, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError):
        print('Candidate file reference failed; preserve evidence and disabled production acceptance.', file=sys.stderr)
        sys.exit(1)
