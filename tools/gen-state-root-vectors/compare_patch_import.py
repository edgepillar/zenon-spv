#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Compare whole owned research imports against one fixed prior source, offline.

Every generation uses 72 fresh children. Preserve both complete outputs, every
child outcome and all samples. This is unsigned local engineering evidence, not
an authenticated benchmark, speedup, memory budget or production qualification.
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
spec = importlib.util.spec_from_file_location('import_comparison_check', HERE / 'check_patch_import_comparison.py')
CHECK = importlib.util.module_from_spec(spec)
spec.loader.exec_module(CHECK)
spec = importlib.util.spec_from_file_location('import_comparison_source', HERE / 'regenerate.py')
SOURCE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(SOURCE)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--node-source', type=Path, required=True)
    parser.add_argument('--baseline-import-source', type=Path, required=True)
    parser.add_argument('--go', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--evidence-directory', type=Path, required=True)
    args = parser.parse_args(argv)
    SOURCE.require(sys.platform in ('darwin', 'linux'), 'resource reference requires Linux or macOS')
    for path in (args.output, args.evidence_directory):
        SOURCE.require(not path.exists() and not path.is_symlink(), 'preserve existing output and evidence')
    SOURCE.require(args.baseline_import_source.is_file() and not args.baseline_import_source.is_symlink(), 'expected regular selected baseline')
    with args.baseline_import_source.open('rb') as stream:
        baseline = stream.read(CHECK.BASELINE['bytes'] + 1)
    SOURCE.require(len(baseline) == CHECK.BASELINE['bytes'] and hashlib.sha256(baseline).hexdigest() == CHECK.BASELINE['sha256'], 'unselected baseline refused')
    SOURCE.require(SOURCE.git_hash('blob', baseline) == CHECK.BASELINE['git_blob'], 'baseline Git blob differs')
    _, manifest = SOURCE.source_manifest()
    original = SOURCE.snapshot_source(args.node_source, manifest['files'])
    selected = {name: (HERE / name).read_bytes() for name in CHECK.INPUT_NAMES}
    SOURCE.require(selected['patch_import.go'] != baseline, 'candidate equals prior source')
    args.evidence_directory.mkdir(mode=0o700)
    SOURCE.seal(args.evidence_directory / 'baseline-patch-import.go', baseline)
    environment = {key: value for key, value in os.environ.items() if not key.startswith('GO')}
    environment.update(GOTOOLCHAIN='local', GOWORK='off', GOFLAGS='', GOENV='off', GOPROXY='off', GOSUMDB='off', CGO_ENABLED='0')
    tags = 'candidate_patch_import,candidate_patch_targets,candidate_patch_resources'
    reports, corpora, controls = {}, {}, {}
    with tempfile.TemporaryDirectory(prefix='owned-import-comparison-') as temporary:
        root = Path(temporary)
        node = root / 'reference-node'
        node.mkdir()
        for name, raw in original.items():
            path = node / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
            path.chmod(0o755 if manifest['files'][name]['mode'] == '100755' else 0o644)
        for role in ('baseline', 'candidate'):
            generator = root / role
            generator.mkdir()
            evidence = args.evidence_directory / role
            evidence.mkdir(mode=0o700)
            for name in CHECK.BUILD_NAMES:
                (generator / name).write_bytes(baseline if name == 'patch_import.go' and role == 'baseline' else selected[name])
            with (generator / 'go.mod').open('ab') as stream:
                stream.write(b'\nreplace github.com/zenon-network/go-zenon => ../reference-node\n')
            commands = []

            def execute(label, command):
                try:
                    result = subprocess.run(command, cwd=generator, env=environment, capture_output=True, timeout=240)
                    out, err, code, completed = result.stdout, result.stderr, result.returncode, True
                except subprocess.TimeoutExpired as error:
                    out, err, code, completed = error.stdout or b'', error.stderr or b'', None, False
                SOURCE.seal(evidence / (label + '.stdout'), out)
                SOURCE.seal(evidence / (label + '.stderr'), err)
                record = {'label': label, 'completed': completed, 'actual_exit': code,
                    'stdout_sha256': hashlib.sha256(out).hexdigest(), 'stderr_sha256': hashlib.sha256(err).hexdigest()}
                SOURCE.seal(evidence / (label + '.json'), SOURCE.encoded(record))
                commands.append(record)
                SOURCE.require(completed and code == 0, 'reference failed; preserve actual outcome and earlier samples')
                return out

            version = execute('go-version', [args.go, 'version']).decode('ascii').strip()
            SOURCE.require(version.startswith('go version go1.25.'), 'select Go 1.25')
            test_output = execute('go-ownership-controls', [args.go, 'test', '-mod=readonly', '-tags', tags, '-count=1', '-json', '.'])
            test_events = [json.loads(line) for line in test_output.splitlines()]
            passed = sorted(event['Test'] for event in test_events if event['Action'] == 'pass' and 'Test' in event)
            SOURCE.require(passed == CHECK.OWNERSHIP_TESTS and not any(event['Action'] == 'fail' for event in test_events), 'ownership control inventory differs')
            controls[role] = {'tests': passed, 'command': commands[-1]}
            executable = generator / 'reference-generator'
            execute('go-build', [args.go, 'build', '-mod=readonly', '-trimpath', '-tags', tags, '-o', str(executable), '.'])
            execute('go-buildinfo', [args.go, 'version', '-m', str(executable)])
            command = [str(executable), '--verified-node-tree', SOURCE.NODE_TREE, '--fixture-kind', 'patch-resources']
            documents = [json.loads(execute(label, command)) for label in ('generate-first', 'generate-second')]
            samples = [document.pop('measurements') for document in documents]
            raw = [SOURCE.encoded(document) for document in documents]
            SOURCE.require(raw[0] == raw[1], 'complete reference conformance differs between generations')
            corpora[role] = raw[0]
            SOURCE.seal(evidence / 'corpus.json', raw[0])
            reports[role] = {'format_version': 1, 'kind': 'candidate-patch-import-resource-samples',
                'source': documents[0]['source'], 'corpus_sha256': hashlib.sha256(raw[0]).hexdigest(),
                'conformance_runs': 2, 'measurement_runs_expected_to_vary': True, 'production_resource_budgets_qualified': False,
                'source_execution_platform': sys.platform, 'go_version': version,
                'reference_binary_sha256': hashlib.sha256(executable.read_bytes()).hexdigest(), 'samples': samples, 'commands': commands[-2:]}
            SOURCE.seal(evidence / 'samples.json', SOURCE.encoded(reports[role]))
        SOURCE.require(SOURCE.snapshot_source(node, manifest['files']) == original, 'copied node source changed')
    SOURCE.require(SOURCE.snapshot_source(args.node_source, manifest['files']) == original, 'selected node source changed')
    SOURCE.require(all((HERE / name).read_bytes() == raw for name, raw in selected.items()), 'selected harness changed')
    SOURCE.require(corpora['baseline'] == corpora['candidate'] == (HERE / 'testdata/candidate-patch-import-resources.json').read_bytes(), 'complete comparison conformance differs')
    report = {'format_version': 1, 'kind': 'owned-patch-import-source-comparison', 'baseline_source': CHECK.BASELINE,
        'selected_input_pins': CHECK.input_pins(), 'corpus_sha256': hashlib.sha256(corpora['candidate']).hexdigest(),
        'scope': CHECK.SCOPE, 'execution_order': ['baseline-first', 'baseline-second', 'candidate-first', 'candidate-second'],
        'ownership_controls': controls, 'reports': reports}
    CHECK.check(report)
    SOURCE.seal(args.output, SOURCE.encoded(report))
    print(json.dumps({'recorded_fresh_children': 288, 'local_Go_ownership_controls': 36,
        'all_selected_conformance_equal': True, 'production_acceptance_enabled': False}, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError):
        print('Owned patch import comparison failed; preserve evidence; production acceptance remains disabled.', file=sys.stderr)
        sys.exit(1)
