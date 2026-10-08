#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Check a fixed prior/candidate whole-import comparison without executing Go."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('import_comparison_resources', HERE / 'check_patch_resources.py')
RESOURCE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(RESOURCE)
BASELINE = {'repository': 'https://github.com/edgepillar/zenon-spv',
    'revision': '02b3a36410f53d879ca5dd1d21bb3c3d0c8c1b73',
    'path': 'tools/gen-state-root-vectors/patch_import.go', 'git_blob': 'ff426a7c2ffc4604f89f888a382c0c503631023a',
    'sha256': '58de0d2014028cb41412794e16df95f484f1d5d5c0d6de95ac5a3c0946c83ad8', 'bytes': 17013}
BUILD_NAMES = ('main.go', 'go.mod', 'go.sum', 'patch_decode.go', 'patch_import.go', 'patch_targets.go',
    'patch_resources.go', 'patch_import_ownership_test.go')
INPUT_NAMES = BUILD_NAMES + ('source-pins.json', 'regenerate.py', 'compare_patch_import.py',
    'check_patch_import_comparison.py', 'check_patch_import_comparison_test.py')
OWNERSHIP_TESTS = sorted(['TestCallbackDetachedBytesAndMetadata', 'TestCallbackEmptyPutAndDeleteRemainDistinct',
    'TestCallbackMismatchRecordsActualBytes', 'TestCallbackExtraAndTransientRefusalPreserveState'] +
    ['TestCallbackMismatchRecordsActualBytes/' + name for name in ('key-high-nibble', 'key-low-nibble', 'key-length',
        'value-high-nibble', 'value-low-nibble', 'value-length', 'put-for-delete', 'delete-for-put', 'delete-key', 'uppercase-plan', 'odd-plan')] +
    ['TestCallbackExtraAndTransientRefusalPreserveState/' + name for name in ('callback_mismatch', 'target_entry_limit', 'target_hex_limit')])
SCOPE = {name: True for name in ('synthetic', 'unsigned', 'whole_owned_importApply_measured', 'fixed_prior_import_source',
    'same_selected_resource_harness', 'complete_original_staging_output_and_callback_bindings',
    'single_exclusive_caller', 'all_recorded_samples_selected', 'variable_samples_separate_from_conformance')}
SCOPE.update({name: False for name in ('execution_provenance_authenticated', 'resource_measurements_executed_in_checker',
    'no_retries_or_filtering_authenticated', 'latency_speedup_qualified', 'production_resource_budgets_qualified',
    'actual_NodeTree_executed', 'authenticated_snapshot_import', 'shared_writer_atomicity', 'crash_durability',
    'network_execution', 'runtime_state_proof_acceptance')})


def input_pins():
    return {name: {'bytes': len((HERE / name).read_bytes()), 'sha256': hashlib.sha256((HERE / name).read_bytes()).hexdigest()}
            for name in INPUT_NAMES}


def check(document):
    raw, corpus = RESOURCE.BYTE.read_corpus(HERE / 'testdata/candidate-patch-import-resources.json')
    fixed = {'format_version': 1, 'kind': 'owned-patch-import-source-comparison', 'baseline_source': BASELINE,
        'selected_input_pins': input_pins(), 'corpus_sha256': hashlib.sha256(raw).hexdigest(), 'scope': SCOPE,
        'execution_order': ['baseline-first', 'baseline-second', 'candidate-first', 'candidate-second']}
    RESOURCE.require(type(document) is dict and set(document) == set(fixed) | {'reports', 'ownership_controls'})
    RESOURCE.DEC.RET.exact({key: document[key] for key in fixed}, fixed)
    reports, controls = document['reports'], document['ownership_controls']
    RESOURCE.require(type(reports) is dict and set(reports) == {'baseline', 'candidate'})
    RESOURCE.require(type(controls) is dict and set(controls) == {'baseline', 'candidate'})
    for role in ('baseline', 'candidate'):
        RESOURCE.check_samples(reports[role], raw, corpus)
        control = controls[role]
        RESOURCE.require(type(control) is dict and set(control) == {'tests', 'command'})
        RESOURCE.DEC.RET.exact(control['tests'], OWNERSHIP_TESTS)
        command = control['command']
        RESOURCE.require(type(command) is dict and set(command) == {'label', 'completed', 'actual_exit', 'stdout_sha256', 'stderr_sha256'})
        RESOURCE.DEC.RET.exact({key: command[key] for key in ('label', 'completed', 'actual_exit')},
            {'label': 'go-ownership-controls', 'completed': True, 'actual_exit': 0})
        RESOURCE.require(RESOURCE.hash_string(command['stdout_sha256']) and RESOURCE.hash_string(command['stderr_sha256']))
    for key in ('source_execution_platform', 'go_version', 'corpus_sha256', 'source'):
        RESOURCE.DEC.RET.exact(reports['baseline'][key], reports['candidate'][key])
    RESOURCE.require(reports['baseline']['reference_binary_sha256'] != reports['candidate']['reference_binary_sha256'])
    RESOURCE.require(document['selected_input_pins']['patch_import.go']['sha256'] != BASELINE['sha256'])
    return {'comparison_families': len(corpus['cases']), 'recorded_fresh_child_samples': 288,
        'recorded_local_Go_ownership_controls': 2 * len(OWNERSHIP_TESTS),
        'complete_prior_and_candidate_bindings_equal': True, 'selected_harness_and_importer_inputs_bound': len(INPUT_NAMES),
        'recorded_reference_platform': reports['candidate']['samples'][0][0]['platform'],
        'reference_backend_execution_in_checker': False, 'resource_measurements_executed_in_checker': False,
        'execution_provenance_authenticated': False, 'latency_speedup_qualified': False,
        'production_resource_budgets_qualified': False, 'production_acceptance_enabled': False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--comparison', type=Path, default=HERE / 'testdata/candidate-patch-import-comparison.json')
    parser.add_argument('--source-revision')
    args = parser.parse_args(argv)
    raw, document = RESOURCE.BYTE.read_corpus(args.comparison)
    report = check(document)
    report.update(source_revision=args.source_revision, comparison_sha256=hashlib.sha256(raw).hexdigest(),
        baseline_revision=BASELINE['revision'], node_revision=RESOURCE.BYTE.NODE_REVISION, node_tree=RESOURCE.BYTE.NODE_TREE)
    print(json.dumps(report, sort_keys=True, separators=(',', ':')))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError):
        print('Owned patch import comparison failed; production acceptance remains disabled.', file=sys.stderr)
        sys.exit(1)
