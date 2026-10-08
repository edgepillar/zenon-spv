#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Bind unsigned whole opened-file handoff observations without reference execution.

Literal raw/count/digest and complete maps are independently reconstructed. Every
recorded sample stays bound, including refusals; elapsed time, cumulative Go
allocation and process lifetime RSS are distinct variable observations. No cold
disk, NodeTree, durability, authenticated snapshot or production budget follows.
"""
import argparse
import copy
import functools
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys

HERE = Path(__file__).resolve().parent


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, HERE / file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


FILE = load('file_resource_file_oracle', 'check_patch_file.py')
RESOURCE = load('file_resource_input_oracle', 'check_patch_resources.py')
BYTE, DEC = FILE.BYTE, FILE.DEC
BUILD_NAMES = ('main.go', 'go.mod', 'go.sum', 'patch_decode.go', 'patch_import.go', 'patch_targets.go',
               'patch_resources.go', 'patch_file.go', 'patch_file_resources_test.go')
INPUT_NAMES = BUILD_NAMES + ('source-pins.json', 'regenerate.py', 'reproduce_patch_file_resources.py',
    'check_patch_file_resources.py', 'check_patch_file.py', 'check_patch_resources.py',
    'check_patch_targets.py', 'check_patch_import.py', 'check_patch_decode.py')
PEAK_METHOD = ('getrusage(RUSAGE_SELF) after importFileApply and stats sampling, before output binding; '
    'process lifetime high water includes startup, fixture creation, file open, initial binding and pre-operation GC')
SCOPE = {name: True for name in ('synthetic', 'unsigned', 'whole_opened_file_importFileApply_measured',
    'owned_temporary_regular_files', 'borrowed_read_only_descriptor', 'caller_source_stability_required',
    'single_exclusive_caller', 'fresh_child_per_sample', 'actual_NewPatchFromDump_executed',
    'default_Batch_Replay_executed', 'complete_map_and_original_alias_bindings',
    'variable_resource_samples_separate_from_conformance')}
SCOPE.update({name: False for name in ('path_open_and_fixture_work_inside_operation_timing',
    'output_binding_and_report_work_inside_operation_timing', 'resident_raw_passed_to_handoff',
    'cold_disk_behavior_qualified', 'atomic_filesystem_snapshot', 'shared_writer_atomicity', 'crash_durability',
    'authenticated_snapshot_import', 'actual_NodeTree_executed', 'node_database_opened',
    'production_resource_budgets_qualified', 'latency_speedup_qualified', 'network_execution', 'full_node_started',
    'signing', 'transactions', 'profile_agreed', 'network_activation_authenticated',
    'execution_provenance_authenticated', 'runtime_state_proof_acceptance')})


def input_pins():
    return {name: hashlib.sha256((HERE / name).read_bytes()).hexdigest() for name in INPUT_NAMES}


def inputs():
    rows = [copy.deepcopy(row) | {'source_fault': 'none'} for row in RESOURCE.inputs()]
    base = next(row for row in rows if row['name'] == 'records-256-owned-1024')
    for name in ('file-wrong-byte-count', 'file-over-raw-cap', 'file-selection-over-cap'):
        row = copy.deepcopy(base)
        row['name'] = row['selection']['name'] = name
        if name == 'file-wrong-byte-count': row['selection']['bytes'] -= 1
        if name == 'file-over-raw-cap': row['raw'] = b'\0' * ((1 << 20) + 1)
        if name == 'file-selection-over-cap': row['selection']['bytes'] = (1 << 20) + 1
        rows.append(row)
    return rows


@functools.lru_cache(maxsize=1)
def expected_document():
    cases = []
    for row in inputs():
        case = FILE.expected_case(row)
        callbacks = case['staging_callbacks']
        case['staging_callbacks'] = {'count': len(callbacks), 'manifest_sha256': RESOURCE.binding(callbacks)}
        cases.append(case)
    return {'format_version': 1, 'kind': 'candidate-patch-file-resource-research',
        'source': {'repository': 'https://github.com/digitalSloth/go-zenon', 'revision': BYTE.NODE_REVISION, 'tree': BYTE.NODE_TREE},
        'scope': SCOPE, 'research_source_inputs': input_pins(), 'cases': cases}


def check_corpus(document):
    DEC.RET.exact(document, expected_document())
    cases = document['cases']
    return {'patch_file_resource_cases': len(cases), 'research_imports_staged': sum(not c['refusal'] for c in cases),
        'research_imports_rejected': sum(bool(c['refusal']) for c in cases), 'consumer_refusals': len(cases),
        'complete_original_aliases_bound': len(cases), 'research_source_inputs_bound': len(INPUT_NAMES),
        'file_read_bound_maximum': max(c['file_buffer_bytes'] for c in cases),
        'file_handoff_executed_in_checker': False, 'resource_measurements_executed_in_checker': False,
        'production_resource_budgets_qualified': False, 'production_acceptance_enabled': False}


def require(condition):
    if not condition:
        raise ValueError('File resource evidence differs from its selected boundary')


def inventory(document):
    return [(case, repetition, mode) for case in document['cases'] for repetition in range(3) for mode in ('plain', 'allocation')]


def check_samples(report, corpus_raw, document):
    check_corpus(document)
    fixed = {'format_version': 1, 'kind': 'candidate-patch-file-resource-samples', 'source': document['source'],
        'corpus_sha256': hashlib.sha256(corpus_raw).hexdigest(), 'conformance_runs': 2,
        'measurement_runs_expected_to_vary': True, 'production_resource_budgets_qualified': False}
    variable = {'source_execution_platform', 'go_version', 'reference_binary_sha256', 'samples', 'commands'}
    require(type(report) is dict and set(report) == set(fixed) | variable)
    DEC.RET.exact({key: report[key] for key in fixed}, fixed)
    match = re.fullmatch(r'go version (go1\.25\.[0-9]+) (darwin|linux)/(amd64|arm64)', report['go_version'])
    require(match is not None and report['source_execution_platform'] == match[2])
    require(RESOURCE.hash_string(report['reference_binary_sha256']))
    require(type(report['samples']) is list and len(report['samples']) == 2)
    require(type(report['commands']) is list and len(report['commands']) == 2)
    wanted = inventory(document)
    fields = {'case', 'mode', 'repetition', 'elapsed_ns', 'go_total_alloc_delta_bytes', 'go_mallocs_delta', 'go_gc_cycles',
        'process_peak_rss_bytes', 'process_peak_rss_method', 'conformance_sha256', 'platform', 'go_version'}
    for generation, (run, commands) in enumerate(zip(report['samples'], report['commands'])):
        require(type(run) is list and type(commands) is list and len(run) == len(commands) == len(wanted))
        for sample, command, (case, repetition, mode) in zip(run, commands, wanted):
            require(type(sample) is dict and set(sample) == fields)
            selected = {'case': case['name'], 'mode': mode, 'repetition': repetition, 'conformance_sha256': RESOURCE.binding(case),
                'platform': match[2] + '/' + match[3], 'go_version': match[1], 'process_peak_rss_method': PEAK_METHOD}
            DEC.RET.exact({key: sample[key] for key in selected}, selected)
            for field in ('elapsed_ns', 'process_peak_rss_bytes'):
                require(RESOURCE.unsigned(sample[field]) and sample[field] > 0)
            for field in ('go_total_alloc_delta_bytes', 'go_mallocs_delta', 'go_gc_cycles'):
                require(sample[field] is None if mode == 'plain' else RESOURCE.unsigned(sample[field]))
            fields_command = {'label', 'completed', 'actual_exit', 'stdout_sha256', 'stderr_sha256', 'result_sha256'}
            require(type(command) is dict and set(command) == fields_command)
            DEC.RET.exact({key: command[key] for key in ('label', 'completed', 'actual_exit', 'result_sha256')},
                {'label': '%d-%s-%d-%s' % (generation, case['name'], repetition, mode), 'completed': True, 'actual_exit': 0,
                 'result_sha256': RESOURCE.binding({'conformance': case, 'measurement': sample})})
            require(RESOURCE.hash_string(command['stdout_sha256']) and command['stderr_sha256'] == hashlib.sha256(b'').hexdigest())
    return {'recorded_fresh_child_samples': 2 * len(wanted), 'samples_per_generation': len(wanted),
        'all_samples_and_command_outcomes_bound': True, 'allocation_metric_is_cumulative_not_peak': True,
        'process_high_water_is_not_operation_allocation': True, 'execution_provenance_authenticated': False,
        'recorded_reference_platform': match[2] + '/' + match[3], 'resource_measurements_executed_in_checker': False,
        'cold_disk_behavior_qualified': False, 'latency_speedup_qualified': False, 'production_acceptance_enabled': False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--corpus', type=Path, default=HERE / 'testdata/candidate-patch-file-resources.json')
    parser.add_argument('--samples', type=Path, default=HERE / 'testdata/candidate-patch-file-resource-samples.json')
    parser.add_argument('--source-revision')
    args = parser.parse_args(argv)
    require(args.source_revision is None or re.fullmatch('[0-9a-f]{40}', args.source_revision) is not None)
    raw, document = BYTE.read_corpus(args.corpus)
    sample_raw, samples = BYTE.read_corpus(args.samples)
    report = check_corpus(document) | check_samples(samples, raw, document)
    report.update(source_revision=args.source_revision, corpus_sha256=hashlib.sha256(raw).hexdigest(),
        samples_sha256=hashlib.sha256(sample_raw).hexdigest(), node_revision=BYTE.NODE_REVISION, node_tree=BYTE.NODE_TREE)
    print(json.dumps(report, sort_keys=True, separators=(',', ':')))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError):
        print('Candidate file resource evidence failed; production acceptance remains disabled.', file=sys.stderr)
        sys.exit(1)
