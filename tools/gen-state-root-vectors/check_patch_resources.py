#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Bind whole owned research import results and all recorded resource samples.

This unsigned offline oracle rebuilds literal raw bytes and complete maps. It
never executes the Go reference. Recorded Go allocation is cumulative allocation,
not peak memory; process high water includes setup and is sampled before output
binding/serialization. No NodeTree, snapshot, budget or production claim follows.
"""
import argparse
import functools
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('resource_target_oracle', HERE / 'check_patch_targets.py')
TARGET = importlib.util.module_from_spec(spec)
spec.loader.exec_module(TARGET)
IMP, BYTE, DEC = TARGET.IMP, TARGET.BYTE, TARGET.DEC
PEAK_METHOD = ('getrusage(RUSAGE_SELF) immediately after importApply and stats sampling, before output binding; '
    'process lifetime high water includes startup, provenance, resident input, initial binding and pre-operation GC')
SCOPE = {name: True for name in ('synthetic', 'unsigned', 'whole_owned_importApply_measured',
    'actual_NewPatchFromDump_executed', 'default_Batch_Replay_executed', 'initial_and_transient_target_limits_executed',
    'single_exclusive_caller', 'fresh_child_per_sample', 'resident_inputs_before_measurement',
    'variable_resource_samples_separate_from_conformance')}
SCOPE.update({name: False for name in ('fixture_and_report_work_inside_operation_timing',
    'map_clone_deep_copies_string_payloads', 'node_database_opened', 'actual_NodeTree_executed',
    'authenticated_snapshot_import', 'shared_writer_atomicity', 'crash_durability', 'production_resource_budgets_qualified',
    'network_execution', 'full_node_started', 'signing', 'transactions', 'profile_agreed',
    'network_activation_authenticated', 'runtime_state_proof_acceptance')})


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')


def binding(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def records(count, size):
    return b''.join(DEC.record(1, DEC.key(i + 1), bytes([i % 251 + 1]) * size) for i in range(count))


def target(count):
    return {DEC.key(i + 1).hex(): DEC.value(i + 1).hex() for i in range(count)}


def inputs():
    rows = []

    def add(name, raw=b'', count=0, initial=None, caps=None, fault='none'):
        rows.append({'name': name, 'raw': raw, 'limits': IMP.CEILINGS.copy(),
            'selection': {'name': name, 'bytes': len(raw), 'records': count, 'changes_hash': BYTE.digest(raw).hex()},
            'fault': fault, 'target': {} if initial is None else initial, 'target_limits': (caps or TARGET.CEILINGS).copy()})

    add('empty-owned-empty')
    add('records-64-owned-128', records(64, 970), 64, target(128))
    add('records-256-owned-1024', records(256, 970), 256, target(1024))
    add('records-1024-owned-4096', records(1024, 32), 1024, target(4096))
    raw = records(15, 65500) + DEC.record(1, DEC.key(16), b'\x01' * 65484)
    add('raw-ceiling-transient-hex-refusal', raw, 16)
    for count in (4096, 4097):
        add('target-entries-%d-noop' % count, initial={'%08x' % i: '' for i in range(count)})
    add('target-hex-ceiling-noop', initial={'': '00' * (1 << 19)})
    for name in ('put-then-delete', 'delete-then-put'):
        raw, count = TARGET.dump(name)
        add(name, raw, count, IMP.initial(), {'entries': 3, 'hex_bytes': 384})
    add('selection-mismatch-before-clone', records(256, 970), 256, target(1024))
    rows[-1]['selection']['changes_hash'] = '00' * 32
    add('injected-replay-error-complete', records(256, 970), 256, target(1024), fault='replay-error-complete')
    return rows


@functools.lru_cache(maxsize=1)
def expected_document():
    cases = []
    for row in inputs():
        case = TARGET.expected_case(row)
        raw = bytes.fromhex(case.pop('input'))
        case['raw_bytes'], case['raw_sha256'] = len(raw), hashlib.sha256(raw).hexdigest()
        case['source_after_sha256'] = hashlib.sha256(bytes.fromhex(case.pop('source_after'))).hexdigest()
        callbacks = case['staging_callbacks']
        case['staging_callbacks'] = {'count': len(callbacks), 'manifest_sha256': binding(callbacks)}
        cases.append(case)
    return {'format_version': 1, 'kind': 'candidate-patch-import-resource-research',
        'source': {'repository': 'https://github.com/digitalSloth/go-zenon', 'revision': BYTE.NODE_REVISION, 'tree': BYTE.NODE_TREE},
        'scope': SCOPE, 'cases': cases}


def check_corpus(document):
    DEC.RET.exact(document, expected_document())
    cases = document['cases']
    return {'patch_import_resource_cases': len(cases), 'research_imports_staged': sum(not c['refusal'] for c in cases),
        'research_imports_rejected': sum(bool(c['refusal']) for c in cases), 'consumer_refusals': len(cases),
        'complete_original_aliases_bound': len(cases), 'complete_output_and_staging_maps_bound': len(cases),
        'reference_backend_execution_in_checker': False, 'resource_measurements_executed_in_checker': False,
        'actual_NodeTree_execution_in_checker': False, 'production_resource_budgets_qualified': False,
        'authenticated_snapshot_import': False, 'shared_writer_atomicity': False, 'crash_durability': False,
        'profile_agreed': False, 'network_activation_authenticated': False, 'production_acceptance_enabled': False}


def require(condition):
    if not condition:
        raise ValueError('Patch import resource record differs from its selected boundary')


def unsigned(value):
    return type(value) is int and 0 <= value <= (1 << 64) - 1


def hash_string(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None


def check_samples(report, corpus_raw, document):
    check_corpus(document)
    fixed = {'format_version': 1, 'kind': 'candidate-patch-import-resource-samples', 'source': document['source'],
        'corpus_sha256': hashlib.sha256(corpus_raw).hexdigest(), 'conformance_runs': 2,
        'measurement_runs_expected_to_vary': True, 'production_resource_budgets_qualified': False}
    variable = {'source_execution_platform', 'go_version', 'reference_binary_sha256', 'samples', 'commands'}
    require(type(report) is dict and set(report) == set(fixed) | variable)
    DEC.RET.exact({key: report[key] for key in fixed}, fixed)
    platform = report['source_execution_platform']
    require(platform in ('darwin', 'linux'))
    match = re.fullmatch(r'go version (go1\.25\.[0-9]+) (darwin|linux)/(amd64|arm64)', report['go_version'])
    require(match is not None and match[2] == platform and hash_string(report['reference_binary_sha256']))
    require(type(report['commands']) is list and len(report['commands']) == 2)
    for command, label in zip(report['commands'], ('generate-first', 'generate-second')):
        require(type(command) is dict and set(command) == {'label', 'completed', 'actual_exit', 'stdout_sha256', 'stderr_sha256'})
        DEC.RET.exact({key: command[key] for key in ('label', 'completed', 'actual_exit')},
                      {'label': label, 'completed': True, 'actual_exit': 0})
        require(hash_string(command['stdout_sha256']) and hash_string(command['stderr_sha256']))
    require(type(report['samples']) is list and len(report['samples']) == 2)
    inventory = [(case, repetition, mode) for case in document['cases'] for repetition in range(3) for mode in ('plain', 'allocation')]
    fields = {'case', 'mode', 'repetition', 'elapsed_ns', 'go_total_alloc_delta_bytes', 'go_mallocs_delta', 'go_gc_cycles',
        'process_peak_rss_bytes', 'process_peak_rss_method', 'conformance_sha256', 'platform', 'go_version'}
    for run in report['samples']:
        require(type(run) is list and len(run) == len(inventory))
        for sample, (case, repetition, mode) in zip(run, inventory):
            require(type(sample) is dict and set(sample) == fields)
            selected = {'case': case['name'], 'mode': mode, 'repetition': repetition,
                'conformance_sha256': binding(case), 'platform': match[2] + '/' + match[3], 'go_version': match[1],
                'process_peak_rss_method': PEAK_METHOD}
            DEC.RET.exact({key: sample[key] for key in selected}, selected)
            require(unsigned(sample['elapsed_ns']) and sample['elapsed_ns'] > 0)
            require(unsigned(sample['process_peak_rss_bytes']) and sample['process_peak_rss_bytes'] > 0)
            for field in ('go_total_alloc_delta_bytes', 'go_mallocs_delta', 'go_gc_cycles'):
                require(sample[field] is None if mode == 'plain' else unsigned(sample[field]))
    return {'recorded_fresh_child_samples': 2 * len(inventory), 'samples_per_generation': len(inventory),
        'all_samples_and_complete_conformance_bindings_checked': True, 'allocation_metric_is_cumulative_not_peak': True,
        'process_high_water_is_not_operation_allocation': True, 'no_sample_retries_or_filtering_qualified': False,
        'execution_provenance_authenticated': False, 'source_execution_platform': platform,
        'recorded_reference_platform': match[2] + '/' + match[3], 'resource_measurements_executed_in_checker': False,
        'latency_speedup_qualified': False, 'production_resource_budgets_qualified': False, 'production_acceptance_enabled': False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--corpus', type=Path, default=HERE / 'testdata/candidate-patch-import-resources.json')
    parser.add_argument('--samples', type=Path, default=HERE / 'testdata/candidate-patch-import-resource-samples.json')
    parser.add_argument('--source-revision')
    args = parser.parse_args(argv)
    raw, document = BYTE.read_corpus(args.corpus)
    sample_raw, samples = BYTE.read_corpus(args.samples)
    report = check_corpus(document)
    report.update(check_samples(samples, raw, document))
    report.update({'source_revision': args.source_revision, 'corpus_sha256': hashlib.sha256(raw).hexdigest(),
        'samples_sha256': hashlib.sha256(sample_raw).hexdigest(), 'node_revision': BYTE.NODE_REVISION, 'node_tree': BYTE.NODE_TREE})
    print(json.dumps(report, sort_keys=True, separators=(',', ':')))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError):
        print('Candidate patch import resources failed; production acceptance remains disabled.', file=sys.stderr)
        sys.exit(1)
