#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Independently bind selected patch resource inputs and complete plan bytes.

Measurements are observations of synthetic Python planning, never budget approval.
This checker executes no worker, node, database or state proof acceptance.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('resource_import_oracle', HERE / 'check_patch_import.py')
ORACLE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ORACLE)
LIMITS = ORACLE.CEILINGS | {'plan_bytes': 4 << 20}
FAMILIES = [('empty', 'empty', 0), ('records-64', 'records', 64),
            ('records-256', 'records', 256), ('records-1024', 'records', 1024),
            ('maximum-raw-values', 'values', 16), ('maximum-keys', 'keys', 255)]
PLAN_FALSE = ('reference_backend_execution', 'constructor_execution', 'replay_execution',
    'target_replacement', 'database_execution', 'actual_NodeTree_execution',
    'authenticated_snapshot_import', 'snapshot_completeness_qualified', 'typed_state_acceptance',
    'shared_writer_atomicity', 'crash_durability', 'resource_budgets_qualified',
    'accepted_VerifiedState_binding_qualified', 'profile_agreed', 'network_activation_authenticated',
    'canonicality_or_consensus_finality_qualified', 'production_state_proof_acceptance_enabled')
SCOPE = {key: True for key in ('synthetic', 'fresh_worker_process_per_sample',
    'complete_ordered_output_independently_bound', 'worker_operation_elapsed_measured',
    'traced_worker_python_allocation_peak_measured', 'process_peak_includes_startup_and_imports',
    'input_may_be_os_cache_resident')}
SCOPE.update({key: False for key in ('whole_pipeline_memory_measured',
    'parent_input_or_oracle_in_python_trace', 'process_peak_parent_inheritance_excluded',
    'process_peak_is_operation_only',
    'reference_backend_execution', 'node_or_network_execution', 'NodeTree_or_retention_measured',
    'target_import', 'authenticated_snapshot_completeness', 'production_resource_budgets_qualified',
    'accepted_VerifiedState_binding_qualified', 'profile_agreed', 'network_activation_authenticated',
    'production_state_proof_acceptance_enabled', 'canonicality_or_consensus_finality_qualified')})


def exact(actual, expected):
    ORACLE.DEC.RET.exact(actual, expected)


def require(condition):
    if not condition:
        raise ValueError('Patch resource report refused.')


def events(name):
    family, count = next((family, count) for selected, family, count in FAMILIES if selected == name)
    result = []
    for index in range(count):
        if family == 'records':
            key, value = index.to_bytes(2, 'big'), b'v' * 1000
        elif family == 'values':
            key, value = bytes([index]), bytes([index]) * (65536 if index < 15 else 65440)
        else:
            key, value = index.to_bytes(2, 'big') + bytes(4094), b'v'
        result.append({'operation': 'Put', 'key': key.hex(), 'value': value.hex()})
    return result


def reference_raw(name):
    # The existing independent byte oracle spells lengths; no planner is called.
    return b''.join(ORACLE.DEC.record(1, bytes.fromhex(event['key']), bytes.fromhex(event['value']))
                    for event in events(name))


def profiles():
    path = HERE / 'testdata/patch-plan-resource-inputs.json'
    with path.open('rb') as stream:
        raw = stream.read((16 << 10) + 1)
    require(len(raw) <= 16 << 10)
    document = json.loads(raw, object_pairs_hook=ORACLE.BYTE.object_pairs)
    rows = []
    for name, family, count in FAMILIES:
        candidate = reference_raw(name)
        require(len(candidate) <= LIMITS['raw_bytes'])
        rows.append({'name': name, 'family': family, 'record_count': count,
            'raw_bytes': len(candidate), 'changes_hash': hashlib.sha3_256(candidate).hexdigest(),
            'input_sha256': hashlib.sha256(candidate).hexdigest()})
    exact(document, {'format_version': 1, 'kind': 'patch-plan-resource-input-selection', 'cases': rows})
    return rows


def reference_plan(profile, source_revision):
    return {'format_version': 1, 'kind': 'read-only-patch-plan-research',
        'source_revision': source_revision, 'node_revision': ORACLE.BYTE.NODE_REVISION,
        'node_tree': ORACLE.BYTE.NODE_TREE, 'selection': {'bytes': profile['raw_bytes'],
            'records': profile['record_count'], 'changes_hash': profile['changes_hash']},
        'limits': LIMITS.copy(), 'input_sha256': profile['input_sha256'], 'events': events(profile['name']),
        'research_plan_result': 'READY', 'consumer_result': 'REFUSED',
        'scope': {'read_only_unsigned_byte_parsing_executed': True,
            'independently_selected_raw_bytes_required': True, **{key: False for key in PLAN_FALSE}}}


def output_selection(profile, source_revision):
    raw = (json.dumps(reference_plan(profile, source_revision), sort_keys=True, separators=(',', ':')) + '\n').encode('ascii')
    require(len(raw) <= LIMITS['plan_bytes'])
    return {'plan_bytes': len(raw), 'plan_sha256': hashlib.sha256(raw).hexdigest()}


def revision(value):
    require(value is None or (type(value) is str and re.fullmatch(r'[0-9a-f]{40}', value) is not None))


def validate_report(document, selected_revision=None):
    revision(selected_revision)
    rows = profiles()
    fields = {'format_version', 'kind', 'source_revision', 'source_files_sha256', 'runtime',
              'repetitions', 'limits', 'scope', 'measurement_result', 'consumer_result', 'cases'}
    require(type(document) is dict and set(document) == fields)
    exact({k: document[k] for k in ('format_version', 'kind', 'source_revision', 'limits', 'scope',
                                  'measurement_result', 'consumer_result')},
        {'format_version': 1, 'kind': 'read-only-patch-plan-resource-observations',
         'source_revision': selected_revision, 'limits': LIMITS, 'scope': SCOPE,
         'measurement_result': 'OBSERVED', 'consumer_result': 'REFUSED'})
    repetitions = document['repetitions']
    require(type(repetitions) is int and 1 <= repetitions <= 3)
    source_files = ('plan_patch.py', 'measure_patch_plan.py', 'check_patch_plan_resources.py',
                    'testdata/patch-plan-resource-inputs.json')
    exact(document['source_files_sha256'], {name: hashlib.sha256((HERE / name).read_bytes()).hexdigest() for name in source_files})
    runtime = document['runtime']
    require(type(runtime) is dict and set(runtime) == {'os', 'architecture', 'python', 'implementation'})
    require(runtime['os'] in ('linux', 'darwin', 'windows') and runtime['architecture'] in ('amd64', 'arm64'))
    require(type(runtime['python']) is str and re.fullmatch(r'[0-9]{1,2}\.[0-9]{1,2}\.[0-9]{1,2}', runtime['python']) is not None)
    exact(runtime['implementation'], 'CPython')
    require(type(document['cases']) is list and len(document['cases']) == len(rows))
    for case, profile in zip(document['cases'], rows):
        expected = profile | output_selection(profile, selected_revision)
        require(type(case) is dict and set(case) == set(expected) | {'samples'})
        exact({key: case[key] for key in expected}, expected)
        require(type(case['samples']) is list and len(case['samples']) == repetitions * 2)
        for sample, (number, traced) in zip(case['samples'], [(n, mode) for n in range(1, repetitions + 1) for mode in (False, True)]):
            wanted = {'repetition': number, 'traced': traced,
                      **{key: expected[key] for key in ('plan_bytes', 'plan_sha256')},
                      'consumer_result': 'REFUSED'}
            require(type(sample) is dict and set(sample) == set(wanted) | {'elapsed_ns', 'python_traced_peak_bytes', 'process_peak_memory'})
            exact({key: sample[key] for key in wanted}, wanted)
            require(type(sample['elapsed_ns']) is int and 0 < sample['elapsed_ns'] < 1 << 63)
            peak = sample['python_traced_peak_bytes']
            require((type(peak) is int and 0 < peak < 1 << 63) if traced else peak is None)
            memory = sample['process_peak_memory']
            require(type(memory) is dict and set(memory) == {'bytes', 'metric', 'available'})
            require(type(memory['available']) is bool)
            if memory['available']:
                require(type(memory['bytes']) is int and 0 < memory['bytes'] < 1 << 63)
                exact(memory['metric'], 'peak_working_set_bytes' if runtime['os'] == 'windows' else 'process_peak_rss_bytes')
            else:
                exact(memory, {'bytes': None, 'metric': 'unavailable', 'available': False})
    return {'profiles': len(rows), 'fresh_worker_samples': len(rows) * repetitions * 2,
            'max_selected_raw_bytes': max(r['raw_bytes'] for r in rows),
            'max_selected_records': max(r['record_count'] for r in rows),
            'all_complete_plan_bytes_bound': True, 'production_budget_qualified': False,
            'NodeTree_or_retention_measured': False, 'consumer_result': 'REFUSED'}


class PrivateParser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError('Patch resource arguments refused.')


def main():
    parser = PrivateParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--report', required=True, type=Path)
    parser.add_argument('--source-revision')
    args = parser.parse_args()
    with args.report.open('rb') as stream:
        raw = stream.read((64 << 10) + 1)
    require(len(raw) <= 64 << 10)
    document = json.loads(raw, object_pairs_hook=ORACLE.BYTE.object_pairs)
    report = validate_report(document, args.source_revision)
    report['report_sha256'] = hashlib.sha256(raw).hexdigest()
    print(json.dumps(report, sort_keys=True, separators=(',', ':')))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, TypeError, KeyError, OSError, StopIteration):
        print('Patch resource conformance refused; production acceptance remains disabled.', file=sys.stderr)
        sys.exit(1)
