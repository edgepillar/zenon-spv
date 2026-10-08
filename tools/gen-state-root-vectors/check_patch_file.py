#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Check opened-file handoff observations with an independent finite byte oracle.

No Go reference, file import, database, network or resource measurement executes.
Recorded file/source outcomes and source hashes are unsigned engineering data.
"""
import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('file_target_oracle', HERE / 'check_patch_targets.py')
TARGET = importlib.util.module_from_spec(spec)
spec.loader.exec_module(TARGET)
IMP, BYTE, DEC = TARGET.IMP, TARGET.BYTE, TARGET.DEC
BUILD_NAMES = ('main.go', 'go.mod', 'go.sum', 'patch_decode.go', 'patch_import.go', 'patch_targets.go',
               'patch_file.go', 'patch_file_test.go')
INPUT_NAMES = BUILD_NAMES + ('source-pins.json', 'regenerate.py', 'reproduce_patch_file.py', 'check_patch_file.py',
                             'check_patch_targets.py', 'check_patch_import.py', 'check_patch_decode.py')
SOURCE_FAULTS = ('nil-source', 'closed-source', 'directory-source', 'stat-error', 'nil-stat-info', 'negative-size',
    'second-stat-error', 'read-error', 'negative-read-count', 'excess-read-count', 'short-eof-read',
    'grow-before-read', 'shrink-before-read', 'grow-after-read', 'shrink-after-read', 'same-size-mutation')
SCOPE = {name: True for name in ('synthetic', 'unsigned', 'owned_temporary_regular_files', 'opened_file_descriptor_handoff',
    'positional_read_at_zero', 'selected_count_plus_one_read_bound', 'actual_NewPatchFromDump_executed',
    'default_Batch_Replay_executed', 'source_and_replay_faults_injected', 'complete_map_and_original_alias_bindings', 'single_exclusive_caller')}
SCOPE.update({name: False for name in ('path_opener_added', 'atomic_filesystem_snapshot', 'shared_writer_atomicity', 'crash_durability',
    'authenticated_snapshot_import', 'actual_NodeTree_executed', 'node_database_opened', 'resource_measurements_executed',
    'network_execution', 'full_node_started', 'signing', 'transactions', 'profile_agreed', 'network_activation_authenticated',
    'execution_provenance_authenticated', 'runtime_state_proof_acceptance')})


def input_pins():
    return {name: hashlib.sha256((HERE / name).read_bytes()).hexdigest() for name in INPUT_NAMES}


def inputs():
    rows = [row | {'source_fault': 'none'} for row in TARGET.inputs()]
    base = TARGET.inputs()[0]
    for fault in SOURCE_FAULTS:
        rows.append(copy.deepcopy(base) | {'name': 'source-' + fault, 'source_fault': fault})
    for fault in ('wrong-byte-count', 'wrong-record-count', 'selection-over-cap', 'selection-uint64-max', 'file-over-cap'):
        row = copy.deepcopy(base) | {'name': fault, 'source_fault': 'none'}
        if fault == 'wrong-byte-count': row['selection']['bytes'] -= 1
        if fault == 'wrong-record-count': row['selection']['records'] -= 1
        if fault == 'selection-over-cap': row['selection']['bytes'] = row['limits']['raw_bytes'] + 1
        if fault == 'selection-uint64-max': row['selection']['bytes'] = (1 << 64) - 1
        if fault == 'file-over-cap': row['raw'] = b'\0' * ((1 << 20) + 1)
        rows.append(row)
    return rows


def expected_case(row):
    raw, limits, chosen, fault, target = (row[n] for n in ('raw', 'limits', 'selection', 'source_fault', 'target'))
    after = raw
    stats = reads = buffer_size = read_size = 0
    refusal = ''
    if any(not 0 < limits[field] <= cap for field, cap in IMP.CEILINGS.items()): refusal = 'invalid_limits'
    elif chosen['bytes'] > limits['raw_bytes']: refusal = 'file_selection_limit'
    else: refusal = TARGET.target_refusal(target, row['target_limits'])
    if not refusal:
        if fault == 'nil-source': refusal = 'file_stat_error'
        else:
            stats = 1
            if fault in ('closed-source', 'stat-error', 'nil-stat-info'): refusal = 'file_stat_error'
            elif fault in ('directory-source', 'negative-size'): refusal = 'file_not_regular'
            elif len(raw) > limits['raw_bytes']: refusal = 'file_size_limit'
            elif len(raw) != chosen['bytes']: refusal = 'file_selection_size'
    if not refusal:
        reads, buffer_size, read_size = 1, chosen['bytes'] + 1, len(raw)
        if fault == 'grow-before-read': after, read_size = raw + b'\x02', len(raw) + 1
        if fault == 'shrink-before-read': after, read_size = raw[:-1], len(raw) - 1
        if fault == 'same-size-mutation': after = raw[:66] + b'\x5a' + raw[67:]
        if fault in ('read-error', 'short-eof-read'): read_size = 1
        if fault in ('negative-read-count', 'excess-read-count'): read_size = 0
        if fault in ('read-error', 'negative-read-count', 'excess-read-count'): refusal = 'file_read_error'
        elif read_size != chosen['bytes']: refusal = 'file_read_size'
        else:
            stats = 2
            if fault == 'second-stat-error': refusal = 'file_stat_error'
            if fault == 'grow-after-read': after, refusal = raw + b'\x02', 'file_changed_size'
            if fault == 'shrink-after-read': after, refusal = raw[:-1], 'file_changed_size'
    if refusal:
        imported = {'raw_copies': 0, 'constructor_calls': 0, 'target_clone_calls': 0, 'target_cloned_entries': 0,
            'default_replay_calls': 0, 'preflight_records': 0, 'staging_callbacks': [], 'target_before': TARGET.summary(target),
            'original_alias_after': TARGET.summary(target), 'staging_target': TARGET.summary({}), 'target_after': TARGET.summary(target),
            'target_replacements': 0, 'research_import_result': 'REJECTED', 'refusal': refusal, 'consumer_result': 'REFUSED'}
    else:
        imported = TARGET.expected_case(row | {'raw': after})
        for field in ('name', 'input', 'source_after', 'limits', 'selection', 'target_limits', 'injected_fault'):
            imported.pop(field, None)
    cursor = fault not in ('nil-source', 'closed-source', 'directory-source')
    return imported | {'name': row['name'], 'source_fault': fault, 'import_fault': row['fault'], 'limits': limits,
        'selection': chosen, 'target_limits': row['target_limits'], 'file_before_bytes': len(raw),
        'file_before_sha256': hashlib.sha256(raw).hexdigest(), 'file_after_bytes': len(after), 'file_after_sha256': hashlib.sha256(after).hexdigest(),
        'file_stat_calls': stats, 'file_read_calls': reads, 'file_buffer_bytes': buffer_size, 'file_read_bytes': read_size,
        'source_cursor_available': cursor, 'source_cursor_preserved': cursor}


def expected_document():
    return {'format_version': 1, 'kind': 'candidate-patch-file-handoff-research',
        'source': {'repository': 'https://github.com/digitalSloth/go-zenon', 'revision': BYTE.NODE_REVISION, 'tree': BYTE.NODE_TREE},
        'scope': SCOPE, 'research_source_inputs': input_pins(), 'cases': [expected_case(row) for row in inputs()]}


def check_corpus(document):
    expected = expected_document()
    DEC.RET.exact(document, expected)
    rows = expected['cases']
    return {'patch_file_cases': len(rows), 'reused_target_cases': len(TARGET.inputs()),
        'research_imports_staged': sum(not row['refusal'] for row in rows), 'research_imports_rejected': sum(bool(row['refusal']) for row in rows),
        'original_aliases_unchanged': len(rows), 'consumer_refusals': len(rows),
        'read_bound_maximum': max(row['file_buffer_bytes'] for row in rows),
        'research_source_inputs_bound': len(INPUT_NAMES), 'reference_backend_execution_in_checker': False,
        'file_handoff_executed_in_checker': False, 'resource_measurements_executed_in_checker': False,
        'execution_provenance_authenticated': False, 'atomic_filesystem_snapshot': False,
        'authenticated_snapshot_import': False, 'production_acceptance_enabled': False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--corpus', type=Path, default=HERE / 'testdata/candidate-patch-file.json')
    parser.add_argument('--source-revision')
    args = parser.parse_args(argv)
    if args.source_revision is not None:
        BYTE.require(len(args.source_revision) == 40 and all(c in '0123456789abcdef' for c in args.source_revision), 'invalid source revision')
    raw, document = BYTE.read_corpus(args.corpus)
    report = check_corpus(document)
    report.update(corpus_sha256=hashlib.sha256(raw).hexdigest(), source_revision=args.source_revision,
                  node_revision=BYTE.NODE_REVISION, node_tree=BYTE.NODE_TREE)
    print(json.dumps(report, sort_keys=True, separators=(',', ':')))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError):
        print('Candidate file handoff conformance failed; production acceptance remains disabled.', file=sys.stderr)
        sys.exit(1)
