#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Check a bounded research import contract with independent unsigned byte parsing.

No Go reference, node database, network or production state acceptance executes.
Only the independently selected finite dump spelling and owned map are bound.
"""
import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('patch_import_decode_oracle', HERE / 'check_patch_decode.py')
DEC = importlib.util.module_from_spec(spec)
spec.loader.exec_module(DEC)
BYTE = DEC.BYTE
CEILINGS = dict(zip(('raw_bytes', 'records', 'key_bytes', 'value_bytes'), (1 << 20, 1024, 4096, 65536)))
DEFAULTS = dict(zip(CEILINGS, (1024, 8, 64, 128)))
SCOPE = {name: True for name in ('synthetic', 'unsigned', 'bounded_research_preflight_executed',
    'actual_NewPatchFromDump_executed', 'default_Batch_Replay_executed', 'injected_constructor_and_replay_faults',
    'owned_memory_map_replacement_executed', 'single_exclusive_caller')}
SCOPE.update({name: False for name in ('decoder_panic_recovery_used', 'node_database_opened', 'actual_NodeTree_executed',
    'production_caller_execution', 'production_corruption_reachability_qualified', 'authenticated_snapshot_import',
    'shared_writer_atomicity', 'crash_durability', 'resource_measurements_executed', 'network_execution',
    'full_node_started', 'signing', 'transactions', 'profile_agreed', 'network_activation_authenticated',
    'runtime_state_proof_acceptance')})


def selected_dump(name):
    raw = DEC.complete()
    return {'complete': raw, 'empty': b'', 'empty-delete': b'\x00\x00', 'empty-put': b'\x01\x00\x00',
        'overlong-empty-put': b'\x01\x80\x00\x80\x00',
        'overlong-complete': b'\x01\xa0\x00' + DEC.key(1) + b'\xa0\x00' + DEC.value(91) + raw[67:],
        'duplicate-9': raw + DEC.record(1, DEC.key(8), DEC.value(9)),
        'duplicate-10': raw + DEC.record(1, DEC.key(8), DEC.value(10))}[name]


def selection(name):
    raw = selected_dump(name)
    count = {'complete': 3, 'overlong-complete': 3, 'duplicate-9': 4, 'duplicate-10': 4, 'empty': 0}.get(name, 1)
    return {'name': name, 'bytes': len(raw), 'records': count, 'changes_hash': BYTE.digest(raw).hex()}


def inputs():
    rows = [(name, raw, DEFAULTS.copy(), selection('complete'), 'none') for name, raw in DEC.inputs()]

    def add(name, limits=None, selected=None, fault='none'):
        chosen = selected or selection('complete')
        rows.append((name, selected_dump(chosen['name']), (limits or DEFAULTS).copy(), chosen.copy(), fault))

    add('exact-all-bounds', dict(zip(CEILINGS, (168, 3, 32, 32))))
    for field, short, name in zip(CEILINGS, (167, 2, 31, 31),
            ('raw-limit-short', 'record-limit-short', 'key-limit-short', 'value-limit-short')):
        add(name, DEFAULTS | {field: short})
    for index, (field, ceiling) in enumerate(CEILINGS.items()):
        for value in (0, ceiling + 1):
            add('invalid-limit-%d-%d' % (index, value), DEFAULTS | {field: value})
    for field, value, name in (('bytes', 167, 'wrong-byte-count'), ('changes_hash', '00' * 32, 'wrong-changes-hash'),
                              ('records', 2, 'wrong-record-count')):
        add(name, selected=selection('complete') | {field: value})
    for name in ('empty', 'empty-delete', 'empty-put', 'overlong-empty-put', 'overlong-complete', 'duplicate-9', 'duplicate-10'):
        add(name + '-selected', selected=selection(name))
    for fault in ('load-error', 'load-nil', 'replay-error-first', 'replay-error-complete', 'replay-omit-last',
                  'replay-extra', 'replay-wrong-value', 'mutate-owned-after-load', 'mutate-source-after-load'):
        add(fault, fault=fault)
    return rows


def preflight(raw, limits):
    if any(type(limits[field]) is not int or not 0 < limits[field] <= cap for field, cap in CEILINGS.items()):
        return [], 'invalid_limits'
    if len(raw) > limits['raw_bytes']:
        return [], 'raw_limit'
    events, offset = [], 0
    while offset < len(raw):
        if len(events) == limits['records']:
            return events, 'record_limit'
        kind = raw[offset]
        offset += 1
        if kind not in (0, 1):
            return events, 'invalid_type'
        fields = []
        for name in ('key', 'value') if kind else ('key',):
            length, width = DEC.unsigned_varint(raw[offset:])
            if width <= 0:
                return events, 'invalid_varint'
            offset += width
            if length > limits[name + '_bytes']:
                return events, name + '_limit'
            if length > len(raw) - offset:
                return events, 'truncated_' + name
            fields.append(raw[offset:offset + length].hex())
            offset += length
        events.append({'operation': 'Put' if kind else 'Delete', 'key': fields[0], 'value': fields[1] if kind else None})
    return events, ''


def initial():
    return {DEC.key(index).hex(): DEC.value(amount).hex() for index, amount in ((1, 5), (2, 7), (99, 123))}


def expected_case(name, raw, limits, chosen, fault):
    events, refusal = preflight(raw, limits)
    staged, target, next_state = [], initial(), initial()
    constructors = replays = replacements = 0
    source_after = raw
    if not refusal and (len(raw) != chosen['bytes'] or len(events) != chosen['records'] or BYTE.digest(raw).hex() != chosen['changes_hash']):
        refusal = 'selection_mismatch'
    if not refusal:
        constructors = 1
        refusal = {'load-error': 'load_error', 'load-nil': 'nil_patch', 'mutate-owned-after-load': 'patch_bytes_mismatch'}.get(fault, '')
    if not refusal:
        replays = 1
        delivered = copy.deepcopy(events)
        if fault == 'mutate-source-after-load':
            source_after = raw[:-1] + bytes([raw[-1] ^ 1])
        if fault == 'replay-error-first':
            delivered = delivered[:1]
        if fault == 'replay-omit-last':
            delivered = delivered[:-1]
        if fault == 'replay-extra':
            delivered.append({'operation': 'Put', 'key': DEC.key(8).hex(), 'value': DEC.value(9).hex()})
        if fault == 'replay-wrong-value':
            value = bytes.fromhex(delivered[0]['value'])
            delivered[0]['value'] = (value[:-1] + bytes([value[-1] ^ 1])).hex()
        for index, event in enumerate(delivered):
            staged.append(event)
            if index >= len(events) or event != events[index]:
                refusal = 'callback_mismatch'
                break
            if event['operation'] == 'Delete':
                next_state.pop(event['key'], None)
            else:
                next_state[event['key']] = event['value']
        if fault in ('replay-error-first', 'replay-error-complete'):
            refusal = 'replay_error'
        if not refusal and len(staged) != len(events):
            refusal = 'incomplete_replay'
        if not refusal:
            target, replacements = next_state, 1
    return {'name': name, 'input': raw.hex(), 'source_after': source_after.hex(), 'limits': limits, 'selection': chosen,
        'injected_fault': fault, 'preflight_records': len(events), 'constructor_calls': constructors, 'default_replay_calls': replays,
        'staging_callbacks': staged, 'target_before': DEC.manifest(initial()), 'target_after': DEC.manifest(target),
        'target_replacements': replacements, 'research_import_result': 'REJECTED' if refusal else 'STAGED',
        'refusal': refusal, 'consumer_result': 'REFUSED'}


def expected_document():
    return {'format_version': 1, 'kind': 'candidate-patch-import-research',
        'source': {'repository': 'https://github.com/digitalSloth/go-zenon', 'revision': BYTE.NODE_REVISION, 'tree': BYTE.NODE_TREE},
        'limits_ceiling': CEILINGS, 'default_limits': DEFAULTS, 'scope': SCOPE,
        'cases': [expected_case(*row) for row in inputs()]}


def check_corpus(document):
    expected = expected_document()
    DEC.RET.exact(document, expected)
    cases = expected['cases']
    rejected = [r for r in cases if r['research_import_result'] == 'REJECTED']
    BYTE.require(all(r['target_after'] == r['target_before'] and r['target_replacements'] == 0 for r in rejected), 'rejected target changed')
    return {'patch_import_cases': len(cases), 'reused_decode_cases': len(DEC.inputs()),
        'research_imports_staged': len(cases) - len(rejected), 'research_imports_rejected': len(rejected),
        'rejections_before_constructor': sum(r['constructor_calls'] == 0 for r in cases),
        'actual_constructor_calls': sum(r['constructor_calls'] for r in cases),
        'actual_default_replay_calls': sum(r['default_replay_calls'] for r in cases),
        'isolated_staging_callbacks': sum(len(r['staging_callbacks']) for r in cases),
        'rejected_after_staging_callbacks': sum(bool(r['staging_callbacks']) for r in rejected),
        'rejected_targets_unchanged': len(rejected), 'owned_map_replacements': len(cases) - len(rejected),
        'consumer_refusals': len(cases), 'reference_backend_execution_in_checker': False,
        'decoder_panic_recovery_used': False, 'production_caller_execution': False,
        'authenticated_snapshot_import': False, 'shared_writer_atomicity': False, 'crash_durability': False,
        'resource_measurements_executed_in_checker': False, 'production_acceptance_enabled': False,
        'accepted_VerifiedState_binding_qualified': False, 'profile_agreed': False, 'network_activation_authenticated': False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--corpus', type=Path, default=HERE / 'testdata/candidate-patch-import.json')
    parser.add_argument('--source-revision')
    args = parser.parse_args(argv)
    raw, document = BYTE.read_corpus(args.corpus)
    report = check_corpus(document)
    report.update({'source_revision': args.source_revision, 'corpus_sha256': hashlib.sha256(raw).hexdigest(),
                   'node_revision': BYTE.NODE_REVISION, 'node_tree': BYTE.NODE_TREE})
    print(json.dumps(report, sort_keys=True, separators=(',', ':')))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError):
        print('Candidate patch import conformance failed; production acceptance remains disabled.', file=sys.stderr)
        sys.exit(1)
