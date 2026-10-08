#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Independently bind bounded initial/transient research maps and complete replay.

This finite oracle never imports Go, opens a node/database or authenticates a
snapshot. Selected string payload caps are not whole-process memory budgets.
"""
import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('target_import_oracle', HERE / 'check_patch_import.py')
IMP = importlib.util.module_from_spec(spec)
spec.loader.exec_module(IMP)
BYTE, DEC = IMP.BYTE, IMP.DEC
CEILINGS = {'entries': 4096, 'hex_bytes': 1 << 20}
DEFAULTS = {'entries': 8, 'hex_bytes': 1024}
SCOPE = {name: True for name in ('synthetic', 'unsigned', 'actual_NewPatchFromDump_executed',
    'default_Batch_Replay_executed', 'injected_constructor_and_replay_faults',
    'initial_and_transient_target_limits_executed', 'owned_memory_map_replacement_executed',
    'cloning_after_complete_selection_and_constructor_checks', 'single_exclusive_caller')}
SCOPE.update({name: False for name in ('hex_payload_cap_is_whole_process_memory_budget',
    'decoder_panic_recovery_used', 'node_database_opened', 'actual_NodeTree_executed',
    'production_caller_execution', 'authenticated_snapshot_import', 'shared_writer_atomicity',
    'crash_durability', 'resource_measurements_executed', 'network_execution', 'full_node_started',
    'signing', 'transactions', 'profile_agreed', 'network_activation_authenticated', 'runtime_state_proof_acceptance')})


def dump(name):
    put = lambda key, value: DEC.record(1, DEC.key(key), value)
    delete = lambda key: DEC.record(0, DEC.key(key))
    choices = {
        'put-then-delete': put(8, DEC.value(9)) + delete(2),
        'delete-then-put': delete(2) + put(8, DEC.value(9)),
        'grow-then-delete': put(1, b'\0' * 33) + delete(2),
        'replace-smaller-then-grow': put(1, b'') + put(1, DEC.value(9)),
        'empty-key-put-delete': b'\x01\x00\x00\x00\x00',
    }
    if name in choices:
        return choices[name], 2
    return IMP.selected_dump(name), IMP.selection(name)['records']


def inputs():
    rows = []

    def add(name, selected='complete', fault='none', target=None, limits=None):
        raw, records = dump(selected)
        chosen = {'name': selected, 'bytes': len(raw), 'records': records, 'changes_hash': BYTE.digest(raw).hex()}
        rows.append({'name': name, 'raw': raw, 'limits': IMP.DEFAULTS.copy(), 'selection': chosen,
            'fault': fault, 'target': IMP.initial() if target is None else target.copy(),
            'target_limits': (DEFAULTS if limits is None else limits).copy()})

    add('default-complete')
    add('exact-target-bounds', limits={'entries': 3, 'hex_bytes': 384})
    add('empty-initial-target', target={}, limits={'entries': 2, 'hex_bytes': 256})
    add('initial-entry-short', limits={'entries': 2, 'hex_bytes': 384})
    add('initial-hex-short', limits={'entries': 3, 'hex_bytes': 383})
    for index, (field, cap) in enumerate(CEILINGS.items()):
        for value in (0, cap + 1):
            add('invalid-target-limit-%d-%d' % (index, value), limits=DEFAULTS | {field: value})
    for field in ('key', 'value'):
        for spelling in ('0', 'GG', 'Aa'):
            target = {spelling: '00'} if field == 'key' else {'00': spelling}
            add('invalid-' + field + '-' + spelling, target=target)
    for name in ('put-then-delete', 'delete-then-put', 'grow-then-delete', 'replace-smaller-then-grow'):
        add(name, selected=name, limits={'entries': 3, 'hex_bytes': 384})
    add('new-entry-with-room', selected='put-then-delete', limits={'entries': 4, 'hex_bytes': 512})
    add('value-growth-with-room', selected='grow-then-delete', limits={'entries': 3, 'hex_bytes': 386})
    for name in ('empty', 'empty-delete', 'empty-put', 'overlong-empty-put', 'overlong-complete',
                 'duplicate-9', 'duplicate-10', 'empty-key-put-delete'):
        add(name + '-selected', selected=name, limits={'entries': 4, 'hex_bytes': 384})
    for fault in ('load-error', 'load-nil', 'replay-error-first', 'replay-error-complete', 'replay-omit-last',
                  'replay-extra', 'replay-wrong-value', 'mutate-owned-after-load', 'mutate-source-after-load'):
        add(fault, fault=fault)
    add('malformed-raw-before-clone')
    rows[-1]['raw'] += b'\x02'
    add('wrong-selection-before-clone')
    rows[-1]['selection']['changes_hash'] = '00' * 32
    add('raw-cap-before-copy')
    rows[-1]['limits']['raw_bytes'] = 167
    add('invalid-raw-limit-before-copy')
    rows[-1]['limits']['raw_bytes'] = 0
    for count in (4096, 4097):
        add('target-entries-%d' % count, selected='empty', target={'%08x' % i: '' for i in range(count)}, limits=CEILINGS)
    for size in (1 << 20, (1 << 20) + 2):
        add('target-hex-bytes-%d' % size, selected='empty', target={'': '00' * (size // 2)}, limits=CEILINGS)
    return rows


def summary(target):
    manifest = [{'key': key, 'value': target[key]} for key in sorted(target)]
    raw = json.dumps(manifest, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')
    return {'entries': len(target), 'hex_bytes': sum(len(key) + len(value) for key, value in target.items()),
        'manifest_sha256': hashlib.sha256(raw).hexdigest()}


def target_refusal(target, limits):
    if any(type(limits[field]) is not int or not 0 < limits[field] <= cap for field, cap in CEILINGS.items()):
        return 'invalid_target_limits'
    if len(target) > limits['entries']:
        return 'target_entry_limit'
    if sum(len(key) + len(value) for key, value in target.items()) > limits['hex_bytes']:
        return 'target_hex_limit'
    if any(len(text) % 2 or any(c not in '0123456789abcdef' for c in text)
           for item in target.items() for text in item):
        return 'invalid_target_encoding'
    return ''


def expected_case(row):
    raw, limits, chosen, fault = (row[n] for n in ('raw', 'limits', 'selection', 'fault'))
    target, caps = row['target'], row['target_limits']
    events, callbacks, stage = [], [], {}
    output, source_after = target.copy(), raw
    copies = constructors = replays = clones = cloned_entries = replacements = 0
    if any(type(limits[field]) is not int or not 0 < limits[field] <= cap for field, cap in IMP.CEILINGS.items()):
        refusal = 'invalid_limits'
    elif len(raw) > limits['raw_bytes']:
        refusal = 'raw_limit'
    else:
        refusal = target_refusal(target, caps)
        if not refusal:
            copies = 1
            events, refusal = IMP.preflight(raw, limits)
    if not refusal and (len(raw) != chosen['bytes'] or len(events) != chosen['records'] or BYTE.digest(raw).hex() != chosen['changes_hash']):
        refusal = 'selection_mismatch'
    if not refusal:
        constructors = 1
        refusal = {'load-error': 'load_error', 'load-nil': 'nil_patch', 'mutate-owned-after-load': 'patch_bytes_mismatch'}.get(fault, '')
    if not refusal:
        clones = replays = 1
        cloned_entries, stage = len(target), target.copy()
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
            callbacks.append(event)
            if index >= len(events) or event != events[index]:
                refusal = 'callback_mismatch'
                break
            # Recompute the entire prospective map. This oracle deliberately
            # avoids the Go prototype's incremental entry/byte accounting.
            prospective = stage.copy()
            if event['operation'] == 'Delete':
                prospective.pop(event['key'], None)
            else:
                prospective[event['key']] = event['value']
            refusal = target_refusal(prospective, caps)
            if refusal:
                break
            stage = prospective
        if fault in ('replay-error-first', 'replay-error-complete'):
            refusal = 'replay_error'
        if not refusal and len(callbacks) != len(events):
            refusal = 'incomplete_replay'
        if not refusal:
            output, replacements = stage.copy(), 1
    return {'name': row['name'], 'input': raw.hex(), 'source_after': source_after.hex(), 'limits': limits,
        'selection': chosen, 'target_limits': caps, 'injected_fault': fault, 'preflight_records': len(events),
        'raw_copies': copies, 'constructor_calls': constructors, 'default_replay_calls': replays,
        'target_clone_calls': clones, 'target_cloned_entries': cloned_entries, 'staging_callbacks': callbacks,
        'staging_target': summary(stage), 'target_before': summary(target), 'target_after': summary(output),
        'original_alias_after': summary(target), 'target_replacements': replacements,
        'research_import_result': 'REJECTED' if refusal else 'STAGED', 'refusal': refusal, 'consumer_result': 'REFUSED'}


def expected_document():
    return {'format_version': 1, 'kind': 'candidate-patch-target-research',
        'source': {'repository': 'https://github.com/digitalSloth/go-zenon', 'revision': BYTE.NODE_REVISION, 'tree': BYTE.NODE_TREE},
        'target_limits_ceiling': CEILINGS, 'default_target_limits': DEFAULTS, 'scope': SCOPE,
        'cases': [expected_case(row) for row in inputs()]}


def check_corpus(document):
    expected = expected_document()
    DEC.RET.exact(document, expected)
    cases = expected['cases']
    rejected = [r for r in cases if r['refusal']]
    return {'patch_target_cases': len(cases), 'research_imports_staged': len(cases) - len(rejected),
        'research_imports_rejected': len(rejected), 'rejected_targets_unchanged': len(rejected),
        'original_aliases_unchanged': len(cases), 'refusals_without_target_clone': sum(not r['target_clone_calls'] for r in rejected),
        'refusals_without_raw_copy': sum(not r['raw_copies'] for r in rejected),
        'actual_constructor_calls': sum(r['constructor_calls'] for r in cases),
        'actual_default_replay_calls': sum(r['default_replay_calls'] for r in cases),
        'consumer_refusals': len(cases), 'reference_backend_execution_in_checker': False,
        'whole_process_memory_budget_qualified': False, 'resource_measurements_executed_in_checker': False,
        'authenticated_snapshot_import': False, 'shared_writer_atomicity': False, 'crash_durability': False,
        'accepted_VerifiedState_binding_qualified': False, 'profile_agreed': False,
        'network_activation_authenticated': False, 'production_acceptance_enabled': False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--corpus', type=Path, default=HERE / 'testdata/candidate-patch-targets.json')
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
        print('Candidate patch target conformance failed; production acceptance remains disabled.', file=sys.stderr)
        sys.exit(1)
