#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Independently decode finite patch dumps and bind diagnostic callback prefixes.

This checker executes no Go reference or database. Signed 64-bit length arithmetic
is explicit; selected complete state is fixed before any observed callbacks.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('patch_decode_retention_oracle', HERE / 'check_retention.py')
RET = importlib.util.module_from_spec(spec)
spec.loader.exec_module(RET)
BYTE = RET.BYTE
DEPENDENCY = {'module': 'github.com/syndtr/goleveldb', 'version': 'v1.0.1-0.20210819022825-2ae1ddf74ef7',
              'sum': 'h1:epCh84lMvA70Z7CTTCmYQn2CKbY8j86K7/FAIr141uY=',
              'batch_source_sha256': '299129fbb88354f140bd7e7c83ffda6554e9af906ab68589f72e7c212f49c096'}
SCOPE = {'synthetic': True, 'unsigned': True, 'reference_64_bit_integers': True,
         'actual_NewPatchFromDump_executed': True, 'default_Batch_Replay_executed': True,
         'diagnostic_replay_after_decode_errors_executed': True, 'runtime_bounds_panics_recovered_in_research': True,
         **{name: False for name in ('custom_Patch_Replay_errors_injected', 'node_database_opened',
            'actual_NodeTree_executed', 'production_caller_execution', 'production_corruption_reachability_qualified',
            'resource_measurements_executed', 'network_execution', 'full_node_started', 'chain_Start_executed',
            'signing', 'transactions', 'profile_agreed', 'network_activation_authenticated', 'runtime_state_proof_acceptance')}}


def key(index):
    return b'\x03' + b'\x11' * 16 + index.to_bytes(4, 'big') + b'\x03' + b'\x22' * 10


def value(amount):
    return amount.to_bytes(32, 'big')


def varint(number):
    encoded = bytearray()
    while number >= 128:
        encoded.append((number & 127) | 128)
        number >>= 7
    return bytes(encoded + bytes([number]))


def record(kind, k, v=b''):
    return bytes([kind]) + varint(len(k)) + k + (varint(len(v)) + v if kind else b'')


def complete():
    return record(1, key(1), value(91)) + record(0, key(2)) + record(1, key(8), value(9))


def inputs():
    raw = complete()
    selected = [('prefix-%03d' % cut, raw[:cut]) for cut in range(len(raw) + 1)]
    tails = [('type-02', b'\x02'), ('type-ff', b'\xff'), ('key-truncated-varint', b'\x00\x80'),
             ('key-overflow-varint', b'\x00' + b'\xff' * 9 + b'\x02'),
             ('key-ten-continuations', b'\x00' + b'\x80' * 10),
             ('key-eleven-continuations', b'\x00' + b'\x80' * 11), ('key-short-bytes', b'\x00\x02\x00'),
             ('value-truncated-varint', b'\x01\x00\x80'),
             ('value-overflow-varint', b'\x01\x00' + b'\xff' * 9 + b'\x02'),
             ('value-short-bytes', b'\x01\x00\x02\x00')]
    for number in ((1 << 63) - 1, 1 << 63, (1 << 64) - 1):
        length = varint(number)
        tails += [('delete-key-length-%d' % number, b'\x00' + length),
                  ('put-key-length-%d' % number, b'\x01' + length),
                  ('put-value-length-%d' % number, b'\x01\x00' + length)]
    for name, prefix in [('fresh', b''), ('after-one', record(1, key(1), value(91))), ('after-complete', raw)]:
        selected += [(name + '/' + tail_name, prefix + tail) for tail_name, tail in tails]
    selected += [('valid-empty-delete', b'\x00\x00'), ('valid-empty-put', b'\x01\x00\x00'),
                 ('valid-overlong-empty-put', b'\x01\x80\x00\x80\x00'),
                 ('valid-overlong-complete', b'\x01\xa0\x00' + key(1) + b'\xa0\x00' + value(91) + raw[67:])]
    selected += [('valid-duplicate-put-%d' % amount, raw + record(1, key(8), value(amount))) for amount in (9, 10)]
    return selected


class Bounds(Exception):
    pass


def i64(number):
    return ((number + (1 << 63)) % (1 << 64)) - (1 << 63)


def slice_bytes(raw, start, end):
    if not 0 <= start <= end <= len(raw):
        raise Bounds()
    return raw[start:end]


def unsigned_varint(raw):
    result = 0
    for index, byte in enumerate(raw):
        if index == 10:
            return 0, -11
        if byte < 128:
            if index == 9 and byte > 1:
                return 0, -10
            return result | (byte << (7 * index)), index + 1
        result |= (byte & 127) << (7 * index)
    return 0, 0


def indexes(raw):
    """Return completed record indexes, an ordinary error, or a bounds exception.

    Load errors retain completed indexes. A runtime exception prevents the patch
    constructor from returning. Decode records precede any diagnostic replay.
    """
    result, offset = [], 0
    while offset < len(raw):
        kind = slice_bytes(raw, offset, offset + 1)[0]
        if kind > 1:
            return result, 'leveldb: batch corrupted: bad record: invalid type %#x' % kind
        offset += 1
        number, size = unsigned_varint(slice_bytes(raw, offset, len(raw)))
        offset = i64(offset + size)
        length = i64(number)
        if size <= 0 or i64(offset + length) > len(raw):
            return result, 'leveldb: batch corrupted: bad record: invalid key length'
        key_pos, key_len = offset, length
        offset = i64(offset + length)
        value_pos, value_len = 0, 0
        if kind:
            number, size = unsigned_varint(slice_bytes(raw, offset, len(raw)))
            offset = i64(offset + size)
            length = i64(number)
            if size <= 0 or i64(offset + length) > len(raw):
                return result, 'leveldb: batch corrupted: bad record: invalid value length'
            value_pos, value_len = offset, length
            offset = i64(offset + length)
        result.append((kind, key_pos, key_len, value_pos, value_len))
    return result, None


def manifest(state):
    return [{'key': k, 'value': v} for k, v in sorted(state.items())]


def selected_state():
    return {key(1).hex(): value(91).hex(), key(8).hex(): value(9).hex()}


def expected_case(name, raw):
    records, error, load_panic = None, None, None
    try:
        records, error = indexes(raw)
    except Bounds:
        load_panic = 'runtime_bounds'
    returned = records is not None
    callbacks, state, replay_panic = [], {}, None
    if returned:
        try:
            for kind, kpos, klen, vpos, vlen in records:
                k = slice_bytes(raw, kpos, i64(kpos + klen)).hex()
                v = (slice_bytes(raw, vpos, i64(vpos + vlen)) if vlen else b'').hex() if kind else None
                callbacks.append({'operation': 'Put' if kind else 'Delete', 'key': k, 'value': v})
                if kind:
                    state[k] = v
                else:
                    state.pop(k, None)
        except Bounds:
            replay_panic = 'runtime_bounds'
    return {'name': name, 'input': raw.hex(), 'load_error': error, 'load_panic': load_panic,
            'patch_returned': returned, 'indexed_records': len(records) if returned else None,
            'dump': raw.hex() if returned else None, 'patch_hash': BYTE.digest(raw).hex() if returned else None,
            'diagnostic_replay_after_decode_error': returned and error is not None,
            'replay_error': None, 'replay_panic': replay_panic, 'replay_callbacks': callbacks,
            'diagnostic_manifest': manifest(state), 'diagnostic_state_matches_selected_fixture': state == selected_state(),
            'consumer_result': 'REFUSED'}


def check_corpus(document):
    expected = [expected_case(name, raw) for name, raw in inputs()]
    RET.exact(document, {'format_version': 1, 'kind': 'candidate-patch-decode-research',
        'source': {'repository': 'https://github.com/digitalSloth/go-zenon', 'revision': BYTE.NODE_REVISION, 'tree': BYTE.NODE_TREE},
        'dependency': DEPENDENCY, 'scope': SCOPE, 'complete_dump': complete().hex(),
        'selected_complete_manifest': manifest(selected_state()), 'cases': expected})
    prefixes = expected[:len(complete()) + 1]
    return {'patch_decode_cases': len(expected), 'all_byte_prefix_cases': len(prefixes),
            'valid_prefix_decodes': sum(r['load_error'] is None and r['load_panic'] is None for r in prefixes),
            'ordinary_decode_errors': sum(r['load_error'] is not None for r in expected),
            'returned_partial_patches_after_error': sum(r['load_error'] is not None and bool(r['replay_callbacks']) for r in expected),
            'decode_runtime_bounds_panics': sum(r['load_panic'] is not None for r in expected),
            'diagnostic_replay_runtime_bounds_panics': sum(r['replay_panic'] is not None for r in expected),
            'diagnostic_replay_callbacks': sum(len(r['replay_callbacks']) for r in expected),
            'diagnostic_state_matches_selected_fixture': sum(r['diagnostic_state_matches_selected_fixture'] for r in expected),
            'decode_errors_with_selected_complete_state': sum(r['load_error'] is not None and r['diagnostic_state_matches_selected_fixture'] for r in expected),
            'consumer_refusals': len(expected), 'reference_backend_execution_in_checker': False,
            'production_caller_execution': False, 'production_corruption_reachability_qualified': False,
            'resource_measurements_executed_in_checker': False, 'production_acceptance_enabled': False,
            'accepted_VerifiedState_binding_qualified': False, 'profile_agreed': False, 'network_activation_authenticated': False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--corpus', type=Path, default=HERE / 'testdata/candidate-patch-decode.json')
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
        print('Candidate patch decode conformance failed; production acceptance remains disabled.', file=sys.stderr)
        sys.exit(1)
