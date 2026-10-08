#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Build a bounded read-only research plan from independently selected patch bytes.

This command performs no node construction, replay, target or database writes.
A plan is unsigned patch syntax; production state-proof acceptance stays disabled.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('patch_plan_oracle', HERE / 'check_patch_import.py')
ORACLE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ORACLE)
CEILINGS = ORACLE.CEILINGS | {'plan_bytes': 4 << 20}
SELECTION_FIELDS = {'bytes', 'records', 'changes_hash'}


class Refused(ValueError):
    """No partial plan or input details may be published on refusal."""


def require(condition):
    if not condition:
        raise Refused('Patch plan refused.')


def validate(selection, limits):
    require(type(limits) is dict and set(limits) == set(CEILINGS))
    for field, ceiling in CEILINGS.items():
        require(type(limits[field]) is int and 0 < limits[field] <= ceiling)
    require(type(selection) is dict and set(selection) == SELECTION_FIELDS)
    for field, cap in (('bytes', 'raw_bytes'), ('records', 'records')):
        require(type(selection[field]) is int and 0 <= selection[field] <= limits[cap])
    require(type(selection['changes_hash']) is str and
            re.fullmatch(r'[0-9a-f]{64}', selection['changes_hash']) is not None)


def read_raw(path, selection, limits):
    validate(selection, limits)
    # Refuse special files before opening, then check the opened descriptor.
    # O_NONBLOCK avoids waiting on a FIFO substituted during the path race.
    require(stat.S_ISREG(Path(path).lstat().st_mode))
    flags = os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NONBLOCK', 0)
    flags |= getattr(os, 'O_NOFOLLOW', 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_size <= limits['raw_bytes'])
        # The explicit selection bounds allocation even when the global ceiling
        # is large. One extra byte detects a tail or growth beyond that selection.
        raw = stream.read(selection['bytes'] + 1)
    require(len(raw) == selection['bytes'])
    return raw


def parse_events(raw, limits):
    """Parse bounded unsigned lengths without copying each remaining input tail."""
    events, offset, view = [], 0, memoryview(raw)
    while offset < len(raw):
        require(len(events) < limits['records'])
        kind = raw[offset]
        offset += 1
        require(kind in (0, 1))
        fields = []
        for field in ('key', 'value') if kind else ('key',):
            length, width = ORACLE.DEC.unsigned_varint(view[offset:offset + 11])
            require(width > 0)
            offset += width
            require(length <= limits[field + '_bytes'] and length <= len(raw) - offset)
            fields.append(view[offset:offset + length].hex())
            offset += length
        events.append({'operation': 'Put' if kind else 'Delete', 'key': fields[0],
                       'value': fields[1] if kind else None})
    return events


def make_plan(raw, selection, limits, source_revision=None):
    validate(selection, limits)
    require(type(raw) is bytes and len(raw) <= limits['raw_bytes'])
    require(source_revision is None or (type(source_revision) is str and
            re.fullmatch(r'[0-9a-f]{40}', source_revision) is not None))
    require(len(raw) == selection['bytes'] and
            hashlib.sha3_256(raw).hexdigest() == selection['changes_hash'])
    events = parse_events(raw, limits)
    require(len(events) == selection['records'])
    return {'format_version': 1, 'kind': 'read-only-patch-plan-research',
        'source_revision': source_revision, 'node_revision': ORACLE.BYTE.NODE_REVISION,
        'node_tree': ORACLE.BYTE.NODE_TREE, 'selection': selection.copy(), 'limits': limits.copy(),
        'input_sha256': hashlib.sha256(raw).hexdigest(), 'events': events,
        'research_plan_result': 'READY', 'consumer_result': 'REFUSED',
        'scope': {'read_only_unsigned_byte_parsing_executed': True,
            'independently_selected_raw_bytes_required': True,
            **{field: False for field in ('reference_backend_execution', 'constructor_execution',
                'replay_execution', 'target_replacement', 'database_execution', 'actual_NodeTree_execution',
                'authenticated_snapshot_import', 'snapshot_completeness_qualified',
                'typed_state_acceptance', 'shared_writer_atomicity', 'crash_durability',
                'resource_budgets_qualified', 'accepted_VerifiedState_binding_qualified',
                'profile_agreed', 'network_activation_authenticated',
                'canonicality_or_consensus_finality_qualified', 'production_state_proof_acceptance_enabled')}}}


def encode_plan(document, maximum):
    require(type(maximum) is int and 0 < maximum <= CEILINGS['plan_bytes'])
    result = bytearray()
    encoder = json.JSONEncoder(sort_keys=True, separators=(',', ':'), ensure_ascii=True)
    for chunk in encoder.iterencode(document):
        part = chunk.encode('ascii')
        require(len(part) <= maximum - len(result))
        result.extend(part)
    require(len(result) < maximum)
    result.extend(b'\n')
    return bytes(result)


class PrivateParser(argparse.ArgumentParser):
    def error(self, message):
        raise Refused('Patch plan refused.')


def number(text):
    require(re.fullmatch(r'0|[1-9][0-9]{0,9}', text) is not None)
    return int(text)


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    options = [value.split('=', 1)[0] for value in argv if value.startswith('--')]
    require(len(options) == len(set(options)))
    parser = PrivateParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--raw', required=True, type=Path)
    parser.add_argument('--changes-hash', required=True)
    parser.add_argument('--expected-bytes', required=True, type=number)
    parser.add_argument('--expected-records', required=True, type=number)
    for field in CEILINGS:
        parser.add_argument('--max-' + field.replace('_', '-'), required=True, type=number)
    parser.add_argument('--source-revision')
    args = parser.parse_args(argv)
    limits = {field: getattr(args, 'max_' + field) for field in CEILINGS}
    selected = {'bytes': args.expected_bytes, 'records': args.expected_records,
                'changes_hash': args.changes_hash}
    raw = read_raw(args.raw, selected, limits)
    plan = make_plan(raw, selected, limits, args.source_revision)
    encoded = encode_plan(plan, limits['plan_bytes'])
    # Publish only the complete bounded result. No path is included in the plan.
    sys.stdout.buffer.write(encoded)


if __name__ == '__main__':
    try:
        main()
    except (Refused, OSError, ValueError, TypeError):
        print('Patch plan refused; no complete plan emitted. Production acceptance remains disabled.', file=sys.stderr)
        sys.exit(1)
