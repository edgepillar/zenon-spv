#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Run selected complete portable oracles through the unchanged recorded runner.

The optional graph scope is serial, bounded and process-local. This entry point
never runs a node, compiler, network observer or new resource capture.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
from types import ModuleType

HERE = Path(__file__).resolve().parent
LEGACY = HERE / 'run_target_hex.py'
LEGACY_SHA256 = '3bf4f6078adba2520bcbf9b750961e9d09569d7a50235447f1812a625c7c5231'
PROGRAMS = (
    'check_tree_import_scale.py', 'check_tree_import_scale_test.py',
    'check_tree_import_lifecycle.py', 'check_tree_import_lifecycle_test.py',
    'check_oracle_projection.py', 'check_oracle_projection_test.py',
)


def require(condition):
    if not condition:
        raise ValueError('Complete oracle driver refused')


def source_bytes(path):
    require(path.is_file() and not path.is_symlink())
    with path.open('rb') as handle:
        raw = handle.read((1 << 20) + 1)
    require(len(raw) <= 1 << 20)
    return raw


def source_hash(path):
    return hashlib.sha256(source_bytes(path)).hexdigest()


def revision(value):
    if re.fullmatch('[0-9a-f]{40}', value) is None:
        raise argparse.ArgumentTypeError('expected a full lowercase source revision')
    return value


def load_legacy():
    raw = source_bytes(LEGACY)
    require(hashlib.sha256(raw).hexdigest() == LEGACY_SHA256)
    module = ModuleType('unchanged_recorded_target_runner')
    module.__file__ = str(LEGACY)
    exec(compile(raw, str(LEGACY), 'exec'), vars(module))
    return module


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--program', choices=PROGRAMS, required=True)
    parser.add_argument('--mode', choices=('translated',), required=True)
    parser.add_argument('--source-revision', type=revision, required=True)
    parser.add_argument('--reuse-graphs', action='store_true',
                        help='reuse bounded complete graphs in selected existing oracle instances')
    args = parser.parse_args(argv)
    own = Path(__file__).resolve()
    own_pin = source_hash(own)
    legacy = load_legacy()
    selected = ['--program', args.program, '--mode', args.mode,
                '--source-revision', args.source_revision]
    if args.reuse_graphs:
        selected.append('--reuse-graphs')
    legacy.main(selected)
    require(source_hash(own) == own_pin and source_hash(LEGACY) == LEGACY_SHA256)
    print(json.dumps({
        'format_version': 1, 'kind': 'selected-complete-oracle-driver',
        'source_revision': args.source_revision, 'program': args.program,
        'mode': args.mode, 'reuse_graphs': args.reuse_graphs,
        'wrapper_sha256': own_pin, 'legacy_runner_sha256': LEGACY_SHA256,
        'legacy_runner_source_unchanged': True, 'checks_completed': True,
        'recorded_producer_source_inputs_rebound': False,
        'new_reference_node_or_resource_measurement': False,
        'production_acceptance_enabled': False,
    }, sort_keys=True, separators=(',', ':')))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError, OverflowError, RecursionError):
        print('Complete oracle driver refused; production acceptance remains disabled.', file=sys.stderr)
        sys.exit(1)
