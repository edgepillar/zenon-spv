#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Run one complete recorded retention checker with optional bounded leaf reuse.

Reference and reused modes keep the original checker and recordings unchanged.
The successful-exit receipt identifies the new execution seam separately.
"""
import argparse
from contextlib import nullcontext
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
import unittest

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
HELPER = HERE.parent / 'conformance_leaf_reuse.py'


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def revision(value):
    if re.fullmatch('[0-9a-f]{40}', value) is None:
        raise argparse.ArgumentTypeError('expected a full lowercase source revision')
    return value


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--program', choices=('check_tree_scale.py', 'check_tree_scale_test.py'), required=True)
    parser.add_argument('--mode', choices=('reference', 'reused'), required=True)
    parser.add_argument('--source-revision', type=revision, required=True)
    args = parser.parse_args(argv)
    own_pin = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    helper_pin = hashlib.sha256(HELPER.read_bytes()).hexdigest()
    helper = load('retention_leaf_reuse', HELPER)
    inputs = helper.verify_sources()
    program = load('selected_retention_leaf_program', HERE / args.program)
    helper.selected_module(program, args.program)
    control_names, tests_run = [], None
    scope = helper.selected_leaves(program, args.program) if args.mode == 'reused' else nullcontext(None)
    with scope as reused:
        if args.program.endswith('_test.py'):
            suite = unittest.defaultTestLoader.loadTestsFromModule(program)
            def names(tests):
                return [name for test in tests for name in
                        (names(test) if isinstance(test, unittest.TestSuite) else [test.id().split('.', 1)[1]])]
            control_names = names(suite)
            result = unittest.TextTestRunner(verbosity=2).run(suite)
            tests_run = result.testsRun
            helper.require(result.wasSuccessful() and not result.skipped and tests_run == len(control_names) > 0)
        else:
            program.main([])
    helper.require(helper.verify_sources() == inputs
                   and hashlib.sha256(HELPER.read_bytes()).hexdigest() == helper_pin
                   and hashlib.sha256(Path(__file__).read_bytes()).hexdigest() == own_pin)
    reuse_report = reused.report() if reused is not None else None
    if reuse_report is not None:
        helper.require(reuse_report['graph_requests'] > 0 and reuse_report['failed_graphs'] == 0
                       and reuse_report['every_graph_traversal_completed'])
    print(json.dumps({'format': 'zenon-retention-leaf-reuse-execution/v1',
                      'source_revision': args.source_revision, 'program': args.program, 'mode': args.mode,
                      'runner_sha256': own_pin, 'helper_sha256': helper_pin,
                      'reference_sources': inputs, 'tests_run': tests_run, 'control_names': control_names,
                      'checks_completed': True, 'leaf_reuse': reuse_report,
                      'recorded_producer_source_inputs_rebound': False, 'new_node_execution': False,
                      'production_acceptance_enabled': False}, sort_keys=True, separators=(',', ':')))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError, OverflowError, RecursionError):
        print('Retention leaf reuse refused; production acceptance remains disabled.', file=sys.stderr)
        sys.exit(1)
