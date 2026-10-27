#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Run both complete, unchanged import control suites with explicit child recipes."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
import unittest

HERE = Path(__file__).resolve().parent


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main(argv=None):
    child = load('selected_import_resource_children', 'import_resource_child_hex.py')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--program', choices=tuple(child.PROFILES), required=True)
    parser.add_argument('--mode', choices=('reference', 'translated'), required=True)
    parser.add_argument('--source-revision', required=True)
    args = parser.parse_args(argv)
    child.require(re.fullmatch('[0-9a-f]{40}', args.source_revision) is not None)
    runner_pin = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    oracle = load('selected_import_parent_hex', 'project_target_hex.py')
    program = oracle.load('selected_import_original_controls', args.program)
    suite = unittest.defaultTestLoader.loadTestsFromModule(program)
    def names(tests):
        return [name for test in tests for name in
                (names(test) if isinstance(test, unittest.TestSuite) else [test.id().split('.', 1)[1]])]
    selected = names(suite)
    child.require(len(selected) == {'check_patch_resources_test.py': 24,
                                    'check_patch_import_comparison_test.py': 21}[args.program])
    with child.selected_children(program, args.program, args.mode, args.source_revision) as owner, \
            oracle.selected_oracles(program, args.program, args.mode) as bindings:
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        child.require(result.wasSuccessful() and not result.skipped
                      and type(result.testsRun) is int and result.testsRun == len(selected))
    child.require(hashlib.sha256(Path(__file__).read_bytes()).hexdigest() == runner_pin)
    report = {'format': 'complete-import-resource-control-execution/v1', 'source_revision': args.source_revision,
              'program': args.program, 'mode': args.mode, 'tests_run': result.testsRun,
              'control_names': selected, 'checks_completed': True, 'runner_sha256': runner_pin,
              'parent_binding_manifest': bindings, 'child_execution': owner.report(),
              'reference_backend_executed': False, 'production_acceptance_enabled': False}
    print(json.dumps(report, sort_keys=True, separators=(',', ':')))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError, OverflowError, RecursionError):
        print('Import resource controls refused; original assertions remain required.', file=sys.stderr)
        sys.exit(1)
