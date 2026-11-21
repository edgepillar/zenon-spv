#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Check recorded workspace observations and their envelope controls together."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
import unittest

HERE = Path(__file__).resolve().parent
RECORDING = 'check_temp_workspace.py'
CONTROLS = 'check_temp_workspace_test.py'


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


HEX = load('workspace_target_hex', HERE / 'project_target_hex.py')
GRAPH = load('workspace_graph_reuse', HERE.parent / 'conformance_graph_reuse.py')


def control_names(tests):
    for test in tests:
        if isinstance(test, unittest.TestSuite):
            yield from control_names(test)
        else:
            yield test.id().split('.', 1)[1]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-revision', required=True)
    args = parser.parse_args(argv)
    HEX.require(re.fullmatch(r'[0-9a-f]{40}', args.source_revision) is not None)
    source = Path(__file__)
    source_pin = hashlib.sha256(source.read_bytes()).hexdigest()
    program = HEX.load('workspace_envelope_program', CONTROLS)
    suite = unittest.defaultTestLoader.loadTestsFromModule(program)
    names = list(control_names(suite))
    with GRAPH.selected_graphs(program, CONTROLS) as reused, \
            HEX.selected_oracles(program, CONTROLS, 'translated') as bindings:
        # Validate the recording before the controls reuse its reference model.
        program.CHECK.main([])
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        HEX.require(result.wasSuccessful() and not result.skipped and type(result.testsRun) is int
                    and result.testsRun == len(names) > 0)
    HEX.require(hashlib.sha256(source.read_bytes()).hexdigest() == source_pin)
    bindings['current_execution_inputs'][source.name] = source_pin
    report = {
        'format_version': 1, 'kind': 'recorded-workspace-checks-execution',
        'source_revision': args.source_revision, 'recording_program': RECORDING,
        'control_program': CONTROLS, 'recording_checked_before_controls': True,
        'tests_run': result.testsRun, 'control_names': names, 'checks_completed': True,
        'binding_manifest': bindings, 'graph_reuse': reused.report(),
    }
    print(json.dumps(report, sort_keys=True, separators=(',', ':')))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError, OverflowError, RecursionError):
        print('Recorded workspace checks refused.', file=sys.stderr)
        sys.exit(1)
