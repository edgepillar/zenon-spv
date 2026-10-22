#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Run one complete selected research checker with an explicit hex seam recipe.

Old producer pins and recordings are unchanged. The separate successful-exit
recipe binds the current checker, optimizer and dependency sources. It does not
authenticate historical execution or qualify node, hardware or state proofs.
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

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('selected_target_hex', HERE / 'project_target_hex.py')
HEX = importlib.util.module_from_spec(spec)
spec.loader.exec_module(HEX)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--program', choices=tuple(HEX.SEAMS), required=True)
    parser.add_argument('--mode', choices=HEX.MODES, required=True)
    parser.add_argument('--source-revision', required=True)
    parser.add_argument('--reuse-graphs', action='store_true',
                        help='reuse bounded complete pure graph results for the selected driver checker only')
    parser.add_argument('--reuse-child-hex', action='store_true',
                        help='select three fresh file-checker CLIs with their own explicit hex recipes')
    args = parser.parse_args(argv)
    HEX.require(re.fullmatch(r'[0-9a-f]{40}', args.source_revision) is not None)
    runner_pin = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    graph = None
    if args.reuse_graphs:
        spec = importlib.util.spec_from_file_location('bounded_conformance_graph_reuse',
                                                     HERE.parent / 'conformance_graph_reuse.py')
        graph = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(graph)
        graph.require(args.program in graph.SEAMS)
        graph.verify_sources()
    program = HEX.load('selected_target_hex_program', args.program)
    children = None
    if args.reuse_child_hex:
        HEX.require(args.program == 'check_patch_file_resources_test.py')
        children = HEX.load('explicit_selected_child_hex', 'selected_child_hex.py')
    tests_run = None
    control_names = []
    graph_scope = graph.selected_graphs(program, args.program) if graph is not None else nullcontext(None)
    child_scope = (children.selected_children(program, args.program, args.mode, args.source_revision)
                   if children is not None else nullcontext(None))
    with child_scope as selected_children, graph_scope as reused, HEX.selected_oracles(program, args.program, args.mode) as bindings:
        if args.program.endswith('_test.py'):
            suite = unittest.defaultTestLoader.loadTestsFromModule(program)
            def names(tests):
                return [name for test in tests for name in
                        (names(test) if isinstance(test, unittest.TestSuite) else [test.id().split('.', 1)[1]])]
            control_names = names(suite)
            result = unittest.TextTestRunner(verbosity=2).run(suite)
            tests_run = result.testsRun
            HEX.require(result.wasSuccessful() and not result.skipped and type(tests_run) is int
                        and tests_run == len(control_names) > 0)
        else:
            revision_programs = ('check_patch_resources.py', 'check_patch_import_comparison.py',
                                 'check_patch_file_resources.py', 'check_tree_import_scale.py',
                                 'check_tree_import_lifecycle.py', 'check_tree_driver_resources.py',
                                 'check_patch_tree.py', 'check_patch_tree_tail.py',
                                 'check_oracle_projection.py', 'check_projected_driver.py')
            arguments = ['--source-revision', args.source_revision] if args.program in revision_programs else []
            program.main(arguments)
    HEX.require(hashlib.sha256(Path(__file__).read_bytes()).hexdigest() == runner_pin)
    bindings['current_execution_inputs']['run_target_hex.py'] = runner_pin
    if selected_children is not None:
        print(json.dumps(selected_children.report(), sort_keys=True, separators=(',', ':')))
    if reused is not None:
        graph_report = {
            'format_version': 1, 'kind': 'bounded-conformance-graph-reuse-execution',
            'source_revision': args.source_revision, 'program': args.program, 'mode': args.mode,
            'tests_run': tests_run, 'control_names': control_names,
            'runner_sha256': runner_pin, 'checks_completed': True,
            'graph_reuse': reused.report(),
        }
        print(json.dumps(graph_report, sort_keys=True, separators=(',', ':')))
    report = {
        'format_version': 1, 'kind': 'selected-target-hex-execution',
        'source_revision': args.source_revision, 'program': args.program, 'mode': args.mode,
        'tests_run': tests_run, 'control_names': control_names,
        'selected_function_identities_restored': True, 'checks_completed': True,
        'binding_manifest': bindings,
    }
    print(json.dumps(report, sort_keys=True, separators=(',', ':')))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError, OverflowError, RecursionError):
        print('Selected target hex oracle refused; production acceptance remains disabled.', file=sys.stderr)
        sys.exit(1)
