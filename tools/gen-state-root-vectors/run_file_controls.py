#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Run all original file controls with three explicit fresh child hex selections.

The recorded control file and original run_target_hex.py remain byte-identical.
This separate execution driver owns its source recipe and never relabels either.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
import unittest

HERE = Path(__file__).resolve().parent


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, HERE / file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


HEX = load("file_controls_hex_oracle", "project_target_hex.py")
CHILD = load("file_controls_explicit_children", "selected_child_hex.py")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--mode", choices=HEX.MODES, required=True)
    parser.add_argument("--source-revision", required=True)
    args = parser.parse_args(argv)
    HEX.require(re.fullmatch("[0-9a-f]{40}", args.source_revision) is not None)
    driver_pin = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    selected = "check_patch_file_resources_test.py"
    program = HEX.load("selected_file_controls_program", selected)
    with CHILD.selected_children(program, selected, args.mode, args.source_revision) as children, \
            HEX.selected_oracles(program, selected, args.mode) as bindings:
        suite = unittest.defaultTestLoader.loadTestsFromModule(program)

        def names(tests):
            return [name for test in tests for name in
                    (names(test) if isinstance(test, unittest.TestSuite) else [test.id().split(".", 1)[1]])]

        control_names = names(suite)
        HEX.require(len(control_names) == 23)
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        HEX.require(result.wasSuccessful() and not result.skipped and type(result.testsRun) is int
                    and result.testsRun == len(control_names) == 23)
    HEX.require(hashlib.sha256(Path(__file__).read_bytes()).hexdigest() == driver_pin)
    child_report = children.report()
    bindings["current_execution_inputs"]["run_file_controls.py"] = driver_pin
    report = {
        "format_version": 1, "kind": "selected-target-hex-execution",
        "source_revision": args.source_revision, "program": selected, "mode": args.mode,
        "tests_run": result.testsRun, "control_names": control_names,
        "selected_function_identities_restored": True, "checks_completed": True,
        "binding_manifest": bindings,
    }
    print(json.dumps(child_report, sort_keys=True, separators=(",", ":")))
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError, OverflowError, RecursionError):
        print("Selected file controls refused; no complete execution recipe is qualified.", file=sys.stderr)
        sys.exit(1)
