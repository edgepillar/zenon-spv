#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Run all original cache rollback controls with explicit optional Git tree reuse."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
import unittest

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
HELPER = HERE.parent / "conformance_tree_reuse.py"
HELPER_SHA256 = "67376363b71d9e079ad0197c814fd478d2eef79e56e75d4763c5fb4ccf87a788"
PROGRAM = "check_cache_identifier_rollback_test.py"
METHODS = (
    "test_boolean_and_numeric_types_are_distinct",
    "test_complete_parent_and_candidate_recording",
    "test_complete_runtime_build_trees_probe_and_modules_bound",
    "test_correct_retained_target_still_rolls_back_and_reopens",
    "test_duplicate_nonfinite_and_oversize_json_refused",
    "test_exact_case_generation_order_and_stage_inventory",
    "test_exit_completeness_timeout_and_terminal_marker_required",
    "test_fixed_mismatches_cannot_become_ready",
    "test_independent_protobuf_batch_and_ordered_metadata_images",
    "test_native_unit_and_binary_evidence_cannot_be_inflated",
    "test_node_internal_control_sources_are_noncompiled_containers",
    "test_parent_defect_cannot_be_rewritten_as_a_refusal",
    "test_reader_cannot_launch_backend_or_network",
    "test_refusal_preserves_all_explicit_fault_metadata",
    "test_refused_queries_return_no_state_value_or_proof",
    "test_scope_and_consumer_cannot_claim_acceptance_or_atomicity",
    "test_stdout_and_private_stderr_references_bound",
    "test_whole_file_and_source_label_required",
)


def require(value):
    if not value:
        raise ValueError("Complete cache rollback controls refused")


def pinned_helper():
    raw = source_bytes(HELPER)
    require(hashlib.sha256(raw).hexdigest() == HELPER_SHA256)
    spec = importlib.util.spec_from_file_location("selected_git_tree_reuse", HELPER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def source_bytes(path):
    require(path.is_file() and not path.is_symlink())
    with path.open("rb") as stream:
        raw = stream.read((1 << 20) + 1)
    require(0 < len(raw) <= 1 << 20)
    return raw


def test_ids(suite):
    if isinstance(suite, unittest.TestSuite):
        return [name for child in suite for name in test_ids(child)]
    return [suite.id().split(".", 1)[1]]


def complete_suite(program):
    suite = unittest.defaultTestLoader.loadTestsFromModule(program)
    expected = ["CacheIdentifierRecordingTests." + method for method in METHODS]
    require(test_ids(suite) == expected and suite.countTestCases() == len(METHODS) == 18)
    return suite, expected


def run_suite(suite):
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    require(result.testsRun == len(METHODS) and result.wasSuccessful())
    require(not result.skipped and not result.expectedFailures and not result.unexpectedSuccesses)
    return result


def revision(value):
    if type(value) is not str or re.fullmatch("[0-9a-f]{40}", value) is None:
        raise argparse.ArgumentTypeError("expected a full lowercase source revision")
    return value


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("direct", "bounded"), required=True)
    parser.add_argument("--source-revision", type=revision, required=True)
    args = parser.parse_args(argv)
    own = Path(__file__).resolve()
    own_pin = hashlib.sha256(source_bytes(own)).hexdigest()
    helper = pinned_helper()
    inputs = helper.verify_sources()
    spec = importlib.util.spec_from_file_location("complete_cache_rollback_controls", HERE / PROGRAM)
    program = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = program
    try:
        spec.loader.exec_module(program)
        seams, _ = helper.selected_seams(program)
        suite, identities = complete_suite(program)
        if args.mode == "bounded":
            with helper.reuse(program) as scope:
                result = run_suite(suite)
                original_report = program.C.check_file(HERE / "testdata" / program.C.CORPUS)
            execution = scope.report()
            require(execution["original_functions_restored"] and execution["cache_cleared"])
        else:
            result = run_suite(suite)
            original_report = program.C.check_file(HERE / "testdata" / program.C.CORPUS)
            execution = {
                "source_pins": inputs, "selected_instances": [name for name, _, _ in seams],
                "cache": None, "original_functions_restored": True, "cache_cleared": True,
                "source_validation_cached": False, "reference_backend_executions": 0,
                "production_acceptance_enabled": False,
            }
        require(helper.verify_sources() == inputs)
        require(hashlib.sha256(source_bytes(own)).hexdigest() == own_pin)
        require(hashlib.sha256(source_bytes(HELPER)).hexdigest() == HELPER_SHA256)
        print(json.dumps({
            "format": "complete-cache-rollback-git-tree-reuse/v1",
            "source_revision": args.source_revision, "mode": args.mode, "program": PROGRAM,
            "runner_sha256": own_pin, "helper_sha256": HELPER_SHA256,
            "complete_control_inventory": identities, "actual_controls": result.testsRun,
            "skips": len(result.skipped), "failures": len(result.failures), "errors": len(result.errors),
            "original_control_source_unchanged": True, "source_validation_cached": False,
            "original_reader_report": original_report,
            "execution": execution, "reference_backend_executions": 0,
            "new_transports": 0, "production_acceptance_enabled": False,
        }, sort_keys=True))
    finally:
        sys.modules.pop(spec.name, None)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError, OverflowError, RecursionError):
        print("Complete cache rollback controls refused; production acceptance stays disabled.", file=sys.stderr)
        raise SystemExit(1)
