#!/usr/bin/env python3
"""Controls for the independent, bounded consumer comparison oracle."""

import copy
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location("consumer_oracle", Path(__file__).with_name("check-query-consumer.py"))
oracle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(oracle)


class OracleControls(unittest.TestCase):
    def test_all_selected_decisions_are_pinned(self):
        cases = oracle.cases()
        self.assertEqual(len({case["id"] for case in cases}), len(cases))
        for case in cases:
            with self.subTest(case=case["id"]):
                self.assertEqual(oracle.consume(case["report"], case["expectations"], case["process_exit"]), case["wanted"])

    def test_original_corpus_remains_byte_identical(self):
        pins = [{"id": case["id"], "exit_code": case["wanted"][0], "process_exit": case["process_exit"],
                 "report_sha256": hashlib.sha256(case["report"]).hexdigest(),
                 "expectations_sha256": hashlib.sha256(case["expectations"]).hexdigest(),
                 "summary_sha256": hashlib.sha256(case["wanted"][1]).hexdigest()}
                for case in oracle.pinned_cases()]
        self.assertEqual(len(pins), 98)
        self.assertEqual(hashlib.sha256(json.dumps(pins, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
                         "34b6e3338b17a070201af308b2714c97839052dfbaaf4cfcd198442a3a3bd6f1")

    def test_generated_programs_are_deterministic_and_complete(self):
        first, second = oracle.generated_cases(), oracle.generated_cases()
        self.assertEqual(first, second)
        self.assertEqual(len(first), 640)
        self.assertEqual(len({case["id"] for case in first}), 640)
        self.assertEqual(sum(case["wanted"][0] == 0 for case in first), 64)
        self.assertEqual(sum(case["wanted"][0] == 2 for case in first), 576)
        self.assertEqual(len(oracle.cases()), 738)
        groups = {}
        for case in first:
            program, variant = case["id"].split("_seed", 1)
            seed, variant = variant.split("_", 1)
            groups.setdefault((program, seed), set()).add(variant)
        self.assertEqual(len(groups), 32)
        self.assertTrue(all(variants == set(oracle.GENERATED_VARIANTS) for variants in groups.values()))

    def test_generated_wire_forms_and_boundary_identities(self):
        heights, segment_blocks, counts, producer_sources = set(), set(), set(), set()
        addresses = set()
        for command in ("verify-commitment", "verify-segment"):
            for version in (1, 2):
                for index in range(len(oracle.GENERATED_SEEDS)):
                    report, expected = oracle.generated_inputs(command, version, index)
                    counts.add(len(expected["targets"]))
                    context = report["verification_context"]
                    producer_sources.add(context["producer"]["source"])
                    if version == 2:
                        self.assertLess(context["policy"]["w"], context["policy"]["retain_headers"])
                    self.assertEqual(json.loads(oracle.wire_equivalent(report)), report)
                    self.assertEqual(json.loads(oracle.wire_equivalent(expected)), expected)
                    for ref in expected["targets"]:
                        heights.add(ref["account_header"]["height"])
                        addresses.add(ref["account_header"]["address"])
                        if command == "verify-segment":
                            segment_blocks.add(ref["block_index"])
                    if command == "verify-segment" and len(expected["targets"]) > 1:
                        self.assertEqual(len({ref["index"] for ref in expected["targets"]}), 1)
                        self.assertEqual(len({ref["block_index"] for ref in expected["targets"]}), len(expected["targets"]))
        self.assertEqual(counts, {1, 3, 17, 64})
        self.assertTrue({0, (1 << 53) + 1, oracle.I64_MAX, 1 << 63, oracle.U64_MAX} <= heights)
        self.assertTrue({0, oracle.I64_MAX} <= segment_blocks)
        self.assertEqual(producer_sources, {"None", "OperatorAttested", "LocallyDerivedFromChain"})
        self.assertGreater(len(addresses), 256)

    def test_generated_last_row_refusals_are_independently_pinned(self):
        valid = {case["id"].removesuffix("_valid"): case for case in oracle.generated_cases()
                 if case["id"].endswith("_valid")}
        checked = 0
        for case in oracle.generated_cases():
            for variant in ("account_hash", "account_height", "required_guarantee", "row_trust"):
                suffix = "_" + variant
                if not case["id"].endswith(suffix):
                    continue
                prefix = case["id"].removesuffix(suffix)
                baseline = json.loads(valid[prefix]["report"])
                changed = json.loads(case["report"])
                self.assertNotEqual(changed["results"][-1], baseline["results"][-1])
                self.assertEqual(changed["results"][:-1], baseline["results"][:-1])
                self.assertNotEqual(case["wanted"][0], 0)
                checked += 1
        self.assertEqual(checked, 128)

    def test_replay_counts_only_selected_actual_comparisons(self):
        case = oracle.generated_cases()[19]
        called = []
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "trusted-synthetic-consumer"
            executable.write_bytes(b"synthetic executable identity")

            def child(args, **kwargs):
                called.append(args)
                self.assertEqual(kwargs["timeout"], 10)
                self.assertEqual(Path(args[2]).read_bytes(), case["report"])
                self.assertEqual(Path(args[4]).read_bytes(), case["expectations"])
                return subprocess.CompletedProcess(args, case["wanted"][0], case["wanted"][1], b"")

            with mock.patch.object(oracle.subprocess, "run", side_effect=child):
                result = oracle.compare(executable, "a" * 40, case["id"])
            self.assertEqual(len(called), 1)
            self.assertEqual(result["case_selection"], case["id"])
            self.assertEqual([row["id"] for row in result["cases"]], [case["id"]])
            self.assertEqual(result["comparison_counts"], {"selected": 1, "reference_checked": 1,
                             "consumer_attempted": 1, "consumer_compared": 1, "skipped": 0, "not_selected": 737})
            with mock.patch.object(oracle.subprocess, "run") as child:
                with self.assertRaises(oracle.Invalid):
                    oracle.compare(executable, "a" * 40, "unselected-private-input")
                child.assert_not_called()

    def test_failure_counters_and_diagnostics_do_not_hide_or_leak_results(self):
        case = oracle.generated_cases()[2]
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "trusted-synthetic-consumer"
            executable.write_bytes(b"synthetic executable identity")
            failures = (
                (subprocess.CompletedProcess([], 0, oracle.summary(count=1, code=0)[1], b"private-child-diagnostic"),
                 "compiled_decision", 1),
                (subprocess.TimeoutExpired("private-command", 10, output=b"private-output"), "child_run", 0),
            )
            for failure, stage, compared in failures:
                with self.subTest(stage=stage):
                    patch = {"side_effect": failure} if isinstance(failure, Exception) else {"return_value": failure}
                    with mock.patch.object(oracle.subprocess, "run", **patch):
                        with self.assertRaises(oracle.ComparisonFailure) as caught:
                            oracle.compare(executable, "a" * 40, case["id"])
                    details = caught.exception.details
                    self.assertEqual(details["case_id"], case["id"])
                    self.assertEqual(details["stage"], stage)
                    self.assertEqual(details["comparison_counts"]["consumer_attempted"], 1)
                    self.assertEqual(details["comparison_counts"]["consumer_compared"], compared)
                    self.assertEqual(details["comparison_counts"]["skipped"], 0)
                    self.assertNotIn("private", json.dumps(details))
                    self.assertNotIn(directory, json.dumps(details))

    def comparison_fault(self, completed=None, cleanup_error=None, creation_error=None, effect=None):
        case = oracle.generated_cases()[2]
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "PRIVATE_CONSUMER"
            executable.write_bytes(b"fixed executable identity")
            class Temporary:
                name = directory
                def __enter__(self): return self.name
                def __exit__(self, *_): self.cleanup()
                def cleanup(self):
                    if cleanup_error is not None: raise cleanup_error
            factory = mock.Mock(side_effect=creation_error, return_value=Temporary())
            result = completed or subprocess.CompletedProcess([], case["wanted"][0], case["wanted"][1], b"")
            options = {"side_effect": effect} if effect is not None else {"return_value": result}
            with mock.patch.object(oracle.tempfile, "TemporaryDirectory", factory), \
                    mock.patch.object(oracle.subprocess, "run", **options) as child:
                try:
                    oracle.compare(executable, "a" * 40, case["id"])
                except BaseException as error:
                    return error, child.call_count, factory
            self.fail("fault did not interrupt comparison")

    def test_completed_refusal_retains_actual_exit_and_private_byte_hashes(self):
        result = subprocess.CompletedProcess([], -9, b"PRIVATE_STDOUT", b"PRIVATE_STDERR")
        error, attempted, _ = self.comparison_fault(completed=result)
        self.assertIsInstance(error, oracle.ComparisonFailure)
        self.assertEqual(attempted, 1)
        self.assertEqual(error.details["stage"], "compiled_decision")
        self.assertEqual(error.details["comparison_counts"]["consumer_compared"], 1)
        self.assertEqual(error.details["process_outcomes"], [{
            "case_id": oracle.generated_cases()[2]["id"], "role": "consumer", "completed": True,
            "actual_exit": -9, "stdout_bytes": len(result.stdout), "stderr_bytes": len(result.stderr),
            "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(),
            "stderr_sha256": hashlib.sha256(result.stderr).hexdigest(),
        }])
        self.assertNotIn("PRIVATE", json.dumps(error.details))

    def test_incomplete_process_has_no_asserted_completed_exit_or_partial_hashes(self):
        for cause in (OSError("PRIVATE_ERROR"), subprocess.SubprocessError("PRIVATE_ERROR"),
                      subprocess.TimeoutExpired("PRIVATE_COMMAND", 10, output=b"PRIVATE_PARTIAL", stderr=b"PRIVATE_PARTIAL")):
            with self.subTest(cause=type(cause).__name__):
                error, attempted, _ = self.comparison_fault(effect=cause)
                self.assertIsInstance(error, oracle.ComparisonFailure)
                self.assertEqual(attempted, 1)
                self.assertEqual(error.details["stage"], "child_run")
                self.assertEqual(error.details["comparison_counts"]["consumer_compared"], 0)
                self.assertEqual(error.details["process_outcomes"], [{"case_id": oracle.generated_cases()[2]["id"],
                                 "role": "consumer", "completed": False, "actual_exit": None}])
                self.assertNotIn("PRIVATE", json.dumps(error.details))

    def test_deleted_input_after_completion_retains_structured_evidence(self):
        case = oracle.generated_cases()[2]
        def child(arguments, **_):
            Path(arguments[2]).unlink()
            return subprocess.CompletedProcess([], case["wanted"][0], case["wanted"][1], b"")
        error, attempted, _ = self.comparison_fault(effect=child)
        self.assertIsInstance(error, oracle.ComparisonFailure)
        self.assertEqual(attempted, 1)
        self.assertEqual(error.details["stage"], "input_or_shape")
        self.assertEqual(error.details["comparison_counts"]["consumer_compared"], 1)
        self.assertEqual(error.details["process_outcomes"][0]["stdout_sha256"], hashlib.sha256(case["wanted"][1]).hexdigest())
        self.assertNotIn("PRIVATE", json.dumps(error.details))

    def test_input_permission_failure_precedes_child_attempt(self):
        original = Path.chmod
        def chmod(path, *args, **kwargs):
            if path.name == "report.json": raise PermissionError("PRIVATE_INPUT_MODE")
            return original(path, *args, **kwargs)
        with mock.patch.object(Path, "chmod", chmod):
            error, attempted, _ = self.comparison_fault()
        self.assertIsInstance(error, oracle.ComparisonFailure)
        self.assertEqual(attempted, 0)
        self.assertEqual(error.details["comparison_counts"]["reference_checked"], 1)
        self.assertEqual(error.details["comparison_counts"]["consumer_attempted"], 0)
        self.assertEqual(error.details["process_outcomes"], [])

    def test_final_executable_read_preserves_completed_case_evidence(self):
        original, reads = Path.read_bytes, []
        def read(path):
            if path.name == "PRIVATE_CONSUMER":
                reads.append(path)
                if len(reads) == 2: raise OSError("PRIVATE_BINARY_REREAD")
            return original(path)
        with mock.patch.object(Path, "read_bytes", read):
            error, attempted, _ = self.comparison_fault()
        self.assertIsInstance(error, oracle.ComparisonFailure)
        self.assertEqual(attempted, 1)
        self.assertEqual(error.details["comparison_counts"]["consumer_compared"], 1)
        self.assertEqual(len(error.details["process_outcomes"]), 1)
        self.assertEqual(error.details["stage"], "input_or_shape")
        self.assertNotIn("PRIVATE", json.dumps(error.details))

    def test_final_oracle_read_preserves_completed_case_evidence(self):
        original = Path.read_bytes
        def read(path):
            if path == Path(oracle.__file__): raise OSError("PRIVATE_ORACLE_REREAD")
            return original(path)
        with mock.patch.object(Path, "read_bytes", read):
            error, attempted, _ = self.comparison_fault()
        self.assertIsInstance(error, oracle.ComparisonFailure)
        self.assertEqual(attempted, 1)
        self.assertEqual(error.details["comparison_counts"]["consumer_compared"], 1)
        self.assertEqual(len(error.details["process_outcomes"]), 1)
        self.assertEqual(error.details["stage"], "input_or_shape")

    def test_cleanup_failure_after_matching_case_has_structured_counts(self):
        error, attempted, _ = self.comparison_fault(cleanup_error=PermissionError("PRIVATE_CLEANUP"))
        self.assertIsInstance(error, oracle.ComparisonFailure)
        self.assertEqual(attempted, 1)
        self.assertEqual(error.details["stage"], "temporary_cleanup")
        self.assertEqual(error.details["comparison_counts"]["consumer_compared"], 1)
        self.assertEqual(len(error.details["process_outcomes"]), 1)
        self.assertEqual(error.details["cleanup_failures"], [])
        self.assertNotIn("PRIVATE", json.dumps(error.details))

    def test_cleanup_keeps_primary_compiled_refusal_and_completion(self):
        result = subprocess.CompletedProcess([], 0, b"PRIVATE_WRONG_RESULT", b"")
        error, attempted, _ = self.comparison_fault(completed=result, cleanup_error=OSError("PRIVATE_CLEANUP"))
        self.assertIsInstance(error, oracle.ComparisonFailure)
        self.assertEqual(attempted, 1)
        self.assertEqual(error.details["stage"], "compiled_decision")
        self.assertEqual(error.details["cleanup_failures"], ["temporary_cleanup"])
        self.assertEqual(error.details["comparison_counts"]["consumer_compared"], 1)
        self.assertEqual(error.details["process_outcomes"][0]["actual_exit"], 0)
        self.assertNotIn("PRIVATE", json.dumps(error.details))

    def test_cleanup_preserves_cancellation_and_unexpected_programming_error(self):
        for cause in (KeyboardInterrupt(), RuntimeError("PRIVATE_PROGRAMMING_ERROR")):
            with self.subTest(cause=type(cause).__name__):
                error, attempted, _ = self.comparison_fault(effect=cause, cleanup_error=OSError("PRIVATE_CLEANUP"))
                self.assertIs(error, cause)
                self.assertEqual(attempted, 1)

    def test_directory_creation_failure_has_no_child_attempt(self):
        error, attempted, factory = self.comparison_fault(creation_error=PermissionError("PRIVATE_SETUP"))
        self.assertIsInstance(error, oracle.ComparisonFailure)
        self.assertEqual(attempted, 0)
        self.assertEqual(error.details["comparison_counts"]["consumer_attempted"], 0)
        self.assertEqual(error.details["process_outcomes"], [])
        factory.assert_called_once()

    def test_cli_emits_only_structured_failure_after_completed_process(self):
        case = oracle.generated_cases()[2]
        stderr, stdout = io.StringIO(), io.StringIO()
        def child(arguments, **_):
            Path(arguments[2]).unlink()
            return subprocess.CompletedProcess([], case["wanted"][0], case["wanted"][1], b"")
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "PRIVATE_CONSUMER"
            executable.write_bytes(b"fixed identity")
            arguments = ["checker", "--consumer", str(executable), "--source-revision", "a" * 40, "--case", case["id"]]
            with mock.patch.object(sys, "argv", arguments), mock.patch.object(oracle.subprocess, "run", side_effect=child), \
                    contextlib.redirect_stderr(stderr), contextlib.redirect_stdout(stdout):
                with self.assertRaises(SystemExit) as failed: oracle.main()
        self.assertEqual(failed.exception.code, 1)
        self.assertEqual(stdout.getvalue(), "")
        details = json.loads(stderr.getvalue())
        self.assertEqual(details["status"], "comparison_failed")
        self.assertEqual(details["comparison_counts"]["consumer_compared"], 1)
        self.assertEqual(len(details["process_outcomes"]), 1)
        self.assertNotIn("PRIVATE", stderr.getvalue())

    def test_published_context_vectors(self):
        root = Path(__file__).resolve().parents[1] / "internal/testdata/verification-context"
        vectors = sorted(root.glob("*.json"))
        self.assertGreaterEqual(len(vectors), 2)
        for vector in vectors:
            with self.subTest(vector=vector.name):
                context = json.loads(vector.read_bytes())
                self.assertEqual(oracle.context_fingerprint(context), context["fingerprint"])

    def test_decoded_duplicate_keys(self):
        for raw in (b'{"x":0,"x":1}', b'{"x":0,"\\u0078":1}', b'{"\\ud800":0,"\\udfff":1}'):
            with self.subTest(raw=raw):
                with self.assertRaises(oracle.Invalid):
                    oracle.bounded_json(raw)

    def test_unicode_normalization_and_byte_bounds(self):
        self.assertEqual(oracle.bounded_json(b'["\\ud800","\\udfff","\\ud83d\\ude80"]'), ["\ufffd", "\ufffd", "\U0001f680"])
        oracle.bounded_json(oracle.encoded(["\U0001f680" * 1024]))
        with self.assertRaises(oracle.Invalid):
            oracle.bounded_json(oracle.encoded(["\U0001f680" * 1025]))

    def test_depth_and_value_boundaries(self):
        oracle.bounded_json(b"[" * 16 + b"0" + b"]" * 16)
        with self.assertRaises(oracle.Invalid):
            oracle.bounded_json(b"[" * 17 + b"0" + b"]" * 17)
        values = [[0] * 127 for _ in range(128)]
        values[0].pop()
        oracle.bounded_json(oracle.encoded(values))  # 16,384 values including containers.
        values[0].append(0)
        with self.assertRaises(oracle.Invalid):
            oracle.bounded_json(oracle.encoded(values))

    def test_object_array_and_key_boundaries(self):
        for value in ([0] * 256, {str(i): 0 for i in range(256)}, {"x" * 128: 0}):
            oracle.bounded_json(oracle.encoded(value))
        for value in ([0] * 257, {str(i): 0 for i in range(257)}, {"x" * 129: 0}):
            with self.assertRaises(oracle.Invalid):
                oracle.bounded_json(oracle.encoded(value))

    def test_lexical_and_typed_integer_boundaries(self):
        for token in (b"-0", b"0.0", b"0e0", b"NaN", b"1" * 22):
            with self.assertRaises(oracle.Invalid):
                oracle.bounded_json(token)
        for kind, low, high in (("u32", 0, (1 << 32) - 1), ("u64", 0, oracle.U64_MAX),
                                ("i64", -(1 << 63), oracle.I64_MAX)):
            for value in (low, high):
                self.assertEqual(oracle.typed(oracle.JSONInteger(str(value)), kind), value)
            for value in (low - 1, high + 1):
                with self.assertRaises(oracle.Invalid):
                    oracle.typed(oracle.JSONInteger(str(value)), kind)
        with self.assertRaises(oracle.Invalid):
            oracle.typed(True, "u64")

    def test_optional_required_and_nullable_shapes(self):
        schema = {"required": "u64", "optional": ("optional", "u64"), "nullable": ("nullable", "text")}
        self.assertEqual(oracle.decode(b'{"required":0,"nullable":null}', schema), {"required": 0, "nullable": None})
        for raw in (b'{"required":null,"nullable":null}', b'{"required":0,"optional":null,"nullable":null}',
                    b'{"nullable":null}', b'{"required":0,"Nullable":null}'):
            with self.assertRaises(oracle.Invalid):
                oracle.decode(raw, schema)

    def test_fingerprint_change_is_detected(self):
        report, _ = oracle.selected_inputs()
        context = report["verification_context"]
        self.assertTrue(oracle.valid_context(context))
        for field in ("w", *oracle.LIMITS, "retain_headers"):
            changed = copy.deepcopy(context)
            changed["policy"][field] += 1
            self.assertFalse(oracle.valid_context(changed))

    def test_status_precedes_every_input(self):
        self.assertEqual(oracle.consume(b"not JSON", b"not JSON", -9), oracle.summary("process_failure"))
        for value in (True, -(1 << 63) - 1, 1 << 63):
            with self.assertRaises(oracle.Invalid):
                oracle.consume(b"", b"", value)

    def test_permissive_match_mutant_is_detected(self):
        original = oracle.match
        try:
            oracle.match = lambda report, expected: None
            for case in oracle.cases():
                if case["id"] in {"missing_target", "wrong_hash", "wrong_expected_pin", "missing_required_guarantee"}:
                    with self.subTest(case=case["id"]):
                        self.assertNotEqual(oracle.consume(case["report"], case["expectations"], case["process_exit"]), case["wanted"])
        finally:
            oracle.match = original


if __name__ == "__main__":
    unittest.main()
