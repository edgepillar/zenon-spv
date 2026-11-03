#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""In-memory runner, failure and output controls; no node or Go execution."""
import copy
import importlib.util
import io
import json
from pathlib import Path
from types import ModuleType, SimpleNamespace
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location(
    "recorded_receipt_runner", Path(__file__).with_name("record-batch-entry-replay.py"))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


def sample_suite(mode="passed", count=23, phase=None):
    def first(self):
        if mode == "failed":
            self.fail("fixture failure")
        if mode == "errored":
            raise RuntimeError("fixture error")
        if mode == "skipped":
            self.skipTest("fixture skip")
        if mode in ("expected_failure", "unexpected_success"):
            self.assertEqual(mode, "unexpected_success")
        if mode.startswith("subtest"):
            for n in range(2):
                with self.subTest(n=n):
                    if n == 0 and mode == "subtest_failed":
                        self.fail("fixture subtest failure")
                    if n == 0 and mode == "subtest_errored":
                        raise RuntimeError("fixture subtest error")
    if mode in ("expected_failure", "unexpected_success"):
        first = unittest.expectedFailure(first)
    methods = {"__module__": "recorded_receipt_controls"}
    for n in range(count):
        methods["test_%02d" % n] = first if n == 0 else lambda self: None
    if phase is not None:
        def error(cls):
            raise RuntimeError("fixture class error")
        methods[phase] = classmethod(error)
    case = type("SampleTests", (unittest.TestCase,), methods)
    return unittest.TestSuite(case("test_%02d" % n) for n in range(count))


class RunnerTests(unittest.TestCase):
    def run_fixture(self, mode="passed", **kwargs):
        return runner.run_controls(sample_suite(mode, **kwargs), io.StringIO())

    def test_success_names_every_actual_root(self):
        report, passed = self.run_fixture()
        self.assertTrue(passed)
        self.assertEqual(report["selected_roots"], 23)
        self.assertEqual(report["started_roots"], 23)
        self.assertEqual(len({row["id"] for row in report["cases"]}), 23)
        self.assertTrue(all(row["status"] == "passed" for row in report["cases"]))

    def test_failure_error_skip_and_expected_outcomes_are_not_passes(self):
        for status in ("failed", "errored", "skipped", "expected_failure", "unexpected_success"):
            with self.subTest(status=status):
                report, passed = self.run_fixture(status)
                self.assertFalse(passed)
                self.assertEqual(report["cases"][0]["status"], status)
                self.assertEqual(report["started_roots"], 23)
                self.assertTrue(report["completed"])

    def test_subtest_successes_are_separate_from_roots(self):
        report, passed = self.run_fixture("subtests")
        self.assertTrue(passed)
        self.assertEqual(report["subtests"], {"passed": 2, "failed": 0, "errored": 0})
        self.assertEqual(len(report["cases"]), 23)

    def test_subtest_failure_and_error_refuse_success(self):
        for mode, status in [("subtest_failed", "failed"), ("subtest_errored", "errored")]:
            with self.subTest(mode=mode):
                report, passed = self.run_fixture(mode)
                self.assertFalse(passed)
                self.assertEqual(report["cases"][0]["status"], status)
                self.assertEqual(report["subtests"][status], 1)
                self.assertEqual(report["subtests"]["passed"], 1)

    def test_class_setup_error_has_no_started_roots(self):
        report, passed = self.run_fixture(phase="setUpClass")
        self.assertFalse(passed)
        self.assertEqual(report["started_roots"], 0)
        self.assertEqual(report["cases"], [])
        self.assertEqual(report["phase_error_events"], 1)
        self.assertEqual(report["error_events"], 1)

    def test_class_teardown_error_preserves_completed_roots(self):
        report, passed = self.run_fixture(phase="tearDownClass")
        self.assertFalse(passed)
        self.assertEqual(report["started_roots"], 23)
        self.assertTrue(all(row["status"] == "passed" for row in report["cases"]))
        self.assertEqual(report["phase_error_events"], 1)
        self.assertEqual(report["error_events"], 1)

    def test_stopped_identity_cannot_relabel_a_completed_root(self):
        result = unittest.TextTestRunner(
            stream=io.StringIO(), verbosity=2, resultclass=runner.ReceiptResult)._makeResult()
        case = sample_suite()._tests[0]
        result.startTest(case)
        result.addSuccess(case)
        result.stopTest(case)
        result.mark(case, "errored")
        self.assertEqual(result.cases[0]["status"], "passed")
        self.assertEqual(result.phase_error_events, 1)

    def test_empty_partial_and_expanded_selections_refuse(self):
        for count in (0, 22, 24):
            with self.subTest(count=count), self.assertRaises(ValueError):
                runner.run_controls(sample_suite(count=count), io.StringIO())

    def test_duplicate_selected_ids_refuse_before_execution(self):
        case = sample_suite()._tests[0].__class__
        suite = unittest.TestSuite(case("test_00") for _ in range(23))
        diagnostics = io.StringIO()
        with self.assertRaises(ValueError):
            runner.run_controls(suite, diagnostics)
        self.assertEqual(diagnostics.getvalue(), "")

    def test_diagnostics_limit_checks_before_writing(self):
        output = io.StringIO()
        stream = runner.BoundedDiagnostics(output)
        self.assertEqual(stream.write("x" * runner.DIAGNOSTIC_LIMIT), runner.DIAGNOSTIC_LIMIT)
        with self.assertRaises(ValueError):
            stream.write("x")
        self.assertEqual(len(output.getvalue()), runner.DIAGNOSTIC_LIMIT)

    def test_short_diagnostic_write_is_not_accepted(self):
        class Short(io.StringIO):
            def write(self, value):
                return super().write(value[:-1])
        with self.assertRaises(ValueError):
            runner.BoundedDiagnostics(Short()).write("diagnostic")

    def fake_controls(self, mode="passed", math=None):
        module = ModuleType("recorded_receipt_controls")
        module.SampleTests = sample_suite(mode)._tests[0].__class__
        module.replay = SimpleNamespace(
            check_corpus=lambda *args: copy.deepcopy(runner.MATH if math is None else math),
            read_corpus=lambda: {},
            HARNESS=SimpleNamespace(read_bytes=lambda: b"fixture"))
        return module

    def build(self, mode="passed", changed=False, math=None):
        inputs = [{"path": name, "bytes": 1, "sha256": "1" * 64} for name in runner.INPUTS]
        after = copy.deepcopy(inputs)
        if changed:
            after[0]["sha256"] = "2" * 64
        with mock.patch.object(runner, "current_platform", return_value="linux-amd64"), \
                mock.patch.object(runner, "source_snapshot", side_effect=[inputs, after]), \
                mock.patch.object(runner, "load_controls", return_value=self.fake_controls(mode, math)):
            return runner.build_receipt("1" * 40, "linux-amd64", io.StringIO())

    def test_receipt_separates_consistency_from_execution_authority(self):
        report = self.build()
        self.assertEqual(report["status"], "passed")
        self.assertEqual(report["byte_replay"], runner.MATH)
        self.assertFalse(report["execution_provenance_authenticated"])
        self.assertFalse(report["production_qualified"])
        self.assertLess(len(json.dumps(report).encode()), runner.RECEIPT_LIMIT)

    def test_source_change_withholds_success(self):
        report = self.build(changed=True)
        self.assertEqual(report["status"], "failed")
        self.assertFalse(report["source_unchanged_after"])
        self.assertTrue(all(row["status"] == "passed" for row in report["tests"]["cases"]))

    def test_bad_or_relabelled_math_withholds_success(self):
        for field, value in [("headers", 2), ("production_qualified", True), ("production_qualified", 0)]:
            with self.subTest(field=field, value=value):
                math = copy.deepcopy(runner.MATH)
                math[field] = value
                self.assertEqual(self.build(math=math)["status"], "failed")

    def test_failed_controls_still_retain_math_and_root_outcomes(self):
        report = self.build("failed")
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["byte_replay"], runner.MATH)
        self.assertEqual(report["tests"]["failure_events"], 1)

    def test_wrong_platform_and_revision_precede_source_reads(self):
        with mock.patch.object(runner, "source_snapshot") as snapshot, \
                mock.patch.object(runner, "current_platform", return_value="linux-amd64"):
            for revision, platform in [("0" * 40, "linux-amd64"), ("1" * 40, "darwin-amd64")]:
                with self.subTest(revision=revision, platform=platform), self.assertRaises(ValueError):
                    runner.build_receipt(revision, platform, io.StringIO())
            snapshot.assert_not_called()

    def invoke(self, receipt, output=None):
        output = io.StringIO() if output is None else output
        diagnostics = io.StringIO()
        with mock.patch.object(runner, "build_receipt", return_value=receipt) as build:
            code = runner.main(["--source-revision", "1" * 40, "--expect-platform", "linux-amd64"],
                               output, diagnostics)
        return code, output, diagnostics, build.call_count

    def test_failed_receipt_has_nonzero_exit_and_complete_document(self):
        code, output, _, calls = self.invoke({"status": "failed"})
        self.assertEqual((code, calls), (1, 1))
        self.assertEqual(json.loads(output.getvalue()), {"status": "failed"})

    def test_short_output_exits_without_retry(self):
        class Short(io.StringIO):
            def write(self, value):
                return super().write(value[:-1])
        code, output, _, calls = self.invoke({"status": "passed"}, Short())
        self.assertEqual((code, calls), (70, 1))
        self.assertNotEqual(output.getvalue(), '{"status":"passed"}\n')

    def test_flush_failure_is_not_success_even_with_written_body(self):
        class BrokenFlush(io.StringIO):
            def flush(self):
                raise OSError("fixture flush")
        code, output, _, calls = self.invoke({"status": "passed"}, BrokenFlush())
        self.assertEqual((code, calls), (70, 1))
        self.assertEqual(json.loads(output.getvalue())["status"], "passed")

    def test_oversized_receipt_is_not_written(self):
        code, output, _, calls = self.invoke({"status": "passed", "padding": "x" * runner.RECEIPT_LIMIT})
        self.assertEqual((code, calls), (70, 1))
        self.assertEqual(output.getvalue(), "")

    def test_bad_invocation_does_not_echo_inputs_or_run_controls(self):
        diagnostics, output = io.StringIO(), io.StringIO()
        with mock.patch.object(runner, "build_receipt") as build:
            code = runner.main(["--source-revision", "/private/DO_NOT_PRINT",
                                "--expect-platform", "linux-amd64"], output, diagnostics)
            build.assert_not_called()
        self.assertEqual(code, 64)
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(diagnostics.getvalue(), "recorded replay: invalid invocation\n")

    def test_operational_failure_does_not_echo_private_paths(self):
        diagnostics, output = io.StringIO(), io.StringIO()
        with mock.patch.object(runner, "build_receipt", side_effect=OSError("/private/DO_NOT_PRINT")):
            code = runner.main(["--source-revision", "1" * 40, "--expect-platform", "linux-amd64"],
                               output, diagnostics)
        self.assertEqual(code, 70)
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(diagnostics.getvalue(), "recorded replay: input, execution or output failed\n")


if __name__ == "__main__":
    unittest.main()
