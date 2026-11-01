#!/usr/bin/env python3
"""Finite receipt consistency controls; real execution remains a CI gate."""
import copy
import importlib.util
import io
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("root_suite_checker", HERE / "check-root-suite.py")
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


def fixture():
    report = {"status": "passed", "source": {"revision": "a" * 40, "modified": False, "inputs_sha256": "b" * 64},
              "test_parent_race_enabled": True,
              "cases": [{"package": "internal/conformance", "passed_subtests": 3, "skipped_subtests": 0}]}
    receipt = {"format": "zenon-root-suite/v1", "status": "passed", "error": None, "source": copy.deepcopy(report["source"]),
               "source_matches_after_run": True, "test_parent_race_enabled": True, "coverage_enabled": True,
               "package_timeout": "10m0s", "overall_timeout": "30m0s", "package_inventory_succeeded": True,
               "test_process_succeeded": True, "stream_complete": True, "stream_bytes": 5000, "stream_sha256": "c" * 64,
               "packages": [{"package": CHECKER.MODULE + "/cmd/no-tests", "status": "skip"},
                            {"package": CHECKER.MODULE + "/internal/conformance", "status": "pass"}],
               "tests": {"root_tests": 4, "subtests": 8, "passed": 11, "skipped": 1, "failed": 0},
               "selected_scenarios": 1, "selected_report_sha256": "d" * 64}
    return receipt, report


class RootSuiteControls(unittest.TestCase):
    def check(self, receipt, report):
        CHECKER.check_receipt(receipt, report, True, True, "10m0s", "30m0s")

    def test_complete_receipt_and_unselected_skip(self):
        self.check(*fixture())

    def test_completion_source_and_policy_refusals(self):
        for key, values in {
            "format": ["other"], "status": ["failed", "incomplete"], "error": ["PRIVATE_ERROR"],
            "source_matches_after_run": [False, 1], "test_parent_race_enabled": [False, 1], "coverage_enabled": [False, 1],
            "package_inventory_succeeded": [False, 1], "test_process_succeeded": [False, 1], "stream_complete": [False, 1],
            "stream_bytes": [0, -1, True, (32 << 20) + 1], "stream_sha256": ["PRIVATE_DIGEST", "A" * 64],
            "package_timeout": ["1m0s"], "overall_timeout": ["10m0s"], "selected_scenarios": [0, True, 2],
            "source": [{"revision": "PRIVATE_REVISION"}],
        }.items():
            for value in values:
                with self.subTest(key=key, value_type=type(value).__name__):
                    receipt, report = fixture()
                    receipt[key] = value
                    with self.assertRaises(CHECKER.Rejected):
                        self.check(receipt, report)

    def test_counts_cannot_hide_unselected_failure_or_missing_tests(self):
        for mutate in [lambda c: c.update(failed=1), lambda c: c.update(root_tests=0),
                       lambda c: c.update(subtests=2), lambda c: c.update(passed=0),
                       lambda c: c.update(skipped=True), lambda c: c.update(passed=65537),
                       lambda c: c.update(extra=0)]:
            receipt, report = fixture()
            mutate(receipt["tests"])
            with self.assertRaises(CHECKER.Rejected):
                self.check(receipt, report)
        receipt, report = fixture()
        report["cases"][0]["skipped_subtests"] = 2
        with self.assertRaises(CHECKER.Rejected):
            self.check(receipt, report)

    def test_package_inventory_must_be_complete_unique_and_ordered(self):
        for mutate in [lambda p: p.clear(), lambda p: p.reverse(), lambda p: p.append(p[-1]),
                       lambda p: p.pop(), lambda p: p[1].update(status="fail"),
                       lambda p: p[1].update(status="skip"), lambda p: p[0].update(package="PRIVATE_PATH"),
                       lambda p: p[0].update(package=CHECKER.MODULE + "/../private"),
                       lambda p: p[0].update(extra="PRIVATE"), lambda p: p.extend([p[0]] * 1024)]:
            receipt, report = fixture()
            mutate(receipt["packages"])
            with self.assertRaises(CHECKER.Rejected):
                self.check(receipt, report)

    def test_exact_schema_and_dependency_pin(self):
        receipt, report = fixture()
        receipt["PRIVATE_EXTRA"] = 1
        with self.assertRaises(CHECKER.Rejected):
            self.check(receipt, report)
        self.assertTrue(callable(CHECKER.companion().verify))

    def test_fixed_private_argument_failure_and_output_failure(self):
        class ShortOutput:
            def write(self, raw):
                return len(raw) - 1
        for args in [[], ["--PRIVATE_FLAG"], ["--receipt", "PRIVATE_PATH", "--receipt", "PRIVATE_PATH"]]:
            output = io.StringIO()
            self.assertEqual(CHECKER.main(args, output), 2)
            self.assertNotIn("PRIVATE", output.getvalue())
        self.assertEqual(CHECKER.main([], ShortOutput()), 70)


if __name__ == "__main__":
    unittest.main()
