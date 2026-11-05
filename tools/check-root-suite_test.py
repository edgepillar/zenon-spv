#!/usr/bin/env python3
"""Finite receipt consistency controls; real execution remains a CI gate."""
import copy
import importlib.util
import io
import json
from pathlib import Path
import re
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


def timed_fixture():
    receipt, report = fixture()
    receipt.update(format="zenon-root-suite/v2", timings={
        "basis": "go_test_elapsed_nanoseconds", "limit": 20, "completed_roots": 4, "measured_roots": 3,
        "missing_elapsed": 1, "withheld_names": 0,
        "slowest_roots": [
            {"package": CHECKER.MODULE + "/internal/conformance", "test": name,
             "status": "pass", "elapsed_nanoseconds": nanoseconds}
            for name, nanoseconds in [("TestSlow", 9000000000), ("TestEqualA", 2000000000), ("TestEqualB", 2000000000)]
        ],
    })
    return receipt, report


def observer_fixture(platform="linux"):
    receipt, report = timed_fixture()
    records = []
    for capacity, concurrency in [(256, 1), (256, 4), (4096, 1), (4096, 4)]:
        for round_number in range(21):
            points = []
            for slot in range(concurrency):
                points.append({"slot": slot, "actual_exit": 0, "elapsed_ns": round_number * 100 + slot + 1,
                               "waited_peak_bytes": 4096, "waited_peak_source": "windows_peak_working_set" if platform == "windows" else "process_rusage",
                               "observer_elapsed_ns": 10, "checked_targets": 16,
                               "verifier": {"exit_code": 0, "elapsed_ns": 2, "stdout_bytes": 128, "stderr_bytes": 0},
                               "consumer": {"exit_code": 0, "elapsed_ns": 3, "stdout_bytes": 32, "stderr_bytes": 0}})
            records.append({"workload": "K%d_T16_C%d" % (capacity, concurrency), "round": round_number,
                            "retained_headers": capacity, "targets": 16, "concurrency": concurrency,
                            "state_bytes": 1000, "bundle_bytes": 2000, "expectations_bytes": 3000,
                            "group_elapsed_ns": round_number + 1, "observations": points})
    receipt.update(format="zenon-root-suite/v3", observer_resources={
        "format": "zenon-observer-workflow-resources/v1", "status": "complete", "records": records, "failures": []})
    return receipt, report


def source_root_fixture(platform="darwin"):
    receipt, report = observer_fixture(platform)
    receipt.update(format="zenon-root-suite/v4", source_root_controls={
        "format": "zenon-source-root-controls/v1", "group": "compiled-source-enumeration/v1", "status": "complete",
        "roots": [{"package": CHECKER.MODULE + "/tools/offline-pilot", "test": "TestCompiledPilotSourceEnumeration",
                   "status": "pass", "passed_subtests": 6, "skipped_subtests": 0, "failed_subtests": 0}]})
    receipt["packages"].append({"package": CHECKER.MODULE + "/tools/offline-pilot", "status": "pass"})
    receipt["tests"].update(root_tests=5, subtests=14, passed=18)
    receipt["timings"].update(completed_roots=5, missing_elapsed=2)
    return receipt, report


class RootSuiteControls(unittest.TestCase):
    def check(self, receipt, report):
        CHECKER.check_receipt(receipt, report, True, True, "10m0s", "30m0s")

    def test_complete_receipt_and_unselected_skip(self):
        self.check(*fixture())
        self.check(*timed_fixture())

    def test_source_root_group_is_explicit_and_platform_bound(self):
        for platform in ("linux", "darwin", "windows"):
            receipt, report = source_root_fixture(platform)
            CHECKER.check_receipt(receipt, report, True, True, "10m0s", "30m0s", platform,
                                  "compiled-source-enumeration/v1")
            summary = CHECKER.check_source_roots(receipt["source_root_controls"], receipt["tests"],
                {p["package"] for p in receipt["packages"] if p["status"] == "pass"}, report)
            self.assertEqual(summary, {"group": "compiled-source-enumeration/v1", "roots": 1,
                                       "passed_subtests": 6, "skipped_subtests": 0})
        for make in (fixture, timed_fixture, observer_fixture):
            receipt, report = make()
            with self.assertRaises(CHECKER.Rejected):
                CHECKER.check_receipt(receipt, report, True, True, "10m0s", "30m0s", "linux",
                                      "compiled-source-enumeration/v1")

    def test_source_root_evidence_refuses_missing_shadowed_and_unexecuted_values(self):
        mutations = [lambda r: r.pop("source_root_controls"), lambda r: r.update(format="zenon-root-suite/v3"),
                     lambda r: r["source_root_controls"].update(format="PRIVATE"),
                     lambda r: r["source_root_controls"].update(group="PRIVATE"),
                     lambda r: r["source_root_controls"].update(status="incomplete"),
                     lambda r: r["source_root_controls"].update(extra="PRIVATE"),
                     lambda r: r["source_root_controls"].update(roots=[]),
                     lambda r: r["source_root_controls"]["roots"].append(r["source_root_controls"]["roots"][0]),
                     lambda r: r["tests"].update(subtests=8, passed=12),
                     lambda r: r["packages"][-1].update(status="skip")]
        for key, options in {
            "test": ["TestOther", "TestCompiledPilotSourceEnumeration/PRIVATE", None],
            "package": ["PRIVATE", CHECKER.MODULE + "/internal/conformance"],
            "status": ["missing", "running", "skip", "fail"],
            "passed_subtests": [5, 7, True, 6.0, "6"],
            "skipped_subtests": [1, False], "failed_subtests": [1, False], "extra": ["PRIVATE"],
        }.items():
            for value in options:
                mutations.append(lambda r, k=key, v=value: r["source_root_controls"]["roots"][0].update({k: v}))
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                receipt, report = source_root_fixture()
                mutate(receipt)
                with self.assertRaises(CHECKER.Rejected):
                    CHECKER.check_receipt(receipt, report, True, True, "10m0s", "30m0s", "darwin",
                                          "compiled-source-enumeration/v1")

    def test_source_root_reuse_preserves_parent_instrumentation_and_complete_suite(self):
        workflow = (HERE.parent / ".github/workflows/ci.yml").read_text()
        linux, matrix = workflow.split("\n  native-platform:\n", 1)
        matrix = matrix.split("\n  recorded-oracles:\n", 1)[0]
        command = "-run '^TestCompiledPilotSourceEnumeration$'"
        self.assertIn(command, linux)
        self.assertNotIn(command, matrix)
        self.assertIn("--full-suite --timeout 30m --package-timeout 10m --race --coverage", linux)
        self.assertIn("--full-suite --timeout 30m --package-timeout 10m --suite-root-group compiled-source-enumeration/v1", matrix)
        self.assertIn("--require-source-root-group compiled-source-enumeration/v1", matrix)
        steps = re.findall(r"^      - name: (.+)$", matrix, re.M)
        self.assertLess(steps.index("Upload root suite receipt"), steps.index("Compiled pilot source enumeration controls"))
        self.assertLess(steps.index("Compiled pilot source enumeration controls"), steps.index("Bounded ledger inventory controls"))

    def test_observer_resources_are_complete_and_platform_bound(self):
        for platform in ("linux", "darwin", "windows"):
            receipt, report = observer_fixture(platform)
            CHECKER.check_receipt(receipt, report, True, True, "10m0s", "30m0s", platform)
            summary = CHECKER.check_observer_resources(receipt["observer_resources"], platform)
            self.assertEqual((summary["groups"], summary["process_observations"]), (84, 210))
        with self.assertRaises(CHECKER.Rejected):
            self.check(*observer_fixture())

    def test_observer_resources_cannot_hide_missing_or_reordered_values(self):
        for mutate in [lambda r: r["records"].pop(), lambda r: r["records"].reverse(),
                       lambda r: r["records"][1].update(round=0), lambda r: r.update(status="incomplete"),
                       lambda r: r["failures"].append({"PRIVATE": 1}),
                       lambda r: r["records"][0]["observations"][0].update(slot=True),
                       lambda r: r["records"][1]["observations"][0].update(elapsed_ns=0),
                       lambda r: r["records"][0].update(workload="PRIVATE_PATH"),
                       lambda r: r["records"][0].update(state_bytes=(64 << 20) + 1),
                       lambda r: r["records"][0].update(extra="PRIVATE"),
                       lambda r: r["records"][21]["observations"].reverse(),
                       lambda r: r["records"][0]["observations"][0].update(waited_peak_source="windows_peak_working_set"),
                       lambda r: r["records"][0]["observations"][0]["consumer"].update(stdout_bytes=1025),
                       lambda r: r["records"][0]["observations"][0]["verifier"].update(exit_code=None),
                       lambda r: r["records"][0]["observations"][0]["verifier"].update(incomplete_output={})]:
            receipt, _ = observer_fixture()
            mutate(receipt["observer_resources"])
            with self.assertRaises(CHECKER.Rejected):
                CHECKER.check_observer_resources(receipt["observer_resources"], "linux")

    def test_resource_dedup_preserves_linux_parent_race_distinction(self):
        workflow = (HERE.parent / ".github/workflows/ci.yml").read_text()
        linux, matrix = workflow.split("\n  native-platform:\n", 1)
        matrix = matrix.split("\n  recorded-oracles:\n", 1)[0]
        command = "-run '^TestCompiledBlockObserverResources$'"
        self.assertIn(command, linux)
        self.assertNotIn(command, matrix)
        self.assertIn("--full-suite", matrix)
        self.assertIn("--race --coverage", linux)
        self.assertNotIn("--race", matrix)

    def test_actual_json_ingress_preserves_integer_only_metadata(self):
        decoder = CHECKER.companion().primitives().checker
        metadata = decoder.metadata
        for receipt, report in [fixture(), timed_fixture()]:
            self.check(metadata(json.dumps(receipt).encode()), metadata(json.dumps(report).encode()))
        receipt, _ = timed_fixture()
        receipt["timings"]["slowest_roots"][0]["elapsed_nanoseconds"] = 1.234
        with self.assertRaises(decoder.Rejected) as rejected:
            metadata(json.dumps(receipt).encode())
        self.assertEqual(rejected.exception.category, "metadata")

    def test_native_receipt_is_checked_before_long_remaining_controls(self):
        workflow = (HERE.parent / ".github/workflows/ci.yml").read_text()
        native = workflow.split("\n  native-platform:\n", 1)[1].split("\n  recorded-oracles:\n", 1)[0]
        steps = re.findall(r"^      - name: (.+)$", native, re.M)
        producer = steps.index("Native test")
        self.assertEqual(steps[producer + 1:producer + 3], ["Offline pilot report", "Upload root suite receipt"])
        self.assertLess(steps.index("Upload root suite receipt"), steps.index("Bounded ledger inventory controls"))
        for name in ("Native test", "Offline pilot report", "Upload root suite receipt"):
            self.assertEqual(steps.count(name), 1)

    def test_timing_coverage_and_strict_version_dispatch(self):
        receipt, report = timed_fixture()
        for mutate in [lambda r: r.pop("timings"), lambda r: r.update(format="zenon-root-suite/v1"),
                       lambda r: r["timings"].update(extra="PRIVATE"),
                       lambda r: r["timings"].update(limit=True), lambda r: r["timings"].update(limit=21),
                       lambda r: r["timings"].update(basis="PRIVATE"),
                       lambda r: r["timings"].update(completed_roots=3),
                       lambda r: r["timings"].update(missing_elapsed=0),
                       lambda r: r["timings"].update(withheld_names=True),
                       lambda r: r["timings"].update(measured_roots=65537),
                       lambda r: r["timings"].update(slowest_roots=None),
                       lambda r: r["timings"]["slowest_roots"].pop(),
                       lambda r: r["timings"]["slowest_roots"].reverse(),
                       lambda r: r["timings"]["slowest_roots"].append(r["timings"]["slowest_roots"][0])]:
            value = copy.deepcopy(receipt)
            mutate(value)
            with self.assertRaises(CHECKER.Rejected):
                self.check(value, report)
        receipt["timings"].update(measured_roots=0, missing_elapsed=0, withheld_names=4, slowest_roots=[])
        self.check(receipt, report)
        receipt["timings"].update(missing_elapsed=4, withheld_names=0)
        self.check(receipt, report)

    def test_timing_rows_are_bounded_public_finite_and_unique(self):
        receipt, report = timed_fixture()
        for key, values in {
            "elapsed_nanoseconds": [-1, True, "PRIVATE", float("nan"), float("inf"), 86400 * 10**9 + 1, 1.234, 0.0],
            "test": ["PRIVATE", "Test/PRIVATE", "Test-private", "Test_λ", "Test" * 65, None],
            "package": ["PRIVATE_PATH", CHECKER.MODULE + "/cmd/no-tests", None],
            "status": ["fail", "run", "PRIVATE"], "extra": ["PRIVATE"],
        }.items():
            for value in values:
                with self.subTest(key=key, value_type=type(value).__name__):
                    invalid = copy.deepcopy(receipt)
                    invalid["timings"]["slowest_roots"][0][key] = value
                    with self.assertRaises(CHECKER.Rejected):
                        self.check(invalid, report)
        duplicate = copy.deepcopy(receipt)
        duplicate["timings"]["slowest_roots"][2] = duplicate["timings"]["slowest_roots"][1]
        with self.assertRaises(CHECKER.Rejected):
            self.check(duplicate, report)
        receipt["timings"]["slowest_roots"][2].update(status="skip", elapsed_nanoseconds=0)
        self.check(receipt, report)
        receipt["tests"].update(skipped=0, passed=12)
        with self.assertRaises(CHECKER.Rejected):
            self.check(receipt, report)

    def test_only_twenty_rows_are_required_for_larger_suites(self):
        receipt, report = timed_fixture()
        receipt["tests"].update(root_tests=30, passed=37)
        receipt["timings"].update(completed_roots=30, measured_roots=30, missing_elapsed=0, slowest_roots=[
            {"package": CHECKER.MODULE + "/internal/conformance", "test": "TestRoot%02d" % i,
             "status": "pass", "elapsed_nanoseconds": 30 - i} for i in range(20)
        ])
        self.check(receipt, report)
        receipt["timings"]["slowest_roots"].append({"package": CHECKER.MODULE + "/internal/conformance",
                                                    "test": "TestRoot20", "status": "pass", "elapsed_nanoseconds": 10})
        with self.assertRaises(CHECKER.Rejected):
            self.check(receipt, report)

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
