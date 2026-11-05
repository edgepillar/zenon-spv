#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Check a root-suite receipt against the selected source and pilot report.

No test or candidate executable is run. A consistent unsigned receipt does not
authenticate execution; the selected CI job's actual completion remains a gate.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import stat
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
DEPENDENCY = (17361, "868167a81686d1fea06469e8b7b94da1558782ffc784fbaf091d91f741a314eb")
MODULE = "github.com/0x3639/zenon-spv"
SOURCE_ROOT_GROUP = "compiled-source-enumeration/v1"
SOURCE_ROOT_TEST = "TestCompiledPilotSourceEnumeration"
RECEIPT_KEYS = {
    "format", "status", "error", "source", "source_matches_after_run", "test_parent_race_enabled",
    "coverage_enabled", "package_timeout", "overall_timeout", "package_inventory_succeeded", "test_process_succeeded",
    "stream_complete", "stream_bytes", "stream_sha256", "packages", "tests", "selected_scenarios",
    "selected_report_sha256",
}


class Rejected(Exception):
    pass


def require(condition):
    if not condition:
        raise Rejected()


def companion():
    path = HERE / "check-scenario-inventory.py"
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_size == DEPENDENCY[0])
    with path.open("rb") as stream:
        raw = stream.read(DEPENDENCY[0] + 1)
    require(len(raw) == DEPENDENCY[0] and hashlib.sha256(raw).hexdigest() == DEPENDENCY[1])
    spec = importlib.util.spec_from_file_location("root_suite_scenario_companion", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest(value):
    return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def integer(value, maximum=65536):
    return type(value) is int and 0 <= value <= maximum


def check_timings(value, counts, passed_packages):
    require(type(value) is dict and set(value) == {
        "basis", "limit", "completed_roots", "measured_roots", "missing_elapsed", "withheld_names", "slowest_roots",
    })
    require(value["basis"] == "go_test_elapsed_nanoseconds" and type(value["limit"]) is int and value["limit"] == 20)
    for key in ("completed_roots", "measured_roots", "missing_elapsed", "withheld_names"):
        require(integer(value[key]))
    require(value["completed_roots"] == counts["root_tests"]
            and value["measured_roots"] + value["missing_elapsed"] + value["withheld_names"] == value["completed_roots"])
    rows = value["slowest_roots"]
    require(type(rows) is list and len(rows) == min(value["limit"], value["measured_roots"]))
    identities, ordering = [], []
    for row in rows:
        require(type(row) is dict and set(row) == {"package", "test", "status", "elapsed_nanoseconds"})
        name, package, elapsed = row["test"], row["package"], row["elapsed_nanoseconds"]
        require(type(name) is str and len(name) <= 256
                and re.fullmatch(r"(?:Test|Fuzz|Example)[A-Za-z0-9_]*", name) is not None
                and type(package) is str and package in passed_packages and row["status"] in ("pass", "skip")
                and integer(elapsed, 86400 * 10**9))
        identities.append((package, name))
        ordering.append((-elapsed, package, name))
    require(len(set(identities)) == len(identities) and ordering == sorted(ordering)
            and sum(row["status"] == "skip" for row in rows) <= counts["skipped"])


def check_observer_resources(value, platform):
    require(platform in ("linux", "darwin", "windows"))
    require(type(value) is dict and set(value) == {"format", "status", "records", "failures"}
            and value["format"] == "zenon-observer-workflow-resources/v1"
            and value["status"] == "complete" and value["failures"] == [])
    rows = value["records"]
    require(type(rows) is list and len(rows) == 84)
    require(len(json.dumps(value, separators=(",", ":"), allow_nan=False).encode()) <= 256 << 10)
    slot_count = 0

    def positive(number, maximum):
        return integer(number, maximum) and number > 0

    def child(record, output_limit):
        require(type(record) is dict and set(record) == {"exit_code", "elapsed_ns", "stdout_bytes", "stderr_bytes"})
        require(type(record["exit_code"]) is int and record["exit_code"] == 0
                and positive(record["elapsed_ns"], 86400 * 10**9)
                and positive(record["stdout_bytes"], output_limit)
                and type(record["stderr_bytes"]) is int and record["stderr_bytes"] == 0)

    for index, row in enumerate(rows):
        group, round_number = divmod(index, 21)
        capacity, concurrency = (256, 1) if group == 0 else (256, 4) if group == 1 else (4096, 1) if group == 2 else (4096, 4)
        require(type(row) is dict and set(row) == {
            "workload", "round", "retained_headers", "targets", "concurrency", "state_bytes", "bundle_bytes",
            "expectations_bytes", "group_elapsed_ns", "observations",
        })
        require(row["workload"] == "K%d_T16_C%d" % (capacity, concurrency)
                and type(row["round"]) is int and row["round"] == round_number
                and type(row["retained_headers"]) is int and row["retained_headers"] == capacity
                and type(row["targets"]) is int and row["targets"] == 16
                and type(row["concurrency"]) is int and row["concurrency"] == concurrency
                and positive(row["state_bytes"], 64 << 20) and positive(row["bundle_bytes"], 64 << 20)
                and positive(row["expectations_bytes"], 256 << 10)
                and positive(row["group_elapsed_ns"], 86400 * 10**9))
        observations = row["observations"]
        require(type(observations) is list and len(observations) == concurrency)
        for slot, point in enumerate(observations):
            require(type(point) is dict and set(point) == {
                "slot", "actual_exit", "elapsed_ns", "waited_peak_bytes", "waited_peak_source",
                "observer_elapsed_ns", "checked_targets", "verifier", "consumer",
            })
            require(type(point["slot"]) is int and point["slot"] == slot
                    and type(point["actual_exit"]) is int and point["actual_exit"] == 0
                    and positive(point["elapsed_ns"], 86400 * 10**9)
                    and positive(point["observer_elapsed_ns"], 86400 * 10**9)
                    and type(point["checked_targets"]) is int and point["checked_targets"] == 16
                    and positive(point["waited_peak_bytes"], 1 << 50)
                    and point["waited_peak_source"] == ("windows_peak_working_set" if platform == "windows" else "process_rusage"))
            child(point["verifier"], 4 << 20)
            child(point["consumer"], 1024)
            slot_count += 1
    require(slot_count == 210)
    return {"format": value["format"], "status": "consistent", "groups": len(rows), "process_observations": slot_count}


def check_source_roots(value, counts, passed_packages, report):
    require(type(value) is dict and set(value) == {"format", "group", "status", "roots"}
            and value["format"] == "zenon-source-root-controls/v1" and value["group"] == SOURCE_ROOT_GROUP
            and value["status"] == "complete" and type(value["roots"]) is list and len(value["roots"]) == 1)
    row = value["roots"][0]
    require(type(row) is dict and set(row) == {
        "package", "test", "status", "passed_subtests", "skipped_subtests", "failed_subtests"})
    package = MODULE + "/tools/offline-pilot"
    require(row["package"] == package and package in passed_packages and row["test"] == SOURCE_ROOT_TEST
            and row["status"] == "pass" and all(integer(row[key]) for key in
                ("passed_subtests", "skipped_subtests", "failed_subtests"))
            and row["passed_subtests"] == 6 and row["skipped_subtests"] == row["failed_subtests"] == 0)
    require(not any(case["package"] == "tools/offline-pilot" and case.get("test") == SOURCE_ROOT_TEST
                    for case in report["cases"]))
    require(counts["root_tests"] >= len(report["cases"]) + 1
            and counts["subtests"] >= 6 + sum(case["passed_subtests"] + case["skipped_subtests"]
                                              for case in report["cases"]))
    return {"group": SOURCE_ROOT_GROUP, "roots": 1, "passed_subtests": 6, "skipped_subtests": 0}


def check_receipt(value, report, race, coverage, package_timeout, overall_timeout, platform=None, required_group=None):
    require(type(value) is dict)
    version2 = value.get("format") in ("zenon-root-suite/v2", "zenon-root-suite/v3", "zenon-root-suite/v4")
    version3 = value.get("format") in ("zenon-root-suite/v3", "zenon-root-suite/v4")
    version4 = value.get("format") == "zenon-root-suite/v4"
    require(required_group is None or required_group == SOURCE_ROOT_GROUP and version4)
    require(set(value) == RECEIPT_KEYS | ({"timings"} if version2 else set()) | ({"observer_resources"} if version3 else set())
            | ({"source_root_controls"} if version4 else set()))
    require(value["format"] in ("zenon-root-suite/v1", "zenon-root-suite/v2", "zenon-root-suite/v3", "zenon-root-suite/v4") and value["status"] == report["status"]
            and value["status"] in ("passed", "passed_with_skips") and value["error"] is None)
    require(value["source"] == report["source"] and value["source_matches_after_run"] is True
            and value["test_parent_race_enabled"] is race
            and value["coverage_enabled"] is coverage
            and report["test_parent_race_enabled"] is race
            and value["package_timeout"] == package_timeout and value["overall_timeout"] == overall_timeout)
    require(value["package_inventory_succeeded"] is True and value["test_process_succeeded"] is True
            and value["stream_complete"] is True and integer(value["stream_bytes"], 32 << 20)
            and value["stream_bytes"] > 0 and digest(value["stream_sha256"]))
    counts = value["tests"]
    require(type(counts) is dict and set(counts) == {"root_tests", "subtests", "passed", "skipped", "failed"}
            and all(integer(count) for count in counts.values()) and counts["failed"] == 0
            and counts["root_tests"] + counts["subtests"] == counts["passed"] + counts["skipped"])
    require(type(value["selected_scenarios"]) is int and value["selected_scenarios"] == len(report["cases"])
            and counts["root_tests"] >= len(report["cases"])
            and counts["subtests"] >= sum(case["passed_subtests"] + case["skipped_subtests"] for case in report["cases"])
            and counts["skipped"] >= sum(case["skipped_subtests"] for case in report["cases"]))
    packages = value["packages"]
    require(type(packages) is list and 0 < len(packages) <= 1024)
    names, passed = [], set()
    for row in packages:
        require(type(row) is dict and set(row) == {"package", "status"})
        name = row["package"]
        require(type(name) is str and len(name) <= 4096 and (name == MODULE or name.startswith(MODULE + "/"))
                and re.fullmatch(r"[A-Za-z0-9_.\-/]+", name) is not None
                and all(part not in ("", ".", "..") for part in name.split("/"))
                and row["status"] in ("pass", "skip"))
        names.append(name)
        if row["status"] == "pass":
            passed.add(name)
    require(names == sorted(set(names))
            and {MODULE + "/" + case["package"] for case in report["cases"]} <= passed)
    if version2:
        check_timings(value["timings"], counts, passed)
    if version3:
        require(MODULE + "/internal/conformance" in passed)
        check_observer_resources(value["observer_resources"], platform)
    if version4:
        check_source_roots(value["source_root_controls"], counts, passed, report)


def verify(args):
    scenario = companion()
    selection = scenario.verify(args.report, args.expect_report_sha256, args.source, args.expect_revision,
                                args.expect_os, args.expect_architecture, require_skip_ledger=True)
    receipt_raw = scenario.read_regular(args.receipt, 1 << 20, "receipt")
    require(digest(args.expect_receipt_sha256)
            and hashlib.sha256(receipt_raw).hexdigest() == args.expect_receipt_sha256)
    c = scenario.primitives().checker
    receipt = c.metadata(receipt_raw)
    report_raw = scenario.read_regular(args.report, scenario.REPORT_LIMIT, "report")
    require(hashlib.sha256(report_raw).hexdigest() == args.expect_report_sha256)
    report = c.metadata(report_raw)
    check_receipt(receipt, report, args.expect_race == "true", args.expect_coverage == "true",
                  args.expect_package_timeout, args.expect_overall_timeout, args.expect_os, args.require_source_root_group)
    require(receipt["selected_report_sha256"] == args.expect_report_sha256)
    result = {
        "format": "zenon-root-suite-check/v1", "status": "consistent", "category": None,
        "source_revision": args.expect_revision, "source_inputs_sha256": selection["source_inputs_sha256"],
        "os": args.expect_os, "architecture": args.expect_architecture,
        "receipt_sha256": args.expect_receipt_sha256, "receipt_bytes": len(receipt_raw),
        "report_sha256": args.expect_report_sha256, "report_bytes": len(report_raw),
        "packages": len(receipt["packages"]), "tests": receipt["tests"],
        "selected_scenarios": receipt["selected_scenarios"],
        "test_execution_authenticated": False, "network_or_state_value_acceptance": False,
    }
    if receipt["format"] in ("zenon-root-suite/v2", "zenon-root-suite/v3", "zenon-root-suite/v4"):
        result.update(format=receipt["format"].replace("root-suite/", "root-suite-check/"), receipt_format=receipt["format"], timings=receipt["timings"])
    if receipt["format"] in ("zenon-root-suite/v3", "zenon-root-suite/v4"):
        result["observer_resources"] = check_observer_resources(receipt["observer_resources"], args.expect_os)
    if receipt["format"] == "zenon-root-suite/v4":
        result["source_root_controls"] = check_source_roots(receipt["source_root_controls"], receipt["tests"],
            {p["package"] for p in receipt["packages"] if p["status"] == "pass"}, report)
    return result


class Parser(argparse.ArgumentParser):
    def error(self, _message):
        raise Rejected()


class Once(argparse.Action):
    def __call__(self, parser, namespace, value, option_string=None):
        require(getattr(namespace, self.dest) is None)
        setattr(namespace, self.dest, value)


def main(argv=None, output=None):
    output = sys.stdout if output is None else output
    parser = Parser(prog="check-root-suite", allow_abbrev=False, add_help=False)
    for name in ("receipt", "expect-receipt-sha256", "report", "expect-report-sha256", "source",
                 "expect-revision", "expect-os", "expect-architecture", "expect-race", "expect-coverage",
                 "expect-package-timeout", "expect-overall-timeout"):
        parser.add_argument("--" + name, action=Once, required=True)
    parser.add_argument("--require-source-root-group", action=Once)
    try:
        args = parser.parse_args(argv)
        require(args.expect_race in ("true", "false") and args.expect_coverage in ("true", "false"))
        for name in ("receipt", "report", "source"):
            require(0 < len(getattr(args, name)) <= 4096)
        result, code = verify(args), 0
    except (Exception, KeyboardInterrupt):
        result, code = {"format": "zenon-root-suite-check/v1", "status": "rejected", "category": "input_or_receipt",
                        "test_execution_authenticated": False, "network_or_state_value_acceptance": False}, 2
    try:
        raw = json.dumps(result, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n"
        if output.write(raw) != len(raw):
            return 70
        output.flush()
    except (OSError, ValueError):
        return 70
    return code


if __name__ == "__main__":
    raise SystemExit(main())
