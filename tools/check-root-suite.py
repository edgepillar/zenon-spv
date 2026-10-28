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


def check_receipt(value, report, race, coverage, package_timeout, overall_timeout):
    require(type(value) is dict and set(value) == RECEIPT_KEYS)
    require(value["format"] == "zenon-root-suite/v1" and value["status"] == report["status"]
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
                  args.expect_package_timeout, args.expect_overall_timeout)
    require(receipt["selected_report_sha256"] == args.expect_report_sha256)
    return {
        "format": "zenon-root-suite-check/v1", "status": "consistent", "category": None,
        "source_revision": args.expect_revision, "source_inputs_sha256": selection["source_inputs_sha256"],
        "os": args.expect_os, "architecture": args.expect_architecture,
        "receipt_sha256": args.expect_receipt_sha256, "receipt_bytes": len(receipt_raw),
        "report_sha256": args.expect_report_sha256, "report_bytes": len(report_raw),
        "packages": len(receipt["packages"]), "tests": receipt["tests"],
        "selected_scenarios": receipt["selected_scenarios"],
        "test_execution_authenticated": False, "network_or_state_value_acceptance": False,
    }


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
