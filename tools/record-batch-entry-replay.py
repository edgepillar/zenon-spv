#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Run the existing recorded BatchEntry controls and emit one small receipt.

A receipt is unsigned consistency data. Qualification also requires the selected
source, actual process completion and successful hosted job/step records.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import platform
import re
import stat
import sys
import unittest

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
INPUTS = (
    "tools/record-batch-entry-replay.py",
    "tools/gen-state-root-vectors/check_batch_entry_header_witness_test.py",
    "tools/gen-state-root-vectors/check_batch_entry_header_witness.py",
    "tools/gen-node-momentum-vectors/check.py",
    "internal/testdata/conformance/batch-entry-node-header-witness.json",
    "tools/gen-state-root-vectors/batch-entry-header-witness_test.go.txt",
)
ROOTS = 23
RECEIPT_LIMIT = 32768
DIAGNOSTIC_LIMIT = 262144
MATH = {
    "headers": 3, "proofs": 2, "ABI_fields": 17, "value_bytes": 800,
    "scope": "RECORDED_FIXTURE_BYTES_NOT_NETWORK_ACCEPTANCE",
    "Ed25519_checked_by_Python": False, "production_qualified": False,
}


def require(value):
    if not value:
        raise ValueError("Recorded replay refused")


def source_snapshot():
    rows = []
    for name in INPUTS:
        path = ROOT / name
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_size <= 262144)
        with path.open("rb") as stream:
            raw = stream.read(262145)
        require(len(raw) <= 262144)
        rows.append({"path": name, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
    return rows


def current_platform():
    system = {"linux": "linux", "darwin": "darwin", "win32": "windows"}.get(sys.platform)
    architecture = {"x86_64": "amd64", "amd64": "amd64",
                    "aarch64": "arm64", "arm64": "arm64"}.get(platform.machine().lower())
    require(system is not None and architecture is not None)
    return system + "-" + architecture


class BoundedDiagnostics:
    def __init__(self, target):
        self.target, self.bytes = target, 0

    def write(self, value):
        size = len(value.encode("utf-8"))
        require(self.bytes + size <= DIAGNOSTIC_LIMIT)
        self.bytes += size
        require(self.target.write(value) == len(value))
        return len(value)

    def flush(self):
        self.target.flush()


class ReceiptResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.cases, self.active = [], {}
        self.subtests = {"passed": 0, "failed": 0, "errored": 0}
        self.phase_error_events = 0

    def startTest(self, test):
        row = {"id": test.id(), "status": "incomplete"}
        self.cases.append(row)
        self.active[id(test)] = row
        super().startTest(test)

    def stopTest(self, test):
        # unittest releases completed cases. A later class-error holder can
        # reuse their object identity; it must never relabel a completed row.
        self.active.pop(id(test), None)
        super().stopTest(test)

    def mark(self, test, status):
        row = self.active.get(id(test))
        if row is None:
            self.phase_error_events += 1
        else:
            row["status"] = status

    def addSuccess(self, test):
        self.mark(test, "passed")
        super().addSuccess(test)

    def addFailure(self, test, error):
        self.mark(test, "failed")
        super().addFailure(test, error)

    def addError(self, test, error):
        self.mark(test, "errored")
        super().addError(test, error)

    def addSkip(self, test, reason):
        self.mark(test, "skipped")
        super().addSkip(test, reason)

    def addExpectedFailure(self, test, error):
        self.mark(test, "expected_failure")
        super().addExpectedFailure(test, error)

    def addUnexpectedSuccess(self, test):
        self.mark(test, "unexpected_success")
        super().addUnexpectedSuccess(test)

    def addSubTest(self, test, subtest, error):
        status = ("passed" if error is None else
                  "failed" if issubclass(error[0], test.failureException) else "errored")
        self.subtests[status] += 1
        if error is not None:
            self.mark(test, status)
        super().addSubTest(test, subtest, error)


def suite_ids(suite):
    result = []
    for test in suite:
        result.extend(suite_ids(test) if isinstance(test, unittest.TestSuite) else [test.id()])
    return result


def run_controls(suite, diagnostics):
    selected = suite_ids(suite)
    require(len(selected) == ROOTS and len(set(selected)) == ROOTS)
    require(all(type(name) is str and re.fullmatch(r"[A-Za-z0-9_.]{1,256}", name) for name in selected))
    result = unittest.TextTestRunner(
        stream=BoundedDiagnostics(diagnostics), verbosity=2, resultclass=ReceiptResult,
    ).run(suite)
    cases = result.cases
    passed = (
        result.wasSuccessful() and result.testsRun == ROOTS and len(cases) == ROOTS
        and sorted(row["id"] for row in cases) == sorted(selected)
        and all(row["status"] == "passed" for row in cases)
        and result.phase_error_events == 0
        and result.subtests["failed"] == result.subtests["errored"] == 0
    )
    return {
        "selected_roots": len(selected), "started_roots": result.testsRun,
        "completed": True, "cases": cases, "subtests": result.subtests,
        "phase_error_events": result.phase_error_events,
        "failure_events": len(result.failures), "error_events": len(result.errors),
        "skipped_events": len(result.skipped),
        "expected_failure_events": len(result.expectedFailures),
        "unexpected_success_events": len(result.unexpectedSuccesses),
    }, passed


def load_controls():
    path = ROOT / INPUTS[1]
    spec = importlib.util.spec_from_file_location("recorded_batch_entry_controls", path)
    controls = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(controls)
    return controls


def build_receipt(revision, expected_platform, diagnostics):
    require(type(revision) is str and re.fullmatch(r"[0-9a-f]{40}", revision)
            and revision != "0" * 40 and current_platform() == expected_platform)
    before = source_snapshot()
    controls = load_controls()
    tests, passed = run_controls(unittest.defaultTestLoader.loadTestsFromModule(controls), diagnostics)
    replay = None
    try:
        replay = controls.replay.check_corpus(controls.replay.read_corpus(),
                                             controls.replay.HARNESS.read_bytes())
    except (ValueError, KeyError, TypeError, OSError):
        passed = False
    after = source_snapshot()
    unchanged = before == after
    passed = (passed and unchanged and
              json.dumps(replay, sort_keys=True, allow_nan=False) ==
              json.dumps(MATH, sort_keys=True, allow_nan=False))
    return {
        "format": "spv-recorded-batch-entry-receipt/v1",
        "status": "passed" if passed else "failed",
        "source_revision": revision, "platform": expected_platform,
        "runtime": {"python": platform.python_version(), "implementation": platform.python_implementation()},
        "source_inputs": before, "source_unchanged_after": unchanged,
        "tests": tests, "byte_replay": replay,
        "scope": "RECORDED_FIXTURE_BYTES_NOT_NETWORK_ACCEPTANCE",
        "execution_provenance_authenticated": False,
        "production_qualified": False,
    }


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError("Invalid invocation")


def main(argv=None, output=None, diagnostics=None):
    output = sys.stdout if output is None else output
    diagnostics = sys.stderr if diagnostics is None else diagnostics
    parser = Parser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--expect-platform", required=True)
    try:
        args = parser.parse_args(argv)
        require(re.fullmatch(r"[0-9a-f]{40}", args.source_revision)
                and args.source_revision != "0" * 40)
        require(args.expect_platform in {
            osname + "-" + arch for osname in ("linux", "darwin", "windows")
            for arch in ("amd64", "arm64")
        })
    except ValueError:
        diagnostics.write("recorded replay: invalid invocation\n")
        return 64
    try:
        receipt = build_receipt(args.source_revision, args.expect_platform, diagnostics)
        raw = json.dumps(receipt, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n"
        require(len(raw.encode("utf-8")) <= RECEIPT_LIMIT)
        if output.write(raw) != len(raw):
            return 70
        output.flush()
        return 0 if receipt["status"] == "passed" else 1
    except (OSError, ValueError, KeyError, TypeError):
        diagnostics.write("recorded replay: input, execution or output failed\n")
        return 70


if __name__ == "__main__":
    sys.exit(main())
