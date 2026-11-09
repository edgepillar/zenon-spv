# SPDX-License-Identifier: GPL-3.0-only
"""Report the platform's completed preparation controls and source pins."""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import platform
import subprocess
import sys
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import model


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    revision = model.digest(args.source_revision, model.HEX40)
    observed = subprocess.check_output(["git", "--no-optional-locks", "rev-parse", "HEAD"],
                                      cwd=HERE, timeout=10).decode("ascii").strip()
    model.require(observed == revision, "controls_source_revision")
    paths = sorted([*HERE.glob("*.py"), HERE / "contract.json"])
    pins = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}
    suite = unittest.defaultTestLoader.discover(str(HERE), pattern="*_test.py")
    result = unittest.TextTestRunner(stream=sys.stderr, verbosity=2).run(suite)
    model.require(pins == {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in paths},
                  "controls_source_changed")
    report = {"format": "owned-devnet-preparation-controls/v1", "source_revision": revision,
        "platform": platform.system(), "machine": platform.machine(), "python": platform.python_version(),
        "source_sha256": pins, "tests": result.testsRun, "failures": len(result.failures),
        "errors": len(result.errors), "skipped": [{"test": case.id(), "reason": reason}
                                                for case, reason in result.skipped],
        "successful": result.wasSuccessful(), "real_devnet_started": False,
        "privileged_reader_executed": False, "native_cli_executed": False}
    with args.report.open("xb") as stream:
        stream.write(model.canonical(report))
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
