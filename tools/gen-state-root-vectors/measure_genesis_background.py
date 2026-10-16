#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Measure one foreground component process; do not select trust or runtime inputs.

The caller owns the fresh database workspace and supplies the four environment
variables from prepare_genesis_background.py. The process inherits stdout and
stderr, so a supervising caller must bound and retain both streams. No database
is deleted here. This measures the entire test process, including its controlled
fixture and proof queries; it is not a complete-node or production memory budget.
"""
import argparse
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import time


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    args = parser.parse_args(argv)
    if sys.platform not in ("darwin", "linux"):
        raise ValueError("Peak RSS units have not been selected for this platform")
    binary = args.binary.absolute()
    info = binary.lstat()
    if (not hasattr(os, "wait4") or not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or any(p.is_symlink() for p in (binary, *binary.parents))):
        raise ValueError("A regular independent binary and wait4 support are required")
    start = time.monotonic_ns()
    process = subprocess.Popen([str(binary), "-test.v", "-test.run=^TestCandidateGenesisBackground$"])
    while True:
        try:
            waited, status, usage = os.wait4(process.pid, 0)
            break
        except InterruptedError:
            continue
    assert waited == process.pid
    result = os.waitstatus_to_exitcode(status)
    process.returncode = result
    # macOS reports bytes; Linux reports KiB. Reject an
    # unselected platform instead of assigning an unverified unit conversion.
    if sys.platform == "darwin":
        rss = usage.ru_maxrss
    elif sys.platform == "linux":
        rss = usage.ru_maxrss * 1024
    record = {
        "kind": "source-genesis-background-process-resource-observation",
        "process_exit": result,
        "output_completeness": "REQUIRES_SEPARATE_SUPERVISOR_EVIDENCE",
        "elapsed_ns": time.monotonic_ns() - start,
        "peak_rss_bytes": rss,
        "user_cpu_seconds": usage.ru_utime,
        "system_cpu_seconds": usage.ru_stime,
        "major_page_faults": usage.ru_majflt,
        "minor_page_faults": usage.ru_minflt,
        "measurement_scope": "entire_waited_component_process_including_fixture_and_queries",
        "descendant_process_memory_included": False,
        "production_resources_qualified": False,
    }
    print("GENESIS_BACKGROUND_RESOURCE=" + json.dumps(record, sort_keys=True), file=sys.stderr, flush=True)
    if result < 0:
        signal.signal(-result, signal.SIG_DFL)
        os.kill(os.getpid(), -result)
    return result


if __name__ == "__main__":
    sys.exit(main())
