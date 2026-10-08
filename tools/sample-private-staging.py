#!/usr/bin/env python3
"""Bounded metadata observations of an explicitly selected private directory.

No file contents, child processes or network access are used. Scans are
non-atomic: a visible disappearing entry is recorded, and unobserved changes
or short peaks can be missed. The caller keeps the selected root protected.
Reported file blocks are filesystem metadata, not physical storage or quotas.
"""
import argparse
import json
import os
from pathlib import Path
import stat
import sys
import time


class ScanError(Exception):
    def __init__(self, category):
        super().__init__(category)
        self.category = category


def unsafe(info):
    return (stat.S_ISLNK(info.st_mode) or
            bool(getattr(info, "st_file_attributes", 0) &
                 getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)))


def snapshot(root, max_entries=128, max_depth=2):
    """Read regular-file sizes without following observed unsafe entries.

    Entry/depth bounds cover this scan, including entries that disappear.
    File sizes are read at different times. Paths/names never enter the result.
    Directory blocks and unlinked open files are excluded; hard links can be
    counted repeatedly. Path-based directory traversal requires caller control
    against concurrent directory replacement, including on Windows.
    """
    if (type(max_entries) is not int or not 1 <= max_entries <= 4096 or
            type(max_depth) is not int or not 0 <= max_depth <= 16):
        raise ScanError("invalid_options")
    try:
        root = Path(root)
    except (TypeError, ValueError):
        raise ScanError("invalid_options") from None
    try:
        initial = os.stat(root, follow_symlinks=False)
    except (OSError, ValueError):
        raise ScanError("input_unavailable") from None
    if unsafe(initial) or not stat.S_ISDIR(initial.st_mode):
        raise ScanError("unsafe_directory")
    if os.name == "posix" and (initial.st_mode & 0o077 or initial.st_uid != os.geteuid()):
        raise ScanError("unsafe_directory")
    observed = {"entries": 0, "directories": 0, "regular_files": 0,
                "logical_file_bytes": 0,
                "filesystem_reported_allocated_bytes": 0 if hasattr(initial, "st_blocks") else None,
                "vanished_entries": 0}

    def visit(directory, depth):
        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    observed["entries"] += 1
                    if observed["entries"] > max_entries:
                        raise ScanError("entry_limit")
                    try:
                        # DirEntry.stat caches metadata and reports zero device
                        # identity on Windows. Read current unfollowed metadata.
                        info = os.stat(Path(directory) / entry.name, follow_symlinks=False)
                    except FileNotFoundError:
                        observed["vanished_entries"] += 1
                        continue
                    if unsafe(info) or info.st_dev != initial.st_dev:
                        raise ScanError("unsafe_entry")
                    if stat.S_ISDIR(info.st_mode):
                        if depth + 1 > max_depth:
                            raise ScanError("depth_limit")
                        observed["directories"] += 1
                        visit(Path(directory) / entry.name, depth + 1)
                    elif stat.S_ISREG(info.st_mode):
                        if info.st_size < 0:
                            raise ScanError("invalid_metadata")
                        observed["regular_files"] += 1
                        observed["logical_file_bytes"] += info.st_size
                        blocks = getattr(info, "st_blocks", None)
                        if blocks is None:
                            observed["filesystem_reported_allocated_bytes"] = None
                        elif type(blocks) is not int or blocks < 0:
                            raise ScanError("invalid_metadata")
                        elif observed["filesystem_reported_allocated_bytes"] is not None:
                            observed["filesystem_reported_allocated_bytes"] += blocks * 512
                    else:
                        raise ScanError("unsafe_entry")
        except FileNotFoundError:
            if depth == 0:
                raise ScanError("input_unavailable") from None
            observed["vanished_entries"] += 1
        except OSError:
            raise ScanError("input_unavailable") from None

    visit(root, 0)
    try:
        final = os.stat(root, follow_symlinks=False)
    except OSError:
        raise ScanError("input_unavailable") from None
    if (unsafe(final) or not stat.S_ISDIR(final.st_mode) or
            (final.st_dev, final.st_ino) != (initial.st_dev, initial.st_ino)):
        raise ScanError("unsafe_directory")
    return observed


class PrivateParser(argparse.ArgumentParser):
    def error(self, message):
        # argparse's original message can contain private argument values.
        raise ScanError("invalid_options")


def main(argv=None):
    parser = PrivateParser(prog="sample-private-staging", description=__doc__)
    parser.add_argument("--private-dir", required=True)
    parser.add_argument("--samples", type=int, default=1)
    parser.add_argument("--interval-ms", type=int, default=10)
    parser.add_argument("--max-entries", type=int, default=128)
    parser.add_argument("--max-depth", type=int, default=2)
    samples, error, failed_index, requested = [], None, None, None
    started = time.monotonic_ns()
    try:
        args = parser.parse_args(argv)
        if (not 1 <= args.samples <= 4096 or not 1 <= args.interval_ms <= 1000 or
                (args.samples - 1) * args.interval_ms > 60000):
            raise ScanError("invalid_options")
        requested = args.samples
        for index in range(args.samples):
            failed_index = index
            observed = snapshot(args.private_dir, args.max_entries, args.max_depth)
            samples.append({"index": index, "elapsed_ns": time.monotonic_ns() - started,
                            "staging": observed})
            failed_index = None
            if index + 1 < args.samples:
                time.sleep(args.interval_ms / 1000)
        failed_index = None
    except ScanError as failure:
        error = failure.category
    except KeyboardInterrupt:
        error = "cancelled"
    values = [row["staging"] for row in samples]
    allocated = [row["filesystem_reported_allocated_bytes"] for row in values]
    report = {"schema_version": 1, "status": "not_observed" if error else "observed",
              "category": error, "requested_samples": requested,
              "observed_samples": len(samples), "failed_sample_index": failed_index,
              "samples": samples,
              "maximum_sampled_logical_file_bytes": max((row["logical_file_bytes"] for row in values), default=None),
              "maximum_sampled_filesystem_reported_allocated_bytes":
                  max(allocated) if allocated and all(value is not None for value in allocated) else None,
              "known_vanished_entries": sum(row["vanished_entries"] for row in values),
              "scope": "Bounded non-atomic file metadata samples only. Short peaks and other changes can be missed; file block sums are not physical storage or quotas. Caller protects the root. No file contents, paths, names, cleanup, child processes or network access."}
    print(json.dumps(report, separators=(",", ":")))
    return 0 if error is None else (130 if error == "cancelled" else
                                    64 if error == "invalid_options" else
                                    2 if error in ("entry_limit", "depth_limit") else 70)


if __name__ == "__main__":
    sys.exit(main())
