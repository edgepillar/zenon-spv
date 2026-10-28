#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Read a completed candidate stream against the selected clean checkout."""
import importlib.util
import json
import os
from pathlib import Path
import sys

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location(
    "source_stream_exported_candidate", Path(__file__).with_name("check-exported-candidate.py"))
exported = importlib.util.module_from_spec(spec)
spec.loader.exec_module(exported)
checker = exported.checker


def verify(path, root, revision, os_name, architecture, require_skip_ledger=False):
    checker.require(type(require_skip_ledger) is bool, "arguments")
    inputs = exported.source_pin(root, revision)
    with exported.regular_file(path, checker.ARCHIVE_LIMIT, "archive") as (source, size):
        checker.require(size > 0, "archive")
        identity = exported.file_identity(os.fstat(source.fileno()))
        digest = checker.file_hash(source)
        source.seek(0)
        result = checker.check_stream_payload(source, size, revision, inputs, os_name, architecture,
                                              require_skip_ledger=require_skip_ledger)
        checker.require(exported.source_pin(root, revision) == inputs, "source")
        checker.require(exported.file_identity(os.fstat(source.fileno())) == identity
                        and exported.file_identity(path.lstat()) == identity, "archive")
    return {"schema_version": 1, "mode": "source_checked_candidate_stream", "status": "verified",
            "source": {"revision": revision, "inputs_sha256": inputs}, "os": os_name,
            "architecture": architecture, "payload": {"bytes": size, "sha256": digest},
            "verification": result}


def main(argv=None, output=None):
    output = sys.stdout if output is None else output
    parser = checker.Parser(prog="check-source-candidate-stream", allow_abbrev=False, add_help=False)
    for name in ("archive", "expect-revision", "expect-os", "expect-architecture"):
        parser.add_argument("--" + name, action=checker.Once, required=True)
    parser.add_argument("--require-skip-ledger", action=checker.OnceBoolean, nargs=0, default=None)
    code = 0
    try:
        args = parser.parse_args(argv)
        checker.require(0 < len(args.archive) <= 4096 and checker.digest(args.expect_revision, (40, 64))
                        and args.expect_os in ("linux", "darwin", "windows")
                        and type(args.expect_architecture) is str
                        and 0 < len(args.expect_architecture) <= 24
                        and all(c in "abcdefghijklmnopqrstuvwxyz0123456789_" for c in args.expect_architecture),
                        "arguments")
        result = verify(Path(args.archive), Path.cwd(), args.expect_revision, args.expect_os,
                        args.expect_architecture, args.require_skip_ledger is True)
    except checker.Rejected as failure:
        result = {"schema_version": 1, "status": "refused", "category": failure.category}
        code = 64 if failure.category == "arguments" else 2
    except (Exception, KeyboardInterrupt):
        result = {"schema_version": 1, "status": "refused", "category": "input"}
        code = 2
    raw = json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n"
    try:
        written = output.write(raw)
        if type(written) is not int or written != len(raw):
            return 70
        output.flush()
    except (OSError, TypeError, ValueError):
        return 70
    return code


if __name__ == "__main__":
    raise SystemExit(main())
