#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Write a source-checked candidate stream to binary stdout without an input copy."""
import contextlib
import importlib.util
from pathlib import Path
import sys

sys.dont_write_bytecode = True


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


exported = load("stream_exported_candidate", "check-exported-candidate.py")
checker = exported.checker
try:
    stream = load("candidate_stream_writer", "candidate_stream.py")
except ImportError:
    stream = None


def pack(directory, root, revision, os_name, architecture, output, require_skip_ledger=False):
    checker.require(stream is not None, "input")
    checker.require(type(require_skip_ledger) is bool, "arguments")
    inputs = exported.source_pin(root, revision)
    suffix = ".exe" if os_name == "windows" else ""
    names = ("manifest.json", "offline-pilot.json") + tuple(name + suffix for name in checker.COMMANDS)
    limits = {name + suffix: checker.BINARY_LIMIT for name in checker.COMMANDS}
    limits.update({"manifest.json": 256 << 10, "offline-pilot.json": 4 << 20})
    with contextlib.ExitStack() as stack:
        members, infos = stack.enter_context(exported.opened_candidate(directory, os_name))

        def validate(selected, selected_infos):
            return checker.check_payloads(selected, selected_infos, revision, inputs, os_name, architecture,
                                          require_skip_ledger=require_skip_ledger)

        def postcheck():
            # Check/close the same descriptors before publishing an XZ end marker.
            stack.close()
            checker.require(exported.source_pin(root, revision) == inputs, "source")

        return stream.write_checked(members, infos, names, limits, output, validate, postcheck)


def main(argv=None, output=None, errors=None):
    output = sys.stdout.buffer if output is None else output
    errors = sys.stderr if errors is None else errors
    if stream is None:
        errors.write("Candidate stream compression is unavailable.\n")
        return 2
    parser = checker.Parser(prog="pack-candidate-stream", allow_abbrev=False, add_help=False)
    for name in ("directory", "expect-revision", "expect-os", "expect-architecture"):
        parser.add_argument("--" + name, action=checker.Once, required=True)
    parser.add_argument("--require-skip-ledger", action=checker.OnceBoolean, nargs=0, default=None)
    try:
        args = parser.parse_args(argv)
        checker.require(0 < len(args.directory) <= 4096 and checker.digest(args.expect_revision, (40, 64))
                        and args.expect_os in ("linux", "darwin", "windows")
                        and type(args.expect_architecture) is str
                        and 0 < len(args.expect_architecture) <= 24
                        and all(c in "abcdefghijklmnopqrstuvwxyz0123456789_" for c in args.expect_architecture), "arguments")
        pack(Path(args.directory), Path.cwd(), args.expect_revision, args.expect_os, args.expect_architecture,
             output, require_skip_ledger=args.require_skip_ledger is True)
    except checker.Rejected as failure:
        errors.write("Candidate stream refused (" + failure.category + ").\n")
        return 64 if failure.category == "arguments" else 2
    except stream.OutputFailure:
        errors.write("Candidate stream output did not complete.\n")
        return 70
    except (Exception, KeyboardInterrupt):
        errors.write("Candidate stream refused (input).\n")
        return 2
    try:
        output.flush()
    except (OSError, TypeError, ValueError):
        errors.write("Candidate stream output did not complete.\n")
        return 70
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
