#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Select three fresh file-checker CLIs with an explicit, source-bound hex recipe.

The original checker and its entrypoint guard execute unchanged. A new report
channel keeps their stdout, stderr and exit contract separate from this recipe.
No import hook, subprocess patch, disk cache or reference backend is installed.
"""
import argparse
import ast
from contextlib import contextmanager, redirect_stderr, redirect_stdout
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import threading
from types import ModuleType

HERE = Path(__file__).resolve().parent
TOOL = Path(__file__).resolve()
TARGET = "check_patch_file_resources.py"
CONTROL = "check_patch_file_resources_test.py"
TARGET_SHA256 = "10cfa1e7af12ed8047e86a43e1713ad8c5b24bd02861d19ff6f546868a04f8cc"
CONTROL_SHA256 = "c1a4e70959e8be8501a6be0ee178a442cf361f08b92abeafc9f42a1d1c0ee867"
MAX_REPORT_BYTES = 256 << 10
KINDS = ("valid-revision", "invalid-revision", "tampered-corpus")
REPORT_FIELDS = frozenset(("format_version", "kind", "execution_revision", "program", "mode",
    "helper_sha256", "declared_exit", "stdout_sha256", "stdout_bytes", "stderr_sha256", "stderr_bytes",
    "binding_manifest", "selected_function_identities_restored", "original_entrypoint_guard_executed",
    "recorded_producer_source_inputs_rebound", "reference_backend_executed", "production_acceptance_enabled"))


def require(value):
    if not value:
        raise ValueError("Selected child hex execution refused")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode("utf-8")


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, HERE / file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def report_destination(path):
    path = Path(path)
    require(path.is_absolute() and not os.path.lexists(path))
    # The caller owns a new stable report parent. This is not a filesystem sandbox.
    for ancestor in (path.parent, *path.parent.parents):
        info = ancestor.lstat()
        require(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode))
    return path


def write_report(path, value):
    raw = encoded(value)
    require(len(raw) <= MAX_REPORT_BYTES)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    with os.fdopen(os.open(path, flags, 0o600), "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def read_report(path):
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1)
    with os.fdopen(os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)), "rb") as stream:
        opened = os.fstat(stream.fileno())
        require((opened.st_dev, opened.st_ino) == (before.st_dev, before.st_ino))
        raw = stream.read(MAX_REPORT_BYTES + 1)
    after = path.lstat()
    require(after.st_nlink == 1 and stat.S_ISREG(after.st_mode)
            and (after.st_dev, after.st_ino, after.st_size) == (opened.st_dev, opened.st_ino, len(raw)))
    require(len(raw) <= MAX_REPORT_BYTES)
    value = json.loads(raw)
    require(encoded(value) == raw)
    return value


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("reference", "translated"), required=True)
    parser.add_argument("--execution-revision", required=True)
    parser.add_argument("--report", required=True)
    parser.add_argument("arguments", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    require(re.fullmatch("[0-9a-f]{40}", args.execution_revision) is not None)
    require(args.arguments and args.arguments[0] == "--")
    destination = report_destination(args.report)
    target_raw = (HERE / TARGET).read_bytes()
    require(sha(target_raw) == TARGET_SHA256)
    tool_pin = sha(TOOL.read_bytes())
    hex_oracle = load("selected_child_hex_oracle", "project_target_hex.py")
    program = hex_oracle.load("selected_child_original_checker", TARGET)
    guard = ast.parse(target_raw).body[-1]
    require(isinstance(guard, ast.If)
            and ast.dump(guard.test) == ast.dump(ast.parse('__name__ == "__main__"', mode="eval").body))
    stdout_buffer, stderr_buffer = io.BytesIO(), io.BytesIO()
    # Match the fresh interpreter's text encoding and native newline behavior,
    # including CRLF on Windows, before emitting the captured bytes unchanged.
    stdout = io.TextIOWrapper(stdout_buffer, encoding=sys.stdout.encoding or "utf-8",
                              errors=sys.stdout.errors or "strict", newline=None, write_through=True)
    stderr = io.TextIOWrapper(stderr_buffer, encoding=sys.stderr.encoding or "utf-8",
                              errors=sys.stderr.errors or "strict", newline=None, write_through=True)
    previous_argv, previous_name = sys.argv, program.__name__
    status = 0
    try:
        sys.argv = [str(HERE / TARGET), *args.arguments[1:]]
        program.__name__ = "__main__"
        with hex_oracle.selected_oracles(program, TARGET, args.mode) as bindings:
            with redirect_stdout(stdout), redirect_stderr(stderr):
                try:
                    # Execute the pinned original CLI guard, including its own
                    # argparse, error handler and exit behavior.
                    exec(compile(ast.Module(body=[guard], type_ignores=[]), str(HERE / TARGET), "exec"), vars(program))
                except SystemExit as exit_result:
                    require(type(exit_result.code) is int and exit_result.code in (0, 1, 2))
                    status = exit_result.code
    finally:
        sys.argv, program.__name__ = previous_argv, previous_name
    require(sha(TOOL.read_bytes()) == tool_pin and sha((HERE / TARGET).read_bytes()) == TARGET_SHA256)
    stdout.flush()
    stderr.flush()
    output, errors = stdout_buffer.getvalue(), stderr_buffer.getvalue()
    write_report(destination, {
        "format_version": 1, "kind": "selected-child-target-hex-CLI",
        "execution_revision": args.execution_revision, "program": TARGET, "mode": args.mode,
        "helper_sha256": tool_pin, "declared_exit": status,
        "stdout_sha256": sha(output), "stdout_bytes": len(output),
        "stderr_sha256": sha(errors), "stderr_bytes": len(errors),
        "binding_manifest": bindings, "selected_function_identities_restored": True,
        "original_entrypoint_guard_executed": True,
        "recorded_producer_source_inputs_rebound": False,
        "reference_backend_executed": False, "production_acceptance_enabled": False,
    })
    sys.stdout.buffer.write(output)
    sys.stderr.buffer.write(errors)
    return status


class SelectedChildren:
    def __init__(self, program, mode, revision):
        require(type(program) is ModuleType and type(getattr(program, "__file__", None)) is str
                and Path(program.__file__).resolve() == HERE / CONTROL)
        require(sha((HERE / CONTROL).read_bytes()) == CONTROL_SHA256)
        require(sha((HERE / TARGET).read_bytes()) == TARGET_SHA256)
        require(type(mode) is str and mode in ("reference", "translated")
                and type(revision) is str and re.fullmatch("[0-9a-f]{40}", revision) is not None)
        require(getattr(program, "CLI_RUN", None) is subprocess.run)
        self.program, self.mode, self.revision = program, mode, revision
        self.original, self.replacement = program.CLI_RUN, self.invoke
        self.tool_pin = sha(TOOL.read_bytes())
        self.thread, self.records, self.closed = threading.get_ident(), [], False
        # Derive the expected complete recipe from a separate private import.
        # The active parent's selected functions never supply this expectation.
        oracle = load("selected_child_parent_oracle", "project_target_hex.py")
        original = oracle.load("selected_child_parent_checker", TARGET)
        with oracle.selected_oracles(original, TARGET, mode) as bindings:
            self.expected_bindings = json.loads(json.dumps(bindings))

    def invoke(self, argv, **kwargs):
        require(not self.closed and threading.get_ident() == self.thread)
        require(self.program.CLI_RUN is self.replacement and len(self.records) < 3)
        require(type(argv) is list and all(type(value) is str for value in argv))
        require(kwargs == {"capture_output": True})
        require(argv[:4] == [sys.executable, "-I", "-B", str(HERE / TARGET)])
        arguments = argv[4:]
        require(len(arguments) == 2)
        if arguments == ["--source-revision", "ab" * 20]:
            kind = "valid-revision"
        elif arguments == ["--source-revision", "invalid"]:
            kind = "invalid-revision"
        else:
            require(arguments[0] == "--corpus" and Path(arguments[1]).name == "tampered.json")
            kind = "tampered-corpus"
        require(kind == KINDS[len(self.records)])
        with tempfile.TemporaryDirectory(prefix="selected-child-hex-") as temporary:
            path = Path(temporary) / "execution.json"
            command = [sys.executable, "-I", "-B", str(TOOL), "--mode", self.mode,
                       "--execution-revision", self.revision, "--report", str(path), "--", *arguments]
            result = subprocess.run(command, capture_output=True, timeout=60)
            report = read_report(path)
        require(type(report) is dict and set(report) == REPORT_FIELDS)
        require(report["kind"] == "selected-child-target-hex-CLI"
                and type(report["format_version"]) is int and report["format_version"] == 1 and report["program"] == TARGET
                and report["mode"] == self.mode and report["execution_revision"] == self.revision
                and report["helper_sha256"] == self.tool_pin)
        require(type(result.returncode) is int and type(report["declared_exit"]) is int
                and result.returncode == report["declared_exit"] == (0 if kind == "valid-revision" else 1))
        require(report["binding_manifest"] == self.expected_bindings)
        for name in ("stdout", "stderr"):
            raw = getattr(result, name)
            require(type(raw) is bytes and type(report[name + "_bytes"]) is int
                    and len(raw) == report[name + "_bytes"] and sha(raw) == report[name + "_sha256"])
        require(report["selected_function_identities_restored"] is True
                and report["original_entrypoint_guard_executed"] is True
                and report["recorded_producer_source_inputs_rebound"] is False
                and report["reference_backend_executed"] is False
                and report["production_acceptance_enabled"] is False)
        self.records.append({"selection": kind, "actual_exit": result.returncode,
                             "actual_streams_bound": True, "recipe": report})
        # Return the actual child's unfiltered output and exit, never a projected
        # successful result or a console stream with a recipe stripped from it.
        return result

    def report(self):
        require(self.closed and len(self.records) == 3)
        return {"format_version": 1, "kind": "explicit-selected-child-hex-execution",
                "execution_revision": self.revision, "program": CONTROL, "mode": self.mode,
                "helper_sha256": self.tool_pin, "control_source_sha256": CONTROL_SHA256,
                "actual_fresh_CLI_processes": 3, "children": json.loads(json.dumps(self.records)),
                "test_local_dispatch_restored": True, "stdio_filtered": False,
                "global_subprocess_patch_installed": False, "import_hook_installed": False,
                "disk_cache_created": False, "reference_backend_executed": False,
                "recorded_producer_source_inputs_rebound": False}


@contextmanager
def selected_children(program, selected, mode, revision):
    require(selected == CONTROL)
    owner = SelectedChildren(program, mode, revision)
    program.CLI_RUN = owner.replacement
    try:
        yield owner
    finally:
        intact = program.CLI_RUN is owner.replacement
        program.CLI_RUN = owner.original
        owner.closed = True
        require(intact and sha(TOOL.read_bytes()) == owner.tool_pin
                and sha((HERE / CONTROL).read_bytes()) == CONTROL_SHA256)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, KeyError, TypeError, OSError, OverflowError, RecursionError):
        print("Selected child hex execution refused; original CLI output is not qualified.", file=sys.stderr)
        sys.exit(1)
