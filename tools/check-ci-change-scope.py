# SPDX-License-Identifier: GPL-3.0-only
"""Select documentation-only CI from an exact, bounded, read-only Git diff.

This selects work; it never qualifies an executable at a new revision. Any
missing selection, changed source, incomplete command or unrecognized record
requires the complete runtime jobs.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import threading
import time

FORMAT = "zenon-ci-change-scope/v1"
REPOSITORY = "edgepillar/zenon-spv"
MAX_DIFF_BYTES = 256 << 10
MAX_SOURCE_BYTES = 256 << 10
MAX_REPORT_BYTES = 1 << 20
MAX_PATH_BYTES = 512
MAX_RECORDS = 512
GIT_TIMEOUT = 10
SOURCE_FILES = ("tools/check-ci-change-scope.py",
                "tools/check-ci-change-scope_test.py", ".github/workflows/ci.yml")
OID = re.compile(r"[0-9a-f]{40}\Z")
ZERO = "0" * 40
RAW_HEADER = re.compile(rb":([0-7]{6}) ([0-7]{6}) ([0-9a-f]{40}) ([0-9a-f]{40}) ([AMD])\Z")
COMPONENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")
RESERVED = {"CON", "PRN", "AUX", "NUL"} | {
    prefix + str(number) for prefix in ("COM", "LPT") for number in range(1, 10)}


class ScopeError(Exception):
    def __init__(self, reason):
        self.reason = reason
        super().__init__(reason)


def valid_oid(value):
    return type(value) is str and OID.fullmatch(value) is not None and value != ZERO


def document_path(raw):
    if not 0 < len(raw) <= MAX_PATH_BYTES:
        return False
    try:
        path = raw.decode("ascii")
    except UnicodeDecodeError:
        return False
    if path == "README.md":
        return True
    parts = path.split("/")
    return (len(parts) >= 2 and parts[0] == "docs" and parts[-1].endswith(".md")
            and all(COMPONENT.fullmatch(part) is not None and not part.endswith(".")
                    and part.split(".", 1)[0].upper() not in RESERVED for part in parts))


def parse_diff(raw):
    if type(raw) is not bytes or len(raw) > MAX_DIFF_BYTES:
        raise ScopeError("diff_bounds")
    if not raw:
        # Identity-only and other empty-tree changes still require fresh CI.
        raise ScopeError("empty_diff")
    if not raw.endswith(b"\0"):
        raise ScopeError("diff_framing")
    fields = raw.split(b"\0")[:-1]
    if len(fields) % 2 or not 0 < len(fields) // 2 <= MAX_RECORDS:
        raise ScopeError("diff_framing")
    paths = []
    seen = set()
    case_names = set()
    for header, path in zip(fields[::2], fields[1::2]):
        match = RAW_HEADER.fullmatch(header)
        if match is None:
            raise ScopeError("diff_record")
        old_mode, new_mode, old_oid, new_oid, change = match.groups()
        expected = {b"A": (b"000000", b"100644"),
                    b"D": (b"100644", b"000000"),
                    b"M": (b"100644", b"100644")}[change]
        if (old_mode, new_mode) != expected:
            raise ScopeError("file_mode")
        zero = ZERO.encode()
        if ((old_oid == zero) != (change == b"A")
                or (new_oid == zero) != (change == b"D")
                or old_oid == new_oid):
            raise ScopeError("diff_identity")
        if not document_path(path):
            raise ScopeError("outside_documentation")
        if path in seen:
            raise ScopeError("duplicate_path")
        if path.lower() in case_names:
            raise ScopeError("case_alias")
        seen.add(path)
        case_names.add(path.lower())
        paths.append({"path": path.decode("ascii"), "change": change.decode("ascii")})
    return paths


def _empty_stream():
    return {"captured_bytes": 0, "observed_bytes": 0,
            "sha256": hashlib.sha256(b"").hexdigest(), "eof": False,
            "truncated": False, "read_error": False}


def bounded_command(command, root, stdout_limit, timeout=GIT_TIMEOUT, env=None):
    """Retain bounded prefixes and actual exit/EOF; never print diagnostics."""
    stopped = threading.Event()
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    streams = {name: _empty_stream() for name in buffers}
    receipt = {"actual_exit": None, "launch_error": False, "timed_out": False,
               "capture_complete": False, "readers_joined": False, "streams": streams}
    try:
        process = subprocess.Popen(command, cwd=root, env=env, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError:
        receipt["launch_error"] = True
        return b"", receipt

    def drain(name, pipe, cap):
        row = streams[name]
        try:
            while True:
                chunk = pipe.read(min(8192, cap + 1 - row["observed_bytes"]))
                if not chunk:
                    row["eof"] = True
                    break
                row["observed_bytes"] += len(chunk)
                remaining = max(0, cap - len(buffers[name]))
                buffers[name].extend(chunk[:remaining])
                if row["observed_bytes"] > cap:
                    row["truncated"] = True
                    stopped.set()
                    break
        except OSError:
            row["read_error"] = True
            stopped.set()
        finally:
            pipe.close()

    readers = [threading.Thread(target=drain, args=(name, pipe, cap), daemon=True)
               for name, pipe, cap in (("stdout", process.stdout, stdout_limit),
                                       ("stderr", process.stderr, 4096))]
    started_readers = []
    try:
        for reader in readers:
            reader.start()
            started_readers.append(reader)
        deadline = time.monotonic() + timeout
        while process.poll() is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                receipt["timed_out"] = True
                break
            if stopped.wait(min(0.05, remaining)):
                break
        if process.poll() is None:
            process.kill()
        try:
            receipt["actual_exit"] = process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            pass
    except BaseException:
        if process.poll() is None:
            process.kill()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            pass
        raise
    finally:
        for reader in started_readers:
            reader.join(timeout=2)
        for reader, pipe in zip(readers, (process.stdout, process.stderr)):
            if reader not in started_readers:
                pipe.close()
    receipt["readers_joined"] = all(not reader.is_alive() for reader in readers)
    for name, row in streams.items():
        row["captured_bytes"] = len(buffers[name])
        row["sha256"] = hashlib.sha256(buffers[name]).hexdigest()
    receipt["capture_complete"] = (
        receipt["actual_exit"] is not None and receipt["readers_joined"]
        and not receipt["timed_out"]
        and all(row["eof"] and not row["truncated"] and not row["read_error"]
                for row in streams.values()))
    return bytes(buffers["stdout"]), receipt


def run_git(root, args, limit):
    env = dict(os.environ, GIT_NO_REPLACE_OBJECTS="1", GIT_OPTIONAL_LOCKS="0")
    raw, receipt = bounded_command(
        ["git", "--no-optional-locks", "-c", "core.fsmonitor=false", *args],
        root, limit, env=env)
    receipt["git_arguments"] = args
    return raw, receipt


def selection_valid(selection):
    return (selection["repository"] == REPOSITORY
            and selection["event"] in ("push", "pull_request")
            and all(valid_oid(selection[key]) for key in
                    ("base_revision", "feature_revision", "checkout_revision"))
            and type(selection["run_id"]) is int and selection["run_id"] > 0
            and type(selection["run_attempt"]) is int and selection["run_attempt"] > 0)


def select_scope(root, selection, runner=run_git):
    report = {"format": FORMAT, "selection": selection, "status": "RUNTIME_REQUIRED",
              "run_runtime": True, "reason": "invalid_selection", "source_tree": None,
              "source_binding_complete": False, "source_pins": {}, "commands": [],
              "documentation_paths": [], "selection_only": True,
              "runtime_qualification_transferred": False}

    def query(args, limit):
        raw, receipt = runner(root, args, limit)
        report["commands"].append(receipt)
        if receipt["actual_exit"] != 0 or not receipt["capture_complete"]:
            raise ScopeError("git_incomplete_or_failed")
        if type(raw) is not bytes or len(raw) > limit:
            raise ScopeError("git_bounds")
        return raw

    try:
        if not selection_valid(selection):
            return report
        line = query(["rev-list", "--parents", "--max-count=1", "HEAD"], 1024)
        if re.fullmatch(rb"[0-9a-f]{40}(?: [0-9a-f]{40}){0,2}\n", line) is None:
            raise ScopeError("checkout_record")
        identifiers = line.decode("ascii").strip().split(" ")
        checkout, parents = identifiers[0], identifiers[1:]
        if checkout != selection["checkout_revision"]:
            raise ScopeError("checkout_mismatch")
        base, feature = selection["base_revision"], selection["feature_revision"]
        if selection["event"] == "pull_request":
            if parents != [base, feature]:
                raise ScopeError("pull_request_parents")
        elif checkout != feature or base not in parents:
            raise ScopeError("push_parent")
        tree = query(["rev-parse", "HEAD^{tree}"], 64)
        if re.fullmatch(rb"[0-9a-f]{40}\n", tree) is None or not valid_oid(tree[:-1].decode("ascii")):
            raise ScopeError("tree_record")
        report["source_tree"] = tree[:-1].decode("ascii")
        if (Path(root) / SOURCE_FILES[0]).resolve(strict=True) != Path(__file__).resolve(strict=True):
            raise ScopeError("source_binding")
        for name in SOURCE_FILES:
            path = Path(root) / name
            if not stat.S_ISREG(path.lstat().st_mode):
                raise ScopeError("source_binding")
            with path.open("rb") as stream:
                working = stream.read(MAX_SOURCE_BYTES + 1)
            if len(working) > MAX_SOURCE_BYTES:
                raise ScopeError("source_bounds")
            selected = query(["show", checkout + ":" + name], MAX_SOURCE_BYTES)
            relation = ("exact" if working == selected else "CRLF-only"
                        if b"\r\n" not in selected and working == selected.replace(b"\n", b"\r\n")
                        else None)
            if relation is None:
                raise ScopeError("source_binding")
            report["source_pins"][name] = {
                "git_sha256": hashlib.sha256(selected).hexdigest(), "git_bytes": len(selected),
                "checkout_sha256": hashlib.sha256(working).hexdigest(),
                "checkout_bytes": len(working), "checkout_relation": relation}
        report["source_binding_complete"] = True
        raw = query(["diff", "--raw", "-z", "--no-abbrev", "--no-renames",
                     "--no-ext-diff", "--no-textconv", "--ignore-submodules=none",
                     base, checkout, "--"], MAX_DIFF_BYTES)
        report["documentation_paths"] = parse_diff(raw)
        report.update(status="DOCUMENTATION_ONLY", run_runtime=False, reason="regular_markdown_only")
    except ScopeError as error:
        report["reason"] = error.reason
    except (OSError, UnicodeError, KeyError, TypeError, ValueError):
        report["reason"] = "selection_or_source_unavailable"
    return report


class Parser(argparse.ArgumentParser):
    def error(self, message):
        self.exit(64, "ci-scope: invalid options\n")


def main(argv=None, stdout=None):
    parser = Parser(description=__doc__)
    parser.add_argument("--source", default=".")
    for name in ("repository", "event", "base-revision", "feature-revision", "checkout-revision"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--run-id", required=True, type=int)
    parser.add_argument("--run-attempt", required=True, type=int)
    args = parser.parse_args(argv)
    selection = {key: getattr(args, key) for key in
                 ("repository", "event", "base_revision", "feature_revision",
                  "checkout_revision", "run_id", "run_attempt")}
    report = select_scope(Path(args.source), selection)
    raw = json.dumps(report, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n"
    if len(raw.encode("utf-8")) > MAX_REPORT_BYTES:
        return 70
    output = sys.stdout if stdout is None else stdout
    try:
        output.write(raw)
        output.flush()
    except (OSError, ValueError):
        return 70
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
