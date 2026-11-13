# SPDX-License-Identifier: GPL-3.0-only
"""Select documentation-only, portable or native-only CI from a bounded Git diff.

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
NATIVE_FORMAT = "zenon-ci-change-scope/v3"
PORTABLE_FORMAT = "zenon-ci-change-scope/v6"
REPOSITORY = "edgepillar/zenon-spv"
MAX_DIFF_BYTES = 256 << 10
MAX_SOURCE_BYTES = 256 << 10
MAX_REPORT_BYTES = 1 << 20
MAX_PATH_BYTES = 512
MAX_RECORDS = 512
GIT_TIMEOUT = 10
SOURCE_FILES = ("tools/check-ci-change-scope.py",
                "tools/check-ci-change-scope_test.py", ".github/workflows/ci.yml")
# These existing Go leaves are exercised by the native jobs, not by the
# recorded Python oracle job. New files and other Go paths are not eligible.
NATIVE_FILES = frozenset("internal/verify/experimental_v3_" + name for name in (
    "state.go", "profile.go", "file.go", "checkpoint.go", "state_test.go",
    "profile_test.go", "file_test.go", "checkpoint_test.go", "workflow_test.go",
    "retention_test.go"))
# Every other non-document tree record remains in this reviewed closure,
# including workflows, research Go sources, Python helpers and fixture data.
ORACLE_SOURCE_PIN = "2966fb81c46e9e0948f0cd9dd6922df679b7a7c88f0434078b4dad2e9d3a96e4"
SHARED_TRANSPORT = "tools/ledger-transport/transport.py"
TRANSPORT_FILES = frozenset("tools/ledger-transport/" + name for name in (
    "archive_index.py", "archive_index_test.py", "archive_tail.py", "archive_tail_test.py",
    "transport.py", "transport_test.py", "README.md", "THIRD_PARTY_NOTICES"))
EXPORT_FILES = frozenset("tools/ledger-export/" + name for name in (
    "inventory_completed_export.py", "inventory_completed_export_test.py", "README.md"))
PREPARATION_FILES = frozenset("tools/owned-devnet-query/" + name for name in (
    "engine_test.py", "images_test.py", "inputs.py", "inputs_test.py",
    "capture_test.py", "review.py", "review_test.py", "README.md"))
PORTABLE_FILES = TRANSPORT_FILES | EXPORT_FILES | PREPARATION_FILES
TRANSPORT_DOCS = frozenset(("docs/state-root-r1-intake.md", "docs/native-roadmap.md"))
PORTABLE_WORKFLOWS = (
    (".github/workflows/ledger-transport.yml", TRANSPORT_FILES | TRANSPORT_DOCS, 7894,
     "3101f06e85bd6bd6d74fe89e86e06a04cce38a26aad7d945f5371880250e49b0"),
    (".github/workflows/ledger-export.yml", EXPORT_FILES | {SHARED_TRANSPORT}, 8084,
     "8fab1803332f60cac43a20b8940988b19c38b8dd0359f005f605dcc55dcb98fb"),
    (".github/workflows/owned-devnet-query.yml", PREPARATION_FILES, 4453,
     "cf4ddd4e2c7a5388af336e42e5d47ce43ca112ed2c699731d4b8cd2137977d66"),
)
# Keep every remaining non-document dependency, including all workflows.
# Refresh only after reviewing dependencies and selecting full runtime CI.
PORTABLE_SOURCE_PIN = "72b06cf37291dfb0610a715aa8dcf80fa7800992194abc58edcaf327085901f5"
MAX_FILTERED_DIFF_RECORDS = 256
MAX_TREE_BYTES = 2 << 20
MAX_TREE_RECORDS = 8192
TREE_RECORD = re.compile(rb"(100644|100755|120000|160000) (blob|commit) ([0-9a-f]{40})\t([^\0]+)\Z")
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


def parse_diff(raw, modified_paths=(), nonmodification_reason="outside_documentation"):
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
            name = path.decode("ascii", errors="replace")
            if name not in modified_paths:
                raise ScopeError("outside_documentation")
            if change != b"M":
                raise ScopeError(nonmodification_reason)
        if path in seen:
            raise ScopeError("duplicate_path")
        if path.lower() in case_names:
            raise ScopeError("case_alias")
        seen.add(path)
        case_names.add(path.lower())
        paths.append({"path": path.decode("ascii"), "change": change.decode("ascii")})
    return paths


def oracle_fingerprint(raw):
    """Exclude only regular reviewed native leaves, documents and selector code."""
    return tree_fingerprint(raw, NATIVE_FILES | set(SOURCE_FILES[:2]))


def portable_fingerprint(raw):
    return tree_fingerprint(raw, PORTABLE_FILES | set(SOURCE_FILES[:2]))


def tree_fingerprint(raw, excluded_paths):
    if (type(raw) is not bytes or not 0 < len(raw) <= MAX_TREE_BYTES
            or not raw.endswith(b"\0")):
        raise ScopeError("runtime_tree_bounds")
    records = raw.split(b"\0")[:-1]
    if not 0 < len(records) <= MAX_TREE_RECORDS:
        raise ScopeError("runtime_tree_bounds")
    kept, seen = [], set()
    excluded = {path.encode("ascii") for path in excluded_paths}
    for record in records:
        match = TREE_RECORD.fullmatch(record)
        if match is None:
            raise ScopeError("runtime_tree_record")
        mode, kind, oid, path = match.groups()
        if ((mode == b"160000") != (kind == b"commit") or oid == ZERO.encode()
                or len(path) > 4096 or path.startswith(b"/") or b"\\" in path
                or any(part in (b"", b".", b"..") for part in path.split(b"/"))
                or path in seen):
            raise ScopeError("runtime_tree_record")
        seen.add(path)
        if mode == b"100644" and (path in excluded or document_path(path)):
            continue
        kept.append(record + b"\0")
    if not kept:
        raise ScopeError("runtime_tree_empty")
    encoded = b"".join(sorted(kept))
    return {"sha256": hashlib.sha256(encoded).hexdigest(), "bytes": len(encoded),
            "entries": len(kept)}


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

    def bind_source(name, checkout):
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
        return selected

    def bind_workflow(name, size, digest):
        selected = bind_source(name, checkout)
        previous = query(["show", base + ":" + name], MAX_SOURCE_BYTES)
        if (selected != previous or len(selected) != size
                or hashlib.sha256(selected).hexdigest() != digest):
            raise ScopeError("portable_workflow_pin")
        return {"path": name, "sha256": digest, "bytes": size, "base_matches_checkout": True}

    def bind_portable_event():
        if parents[0] != base:
            raise ScopeError("portable_event_diff")
        if selection["event"] == "pull_request":
            # GitHub's path-filter diff must match the reviewed test merge.
            raw_feature = query(["cat-file", "commit", feature], MAX_SOURCE_BYTES)
            header, separator, _ = raw_feature.partition(b"\n\n")
            lines = header.split(b"\n")
            if (not separator or lines[0] != b"tree " + tree[:-1]
                    or [line for line in lines if line.startswith(b"parent ")]
                    != [b"parent " + base.encode("ascii")]):
                raise ScopeError("portable_event_diff")

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
            bind_source(name, checkout)
        report["source_binding_complete"] = True
        raw = query(["diff", "--raw", "-z", "--no-abbrev", "--no-renames",
                     "--no-ext-diff", "--no-textconv", "--ignore-submodules=none",
                     base, checkout, "--"], MAX_DIFF_BYTES)
        reviewed = PORTABLE_FILES | NATIVE_FILES
        paths = parse_diff(raw, reviewed, "reviewed_leaf_change")
        native = [row for row in paths if row["path"] in NATIVE_FILES]
        portable = [row for row in paths if row["path"] in PORTABLE_FILES]
        documents = [row for row in paths if row["path"] not in reviewed]
        if native and portable:
            raise ScopeError("mixed_runtime_leaves")
        if native:
            report.update(format=NATIVE_FORMAT, run_recorded_oracles=True)
            closure = oracle_fingerprint(query(
                ["ls-tree", "-r", "-z", "--full-tree", checkout], MAX_TREE_BYTES))
            if closure["sha256"] != ORACLE_SOURCE_PIN:
                raise ScopeError("oracle_source_pin")
            report.update(status="NATIVE_RUNTIME_ONLY", run_runtime=True,
                          run_recorded_oracles=False, reason="modified_native_v3_leaves",
                          documentation_paths=documents, native_paths=native,
                          oracle_closure={**closure, "expected_sha256": ORACLE_SOURCE_PIN,
                                          "matched": True})
        elif portable:
            # Leave room below GitHub's path-filter diff limit, including docs.
            if len(paths) > MAX_FILTERED_DIFF_RECORDS:
                raise ScopeError("portable_diff_count")
            report["format"] = PORTABLE_FORMAT
            bind_portable_event()
            names = {row["path"] for row in paths}
            workflows = [bind_workflow(name, size, digest)
                         for name, triggers, size, digest in PORTABLE_WORKFLOWS
                         if names & triggers]
            closure = portable_fingerprint(query(
                ["ls-tree", "-r", "-z", "--full-tree", checkout], MAX_TREE_BYTES))
            if closure["sha256"] != PORTABLE_SOURCE_PIN:
                raise ScopeError("portable_source_pin")
            report.update(status="PORTABLE_WORKFLOWS_ONLY", run_runtime=False,
                          reason="modified_reviewed_portable_leaves",
                          documentation_paths=documents, portable_paths=portable,
                          portable_event_tree=report["source_tree"],
                          required_workflows=[workflow["path"] for workflow in workflows],
                          portable_workflows=workflows,
                          runtime_closure={**closure, "expected_sha256": PORTABLE_SOURCE_PIN,
                                           "matched": True})
        else:
            report["documentation_paths"] = documents
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
