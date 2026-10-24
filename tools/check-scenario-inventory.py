#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Compare an offline report with a separately selected source checkout.

This is a scenario-selection companion to full candidate validation. It never
packages files, hashes executable payloads, runs tests or authenticates execution.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
REPORT_LIMIT = 4 << 20
SCENARIO_SOURCE_LIMIT = 64 << 10
TOKEN_LIMIT = 16384
WORD = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
SCENARIO_PATH = "tools/offline-pilot/manifest.go"
DEPENDENCIES = {
    "check-candidate-archive.py": (31418, "1faa1b0b30e3296b43b30d9abe160f8a4aa655f93ea1c87fd910cbf35c24fefc"),
    "check-exported-candidate.py": (10446, "bb2d20cb30ee31ae004b6d050bf51fa96f95594e0ea31755e928f6a726a708ba"),
}
_PRIMITIVES = None


class Rejected(Exception):
    def __init__(self, category):
        self.category = category


def require(condition, category):
    if not condition:
        raise Rejected(category)


def dependencies_intact():
    for name, (size, digest) in DEPENDENCIES.items():
        path = HERE / name
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_size == size, "checker_source")
        with path.open("rb") as stream:
            raw = stream.read(size + 1)
        require(len(raw) == size and hashlib.sha256(raw).hexdigest() == digest, "checker_source")


def primitives():
    global _PRIMITIVES
    if _PRIMITIVES is None:
        dependencies_intact()
        spec = importlib.util.spec_from_file_location(
            "scenario_inventory_candidate_primitives", HERE / "check-exported-candidate.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        dependencies_intact()
        _PRIMITIVES = module
    return _PRIMITIVES


def read_regular(path, limit, category):
    """Read one descriptor-selected snapshot, with real EOF and closed handles."""
    p = primitives()
    try:
        with p.regular_file(Path(path), limit, category) as (stream, size):
            require(0 < size <= limit, category)
            before = p.file_identity(os.fstat(stream.fileno()))
            pathname = p.file_identity(Path(path).lstat())
            # The pinned identity tuple ends with ctime. On Windows, stat()
            # and fstat() can expose different meanings for that field.
            # Bind the other identity fields across APIs and retain both full
            # snapshots so changes within either API still reject the read.
            require(before[:-1] == pathname[:-1], category)
            raw = b"".join(p.chunks(stream, size, category))
            require(p.file_identity(os.fstat(stream.fileno())) == before
                    and p.file_identity(Path(path).lstat()) == pathname, category)
        return raw
    except p.checker.Rejected:
        raise Rejected(category) from None
    except OSError:
        raise Rejected(category) from None


def tokens(text):
    """Accept only the bounded literal Go syntax used by the selected manifest."""
    require(type(text) is str, "scenario_source_syntax")
    result, position = [], 0
    decoder = json.JSONDecoder()
    while position < len(text):
        char = text[position]
        if char in " \t\r\n":
            position += 1
            continue
        if text.startswith("//", position):
            end = text.find("\n", position + 2)
            position = len(text) if end < 0 else end + 1
            continue
        if text.startswith("/*", position):
            end = text.find("*/", position + 2)
            require(end >= 0, "scenario_source_syntax")
            position = end + 2
            continue
        if char == '"':
            try:
                value, end = decoder.raw_decode(text, position)
            except ValueError:
                raise Rejected("scenario_source_syntax") from None
            require(type(value) is str, "scenario_source_syntax")
            result.append(("string", value))
            position = end
        elif char == "`":
            end = text.find("`", position + 1)
            require(end >= 0, "scenario_source_syntax")
            result.append(("raw", text[position + 1:end]))
            position = end + 1
        elif char in "[]{},=":
            result.append(("punctuation", char))
            position += 1
        else:
            match = WORD.match(text, position)
            require(match is not None, "scenario_source_syntax")
            result.append(("word", match.group()))
            position = match.end()
        require(len(result) <= TOKEN_LIMIT, "scenario_source_syntax")
    return result


SOURCE_HEAD = """package main
type scenario struct {
ID string `json:"id"`
Package string `json:"package"`
Test string `json:"test"`
Commands []string `json:"-"`
}
var scenarios = []scenario{
"""


def parse_scenarios(raw):
    """Parse a literal registry, refusing computed entries or trailing Go code."""
    c = primitives().checker
    require(type(raw) is bytes and 0 < len(raw) <= SCENARIO_SOURCE_LIMIT, "scenario_source_syntax")
    try:
        selected = tokens(raw.decode("utf-8"))
    except UnicodeError:
        raise Rejected("scenario_source_syntax") from None
    prefix = tokens(SOURCE_HEAD)
    require(selected[:len(prefix)] == prefix, "scenario_source_syntax")
    position, rows, identities = len(prefix), {}, set()

    def take(kind, value=None):
        nonlocal position
        require(position < len(selected), "scenario_source_syntax")
        token = selected[position]
        require(token[0] == kind and (value is None or token[1] == value), "scenario_source_syntax")
        position += 1
        return token[1]

    while position < len(selected) and selected[position] != ("punctuation", "}"):
        take("punctuation", "{")
        identity = take("string")
        take("punctuation", ",")
        package = take("string")
        take("punctuation", ",")
        test = take("string")
        take("punctuation", ",")
        commands = []
        if position < len(selected) and selected[position] == ("word", "nil"):
            take("word", "nil")
        else:
            for kind, value in (("punctuation", "["), ("punctuation", "]"),
                                ("word", "string"), ("punctuation", "{")):
                take(kind, value)
            while position < len(selected) and selected[position] != ("punctuation", "}"):
                commands.append(take("string"))
                require(len(commands) <= len(c.COMMANDS), "scenario_source_syntax")
                if position < len(selected) and selected[position] == ("punctuation", ","):
                    take("punctuation", ",")
                else:
                    break
            take("punctuation", "}")
        take("punctuation", "}")
        take("punctuation", ",")
        require(re.fullmatch(r"[a-z0-9_]{1,128}", identity) is not None
                and package in c.PACKAGES and re.fullmatch(r"Test[A-Za-z0-9_]{1,127}", test) is not None
                and identity not in rows and (package, test) not in identities
                and len(commands) == len(set(commands)) and set(commands) <= set(c.COMMANDS),
                "scenario_source_syntax")
        rows[identity] = {"package": package, "test": test, "commands": frozenset(commands)}
        identities.add((package, test))
        require(len(rows) <= 256, "scenario_source_syntax")
    take("punctuation", "}")
    require(bool(rows), "scenario_source_syntax")
    tail = ('const modulePath = "github.com/0x3639/zenon-spv"\n'
            'const binaryMarker = "offline-pilot-binary "\nvar corpusPaths = []string{\n'
            + "".join(json.dumps(name) + ",\n" for name in c.CORPUS) + "}\n")
    require(selected[position:] == tokens(tail), "scenario_source_syntax")
    return rows


def report_context(report, revision, inputs, os_name, architecture):
    c = primitives().checker
    try:
        version = report.get("schema_version") if type(report) is dict else None
        c.require(type(version) is int and version in (1, 2))
        c.exact_keys(report, ("schema_version", "mode", "status", "error", "runner", "test_parent_race_enabled",
                             "source", "source_matches_after_run", "corpus", "cases", "caveats"),
                     ("skip_ledger",) if version == 2 else ())
        c.require(version != 2 or "skip_ledger" in report)
        c.require(report["mode"] == "offline_synthetic" and report["status"] in ("passed", "passed_with_skips")
                  and report["error"] is None and report["source_matches_after_run"] is True
                  and type(report["test_parent_race_enabled"]) is bool)
        c.exact_keys(report["source"], ("revision", "modified", "inputs_sha256"))
        c.require(report["source"] == {"revision": revision, "modified": False, "inputs_sha256": inputs}
                  and report["source"]["modified"] is False)
        runner = report["runner"]
        c.exact_keys(runner, ("schema_version", "command", "go_version", "os", "architecture", "source"))
        c.require(type(runner["schema_version"]) is int and runner["schema_version"] == 1
                  and runner["command"] == "offline-pilot" and runner["os"] == os_name
                  and runner["architecture"] == architecture and type(runner["go_version"]) is str
                  and len(runner["go_version"]) <= 32
                  and (runner["go_version"] == "unknown" or re.fullmatch(
                      r"go[0-9]+\.[0-9]+(?:\.[0-9]+|(?:beta|rc)[0-9]+)?", runner["go_version"])))
        if runner["source"] is not None:
            c.exact_keys(runner["source"], ("vcs", "revision", "modified"))
            c.require(runner["source"] == {"vcs": "git", "revision": revision, "modified": False}
                      and runner["source"]["modified"] is False)
        c.require(type(report["corpus"]) is list and len(report["corpus"]) == len(c.CORPUS))
        for record, name in zip(report["corpus"], c.CORPUS):
            c.exact_keys(record, ("path", "sha256"))
            c.require(record["path"] == name and c.digest(record["sha256"]))
        c.require(type(report["caveats"]) is list and all(type(value) is str for value in report["caveats"]))
    except (c.Rejected, KeyError, TypeError):
        raise Rejected("report_context") from None


def selected_cases(report, selected, os_name, require_skip_ledger):
    c = primitives().checker
    cases, seen, skipped = report["cases"], set(), 0
    require(type(cases) is list and 0 < len(cases) <= 256, "scenario_coverage")
    try:
        for case in cases:
            c.exact_keys(case, ("id", "package", "test", "status", "passed_subtests", "skipped_subtests",
                                "failed_subtests", "binaries"), ("resource_samples", "query_resource_samples"))
            identity = case["id"]
            require(type(identity) is str and identity in selected and identity not in seen, "scenario_coverage")
            expected = selected[identity]
            require((case["package"], case["test"]) == (expected["package"], expected["test"]), "scenario_coverage")
            seen.add(identity)
            c.require(c.integer(case["passed_subtests"]) and c.integer(case["skipped_subtests"])
                      and type(case["failed_subtests"]) is int and case["failed_subtests"] == 0
                      and case["status"] in ("passed", "passed_with_skips")
                      and (case["status"] == "passed_with_skips") == (case["skipped_subtests"] > 0))
            skipped += case["skipped_subtests"]
            c.require(c.integer(skipped) and type(case["binaries"]) is list
                      and len(case["binaries"]) <= len(c.COMMANDS))
            recorded = set()
            for record in case["binaries"]:
                c.exact_keys(record, ("command", "sha256"))
                c.require(record["command"] in c.COMMANDS and record["command"] not in recorded
                          and c.digest(record["sha256"]))
                recorded.add(record["command"])
            require(expected["commands"] <= recorded, "binary_selection")
            c.verifier_resources(case, os_name)
            c.query_resources(case, os_name)
        require(seen == set(selected), "scenario_coverage")
        c.require((report["status"] == "passed_with_skips") == (skipped > 0))
        ledger = c.check_skip_ledger(
            report, os_name, require_complete=require_skip_ledger or report["schema_version"] == 2)
    except (c.Rejected, KeyError, TypeError):
        raise Rejected("report_metadata") from None
    return skipped, ledger


def verify(report_path, report_sha256, source, revision, os_name, architecture, require_skip_ledger=False):
    p = primitives()
    c = p.checker
    require(c.digest(report_sha256) and c.digest(revision, (40, 64))
            and os_name in ("linux", "darwin", "windows") and type(architecture) is str
            and re.fullmatch(r"[a-z0-9_]{1,24}", architecture) is not None
            and type(require_skip_ledger) is bool, "arguments")
    source = Path(source)
    try:
        inputs = p.source_pin(source, revision)
        registry = read_regular(source / SCENARIO_PATH, SCENARIO_SOURCE_LIMIT, "scenario_source_read")
        selected = parse_scenarios(registry)
        raw = read_regular(report_path, REPORT_LIMIT, "report_read")
        require(hashlib.sha256(raw).hexdigest() == report_sha256, "report_pin")
        report = c.metadata(raw)
        report_context(report, revision, inputs, os_name, architecture)
        skipped, ledger = selected_cases(report, selected, os_name, require_skip_ledger)
        require(p.source_pin(source, revision) == inputs, "source")
        dependencies_intact()
    except c.Rejected:
        raise Rejected("source_or_report_metadata") from None
    return {
        "schema_version": 1, "kind": "source-selected-offline-pilot-scenarios", "status": "consistent",
        "category": None, "scope": "scenario_selection_only", "source_revision": revision,
        "source_inputs_sha256": inputs, "os": os_name, "architecture": architecture,
        "scenario_source_sha256": hashlib.sha256(registry).hexdigest(), "scenario_source_bytes": len(registry),
        "report_sha256": report_sha256, "report_bytes": len(raw), "scenarios": len(selected),
        "required_command_records": sum(len(row["commands"]) for row in selected.values()),
        "skipped_subtests": skipped, "skip_ledger_coverage": ledger["coverage"],
        "skip_ledger_records": ledger["records"], "candidate_payloads_validated": False,
        "test_execution_authenticated": False, "network_or_state_value_acceptance": False,
    }


class Once(argparse.Action):
    def __call__(self, parser, namespace, value, option_string=None):
        require(getattr(namespace, self.dest) is None, "arguments")
        setattr(namespace, self.dest, value)


class OnceBoolean(Once):
    def __call__(self, parser, namespace, value, option_string=None):
        super().__call__(parser, namespace, True, option_string)


class Parser(argparse.ArgumentParser):
    def error(self, _message):
        raise Rejected("arguments")


def main(argv=None, output=None):
    output = sys.stdout if output is None else output
    parser = Parser(prog="check-scenario-inventory", allow_abbrev=False, add_help=False)
    for name in ("report", "expect-report-sha256", "source", "expect-revision", "expect-os", "expect-architecture"):
        parser.add_argument("--" + name, action=Once, required=True)
    parser.add_argument("--require-skip-ledger", action=OnceBoolean, nargs=0, default=None)
    code = 0
    try:
        args = parser.parse_args(argv)
        require(0 < len(args.report) <= 4096 and 0 < len(args.source) <= 4096, "arguments")
        result = verify(Path(args.report), args.expect_report_sha256, Path(args.source), args.expect_revision,
                        args.expect_os, args.expect_architecture, require_skip_ledger=bool(args.require_skip_ledger))
    except Rejected as failure:
        code = 64 if failure.category == "arguments" else 2
        result = {"schema_version": 1, "kind": "source-selected-offline-pilot-scenarios",
                  "status": "rejected", "category": failure.category, "scope": "scenario_selection_only",
                  "scenarios": 0, "candidate_payloads_validated": False,
                  "test_execution_authenticated": False, "network_or_state_value_acceptance": False}
    except (Exception, KeyboardInterrupt):
        code = 2
        result = {"schema_version": 1, "kind": "source-selected-offline-pilot-scenarios",
                  "status": "rejected", "category": "input", "scope": "scenario_selection_only",
                  "scenarios": 0, "candidate_payloads_validated": False,
                  "test_execution_authenticated": False, "network_or_state_value_acceptance": False}
    try:
        raw = json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n"
        if output.write(raw) != len(raw):
            return 70
        output.flush()
    except (OSError, ValueError):
        return 70
    return code


if __name__ == "__main__":
    raise SystemExit(main())
