#!/usr/bin/env python3
"""Check a pinned candidate ZIP without extracting or executing its contents."""

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import zipfile
from pathlib import Path

COMMANDS = tuple(sorted(("zenon-spv", "fetch-bundle", "derive-checkpoints",
                         "derive-producer-schedule", "verify-mainnet-genesis",
                         "consume-query-report", "observe-block")))
CORPUS = tuple("internal/testdata/conformance/" + name + ".json" for name in (
    "momentum-v1-v2", "account-amounts", "account-segments", "contract-batches",
    "delayed-inclusion", "content-scaling"))
PACKAGES = {"internal/conformance", "internal/chain", "internal/verify", "internal/proof",
            "internal/syncer", "internal/statelock", "tools/observe-block", "tools/offline-pilot"}
BINARY_LIMIT = 128 << 20
ARCHIVE_LIMIT = 256 << 20


class Rejected(Exception):
    def __init__(self, category):
        self.category = category


def require(condition, category="metadata"):
    if not condition:
        raise Rejected(category)


def exact_keys(value, required, optional=()):
    require(type(value) is dict and set(required) <= set(value)
            and set(value) <= set(required) | set(optional))


def integer(value, minimum=0, maximum=(1 << 64) - 1):
    return type(value) is int and minimum <= value <= maximum


def digest(value, lengths=(64,)):
    return type(value) is str and len(value) in lengths and re.fullmatch(r"[0-9a-f]+", value) is not None


def metadata(raw):
    def pairs(values):
        result = {}
        for key, value in values:
            require(key not in result)
            result[key] = value
        return result

    def number(value):
        require(len(value) <= 20)
        result = int(value)
        require(integer(result))
        return result

    def invalid_number(_):
        raise Rejected("metadata")

    value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_int=number,
                       parse_float=invalid_number, parse_constant=invalid_number)
    nodes = 0

    def bounded(item, depth=0):
        nonlocal nodes
        nodes += 1
        require(nodes <= 65536 and depth <= 16)
        if type(item) is dict:
            require(len(item) <= 256)
            for key, child in item.items():
                require(len(key) <= 128)
                bounded(child, depth + 1)
        elif type(item) is list:
            require(len(item) <= 256)
            for child in item:
                bounded(child, depth + 1)
        elif type(item) is str:
            require(len(item) <= 4096)
        else:
            require(item is None or type(item) is bool or integer(item))

    bounded(value)
    return value


def file_hash(stream):
    info = os.fstat(stream.fileno())
    require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= ARCHIVE_LIMIT, "archive")
    result, total = hashlib.sha256(), 0
    while True:
        raw = stream.read(1 << 20)
        if not raw:
            break
        total += len(raw)
        require(total <= ARCHIVE_LIMIT, "archive")
        result.update(raw)
    require(total == info.st_size, "archive")
    return result.hexdigest()


def entry_bytes(archive, info, limit):
    require(0 < info.file_size <= limit, "archive")
    with archive.open(info) as stream:
        raw = stream.read(limit + 1)
    require(len(raw) == info.file_size and len(raw) <= limit, "archive")
    return raw


def check(path, archive_sha256, revision, inputs_sha256, os_name, architecture):
    # These expectations must come from an independently selected source/CI
    # record. Copying them out of this archive establishes no authenticity.
    with path.open("rb") as source:
        require(file_hash(source) == archive_sha256, "archive_pin")
        source.seek(0)
        return check_contents(source, revision, inputs_sha256, os_name, architecture)


def check_contents(source, revision, inputs_sha256, os_name, architecture):
    with zipfile.ZipFile(source) as archive:
        infos = archive.infolist()
        suffix = ".exe" if os_name == "windows" else ""
        expected_names = {command + suffix for command in COMMANDS} | {"manifest.json", "offline-pilot.json"}
        require(len(infos) == len(expected_names) and {i.filename for i in infos} == expected_names, "layout")
        for info in infos:
            mode = stat.S_IFMT(info.external_attr >> 16)
            require(not info.is_dir() and mode in (0, stat.S_IFREG) and not info.flag_bits & 1
                    and info.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED), "layout")
        by_name = {info.filename: info for info in infos}
        manifest = metadata(entry_bytes(archive, by_name["manifest.json"], 256 << 10))
        exact_keys(manifest, ("schema_version", "mode", "test_status", "os", "architecture", "go_version",
                              "source", "corpus", "report", "binaries"))
        require(type(manifest["schema_version"]) is int and manifest["schema_version"] == 1
                and manifest["mode"] == "offline_synthetic_candidate")
        require(manifest["os"] == os_name and manifest["architecture"] == architecture, "platform_pin")
        require(type(manifest["go_version"]) is str and len(manifest["go_version"]) <= 32
                and (manifest["go_version"] == "unknown"
                     or re.fullmatch(r"go[0-9]+\.[0-9]+(?:\.[0-9]+|(?:beta|rc)[0-9]+)?", manifest["go_version"])))
        require(manifest["test_status"] in ("passed", "passed_with_skips"))
        exact_keys(manifest["source"], ("revision", "modified", "inputs_sha256"))
        require(manifest["source"] == {"revision": revision, "modified": False, "inputs_sha256": inputs_sha256}
                and manifest["source"]["modified"] is False, "source_pin")
        corpus = manifest["corpus"]
        require(type(corpus) is list and len(corpus) == len(CORPUS))
        for record, expected_path in zip(corpus, CORPUS):
            exact_keys(record, ("path", "sha256"))
            require(record["path"] == expected_path and digest(record["sha256"]))
        report_record = manifest["report"]
        exact_keys(report_record, ("filename", "sha256", "bytes"))
        require(report_record["filename"] == "offline-pilot.json" and digest(report_record["sha256"])
                and integer(report_record["bytes"], 1, 4 << 20))
        raw = entry_bytes(archive, by_name["offline-pilot.json"], 4 << 20)
        require(len(raw) == report_record["bytes"] and hashlib.sha256(raw).hexdigest() == report_record["sha256"], "report_pin")
        report = metadata(raw)
        exact_keys(report, ("schema_version", "mode", "status", "error", "runner", "test_parent_race_enabled",
                            "source", "source_matches_after_run", "corpus", "cases", "caveats"))
        require(type(report["schema_version"]) is int and report["schema_version"] == 1
                and report["mode"] == "offline_synthetic" and report["status"] == manifest["test_status"]
                and report["error"] is None and report["source_matches_after_run"] is True
                and type(report["test_parent_race_enabled"]) is bool and report["source"] == manifest["source"]
                and report["corpus"] == corpus)
        require(report["source"]["modified"] is False)
        runner = report["runner"]
        exact_keys(runner, ("schema_version", "command", "go_version", "os", "architecture", "source"))
        require(type(runner["schema_version"]) is int and runner["schema_version"] == 1
                and runner["command"] == "offline-pilot" and runner["os"] == os_name
                and runner["architecture"] == architecture and runner["go_version"] == manifest["go_version"])
        if runner["source"] is not None:
            exact_keys(runner["source"], ("vcs", "revision", "modified"))
            require(runner["source"]["vcs"] == "git" and runner["source"]["revision"] == revision
                    and runner["source"]["modified"] is False)
        require(type(report["caveats"]) is list and all(type(c) is str for c in report["caveats"]))
        binaries = manifest["binaries"]
        require(type(binaries) is list and len(binaries) == len(COMMANDS))
        binary_map = {}
        for binary, command in zip(binaries, COMMANDS):
            exact_keys(binary, ("command", "filename", "sha256", "bytes"))
            require(binary["command"] == command and binary["filename"] == command + suffix
                    and digest(binary["sha256"]) and integer(binary["bytes"], 1, BINARY_LIMIT))
            info = by_name[binary["filename"]]
            require(info.file_size == binary["bytes"], "binary_pin")
            result, total = hashlib.sha256(), 0
            with archive.open(info) as stream:
                while True:
                    block = stream.read(1 << 20)
                    if not block:
                        break
                    total += len(block)
                    require(total <= BINARY_LIMIT, "binary_pin")
                    result.update(block)
            require(total == binary["bytes"] and result.hexdigest() == binary["sha256"], "binary_pin")
            binary_map[command] = binary["sha256"]
        cases = report["cases"]
        require(type(cases) is list and 0 < len(cases) <= 256)
        seen, observed, skipped = set(), set(), 0
        for case in cases:
            exact_keys(case, ("id", "package", "test", "status", "passed_subtests", "skipped_subtests",
                              "failed_subtests", "binaries"), ("resource_samples", "query_resource_samples"))
            require(type(case["id"]) is str and re.fullmatch(r"[a-z0-9_]{1,128}", case["id"])
                    and case["id"] not in seen and case["package"] in PACKAGES
                    and type(case["test"]) is str and re.fullmatch(r"Test[A-Za-z0-9_]+", case["test"]))
            seen.add(case["id"])
            require(integer(case["passed_subtests"]) and integer(case["skipped_subtests"])
                    and type(case["failed_subtests"]) is int and case["failed_subtests"] == 0
                    and case["status"] in ("passed", "passed_with_skips")
                    and (case["status"] == "passed_with_skips") == (case["skipped_subtests"] > 0))
            skipped += case["skipped_subtests"]
            require(integer(skipped))
            require(type(case["binaries"]) is list and len(case["binaries"]) <= len(COMMANDS))
            recorded = set()
            for binary in case["binaries"]:
                exact_keys(binary, ("command", "sha256"))
                command = binary["command"]
                require(command in binary_map and command not in recorded and binary["sha256"] == binary_map[command], "execution_pin")
                recorded.add(command)
                observed.add(command)
        require(observed == set(COMMANDS) and (report["status"] == "passed_with_skips") == (skipped > 0), "execution_pin")
    return {"schema_version": 1, "status": "verified", "category": None, "binaries": len(COMMANDS),
            "test_status": report["status"], "skipped_subtests": skipped}


class Once(argparse.Action):
    def __call__(self, parser, namespace, value, option_string=None):
        if getattr(namespace, self.dest) is not None:
            raise Rejected("arguments")
        setattr(namespace, self.dest, value)


class Parser(argparse.ArgumentParser):
    def error(self, _message):
        raise Rejected("arguments")


def main(argv=None, output=None):
    output = sys.stdout if output is None else output
    parser = Parser(prog="check-candidate-archive", allow_abbrev=False)
    for name in ("archive", "expect-archive-sha256", "expect-revision", "expect-inputs", "expect-os", "expect-architecture"):
        parser.add_argument("--" + name, action=Once, required=True)
    code = 0
    try:
        args = parser.parse_args(argv)
        require(digest(args.expect_archive_sha256) and digest(args.expect_revision, (40, 64))
                and digest(args.expect_inputs) and args.expect_os in ("linux", "darwin", "windows")
                and re.fullmatch(r"[a-z0-9_]{1,24}", args.expect_architecture) is not None, "arguments")
        result = check(Path(args.archive), args.expect_archive_sha256, args.expect_revision, args.expect_inputs,
                       args.expect_os, args.expect_architecture)
    except Rejected as failure:
        result = {"schema_version": 1, "status": "rejected", "category": failure.category,
                  "binaries": 0, "test_status": None, "skipped_subtests": 0}
        code = 64 if failure.category == "arguments" else 2
    except (Exception, KeyboardInterrupt):
        result = {"schema_version": 1, "status": "rejected", "category": "archive",
                  "binaries": 0, "test_status": None, "skipped_subtests": 0}
        code = 2
    try:
        raw = json.dumps(result, separators=(",", ":")) + "\n"
        if output.write(raw) != len(raw):
            return 70
        output.flush()
    except (OSError, ValueError):
        return 70
    return code


if __name__ == "__main__":
    sys.exit(main())
