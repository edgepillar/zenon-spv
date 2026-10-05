#!/usr/bin/env python3
"""Check a pinned candidate ZIP without extracting or executing its contents."""

import argparse
import contextlib
import hashlib
import json
import os
import re
import stat
import struct
import sys
import zipfile
from pathlib import Path

COMMANDS = tuple(sorted(("zenon-spv", "fetch-bundle", "derive-checkpoints",
                         "derive-producer-schedule", "verify-mainnet-genesis",
                         "consume-query-report", "observe-block")))
CORPUS = tuple("internal/testdata/conformance/" + name + ".json" for name in (
    "momentum-v1-v2", "account-amounts", "account-segments", "contract-batches",
    "delayed-inclusion", "content-scaling", "historical-testnet-genesis"))
PACKAGES = {"internal/conformance", "internal/chain", "internal/verify", "internal/proof",
            "internal/syncer", "internal/statelock", "tools/consume-query-report",
            "tools/observe-block", "tools/offline-pilot"}
BINARY_LIMIT = 128 << 20
ARCHIVE_LIMIT = 256 << 20
QUERY_WORKLOADS = {"T1": 1, "T16": 16, "T256": 256}
RESOURCE_WORKLOADS = {"M1_P1": (1, 1), "M1000_P1": (1000, 1),
                      "M100000_P1": (100000, 1), "M100000_P4": (100000, 4)}


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


@contextlib.contextmanager
def regular_archive(path):
    # A FIFO can block in open before file_hash reaches its descriptor check.
    selected = path.stat()
    require(stat.S_ISREG(selected.st_mode) and 0 < selected.st_size <= ARCHIVE_LIMIT, "archive")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        require(stat.S_ISREG(opened.st_mode) and 0 < opened.st_size <= ARCHIVE_LIMIT, "archive")
        with os.fdopen(descriptor, "rb") as source:
            descriptor = None
            yield source
    finally:
        if descriptor is not None:
            os.close(descriptor)


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


def central_zip_metadata(source, expected_names):
    # ZipFile materializes the whole central directory before infolist() can
    # enforce our nine-file limit. Bound and count the actual records first;
    # an EOCD entry count alone does not constrain the stdlib parser.
    source.seek(0, os.SEEK_END)
    size = source.tell()
    require(22 <= size <= ARCHIVE_LIMIT, "layout")
    tail_start = max(0, size - (22 + 0xffff))
    source.seek(tail_start)
    tail = source.read(size - tail_start)
    # Match ZipFile's no-comment fast path before searching a commented tail.
    # The signature bytes can also occur inside an otherwise valid offset.
    if tail[-22:-18] == b"PK\x05\x06" and tail[-2:] == b"\0\0":
        position = len(tail) - 22
    else:
        position = tail.rfind(b"PK\x05\x06")
    require(position >= 0 and len(tail) - position >= 22, "layout")
    end = struct.unpack("<4s4H2IH", tail[position:position + 22])
    _signature, disk, central_disk, disk_count, count, central_bytes, central_offset, comment_bytes = end
    require(disk == central_disk == 0 and position + 22 + comment_bytes == len(tail), "layout")
    central_end = tail_start + position

    # The supported single-disk ZIP64 end record has no extensible data sector.
    # Its offset is relative to the ZIP start, as are central/local offsets; a
    # prepended payload is permitted only when all inferred offsets agree.
    if central_end >= 20:
        source.seek(central_end - 20)
        locator = source.read(20)
        if locator.startswith(b"PK\x06\x07"):
            _signature, zip64_disk, zip64_offset, disks = struct.unpack("<4sIQI", locator)
            require(zip64_disk == 0 and disks == 1 and central_end >= 76, "layout")
            fixed_position = central_end - 76
            require(zip64_offset <= fixed_position, "layout")
            if zip64_offset != fixed_position:
                # Modern ZipFile first tries the locator offset as an absolute
                # position before falling back to the fixed record near EOF.
                # A prefixed ZIP must not supply a competing record there.
                source.seek(zip64_offset)
                require(source.read(4) != b"PK\x06\x06", "layout")
            source.seek(fixed_position)
            raw = source.read(56)
            require(len(raw) == 56, "layout")
            record = struct.unpack("<4sQ2H2I4Q", raw)
            signature, record_bytes, _made, needed, disk64, central_disk64, disk_count64, count64, bytes64, offset64 = record
            require(signature == b"PK\x06\x06" and record_bytes == 44 and needed >= 45
                    and disk64 == central_disk64 == 0 and disk_count in (0xffff, disk_count64)
                    and count in (0xffff, count64) and central_bytes in (0xffffffff, bytes64)
                    and central_offset in (0xffffffff, offset64) and zip64_offset == offset64 + bytes64, "layout")
            disk_count, count, central_bytes, central_offset = disk_count64, count64, bytes64, offset64
            central_end -= 76

    require(disk_count == count == len(expected_names), "layout")
    # Each permitted record has a fixed name and at most two uint16-sized
    # variable fields. This bounds any later stdlib central-directory read.
    max_central_bytes = sum(46 + len(name) + 2 * 0xffff for name in expected_names)
    require(0 < central_bytes <= max_central_bytes and central_bytes <= central_end, "layout")
    central_start = central_end - central_bytes
    require(0 <= central_offset <= central_start, "layout")
    source.seek(central_start)
    seen = set()
    encoded_names = {name.encode("ascii") for name in expected_names}
    longest_name = max(map(len, encoded_names))
    for _ in range(len(expected_names)):
        require(source.tell() + 46 <= central_end, "layout")
        raw = source.read(46)
        require(len(raw) == 46 and raw[:4] == b"PK\x01\x02", "layout")
        name_bytes, extra_bytes, entry_comment_bytes = struct.unpack_from("<3H", raw, 28)
        require(0 < name_bytes <= longest_name
                and source.tell() + name_bytes + extra_bytes + entry_comment_bytes <= central_end, "layout")
        name = source.read(name_bytes)
        require(name in encoded_names and name not in seen, "layout")
        seen.add(name)
        source.seek(extra_bytes + entry_comment_bytes, os.SEEK_CUR)
    require(source.tell() == central_end and len(seen) == len(expected_names), "layout")
    source.seek(0)


def local_zip_metadata(source, archive, infos):
    # zipfile checks central-directory CRCs while reading payloads. Also bind
    # local records, which other ZIP readers can use for methods and sizes.
    ordered = sorted(infos, key=lambda info: info.header_offset)
    for index, info in enumerate(ordered):
        boundary = ordered[index + 1].header_offset if index + 1 < len(ordered) else archive.start_dir
        require(0 <= info.header_offset and info.header_offset + 30 <= boundary, "layout")
        source.seek(info.header_offset)
        raw = source.read(30)
        require(len(raw) == 30, "layout")
        header = struct.unpack("<4s5H3I2H", raw)
        signature, _version, flags, method, _time, _date, crc, compressed, size, name_bytes, extra_bytes = header
        require(signature == b"PK\x03\x04" and flags == info.flag_bits and method == info.compress_type
                and not flags & ~0x080e and (method == zipfile.ZIP_DEFLATED or not flags & 6), "layout")
        data_offset = info.header_offset + 30 + name_bytes + extra_bytes
        require(data_offset <= boundary, "layout")
        require(source.read(name_bytes) == info.filename.encode("ascii"), "layout")
        extra = source.read(extra_bytes)
        require(len(extra) == extra_bytes, "layout")
        extended = None
        while extra:
            require(len(extra) >= 4, "layout")
            kind, length = struct.unpack("<HH", extra[:4])
            require(length <= len(extra) - 4, "layout")
            if kind == 1:
                # ZIP64 local extras carry both original and compressed sizes.
                require(extended is None and length == 16, "layout")
                extended = struct.unpack("<QQ", extra[4:20])
            extra = extra[4 + length:]
        require((size != 0xffffffff and compressed != 0xffffffff) or extended is not None, "layout")
        local_size, local_compressed = extended if extended is not None else (size, compressed)
        payload_end = data_offset + info.compress_size
        require(payload_end <= boundary, "layout")
        if flags & 8:
            require(crc == 0 and size in (0, 0xffffffff) and compressed in (0, 0xffffffff)
                    and local_size in (0, info.file_size) and local_compressed in (0, info.compress_size), "layout")
            source.seek(payload_end)
            descriptor = source.read(min(24, boundary - payload_end))
            expected = struct.pack("<IQQ" if extended is not None else "<III",
                                   info.CRC, info.compress_size, info.file_size)
            require(descriptor.startswith(b"PK\x07\x08" + expected) or descriptor.startswith(expected), "layout")
        else:
            require(crc == info.CRC and local_size == info.file_size and local_compressed == info.compress_size
                    and (size == 0xffffffff or size == info.file_size)
                    and (compressed == 0xffffffff or compressed == info.compress_size), "layout")


def verifier_resources(case, os_name):
    if case["id"] != "compiled_content_scaling":
        require("resource_samples" not in case)
        return
    samples = case.get("resource_samples")
    require(type(samples) is list and len(samples) == len(RESOURCE_WORKLOADS)
            and case["package"] == "internal/conformance" and case["test"] == "TestCompiledContentScalingWorkflow"
            and {record["command"] for record in case["binaries"]} == {"zenon-spv"}
            and case["status"] == "passed" and case["passed_subtests"] == 4 and case["skipped_subtests"] == 0)
    seen = set()
    expected_source = "windows_peak_working_set" if os_name == "windows" else "process_rusage"
    for sample in samples:
        exact_keys(sample, ("workload", "members_per_proof", "proofs", "input_bytes", "elapsed_ns",
                            "peak_rss_bytes", "peak_rss_source"))
        name = sample["workload"]
        require(type(name) is str and name in RESOURCE_WORKLOADS and name not in seen)
        members, proofs = RESOURCE_WORKLOADS[name]
        require(integer(sample["members_per_proof"]) and sample["members_per_proof"] == members
                and integer(sample["proofs"]) and sample["proofs"] == proofs
                and integer(sample["input_bytes"], 1, 64 << 20)
                and integer(sample["elapsed_ns"], 1, 60_000_000_000)
                and integer(sample["peak_rss_bytes"], 1, 1 << 50)
                and sample["peak_rss_source"] == expected_source)
        seen.add(name)
    require(seen == set(RESOURCE_WORKLOADS))


def query_resources(case, os_name):
    if case["id"] != "compiled_query_consumer_scaling":
        require("query_resource_samples" not in case)
        return
    samples = case.get("query_resource_samples")
    require(type(samples) is list and len(samples) == len(QUERY_WORKLOADS)
            and case["package"] == "internal/conformance" and case["test"] == "TestCompiledQueryConsumerScaling"
            and {record["command"] for record in case["binaries"]} == {"zenon-spv", "consume-query-report"}
            and case["status"] == "passed" and case["passed_subtests"] == 3 and case["skipped_subtests"] == 0)
    seen = set()
    expected_source = "windows_peak_working_set" if os_name == "windows" else "process_rusage"
    measurement_fields = ("elapsed_ns", "peak_rss_bytes", "peak_rss_source")
    for sample in samples:
        exact_keys(sample, ("workload", "targets", "report_bytes", "expectations_bytes", "observations") + measurement_fields)
        name = sample["workload"]
        require(type(name) is str and name in QUERY_WORKLOADS and name not in seen
                and type(sample["targets"]) is int and sample["targets"] == QUERY_WORKLOADS[name]
                and integer(sample["report_bytes"], 1, 4 << 20) and integer(sample["expectations_bytes"], 1, 256 << 10))
        seen.add(name)
        points = sample["observations"]
        require(type(points) is list and len(points) == 21)
        for point in points:
            exact_keys(point, measurement_fields)
            require(integer(point["elapsed_ns"], 1, 60_000_000_000)
                    and integer(point["peak_rss_bytes"], 1, 1 << 50) and point["peak_rss_source"] == expected_source)
        require(all(sample[field] == points[0][field] and type(sample[field]) is type(points[0][field])
                    for field in measurement_fields))
    require(seen == set(QUERY_WORKLOADS))


def check(path, archive_sha256, revision, inputs_sha256, os_name, architecture):
    # These expectations must come from an independently selected source/CI
    # record. Copying them out of this archive establishes no authenticity.
    with regular_archive(path) as source:
        require(file_hash(source) == archive_sha256, "archive_pin")
        source.seek(0)
        return check_contents(source, revision, inputs_sha256, os_name, architecture)


def check_contents(source, revision, inputs_sha256, os_name, architecture):
    suffix = ".exe" if os_name == "windows" else ""
    expected_names = {command + suffix for command in COMMANDS} | {"manifest.json", "offline-pilot.json"}
    central_zip_metadata(source, expected_names)
    with zipfile.ZipFile(source) as archive:
        infos = archive.infolist()
        require(len(infos) == len(expected_names) and {i.filename for i in infos} == expected_names, "layout")
        for info in infos:
            mode = stat.S_IFMT(info.external_attr >> 16)
            require(not info.is_dir() and mode in (0, stat.S_IFREG) and not info.flag_bits & 1
                    and info.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED), "layout")
        local_zip_metadata(source, archive, infos)
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
            verifier_resources(case, os_name)
            query_resources(case, os_name)
        require("compiled_content_scaling" in seen)
        require("compiled_query_consumer_scaling" in seen)
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
