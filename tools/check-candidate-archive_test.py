"""Adversarial byte/layout checks; fixtures are not executable or network evidence."""

import copy
import hashlib
import importlib.util
import io
import json
import os
import re
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import warnings
import zipfile
from pathlib import Path

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("candidate_check", Path(__file__).with_name("check-candidate-archive.py"))
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)

REVISION = "b" * 40
INPUTS = "c" * 64


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def query_fixture(os_name, binaries):
    case = {"id": "compiled_query_consumer_scaling", "package": "internal/conformance",
            "test": "TestCompiledQueryConsumerScaling", "status": "passed", "passed_subtests": 3,
            "skipped_subtests": 0, "failed_subtests": 0,
            "binaries": [{"command": b["command"], "sha256": b["sha256"]} for b in binaries
                         if b["command"] in ("zenon-spv", "consume-query-report")], "query_resource_samples": []}
    for name, targets in (("T1", 1), ("T16", 16), ("T256", 256)):
        point = {"elapsed_ns": 1000000, "peak_rss_bytes": 1048576,
                 "peak_rss_source": "windows_peak_working_set" if os_name == "windows" else "process_rusage"}
        case["query_resource_samples"].append(dict(workload=name, targets=targets, report_bytes=1000,
            expectations_bytes=500, observations=[dict(point, elapsed_ns=1000000 + i) for i in range(21)], **point))
    return case


def verifier_resource_fixture(os_name, binaries):
    # Opaque serialization controls, not genuine performance observations.
    case = {"id": "compiled_content_scaling", "package": "internal/conformance",
            "test": "TestCompiledContentScalingWorkflow", "status": "passed", "passed_subtests": 4,
            "skipped_subtests": 0, "failed_subtests": 0,
            "binaries": [{"command": b["command"], "sha256": b["sha256"]} for b in binaries
                         if b["command"] == "zenon-spv"], "resource_samples": []}
    for name, members, proofs in (("M1_P1", 1, 1), ("M1000_P1", 1000, 1),
                                 ("M100000_P1", 100000, 1), ("M100000_P4", 100000, 4)):
        case["resource_samples"].append({"workload": name, "members_per_proof": members, "proofs": proofs,
            "input_bytes": 1000, "elapsed_ns": 1000000, "peak_rss_bytes": 1048576,
            "peak_rss_source": "windows_peak_working_set" if os_name == "windows" else "process_rusage"})
    return case


class StreamingZIP(io.BytesIO):
    def __init__(self, unsigned):
        super().__init__()
        self.unsigned = unsigned

    def seek(self, *_args):
        raise io.UnsupportedOperation()

    def write(self, raw):
        # Strip only the descriptor signature emitted as its own fixture write.
        original = len(raw)
        if self.unsigned and len(raw) in (16, 24) and raw.startswith(b"PK\x07\x08"):
            raw = raw[4:]
        super().write(raw)
        return original


def fixture(os_name="linux"):
    suffix = ".exe" if os_name == "windows" else ""
    files = {name + suffix: (name + " opaque bytes").encode() for name in checker.COMMANDS}
    source = {"revision": REVISION, "modified": False, "inputs_sha256": INPUTS}
    corpus = [{"path": name, "sha256": sha(name.encode())} for name in checker.CORPUS]
    binaries = [{"command": name, "filename": name + suffix, "sha256": sha(files[name + suffix]),
                 "bytes": len(files[name + suffix])} for name in checker.COMMANDS]
    report = {
        "schema_version": 1, "mode": "offline_synthetic", "status": "passed", "error": None,
        "runner": {"schema_version": 1, "command": "offline-pilot", "go_version": "go1.25.14",
                   "os": os_name, "architecture": "amd64", "source": None},
        "test_parent_race_enabled": os_name == "linux", "source": copy.deepcopy(source),
        "source_matches_after_run": True, "corpus": copy.deepcopy(corpus),
        "cases": [{"id": "example", "package": "internal/conformance", "test": "TestExample", "status": "passed",
                   "passed_subtests": 1, "skipped_subtests": 0, "failed_subtests": 0,
                   "binaries": [{"command": b["command"], "sha256": b["sha256"]} for b in binaries]}],
        "caveats": ["Synthetic archive-check fixture; not live-network evidence."]}
    report["cases"].append(query_fixture(os_name, binaries))
    report["cases"].append(verifier_resource_fixture(os_name, binaries))
    manifest = {"schema_version": 1, "mode": "offline_synthetic_candidate", "test_status": "passed",
                "os": os_name, "architecture": "amd64", "go_version": "go1.25.14",
                "source": source, "corpus": corpus, "report": {}, "binaries": binaries}
    return files, manifest, report


def pack(files, manifest, report, mutate_manifest=None, mutate_raw=None, extra=None,
         compression=zipfile.ZIP_DEFLATED, descriptor=False, zip64=False, unsigned=False, comment=b"",
         mutate_report_raw=None):
    manifest = copy.deepcopy(manifest)
    raw_report = json.dumps(report).encode()
    if mutate_report_raw:
        raw_report = mutate_report_raw(raw_report)
    manifest["report"] = {"filename": "offline-pilot.json", "sha256": sha(raw_report), "bytes": len(raw_report)}
    if mutate_manifest:
        mutate_manifest(manifest)
    raw_manifest = json.dumps(manifest).encode()
    if mutate_raw:
        raw_manifest = mutate_raw(raw_manifest)
    stream = StreamingZIP(unsigned) if descriptor else io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(stream, "w", compression=compression) as archive:
            archive.comment = comment
            for filename, raw in list(files.items()) + [("manifest.json", raw_manifest), ("offline-pilot.json", raw_report)]:
                if zip64:
                    with archive.open(filename, "w", force_zip64=True) as entry:
                        entry.write(raw)
                else:
                    archive.writestr(filename, raw)
            if extra:
                archive.writestr(*extra)
    return stream.getvalue()


def zip64_end(raw, sentinel=True):
    # Add a complete, small ZIP64 end record independently of local extras.
    position = raw.rfind(b"PK\x05\x06")
    end = list(struct.unpack("<4s4H2IH", raw[position:position + 22]))
    record = struct.pack("<4sQ2H2I4Q", b"PK\x06\x06", 44, 45, 45,
                         end[1], end[2], end[3], end[4], end[5], end[6])
    locator = struct.pack("<4sIQI", b"PK\x06\x07", 0, position, 1)
    if sentinel:
        end[3:7] = [0xffff, 0xffff, 0xffffffff, 0xffffffff]
    return raw[:position] + record + locator + struct.pack("<4s4H2IH", *end) + raw[position + 22:]


def central_records(raw):
    end = raw.rfind(b"PK\x05\x06")
    size, offset = struct.unpack_from("<II", raw, end + 12)
    records = []
    position = offset
    while position < end:
        lengths = struct.unpack_from("<3H", raw, position + 28)
        length = 46 + sum(lengths)
        records.append((position, raw[position:position + length]))
        position += length
    assert position == end and sum(len(record) for _, record in records) == size
    return end, records


def metadata_entry_fixture(name, payload, compression):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=compression) as archive:
        archive.writestr(name, payload)
    return buffer.getvalue()


class CandidateCheckTests(unittest.TestCase):
    def invoke(self, raw, os_name="linux", replace=None, extra_args=()):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "PRIVATE_ARCHIVE.zip"
            path.write_bytes(raw)
            before = path.stat()
            options = {"archive": str(path), "expect-archive-sha256": sha(raw), "expect-revision": REVISION,
                       "expect-inputs": INPUTS, "expect-os": os_name, "expect-architecture": "amd64"}
            options.update(replace or {})
            args = [value for key, value in options.items() for value in ("--" + key, value)] + list(extra_args)
            output = io.StringIO()
            code = checker.main(args, output)
            result = json.loads(output.getvalue())
            self.assertNotIn("PRIVATE", output.getvalue())
            self.assertEqual(path.read_bytes(), raw)
            self.assertEqual(path.stat().st_mtime_ns, before.st_mtime_ns)
            self.assertEqual(list(Path(directory).iterdir()), [path])
            return code, result

    @unittest.skipUnless(hasattr(os, "mkfifo"), "native FIFO creation is unavailable")
    def test_real_fifo_archive_targets_do_not_wait_for_a_writer(self):
        with tempfile.TemporaryDirectory(prefix="private-archive-fifo-control-") as directory:
            root = Path(directory)
            fifo = root / "PRIVATE_ARCHIVE.zip"
            os.mkfifo(fifo, 0o600)
            ordinary = root / "ordinary.zip"
            ordinary.write_bytes(b"ordinary data")
            # The second child models replacement after a regular precheck.
            # It still opens a real FIFO; omitting O_NONBLOCK would hang.
            code = '''import importlib.util, os, sys
from pathlib import Path
from unittest import mock
spec = importlib.util.spec_from_file_location("checker", sys.argv[1])
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)
selected = os.stat(sys.argv[2])
with mock.patch.object(Path, "stat", return_value=selected):
    raise SystemExit(checker.main(sys.argv[3:]))
'''
            args = ["--archive", str(fifo), "--expect-archive-sha256", "0" * 64,
                    "--expect-revision", REVISION, "--expect-inputs", INPUTS,
                    "--expect-os", "linux", "--expect-architecture", "amd64"]
            programs = ([sys.executable, "-I", "-B", str(Path(checker.__file__))] + args,
                        [sys.executable, "-I", "-B", "-c", code, str(Path(checker.__file__)), str(ordinary)] + args)
            for program in programs:
                with self.subTest(replacement=program[3] == "-c"):
                    process = subprocess.Popen(program, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                               stderr=subprocess.PIPE, start_new_session=True)
                    try:
                        stdout, stderr = process.communicate(timeout=5)
                    except subprocess.TimeoutExpired:
                        try:
                            os.killpg(process.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        process.communicate(timeout=5)
                        self.fail("owned archive checker waited for a FIFO writer")
                    self.assertEqual(process.returncode, 2)
                    self.assertEqual(stderr, b"")
                    result = json.loads(stdout)
                    self.assertEqual((result["status"], result["category"], result["binaries"]),
                                     ("rejected", "archive", 0))
                    self.assertNotIn(b"PRIVATE", stdout)
                    self.assertTrue(stat.S_ISFIFO(fifo.stat().st_mode))
                    self.assertEqual(ordinary.read_bytes(), b"ordinary data")
                    self.assertEqual(set(root.iterdir()), {fifo, ordinary})

    def test_archive_hash_stable_files_have_bounded_reads_and_real_eof(self):
        controls = 0
        for size, short_read in ((1, None), (1024, None), (1024, 37),
                                 ((1 << 20) - 1, None), (1 << 20, None),
                                 ((1 << 20) + 17, None)):
            with self.subTest(size=size, short_read=short_read), tempfile.TemporaryDirectory() as directory:
                payload = b"a" * size
                path = Path(directory) / "archive.zip"
                path.write_bytes(payload)
                requests, returned = [], []
                with checker.regular_archive(path) as stream:
                    descriptor, actual_read = stream.fileno(), stream.read

                    def read(count=-1):
                        requests.append(count)
                        raw = actual_read(min(count, short_read) if short_read else count)
                        returned.append(len(raw))
                        return raw

                    with mock.patch.object(stream, "read", side_effect=read):
                        self.assertEqual(checker.file_hash(stream), sha(payload))
                self.assertTrue(stream.closed)
                with self.assertRaises(OSError):
                    os.fstat(descriptor)
                total = 0
                for requested, length in zip(requests, returned):
                    self.assertEqual(requested, min(1 << 20, size - total + 1))
                    self.assertLessEqual(length, requested)
                    total += length
                self.assertEqual(total, size)
                self.assertEqual((requests[-1], returned[-1]), (1, 0))
                if short_read:
                    self.assertGreater(len(requests), 2)
                controls += 1
        self.assertEqual(controls, 6)
        print('candidate-archive-hash-stable-controls {"schema_version":1,"actual_stable_file_hashes":6,"short_reads_supported":true,"one_MiB_maximum_request":true,"remaining_length_plus_one_bound":true,"real_eof_required":true,"descriptors_closed":true}')

    def test_archive_hash_growth_shrinkage_and_read_errors_close(self):
        controls = {"grow": 0, "shrink": 0, "read": 0}
        for size in (1024, (1 << 20) + 17):
            for mode in controls:
                with self.subTest(size=size, mode=mode), tempfile.TemporaryDirectory() as directory:
                    path = Path(directory) / "archive.zip"
                    path.write_bytes(b"a" * size)
                    requests, returned = [], []
                    with checker.regular_archive(path) as stream:
                        descriptor, actual_read = stream.fileno(), stream.read

                        def read(count=-1):
                            if not requests:
                                if mode == "grow":
                                    with path.open("ab") as target:
                                        target.write(b"b" * (2 << 20))
                                elif mode == "shrink":
                                    with path.open("r+b") as target:
                                        target.truncate(size // 2)
                            requests.append(count)
                            if mode == "read":
                                raise OSError("injected read failure")
                            raw = actual_read(count)
                            returned.append(len(raw))
                            return raw

                        with mock.patch.object(stream, "read", side_effect=read):
                            expected = OSError if mode == "read" else checker.Rejected
                            with self.assertRaises(expected) as failure:
                                checker.file_hash(stream)
                            if mode != "read":
                                self.assertEqual(failure.exception.category, "archive")
                    self.assertTrue(stream.closed)
                    with self.assertRaises(OSError):
                        os.fstat(descriptor)
                    self.assertLessEqual(sum(returned), size + 1)
                    self.assertTrue(all(0 < count <= 1 << 20 for count in requests))
                    if mode == "grow":
                        self.assertEqual(sum(returned), size + 1)
                        self.assertEqual(path.stat().st_size, size + (2 << 20))
                        self.assertEqual(len(requests), 1 if size < 1 << 20 else 2)
                    elif mode == "shrink":
                        self.assertEqual(sum(returned), size // 2)
                        self.assertEqual(returned[-1], 0)
                        self.assertEqual(path.stat().st_size, size // 2)
                    else:
                        self.assertEqual((len(requests), sum(returned)), (1, 0))
                    controls[mode] += 1
        self.assertEqual(controls, {"grow": 2, "shrink": 2, "read": 2})

    def test_archive_hash_descriptor_size_bounds_precede_reads(self):
        controls = 0
        for size in (0, checker.ARCHIVE_LIMIT + 1):
            with self.subTest(size=size), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "archive.zip"
                with path.open("wb") as target:
                    target.truncate(size)
                with path.open("rb") as stream:
                    descriptor = stream.fileno()
                    with mock.patch.object(stream, "read") as read:
                        with self.assertRaises(checker.Rejected) as failure:
                            checker.file_hash(stream)
                        self.assertEqual(failure.exception.category, "archive")
                        read.assert_not_called()
                self.assertTrue(stream.closed)
                with self.assertRaises(OSError):
                    os.fstat(descriptor)
                controls += 1
        self.assertEqual(controls, 2)
        print('candidate-archive-hash-refusal-controls {"schema_version":1,"actual_growth_refusals":2,"actual_shrinkage_refusals":2,"injected_read_errors":2,"actual_size_preconditions_refused_before_read":2,"growth_read_bytes_at_most_selected_plus_one":true,"actual_fstat_not_mocked":true,"descriptors_closed":true}')

    def test_metadata_entry_reads_use_selected_length_and_close(self):
        controls = 0
        for name, limit in (("manifest.json", 256 << 10), ("offline-pilot.json", 4 << 20)):
            for size in (1, 1024, 128 << 10, limit):
                payload = b"a" * size
                for compression in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                    with self.subTest(name=name, size=size, compression=compression):
                        raw = metadata_entry_fixture(name, payload, compression)
                        opened, requests = [], []
                        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                            actual_open = archive.open

                            def record_open(*args, **kwargs):
                                stream = actual_open(*args, **kwargs)
                                actual_read = stream.read

                                def record_read(count=-1):
                                    requests.append(count)
                                    return actual_read(count)

                                stream.read = record_read
                                opened.append(stream)
                                return stream

                            with mock.patch.object(archive, "open", side_effect=record_open):
                                result = checker.entry_bytes(archive, archive.getinfo(name), limit)
                            self.assertEqual(result, payload)
                        self.assertEqual(requests, [size + 1])
                        self.assertEqual(len(opened), 1)
                        self.assertTrue(opened[0].closed)
                        controls += 1
        self.assertEqual(controls, 16)
        print('candidate-metadata-read-controls {"schema_version":1,"actual_stable_entry_reads":16,"selected_length_read_requests":true,"stored_and_deflated":true,"exact_category_caps":true,"entry_streams_closed":true}')

    def test_metadata_entry_crc_length_and_preopen_bounds_remain_required(self):
        crc_refusals, length_refusals, preopen_refusals = 0, 0, 0
        for name, limit in (("manifest.json", 256 << 10), ("offline-pilot.json", 4 << 20)):
            payload = b"bounded metadata entry bytes"
            for compression in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                for mode in ("crc", "length"):
                    with self.subTest(name=name, compression=compression, mode=mode):
                        raw = bytearray(metadata_entry_fixture(name, payload, compression))
                        central = raw.index(b"PK\x01\x02")
                        if mode == "crc":
                            struct.pack_into("<I", raw, central + 16, struct.unpack_from("<I", raw, central + 16)[0] ^ 1)
                            expected = zipfile.BadZipFile
                        else:
                            struct.pack_into("<I", raw, central + 24, len(payload) + 1)
                            expected = checker.Rejected
                        opened = []
                        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                            actual_open = archive.open

                            def record_open(*args, **kwargs):
                                stream = actual_open(*args, **kwargs)
                                opened.append(stream)
                                return stream

                            with mock.patch.object(archive, "open", side_effect=record_open):
                                with self.assertRaises(expected) as failure:
                                    checker.entry_bytes(archive, archive.getinfo(name), limit)
                            if mode == "length":
                                self.assertEqual(failure.exception.category, "archive")
                                length_refusals += 1
                            else:
                                crc_refusals += 1
                        self.assertEqual(len(opened), 1)
                        self.assertTrue(opened[0].closed)
            for size in (0, limit + 1):
                with self.subTest(name=name, refused_size=size):
                    raw = metadata_entry_fixture(name, b"a" * size, zipfile.ZIP_STORED)
                    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                        with mock.patch.object(archive, "open") as opened:
                            with self.assertRaises(checker.Rejected) as failure:
                                checker.entry_bytes(archive, archive.getinfo(name), limit)
                            self.assertEqual(failure.exception.category, "archive")
                            opened.assert_not_called()
                    preopen_refusals += 1
        self.assertEqual((crc_refusals, length_refusals, preopen_refusals), (4, 4, 4))
        print('candidate-metadata-refusal-controls {"schema_version":1,"actual_crc_refusals":4,"actual_length_refusals":4,"actual_preopen_size_refusals":4,"malformed_entry_streams_closed":true,"invalid_size_entries_not_opened":true}')

    def test_replaced_descriptor_type_and_size_are_refused_and_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "archive.zip"
            path.write_bytes(b"ordinary input")
            actual_fstat = checker.os.fstat
            for replacement in ("fifo", "oversize"):
                with self.subTest(replacement=replacement):
                    descriptors = []
                    def changed_descriptor(fd):
                        descriptors.append(fd)
                        fields = list(actual_fstat(fd))
                        if replacement == "fifo":
                            fields[0] = stat.S_IFIFO | 0o600
                        else:
                            fields[6] = checker.ARCHIVE_LIMIT + 1
                        return os.stat_result(fields)
                    with mock.patch.object(checker.os, "fstat", side_effect=changed_descriptor):
                        with mock.patch.object(checker, "file_hash") as hashed:
                            with self.assertRaises(checker.Rejected) as failure:
                                checker.check(path, "0" * 64, REVISION, INPUTS, "linux", "amd64")
                            self.assertEqual(failure.exception.category, "archive")
                            hashed.assert_not_called()
                    self.assertEqual(len(descriptors), 1)
                    with self.assertRaises(OSError):
                        actual_fstat(descriptors[0])

    def test_actual_replacements_are_refused_before_hashing_or_parsing(self):
        for mode in ("same_bytes", "same_size", "different_size"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                selected = Path(directory) / "PRIVATE_ARCHIVE.zip"
                replacement = Path(directory) / "replacement.zip"
                selected.write_bytes(b"old bytes")
                raw = {"same_bytes": b"old bytes", "same_size": b"new bytes",
                       "different_size": b"new length"}[mode]
                replacement.write_bytes(raw)
                self.assertFalse(os.path.samestat(selected.stat(), replacement.stat()))
                actual_open = os.open
                descriptors = []

                def replace_at_open(path, flags):
                    os.replace(replacement, selected)
                    descriptor = actual_open(path, flags)
                    descriptors.append(descriptor)
                    return descriptor

                with mock.patch.object(checker.os, "open", side_effect=replace_at_open), \
                        mock.patch.object(checker, "file_hash") as hashed, \
                        mock.patch.object(checker, "check_contents") as parsed:
                    with self.assertRaises(checker.Rejected) as failure:
                        checker.check(selected, "0" * 64, REVISION, INPUTS, "linux", "amd64")
                    self.assertEqual(failure.exception.category, "archive")
                    hashed.assert_not_called()
                    parsed.assert_not_called()
                self.assertEqual(len(descriptors), 1)
                with self.assertRaises(OSError):
                    os.fstat(descriptors[0])
                self.assertEqual(selected.read_bytes(), raw)
        print('candidate-archive-identity-controls {"schema_version":1,"actual_replacement_refusals":3,"same_bytes_control":true,"descriptors_closed":true,"hashing_and_parsing_started":false}')

    def test_actual_same_inode_size_drift_precedes_hashing(self):
        with tempfile.TemporaryDirectory() as directory:
            selected = Path(directory) / "PRIVATE_ARCHIVE.zip"
            selected.write_bytes(b"old bytes")
            initial = selected.stat()
            actual_open = os.open
            descriptors = []

            def grow_at_open(path, flags):
                selected.write_bytes(b"old bytes plus growth")
                descriptor = actual_open(path, flags)
                descriptors.append(descriptor)
                self.assertTrue(os.path.samestat(initial, os.fstat(descriptor)))
                return descriptor

            with mock.patch.object(checker.os, "open", side_effect=grow_at_open), \
                    mock.patch.object(checker, "file_hash") as hashed, \
                    mock.patch.object(checker, "check_contents") as parsed:
                with self.assertRaises(checker.Rejected) as failure:
                    checker.check(selected, "0" * 64, REVISION, INPUTS, "linux", "amd64")
                self.assertEqual(failure.exception.category, "archive")
                hashed.assert_not_called()
                parsed.assert_not_called()
            self.assertEqual(len(descriptors), 1)
            with self.assertRaises(OSError):
                os.fstat(descriptors[0])
        print('candidate-archive-size-controls {"schema_version":1,"actual_same_inode_size_refusals":1,"descriptor_closed":true,"hashing_and_parsing_started":false}')

    def test_actual_stable_archive_identity_is_accepted(self):
        with tempfile.TemporaryDirectory() as directory:
            selected = Path(directory) / "archive.zip"
            raw = b"\x00\xff\x80Z\n"
            selected.write_bytes(raw)
            with checker.regular_archive(selected) as stream:
                descriptor = stream.fileno()
                self.assertTrue(os.path.samestat(selected.stat(), os.fstat(descriptor)))
                self.assertEqual(stream.read(), raw)
            with self.assertRaises(OSError):
                os.fstat(descriptor)
        print('candidate-archive-stable-identity-controls {"schema_version":1,"actual_stable_descriptors":1,"descriptor_closed":true}')

    def test_nonregular_empty_and_oversize_targets_precede_open_and_parsing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            empty = root / "empty.zip"
            empty.write_bytes(b"")
            oversized = root / "oversize.zip"
            with oversized.open("wb") as stream:
                stream.truncate(checker.ARCHIVE_LIMIT + 1)
            for path in (root, empty, oversized):
                with self.subTest(target=path.name):
                    with mock.patch.object(checker.os, "open") as opened:
                        with mock.patch.object(checker, "file_hash") as hashed:
                            with mock.patch.object(checker, "check_contents") as parsed:
                                with self.assertRaises(checker.Rejected) as failure:
                                    checker.check(path, "0" * 64, REVISION, INPUTS, "linux", "amd64")
                                self.assertEqual(failure.exception.category, "archive")
                                opened.assert_not_called()
                                hashed.assert_not_called()
                                parsed.assert_not_called()

    def test_native_layouts_and_explicit_skips(self):
        for os_name in ("linux", "darwin", "windows"):
            with self.subTest(os=os_name):
                files, manifest, report = fixture(os_name)
                code, result = self.invoke(pack(files, manifest, report), os_name)
                self.assertEqual(code, 0)
                self.assertEqual(result["binaries"], 7)
                report["status"] = manifest["test_status"] = "passed_with_skips"
                report["cases"][0]["status"], report["cases"][0]["skipped_subtests"] = "passed_with_skips", 1
                code, result = self.invoke(pack(files, manifest, report), os_name)
                self.assertEqual(code, 0)
                self.assertEqual(result["skipped_subtests"], 1)
                self.assertEqual(result["test_status"], "passed_with_skips")

    def test_selected_pilot_packages_have_archive_support(self):
        manifest = Path(__file__).parent / "offline-pilot" / "manifest.go"
        packages = re.findall(r'^\s*\{"[^"]+", "([^"]+)", "Test[^"]+",',
                              manifest.read_text(), re.MULTILINE)
        self.assertTrue(packages, "selected pilot packages were not found")
        self.assertFalse(set(packages) - checker.PACKAGES,
                         "selected pilot package is unsupported by the archive checker")
        for os_name in ("linux", "darwin", "windows"):
            with self.subTest(os=os_name):
                files, manifest, report = fixture(os_name)
                report["cases"].append({"id": "bounded_rpc_response_reader", "package": "internal/fetch",
                    "test": "TestRPCResponseReadContract", "status": "passed", "passed_subtests": 6,
                    "skipped_subtests": 0, "failed_subtests": 0, "binaries": []})
                code, result = self.invoke(pack(files, manifest, report), os_name)
                self.assertEqual((code, result["status"]), (0, "verified"))
                report["cases"][-1]["package"] = "internal/PRIVATE_UNSUPPORTED"
                code, result = self.invoke(pack(files, manifest, report), os_name)
                self.assertEqual((code, result["status"], result["category"]), (2, "rejected", "metadata"))

    def test_consumer_input_cases_and_explicit_native_skips(self):
        # These opaque archives exercise report compatibility, not native I/O.
        for os_name in ("linux", "darwin", "windows"):
            with self.subTest(os=os_name):
                files, manifest, report = fixture(os_name)
                descriptors = {"id": "consumer_input_descriptors", "package": "tools/consume-query-report",
                    "test": "TestConsumerInputDescriptors", "status": "passed", "passed_subtests": 6,
                    "skipped_subtests": 0, "failed_subtests": 0, "binaries": []}
                native = {"id": "consumer_input_fifo", "package": "tools/consume-query-report",
                    "test": "TestConsumerInputFIFOOpenIsBounded", "status": "passed", "passed_subtests": 3,
                    "skipped_subtests": 0, "failed_subtests": 0, "binaries": []}
                if os_name == "windows":
                    native.update(status="passed_with_skips", passed_subtests=0, skipped_subtests=3)
                    report["status"] = manifest["test_status"] = "passed_with_skips"
                report["cases"].extend((descriptors, native))
                code, result = self.invoke(pack(files, manifest, report), os_name)
                self.assertEqual(code, 0)
                self.assertEqual(result["binaries"], 7)
                self.assertEqual(result["skipped_subtests"], 3 if os_name == "windows" else 0)
                for mode in ("unknown_package", "whole_scenario_skip"):
                    with self.subTest(control=mode):
                        invalid = copy.deepcopy(report)
                        if mode == "unknown_package":
                            invalid["cases"][-1]["package"] = "tools/PRIVATE_PACKAGE"
                        else:
                            invalid["cases"][-1]["status"] = "skipped"
                        code, result = self.invoke(pack(files, manifest, invalid), os_name)
                        self.assertEqual(code, 2)
                        self.assertEqual(result["category"], "metadata")

    def test_external_pins_are_required(self):
        raw = pack(*fixture())
        for key, value in (("expect-archive-sha256", "a" * 64), ("expect-revision", "a" * 40),
                           ("expect-inputs", "a" * 64), ("expect-os", "darwin"), ("expect-architecture", "arm64")):
            with self.subTest(pin=key):
                code, result = self.invoke(raw, replace={key: value})
                self.assertEqual(code, 2)
                self.assertEqual(result["status"], "rejected")

    def test_archive_layouts_cannot_extract_paths_or_alias_payloads(self):
        for mode in ("missing", "extra", "duplicate", "traversal", "symlink"):
            with self.subTest(layout=mode):
                files, manifest, report = fixture()
                extra = None
                if mode == "missing":
                    del files["zenon-spv"]
                elif mode == "extra":
                    extra = ("PRIVATE_FILE", b"private bytes")
                elif mode == "duplicate":
                    extra = ("zenon-spv", files["zenon-spv"])
                elif mode == "traversal":
                    files["../zenon-spv"] = files.pop("zenon-spv")
                else:
                    value = files.pop("zenon-spv")
                    info = zipfile.ZipInfo("zenon-spv")
                    info.create_system = 3
                    info.external_attr = (stat.S_IFLNK | 0o777) << 16
                    extra = (info, value)
                code, result = self.invoke(pack(files, manifest, report, extra=extra))
                self.assertEqual(code, 2)
                self.assertEqual(result["category"], "layout")

    def test_tested_bytes_and_report_hashes_are_bound(self):
        for mode in ("binary", "report_hash", "execution_hash", "unobserved_command"):
            with self.subTest(binding=mode):
                files, manifest, report = fixture()
                mutate = None
                if mode == "binary":
                    files["zenon-spv"] = b"different executable bytes"
                elif mode == "report_hash":
                    mutate = lambda value: value["report"].update(sha256="a" * 64)
                elif mode == "execution_hash":
                    report["cases"][0]["binaries"][0]["sha256"] = "a" * 64
                else:
                    report["cases"][0]["binaries"] = [b for b in report["cases"][0]["binaries"]
                                                       if b["command"] != "fetch-bundle"]
                code, _ = self.invoke(pack(files, manifest, report, mutate_manifest=mutate))
                self.assertEqual(code, 2)

    def test_ambiguous_json_and_unbounded_values_are_refused(self):
        mutations = (
            lambda raw: raw.replace(b'"schema_version": 1', b'"schema_version": 1, "schema_version": 1', 1),
            lambda raw: raw.replace(b'"schema_version": 1', b'"Schema_Version": 1', 1),
            lambda raw: raw.replace(b'"schema_version": 1', b'"schema_version": true', 1),
            lambda raw: raw.replace(b'"schema_version": 1', b'"schema_version": 1.0', 1),
            lambda raw: raw.replace(b'"schema_version": 1', b'"schema_version": 18446744073709551616', 1),
            lambda raw: raw + b' {}',
        )
        for i, mutate in enumerate(mutations):
            with self.subTest(mutation=i):
                code, _ = self.invoke(pack(*fixture(), mutate_raw=mutate))
                self.assertEqual(code, 2)

    def test_inconsistent_status_or_source_cannot_pass(self):
        for mode in ("failure", "hidden_skip", "bool_count", "changed_source", "numeric_modified", "duplicate_case", "duplicate_command", "unknown_field", "oversize"):
            with self.subTest(metadata=mode):
                files, manifest, report = fixture()
                mutate = None
                if mode == "failure":
                    report["cases"][0]["failed_subtests"] = 1
                elif mode == "hidden_skip":
                    report["cases"][0]["skipped_subtests"] = 1
                elif mode == "bool_count":
                    report["cases"][0]["passed_subtests"] = True
                elif mode == "changed_source":
                    report["source_matches_after_run"] = False
                elif mode == "numeric_modified":
                    report["source"]["modified"] = 0
                elif mode == "duplicate_case":
                    report["cases"].append(copy.deepcopy(report["cases"][0]))
                elif mode == "duplicate_command":
                    report["cases"][0]["binaries"][1] = copy.deepcopy(report["cases"][0]["binaries"][0])
                elif mode == "unknown_field":
                    mutate = lambda value: value.update(PRIVATE_FIELD=True)
                else:
                    mutate = lambda value: value["binaries"][0].update(bytes=checker.BINARY_LIMIT + 1)
                code, _ = self.invoke(pack(files, manifest, report, mutate_manifest=mutate))
                self.assertEqual(code, 2)

    def test_invalid_invocations_do_not_echo_private_values(self):
        for replace, extra in (({"expect-revision": "PRIVATE_REVISION"}, ()), ({}, ("--archive", "PRIVATE_OTHER_ARCHIVE")),
                               ({}, ("--PRIVATE_OPTION",)), ({}, ("PRIVATE_POSITIONAL",))):
            with self.subTest(arguments=bool(extra)):
                code, result = self.invoke(pack(*fixture()), replace=replace, extra_args=extra)
                self.assertEqual(code, 64)
                self.assertEqual(result["category"], "arguments")

    def test_actual_go_identifiers_allow_underscores_without_paths(self):
        for name in ("TestVerifyHeadersWithOptions_RequiredUnknownHeightRefuses",
                     "TestAuthorizeRetainedWindow_RequiredRefusesUncoveredHeight",
                     "TestExample/PRIVATE_PATH", "../PRIVATE_PATH", "Test PRIVATE_NAME"):
            with self.subTest(test_name=name):
                files, manifest, report = fixture()
                report["cases"][0]["test"] = name
                code, _ = self.invoke(pack(files, manifest, report))
                self.assertEqual(code, 0 if name.startswith(("TestVerifyHeaders", "TestAuthorizeRetained")) else 2)

    def test_repeated_query_measurements_are_complete_and_native(self):
        for os_name in ("linux", "darwin", "windows"):
            for mode in ("complete", "missing", "short", "long", "duplicate_workload", "unknown_workload", "wrong_targets",
                         "oversize_report", "zero_expectations", "wrong_source", "zero_peak", "overflow_peak", "zero_elapsed",
                         "overlong_elapsed", "float_elapsed", "bool_elapsed", "null_point", "missing_point_field",
                         "unknown_point_field", "first_mismatch", "bool_first", "hidden_skip", "wrong_case"):
                with self.subTest(os=os_name, mutation=mode):
                    files, manifest, report = fixture(os_name)
                    case = report["cases"][1]
                    sample = case["query_resource_samples"][0]
                    point = sample["observations"][20]
                    if mode == "missing":
                        del sample["observations"]
                    elif mode == "short":
                        sample["observations"].pop()
                    elif mode == "long":
                        sample["observations"].append(copy.deepcopy(point))
                    elif mode == "duplicate_workload":
                        case["query_resource_samples"][1] = copy.deepcopy(sample)
                    elif mode == "unknown_workload":
                        sample["workload"] = "PRIVATE_PATH"
                    elif mode == "wrong_targets":
                        sample["targets"] = 16
                    elif mode == "oversize_report":
                        sample["report_bytes"] = (4 << 20) + 1
                    elif mode == "zero_expectations":
                        sample["expectations_bytes"] = 0
                    elif mode == "wrong_source":
                        point["peak_rss_source"] = "process_rusage" if os_name == "windows" else "windows_peak_working_set"
                    elif mode == "zero_peak":
                        point["peak_rss_bytes"] = 0
                    elif mode == "overflow_peak":
                        point["peak_rss_bytes"] = (1 << 50) + 1
                    elif mode == "zero_elapsed":
                        point["elapsed_ns"] = 0
                    elif mode == "overlong_elapsed":
                        point["elapsed_ns"] = 60_000_000_001
                    elif mode == "float_elapsed":
                        point["elapsed_ns"] = 1000020.0
                    elif mode == "bool_elapsed":
                        point["elapsed_ns"] = True
                    elif mode == "null_point":
                        sample["observations"][20] = None
                    elif mode == "missing_point_field":
                        del point["peak_rss_source"]
                    elif mode == "unknown_point_field":
                        point["PRIVATE_FIELD"] = "PRIVATE_PATH"
                    elif mode == "first_mismatch":
                        sample["elapsed_ns"] += 1
                    elif mode == "bool_first":
                        sample["elapsed_ns"] = True
                    elif mode == "hidden_skip":
                        case["skipped_subtests"] = 1
                    elif mode == "wrong_case":
                        case["id"] = "example_other"
                    code, result = self.invoke(pack(files, manifest, report), os_name)
                    self.assertEqual(code, 0 if mode == "complete" else 2)
                    self.assertEqual(result["status"], "verified" if mode == "complete" else "rejected")

    def test_query_case_cannot_be_removed_or_reidentified(self):
        for os_name in ("linux", "darwin", "windows"):
            for mode in ("removed", "renamed", "relabeled_samples", "wrong_package", "wrong_test",
                         "missing_verifier", "missing_consumer", "extra_command"):
                with self.subTest(os=os_name, mutation=mode):
                    files, manifest, report = fixture(os_name)
                    case = report["cases"][1]
                    if mode == "removed":
                        report["cases"].pop(1)
                    elif mode == "renamed":
                        case["id"] = "other_case"
                        del case["query_resource_samples"]
                    elif mode == "relabeled_samples":
                        case["id"] = "other_case"
                        case["resource_samples"] = case.pop("query_resource_samples")
                    elif mode == "wrong_package":
                        case["package"] = "internal/proof"
                    elif mode == "wrong_test":
                        case["test"] = "TestOther"
                    elif mode == "missing_verifier":
                        case["binaries"] = [b for b in case["binaries"] if b["command"] != "zenon-spv"]
                    elif mode == "missing_consumer":
                        case["binaries"] = [b for b in case["binaries"] if b["command"] != "consume-query-report"]
                    else:
                        case["binaries"].append(next(b for b in report["cases"][0]["binaries"] if b["command"] == "fetch-bundle"))
                    code, result = self.invoke(pack(files, manifest, report), os_name)
                    self.assertEqual((code, result["status"]), (2, "rejected"))

    def test_verifier_resource_case_cannot_be_removed_or_reidentified(self):
        for os_name in ("linux", "darwin", "windows"):
            for mode in ("removed", "renamed", "renamed_without_samples", "foreign_example", "foreign_query",
                         "foreign_null", "foreign_empty", "wrong_package", "wrong_test", "missing_verifier", "extra_command"):
                with self.subTest(os=os_name, mutation=mode):
                    files, manifest, report = fixture(os_name)
                    case = report["cases"][2]
                    if mode == "removed":
                        report["cases"].pop(2)
                    elif mode in ("renamed", "renamed_without_samples"):
                        case["id"] = "other_case"
                        if mode == "renamed_without_samples":
                            del case["resource_samples"]
                    elif mode in ("foreign_example", "foreign_query", "foreign_null", "foreign_empty"):
                        target = report["cases"][1 if mode == "foreign_query" else 0]
                        target["resource_samples"] = (None if mode == "foreign_null" else
                            [] if mode == "foreign_empty" else copy.deepcopy(case["resource_samples"]))
                    elif mode == "wrong_package":
                        case["package"] = "internal/proof"
                    elif mode == "wrong_test":
                        case["test"] = "TestOther"
                    elif mode == "missing_verifier":
                        case["binaries"] = []
                    else:
                        case["binaries"].append(next(b for b in report["cases"][0]["binaries"]
                                                      if b["command"] == "fetch-bundle"))
                    code, result = self.invoke(pack(files, manifest, report), os_name)
                    self.assertEqual((code, result["status"]), (2, "rejected"))

    def test_verifier_resource_case_requires_exact_completion(self):
        for os_name in ("linux", "darwin", "windows"):
            for mode in ("too_few_passes", "too_many_passes", "bool_passes", "float_passes", "hidden_skip", "explicit_skip", "failure"):
                with self.subTest(os=os_name, mutation=mode):
                    files, manifest, report = fixture(os_name)
                    case = report["cases"][2]
                    if mode in ("too_few_passes", "too_many_passes", "bool_passes", "float_passes"):
                        case["passed_subtests"] = {"too_few_passes": 3, "too_many_passes": 5,
                                                  "bool_passes": True, "float_passes": 4.0}[mode]
                    elif mode in ("hidden_skip", "explicit_skip"):
                        case["skipped_subtests"] = 1
                        if mode == "explicit_skip":
                            case["status"] = report["status"] = manifest["test_status"] = "passed_with_skips"
                    else:
                        case["failed_subtests"] = 1
                    code, result = self.invoke(pack(files, manifest, report), os_name)
                    self.assertEqual((code, result["status"]), (2, "rejected"))

    def test_verifier_resource_workloads_are_complete_and_unique(self):
        for os_name in ("linux", "darwin", "windows"):
            for mode in ("missing", "null", "empty", "short", "long", "duplicate", "unknown", "null_point", "object_list"):
                with self.subTest(os=os_name, mutation=mode):
                    files, manifest, report = fixture(os_name)
                    case = report["cases"][2]
                    samples = case["resource_samples"]
                    if mode == "missing":
                        del case["resource_samples"]
                    elif mode == "null":
                        case["resource_samples"] = None
                    elif mode == "empty":
                        samples.clear()
                    elif mode == "short":
                        samples.pop()
                    elif mode == "long":
                        samples.append(copy.deepcopy(samples[0]))
                    elif mode == "duplicate":
                        samples[1] = copy.deepcopy(samples[0])
                    elif mode == "unknown":
                        samples[0]["workload"] = "PRIVATE_WORKLOAD"
                    elif mode == "null_point":
                        samples[0] = None
                    else:
                        case["resource_samples"] = {sample["workload"]: sample for sample in samples}
                    code, result = self.invoke(pack(files, manifest, report), os_name)
                    self.assertEqual((code, result["status"]), (2, "rejected"))

    def test_verifier_resource_dimensions_require_exact_json_integers(self):
        for os_name in ("linux", "darwin", "windows"):
            for index in range(4):
                for field in ("members_per_proof", "proofs"):
                    for alias in (True, False, None, "1", 1.0, 0, -1, 2**64):
                        with self.subTest(os=os_name, workload=index, field=field, value=alias):
                            files, manifest, report = fixture(os_name)
                            report["cases"][2]["resource_samples"][index][field] = alias
                            code, result = self.invoke(pack(files, manifest, report), os_name)
                            self.assertEqual((code, result["status"]), (2, "rejected"))
            # These remain valid integers but name a different workload grid.
            for field, value in (("members_per_proof", 1000), ("proofs", 4)):
                with self.subTest(os=os_name, wrong_dimension=field):
                    files, manifest, report = fixture(os_name)
                    report["cases"][2]["resource_samples"][0][field] = value
                    code, result = self.invoke(pack(files, manifest, report), os_name)
                    self.assertEqual((code, result["status"]), (2, "rejected"))

    def test_verifier_resource_measurements_require_bounded_native_values(self):
        for os_name in ("linux", "darwin", "windows"):
            for field, ceiling in (("input_bytes", 64 << 20), ("elapsed_ns", 60_000_000_000), ("peak_rss_bytes", 1 << 50)):
                for value in (0, -1, ceiling + 1, 2**64, True, False, None, "1", 1.0):
                    with self.subTest(os=os_name, field=field, value=value):
                        files, manifest, report = fixture(os_name)
                        report["cases"][2]["resource_samples"][0][field] = value
                        code, result = self.invoke(pack(files, manifest, report), os_name)
                        self.assertEqual((code, result["status"]), (2, "rejected"))
            wrong_source = "process_rusage" if os_name == "windows" else "windows_peak_working_set"
            for value in (wrong_source, "unavailable", "PRIVATE_MEMORY_SOURCE", None, False, []):
                with self.subTest(os=os_name, memory_source=value):
                    files, manifest, report = fixture(os_name)
                    report["cases"][2]["resource_samples"][0]["peak_rss_source"] = value
                    code, result = self.invoke(pack(files, manifest, report), os_name)
                    self.assertEqual((code, result["status"]), (2, "rejected"))

    def test_verifier_resource_fields_cannot_be_missing_repeated_or_private(self):
        for os_name in ("linux", "darwin", "windows"):
            fields = ("workload", "members_per_proof", "proofs", "input_bytes", "elapsed_ns", "peak_rss_bytes", "peak_rss_source")
            for field in fields:
                with self.subTest(os=os_name, missing=field):
                    files, manifest, report = fixture(os_name)
                    del report["cases"][2]["resource_samples"][0][field]
                    code, result = self.invoke(pack(files, manifest, report), os_name)
                    self.assertEqual((code, result["status"]), (2, "rejected"))
            files, manifest, report = fixture(os_name)
            report["cases"][2]["resource_samples"][0]["PRIVATE_FIELD"] = "PRIVATE_PATH"
            code, result = self.invoke(pack(files, manifest, report), os_name)
            self.assertEqual((code, result["status"]), (2, "rejected"))
            for field in fields:
                with self.subTest(os=os_name, repeated=field):
                    files, manifest, report = fixture(os_name)
                    sample = report["cases"][2]["resource_samples"][0]
                    fragment = json.dumps({field: sample[field]})[1:-1].encode()
                    # Locate this resource record rather than the earlier query
                    # sample's identically named elapsed or memory fields.
                    needle = json.dumps(sample).encode()
                    replaced = needle.replace(fragment, fragment + b", " + fragment, 1)
                    mutate = lambda raw, a=needle, b=replaced: raw.replace(a, b, 1)
                    code, result = self.invoke(pack(files, manifest, report, mutate_report_raw=mutate), os_name)
                    self.assertEqual((code, result["status"]), (2, "rejected"))

    def test_verifier_resource_boundaries_and_order_independence(self):
        for os_name in ("linux", "darwin", "windows"):
            for upper in (False, True):
                with self.subTest(os=os_name, upper_boundary=upper):
                    files, manifest, report = fixture(os_name)
                    samples = report["cases"][2]["resource_samples"]
                    for sample in samples:
                        sample.update(input_bytes=64 << 20 if upper else 1,
                                      elapsed_ns=60_000_000_000 if upper else 1,
                                      peak_rss_bytes=1 << 50 if upper else 1)
                    # The Go collector validates workload identities and does
                    # not require resource input records in a fixed order.
                    samples[:] = [samples[i] for i in (3, 1, 0, 2)]
                    code, result = self.invoke(pack(files, manifest, report), os_name)
                    self.assertEqual((code, result["status"]), (0, "verified"))

    def test_local_zip_metadata_supports_fixed_native_layouts(self):
        for os_name in ("linux", "darwin", "windows"):
            for compression in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                for descriptor, zip64, unsigned in ((False, False, False), (False, True, False),
                        (True, False, False), (True, False, True), (True, True, False), (True, True, True)):
                    with self.subTest(os=os_name, method=compression, descriptor=descriptor, zip64=zip64, unsigned=unsigned):
                        raw = pack(*fixture(os_name), compression=compression, descriptor=descriptor, zip64=zip64, unsigned=unsigned)
                        code, result = self.invoke(raw, os_name)
                        self.assertEqual((code, result["status"]), (0, "verified"))
                        if zip64:
                            # Exercise explicit ZIP64 sentinels independently of writer-version choices.
                            changed = bytearray(raw)
                            with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                                for info in archive.infolist():
                                    struct.pack_into("<II", changed, info.header_offset + 18, 0xffffffff, 0xffffffff)
                            code, result = self.invoke(bytes(changed), os_name)
                            self.assertEqual((code, result["status"]), (0, "verified"))

    def test_central_directory_is_bounded_before_zipfile_allocation(self):
        raw = pack(*fixture())
        end, records = central_records(raw)
        count_lie = None
        for copies, claim_actual in ((1, False), (10000, False), (10000, True)):
            with self.subTest(extra_records=copies, claimed_count=claim_actual):
                extra = records[0][1] * copies
                trailer = bytearray(raw[end:])
                struct.pack_into("<I", trailer, 12, end - records[0][0] + len(extra))
                if claim_actual:
                    struct.pack_into("<HH", trailer, 8, 9 + copies, 9 + copies)
                changed = raw[:end] + extra + trailer
                if copies == 10000 and not claim_actual:
                    count_lie = changed
                # The ordinary reader ignores EOCD counts and materializes
                # every actual record, including a count lie of nine.
                with zipfile.ZipFile(io.BytesIO(changed)) as archive:
                    self.assertEqual(len(archive.infolist()), 9 + copies)
                with mock.patch.object(checker.zipfile, "ZipFile") as constructor:
                    code, result = self.invoke(changed)
                    self.assertEqual((code, result["category"]), (2, "layout"))
                    constructor.assert_not_called()

        class BoundedReads(io.BytesIO):
            def read(self, size=-1):
                if not 0 <= size <= 22 + 0xffff:
                    raise AssertionError("unbounded central-directory preflight read")
                return super().read(size)

        with mock.patch.object(checker.zipfile, "ZipFile") as constructor:
            with self.assertRaises(checker.Rejected) as failure:
                checker.check_contents(BoundedReads(count_lie), REVISION, INPUTS, "linux", "amd64")
            self.assertEqual(failure.exception.category, "layout")
            constructor.assert_not_called()

    def test_central_directory_malformed_boundaries_precede_zipfile(self):
        raw = pack(*fixture())
        end, records = central_records(raw)
        for mode in ("disk", "central_disk", "disk_count", "count", "zero_size", "large_size", "offset",
                     "truncated_directory", "record_signature", "zero_name", "name_bound", "extra_bound",
                     "entry_comment_bound", "comment_bound", "trailing_bytes", "short_end"):
            with self.subTest(mutation=mode):
                changed = bytearray(raw)
                if mode in ("disk", "central_disk", "disk_count", "count"):
                    offset = {"disk": 4, "central_disk": 6, "disk_count": 8, "count": 10}[mode]
                    struct.pack_into("<H", changed, end + offset, 1)
                elif mode in ("zero_size", "large_size", "truncated_directory"):
                    value = {"zero_size": 0, "large_size": 0xffffffff,
                             "truncated_directory": end - records[0][0] + 1}[mode]
                    struct.pack_into("<I", changed, end + 12, value)
                elif mode == "offset":
                    struct.pack_into("<I", changed, end + 16, records[0][0] + 1)
                elif mode == "record_signature":
                    changed[records[0][0]] = ord("X")
                elif mode in ("zero_name", "name_bound", "extra_bound", "entry_comment_bound"):
                    offset = {"zero_name": 28, "name_bound": 28, "extra_bound": 30, "entry_comment_bound": 32}[mode]
                    struct.pack_into("<H", changed, records[-1][0] + offset, 0 if mode == "zero_name" else 0xffff)
                elif mode == "comment_bound":
                    struct.pack_into("<H", changed, end + 20, 1)
                elif mode == "trailing_bytes":
                    changed += b"PRIVATE_TRAILER"
                else:
                    changed = changed[:-1]
                with mock.patch.object(checker.zipfile, "ZipFile") as constructor:
                    code, result = self.invoke(bytes(changed))
                    self.assertEqual((code, result["category"]), (2, "layout"))
                    constructor.assert_not_called()

    def test_central_end_comments_prefixes_and_complete_zip64(self):
        for os_name in ("linux", "darwin", "windows"):
            for compression in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                for descriptor, local_zip64 in ((False, False), (False, True), (True, False), (True, True)):
                    for comment in (b"", b"bounded archive comment", b"x" * 0xffff):
                        raw = pack(*fixture(os_name), compression=compression, descriptor=descriptor,
                                   zip64=local_zip64, comment=comment)
                        for end_zip64 in (None, False, True):
                            with self.subTest(os=os_name, method=compression, descriptor=descriptor,
                                    local_zip64=local_zip64, comment_bytes=len(comment), end_zip64=end_zip64):
                                changed = raw if end_zip64 is None else zip64_end(raw, sentinel=end_zip64)
                                for prefix in (b"", b"opaque prepended ZIP bytes"):
                                    code, result = self.invoke(prefix + changed, os_name)
                                    self.assertEqual((code, result["status"]), (0, "verified"))

    def test_zip64_end_contradictions_precede_zipfile(self):
        raw = zip64_end(pack(*fixture()))
        end = raw.rfind(b"PK\x05\x06")
        record, locator = end - 76, end - 20
        mutations = ((record, "<4s", b"XXXX"), (record + 4, "<Q", 45), (record + 14, "<H", 44),
                     (record + 16, "<I", 1), (record + 20, "<I", 1), (record + 24, "<Q", 8),
                     (record + 32, "<Q", 8), (record + 40, "<Q", 0xffffffffffffffff),
                     (record + 48, "<Q", 0xffffffffffffffff), (locator + 4, "<I", 1),
                     (locator + 8, "<Q", 0xffffffffffffffff), (locator + 16, "<I", 2),
                     (end + 8, "<H", 8), (end + 10, "<H", 8),
                     (end + 12, "<I", 1), (end + 16, "<I", 1))
        for offset, fmt, value in mutations:
            with self.subTest(offset=offset, value=value):
                changed = bytearray(raw)
                struct.pack_into(fmt, changed, offset, value)
                with mock.patch.object(checker.zipfile, "ZipFile") as constructor:
                    code, result = self.invoke(bytes(changed))
                    self.assertEqual((code, result["category"]), (2, "layout"))
                    constructor.assert_not_called()

    def test_prefixed_zip64_cannot_select_another_directory(self):
        raw = pack(*fixture(), compression=zipfile.ZIP_STORED)
        end, records = central_records(raw)
        copies = 10000
        competing_directory = records[0][1] * copies
        locator_offset = len(competing_directory)
        padding = locator_offset - end
        self.assertGreaterEqual(padding, 0)
        central_start = records[0][0]
        padded = bytearray(raw[:central_start] + b"\0" * padding + raw[central_start:])
        struct.pack_into("<I", padded, locator_offset + 16, central_start + padding)
        genuine = zip64_end(bytes(padded))
        prefix_bytes = locator_offset + 56
        competing_record = struct.pack("<4sQ2H2I4Q", b"PK\x06\x06", 44 + prefix_bytes,
                                       45, 45, 0, 0, copies, copies, locator_offset, 0)
        changed = competing_directory + competing_record + genuine
        # Older readers fall back to the genuine fixed record; modern readers
        # can interpret the relative locator as an absolute competing record.
        # Refuse that ambiguity without constructing either reader's list.
        self.assertEqual(changed[locator_offset:locator_offset + 4], b"PK\x06\x06")
        self.assertEqual(changed[-98:-94], b"PK\x06\x06")
        with mock.patch.object(checker.zipfile, "ZipFile") as constructor:
            code, result = self.invoke(changed)
            self.assertEqual((code, result["category"]), (2, "layout"))
            constructor.assert_not_called()

    def test_local_zip_metadata_rejects_contradictions(self):
        for descriptor, zip64 in ((False, False), (False, True), (True, False), (True, True)):
            for mode in ("method", "flags", "crc", "compressed_size", "original_size", "name", "signature", "name_bound", "extra_bound"):
                with self.subTest(descriptor=descriptor, zip64=zip64, mutation=mode):
                    raw = pack(*fixture(), descriptor=descriptor, zip64=zip64)
                    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                        info = archive.getinfo("zenon-spv")
                    changed = bytearray(raw)
                    start = info.header_offset
                    if mode == "method":
                        struct.pack_into("<H", changed, start + 8, 99)
                    elif mode == "flags":
                        struct.pack_into("<H", changed, start + 6, info.flag_bits | 1)
                    elif mode == "crc":
                        struct.pack_into("<I", changed, start + 14, info.CRC ^ 1)
                    elif mode == "compressed_size":
                        struct.pack_into("<I", changed, start + 18, info.compress_size + 1)
                    elif mode == "original_size":
                        struct.pack_into("<I", changed, start + 22, info.file_size + 1)
                    elif mode == "name":
                        changed[start + 30] = ord("X")
                    elif mode == "name_bound":
                        struct.pack_into("<H", changed, start + 26, 0xffff)
                    elif mode == "extra_bound":
                        struct.pack_into("<H", changed, start + 28, 0xffff)
                    else:
                        changed[start] = ord("X")
                    code, result = self.invoke(bytes(changed))
                    self.assertEqual((code, result["category"]), (2, "layout"))

    def test_data_descriptors_and_zip64_sizes_are_bound(self):
        for zip64 in (False, True):
            for unsigned in (False, True):
                for mode in ("descriptor_crc", "descriptor_compressed", "descriptor_original", "missing_descriptor"):
                    with self.subTest(zip64=zip64, unsigned=unsigned, mutation=mode):
                        raw = pack(*fixture(), descriptor=True, zip64=zip64, unsigned=unsigned)
                        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                            info = archive.getinfo("zenon-spv")
                        changed = bytearray(raw)
                        name_bytes, extra_bytes = struct.unpack_from("<HH", changed, info.header_offset + 26)
                        start = info.header_offset + 30 + name_bytes + extra_bytes + info.compress_size
                        content = start if unsigned else start + 4
                        if mode == "descriptor_crc":
                            struct.pack_into("<I", changed, content, info.CRC ^ 1)
                        elif mode == "descriptor_compressed":
                            struct.pack_into("<Q" if zip64 else "<I", changed, content + 4, info.compress_size + 1)
                        elif mode == "descriptor_original":
                            struct.pack_into("<Q" if zip64 else "<I", changed, content + (12 if zip64 else 8), info.file_size + 1)
                        else:
                            changed[start: start + 12] = b"X" * 12
                        code, result = self.invoke(bytes(changed))
                        self.assertEqual((code, result["category"]), (2, "layout"))
        for descriptor in (False, True):
            for mode in ("missing_extra", "short_extra", "original", "compressed", "duplicate_extra"):
                with self.subTest(descriptor=descriptor, mutation=mode):
                    raw = pack(*fixture(), descriptor=descriptor, zip64=True)
                    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                        info = archive.getinfo("zenon-spv")
                    changed = bytearray(raw)
                    name_bytes, extra_bytes = struct.unpack_from("<HH", changed, info.header_offset + 26)
                    start = info.header_offset + 30 + name_bytes
                    if mode == "missing_extra":
                        # Require extended sizes even when the fixture writer emits small 32-bit sizes.
                        struct.pack_into("<II", changed, info.header_offset + 18, 0xffffffff, 0xffffffff)
                        struct.pack_into("<H", changed, start, 0xffff)
                    elif mode == "short_extra":
                        struct.pack_into("<H", changed, start + 2, 8)
                    elif mode == "original":
                        struct.pack_into("<Q", changed, start + 4, info.file_size + 1)
                    elif mode == "compressed":
                        struct.pack_into("<Q", changed, start + 12, info.compress_size + 1)
                    else:
                        # Reinterpret the 16-byte size payload as two empty ZIP64 extras.
                        struct.pack_into("<H", changed, start + 2, 0)
                        struct.pack_into("<HH", changed, start + 4, 1, 0)
                    code, result = self.invoke(bytes(changed))
                    self.assertEqual((code, result["category"]), (2, "layout"))


if __name__ == "__main__":
    unittest.main()
