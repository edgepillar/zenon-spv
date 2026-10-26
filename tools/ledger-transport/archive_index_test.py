#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Finite literal ZIP directory controls; no archive download or payload files."""
import copy
import hashlib
import importlib.util
import io
import json
import struct
import subprocess
import sys
import unittest
import zipfile
from pathlib import Path


HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("archive_directory_under_test", HERE / "archive_index.py")
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def selected(raw, archive_bytes=None):
    return {"archive_bytes": len(raw) if archive_bytes is None else archive_bytes,
            "archive_sha256": "ab" * 32, "tail_bytes": len(raw), "tail_sha256": sha(raw)}


def entry(name=b"backup/nom.bak/000001.ldb", *, packed=4, unpacked=8, offset=0,
          external=0o100600 << 16, flags=0, method=8, extra=b"", disk=0):
    return struct.pack("<4s6H3I5H2I", b"PK\x01\x02", 0x32d, 45, flags, method, 0, 0,
                       0x12345678, packed, unpacked, len(name), len(extra), 0,
                       disk, 0, external, offset) + name + extra


def envelope(directory, *, count=1, offset=1 << 33, zip64=True, comment=b""):
    # A logical >4 GiB prefix is never allocated or read by the test.
    if zip64:
        end = struct.pack("<4sQ2H2I4Q", b"PK\x06\x06", 44, 45, 45, 0, 0,
                          count, count, len(directory), offset)
        end += struct.pack("<4sIQI", b"PK\x06\x07", 0, offset + len(directory), 1)
        end += struct.pack("<4s4H2IH", b"PK\x05\x06", 0, 0, count, count,
                           len(directory), 0xffffffff, len(comment)) + comment
    else:
        end = struct.pack("<4s4H2IH", b"PK\x05\x06", 0, 0, count, count,
                          len(directory), offset, len(comment)) + comment
    raw = directory + end
    return raw, selected(raw, offset + len(raw))


class Fragmented:
    def __init__(self, raw, fragment=23):
        self.raw, self.fragment, self.position, self.requests = raw, fragment, 0, []

    def read(self, size):
        assert 0 < size <= 65536
        self.requests.append(size)
        part = self.raw[self.position:self.position + min(size, self.fragment)]
        self.position += len(part)
        return part


class ArchiveIndexTests(unittest.TestCase):
    def check(self, raw, selection=None, limits=None):
        return tool.observe(io.BytesIO(raw), selection or selected(raw), limits)

    def refuse(self, raw, reason=None, selection=None, limits=None):
        with self.assertRaises(tool.Refused) as caught:
            self.check(raw, selection, limits)
        if reason is not None:
            self.assertEqual(str(caught.exception), reason)
        self.assertNotIn("backup/", str(caught.exception))

    def test_zip64_directory_without_payload(self):
        directory = entry() + entry(b"backup/nom.bak/", packed=0, unpacked=0,
                                    offset=50, external=(0o40700 << 16) | 16, method=0)
        raw, pin = envelope(directory, count=2)
        report = self.check(raw, pin)
        self.assertEqual(report["status"], "SELECTED_DIRECTORY_OBSERVED")
        self.assertEqual(report["directory"], {"format": "ZIP64", "offset": 1 << 33, "bytes": len(directory)})
        expected = {"members": 2, "files": 1, "directories": 1, "compressed_bytes": 4,
                    "unpacked_bytes": 8, "largest_file_bytes": 8, "ldb": 1, "log": 0, "manifests": 0}
        self.assertEqual(report["totals"], expected)
        self.assertEqual(report["groups"], {"backup/nom.bak": expected})
        self.assertEqual(report["selection"], pin)
        self.assertTrue(report["scope"])
        self.assertTrue(all(value is False for value in report["scope"].values()))

    def test_standard_library_zip_and_empty_zip(self):
        for count in (0, 3):
            with self.subTest(count=count):
                stream = io.BytesIO()
                with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                    for index in range(count):
                        archive.writestr("backup/nom.bak/" + str(index) + ".log", b"finite")
                raw = stream.getvalue()
                result = self.check(raw)
                self.assertEqual(result["totals"]["files"], count)
                self.assertEqual(result["totals"]["unpacked_bytes"], count * 6)
                self.assertEqual(result["directory"]["format"], "ZIP")

    def test_fragmented_reads_and_exact_eof(self):
        raw, pin = envelope(entry(), comment=b"complete comment")
        fragmented = Fragmented(raw)
        self.assertEqual(tool.observe(fragmented, pin), self.check(raw, pin))
        self.assertGreater(len(fragmented.requests), 2)
        self.refuse(raw + b"x", "TRAILING_DATA", pin)
        self.refuse(raw[:-1], "TAIL_READ", pin)
        changed = bytearray(raw)
        changed[10] ^= 1
        self.refuse(bytes(changed), "TAIL_DIGEST", pin)

    def test_selection_and_limits_refuse_before_read(self):
        class NoRead:
            def read(self, size):
                raise AssertionError("must refuse before read")
        raw, pin = envelope(entry())
        for key, value in (("archive_bytes", True), ("archive_bytes", 1 << 41),
                           ("tail_bytes", 21), ("tail_bytes", (4 << 20) + 1),
                           ("archive_sha256", "AB" * 32), ("tail_sha256", "x")):
            with self.subTest(key=key, value=value):
                changed = dict(pin, **{key: value})
                with self.assertRaises(tool.Refused):
                    tool.observe(NoRead(), changed)
        for limits in (dict(tool.DEFAULT_LIMITS, members=True),
                       dict(tool.DEFAULT_LIMITS, members=16385), {}, None):
            if limits is None:
                with self.assertRaises(tool.Refused):
                    tool.observe(NoRead(), {**pin, "unexpected": False})
            else:
                with self.assertRaises(tool.Refused):
                    tool.observe(NoRead(), pin, limits)

    def test_selection_is_frozen_before_input(self):
        raw, pin = envelope(entry())
        original = copy.deepcopy(pin)
        limits = dict(tool.DEFAULT_LIMITS)
        class Mutating(Fragmented):
            def read(self, size):
                pin["archive_sha256"] = "cd" * 32
                limits["file_bytes"] = 1
                return super().read(size)
        result = tool.observe(Mutating(raw), pin, limits)
        self.assertEqual(result["selection"], original)
        self.assertEqual(result["limits"], tool.DEFAULT_LIMITS)

    def test_directory_limits_and_count_disagreement(self):
        raw, pin = envelope(entry(unpacked=17))
        self.refuse(raw, "FILE_BYTES", pin, dict(tool.DEFAULT_LIMITS, file_bytes=16))
        self.refuse(raw, "UNPACKED_BYTES", pin, dict(tool.DEFAULT_LIMITS, unpacked_bytes=16))
        for directory, count in ((entry(), 0), (entry(), 2), (entry() + b"x", 1)):
            with self.subTest(count=count, length=len(directory)):
                raw, pin = envelope(directory, count=count)
                self.refuse(raw, selection=pin)
        raw, pin = envelope(entry(), count=10001)
        self.refuse(raw, "MEMBER_LIMIT", pin)

    def test_partial_directory_and_end_record(self):
        raw, pin = envelope(entry())
        for tail in (raw[1:], raw[:-1], b"x" * 100):
            with self.subTest(length=len(tail)):
                self.refuse(tail, selection=selected(tail, pin["archive_bytes"]))
        # ZIP64 end record, locator and EOCD must be adjacent and agree.
        for position in (len(entry()) + 4, len(raw) - 36, len(raw) - 18, len(raw) - 12):
            with self.subTest(position=position):
                changed = bytearray(raw)
                changed[position] ^= 1
                self.refuse(bytes(changed), selection=selected(changed, pin["archive_bytes"]))

    def test_ambiguous_end_record_refuses(self):
        raw, pin = envelope(entry(), zip64=False, offset=1024)
        fake = struct.pack("<4s4H2IH", b"PK\x05\x06", 0, 0, 0, 0, 0, 0, 0)
        changed = raw[:-2] + struct.pack("<H", len(fake)) + fake
        self.refuse(changed, "END_RECORD", selected(changed, pin["archive_bytes"] + len(fake)))

    def test_paths_aliases_and_member_types(self):
        for name in (b"../private", b"/absolute", b"a//b", b"a/./b", b"a/../b",
                     b"C:/file", b"a\\b", b"a\x00b", b"a\nb", b"x" * 513):
            with self.subTest(name=name):
                raw, pin = envelope(entry(name))
                self.refuse(raw, "MEMBER_NAME", pin)
        for second in (b"BACKUP/nom.bak/000001.ldb", b"backup/nom.bak/000001.ldb/"):
            raw, pin = envelope(entry() + entry(second, offset=100), count=2)
            self.refuse(raw, "MEMBER_ALIAS", pin)
        for mode in (0o120700, 0o010600, 0o060600, 0o040700):
            raw, pin = envelope(entry(external=mode << 16))
            self.refuse(raw, "MEMBER_TYPE", pin)
        raw, pin = envelope(entry(b"a", offset=0) + entry(b"a/file", offset=100), count=2)
        self.refuse(raw, "MEMBER_ALIAS", pin)

    def test_unicode_aliases_and_bad_utf8(self):
        first = entry("backup/caf\u00e9/file".encode(), flags=2048)
        second = entry("backup/cafe\u0301/file".encode(), flags=2048, offset=100)
        raw, pin = envelope(first + second, count=2)
        self.refuse(raw, "MEMBER_ALIAS", pin)
        raw, pin = envelope(entry(b"bad\xffname", flags=2048))
        self.refuse(raw, "MEMBER_NAME", pin)

    def test_encoding_offsets_and_directory_payload(self):
        for arguments, reason in (({"flags": 1}, "MEMBER_ENCODING"),
                                  ({"method": 12}, "MEMBER_ENCODING"),
                                  ({"method": 0}, "FILE_BYTES"),
                                  ({"offset": 0xfffffffe}, "MEMBER_OFFSET"),
                                  ({"disk": 1}, "MULTI_DISK"),
                                  ({"extra": b"\x02"}, "EXTRA_FIELD")):
            with self.subTest(arguments=arguments):
                raw, pin = envelope(entry(**arguments), offset=1024)
                self.refuse(raw, reason, pin)
        raw, pin = envelope(entry(b"backup/nom.bak/", external=(0o40700 << 16) | 16))
        self.refuse(raw, "DIRECTORY_PAYLOAD", pin)
        raw, pin = envelope(entry() + entry(b"backup/nom.bak/second.ldb"), count=2)
        self.refuse(raw, "MEMBER_OFFSET", pin)

    def test_zip64_extra_values(self):
        extra = struct.pack("<HHQQQ", 1, 24, 1 << 32, 1 << 31, 1 << 32)
        raw, pin = envelope(entry(unpacked=0xffffffff, packed=0xffffffff, offset=0xffffffff, extra=extra))
        result = self.check(raw, pin)
        self.assertEqual(result["totals"]["unpacked_bytes"], 1 << 32)
        self.assertEqual(result["totals"]["compressed_bytes"], 1 << 31)
        for extra in (b"", b"\x01\x00\x00\x00", extra[:-1], extra + extra):
            with self.subTest(length=len(extra)):
                raw, pin = envelope(entry(unpacked=0xffffffff, packed=0xffffffff, offset=0xffffffff, extra=extra))
                self.refuse(raw, selection=pin)

    def test_group_limit(self):
        directory = b"".join(entry(("backup/part" + str(i) + "/x").encode(), offset=i * 100)
                             for i in range(65))
        raw, pin = envelope(directory, count=65)
        self.refuse(raw, "GROUP_LIMIT", pin)

    def test_report_size_cap(self):
        directory = b"".join(entry((b"backup/" + str(i).encode() + b"_" + bytes([128 + i]) * 240 + b"/x"), offset=i * 600)
                             for i in range(64))
        raw, pin = envelope(directory, count=64)
        self.refuse(raw, "REPORT_BYTES", pin)

    def test_ten_thousand_members_no_payload_allocation(self):
        directory = b"".join(entry(("backup/nom.bak/%06d.ldb" % i).encode(), offset=i * 100)
                             for i in range(10000))
        raw, pin = envelope(directory, count=10000)
        reader = Fragmented(raw, fragment=65536)
        result = tool.observe(reader, pin)
        self.assertEqual(result["totals"]["members"], 10000)
        self.assertEqual(result["totals"]["unpacked_bytes"], 80000)
        self.assertLess(len(tool.json_bytes(result)), 8192)
        self.assertLessEqual(max(reader.requests), 65536)

    def test_cli_success_help_failure_and_option_bounds(self):
        raw, pin = envelope(entry())
        command = [sys.executable, "-I", "-B", str(HERE / "archive_index.py")]
        args = [item for key, value in pin.items() for item in ("--" + key.replace("_", "-"), str(value))]
        run = subprocess.run(command + args, input=raw, capture_output=True, timeout=10)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(json.loads(run.stdout), self.check(raw, pin))
        for options, data, status in ((["--help"], b"", 0), ([], b"", 64),
                                      (args + ["--tail-bytes", "1"], b"", 64),
                                      (args, raw[:-1], 2), (args, raw + b"x", 2)):
            with self.subTest(options=options[-2:], status=status):
                failed = subprocess.run(command + options, input=data, capture_output=True, timeout=10)
                self.assertEqual(failed.returncode, status, failed.stderr)
                self.assertEqual(json.loads(failed.stdout)["status"], "UNKNOWN")

    def test_input_failures_and_output_failure(self):
        raw, pin = envelope(entry())
        args = [item for key, value in pin.items() for item in ("--" + key.replace("_", "-"), str(value))]
        for error, status in ((OSError(), 70), (KeyboardInterrupt(), 130)):
            class Failed:
                def read(self, size):
                    raise error
            output = io.BytesIO()
            self.assertEqual(tool.main(args, Failed(), output, io.StringIO()), status)
            self.assertEqual(json.loads(output.getvalue())["status"], "UNKNOWN")
        class Broken:
            def write(self, value):
                raise BrokenPipeError()
        with self.assertRaises(BrokenPipeError):
            tool.main(args, io.BytesIO(raw), Broken(), io.StringIO())
        class Short:
            def write(self, value):
                return len(value) - 1
        with self.assertRaises(OSError):
            tool.main(args, io.BytesIO(raw), Short(), io.StringIO())
        class BadFlush(io.BytesIO):
            def flush(self):
                raise OSError()
        with self.assertRaises(OSError):
            tool.main(args, io.BytesIO(raw), BadFlush(), io.StringIO())


class RecordingResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.roots, self.subtests = [], {"passed": 0, "failed": 0}

    def addSuccess(self, test):
        super().addSuccess(test)
        self.roots.append({"name": test._testMethodName, "status": "PASS"})

    def addSubTest(self, test, subtest, error):
        super().addSubTest(test, subtest, error)
        self.subtests["passed" if error is None else "failed"] += 1


def run_tests(args):
    destination = None
    if args:
        if len(args) != 2 or args[0] != "--report":
            raise SystemExit("expected optional --report PATH")
        destination = Path(args[1])
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(ArchiveIndexTests)
    selected_roots = [test._testMethodName for test in suite]
    result = unittest.TextTestRunner(verbosity=2, resultclass=RecordingResult).run(suite)
    report = {"format": "zenon-r1-archive-index-tests/v1", "passed": result.wasSuccessful(),
              "selected_roots": selected_roots, "roots": result.roots, "tests_run": result.testsRun,
              "failures": len(result.failures), "errors": len(result.errors),
              "skips": [{"name": test._testMethodName, "reason": reason} for test, reason in result.skipped],
              "subtests": result.subtests, "real_R1_dataset_used": False,
              "archive_payloads_opened": False, "state_value_acceptance_enabled": False}
    raw = tool.json_bytes(report)
    if destination is not None:
        with destination.open("xb") as output:
            output.write(raw)
    sys.stdout.buffer.write(raw)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(run_tests(sys.argv[1:]))
