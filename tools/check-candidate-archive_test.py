"""Adversarial byte/layout checks; fixtures are not executable or network evidence."""

import copy
import hashlib
import importlib.util
import io
import json
import stat
import struct
import sys
import tempfile
import unittest
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
    manifest = {"schema_version": 1, "mode": "offline_synthetic_candidate", "test_status": "passed",
                "os": os_name, "architecture": "amd64", "go_version": "go1.25.14",
                "source": source, "corpus": corpus, "report": {}, "binaries": binaries}
    return files, manifest, report


def pack(files, manifest, report, mutate_manifest=None, mutate_raw=None, extra=None,
         compression=zipfile.ZIP_DEFLATED, descriptor=False, zip64=False, unsigned=False):
    manifest = copy.deepcopy(manifest)
    raw_report = json.dumps(report).encode()
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
            for filename, raw in list(files.items()) + [("manifest.json", raw_manifest), ("offline-pilot.json", raw_report)]:
                if zip64:
                    with archive.open(filename, "w", force_zip64=True) as entry:
                        entry.write(raw)
                else:
                    archive.writestr(filename, raw)
            if extra:
                archive.writestr(*extra)
    return stream.getvalue()


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
                        report["cases"].pop()
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
