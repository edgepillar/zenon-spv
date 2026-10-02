"""Adversarial byte/layout checks; fixtures are not executable or network evidence."""

import copy
import hashlib
import importlib.util
import io
import json
import stat
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
    manifest = {"schema_version": 1, "mode": "offline_synthetic_candidate", "test_status": "passed",
                "os": os_name, "architecture": "amd64", "go_version": "go1.25.14",
                "source": source, "corpus": corpus, "report": {}, "binaries": binaries}
    return files, manifest, report


def pack(files, manifest, report, mutate_manifest=None, mutate_raw=None, extra=None):
    manifest = copy.deepcopy(manifest)
    raw_report = json.dumps(report).encode()
    manifest["report"] = {"filename": "offline-pilot.json", "sha256": sha(raw_report), "bytes": len(raw_report)}
    if mutate_manifest:
        mutate_manifest(manifest)
    raw_manifest = json.dumps(manifest).encode()
    if mutate_raw:
        raw_manifest = mutate_raw(raw_manifest)
    stream = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for filename, raw in files.items():
                archive.writestr(filename, raw)
            archive.writestr("manifest.json", raw_manifest)
            archive.writestr("offline-pilot.json", raw_report)
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
                    report["cases"][0]["binaries"].pop()
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


if __name__ == "__main__":
    unittest.main()
