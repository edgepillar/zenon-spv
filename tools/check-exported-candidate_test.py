"""CI export controls use opaque bytes; they are not network or execution evidence."""

import hashlib
import importlib.util
import io
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

spec = importlib.util.spec_from_file_location("export_check", Path(__file__).with_name("check-exported-candidate.py"))
export = importlib.util.module_from_spec(spec)
spec.loader.exec_module(export)
spec = importlib.util.spec_from_file_location("archive_fixtures", Path(__file__).with_name("check-candidate-archive_test.py"))
fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixtures)


def source_fixture(root):
    for name in ("cmd", "internal", "tools"):
        (root / name).mkdir()
    values = {"go.mod": b"module github.com/0x3639/zenon-spv\n", "go.sum": b"",
              "cmd/small.go": b"package main\n", "internal/facts.json": b"{}\n"}
    for name, raw in values.items():
        (root / name).write_bytes(raw)
    return values


def candidate_fixture(root, os_name):
    files, manifest, report = fixtures.fixture(os_name)
    if os_name == "windows":
        report["status"] = manifest["test_status"] = "passed_with_skips"
        report["cases"][0].update(status="passed_with_skips", skipped_subtests=1)
    raw = json.dumps(report).encode()
    manifest["report"] = {"filename": "offline-pilot.json", "bytes": len(raw),
                          "sha256": hashlib.sha256(raw).hexdigest()}
    files.update({"offline-pilot.json": raw, "manifest.json": json.dumps(manifest).encode()})
    for name, raw in files.items():
        (root / name).write_bytes(raw)


class ExportCheckTests(unittest.TestCase):
    def invoke(self, root, os_name="linux", replace=None, extra=(), source_effect=None, output=None):
        args = {"directory": str(root), "expect-revision": fixtures.REVISION,
                "expect-os": os_name, "expect-architecture": "amd64"}
        args.update(replace or {})
        output = io.StringIO() if output is None else output
        with mock.patch.object(export, "source_pin", return_value=fixtures.INPUTS, side_effect=source_effect):
            code = export.main([v for k, v in args.items() for v in ("--" + k, v)] + list(extra), output)
        if isinstance(output, io.StringIO):
            self.assertNotIn("PRIVATE", output.getvalue())
            self.assertNotIn(str(root), output.getvalue())
            return code, json.loads(output.getvalue())
        return code, None

    def test_complete_native_exports_are_checked_without_execution_or_replacement(self):
        for os_name in ("linux", "darwin", "windows"):
            with self.subTest(os=os_name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                candidate_fixture(root, os_name)
                before = {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in root.iterdir()}
                with mock.patch.object(subprocess, "run", side_effect=AssertionError("payload execution forbidden")):
                    code, result = self.invoke(root, os_name)
                self.assertEqual(code, 0)
                self.assertEqual(result["binaries"], 7)
                self.assertEqual(result["skipped_subtests"], 1 if os_name == "windows" else 0)
                self.assertEqual({p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in root.iterdir()}, before)

    def test_incomplete_additional_and_changed_payloads_fail(self):
        for mode in ("missing", "extra", "empty", "changed", "size"):
            with self.subTest(control=mode), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                candidate_fixture(root, "linux")
                if mode == "missing":
                    (root / "zenon-spv").unlink()
                elif mode == "extra":
                    (root / "PRIVATE_EXTRA").write_bytes(b"extra")
                elif mode in ("empty", "changed"):
                    (root / "zenon-spv").write_bytes(b"" if mode == "empty" else b"changed")
                else:
                    with (root / "manifest.json").open("wb") as stream:
                        stream.truncate((256 << 10) + 1)
                code, result = self.invoke(root)
                self.assertEqual(code, 2)
                self.assertEqual(result["status"], "rejected")

    def test_revision_platform_and_source_drift_fail(self):
        for mode in ("revision", "platform", "inputs", "drift"):
            with self.subTest(control=mode), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                candidate_fixture(root, "linux")
                replace = {"expect-revision": "d" * 40} if mode == "revision" else {}
                if mode == "platform":
                    replace["expect-architecture"] = "arm64"
                effect = ["d" * 64] if mode == "inputs" else ([fixtures.INPUTS, "d" * 64] if mode == "drift" else None)
                code, result = self.invoke(root, replace=replace, source_effect=effect)
                self.assertEqual(code, 2)
                self.assertEqual(result["status"], "rejected")

    def test_an_unsupported_report_package_prevents_upload_acceptance(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            candidate_fixture(root, "linux")
            report = json.loads((root / "offline-pilot.json").read_bytes())
            report["cases"].append({"id": "unsupported_package", "package": "tools/PRIVATE_UNSUPPORTED",
                "test": "TestUnsupported", "status": "passed", "passed_subtests": 1,
                "skipped_subtests": 0, "failed_subtests": 0, "binaries": []})
            raw = json.dumps(report).encode()
            (root / "offline-pilot.json").write_bytes(raw)
            manifest = json.loads((root / "manifest.json").read_bytes())
            manifest["report"].update(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
            (root / "manifest.json").write_text(json.dumps(manifest))
            code, result = self.invoke(root)
            self.assertEqual(code, 2)
            self.assertEqual(result["category"], "metadata")

    def test_invalid_arguments_precede_source_access_and_do_not_echo(self):
        with tempfile.TemporaryDirectory() as directory:
            for replace, extra in (({"expect-revision": "PRIVATE_REVISION"}, ()),
                                   ({"expect-os": "PRIVATE_PLATFORM"}, ()),
                                   ({}, ("--directory", "PRIVATE_DIRECTORY")),
                                   ({}, ("--PRIVATE_OPTION",))):
                with self.subTest(arguments=bool(extra)), mock.patch.object(export, "verify") as verify:
                    code, result = self.invoke(Path(directory), replace=replace, extra=extra)
                    self.assertEqual(code, 64)
                    self.assertEqual(result["category"], "arguments")
                    verify.assert_not_called()

    def test_delivery_failure_has_a_nonzero_exit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            candidate_fixture(root, "linux")
            output = mock.Mock()
            output.write.side_effect = OSError("PRIVATE_OUTPUT")
            self.assertEqual(self.invoke(root, output=output)[0], 70)

    def test_source_fingerprint_matches_fixed_length_prefixed_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_fixture(root)
            # Fixed wire vector; changing order, widths or zero-length inputs changes it.
            wire = (b"\0\0\0\0\0\0\0\x0ccmd/small.go\0\0\0\0\0\0\0\x0dpackage main\n"
                    b"\0\0\0\0\0\0\0\x06go.mod\0\0\0\0\0\0\0\x23module github.com/0x3639/zenon-spv\n"
                    b"\0\0\0\0\0\0\0\x06go.sum\0\0\0\0\0\0\0\0"
                    b"\0\0\0\0\0\0\0\x13internal/facts.json\0\0\0\0\0\0\0\x03{}\n")
            self.assertEqual(export.input_fingerprint(root), hashlib.sha256(wire).hexdigest())
            (root / "tools" / "ignored.py").write_bytes(b"outside the Go input fingerprint")
            self.assertEqual(export.input_fingerprint(root), hashlib.sha256(wire).hexdigest())
            (root / "cmd" / ".go").write_bytes(b"x")
            hidden = b"\0\0\0\0\0\0\0\x07cmd/.go\0\0\0\0\0\0\0\x01x"
            self.assertEqual(export.input_fingerprint(root), hashlib.sha256(hidden + wire).hexdigest())
            (root / "internal" / "facts.json").write_bytes(b"changed\n")
            self.assertNotEqual(export.input_fingerprint(root), hashlib.sha256(wire).hexdigest())

    def test_source_type_entry_and_byte_bounds(self):
        for mode in ("missing", "module", "extra_cr", "directory", "bytes", "entries", "depth"):
            with self.subTest(control=mode), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source_fixture(root)
                if mode == "missing":
                    (root / "go.sum").unlink()
                elif mode == "module":
                    (root / "go.mod").write_bytes(b"PRIVATE_MODULE\n")
                elif mode == "extra_cr":
                    (root / "go.mod").write_bytes(b"module github.com/0x3639/zenon-spv\r\r\n")
                elif mode == "directory":
                    (root / "go.sum").unlink()
                    (root / "go.sum").mkdir()
                elif mode == "bytes":
                    (root / "internal" / "facts.json").write_bytes(b"x" * 128)
                elif mode == "depth":
                    parent = root / "tools"
                    for _ in range(33):
                        parent = parent / "nested"
                        parent.mkdir()
                context = mock.patch.object(export, "SOURCE_ENTRIES", 1) if mode == "entries" else mock.patch.object(export, "SOURCE_LIMIT", 128)
                with context, self.assertRaises((export.checker.Rejected, OSError)):
                    export.input_fingerprint(root)

    def test_source_symlinks_are_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_fixture(root)
            try:
                (root / "tools" / "link.py").symlink_to(root / "go.mod")
            except (OSError, NotImplementedError):
                self.skipTest("source symlink creation is unavailable")
            with self.assertRaises(export.checker.Rejected):
                export.input_fingerprint(root)

    def test_opened_size_mismatch_is_refused_and_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            selected, replacement = root / "selected", root / "replacement"
            selected.write_bytes(b"one")
            replacement.write_bytes(b"longer")
            descriptor = os.open(replacement, os.O_RDONLY)
            with mock.patch.object(export.os, "open", return_value=descriptor), self.assertRaises(export.checker.Rejected):
                with export.regular_file(selected, 32, "export"):
                    self.fail("replaced descriptor was consumed")
            with self.assertRaises(OSError):
                os.fstat(descriptor)

    def test_git_root_head_cleanliness_and_environment_are_checked(self):
        for mode in ("clean", "root", "head", "dirty"):
            with self.subTest(control=mode), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source_fixture(root)
                responses = [str(root if mode != "root" else root / "PRIVATE_OTHER").encode(),
                             (fixtures.REVISION if mode != "head" else "d" * 40).encode(),
                             b"?? PRIVATE_CHANGE\n" if mode == "dirty" else b""]
                with mock.patch.dict(os.environ, {"GIT_DIR": "PRIVATE_GIT", "git_work_tree": "PRIVATE_TREE"}), mock.patch.object(
                        export.subprocess, "run", side_effect=[SimpleNamespace(stdout=raw) for raw in responses]) as git:
                    if mode == "clean":
                        self.assertEqual(export.source_pin(root, fixtures.REVISION), export.input_fingerprint(root))
                    else:
                        with self.assertRaises(export.checker.Rejected):
                            export.source_pin(root, fixtures.REVISION)
                    for call in git.call_args_list:
                        self.assertFalse(any(k.upper().startswith("GIT_") for k in call.kwargs["env"]))


if __name__ == "__main__":
    unittest.main()
