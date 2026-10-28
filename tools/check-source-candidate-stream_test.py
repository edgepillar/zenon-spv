#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Source-bound stream readback controls; synthetic files are not native evidence."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

sys.dont_write_bytecode = True


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


fixture = load("source_stream_fixture", "candidate_stream_test.py")
helper = load("source_stream_readback", "check-source-candidate-stream.py")
REVISION, INPUTS = fixture.original.REVISION, fixture.original.INPUTS


class SourceCandidateStreamControls(unittest.TestCase):
    def test_actual_stream_file_and_checkout_brackets_for_all_payload_platforms(self):
        for platform in ("linux", "darwin", "windows"):
            with self.subTest(platform=platform), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "candidate-v1.tar.xz"
                raw, expected, _, _ = fixture.encode(platform)
                path.write_bytes(raw)
                before = helper.exported.file_identity(path.stat())
                with mock.patch.object(helper.exported, "source_pin", return_value=INPUTS) as pin:
                    result = helper.verify(path, Path(directory), REVISION, platform, "amd64", True)
                self.assertEqual(pin.call_count, 2)
                self.assertEqual(result["source"], {"revision": REVISION, "inputs_sha256": INPUTS})
                self.assertEqual(result["verification"], expected["verification"])
                self.assertEqual(result["payload"], {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
                self.assertEqual((result["os"], result["architecture"]), (platform, "amd64"))
                self.assertEqual(before, helper.exported.file_identity(path.stat()))
                self.assertEqual(path.read_bytes(), raw)
                self.assertEqual(set(Path(directory).iterdir()), {path})

    def test_source_preflight_refuses_before_opening_the_payload(self):
        with mock.patch.object(helper.exported, "source_pin", side_effect=helper.checker.Rejected("source")), \
                mock.patch.object(helper.exported, "regular_file") as opened:
            with self.assertRaises(helper.checker.Rejected):
                helper.verify(Path("PRIVATE"), Path("PRIVATE"), REVISION, "linux", "amd64", True)
        opened.assert_not_called()

    def test_changed_checkout_after_decode_prevents_success(self):
        raw, _, _, _ = fixture.encode()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "selected"
            path.write_bytes(raw)
            with mock.patch.object(helper.exported, "source_pin", side_effect=[INPUTS, "a" * 64]), \
                    self.assertRaises(helper.checker.Rejected) as failure:
                helper.verify(path, Path(directory), REVISION, "linux", "amd64", True)
            self.assertEqual(failure.exception.category, "source")

    def test_selected_revision_inputs_platform_and_architecture_are_required(self):
        raw, _, _, _ = fixture.encode()
        controls = (("a" * 40, INPUTS, "linux", "amd64"),
                    (REVISION, "a" * 64, "linux", "amd64"),
                    (REVISION, INPUTS, "darwin", "amd64"),
                    (REVISION, INPUTS, "linux", "arm64"))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "selected"
            path.write_bytes(raw)
            for revision, inputs, platform, architecture in controls:
                with self.subTest(control=(revision, inputs, platform, architecture)), \
                        mock.patch.object(helper.exported, "source_pin", return_value=inputs), \
                        self.assertRaises(helper.checker.Rejected):
                    helper.verify(path, Path(directory), revision, platform, architecture, True)

    def test_full_stream_end_and_raw_layout_are_required(self):
        raw, _, _, _ = fixture.encode()
        legacy, _, _, _, _ = fixture.fixture()
        for changed in (b"", raw[:-1], raw + b"x", raw + raw, legacy, fixture.envelope(raw)):
            with self.subTest(size=len(changed)), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "selected"
                path.write_bytes(changed)
                with mock.patch.object(helper.exported, "source_pin", return_value=INPUTS), \
                        self.assertRaises(helper.checker.Rejected):
                    helper.verify(path, Path(directory), REVISION, "linux", "amd64", True)

    def test_complete_skip_ledger_remains_required_when_selected(self):
        raw, _, _, _ = fixture.encode(complete=False)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "selected"
            path.write_bytes(raw)
            with mock.patch.object(helper.exported, "source_pin", return_value=INPUTS), \
                    self.assertRaises(helper.checker.Rejected):
                helper.verify(path, Path(directory), REVISION, "linux", "amd64", True)

    def test_path_identity_change_after_decode_is_refused(self):
        raw, _, _, _ = fixture.encode()
        read = helper.checker.check_stream_payload
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "selected"
            path.write_bytes(raw)
            changed = False
            lstat = Path.lstat
            def replace(*args, **kwargs):
                nonlocal changed
                result = read(*args, **kwargs)
                changed = True
                return result
            def observed(selected, *args, **kwargs):
                info = lstat(selected, *args, **kwargs)
                if selected == path and changed:
                    # A portable path observation needs no OS delete-sharing assumption.
                    values = {name: getattr(info, name) for name in
                              ("st_dev", "st_ino", "st_mode", "st_nlink", "st_size",
                               "st_mtime_ns", "st_ctime_ns")}
                    values["st_ino"] += 1
                    return SimpleNamespace(**values)
                return info
            with mock.patch.object(helper.exported, "source_pin", return_value=INPUTS), \
                    mock.patch.object(Path, "lstat", observed), \
                    mock.patch.object(helper.checker, "check_stream_payload", side_effect=replace), \
                    self.assertRaises(helper.checker.Rejected) as failure:
                helper.verify(path, Path(directory), REVISION, "linux", "amd64", True)
            self.assertEqual(failure.exception.category, "archive")
            self.assertEqual(path.read_bytes(), raw)

    def test_growth_after_hash_is_not_accepted_as_the_hashed_stream(self):
        raw, _, _, _ = fixture.encode()
        hash_file = helper.checker.file_hash
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "selected"
            path.write_bytes(raw)
            def grow(source):
                digest = hash_file(source)
                with path.open("ab") as destination:
                    destination.write(b"x")
                return digest
            with mock.patch.object(helper.exported, "source_pin", return_value=INPUTS), \
                    mock.patch.object(helper.checker, "file_hash", side_effect=grow), \
                    self.assertRaises(helper.checker.Rejected):
                helper.verify(path, Path(directory), REVISION, "linux", "amd64", True)

    def test_boolean_skip_option_is_not_coerced(self):
        for value in (None, 0, 1, "true"):
            with self.subTest(value=value), mock.patch.object(helper.exported, "source_pin") as pin, \
                    self.assertRaises(helper.checker.Rejected):
                helper.verify(Path("PRIVATE"), Path("PRIVATE"), REVISION, "linux", "amd64", value)
            pin.assert_not_called()

    def test_cli_emits_only_the_selected_source_and_payload_receipt(self):
        raw, _, _, _ = fixture.encode()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "PRIVATE_candidate.tar.xz"
            path.write_bytes(raw)
            output = io.StringIO()
            with mock.patch.object(helper.exported, "source_pin", return_value=INPUTS):
                code = helper.main(["--archive", str(path), "--expect-revision", REVISION,
                                    "--expect-os", "linux", "--expect-architecture", "amd64",
                                    "--require-skip-ledger"], output)
            self.assertEqual(code, 0)
            result = json.loads(output.getvalue())
            self.assertEqual((result["status"], result["verification"]["binaries"]), ("verified", 7))
            self.assertEqual(result["payload"]["sha256"], hashlib.sha256(raw).hexdigest())
            self.assertNotIn("PRIVATE", output.getvalue())
            self.assertNotIn(directory, output.getvalue())

    def test_cli_argument_refusals_precede_input_access_and_do_not_echo(self):
        args = ["--archive", "PRIVATE", "--expect-revision", REVISION,
                "--expect-os", "linux", "--expect-architecture", "amd64"]
        for extra in (("--archive", "PRIVATE"), ("--expect-os", "linux"),
                      ("--unknown", "PRIVATE"), ("--require-skip-ledger", "--require-skip-ledger"),
                      ("--require-skip-ledger=true",)):
            with self.subTest(extra=extra), mock.patch.object(helper, "verify") as read:
                output = io.StringIO()
                self.assertEqual(helper.main(args + list(extra), output), 64)
                self.assertEqual(json.loads(output.getvalue())["category"], "arguments")
                self.assertNotIn("PRIVATE", output.getvalue())
                read.assert_not_called()

    def test_cli_failed_input_and_changed_source_never_echo_private_details(self):
        args = ["--archive", "PRIVATE", "--expect-revision", REVISION,
                "--expect-os", "linux", "--expect-architecture", "amd64"]
        for failure in (OSError("PRIVATE path"), helper.checker.Rejected("source"), KeyboardInterrupt()):
            with self.subTest(kind=type(failure).__name__), mock.patch.object(helper, "verify", side_effect=failure):
                output = io.StringIO()
                self.assertEqual(helper.main(args, output), 2)
                self.assertEqual(json.loads(output.getvalue())["status"], "refused")
                self.assertNotIn("PRIVATE", output.getvalue())

    def test_cli_delivery_failure_cannot_report_success(self):
        class Short(io.StringIO):
            def write(self, raw):
                super().write(raw)
                return len(raw) - 1
        class Failed(io.StringIO):
            def write(self, raw):
                raise OSError("PRIVATE output")
        class FlushFailed(io.StringIO):
            def flush(self):
                raise OSError("PRIVATE flush")
        args = ["--archive", "PRIVATE", "--expect-revision", REVISION,
                "--expect-os", "linux", "--expect-architecture", "amd64"]
        for output in (Short(), Failed(), FlushFailed()):
            with self.subTest(kind=type(output).__name__), \
                    mock.patch.object(helper, "verify", return_value={"status": "verified"}):
                self.assertEqual(helper.main(args, output), 70)


if __name__ == "__main__":
    unittest.main()
