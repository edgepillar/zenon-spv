#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Actual bounded-child controls using isolated non-secret fixtures."""
import importlib.util
import io
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("observer_eof_preparation", HERE / "prepare.py")
P = importlib.util.module_from_spec(spec)
spec.loader.exec_module(P)
spec = importlib.util.spec_from_file_location("observer_eof_runner", HERE / "run.py")
C = importlib.util.module_from_spec(spec)
with mock.patch.dict(sys.modules, {"prepare": P}):
    spec.loader.exec_module(C)


class CaptureTests(unittest.TestCase):
    def capture(self, program, timeout=5, out_limit=4096, err_limit=4096):
        with tempfile.TemporaryDirectory() as directory:
            raw_out, raw_err = io.BytesIO(), io.BytesIO()
            stdout, stderr = io.TextIOWrapper(raw_out), io.TextIOWrapper(raw_err)
            with mock.patch.object(C.sys, "stdout", stdout), mock.patch.object(C.sys, "stderr", stderr):
                receipt = C.capture([sys.executable, "-I", "-B", "-c", program], directory, os.environ.copy(),
                                    timeout, out_limit, err_limit)
            stdout.flush()
            stderr.flush()
            return receipt, raw_out.getvalue(), raw_err.getvalue()

    def test_complete_streams_and_actual_exit(self):
        r, out, err = self.capture("import os;os.write(1,b'abc');os.write(2,b'defg')")
        self.assertEqual(r["actual_exit"], 0)
        self.assertTrue(r["output_complete"])
        self.assertTrue(r["copy_threads_joined"])
        self.assertEqual((r["stdout"]["bytes"], r["stderr"]["bytes"]), (3, 4))
        self.assertTrue(out.startswith(b"abc"))
        self.assertEqual(err, b"defg")

    def test_nonzero_exit_preserved_with_complete_output(self):
        r, _, _ = self.capture("import os;os.write(1,b'failed');os._exit(42)")
        self.assertEqual(r["actual_exit"], 42)
        self.assertTrue(r["output_complete"])
        self.assertEqual(r["stdout"]["bytes"], 6)

    def test_stdout_cap_retains_actual_incomplete_outcome(self):
        r, out, _ = self.capture("import os;os.write(1,b'x'*8192)", out_limit=32)
        self.assertFalse(r["output_complete"])
        self.assertTrue(r["stdout"]["cap_exceeded"])
        self.assertEqual(r["stdout"]["emitted_bytes"], 32)
        self.assertTrue(out.startswith(b"x" * 32 + b"observer-eof-command-receipt "))

    def test_stderr_cap_preserves_separate_streams(self):
        r, _, err = self.capture("import os;os.write(2,b'x'*8192)", err_limit=32)
        self.assertFalse(r["output_complete"])
        self.assertTrue(r["stderr"]["cap_exceeded"])
        self.assertEqual(err, b"x" * 32)

    def test_timeout_is_not_a_successful_sample(self):
        r, _, _ = self.capture("import time;time.sleep(30)", timeout=0.1)
        self.assertNotEqual(r["actual_exit"], 0)
        self.assertEqual(r["reason"], "timeout")
        self.assertTrue(r["copy_threads_joined"])

    def test_owned_control_image_removed_after_transient_access_denial(self):
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / "controls.exe"
            image.write_bytes(b"isolated-test-image")
            selected = C.image_pin(image)
            original = Path.unlink
            calls = []
            def unlink(path):
                calls.append(path)
                if len(calls) == 1:
                    raise PermissionError("isolated access-denied fixture")
                return original(path)
            with mock.patch.object(C.sys, "platform", "win32"), mock.patch.object(Path, "unlink", unlink):
                report = C.remove_control_image(image, selected)
            self.assertFalse(image.exists())
            self.assertEqual(report["removal_attempts"], 2)
            self.assertEqual(report["lock_holder"], "UNKNOWN")
            self.assertFalse(report["observer_deadline_or_pipe_wait_changed"])

    def test_changed_control_image_held(self):
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / "controls.exe"
            image.write_bytes(b"selected-image")
            selected = C.image_pin(image)
            image.write_bytes(b"changed-image")
            with mock.patch.object(C.sys, "platform", "win32"):
                with self.assertRaises(RuntimeError):
                    C.remove_control_image(image, selected)
            self.assertEqual(image.read_bytes(), b"changed-image")

    def test_permanent_control_image_access_denial_held(self):
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / "controls.exe"
            image.write_bytes(b"selected-image")
            selected = C.image_pin(image)
            with mock.patch.object(C.sys, "platform", "win32"), mock.patch.object(Path, "unlink", side_effect=PermissionError("isolated hold")), mock.patch.object(C.sys, "stdout", io.StringIO()):
                with self.assertRaises(RuntimeError):
                    C.remove_control_image(image, selected, timeout=0)
            self.assertTrue(image.exists())

    def test_uncertain_control_image_removal_held(self):
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / "controls.exe"
            image.write_bytes(b"selected-image")
            selected = C.image_pin(image)
            with mock.patch.object(C.sys, "platform", "win32"), mock.patch.object(Path, "unlink", side_effect=OSError("isolated uncertain outcome")):
                with self.assertRaises(RuntimeError):
                    C.remove_control_image(image, selected)
            self.assertTrue(image.exists())


if __name__ == "__main__":
    unittest.main()
