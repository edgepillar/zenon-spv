# SPDX-License-Identifier: GPL-3.0-only
"""No engine or networking. Child fixtures use anonymous pipes only."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import signal
import sys
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True
HERE = Path(__file__).absolute().parent
sys.path.insert(0, str(HERE))
import model
import process as owned_process


class Boundaries(unittest.TestCase):
    def test_invalid_invocations_do_not_launch(self):
        with mock.patch.object(owned_process.subprocess, "Popen") as launch:
            for argv, env, cap, timeout in (
                    ([], {}, 1, 1), (["program"], None, 1, 1),
                    (["program"], {"X": None}, 1, 1), (["program"], {}, True, 1),
                    (["program"], {}, 1, float("nan")), (["program"], {}, 1, 0)):
                with self.subTest(arguments=(argv, env, cap, timeout)):
                    with self.assertRaises(model.Refused):
                        owned_process.capture(argv, ".", env, stdout_cap=cap, timeout=timeout)
            launch.assert_not_called()


@unittest.skipUnless(os.name == "posix", "POSIX process groups are not Windows qualification")
class CaptureTests(unittest.TestCase):
    def env(self):
        return {"PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                "PYTHONDONTWRITEBYTECODE": "1"}

    def run_child(self, program, **kwargs):
        return owned_process.capture([sys.executable, "-I", "-B", "-u", "-c", program],
                                     HERE, self.env(), **kwargs)

    def test_two_complete_streams_and_exit(self):
        raw, receipt = self.run_child(
            "import sys;sys.stdout.write('out');sys.stderr.write('err')")
        self.assertEqual(raw, {"stdout": b"out", "stderr": b"err"})
        self.assertEqual(receipt["actual_exit"], 0)
        self.assertIs(receipt["output_complete"], True)
        self.assertIs(receipt["process_group_quiescent"], True)
        for name in raw:
            self.assertEqual(receipt["streams"][name]["sha256"],
                             hashlib.sha256(raw[name]).hexdigest())

    def test_nonzero_exit_is_preserved_with_complete_output(self):
        raw, receipt = self.run_child("import sys;print('prefix');sys.exit(7)")
        self.assertEqual(receipt["actual_exit"], 7)
        self.assertEqual(raw["stdout"], b"prefix\n")
        self.assertIs(receipt["output_complete"], True)

    def test_both_output_bounds(self):
        for stream in ("stdout", "stderr"):
            with self.subTest(stream=stream):
                raw, receipt = self.run_child(
                    "import sys,time;sys." + stream + ".write('x'*65536);"
                    "sys." + stream + ".flush();time.sleep(30)",
                    stdout_cap=512, stderr_cap=512, timeout=3)
                self.assertEqual(len(raw[stream]), 512)
                self.assertIs(receipt["streams"][stream]["truncated"], True)
                self.assertEqual(receipt["reason"], "output_bound")
                self.assertIs(receipt["output_complete"], False)
                self.assertIs(receipt["process_group_quiescent"], True)

    def test_launch_failure_is_not_zero_exit(self):
        raw, receipt = owned_process.capture(
            ["/nonexistent-owned-fixture-command"], HERE, self.env(), timeout=1)
        self.assertIsNone(receipt["actual_exit"])
        self.assertEqual(receipt["launch_outcome"], "FAILED")
        self.assertEqual(receipt["reason"], "launch_failed")
        self.assertIs(receipt["output_complete"], False)
        self.assertEqual(raw, {"stdout": b"", "stderr": b""})

    def test_cancellation_and_guard_before_launch(self):
        with mock.patch.object(owned_process.subprocess, "Popen") as launch:
            _, receipt = self.run_child("raise RuntimeError()", cancelled=lambda: True)
            self.assertEqual(receipt["reason"], "cancelled")
            self.assertEqual(receipt["launch_outcome"], "NOT_STARTED")
            def reject():
                raise model.Refused("budget")
            _, receipt = self.run_child("raise RuntimeError()", guard=reject)
            self.assertEqual(receipt["reason"], "guard_refused")
            self.assertIsNone(receipt["actual_exit"])
            launch.assert_not_called()

    def test_timeout_stops_only_the_new_group_and_reaps_child(self):
        program = (
            "import signal,subprocess,sys,time\n"
            "child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)'])\n"
            "def stop(*args):\n child.wait(timeout=2)\n sys.exit(3)\n"
            "signal.signal(signal.SIGTERM,stop)\n"
            "print(child.pid,flush=True)\n"
            "time.sleep(30)\n")
        raw, receipt = self.run_child(program, timeout=1, terminate_grace=1)
        self.assertTrue(raw["stdout"].strip().isdigit())
        self.assertEqual(receipt["reason"], "timeout")
        self.assertIn("SIGTERM", receipt["group_signals"])
        self.assertIs(receipt["output_complete"], False)
        self.assertIs(receipt["process_group_quiescent"], True)

    def test_sigkill_escalation_for_own_term_ignoring_child(self):
        raw, receipt = self.run_child(
            "import signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);"
            "print('ready',flush=True);time.sleep(30)", timeout=1, terminate_grace=0.1)
        self.assertEqual(raw["stdout"], b"ready\n")
        self.assertEqual(receipt["actual_exit"], -signal.SIGKILL)
        self.assertIn("SIGKILL", receipt["group_signals"])
        self.assertIs(receipt["process_group_quiescent"], True)

    def test_start_record_failure_stops_child_honestly(self):
        def reject(_):
            raise OSError("fixture failure")
        _, receipt = self.run_child("import time;time.sleep(30)", on_start=reject)
        self.assertEqual(receipt["launch_outcome"], "STARTED")
        self.assertIs(receipt["output_complete"], False)
        self.assertIsNotNone(receipt["actual_exit"])
        self.assertIs(receipt["process_group_quiescent"], True)

    def test_sink_failure_and_stream_read_failure_are_not_success(self):
        class Short:
            def write(self, raw):
                return 1
        raw, receipt = self.run_child("print('longer')", stdout_sink=Short())
        self.assertIsNone(raw["stdout"])
        self.assertEqual(receipt["reason"], "write_failed")
        self.assertIs(receipt["streams"]["stdout"]["captured_bytes_known"], False)
        self.assertIs(receipt["output_complete"], False)
        def broken(*_):
            raise OSError("fixture")
        _, receipt = self.run_child("print('x')", reader=broken)
        self.assertEqual(receipt["reason"], "read_failed")
        self.assertIs(receipt["output_complete"], False)


@unittest.skipUnless(os.name == "posix", "Runtime command recorder is POSIX-only")
class RecorderTests(unittest.TestCase):
    def env(self):
        return {"PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                "PYTHONDONTWRITEBYTECODE": "1"}

    def test_actual_receipts_and_direct_binary_destination(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "commands"
            recorder = owned_process.Recorder(target)
            result = recorder.run("artifact", [sys.executable, "-I", "-B", "-c",
                "import sys;sys.stdout.buffer.write(b'PK'+bytes(range(256)))"],
                target, self.env(), stdout_name="selected.zip", stdout_cap=1024)
            self.assertEqual(result.stdout(1024), b"PK" + bytes(range(256)))
            self.assertIs(result.receipt["output_complete"], True)
            self.assertTrue((target / "selected.zip").is_file())
            self.assertFalse((target / "artifact.stdout").exists())
            self.assertEqual(len(recorder.records), 1)
            self.assertTrue((target / "artifact.launch.json").exists())
            self.assertTrue((target / "artifact.started.json").exists())
            self.assertTrue((target / "artifact.complete.json").exists())
            with self.assertRaises(model.Refused):
                recorder.run("artifact", [sys.executable, "-c", "pass"], target, self.env())
            with self.assertRaises(model.Refused):
                owned_process.Recorder(target)

    def test_failed_command_is_retained_and_raises(self):
        with tempfile.TemporaryDirectory() as directory:
            recorder = owned_process.Recorder(Path(directory) / "commands")
            with self.assertRaises(owned_process.CommandFailed) as caught:
                recorder.run("failed", [sys.executable, "-I", "-B", "-c",
                    "import sys;print('retained');sys.exit(4)"],
                    recorder.directory, self.env())
            result = caught.exception.result
            self.assertEqual(result.receipt["actual_exit"], 4)
            self.assertEqual(result.stdout(), b"retained\n")
            self.assertEqual(len(recorder.records), 1)

    def test_foreign_file_is_not_overwritten_or_adopted(self):
        with tempfile.TemporaryDirectory() as directory:
            recorder = owned_process.Recorder(Path(directory) / "commands")
            foreign = recorder.directory / "selected.zip"
            foreign.write_bytes(b"existing")
            with self.assertRaises(model.Refused):
                recorder.run("artifact", [sys.executable, "-c", "pass"],
                             recorder.directory, self.env(), stdout_name="selected.zip")
            self.assertEqual(foreign.read_bytes(), b"existing")
            self.assertFalse((recorder.directory / "artifact.launch.json").exists())

    def test_replaced_equal_bytes_are_not_reused(self):
        with tempfile.TemporaryDirectory() as directory:
            recorder = owned_process.Recorder(Path(directory) / "commands")
            result = recorder.run("sample", [sys.executable, "-I", "-B", "-c",
                "print('original')"], recorder.directory, self.env())
            original = result.stdout()
            changed_receipt = result.receipt
            changed_receipt["actual_exit"] = 9
            self.assertEqual(result.receipt["actual_exit"], 0)
            with result.open_stdout(1024) as stream:
                self.assertEqual(stream.read(), original)
            replacement = recorder.directory / "replacement"
            replacement.write_bytes(original)
            replacement.replace(recorder.directory / result.stdout_name)
            with self.assertRaises(model.Refused):
                result.stdout()

    def test_unfinished_receipt_does_not_erase_launch_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            recorder = owned_process.Recorder(Path(directory) / "commands")
            original_seal = recorder.seal
            def seal(name, raw):
                if name.endswith(".complete.json"):
                    raise OSError("fixture seal failure")
                return original_seal(name, raw)
            with mock.patch.object(recorder, "seal", side_effect=seal):
                with self.assertRaises(OSError):
                    recorder.run("sample", [sys.executable, "-I", "-B", "-c",
                        "print('retained')"], recorder.directory, self.env())
            self.assertEqual(len(recorder.records), 1)
            self.assertEqual(recorder.records[0]["outcome"], "UNKNOWN")
            self.assertIsNone(recorder.records[0]["receipt"])
            self.assertTrue((recorder.directory / "sample.launch.json").is_file())
            self.assertEqual((recorder.directory / "sample.stdout").read_bytes(), b"retained\n")

    def test_partial_output_setup_closes_first_handle_without_launch(self):
        with tempfile.TemporaryDirectory() as directory:
            recorder = owned_process.Recorder(Path(directory) / "commands")
            original = Path.open
            opened = []
            def create(path, *args, **kwargs):
                if path.name == "sample.stderr":
                    raise OSError("fixture second create failure")
                stream = original(path, *args, **kwargs)
                if path.name == "sample.stdout":
                    opened.append(stream)
                return stream
            with mock.patch.object(Path, "open", new=create):
                with mock.patch.object(owned_process.subprocess, "Popen") as launch:
                    with self.assertRaises(OSError):
                        recorder.run("sample", [sys.executable, "-c", "pass"],
                                     recorder.directory, self.env())
                    launch.assert_not_called()
            self.assertEqual(len(opened), 1)
            self.assertIs(opened[0].closed, True)
            self.assertEqual(recorder.records[0]["outcome"], "UNKNOWN")
            self.assertFalse((recorder.directory / "sample.started.json").exists())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receipt", type=Path)
    parser.add_argument("--source-revision")
    args = parser.parse_args()
    if args.source_revision is not None:
        model.digest(args.source_revision, model.HEX40)
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(Boundaries)
    suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(CaptureTests))
    suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(RecorderTests))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    receipt = {"format": "owned-devnet-query-process-controls/v1",
               "source_revision": args.source_revision, "root_tests": result.testsRun,
               "failures": len(result.failures), "errors": len(result.errors),
               "skipped": len(result.skipped), "successful": result.wasSuccessful(),
               "engine_or_service_or_signing_executed": False,
               "POSIX_process_groups_executed": os.name == "posix"}
    if args.receipt is not None:
        with args.receipt.open("xb") as stream:
            stream.write(model.canonical(receipt))
    print(json.dumps(receipt, sort_keys=True))
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
