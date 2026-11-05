#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Small regular-file and anonymous-pipe controls; no node or Go invocation."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("closed_parent_qualification", HERE / "qualify_closed_parent_oracle.py")
Q = importlib.util.module_from_spec(spec)
spec.loader.exec_module(Q)


def source_fixture():
    raw = b"package source\n"
    oid = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest().encode()
    return raw, b"".join(b"100644 " + oid + b" 0\tf" + str(index).zfill(4).encode() + b".go\0" for index in range(400))


class Controls(unittest.TestCase):
    def selected(self):
        return {"repository": "edgepillar/zenon-spv", "run_id": 1, "run_attempt": 1, "source_revision": "a" * 40}

    def test_portable_capture_both_streams(self):
        raw, receipt = Q.capture([sys.executable, "-I", "-B", "-c",
                                 "import sys; sys.stdout.write('out'); sys.stderr.write('err')"], HERE)
        self.assertEqual(raw, {"stdout": b"out", "stderr": b"err"})
        self.assertEqual(receipt["actual_exit"], 0)
        self.assertTrue(receipt["output_complete"])
        for name in raw:
            self.assertTrue(receipt["streams"][name]["eof"])
            self.assertEqual(receipt["streams"][name]["sha256"], hashlib.sha256(raw[name]).hexdigest())

    def test_nonzero_exit_is_complete_failure(self):
        raw, receipt = Q.capture([sys.executable, "-I", "-B", "-c", "import sys; sys.exit(7)"], HERE)
        self.assertEqual(receipt["actual_exit"], 7)
        self.assertTrue(receipt["output_complete"])
        self.assertEqual(raw["stdout"], b"")

    def test_capture_bound_refuses_success_claim(self):
        raw, receipt = Q.capture([sys.executable, "-I", "-B", "-c", "print('x' * 10000)"], HERE, cap=64)
        self.assertLessEqual(len(raw["stdout"]), 64)
        self.assertTrue(receipt["streams"]["stdout"]["truncated"])
        self.assertFalse(receipt["output_complete"])

    def test_timeout_retains_actual_incomplete_exit(self):
        _, receipt = Q.capture([sys.executable, "-I", "-B", "-c", "import time; time.sleep(2)"], HERE, timeout=0.05)
        self.assertTrue(receipt["timed_out"])
        self.assertFalse(receipt["output_complete"])
        self.assertIsInstance(receipt["actual_exit"], int)

    def test_launch_refusal_has_no_fabricated_exit(self):
        _, receipt = Q.capture([str(HERE / "absent-owned-test-program")], HERE)
        self.assertTrue(receipt["launch_failed"])
        self.assertIsNone(receipt["actual_exit"])
        self.assertFalse(receipt["output_complete"])

    def test_command_failure_preserves_streams_and_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            records = []
            with self.assertRaises(Q.Refused):
                Q.command(root, "failed", [sys.executable, "-I", "-B", "-c", "import sys; sys.stdout.buffer.write(b'evidence\\n'); sys.exit(9)"],
                          HERE, records)
            self.assertEqual((root / "failed.stdout").read_bytes(), b"evidence\n")
            receipt = json.loads((root / "failed.json").read_bytes())
            self.assertEqual(receipt["actual_exit"], 9)
            self.assertTrue(receipt["output_complete"])
            self.assertEqual(len(records), 1)

    def test_regular_reader_and_bound(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "regular.json"
            path.write_bytes(b"test")
            self.assertEqual(Q.regular(path, 4), b"test")
            with self.assertRaises(Q.Refused):
                Q.regular(path, 3)
            with self.assertRaises(Q.Refused):
                Q.regular(root, 1024)

    def test_source_blobs_include_executable_regular_files(self):
        raw, index = source_fixture()
        with patch.object(Q, "regular", return_value=raw):
            self.assertEqual(len(Q.source_inventory(Path("unused"), index)), 400)
            executable = index.replace(b"100644 ", b"100755 ", 1)
            self.assertEqual(len(Q.source_inventory(Path("unused"), executable)), 400)

    def test_source_index_and_blob_refusals(self):
        raw, index = source_fixture()
        cases = {"missing-framing": index[:-1], "nonregular": index.replace(b"100644", b"120000", 1),
                 "traversal": index.replace(b"f0000.go", b"../f0000.go", 1),
                 "duplicate": index + index.split(b"\0")[0] + b"\0",
                 "blob-substitution": index.replace(index[7:47], b"0" * 40, 1),
                 "incomplete-source": index.split(b"\0")[0] + b"\0"}
        with patch.object(Q, "regular", return_value=raw):
            for name, value in cases.items():
                with self.subTest(name=name), self.assertRaises(Q.Refused):
                    Q.source_inventory(Path("unused"), value)

    def test_selected_source_bytes_and_workflow_CRLF(self):
        canonical = {"helper.py": b"print('source')\n", "workflow.yml": b"name: source\n"}
        index = b""
        for name, raw in canonical.items():
            oid = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest().encode()
            index += b"100644 " + oid + b" 0\t" + name.encode() + b"\0"
        working = {**canonical, "workflow.yml": canonical["workflow.yml"].replace(b"\n", b"\r\n")}
        def read(path, limit):
            return working[str(path.relative_to(Q.ROOT))]
        with patch.object(Q, "regular", side_effect=read):
            source, actual = Q.selected_sources(index, set(canonical))
            self.assertEqual(source, {name: Q.digest(raw) for name, raw in canonical.items()})
            self.assertEqual(actual["workflow.yml"]["relation"], "CRLF-only")
            working["helper.py"] = working["helper.py"].replace(b"\n", b"\r\n")
            with self.assertRaises(Q.Refused):
                Q.selected_sources(index, set(canonical))
            working["helper.py"] = canonical["helper.py"]
            working["workflow.yml"] = b"name: changed\n"
            with self.assertRaises(Q.Refused):
                Q.selected_sources(index, set(canonical))

    def test_CI_context_is_explicit_and_native(self):
        native = {"linux": "linux-amd64", "darwin": "darwin-amd64", "win32": "windows-amd64"}[sys.platform]
        values = {"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": "edgepillar/zenon-spv", "GITHUB_SHA": "b" * 40,
                  "SPV_FEATURE_REVISION": "a" * 40, "GITHUB_EVENT_NAME": "pull_request",
                  "GITHUB_RUN_ID": "1", "GITHUB_RUN_ATTEMPT": "1"}
        with patch.dict(os.environ, values, clear=True):
            self.assertEqual(Q.context(native)["source_revision"], "b" * 40)
        for name, value in (("GITHUB_REPOSITORY", "unrelated/repository"), ("GITHUB_RUN_ID", "0"),
                            ("GITHUB_EVENT_NAME", "workflow_dispatch"), ("SPV_FEATURE_REVISION", "invalid")):
            with self.subTest(name=name), patch.dict(os.environ, {**values, name: value}, clear=True), self.assertRaises(Q.Refused):
                Q.context(native)

    def test_low_space_refuses_before_creating_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with patch.object(Q.shutil, "disk_usage", return_value=type("Usage", (), {"free": 10 * Q.GIB})()):
                with self.assertRaises(Q.Refused):
                    Q.stage(root / "work", root / "evidence", self.selected(), [])
            self.assertEqual(list(root.iterdir()), [])

    def test_foreign_existing_directories_remain_unchanged(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            work, evidence = root / "work", root / "evidence"
            work.mkdir()
            evidence.mkdir()
            (evidence / "keep").write_bytes(b"unrelated")
            with patch.object(Q, "context", return_value=self.selected()), contextlib.redirect_stderr(io.StringIO()):
                code = Q.main(["--mode", "prepare", "--workspace", str(work), "--evidence", str(evidence),
                               "--platform", "linux-amd64"])
            self.assertEqual(code, 1)
            self.assertEqual(sorted(p.name for p in evidence.iterdir()), ["keep"])
            self.assertEqual((evidence / "keep").read_bytes(), b"unrelated")
            self.assertEqual(list(work.iterdir()), [])

    def test_owned_partial_stage_preserves_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            work, evidence = root / "work", root / "evidence"
            with patch.object(Q, "context", return_value=self.selected()), patch.object(Q, "space", return_value={}), \
                    patch.object(Q, "git", side_effect=Q.Refused("controlled_failure")), \
                    contextlib.redirect_stderr(io.StringIO()):
                code = Q.main(["--mode", "prepare", "--workspace", str(work), "--evidence", str(evidence),
                               "--platform", "linux-amd64"])
            self.assertEqual(code, 1)
            self.assertTrue(Q.owned_scope(work, evidence, self.selected()))
            self.assertTrue((evidence / "failure-prepare.json").is_file())

    def test_scope_requires_exact_selection_and_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            work, output = root / "work", root / "out"
            work.mkdir()
            output.mkdir()
            selected = self.selected()
            value = {"format": "owned-closed-parent-oracle-scope/v1", "context": selected,
                     "work_identity": [work.stat().st_dev, work.stat().st_ino],
                     "output_identity": [output.stat().st_dev, output.stat().st_ino]}
            Q.seal(work / "scope.json", Q.encoded(value))
            self.assertTrue(Q.owned_scope(work, output, selected))
            self.assertFalse(Q.owned_scope(work, output, {**selected, "run_id": 2}))
            self.assertFalse(Q.owned_scope(work, root, selected))


if __name__ == "__main__":
    unittest.main()
