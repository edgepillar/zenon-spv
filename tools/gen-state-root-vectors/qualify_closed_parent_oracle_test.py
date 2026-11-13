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


def native_fixture(change_trace=None):
    baseline = json.loads((Q.ROOT / Q.H1_BASELINE).read_bytes())
    trace = {"format": "zenon-read-only-source-H1-slots-control/v1", "node_revision": Q.NODE_REVISION,
             "snapshot": baseline["trace"]["snapshot"], "baseline_sha256": Q.H1_BASELINE_SHA256,
             "raw_ledger_files": 14, "raw_ledger_names_and_content_unchanged": True, "source_H1_only": True,
             "Chain_Init_in_reader": False, "Chain_Start": False, "consensus_Start": False,
             "accepting_schedule": False, "actual_devnet_query": False}
    if change_trace:
        change_trace(trace)
    events = [{"Action": "start", "Package": Q.NATIVE_PACKAGE}]
    def event(action, name, **extra):
        events.append({"Action": action, "Package": Q.NATIVE_PACKAGE, "Test": name, **extra})
    for root in sorted(Q.NATIVE_ROOTS):
        event("run", root)
        if root == "TestClosedParentOracleRequestBoundaries":
            for case in sorted(Q.NATIVE_REQUEST_CASES):
                event("run", root + "/" + case)
                event("pass", root + "/" + case)
        if root == "TestClosedParentOracleReadOnlySourceH1":
            event("output", root, Output="    main_test.go:1: SPV_CLOSED_PARENT_ORACLE_H1 " + json.dumps(trace) + "\n")
        event("pass", root)
    events.append({"Action": "pass", "Package": Q.NATIVE_PACKAGE})
    return events


def event_bytes(events):
    return b"".join(json.dumps(row).encode("ascii") + b"\n" for row in events)


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

    def test_selected_refusal_keeps_the_actual_nonzero_exit(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            records = []
            result = Q.command(root, "expected-refusal", [sys.executable, "-I", "-B", "-c",
                "import sys; sys.stderr.buffer.write(b'fixture refused\\n'); sys.exit(1)"], HERE, records, expected_exit=1)
            receipt = json.loads((root / "expected-refusal.json").read_bytes())
            self.assertEqual(result, b"")
            self.assertEqual(receipt["actual_exit"], 1)
            self.assertEqual(receipt["expected_exit"], 1)
            self.assertTrue(receipt["output_complete"])
            self.assertEqual((root / "expected-refusal.stderr").read_bytes(), b"fixture refused\n")
            with self.assertRaises(Q.Refused):
                Q.command(root, "invalid-exit", [sys.executable, "-c", "pass"], HERE, records, expected_exit=True)

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

    def test_complete_node_requires_native_cgo_toolchain(self):
        for platform in ("linux-amd64", "darwin-amd64", "windows-amd64"):
            go = {"GOOS": platform.split("-")[0], "GOARCH": "amd64", "GOVERSION": "go1.25.14",
                  "CGO_ENABLED": "1", "CC": "clang" if platform.startswith("darwin") else "gcc"}
            Q.require_toolchain(go, platform)
            for field, value in (("CGO_ENABLED", "0"), ("GOARCH", "arm64"),
                                 ("CC", "unselected-compiler"), ("GOVERSION", "go1.23.0")):
                with self.subTest(platform=platform, field=field), self.assertRaises(Q.Refused):
                    Q.require_toolchain({**go, field: value}, platform)

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

    def test_selected_helper_retains_original_slot_recording(self):
        inputs = Q.selected_inputs()
        self.assertEqual(Q.NODE_REVISION, "2835c436b197fece5c76adf4ba8dc1decca2e3ea")
        self.assertEqual(Q.NODE_TREE, "f89d645c7f5be85dfe10dc7a510d80df7965d22f")
        self.assertEqual(Q.digest(inputs[Q.H1_BASELINE]), {"sha256": Q.H1_BASELINE_SHA256, "bytes": 8640})
        self.assertEqual(json.loads(inputs[Q.H1_BASELINE])["source"]["revision"],
                         "938fca3b7787da86827a5eb63371509b36e14761")

    def test_stale_helper_revision_refuses_before_workspace_allocation(self):
        inputs = Q.selected_inputs()
        helper = "tools/gen-state-root-vectors/closed-devnet-parent-oracle.go.txt"
        for replacement in (b"938fca3b7787da86827a5eb63371509b36e14761", b"0" * 40, b"main"):
            changed = {**inputs, helper: inputs[helper].replace(Q.NODE_REVISION.encode(), replacement)}
            with self.subTest(replacement=replacement), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                with patch.object(Q, "regular", side_effect=lambda path, limit: changed[path.relative_to(Q.ROOT).as_posix()]), \
                        patch.object(Q, "git") as git, self.assertRaisesRegex(Q.Refused, "helper_node_revision"):
                    Q.stage(root / "work", root / "evidence", self.selected(), [])
                git.assert_not_called()
                self.assertEqual(list(root.iterdir()), [])

    def test_staged_foreign_node_pair_refuses_before_native_commands(self):
        selected = self.selected()
        marker = {"format": "owned-closed-parent-oracle-work/v1", "context": selected,
                  "node_revision": Q.NODE_REVISION, "node_tree": Q.NODE_TREE}
        for field, value in (("node_revision", "938fca3b7787da86827a5eb63371509b36e14761"),
                             ("node_tree", "f3b7947d2267ebdb806f18ff0c02bba5bffae9c4"), ("node_revision", None)):
            with self.subTest(field=field, value=value), patch.object(Q, "owned_scope", return_value=True), \
                    patch.object(Q, "regular", return_value=Q.encoded({**marker, field: value})), \
                    patch.object(Q, "command") as command, patch.object(Q, "git") as git, \
                    self.assertRaisesRegex(Q.Refused, "owned_stage_node_selection"):
                Q.qualify(Path("unused"), Path("unused-output"), selected, [])
            command.assert_not_called()
            git.assert_not_called()

    def test_complete_native_event_selection_and_H1_source_binding(self):
        controls = Q.native_controls(event_bytes(native_fixture()))
        self.assertEqual((controls["root_tests"], controls["subtests"], controls["failed"], controls["skipped"]),
                         (3, 25, 0, 0))
        self.assertEqual(controls["attempted_names"], controls["passed_names"])
        self.assertEqual(controls["source_node_revision"], Q.NODE_REVISION)
        self.assertFalse(controls["actual_devnet_consumer_qualified"])

    def test_split_output_events_reassemble_only_the_H1_test_stream(self):
        events = native_fixture()
        index, = [i for i, row in enumerate(events) if "SPV_CLOSED_PARENT_ORACLE_H1 " in row.get("Output", "")]
        original = events[index]
        expected = Q.native_controls(event_bytes(events))
        for chunk_size in (7, 31, 1024, 2048):
            chunks = [{**original, "Output": original["Output"][i:i + chunk_size]}
                      for i in range(0, len(original["Output"]), chunk_size)]
            split = [*events[:index], *chunks, *events[index + 1:]]
            with self.subTest(chunk_size=chunk_size):
                self.assertEqual(Q.native_controls(event_bytes(split)), expected)
            for changed in (chunks[:-1], [*chunks, *chunks],
                            [{**chunk, "Test": None} for chunk in chunks]):
                with self.subTest(chunk_size=chunk_size, changed=len(changed)), self.assertRaises(Q.Refused):
                    Q.native_controls(event_bytes([*events[:index], *changed, *events[index + 1:]]))

    def test_native_partial_failed_skipped_and_extra_events_refuse(self):
        events = native_fixture()
        subtest = "TestClosedParentOracleRequestBoundaries/unknown-field"
        no_subtest = [row for row in events if row.get("Test") != subtest]
        no_root = [row for row in events if row.get("Test") != "TestClosedParentOracleRegularInput"]
        cases = {"missing-package-pass": events[:-1], "missing-package-start": events[1:],
                 "missing-subtest": no_subtest, "missing-root": no_root,
                 "repeated-run": [*events[:2], events[1], *events[2:]],
                 "after-terminal": [*events, {"Action": "output", "Package": Q.NATIVE_PACKAGE, "Output": "late"}]}
        for action in ("fail", "skip"):
            cases[action] = [{**row, "Action": action} if row.get("Test") == subtest and row["Action"] == "pass"
                             else row for row in events]
        cases["foreign-package"] = [{**events[0], "Package": "unselected/package"}, *events[1:]]
        for name, rows in cases.items():
            with self.subTest(name=name), self.assertRaises(Q.Refused):
                Q.native_controls(event_bytes(rows))
        for raw in (event_bytes(events).rstrip(b"\n"), b"{}\n", b"invalid\n",
                    event_bytes(events).replace(b'"Action": "start"', b'"Action": "fail", "Action": "start"', 1),
                    event_bytes(events).replace(b'"Action": "start"', b'"Elapsed": NaN, "Action": "start"', 1)):
            with self.subTest(raw=raw[:80]), self.assertRaises(Q.Refused):
                Q.native_controls(raw)

    def test_native_H1_trace_cannot_change_source_or_claim_scope(self):
        cases = (("node_revision", "938fca3b7787da86827a5eb63371509b36e14761"), ("baseline_sha256", "0" * 64),
                 ("snapshot", {}), ("raw_ledger_files", 0), ("raw_ledger_files", True),
                 ("raw_ledger_names_and_content_unchanged", False), ("source_H1_only", 1),
                 ("Chain_Init_in_reader", True), ("Chain_Start", True), ("consensus_Start", True),
                 ("accepting_schedule", True), ("actual_devnet_query", True))
        for field, value in cases:
            with self.subTest(field=field, value=value), self.assertRaises(Q.Refused):
                Q.native_controls(event_bytes(native_fixture(lambda trace: trace.update({field: value}))))

    def test_incomplete_native_stream_cannot_reach_binary_build(self):
        with tempfile.TemporaryDirectory() as temporary:
            work, output = Path(temporary) / "work", Path(temporary) / "out"
            work.mkdir()
            output.mkdir()
            node = work / "node"
            node.mkdir()
            selected = {**self.selected(), "platform": "linux-amd64"}
            marker = {"format": "owned-closed-parent-oracle-work/v1", "context": selected,
                      "node_revision": Q.NODE_REVISION, "node_tree": Q.NODE_TREE,
                      "work_identity": [work.stat().st_dev, work.stat().st_ino],
                      "output_identity": [output.stat().st_dev, output.stat().st_ino],
                      "node_identity": [node.stat().st_dev, node.stat().st_ino], "inputs": {}, "original_sources": {}}
            Q.seal(work / "ownership.json", Q.encoded(marker))
            go = {"GOOS": "linux", "GOARCH": "amd64", "GOVERSION": "go1.25.14", "CGO_ENABLED": "1", "CC": "gcc"}
            def command(_, label, *args, **kwargs):
                if label == "go-environment":
                    return Q.encoded(go)
                if label == "c-compiler-version":
                    return b"fixture compiler\n"
                if label == "native-test":
                    return event_bytes(native_fixture()[:-1])
                self.fail("incomplete native evidence reached " + label)
            with patch.object(Q, "owned_scope", return_value=True), patch.object(Q, "installed_inputs", return_value={}), \
                    patch.object(Q, "source_inventory", return_value={}), patch.object(Q, "space", return_value={}), \
                    patch.object(Q, "git", return_value=b"\0"), patch.object(Q, "command", side_effect=command), \
                    self.assertRaisesRegex(Q.Refused, "native_test_completion"):
                Q.qualify(work, output, selected, [])


if __name__ == "__main__":
    unittest.main()
