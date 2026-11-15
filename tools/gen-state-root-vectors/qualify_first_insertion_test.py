#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Regular-file controls only; no Go, engine, node, wallet or network execution."""
import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("first_insertion_control", HERE / "qualify_first_insertion.py")
Q = importlib.util.module_from_spec(spec)
spec.loader.exec_module(Q)


def events():
    result = [{"Action": "start", "Package": Q.PACKAGE},
              {"Action": "run", "Package": Q.PACKAGE, "Test": Q.TEST}]
    for case, gap in Q.CASES.items():
        name = Q.TEST + "/" + case
        trace = {**dict.fromkeys(Q.FALSE_FIELDS, False), **dict.fromkeys(Q.TRUE_FIELDS, True),
            "format": "selected-first-insertion-catchup/v1", "case": case,
            "node_revision": Q.C.NODE_REVISION, "source_genesis_sha256": Q.C.GENESIS_SHA256,
            "source_genesis_unix": 1739923200, "unsigned_H2_unix": 1739923200 + gap,
            "gap_seconds": gap, "period_seconds": 300, "completed_periods": gap // 300,
            "completed_epochs": gap // 86400, "unsigned_insert_seconds": 0.01, "points_listener_seconds": 1.5,
            "consensus_get_calls": 10, "consensus_put_calls": gap // 300 + gap // 86400,
            "consensus_put_value_bytes": 300, "closed_consensus_files": 5, "closed_consensus_logical_bytes": 4096}
        result.extend([{"Action": "run", "Package": Q.PACKAGE, "Test": name},
            {"Action": "output", "Package": Q.PACKAGE, "Test": name,
             "Output": "    control_test.go:1: " + Q.MARKER + json.dumps(trace) + "\n"},
            {"Action": "pass", "Package": Q.PACKAGE, "Test": name}])
    result.extend([{"Action": "pass", "Package": Q.PACKAGE, "Test": Q.TEST},
                   {"Action": "pass", "Package": Q.PACKAGE}])
    return result


def encoded(value):
    return b"".join(json.dumps(row).encode() + b"\n" for row in value)


class Controls(unittest.TestCase):
    def refused(self, value):
        with self.assertRaises(Q.Refused):
            Q.native_controls(encoded(value))

    def test_complete_three_case_observation_is_not_acceptance(self):
        result = Q.native_controls(encoded(events()))
        self.assertEqual((result["root_tests"], result["subtests"]), (1, 3))
        self.assertFalse(result["actual_fixture_cause_established"])
        self.assertFalse(result["new_devnet_acceptance_established"])
        self.assertEqual(result["observations"]["fixture-window"]["completed_periods"], 182718)

    def test_split_trace_reassembled_only_in_its_own_test(self):
        value = events()
        row = value[3]
        text = row["Output"]
        for split in (1, 35, 90, len(text) - 1):
            with self.subTest(split=split):
                result = value[:3] + [{**row, "Output": text[:split]}, {**row, "Output": text[split:]}] + value[4:]
                Q.native_controls(encoded(result))

    def test_failed_skipped_and_missing_completion_refused(self):
        for action in ("fail", "skip", "pause"):
            value = events()
            value[4]["Action"] = action
            with self.subTest(action=action):
                self.refused(value)
        self.refused(events()[:-1])
        self.refused(events()[:-2] + events()[-1:])

    def test_repeated_tests_and_post_completion_refused(self):
        value = events()
        self.refused(value[:2] + [value[1]] + value[2:])
        self.refused(value + [value[-1]])
        self.refused(value[:5] + [value[4]] + value[5:])

    def test_foreign_package_and_case_refused(self):
        value = events()
        value[3]["Package"] = "unselected/package"
        self.refused(value)
        value = events()
        value[2]["Test"] = Q.TEST + "/unselected"
        self.refused(value)

    def test_trace_cannot_come_from_root_or_another_test(self):
        for target in (None, Q.TEST, Q.TEST + "/one-day"):
            value = events()
            if target is None:
                value[3].pop("Test")
            else:
                value[3]["Test"] = target
            with self.subTest(target=target):
                self.refused(value)

    def test_duplicate_fields_and_nonfinite_numbers_refused(self):
        for raw in (b'{"Action":"start","Action":"pass"}\n', b'{"value":NaN}\n', b'{"value":Infinity}\n'):
            with self.subTest(raw=raw), self.assertRaises(Q.Refused):
                Q.decode(raw)

    def test_empty_truncated_and_oversized_streams_refused(self):
        for raw in (b"", encoded(events())[:-1], b"x" * (Q.C.MAX_STREAM + 1)):
            with self.assertRaises(Q.Refused):
                Q.native_controls(raw)

    def test_trace_scope_and_measurement_mutations_refused(self):
        original = events()
        trace = json.loads(original[3]["Output"].split(Q.MARKER, 1)[1])
        changes = {**dict.fromkeys(Q.FALSE_FIELDS, True), **dict.fromkeys(Q.TRUE_FIELDS, False),
            "node_revision": "0" * 40, "source_genesis_sha256": "0" * 64, "period_seconds": 10,
            "completed_periods": 0, "gap_seconds": 86400, "unsigned_H2_unix": 1739923201,
            "closed_consensus_files": 0, "closed_consensus_logical_bytes": (256 << 20) + 1,
            "consensus_put_calls": 0, "consensus_put_value_bytes": True,
            "points_listener_seconds": -1, "unsigned_insert_seconds": True, "extra": "unexpected"}
        for key, value in changes.items():
            with self.subTest(key=key):
                changed = copy.deepcopy(original)
                changed[3]["Output"] = Q.MARKER + json.dumps({**trace, key: value}) + "\n"
                self.refused(changed)

    def test_low_space_refuses_before_paths_exist(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with patch.object(Q.shutil, "disk_usage", return_value=type("Usage", (), {"free": 14 * Q.C.GIB - 1})()):
                with self.assertRaises(Q.Refused):
                    Q.stage(root / "work", root / "evidence", {}, [])
            self.assertEqual(list(root.iterdir()), [])

    def test_existing_directories_preserved(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            work, evidence = root / "work", root / "evidence"
            work.mkdir()
            evidence.mkdir()
            (work / "keep").write_bytes(b"unrelated")
            with patch.object(Q, "context", return_value={}), contextlib.redirect_stderr(io.StringIO()):
                code = Q.main(["--mode", "prepare", "--workspace", str(work), "--evidence", str(evidence), "--platform", "linux-amd64"])
            self.assertEqual(code, 1)
            self.assertEqual((work / "keep").read_bytes(), b"unrelated")
            self.assertEqual(list(evidence.iterdir()), [])

    def test_owned_failed_stage_retains_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            work, evidence = root / "work", root / "evidence"
            with patch.object(Q, "context", return_value={}), patch.object(Q, "space", return_value={}), \
                    patch.object(Q.C, "git", side_effect=Q.Refused("controlled_failure")), \
                    contextlib.redirect_stderr(io.StringIO()):
                code = Q.main(["--mode", "prepare", "--workspace", str(work), "--evidence", str(evidence), "--platform", "linux-amd64"])
            self.assertEqual(code, 1)
            self.assertTrue(Q.owned_scope(work, evidence, {}))
            self.assertEqual(json.loads((evidence / "failure-prepare.json").read_bytes())["status"], "FAILURE_OR_UNKNOWN")

    def test_foreign_context_and_identity_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            work, output = root / "work", root / "evidence"
            work.mkdir()
            output.mkdir()
            Q.C.seal(work / "scope.json", Q.C.encoded({"format": "owned-first-insertion-scope/v1", "context": {"run": 1},
                "work_identity": [work.stat().st_dev, work.stat().st_ino],
                "output_identity": [output.stat().st_dev, output.stat().st_ino]}))
            self.assertTrue(Q.owned_scope(work, output, {"run": 1}))
            self.assertFalse(Q.owned_scope(work, output, {"run": 2}))
            self.assertFalse(Q.owned_scope(work, output, None))
            self.assertFalse(Q.owned_scope(output, work, {"run": 1}))

    def test_no_native_or_engine_launch_in_python_controls(self):
        # Exercise only the inherited bounded anonymous-pipe capture contract.
        raw, record = Q.C.capture([sys.executable, "-I", "-B", "-c", "print('regular control')"], HERE, timeout=5)
        self.assertEqual(record["actual_exit"], 0)
        self.assertTrue(record["output_complete"])
        self.assertEqual(raw["stdout"], b"regular control\n")


if __name__ == "__main__":
    unittest.main()
