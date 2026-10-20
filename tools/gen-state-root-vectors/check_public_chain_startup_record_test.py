#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Recorded-byte trust controls; these tests execute no reference process."""
import copy
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import unittest

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("startup_record_controls", HERE / "check_public_chain_startup_record.py")
M = importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)


class PublicChainStartupRecordTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = (HERE / "testdata" / M.CORPUS).read_bytes()
        cls.value = M.document(cls.raw)

    def changed_trace(self, change, variant="candidate"):
        row = copy.deepcopy(self.value["cases"][variant == "candidate"])
        events = [M.document(line.encode()) for line in row["stdout_utf8"].splitlines()]
        change(events)
        raw = ("\n".join(json.dumps(e, sort_keys=True, separators=(",", ":")) for e in events) + "\n").encode()
        row["stdout_utf8"] = raw.decode()
        row["command"]["stdout"] = {"bytes": len(raw), "sha256": M.P.sha(raw)}
        return row

    def test_recorded_positive_scope_and_counts(self):
        result = M.check_file(HERE / "testdata" / M.CORPUS)
        self.assertEqual(result["recorded_events"], 150)
        self.assertEqual(result["recorded_native_unit_pass_results"], 17)
        self.assertEqual(result["recorded_parent_API_panics"], 4)
        self.assertEqual(result["recorded_candidate_API_panics"], 0)
        self.assertEqual(result["recorded_parent_inconsistent_ready_results"], 5)
        self.assertEqual(result["reference_processes_executed_by_this_check"], 0)
        self.assertEqual(result["consumer_result"], "REFUSED")

    def test_scope_substitution_refuses(self):
        for key in M.SCOPE:
            value = copy.deepcopy(self.value)
            value["scope"][key] = not value["scope"][key]
            with self.assertRaises(ValueError):
                M.check_corpus(value)

    def test_source_or_unit_tree_substitution_refuses(self):
        for key in ("revision", "parent_runtime_tree", "candidate_runtime_tree", "module_sha256",
                    "candidate_probe_build_tree", "candidate_unit_build_tree"):
            value = copy.deepcopy(self.value)
            value["source"][key] = "0" * len(value["source"][key])
            with self.assertRaises(ValueError):
                M.check_corpus(value)

    def test_incomplete_or_nonzero_process_refuses(self):
        for key, replacement in (("actual_exit", None), ("actual_exit", 2), ("output_complete", False),
                                 ("reason", "OUTPUT_LIMIT_OR_CAPTURE_FAILURE")):
            row = copy.deepcopy(self.value["cases"][1])
            row["command"][key] = replacement
            with self.assertRaises(ValueError):
                M.check_trace(row, "candidate")
        row = copy.deepcopy(self.value["cases"][1])
        row["completion_marker_observed"] = False
        with self.assertRaises(ValueError):
            M.check_trace(row, "candidate")

    def test_missing_or_duplicated_case_refuses_after_rehash(self):
        for change in (lambda es: es.pop(), lambda es: es.insert(3, copy.deepcopy(es[3]))):
            with self.assertRaises(ValueError):
                M.check_trace(self.changed_trace(change), "candidate")

    def test_false_readiness_refuses_after_rehash(self):
        def change(events):
            e = next(e for e in events if e["stage"] == "public-init-observation" and e["case"] == "missing-genesis")
            e["state_tree_ready"] = True
        with self.assertRaises(ValueError):
            M.check_trace(self.changed_trace(change), "candidate")

    def test_failed_start_cannot_return_a_root(self):
        def change(events):
            e = next(e for e in events if e["stage"] == "public-init-observation" and e["case"] == "corrupt-frontier")
            e["root"] = M.ROOT
            e["root_query_result"] = {"error_class": "none", "error_sha256": "", "panic": False,
                                      "panic_type": "", "panic_sha256": ""}
        with self.assertRaises(ValueError):
            M.check_trace(self.changed_trace(change), "candidate")

    def test_mutation_target_height_refuses_after_rehash(self):
        def change(events):
            e = next(e for e in events if e["stage"] == "fixture-before-public-init" and e["case"] == "missing-genesis")
            e["mutation"]["key_hex"] = "55020000000000000002"
        with self.assertRaises(ValueError):
            M.check_trace(self.changed_trace(change), "candidate")

    def test_changed_closed_raw_image_refuses_after_rehash(self):
        def change(events):
            e = next(e for e in events if e["stage"] == "fixture-after-public-stop")
            e["images"]["tree"]["sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            M.check_trace(self.changed_trace(change), "candidate")

    def test_omitted_raw_empty_row_refuses_after_rehash(self):
        def change(events):
            events[0]["image"].update(records=0, key_bytes=0, sha256=M.P.sha(b""))
        with self.assertRaises(ValueError):
            M.check_trace(self.changed_trace(change), "candidate")

    def test_candidate_does_not_borrow_a_consumed_genesis_patch(self):
        def change(events):
            e = next(e for e in events if e["stage"] == "configured-genesis-transaction-after-stop")
            e.update(changes_present=False, bytes=0, sha256=M.P.sha(b""))
        with self.assertRaises(ValueError):
            M.check_trace(self.changed_trace(change), "candidate")

    def test_independent_v1_hash_rejects_changed_body(self):
        for key in ("genesis", "second"):
            header = copy.deepcopy(M.HEADERS[key])
            self.assertEqual(M.header_hash(header), header["hash"])
            header["timestamp"] += 1
            self.assertNotEqual(M.header_hash(header), header["hash"])

    def test_header_boolean_or_noncanonical_hex_refuses(self):
        for key, value in (("height", True), ("timestamp", -1), ("data_hex", "0G"), ("public_key_bytes", 1)):
            header = copy.deepcopy(M.HEADERS["second"])
            header[key] = value
            with self.assertRaises(ValueError):
                M.header_hash(header)

    def test_native_unit_skip_or_missing_pass_refuses(self):
        for key, value in (("explicit_skips", ["unexecuted"]), ("failed_tests", ["failure"]),
                           ("test_pass_names", []), ("race_detector", True)):
            units = copy.deepcopy(self.value["unit_run"])
            units[key] = value
            with self.assertRaises(ValueError):
                M.check_units(units)

    def test_duplicate_or_nonfinite_json_refuses(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":Infinity}', b'{"x":-Infinity}'):
            with self.assertRaises(ValueError):
                M.document(raw)

    def test_failed_attempts_cannot_be_relabelled_successful(self):
        value = copy.deepcopy(self.value)
        value["execution"]["attempt_inventory"][-1].update(actual_exit=0, output_complete=True, outcome="PASS")
        with self.assertRaises(ValueError):
            M.check_corpus(value)

    def test_recorded_binary_substitution_refuses(self):
        value = copy.deepcopy(self.value)
        value["execution"]["binaries"]["candidate"]["sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            M.check_corpus(value)

    def test_CI_revision_pin_and_invalid_revision(self):
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            self.assertEqual(M.main(["--source-revision", "a" * 40]), 0)
        report = json.loads(stream.getvalue())
        self.assertEqual(report["source_revision"], "a" * 40)
        self.assertEqual(report["reference_processes_executed_by_this_check"], 0)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(M.main(["--source-revision", "invalid"]), 1)


if __name__ == "__main__":
    unittest.main()
