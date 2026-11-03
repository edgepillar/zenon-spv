#!/usr/bin/env python3
"""Regression controls for the recorded source-parent-slot reader.

Fixtures stay in memory. The reader does not launch a node or create a DB.
"""

import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import unittest


spec = importlib.util.spec_from_file_location(
    "source_parent_slots", Path(__file__).with_name("check_parent_snapshot_slots.py"))
reader = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reader)


class ParentSnapshotSlotsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.value = reader.parse(reader.read_regular(reader.CORPUS, 32 << 10), 32 << 10)
        cls.config_raw = reader.read_regular(reader.ROOT / reader.CONFIG["path"], 16 << 10)
        cls.config = reader.parse(cls.config_raw, 16 << 10)
        cls.helpers = {key: reader.read_regular(reader.ROOT / pin["path"], 16 << 10)
                       for key, pin in reader.HELPERS.items()}

    def verify(self, value):
        return reader.check_corpus(value, self.config_raw, self.helpers)

    def changed(self, path, replacement):
        value = copy.deepcopy(self.value)
        selected = value
        for key in path[:-1]:
            selected = selected[key]
        selected[path[-1]] = replacement
        return value

    def test_recorded_capture_and_honest_scope(self):
        report = self.verify(self.value)
        self.assertEqual(report["recorded_slot_queries"], 6)
        self.assertEqual(report["recorded_negative_controls"], 10)
        self.assertTrue(report["independent_tick_and_proof_time_checks"])
        self.assertFalse(report["independent_election_order_recomputed"])
        self.assertFalse(report["node_or_managers_executed_by_reader"])
        self.assertEqual(report["original_controller_outcome"], "FAILURE")
        self.assertEqual(report["node_test_actual_exit"], 0)
        self.assertTrue(report["node_test_output_complete"])
        self.assertFalse(report["accepting_ProducerSchedule_created"])

    def test_source_and_execution_pins(self):
        mutations = [
            (["source", "revision"], "0" * 40),
            (["source", "tree"], "0" * 40),
            (["source_files", "consensus/election.go", "sha256"], "0" * 64),
            (["execution", "node_test_actual_exit"], 1),
            (["execution", "node_test_output_complete"], False),
            (["execution", "node_test_output", "sha256"], "0" * 64),
            (["execution", "readback_record", "sha256"], "0" * 64),
            (["execution", "used_modules_verified"], 0),
        ]
        for path, replacement in mutations:
            with self.subTest(path=path):
                with self.assertRaises(ValueError):
                    self.verify(self.changed(path, replacement))

    def test_cleanup_failure_cannot_be_rewritten_as_success(self):
        for field, replacement in (
                ("original_controller_outcome", "SUCCESS"),
                ("original_controller_exit", 0),
                ("cleanup_failed_after_completed_node_test", False),
                ("full_module_graph_go_mod_verify", "PASS"),
                ("native_execution_repeated_for_publication", True)):
            with self.subTest(field=field):
                with self.assertRaises(ValueError):
                    self.verify(self.changed(["execution", field], replacement))

    def test_snapshot_and_proof_parent_identity(self):
        for path in (["trace", "genesis"], ["trace", "snapshot", "parent"],
                     ["trace", "snapshot", "rows", 0, "proof_block"]):
            for field, replacement in (("hash", "0" * 64), ("height", 2), ("height", True)):
                with self.subTest(path=path, field=field, replacement=replacement):
                    with self.assertRaises(ValueError):
                        self.verify(self.changed(path + [field], replacement))

    def test_slot_order_and_cardinality(self):
        rows = self.value["trace"]["snapshot"]["rows"]
        for replacement in ([], rows[:-1], rows + [rows[-1]], rows[::-1], [rows[0]] * 6):
            with self.subTest(rows=replacement):
                with self.assertRaises(ValueError):
                    self.verify(self.changed(["trace", "snapshot", "rows"], replacement))

    def test_slot_alignment_and_duration(self):
        row = self.value["trace"]["snapshot"]["rows"][0]
        for field, replacement in (
                ("timestamp", row["timestamp"] + 1),
                ("slot_start", row["slot_start"] + 1),
                ("slot_end", row["slot_end"] + 1), ("tick", 1)):
            with self.subTest(field=field):
                with self.assertRaises(ValueError):
                    self.verify(self.changed(["trace", "snapshot", "rows", 0, field], replacement))

    def test_proof_time_transition(self):
        for index, replacement in ((0, 1739923500), (3, 1739923500), (5, 1739923201)):
            with self.subTest(index=index):
                with self.assertRaises(ValueError):
                    self.verify(self.changed(
                        ["trace", "snapshot", "rows", index, "proof_time"], replacement))

    def test_uint_width_and_type(self):
        for field in ("timestamp", "tick", "slot_start", "slot_end",
                      "proof_time", "proof_block_timestamp"):
            for replacement in (True, 1.0, "1", -1, 2**64):
                with self.subTest(field=field, replacement=replacement):
                    with self.assertRaises(ValueError):
                        self.verify(self.changed(
                            ["trace", "snapshot", "rows", 0, field], replacement))

    def test_normal_consensus_parameters_and_work_limits(self):
        for path, replacement in (
                (["parameters", "block_time"], 1), (["parameters", "node_count"], 3),
                (["parameters", "rand_count"], 0), (["parameters", "counting_zts"], "QSR"),
                (["limits", "query_count"], 65), (["limits", "max_genesis_delta_seconds"], 2**64)):
            with self.subTest(path=path):
                with self.assertRaises(ValueError):
                    self.verify(self.changed(["trace"] + path, replacement))

    def test_source_pillar_membership(self):
        for path, replacement in (
                (["snapshot", "rows", 0, "name"], "unknown"),
                (["snapshot", "rows", 0, "producer"], "unknown"),
                (["source_pillars", "dev2"], "unknown")):
            with self.subTest(path=path):
                with self.assertRaises(ValueError):
                    self.verify(self.changed(["trace"] + path, replacement))

    def test_election_order_remains_a_digest_bound_node_output(self):
        # Another real genesis producer passes the independent membership/math
        # checks, but differs from the actual node oracle and must be refused.
        value = copy.deepcopy(self.value)
        row = value["trace"]["snapshot"]["rows"][0]
        row["name"] = "dev1"
        row["producer"] = value["trace"]["source_pillars"]["dev1"]
        reader.check_trace(value["trace"], self.config)
        with self.assertRaises(ValueError):
            self.verify(value)

    def test_authority_and_partial_output_upgrades(self):
        for field in reader.NO_AUTHORITY:
            with self.subTest(field=field):
                with self.assertRaises(ValueError):
                    self.verify(self.changed(["trace", field], True))
        for path, replacement in (
                (["trace", "refused_controls"], reader.REFUSALS[:-1]),
                (["trace", "frontier_unchanged"], False),
                (["trace", "Stop_returned_nil"], False),
                (["scope", "accepted_SPV_header"], True),
                (["scope", "first_incoming_v3_captured"], True),
                (["scope", "production_qualified"], True)):
            with self.subTest(path=path):
                with self.assertRaises(ValueError):
                    self.verify(self.changed(path, replacement))
        value = copy.deepcopy(self.value)
        value["trace"]["snapshot"]["rows"][0]["height"] = 2
        with self.assertRaises(ValueError):
            self.verify(value)

    def test_config_and_both_helper_bytes(self):
        with self.assertRaises(ValueError):
            reader.check_corpus(self.value, self.config_raw + b"\n", self.helpers)
        for key in self.helpers:
            with self.subTest(helper=key):
                helpers = dict(self.helpers)
                helpers[key] += b"\n"
                with self.assertRaises(ValueError):
                    reader.check_corpus(self.value, self.config_raw, helpers)

    def test_strict_json_and_cli_input(self):
        for raw in (b'{"parent":1,"parent":2}', b'{"n":NaN}', b'{"n":Infinity}',
                    b"\xff", b"", b" " * (32 << 10) + b"{}"):
            with self.subTest(raw=raw[:32]):
                with self.assertRaises(ValueError):
                    reader.parse(raw, 32 << 10)
        for args in (["--unknown", "DO_NOT_ECHO"], ["--source-revision", "A" * 40], ["--source-revision"]):
            with self.subTest(args=args):
                error = io.StringIO()
                with contextlib.redirect_stderr(error):
                    self.assertEqual(reader.main(args), 64)
                self.assertEqual(error.getvalue(), "source-parent-slots: invalid command syntax\n")


if __name__ == "__main__":
    unittest.main()
