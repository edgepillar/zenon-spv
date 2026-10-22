#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Source-only preparation controls; no node component executes."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest import mock

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("read_Stop_preparation_controls", HERE / "prepare_public_chain_proof_stop.py")
R = importlib.util.module_from_spec(spec)
spec.loader.exec_module(R)

class PreparationControls(unittest.TestCase):
    def test_two_finite_build_profiles_keep_runtime_and_authority_boundaries(self):
        value = R.plan(HERE / "not-created-read-Stop-workspace", "selected-go-tool")
        self.assertEqual(value["runtime_tree"], "053c87e5bc4addd1bb70a467cb34facd439e66bc")
        self.assertEqual(value["source_blobs"], 472)
        self.assertEqual(value["selected_reference_builds"], 2)
        self.assertEqual(value["selected_reference_processes"], 2)
        self.assertNotIn("-race", value["profiles"][0]["build_argv"])
        self.assertIn("-race", value["profiles"][1]["build_argv"])
        self.assertEqual(value["minimum_free_floor_bytes"], 10 << 30)
        self.assertFalse(value["reference_backend_executed"])
        self.assertFalse(value["Chain_Start_selected"])
        self.assertFalse(value["Node_or_wallet_or_network_execution_selected"])
        self.assertFalse(value["accepted_header_binding"])
        self.assertEqual(value["consumer_result"], "REFUSED")

    def test_wire_and_contract_reuse_the_preselected_independent_witnesses(self):
        values = {name: json.loads(raw) for name, raw in R.fixtures().items()}
        self.assertEqual(values["selection"]["stop_after_completed_pairs"], 32)
        self.assertEqual(values["contract"]["minimum_successful_caller_intervals_overlapping_Stop"], 1)
        self.assertEqual(len(values["contract"]["successful_proof_rows"]), 128)
        self.assertNotIn("successful_root", values["selection"])
        self.assertNotIn("successful_proof_rows", values["selection"])

    def test_changed_probe_refuses_without_staging(self):
        with mock.patch.object(R.P, "read_regular", return_value=b"changed"):
            with self.assertRaises(ValueError):
                R.probe()

    def test_changed_wire_refuses_before_parent_catalog_validation(self):
        original = R.P.read_regular
        def changed(path, limit):
            value = original(path, limit)
            return value + b"\n" if Path(path).name == "public-chain-proof-stop-selection.json" else value
        with mock.patch.object(R.P, "read_regular", side_effect=changed), mock.patch.object(R.W, "fixtures", side_effect=AssertionError("parent catalog must not run")):
            with self.assertRaises(ValueError):
                R.fixtures()

    def test_existing_or_overlapping_destination_refuses_before_source_read(self):
        with mock.patch.object(R, "plan", side_effect=AssertionError("no preparation plan")):
            with self.assertRaises(ValueError):
                R.prepare(HERE, HERE, "selected-go-tool")
            with self.assertRaises(ValueError):
                R.prepare(HERE, HERE / "not-created-read-Stop-child", "selected-go-tool")
        self.assertFalse((HERE / "not-created-read-Stop-child").exists())

    def test_changed_parent_tree_is_not_an_admitted_runtime(self):
        manifest, modified, pins = R.C.selection("candidate")
        changed = copy.deepcopy(pins)
        changed[sorted(changed)[0]]["git_blob"] = "0" * 40
        with mock.patch.object(R.C, "selection", return_value=(manifest, modified, changed)):
            with self.assertRaises(ValueError):
                R.build_pins()

    def test_framing_vectors_distinguish_absent_and_empty_values(self):
        root = bytes(range(32))
        expected = ("7e6c942b4713bf5ebb058f7b315e0052a31b4d0317aede5d091cf1195d2004de",
                    "53703a23461aa6323df7ba0d4fef5e1de90c1afc5a8018e869fb8eccc44b12de")
        for value, digest in zip((None, b""), expected):
            self.assertEqual(R.M.framed(root, b"k", value, b"p").hex(), digest)
            self.assertIn(digest.encode(), R.probe())
        self.assertNotEqual(*expected)

if __name__ == "__main__":
    unittest.main(verbosity=2)

