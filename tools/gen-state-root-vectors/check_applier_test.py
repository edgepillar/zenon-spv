#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Non-vacuous controls for node-derived in-memory L1 applier evidence."""

import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("applier_under_test", HERE / "check_applier.py")
CHECK = importlib.util.module_from_spec(spec)
spec.loader.exec_module(CHECK)


class ApplierControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw, cls.original = CHECK.BYTE.read_corpus(HERE / "testdata/candidate-l1-applier.json")

    def changed(self):
        return copy.deepcopy(self.original)

    def refused(self, document):
        with self.assertRaises((ValueError, TypeError, KeyError)):
            CHECK.check_corpus(document)

    def test_all_actual_node_roots_values_and_proofs(self):
        report = CHECK.check_corpus(self.original)
        self.assertEqual((report["selected_keys"], report["checkpoints"], report["commits"]), (8, 7, 6))
        self.assertEqual((report["input_operations"], report["node_proof_comparisons"]), (88, 56))
        self.assertEqual((report["present_observations"], report["absent_observations"]), (20, 36))
        self.assertFalse(report["production_acceptance_enabled"])

    def test_stored_zero_empty_put_and_delete_are_distinct(self):
        decisions = CHECK.check_corpus(self.original)["checkpoint_decisions"]
        self.assertEqual([row["leaf_count"] for row in decisions], [0, 5, 5, 5, 0, 5, 0])
        self.assertEqual(decisions[1]["root"], decisions[5]["root"])
        self.assertEqual(decisions[0]["root"], decisions[4]["root"])
        self.assertEqual(decisions[0]["root"], decisions[6]["root"])
        zero = decisions[1]["observations"][0]["typed_balance"]
        missing = decisions[4]["observations"][0]["typed_balance"]
        self.assertEqual(zero, {"present": True, "amount": "0"})
        self.assertEqual(missing, {"present": False, "amount": "0"})
        self.assertNotEqual(decisions[1]["root"], decisions[4]["root"])

    def test_duplicate_events_preserve_last_write_semantics(self):
        report = CHECK.check_corpus(self.original)
        self.assertEqual(report["checkpoint_decisions"][2]["observations"][0]["typed_balance"]["amount"], "2")
        self.assertEqual(report["checkpoint_decisions"][3]["observations"][0]["typed_balance"]["amount"], "4")
        for height in (2, 3, 6):
            document = self.changed()
            events = document["checkpoints"][height]["input"]
            events[0], events[1] = events[1], events[0]
            self.refused(document)

    def test_excluded_domains_are_not_ledger_absence_claims(self):
        report = CHECK.check_corpus(self.original)
        self.assertEqual(report["unsupported_typed_query_refusals"], 42)
        self.assertEqual(report["typed_balance_research_observations"], 14)
        for checkpoint in report["checkpoint_decisions"]:
            for row in checkpoint["observations"][5:]:
                self.assertFalse(row["present"])
                self.assertIsNone(row["typed_balance"])
                self.assertTrue(row["unsupported_typed_query_refused"])

    def test_raw_short_family_keys_do_not_become_typed_balances(self):
        observations = CHECK.check_corpus(self.original)["checkpoint_decisions"][1]["observations"]
        for row in observations[2:5]:
            self.assertTrue(row["present"])
            self.assertIsNone(row["typed_balance"])
            self.assertTrue(row["unsupported_typed_query_refused"])

    def test_coherent_selected_key_substitution_is_refused(self):
        document = self.changed()
        old = document["selected_keys"][0]["key"]
        new = old[:-2] + "23"
        document["selected_keys"][0]["key"] = new
        for checkpoint in document["checkpoints"]:
            for event in checkpoint["input"]:
                if event["key"] == old:
                    event["key"] = new
            observation = checkpoint["observations"][0]
            observation["key"] = new
            observation["path"] = hashlib.sha3_256(bytes.fromhex(new)).hexdigest()
        self.refused(document)

    def test_checkpoint_height_hash_name_and_order_are_selected(self):
        for field, value in (("height", True), ("height", -1), ("height", 1 << 64), ("height", "1"),
                             ("hash", "ff" * 32), ("hash", "00" * 31), ("name", "provider-selected")):
            document = self.changed()
            document["checkpoints"][1][field] = value
            self.refused(document)
        document = self.changed()
        document["checkpoints"][1:3] = reversed(document["checkpoints"][1:3])
        self.refused(document)

    def test_query_key_and_single_hash_path_are_bound_locally(self):
        for field, value in (("key", "00"), ("name", "balance-b"), ("path", "ff" * 32),
                             ("path", hashlib.sha3_256(bytes.fromhex(self.original["checkpoints"][1]["observations"][0]["path"])).hexdigest())):
            document = self.changed()
            document["checkpoints"][1]["observations"][0][field] = value
            self.refused(document)

    def test_wrong_committed_root_is_refused(self):
        for height in range(7):
            document = self.changed()
            root = document["checkpoints"][height]["root"]
            document["checkpoints"][height]["root"] = ("ff" if root[:2] != "ff" else "00") + root[2:]
            self.refused(document)

    def test_presence_values_and_node_verdicts_cannot_be_substituted(self):
        for field, value in (("present", False), ("present", 1), ("value", "01" * 32),
                             ("value", ""), ("node_result", "mismatch"), ("node_result", True)):
            document = self.changed()
            document["checkpoints"][1]["observations"][0][field] = value
            self.refused(document)

    def test_proof_flags_bitmap_lengths_and_trailing_bytes(self):
        proof = bytes.fromhex(self.original["checkpoints"][1]["observations"][0]["proof"])
        variants = [proof[:-1], proof + b"\x00", bytes([2]) + proof[1:], bytes([0]) + proof[1:],
                    proof[:97] + b"\xff\xff" + proof[99:], proof[:65] + bytes(32) + proof[97:]]
        for changed in variants:
            document = self.changed()
            document["checkpoints"][1]["observations"][0]["proof"] = changed.hex()
            self.refused(document)

    def test_operation_shape_and_scalar_types_are_strict(self):
        for changed in (None, [], {"kind": "put", "key": "00"},
                        {"kind": "delete", "key": "00", "value": "01"},
                        {"kind": True, "key": "00", "value": ""},
                        {"kind": "put", "key": 3, "value": ""},
                        {"kind": "put", "key": "00", "value": False}):
            document = self.changed()
            document["checkpoints"][1]["input"][0] = changed
            self.refused(document)

    def test_bounds_refuse_large_work_before_byte_decoding(self):
        for field, size in (("key", CHECK.FOLD.MAX_KEY_BYTES), ("value", CHECK.FOLD.MAX_VALUE_BYTES)):
            with mock.patch.object(CHECK.BYTE, "hex_bytes", side_effect=AssertionError("decoder must not run")):
                with self.assertRaises(ValueError):
                    CHECK.FOLD.bounded_hex("z" * (size * 2 + 1), size)
        document = self.changed()
        document["checkpoints"][1]["input"] *= 9
        self.refused(document)
        document = self.changed()
        document["checkpoints"] *= 10
        self.refused(document)

    def test_inventories_and_closed_shapes_are_exact(self):
        for member in ("selected_keys", "checkpoints"):
            document = self.changed()
            document[member].append(copy.deepcopy(document[member][0]))
            self.refused(document)
            document = self.changed()
            document[member].pop()
            self.refused(document)
        document = self.changed()
        document["checkpoints"][1]["observations"][1] = copy.deepcopy(document["checkpoints"][1]["observations"][0])
        self.refused(document)
        for row in ("top", "checkpoint", "observation"):
            document = self.changed()
            target = document if row == "top" else document["checkpoints"][1]
            if row == "observation":
                target = target["observations"][0]
            target["future"] = True
            self.refused(document)

    def test_source_backend_and_execution_scope_are_fixed(self):
        for member, value in (("backend", "Tree"), ("kind", "state-proof"), ("format_version", True)):
            document = self.changed()
            document[member] = value
            self.refused(document)
        document = self.changed()
        document["source"]["revision"] = "00" * 20
        self.refused(document)
        for member, value in (("node_database_opened", False), ("database_storage_in_memory_only", False),
                              ("temporary_database_closed", False), ("persisted_disk_lifecycle_executed", True),
                              ("runtime_state_proof_acceptance", True), ("unsigned", 1)):
            document = self.changed()
            document["scope"][member] = value
            self.refused(document)

    def test_hex_spelling_preserves_bytes_and_whitespace_is_refused(self):
        document = self.changed()
        for checkpoint in document["checkpoints"]:
            checkpoint["root"] = checkpoint["root"].upper()
            for row in checkpoint["observations"]:
                for member in ("key", "path", "value", "proof"):
                    row[member] = row[member].upper()
        self.assertEqual(CHECK.check_corpus(document), CHECK.check_corpus(self.original))
        document["checkpoints"][0]["root"] += " "
        self.refused(document)

    def test_file_bounds_duplicate_fields_and_both_previous_corpora(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "fixture.json"
            path.write_bytes(b'{"kind":1,"kind":2}')
            with self.assertRaises(ValueError):
                CHECK.BYTE.read_corpus(path)
            path.write_bytes(b" " * (CHECK.BYTE.MAX_FILE_BYTES + 1))
            with self.assertRaises(ValueError):
                CHECK.BYTE.read_corpus(path)
        for name, wanted in (("candidate-v3-balances.json", "8b69cdaf78ae4eeaad79cdfa493ed9633a1202e09819178da83e17be385f00d3"),
                             ("candidate-l1-fold-filter.json", "0a68118625d0f5df3497dd8d35ce39b9e0df3eb7dc8ccd73e703408031ff45ea")):
            self.assertEqual(hashlib.sha256((HERE / "testdata" / name).read_bytes()).hexdigest(), wanted)

    def test_cli_source_revision_is_only_strict_metadata(self):
        with mock.patch("sys.stdout", new_callable=io.StringIO) as output:
            CHECK.main(["--source-revision", "01" * 20])
        report = json.loads(output.getvalue())
        self.assertEqual(report["source_revision"], "01" * 20)
        self.assertFalse(report["profile_agreed"])
        self.assertFalse(report["production_acceptance_enabled"])
        with self.assertRaises(ValueError):
            CHECK.main(["--corpus", "missing", "--source-revision", "bad"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
