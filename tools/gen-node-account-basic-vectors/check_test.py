#!/usr/bin/env python3
"""Corruption controls for independently reconstructed method/store observations."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("basic_checks", HERE / "check.py")
CHECK = importlib.util.module_from_spec(spec)
spec.loader.exec_module(CHECK)


class BasicStoreControls(unittest.TestCase):
    def setUp(self):
        self.document = json.loads((CHECK.FIXTURES / "node-account-basic.json").read_bytes())

    def reject(self, edit):
        altered = copy.deepcopy(self.document); edit(altered)
        with self.assertRaises(CHECK.ACCOUNT.signatures.Refused): CHECK.check(altered)

    def test_complete_inventory(self):
        report = CHECK.check(self.document)
        self.assertEqual((report["recorded_MATCH"], report["recorded_REJECT"], report["recorded_PANIC"]), (11, 39, 0))
        self.assertEqual(report["recorded_database_reads_checked"], 21)
        self.assertEqual(report["complete_seeded_store_maps_checked"], 100)

    def test_frontier_identifier_is_proto_not_flat(self):
        identifier = {"hash": "11" * 32, "height": 3000}
        records = CHECK.seed_records(identifier, b"\xff")
        self.assertEqual(records["00"].hex(), "0a220a20" + "11" * 32 + "10b817")
        self.assertEqual(records["01" + "11" * 32], bytes.fromhex("0000000000000bb8"))
        self.assertEqual(records["020000000000000bb8"], b"\xff")

    def test_varint_boundaries(self):
        self.assertEqual([CHECK.varint(n).hex() for n in (0, 127, 128, 3000, (1 << 64) - 1)],
                         ["00", "7f", "8001", "b817", "ffffffffffffffffff01"])
        for n in (-1, 1 << 64, True, 1.0):
            with self.subTest(number=n), self.assertRaises(CHECK.ACCOUNT.signatures.Refused): CHECK.varint(n)

    def test_source_substitution(self): self.reject(lambda d: d["source"].update(commit="00" * 20))
    def test_method_claim_substitution(self): self.reject(lambda d: d["source"]["methods"].append("Other"))
    def test_input_pin_substitution(self): self.reject(lambda d: d["input_files_sha256"].update({"account-segments.json": "00" * 32}))
    def test_authenticated_context_claim(self): self.reject(lambda d: d["scope"].update(authenticated_context=True))
    def test_full_node_claim(self): self.reject(lambda d: d["scope"].update(full_node_validation=True))
    def test_unsigned_metadata_claim(self): self.reject(lambda d: d["scope"].update(synthetic_unsigned_momentum_metadata=False))
    def test_missing_observation(self): self.reject(lambda d: d["observations"].pop())
    def test_duplicate_observation(self): self.reject(lambda d: d["observations"].append(copy.deepcopy(d["observations"][0])))
    def test_reordered_methods(self): self.reject(lambda d: d["observations"].reverse())
    def test_bool_integer_alias(self): self.reject(lambda d: d["observations"][0]["store_plan"].update(chain_id=True))
    def test_float_integer_alias(self): self.reject(lambda d: d["observations"][0]["account_block"].update(height=1.0))
    def test_changed_hash_preimages(self):
        for index in range(50):
            with self.subTest(row=index): self.reject(lambda d: d["observations"][index].update(computed_hash="00" * 32))
    def test_forged_method_outcomes(self):
        for index, row in enumerate(self.document["observations"]):
            with self.subTest(row=index):
                self.reject(lambda d: d["observations"][index].update(node_method_result="MATCH" if row["node_method_result"] == "REJECT" else "REJECT"))
    def test_error_precedence(self): self.reject(lambda d: d["observations"][2].update(node_error="hash_mismatch"))
    def test_dropped_store_call(self): self.reject(lambda d: d["observations"][0]["store_calls"].pop())
    def test_extra_store_call(self): self.reject(lambda d: d["observations"][0]["store_calls"].append({"method": "Chain.Start"}))
    def test_selected_parent_identifier(self): self.reject(lambda d: d["observations"][34]["store_calls"][0]["identifier"].update(height=0))
    def test_selected_store_address(self): self.reject(lambda d: d["observations"][0]["store_calls"][0].update(address="z1unselected"))
    def test_seeded_record_bytes(self):
        for field in ("account_entries", "momentum_entries"):
            for index, row in enumerate(self.document["observations"]):
                if row[field]:
                    with self.subTest(row=index, store=field): self.reject(lambda d: d["observations"][index][field][0].update(value="00"))
    def test_seeded_record_inventory(self): self.reject(lambda d: d["observations"][0]["momentum_entries"].pop())
    def test_wrong_database_read_bytes(self): self.reject(lambda d: d["observations"][0]["database_reads"][0].update(value="ff"))
    def test_wrong_database_read_key(self): self.reject(lambda d: d["observations"][0]["database_reads"][0].update(key="00"))
    def test_suppressed_not_found(self): self.reject(lambda d: d["observations"][28]["database_reads"][0].update(error=""))
    def test_unselected_database_read(self): self.reject(lambda d: d["observations"][1]["database_reads"].append({"store": "account", "key": "00", "value": "", "error": "not_found"}))
    def test_corrupt_seed_repaired(self): self.reject(lambda d: d["observations"][32]["momentum_entries"][2].update(value="00"))
    def test_unselected_field(self): self.reject(lambda d: d.update(activation=True))
    def test_duplicate_json_member(self):
        raw = b'{"observations":[],"observations":[]}'
        with tempfile.TemporaryDirectory() as work:
            path = Path(work) / "input.json"; path.write_bytes(raw)
            with self.assertRaises(CHECK.ACCOUNT.signatures.Refused): CHECK.ACCOUNT.read_selected(path, hashlib.sha256(raw).hexdigest())
    def test_nonfinite_json_scalar(self):
        raw = b'{"height":NaN}'
        with tempfile.TemporaryDirectory() as work:
            path = Path(work) / "input.json"; path.write_bytes(raw)
            with self.assertRaises(CHECK.ACCOUNT.signatures.Refused): CHECK.ACCOUNT.read_selected(path, hashlib.sha256(raw).hexdigest())


if __name__ == "__main__": unittest.main()
