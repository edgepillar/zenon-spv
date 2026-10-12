#!/usr/bin/env python3
"""Corruption controls for the complete independent context corpus."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("node_context_checks", HERE / "check.py")
CHECK = importlib.util.module_from_spec(spec)
spec.loader.exec_module(CHECK)


class ContextControls(unittest.TestCase):
    def setUp(self):
        self.document = json.loads((CHECK.FIXTURES / "node-account-context.json").read_bytes())

    def reject(self, edit):
        altered = copy.deepcopy(self.document)
        edit(altered)
        with self.assertRaises(CHECK.ACCOUNT.signatures.Refused):
            CHECK.check(altered)

    def test_complete_exact_inventory(self):
        report = CHECK.check(self.document)
        self.assertEqual(report["complete_byte_preimages_checked"], 50)
        self.assertEqual(report["recorded_REJECT"], 38)
        self.assertEqual(report["recorded_PANIC"], 12)
        self.assertEqual(report["actual_signature_processes"], 0)

    def test_source_substitution(self): self.reject(lambda d: d["source"].update(commit="00" * 20))
    def test_new_method_claim(self): self.reject(lambda d: d["source"]["methods"].append("Other"))
    def test_input_pin_substitution(self): self.reject(lambda d: d["input_files_sha256"].update({"account-segments.json": "00" * 32}))
    def test_authenticated_context_claim(self): self.reject(lambda d: d["scope"].update(authenticated_context=True))
    def test_basic_validation_claim(self): self.reject(lambda d: d["scope"].update(basic_account_checks_reached=True))
    def test_hash_signature_validation_claim(self): self.reject(lambda d: d["scope"].update(hash_signature_checks_reached=True))
    def test_missing_observation(self): self.reject(lambda d: d["observations"].pop())
    def test_duplicate_observation(self): self.reject(lambda d: d["observations"].append(copy.deepcopy(d["observations"][0])))
    def test_reordered_methods(self): self.reject(lambda d: d["observations"].reverse())
    def test_changed_block_height(self): self.reject(lambda d: d["observations"][0]["account_block"].update(height=1))
    def test_changed_signature_bytes(self): self.reject(lambda d: d["observations"][8]["account_block"].update(signature=None))
    def test_changed_preimage_hash(self): self.reject(lambda d: d["observations"][0].update(computed_hash="00" * 32))
    def test_changed_method(self): self.reject(lambda d: d["observations"][0].update(method="Other"))
    def test_forged_match(self): self.reject(lambda d: d["observations"][0].update(node_context_result="MATCH", node_error=""))
    def test_panic_suppression(self): self.reject(lambda d: d["observations"][18].update(node_context_result="REJECT"))
    def test_error_precedence(self): self.reject(lambda d: d["observations"][0].update(node_error="ack_zero"))
    def test_fabricated_account_presence(self): self.reject(lambda d: d["observations"][8]["store_plan"].update(global_account_present=False))
    def test_frontier_height_boolean_alias(self): self.reject(lambda d: d["observations"][8]["store_plan"].update(frontier_height=False))
    def test_frontier_height_float_alias(self): self.reject(lambda d: d["observations"][8]["store_plan"].update(frontier_height=0.0))
    def test_dropped_lookup(self): self.reject(lambda d: d["observations"][8]["context_calls"].pop())
    def test_extra_lookup(self): self.reject(lambda d: d["observations"][0]["context_calls"].append({"method": "Chain.Start"}))
    def test_lookup_address(self): self.reject(lambda d: d["observations"][8]["context_calls"][0].update(address="z1unselected"))
    def test_lookup_identifier(self): self.reject(lambda d: d["observations"][8]["context_calls"][0]["identifier"].update(height=1))
    def test_by_hash_argument(self): self.reject(lambda d: d["observations"][10]["context_calls"][-1].update(hash="ff" * 32))
    def test_unselected_field(self): self.reject(lambda d: d.update(activation=True))

    def test_duplicate_json_member(self):
        raw = b'{"observations":[],"observations":[]}'
        with tempfile.TemporaryDirectory() as work:
            path = Path(work) / "input.json"; path.write_bytes(raw)
            with self.assertRaises(CHECK.ACCOUNT.signatures.Refused):
                CHECK.ACCOUNT.read_selected(path, hashlib.sha256(raw).hexdigest())

    def test_nonfinite_json_scalar(self):
        raw = b'{"height":NaN}'
        with tempfile.TemporaryDirectory() as work:
            path = Path(work) / "input.json"; path.write_bytes(raw)
            with self.assertRaises(CHECK.ACCOUNT.signatures.Refused):
                CHECK.ACCOUNT.read_selected(path, hashlib.sha256(raw).hexdigest())


if __name__ == "__main__":
    unittest.main()
