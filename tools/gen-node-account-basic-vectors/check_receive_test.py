#!/usr/bin/env python3
"""Counterexamples for the selected receive corpus and its evidence limits."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("receive_checks", HERE / "check_receive.py")
CHECK = importlib.util.module_from_spec(spec)
spec.loader.exec_module(CHECK)


class ReceiveStoreControls(unittest.TestCase):
    def setUp(self):
        self.document = json.loads((CHECK.BASIC.FIXTURES / "node-account-receive.json").read_bytes())

    def row(self, profile, method="AccountBlock"):
        return next(row for row in self.document["observations"] if row["profile"] == profile and row["method"] == method)

    def reject(self, edit):
        altered = copy.deepcopy(self.document); edit(altered)
        with self.assertRaises(CHECK.ACCOUNT.signatures.Refused): CHECK.check(altered)

    def test_complete_inventory(self):
        report = CHECK.check(self.document)
        self.assertEqual((report["recorded_MATCH"], report["recorded_REJECT"], report["recorded_PANIC"]), (23, 21, 0))
        self.assertEqual(report["recorded_database_reads_checked"], 120)
        self.assertEqual(report["complete_seeded_store_maps_checked"], 88)
        self.assertFalse(report["execution_eligibility_proven"])

    def test_receiver_gate_uses_ledger_frontier_not_acknowledgement(self):
        for profile, height, result in (("receiver-before-enforcement", CHECK.ENFORCEMENT_HEIGHT - 1, "MATCH"),
                                       ("receiver-at-enforcement", CHECK.ENFORCEMENT_HEIGHT, "REJECT"),
                                       ("receiver-after-enforcement", CHECK.ENFORCEMENT_HEIGHT + 1, "REJECT")):
            with self.subTest(profile=profile):
                row = self.row(profile)
                self.assertEqual(row["account_block"]["momentumAcknowledged"]["height"], 3000)
                self.assertEqual(row["store_plan"]["ledger_frontier_height"], height)
                self.assertEqual(row["node_method_result"], result)
                self.assertEqual(row["store_calls"][-1]["method"], "Account.IsReceived" if result == "MATCH" else "Momentum.Identifier")

    def test_absent_confirmation_is_recorded_not_inferred_authenticated(self):
        row = self.row("confirmation-missing")
        self.assertEqual(row["node_method_result"], "MATCH")
        self.assertEqual(row["database_reads"][-2]["error"], "not_found")
        self.assertTrue(row["database_reads"][-2]["key"].startswith("05"))
        self.assertFalse(self.document["scope"]["authenticated_context"])

    def test_empty_received_marker_is_present(self):
        row = self.row("received-empty")
        self.assertEqual(row["node_error"], "source_already_received")
        self.assertEqual(row["database_reads"][-1]["value"], "")
        self.assertEqual(row["database_reads"][-1]["error"], "")

    def test_empty_marker_and_deletion_tombstone_have_different_get_status(self):
        marker = next(r for r in self.row("received-empty")["account_entries"] if r["key"].startswith("06"))
        deleted = next(r for r in self.row("source-body-missing")["momentum_entries"] if r["key"].startswith("03") and r["value"] == "")
        self.assertEqual((marker["value"], deleted["value"]), ("", ""))
        self.assertEqual((marker["read_error"], deleted["read_error"]), ("", "not_found"))
        self.reject(lambda d: d["observations"][4]["momentum_entries"].__setitem__(5, dict(deleted, read_error="")))

    def test_missing_source_body_is_distinct_from_missing_index(self):
        header = self.row("source-header-missing")["database_reads"]
        body = self.row("source-body-missing")["database_reads"]
        self.assertEqual(len(body), len(header) + 1)
        self.assertTrue(header[-1]["key"].startswith("09"))
        self.assertTrue(body[-1]["key"].startswith("03"))
        self.assertEqual((header[-1]["error"], body[-1]["error"]), ("not_found", "not_found"))

    def test_incoherent_source_index_does_not_authenticate_history(self):
        row = self.row("source-index-other-original")
        self.assertEqual(row["node_method_result"], "MATCH")
        self.assertEqual(row["store_calls"][-2]["method"], "Momentum.Identifier")
        source_read = next(r for r in row["database_reads"] if r["key"].startswith("09"))
        self.assertNotIn(bytes.fromhex(row["account_block"]["fromBlockHash"]), bytes.fromhex(source_read["value"]))
        self.assertFalse(self.document["scope"]["full_node_validation"])

    def test_transaction_matches_do_not_read_protocol_stores(self):
        for row in self.document["observations"]:
            if row["method"] == "AccountBlockTransaction":
                with self.subTest(profile=row["profile"]):
                    self.assertEqual(row["database_reads"], [])
                    self.assertEqual([c["method"] for c in row["store_calls"]], ["Chain.GetAccountStore", "Chain.GetFrontierMomentumStore"])

    def test_source_pin_substitution(self): self.reject(lambda d: d["source"].update(commit="00" * 20))
    def test_input_pin_substitution(self): self.reject(lambda d: d["input_files_sha256"].update({"account-segments.json": "00" * 32}))
    def test_enforcement_height_substitution(self): self.reject(lambda d: d["source"].update(receiver_mismatch_enforcement_height=3000))
    def test_removed_or_duplicated_observation(self):
        self.reject(lambda d: d["observations"].pop())
        self.reject(lambda d: d["observations"].append(copy.deepcopy(d["observations"][0])))
    def test_reordered_methods(self): self.reject(lambda d: d["observations"].reverse())
    def test_bool_and_float_integer_aliases(self):
        self.reject(lambda d: d["observations"][0]["store_plan"].update(ledger_frontier_height=True))
        self.reject(lambda d: d["observations"][0]["account_block"].update(height=2.0))
    def test_changed_hash_and_signature_inputs(self):
        self.reject(lambda d: d["observations"][0].update(computed_hash="00" * 32))
        self.reject(lambda d: d["observations"][0]["account_block"].update(signature=None))
    def test_forged_method_outcomes(self):
        for index, row in enumerate(self.document["observations"]):
            with self.subTest(row=index):
                self.reject(lambda d: d["observations"][index].update(node_method_result="MATCH" if row["node_method_result"] == "REJECT" else "REJECT"))
    def test_wrong_error_precedence(self): self.reject(lambda d: d["observations"][2].update(node_error="hash_mismatch"))
    def test_store_calls_removed_added_or_rebound(self):
        self.reject(lambda d: d["observations"][0]["store_calls"].pop())
        self.reject(lambda d: d["observations"][0]["store_calls"].append({"method": "Chain.Start"}))
        self.reject(lambda d: d["observations"][0]["store_calls"][0]["identifier"].update(height=0))
    def test_seed_bytes_and_inventory(self):
        for field in ("account_entries", "momentum_entries"):
            with self.subTest(store=field):
                self.reject(lambda d: d["observations"][0][field][0].update(value="ff"))
                self.reject(lambda d: d["observations"][0][field].pop())
    def test_database_reads_bytes_keys_and_errors(self):
        self.reject(lambda d: d["observations"][0]["database_reads"][0].update(value="ff"))
        self.reject(lambda d: d["observations"][0]["database_reads"][0].update(key="09"))
        self.reject(lambda d: d["observations"][0]["database_reads"][-1].update(error=""))
    def test_dropped_or_reordered_database_reads(self):
        self.reject(lambda d: d["observations"][0]["database_reads"].pop())
        self.reject(lambda d: d["observations"][0]["database_reads"].reverse())
    def test_scope_inflation(self):
        for field in ("authenticated_context", "full_node_validation", "state_value_acceptance", "network_transport", "mailbox_or_contract_execution"):
            with self.subTest(field=field): self.reject(lambda d: d["scope"].update({field: True}))
    def test_unselected_field(self): self.reject(lambda d: d.update(activation=True))
    def test_duplicate_or_nonfinite_json(self):
        for raw in (b'{"observations":[],"observations":[]}', b'{"height":NaN}'):
            with self.subTest(raw=raw), tempfile.TemporaryDirectory() as work:
                path = Path(work) / "input.json"; path.write_bytes(raw)
                with self.assertRaises(CHECK.ACCOUNT.signatures.Refused): CHECK.ACCOUNT.read_selected(path, hashlib.sha256(raw).hexdigest())


if __name__ == "__main__": unittest.main()
