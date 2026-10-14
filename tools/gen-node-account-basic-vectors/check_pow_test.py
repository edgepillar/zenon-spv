#!/usr/bin/env python3
"""Adverse controls for the selected PoW bytes, methods and evidence scope."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("pow_corpus_checks", HERE / "check_pow.py")
CHECK = importlib.util.module_from_spec(spec)
spec.loader.exec_module(CHECK)


class PoWControls(unittest.TestCase):
    def setUp(self):
        self.document = json.loads((CHECK.BASIC.FIXTURES / "node-account-pow.json").read_bytes())

    def reject(self, edit):
        altered = copy.deepcopy(self.document)
        edit(altered)
        with self.assertRaises(CHECK.ACCOUNT.signatures.Refused):
            CHECK.check(altered)

    def test_complete_inventory(self):
        r = CHECK.check(self.document)
        self.assertEqual((r["recorded_pow_probes"], r["recorded_account_method_calls"]), (32, 64))
        self.assertEqual((r["recorded_MATCH"], r["recorded_REJECT"], r["recorded_PANIC"]), (11, 53, 0))
        self.assertEqual((r["complete_seeded_store_maps_checked"], r["recorded_database_reads_checked"]), (128, 10))
        self.assertFalse(r["context_authenticated"])
        self.assertFalse(r["runtime_acceptance_changed"])

    def test_unsigned_upper_half_and_monotonic_thresholds(self):
        thresholds = [int(p["node_producer_threshold_decimal"]) for p in self.document["pow_probes"] if p["producer_threshold_status"] == "RETURNED"]
        self.assertEqual(thresholds, sorted(thresholds))
        for p in self.document["pow_probes"]:
            if int(p["difficulty_decimal"]) >= 1 << 63:
                self.assertGreater(int(p["node_producer_threshold_decimal"]), (1 << 63) - 1)
                self.assertFalse(p["node_nonce_matches"])

    def test_zero_difficulty_helper_is_not_called(self):
        zero = self.document["pow_probes"][:4]
        self.assertTrue(all(p["producer_threshold_status"] == "SKIPPED_ZERO_DIFFICULTY" for p in zero))
        self.assertTrue(all(p["node_producer_threshold_decimal"] == p["node_producer_threshold_le_hex"] == "" for p in zero))
        self.assertTrue(all(p["node_nonce_matches"] for p in zero))
        self.assertFalse(self.document["scope"]["zero_difficulty_producer_helper_called"])

    def test_matching_work_does_not_authorize_changed_hash(self):
        for p in self.document["pow_probes"]:
            if int(p["difficulty_decimal"]) > 0 and p["node_nonce_matches"]:
                rows = [r for r in self.document["observations"] if r["name"].startswith(p["name"] + "/")]
                self.assertEqual((rows[0]["node_method_result"], rows[1]["node_error"]), ("MATCH", "hash_mismatch"))
                self.assertNotEqual(rows[0]["computed_hash"], rows[0]["account_block"]["hash"])

    def test_zero_difficulty_skips_work_but_not_transaction_hash(self):
        rows = self.document["observations"][:8]
        self.assertTrue(all(r["node_method_result"] == "MATCH" for r in rows[::2]))
        self.assertEqual(rows[1]["node_method_result"], "MATCH")
        self.assertTrue(all(r["node_error"] == "hash_mismatch" for r in rows[3::2]))

    def test_failed_work_stops_before_acknowledgement_reads(self):
        failures = [r for r in self.document["observations"] if r["node_error"] == "pow_invalid"]
        self.assertEqual(len(failures), 22)
        for r in failures:
            self.assertEqual([c["method"] for c in r["store_calls"]], ["Chain.GetAccountStore", "Chain.GetFrontierMomentumStore", "Momentum.ChainIdentifier"])
            self.assertEqual(r["database_reads"], [])

    def test_transaction_method_does_not_read_protocol_stores(self):
        rows = [r for r in self.document["observations"] if r["method"] == "AccountBlockTransaction"]
        self.assertEqual(len(rows), 32)
        for r in rows:
            self.assertEqual(r["database_reads"], [])
            self.assertEqual([c["method"] for c in r["store_calls"]], ["Chain.GetAccountStore", "Chain.GetFrontierMomentumStore"])

    def test_original_hash_and_signature_are_preserved(self):
        original = CHECK.BASIC.expected_rows()[0]["account_block"]
        for r in self.document["observations"]:
            self.assertEqual(r["account_block"]["hash"], original["hash"])
            self.assertEqual(r["account_block"]["signature"], original["signature"])

    def test_source_pin_substitution(self):
        self.reject(lambda d: d["source"].update(commit="00" * 20))

    def test_function_inventory_substitution(self):
        self.reject(lambda d: d["source"]["functions"].append("pow.GetPoWNonce"))

    def test_input_pin_substitution(self):
        self.reject(lambda d: d["input_files_sha256"].update({"account-segments.json": "00" * 32}))

    def test_removed_or_duplicated_probe(self):
        self.reject(lambda d: d["pow_probes"].pop())
        self.reject(lambda d: d["pow_probes"].append(copy.deepcopy(d["pow_probes"][0])))

    def test_reordered_probes(self):
        self.reject(lambda d: d["pow_probes"].reverse())

    def test_removed_or_duplicated_method(self):
        self.reject(lambda d: d["observations"].pop())
        self.reject(lambda d: d["observations"].append(copy.deepcopy(d["observations"][0])))

    def test_reordered_methods(self):
        self.reject(lambda d: d["observations"].reverse())

    def test_numeric_bool_float_and_signed_aliases(self):
        for value in (True, 1.0, -1, 1 << 64):
            with self.subTest(value=value):
                self.reject(lambda d: d["observations"][0]["account_block"].update(difficulty=value))
        self.reject(lambda d: d["pow_probes"][0].update(difficulty_decimal=0))
        self.reject(lambda d: d["pow_probes"][0].update(node_nonce_matches=1))

    def test_nonce_width_order_and_binding(self):
        for value in ("00" * 7, "00" * 9, "0100000000000000", "g0" * 8):
            with self.subTest(nonce=value):
                self.reject(lambda d: d["pow_probes"][0].update(nonce_hex=value))

    def test_data_preimage_and_hash_binding(self):
        self.reject(lambda d: d["pow_probes"][0].update(data_preimage_hex="00" * 52))
        self.reject(lambda d: d["pow_probes"][0].update(node_data_hash="00" * 32))

    def test_nonce_preimage_binding(self):
        self.reject(lambda d: d["pow_probes"][1].update(nonce_preimage_hex=d["pow_probes"][0]["nonce_preimage_hex"]))

    def test_full_calculated_hash_is_checked(self):
        self.reject(lambda d: d["pow_probes"][0].update(node_calculated_hash=d["pow_probes"][0]["node_calculated_hash"][:16] + "00" * 24))

    def test_calculated_uint64_byte_order(self):
        self.reject(lambda d: d["pow_probes"][1].update(calculated_uint64_decimal=str(int.from_bytes(bytes.fromhex(d["pow_probes"][1]["node_calculated_hash"])[:8], "big"))))

    def test_high_difficulty_signed_target_regression(self):
        self.reject(lambda d: d["pow_probes"][20].update(node_producer_threshold_decimal="0"))
        self.reject(lambda d: d["pow_probes"][20].update(node_producer_threshold_decimal="-2"))

    def test_threshold_width_and_byte_order(self):
        self.reject(lambda d: d["pow_probes"][8].update(node_producer_threshold_le_hex=bytes.fromhex(d["pow_probes"][8]["node_producer_threshold_le_hex"])[::-1].hex()))
        self.reject(lambda d: d["pow_probes"][8].update(node_producer_threshold_le_hex="00" * 7))

    def test_forged_nonce_outcomes(self):
        for i in range(32):
            with self.subTest(probe=i):
                self.reject(lambda d: d["pow_probes"][i].update(node_nonce_matches=not d["pow_probes"][i]["node_nonce_matches"]))

    def test_forged_method_outcomes(self):
        for i in range(64):
            with self.subTest(method=i):
                self.reject(lambda d: d["observations"][i].update(node_method_result="MATCH" if d["observations"][i]["node_method_result"] == "REJECT" else "REJECT"))

    def test_changed_error_precedence(self):
        self.reject(lambda d: d["observations"][1].update(node_error="pow_invalid"))

    def test_changed_signature_or_rebound_claimed_hash(self):
        self.reject(lambda d: d["observations"][8]["account_block"].update(signature=None))
        self.reject(lambda d: d["observations"][8]["account_block"].update(hash=d["observations"][8]["computed_hash"]))

    def test_computed_account_hash_substitution(self):
        self.reject(lambda d: d["observations"][8].update(computed_hash="00" * 32))

    def test_store_calls_inventory_and_arguments(self):
        self.reject(lambda d: d["observations"][0]["store_calls"].pop())
        self.reject(lambda d: d["observations"][0]["store_calls"].append({"method": "Chain.Start"}))
        self.reject(lambda d: d["observations"][0]["store_calls"][0]["identifier"].update(height=1))

    def test_seed_bytes_inventory_and_order(self):
        self.reject(lambda d: d["observations"][0]["momentum_entries"][0].update(value="ff"))
        self.reject(lambda d: d["observations"][0]["momentum_entries"].pop())
        self.reject(lambda d: d["observations"][0]["momentum_entries"].reverse())

    def test_raw_reads_bytes_keys_errors_and_inventory(self):
        self.reject(lambda d: d["observations"][0]["database_reads"][0].update(value="ff"))
        self.reject(lambda d: d["observations"][0]["database_reads"][0].update(key="00"))
        self.reject(lambda d: d["observations"][0]["database_reads"][0].update(error="not_found"))
        self.reject(lambda d: d["observations"][0]["database_reads"].pop())

    def test_scope_inflation(self):
        for field in ("nonce_generation", "wallet_api_calls", "new_signatures_generated", "zero_difficulty_producer_helper_called", "full_node_validation", "authenticated_context", "canonicality", "consensus_finality", "state_value_acceptance", "network_transport"):
            with self.subTest(scope=field):
                self.reject(lambda d: d["scope"].update({field: True}))

    def test_unselected_field(self):
        self.reject(lambda d: d.update(network_activation=True))

    def test_duplicate_or_nonfinite_json(self):
        for raw in (b'{"pow_probes":[],"pow_probes":[]}', b'{"difficulty":NaN}'):
            with self.subTest(raw=raw), tempfile.TemporaryDirectory() as work:
                p = Path(work) / "input.json"
                p.write_bytes(raw)
                with self.assertRaises(CHECK.ACCOUNT.signatures.Refused):
                    CHECK.ACCOUNT.read_selected(p, hashlib.sha256(raw).hexdigest())

    def test_corpus_digest_substitution(self):
        p = CHECK.BASIC.FIXTURES / "node-account-pow.json"
        with self.assertRaises(CHECK.ACCOUNT.signatures.Refused):
            CHECK.ACCOUNT.read_selected(p, "00" * 32)

    def test_source_revision_cli_refusal(self):
        r = subprocess.run([sys.executable, "-I", "-B", str(HERE / "check_pow.py"), "--source-revision", "invalid"], capture_output=True, timeout=20)
        self.assertEqual(r.returncode, 1)
        self.assertEqual(r.stdout, b"")
        self.assertEqual(json.loads(r.stderr), {"status": "REFUSED", "stage": "node_account_pow_corpus"})


if __name__ == "__main__":
    unittest.main()
