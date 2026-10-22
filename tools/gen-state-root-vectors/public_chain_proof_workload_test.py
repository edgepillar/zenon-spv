#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Portable independent-byte/source controls; no reference process is launched."""
import copy
import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("proof_workload_portable_preparation", HERE / "prepare_public_chain_proof_workload.py")
P = importlib.util.module_from_spec(spec)
spec.loader.exec_module(P)
M = P.M


class ProofWorkloadControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import json
        raw = P.fixtures()
        cls.selection = json.loads(raw["selection"])
        cls.expected = json.loads(raw["expectations"])

    def refuse(self, change):
        selected, expected = copy.deepcopy(self.selection), copy.deepcopy(self.expected)
        change(selected, expected)
        with self.assertRaises((ValueError, KeyError, TypeError, AssertionError)):
            M.check_expected(selected, expected)

    def test_complete_independent_canonical_witnesses(self):
        result = M.check_expected(self.selection, self.expected)
        self.assertEqual(result["independent_canonical_witnesses_checked"], 128)
        self.assertEqual(result["ordered_requests"], 4096)
        self.assertEqual(sorted(self.expected["selected_balance_token_distribution"].values()), [3, 77])
        self.assertFalse(result["accepted_header_binding"])

    def test_small_token_family_keeps_the_full_balance_budget(self):
        a, b = b"\x11" * 10, b"\x22" * 10
        leaves = {}
        for token, count in ((a, 100), (b, 3)):
            for i in range(count):
                leaves[b"\x03" + i.to_bytes(20, "big") + b"\x03" + token] = (i+1).to_bytes(32, "big")
        for i in range(40):
            leaves[b"\x03" + bytes(20) + b"\x04" + i.to_bytes(4, "big")] = bytes([i+1]) * (i+1)
        state = dict(leaves)
        state.update({b"\x01" + i.to_bytes(8, "big"): b"excluded" for i in range(8)})
        rows = M.targets(state, leaves)
        balances = [key for domain, key in rows if domain == "balance"]
        self.assertEqual(len(rows), 128)
        self.assertEqual(len(balances), 80)
        self.assertEqual(sum(key[22:] == b for key in balances), 3)
        self.assertEqual(len({key for _, key in rows}), 128)
        storage = [key for domain, key in rows if domain == "contract_storage"]
        self.assertTrue(set(sorted((key for key in leaves if key[21] == 4), key=lambda k: (-len(leaves[k]), k))[:16]).issubset(storage))

    def test_nil_empty_and_stored_zero_have_distinct_frames(self):
        root, key, proof = bytes(32), b"selected-key", b"proof-bytes"
        self.assertEqual(len({M.framed(root, key, value, proof) for value in (None, b"", bytes(32))}), 3)

    def test_root_and_value_substitution_refused(self):
        self.refuse(lambda s,e: e.update(expected_root="00"*32))
        self.refuse(lambda s,e: e["expected_rows"][0].update(value_hex="ff"*32))

    def test_rehashed_corrupt_proof_still_refused(self):
        def change(selected, expected):
            row = expected["expected_rows"][0]
            raw = bytearray.fromhex(row["proof_hex"])
            raw[100] ^= 1
            proof = bytes(raw)
            row.update(proof_hex=proof.hex(), proof_sha256=hashlib.sha256(proof).hexdigest(),
                       row_sha256=M.framed(bytes.fromhex(row["root"]), bytes.fromhex(row["raw_key"]), bytes.fromhex(row["value_hex"]), proof).hex())
        self.refuse(change)

    def test_selected_key_and_order_are_bound(self):
        self.refuse(lambda s,e: s["keys"].reverse())
        self.refuse(lambda s,e: e["expected_rows"].reverse())
        self.refuse(lambda s,e: e.update(ordered_request_rows_sha256="00"*32))

    def test_projection_absence_cannot_claim_ledger_absence(self):
        def change(s,e):
            row = next(row for row in e["expected_rows"] if row["domain"] == "excluded_ledger_key")
            row["ledger_raw_input_has_key"] = False
        self.refuse(change)

    def test_counters_are_not_booleans_or_floats(self):
        for value in (True, 4096.0, -1):
            self.refuse(lambda s,e: s.update(requests=value))
            self.refuse(lambda s,e: e.update(requests=value))
        self.refuse(lambda s,e: e.update(source_balance_rows_checked=True))
        self.refuse(lambda s,e: s.update(workers=[True,4,16]))

    def test_unknown_fields_and_acceptance_claims_refused(self):
        self.refuse(lambda s,e: s.update(unselected_network="network"))
        self.refuse(lambda s,e: e.update(production_qualified=True))
        self.refuse(lambda s,e: e["expected_rows"][0].update(accepted_header=True))
        for name in ("accepted_header_binding", "production_state_value_accepted"):
            self.refuse(lambda s,e: s.update({name: True}))
            self.refuse(lambda s,e: e.update({name: True}))
        self.refuse(lambda s,e: e.update(consumer_result="ACCEPT"))

    def test_prepared_runtime_and_ordinary_build_are_separate(self):
        result = P.plan(Path("unused-proof-workspace"), "selected-go")
        self.assertEqual(result["runtime_tree"], M.RUNTIME_TREE)
        self.assertNotEqual(result["build_tree"], M.RUNTIME_TREE)
        self.assertEqual(result["source_blobs"], 472)
        self.assertEqual(result["ordinary_builds"], 1)
        self.assertEqual(result["ordinary_processes"], 4)
        self.assertNotIn("-race", result["build_argv"])
        self.assertNotIn("-cover", result["build_argv"])
        self.assertFalse(result["reference_backend_executed"])
        self.assertFalse(result["Node_or_wallet_or_network_execution_selected"])
        self.assertEqual(result["cases"][-1], {"workers": 4, "reopen": True, "root_role": "fresh-16-closed"})

    def test_changed_probe_refused_before_staging(self):
        original = P.P.read_regular
        def read(path, limit):
            raw = original(path, limit)
            return raw + b"\n" if Path(path).name == P.PROBE else raw
        with patch.object(P.P, "read_regular", side_effect=read), self.assertRaises(ValueError):
            P.build_pins()

    def test_existing_or_overlapping_destination_refused_before_source_read(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            source = root / "source"
            source.mkdir()
            existing = root / "existing"
            existing.mkdir()
            for destination in (existing, source / "nested", source):
                with patch.object(M, "snapshot_source", side_effect=AssertionError("must not read source")) as reader:
                    with self.assertRaises(ValueError):
                        P.prepare(source, destination, "selected-go")
                    reader.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
