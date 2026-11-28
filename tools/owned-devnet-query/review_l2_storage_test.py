# SPDX-License-Identifier: GPL-3.0-only
import copy
import hashlib
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import review_l2_storage as l2
from model import Refused


def sha3(data):
    return hashlib.sha3_256(data).digest()


class L2StorageControls(unittest.TestCase):
    contract = bytes.fromhex("11" * 32)
    key = bytes.fromhex("0001")
    path = sha3(contract + key)
    zero = bytes(32)

    def gateway(self, root, present, value, proof):
        return {"domainId": 1, "batchId": 0, "verified": False, "postStateRoot": root.hex(),
                "proofs": [{"path": self.path.hex(), "present": present,
                            "value": None if value is None else value.hex(), "proof": proof.hex()}]}

    def read(self, root, result):
        return l2.read_storage(1, 0, root, self.contract, self.key, proof_result=result)

    def single_leaf(self, value):
        leaf = sha3(self.path + value)
        root = leaf
        position = int.from_bytes(self.path, "big")
        for bit in range(256):
            root = sha3(self.zero + root if (position >> bit) & 1 else root + self.zero)
        raw = b"\1" + self.path + leaf + bytes(34) + len(value).to_bytes(4, "big") + value
        return root, raw

    def test_bound_empty_commitment(self):
        observed = l2.read_storage(1, 0, self.zero, self.contract, self.key, empty_root=True)
        self.assertEqual(observed["path"], self.path.hex())
        self.assertEqual(observed["proof_origin"], "local_empty_commitment")
        self.assertEqual((observed["proof_bytes"], observed["siblings"]), (99, 0))
        self.assertFalse(observed["present"])
        self.assertIsNone(observed["value_hex"])
        with self.assertRaisesRegex(Refused, "l2_empty_commitment_required"):
            l2.read_storage(1, 0, b"\xff" * 32, self.contract, self.key, empty_root=True)
        with self.assertRaisesRegex(Refused, "l2_witness_unavailable"):
            self.read(self.zero, None)

    def test_gateway_membership_uses_derived_path(self):
        with self.subTest("stored bytes"):
            value = b"\x00\xff"
            root, proof = self.single_leaf(value)
            observed = self.read(root, self.gateway(root, True, value, proof))
            self.assertEqual(observed["path"], self.path.hex())
            self.assertTrue(observed["present"])
            self.assertEqual(observed["value_hex"], "00ff")
        with self.subTest("present empty"):
            root, proof = self.single_leaf(b"")
            observed = self.read(root, self.gateway(root, True, b"", proof))
            self.assertTrue(observed["present"])
            self.assertEqual(observed["value_hex"], "")
            with self.assertRaises(Refused):
                self.read(root, self.gateway(root, False, None, proof))
        with self.subTest("absent"):
            proof = b"\0" + self.path + bytes(66)
            observed = self.read(self.zero, self.gateway(self.zero, False, None, proof))
            self.assertFalse(observed["present"])
            self.assertIsNone(observed["value_hex"])

    def test_gateway_cannot_select_root_or_identity(self):
        proof = b"\0" + self.path + bytes(66)
        result = self.gateway(self.zero, False, None, proof)
        for field, value, error in (("domainId", 2, "l2_gateway_batch"), ("batchId", 1, "l2_gateway_batch"),
                                    ("postStateRoot", "44" * 32, "l2_gateway_root"),
                                    ("verified", "true", "l2_gateway_result"), ("proofs", [], "l2_gateway_proof_count")):
            with self.subTest(field):
                changed = {**result, field: value}
                with self.assertRaisesRegex(Refused, error):
                    self.read(self.zero, changed)
        with self.assertRaisesRegex(Refused, "l2_gateway_path"):
            l2.read_storage(1, 0, self.zero, bytes.fromhex("22" * 32), self.key, proof_result=result)

    def test_altered_or_noncanonical_proof_fails_closed(self):
        raw = b"\0" + self.path + bytes(66)
        for proof, error in ((b"\0" + sha3(self.path) + bytes(66), "l2_storage_absence"),
                             (raw + b"\0", "l2_storage_absence_length"),
                             (raw[:65] + b"\x80" + bytes(31) + b"\x00\x01" + bytes(32),
                              "l2_storage_noncanonical_sibling")):
            with self.subTest(error):
                with self.assertRaisesRegex(Refused, error):
                    self.read(self.zero, self.gateway(self.zero, False, None, proof))
        result = self.gateway(self.zero, False, None, raw)
        for field, value in (("present", 0), ("value", ""), ("proof", "aa" * (l2.MAX_PROOF_BYTES + 1))):
            with self.subTest(field):
                changed = copy.deepcopy(result)
                changed["proofs"][0][field] = value
                with self.assertRaises(Refused):
                    self.read(self.zero, changed)

    def test_storage_path_bounds(self):
        self.assertEqual(l2.storage_path(self.contract, b""), sha3(self.contract))
        self.assertEqual(l2.storage_path(self.contract, bytes(32)), sha3(self.contract + bytes(32)))
        with self.assertRaisesRegex(Refused, "l2_storage_key"):
            l2.storage_path(self.contract, bytes(33))


if __name__ == "__main__":
    unittest.main()
