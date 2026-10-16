#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Independent byte and finite-update controls; execute no node or subprocess."""
import hashlib
import importlib.util
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent


def module(name, file):
    spec = importlib.util.spec_from_file_location(name, HERE / file)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


B = module("genesis_model_old_byte_contract", "check.py")
D = module("genesis_model_old_dump_contract", "check_patch_decode.py")
L = module("genesis_model_bounded_layers", "genesis_sparse_model.py")
F = module("genesis_model_selected_witnesses", "genesis_witness_model.py")
I = module("genesis_model_source_input", "genesis_input_decode.py")


class GenesisModelControls(unittest.TestCase):
    def test_original_six_roots_and_canonical_proof_bytes(self):
        _, document = B.read_corpus(HERE / "testdata/candidate-v3-balances.json")
        B.check_corpus(document)
        roots = proofs = 0
        for state in document["states"]:
            leaves = {bytes.fromhex(row["path"]): bytes.fromhex(row["value"])
                      for row in state["leaves"]}
            selected = [row for row in document["proofs"]
                        if row["state"] == state["name"] and row["node_result"] == "match"
                        and B.decode_proof(bytes.fromhex(row["proof"]))["canonical"]]
            targets = list(dict.fromkeys(bytes.fromhex(row["path"]) for row in selected))
            root, actual, _ = L.model(leaves, targets)
            self.assertEqual(root.hex(), state["root"])
            roots += 1
            for row in selected:
                self.assertEqual(actual[bytes.fromhex(row["path"])].hex(), row["proof"])
                proofs += 1
        self.assertEqual((roots, proofs), (6, 22))

    def test_selected_forest_matches_full_layers_for_76_updates(self):
        comparisons = 0
        for size in (0, 1, 2, 3, 8):
            state = {hashlib.sha3_256(("old-control-" + str(i)).encode()).digest(): bytes([i]) * 32
                     for i in range(size)}
            selected = list(state) + [hashlib.sha3_256(b"absent-control").digest()]
            root, proofs, _ = L.model(state, selected)
            rows = [{"path": p.hex(), "value": state[p].hex() if p in state else None,
                     "proof": proofs[p].hex()} for p in selected]
            forest = F.Forest(root, rows)
            for i, position in enumerate(selected):
                for value in (b"\0" * 32, bytes([19 + i]) * 32, None, bytes([90 + i]) * 32):
                    if value is None:
                        state.pop(position, None)
                    else:
                        state[position] = value
                    actual = forest.update(position, value)
                    expected, proof_bytes, _ = L.model(state, selected)
                    self.assertEqual(actual, expected)
                    for p in selected:
                        self.assertEqual(forest.proof(p), proof_bytes[p])
                    comparisons += 1
        self.assertEqual(comparisons, 76)

    def test_empty_tree_has_zero_root_and_canonical_absence(self):
        target = b"\0" * 32
        root, proofs, _ = L.model({}, [target])
        self.assertEqual(root, b"\0" * 32)
        self.assertEqual(proofs[target], b"\0" * 99)
        self.assertEqual(B.proof_result(root, target, b"", proofs[target], False), "match")

    def test_present_zero_is_distinct_from_absence(self):
        target = b"\x80" + b"\0" * 31
        root, proofs, _ = L.model({target: b"\0" * 32}, [target])
        empty, absence, _ = L.model({}, [target])
        self.assertNotEqual(root, empty)
        self.assertNotEqual(proofs[target], absence[target])
        self.assertEqual(B.proof_result(root, target, b"\0" * 32, proofs[target], True), "match")

    def test_generic_present_empty_is_not_implicit_fold_deletion(self):
        target = b"\xff" * 32
        root, proofs, _ = L.model({target: b""}, [target])
        self.assertNotEqual(root, b"\0" * 32)
        self.assertEqual(proofs[target][0], 1)
        self.assertEqual(B.proof_result(root, target, b"", proofs[target], True), "match")

    def test_path_bit_edges_and_same_prefixes(self):
        positions = [0, 1, 1 << 255, (1 << 256) - 1]
        state = {p.to_bytes(32, "big"): bytes([i]) * 32 for i, p in enumerate(positions)}
        root, proofs, _ = L.model(state, list(state))
        for path, value in state.items():
            self.assertEqual(B.proof_result(root, path, value, proofs[path], True), "match")

    def test_layer_width_type_duplicate_and_work_bounds(self):
        malformed = [({b"short": b"x"}, []), ({}, [b"short"]),
                     ({}, [b"0" * 32, b"0" * 32]), ({b"0" * 32: "text"}, []),
                     ({}, [i.to_bytes(32, "big") for i in range(129)]),
                     ([], [])]
        for state, targets in malformed:
            with self.subTest(state_type=type(state).__name__, targets=len(targets)):
                with self.assertRaises(AssertionError):
                    L.model(state, targets)

    def test_forest_cannot_update_or_prove_an_unselected_path(self):
        root, proofs, _ = L.model({}, [b"\0" * 32])
        forest = F.Forest(root, [{"path": (b"\0" * 32).hex(), "value": None,
                                 "proof": proofs[b"\0" * 32].hex()}])
        for action in (lambda: forest.update(b"\1" * 32, b"x"),
                       lambda: forest.proof(b"\1" * 32)):
            with self.assertRaises(AssertionError):
                action()

    def test_independently_derived_source_address_and_token_bytes(self):
        # These bytes were also found in the complete source-derived batch;
        # this regression does not authenticate a genesis or network selection.
        self.assertEqual(I.bech("z1qp004vzesjnnxhcmlkwvyefj4gnr6a0vyh94sk", "z", 20).hex(),
                         "005efab05984a7335f1bfd9cc26532aa263d75ec")
        self.assertEqual(I.bech("zts1qsrxxxxxxxxxxxxxmrhjll", "zts", 10).hex(),
                         "04066318c6318c6318c6")

    def test_address_hrp_checksum_case_and_width_are_checked(self):
        address = "z1qp004vzesjnnxhcmlkwvyefj4gnr6a0vyh94sk"
        for raw, hrp, width in ((address.upper(), "z", 20), (address, "wrong", 20),
                                (address[:-1] + "q", "z", 20), (address, "z", 19),
                                ("z1qq", "z", 20)):
            with self.subTest(raw=raw), self.assertRaises((AssertionError, ValueError)):
                I.bech(raw, hrp, width)

    def test_batch_replay_order_and_counts_remain_separate(self):
        key = D.key(1)
        raw = D.record(1, key, b"first") + D.record(0, key) + D.record(1, key, b"\0" * 32)
        counts, state = I.counts_and_state(raw, D)
        self.assertEqual(state, {key: b"\0" * 32})
        self.assertEqual(counts, {"Puts": 2, "Deletes": 1, "KeyBytes": 96,
                                  "ValueBytes": 37, "BalancePuts": 2, "StoragePuts": 0})

    def test_partial_or_invalid_batch_is_not_a_complete_input(self):
        for raw in (D.complete() + b"\xff", D.complete()[:-1]):
            with self.subTest(bytes=len(raw)), self.assertRaises((AssertionError, D.Bounds)):
                I.counts_and_state(raw, D)

    def test_mapping_digest_is_order_independent_and_length_framed(self):
        self.assertEqual(I.mapping_sha({b"a": b"b", b"c": b"d"}),
                         I.mapping_sha({b"c": b"d", b"a": b"b"}))
        self.assertNotEqual(I.mapping_sha({b"a": b"bc"}), I.mapping_sha({b"ab": b"c"}))


if __name__ == "__main__":
    unittest.main(verbosity=2)
