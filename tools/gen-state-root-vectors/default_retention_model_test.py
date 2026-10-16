#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Finite independent root/proof, horizon and bounded witness-batch controls."""
import copy
import hashlib
import importlib.util
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("selected_default_retention_model", HERE / "default_retention_model.py")
M = importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)


def key(index):
    return b"\x03" + index.to_bytes(20, "big") + b"\x03" + b"\x42" * 10


def fixture(size=9):
    leaves = {key(i): (100 + i).to_bytes(32, "big") for i in range(size)}
    storage = b"\x03" + b"\x90" * 20 + b"\x04" + b"storage-slot"
    leaves[storage] = b"contract-value"
    excluded = b"excluded-ledger-domain"
    absent = key(1000)
    targets = sorted(set(leaves) | {absent, excluded})
    root, _, _ = M.G.L.model({M.G.L.digest(k): v for k, v in leaves.items()}, [])
    rows, batches = M.initial_witnesses(leaves, targets, root)
    return leaves, root, rows, batches, absent, excluded


class DefaultRetentionModelControls(unittest.TestCase):
    def test_balance_selection_spans_the_source_instead_of_repeating_eight_keys(self):
        leaves = {key(i): i.to_bytes(32, "big") for i in range(35)}
        leaves[b"not-a-balance"] = b"ignored"
        chosen = M.select_balances(leaves, 8)
        self.assertEqual(chosen, [key(i) for i in (0, 4, 9, 14, 19, 24, 29, 34)])
        self.assertEqual(len(set(chosen)), 8)

    def test_full_256_key_selection_and_source_endpoints(self):
        leaves = {key(i): i.to_bytes(32, "big") for i in range(512)}
        chosen = M.select_balances(leaves)
        self.assertEqual(len(chosen), 256)
        self.assertEqual((chosen[0], chosen[-1]), (key(0), key(511)))
        self.assertEqual(len({k[1:21] for k in chosen}), 256)

    def test_selection_refuses_bad_counts_insufficient_source_or_non_uint256_values(self):
        for count in (True, False, 1, 257, -1, 2.0):
            with self.subTest(count=count), self.assertRaises(ValueError):
                M.select_balances({key(0): b"\0" * 32, key(1): b"\0" * 32}, count)
        with self.assertRaises(ValueError):
            M.select_balances({key(0): b"\0" * 32}, 2)
        with self.assertRaises(ValueError):
            M.select_balances({key(0): b"short", key(1): b"\0" * 32}, 2)

    def test_source_default_inclusive_horizon_and_adjacent_queries(self):
        self.assertEqual(M.checkpoint_heights(), [1, 15387, 15388, 15389, 32758, 32768])
        self.assertEqual((M.HISTORY_HEIGHT - M.RETENTION, M.RETENTION + 1), (15388, 17381))

    def test_horizon_bounds_do_not_accept_bool_or_a_nonadvancing_history(self):
        for height, retention in ((True, 2), (33, True), (2, 2), (10, 1), (65537, 2), (33, 33)):
            with self.subTest(height=height, retention=retention), self.assertRaises(ValueError):
                M.checkpoint_heights(height, retention)

    def test_delete_zero_and_nonzero_precedence_and_byte_order(self):
        keys = [key(0), key(1)]
        self.assertEqual(M.mutation(2, keys), (key(0), (1000002).to_bytes(32, "big")))
        self.assertEqual(M.mutation(7, keys), (key(1), b"\0" * 32))
        self.assertEqual(M.mutation(11, keys), (key(1), None))
        self.assertEqual(M.mutation(77, keys), (key(1), None))
        self.assertEqual(M.mutation_frame(2, key(0), b"\0" * 32),
                         b"\0" * 7 + b"\x02" + key(0) + b"\x01" + b"\0" * 32)
        self.assertEqual(M.mutation_frame(11, key(1), None), b"\0" * 7 + b"\x0b" + key(1) + b"\0")

    def test_invalid_mutation_shapes_are_refused(self):
        for action in (lambda: M.mutation(True, [key(0), key(1)]),
                       lambda: M.mutation(1, [key(0), key(1)]),
                       lambda: M.mutation(2, [b"wrong", key(1)]),
                       lambda: M.mutation_frame(2, key(0), b"short"),
                       lambda: M.mutation_frame(2, b"wrong", None)):
            with self.assertRaises(ValueError):
                action()

    def test_269_witnesses_use_three_bounded_complete_root_recomputations(self):
        leaves, root, _, _, _, _ = fixture(9)
        targets = [key(i) for i in range(269)]
        rows, batches = M.initial_witnesses(leaves, targets, root)
        self.assertEqual([b["selected_witness_paths"] for b in batches], [128, 128, 13])
        self.assertEqual(len(rows), 269)
        self.assertTrue(all(b["full_256_layer_graph_retained"] is False for b in batches))
        positions = {M.G.L.digest(k): v for k, v in leaves.items()}
        for i in (0, 128, 268):
            target = M.G.L.digest(targets[i])
            again, proofs, _ = M.G.L.model(positions, [target])
            self.assertEqual(again, root)
            self.assertEqual(rows[i]["proof"], proofs[target].hex())
        with self.assertRaises(AssertionError):
            M.G.L.model(positions, [M.G.L.digest(k) for k in targets[:129]])

    def test_witness_inventory_and_independent_root_are_pinned(self):
        leaves, root, _, _, _, _ = fixture(3)
        for targets in ([], [key(0), key(0)], [key(i) for i in range(385)]):
            with self.subTest(targets=len(targets)), self.assertRaises(ValueError):
                M.initial_witnesses(leaves, targets, root)
        with self.assertRaises(ValueError):
            M.initial_witnesses(leaves, [key(0)], b"\xff" * 32)

    def test_every_root_and_checkpoint_proof_matches_complete_state_recomputation(self):
        leaves, root, rows, _, absent, excluded = fixture(9)
        keys = M.select_balances(leaves, 5)
        query = [key(0), key(4), absent, excluded]
        expected, forest = M.history(root, rows, keys, query, height=33, retention=9)
        state = dict(leaves)
        frame = hashlib.sha256()
        for h in range(1, 34):
            if h > 1:
                raw_key, value = M.mutation(h, keys)
                frame.update(h.to_bytes(8, "big") + raw_key + (b"\0" if value is None else b"\1" + value))
                if value is None:
                    state.pop(raw_key, None)
                else:
                    state[raw_key] = value
            paths = [M.G.L.digest(k) for k in query]
            actual, proofs, _ = M.G.L.model({M.G.L.digest(k): v for k, v in state.items()}, paths)
            self.assertEqual(expected["roots"][h - 1], {"height": h, "root": actual.hex()})
            if str(h) in expected["checkpoints"]:
                for record, path in zip(expected["checkpoints"][str(h)], paths):
                    self.assertEqual(record["proof"], proofs[path].hex())
                    self.assertEqual(record["consumer_result"], "REFUSED")
        self.assertEqual(expected["mutation_frame_sha256"], frame.hexdigest())
        self.assertEqual(expected["final_root"], forest.root().hex())
        self.assertEqual((expected["horizon_inclusive"], expected["expected_pruned_roots"],
                          expected["expected_archive_roots"]), (24, 10, 33))

    def test_present_zero_remains_a_leaf_and_excluded_key_stays_absent(self):
        leaves, root, rows, _, absent, excluded = fixture(3)
        expected, forest = M.history(root, rows, [key(0), key(1)], [key(0), absent, excluded],
                                     height=15, retention=5)
        self.assertEqual(expected["mutation_counts"], {"Delete": 1, "present_zero": 2, "other_Put": 11})
        self.assertEqual(forest.values[M.G.F.digest(key(0))], b"\0" * 32)
        self.assertNotIn(M.G.F.digest(excluded), forest.values)
        for snapshot in expected["checkpoints"].values():
            self.assertFalse(snapshot[-1]["present_in_projection"])

    def test_corrupt_initial_proof_duplicate_witness_and_unselected_key_refuse(self):
        _, root, rows, _, _, _ = fixture(3)
        corrupt = copy.deepcopy(rows)
        raw = bytearray.fromhex(corrupt[0]["proof"])
        raw[-1] ^= 1
        corrupt[0]["proof"] = raw.hex()
        for witnesses, keys, query in ((corrupt, [key(0), key(1)], [key(0)]),
                                       (rows + [copy.deepcopy(rows[0])], [key(0), key(1)], [key(0)]),
                                       (rows, [key(0), key(2000)], [key(0)]),
                                       (rows, [key(0), key(1)], [key(2000)])):
            with self.assertRaises((ValueError, AssertionError)):
                M.history(root, witnesses, keys, query, 33, 9)

    def test_unvisited_malformed_mutation_key_is_still_refused(self):
        _, root, rows, _, _, _ = fixture(3)
        with self.assertRaises(ValueError):
            M.history(root, rows, [key(0), key(1), b"unvisited-invalid"], [key(0)], 3, 2)

    def test_selection_serialization_is_deterministic_and_not_network_acceptance(self):
        self.assertEqual(M.encoded({"b": 2, "a": 1}), b'{"a":1,"b":2}\n')
        with self.assertRaises(ValueError):
            M.derive(b"unselected source bytes", {})


if __name__ == "__main__":
    unittest.main(verbosity=2)
