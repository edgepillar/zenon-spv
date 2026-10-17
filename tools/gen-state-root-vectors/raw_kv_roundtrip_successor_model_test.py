#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Independent topology, identity, projection and proof controls for the oracle."""
from collections import Counter
import copy
import hashlib
import importlib.util
from pathlib import Path
import unittest


HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("raw_store_model_controls", HERE / "raw_kv_roundtrip_successor_model.py")
M = importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)


class RawStoreOracleControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.expected = M.derive()
        cls.history = M.logical_history()

    def records(self, policy="archive", store="64"):
        return M.store_records(self.expected, policy, store)

    def test_selected_keys_and_operations_are_finite_and_explicit(self):
        selected = self.expected["selection"]
        self.assertEqual(len(set(selected["keys"])), 64)
        self.assertEqual(len(selected["proof_keys"]), 9)
        self.assertEqual([row["identifier"]["height"] for row in selected["history"]], list(range(1, 66)))
        self.assertEqual(len(selected["query_identifiers"]), 130)
        self.assertEqual(self.expected["selection_sha256"], hashlib.sha256(M.encoded(selected)).hexdigest())

    def test_L1_empty_put_deletes_but_nonempty_zero_bytes_remain(self):
        key = M.raw_key(0)
        row = {"operation": "put", "key": key.hex(), "value": bytes(32).hex()}
        present = M.apply_operations({}, [row])
        self.assertEqual(present[key], bytes(32))
        self.assertEqual(M.apply_operations(present, [dict(row, value="")]), {})
        self.assertEqual(M.apply_operations(present, [dict(row, operation="delete", value="")]), {})
        for state in self.history.values():
            if state:
                for index in (0, 32):
                    self.assertEqual(state[M.raw_key(index)], bytes(32))
                for index in (1, 33, 64):
                    self.assertNotIn(M.raw_key(index), state)

    def test_excluded_domains_are_not_promoted_to_committed_state(self):
        ignored = [row for row in M.operations(1) if not M.fold_keep(bytes.fromhex(row["key"]))]
        self.assertEqual(len(ignored), 3)
        self.assertEqual(M.apply_operations({}, ignored), {})
        self.assertEqual(len(self.history[1]), 62)
        for state in self.history.values():
            self.assertTrue(all(M.fold_keep(key) and value for key, value in state.items()))

    def test_invalid_scalar_and_patch_shapes_are_refused(self):
        for value in (True, 0, -1, 66, 1.0):
            with self.assertRaises(ValueError):
                M.identifier(value)
        for value in (True, -1, 65, 1.0):
            with self.assertRaises(ValueError):
                M.raw_key(value)
        for row in ({}, {"operation": "delete", "key": M.raw_key(0).hex(), "value": "00"},
                    {"operation": "unknown", "key": "00", "value": "00"},
                    {"operation": "put", "key": "FF", "value": "00"}):
            with self.assertRaises(ValueError):
                M.apply_operations({}, [row])

    def test_single_leaf_storage_id_is_not_the_padded_commitment(self):
        path, value = hashlib.sha3_256(b"literal controlled path").digest(), bytes(32)
        root_id, root, nodes, edges = M.G.graph({path: value})
        self.assertEqual(root_id, hashlib.sha3_256(path + value).digest())
        self.assertEqual(nodes, {root_id: b"\x00" + path + value})
        self.assertEqual(edges, {})
        self.assertNotEqual(root_id, root)
        current = root_id
        index = int.from_bytes(path, "big")
        for bit in range(256):
            pair = M.B.ZERO + current if (index >> bit) & 1 else current + M.B.ZERO
            current = hashlib.sha3_256(pair).digest()
        self.assertEqual(root, current)

    def test_all_dumps_bind_counts_bytes_and_complete_record_maps(self):
        for policy in M.POLICIES:
            for name, store in self.expected["policies"][policy]["stores"].items():
                rows = self.records(policy, name)
                dumped = M.C.encode_dump(rows)
                self.assertEqual(M.C.decode_selected_dump(dumped, store["dump_selection"]), rows)
                self.assertEqual(store["record_manifest"], M.record_manifest(rows))
                self.assertEqual(store["dump_selection"]["records"], len(rows))
                self.assertLessEqual(len(rows), 32768)
                self.assertLessEqual(len(dumped), 8 << 20)

    def test_format_frontier_and_retained_hash_sidecars_are_exact(self):
        for policy in M.POLICIES:
            for name, store in self.expected["policies"][policy]["stores"].items():
                rows = dict(self.records(policy, name))
                self.assertEqual(rows[b"\x05"], b"\x03")
                frontier = store["frontier"]
                self.assertEqual(rows[b"\x00"], bytes.fromhex(frontier["hash"]) + frontier["height"].to_bytes(8, "big"))
                for row in store["retained"]:
                    height = row["identifier"]["height"]
                    self.assertEqual(rows[b"\x06" + height.to_bytes(8, "big")], bytes.fromhex(row["identifier"]["hash"]))
                    self.assertEqual(rows[b"\x03" + height.to_bytes(8, "big")],
                                     bytes.fromhex(self.expected["witnesses"][str(height)]["root_id"]))
                counts = Counter(key[0] for key in rows)
                self.assertEqual(counts[0], 1)
                self.assertEqual(counts[5], 1)
                self.assertEqual(counts[3], len(store["retained"]))
                self.assertEqual(counts[6], len(store["retained"]))

    def test_serialized_nodes_refcounts_and_reachability_agree(self):
        for policy in M.POLICIES:
            for name in ("64", "65", "60", "fork-61"):
                rows = dict(self.records(policy, name))
                nodes = {key[1:]: value for key, value in rows.items() if key[0] == 1}
                expected_refs, children = Counter(), {}
                roots = [value for key, value in rows.items() if key[0] == 3]
                for root in roots:
                    expected_refs[root] += 1
                for node, value in nodes.items():
                    if value[0] == 0:
                        self.assertEqual(node, hashlib.sha3_256(value[1:]).digest())
                        children[node] = ()
                    else:
                        self.assertEqual(value[0], 1)
                        self.assertEqual(len(value), 131)
                        self.assertLess(int.from_bytes(value[1:3], "big"), 256)
                        self.assertEqual(node, hashlib.sha3_256(value[3:35] + value[67:99]).digest())
                        children[node] = (value[35:67], value[99:131])
                        expected_refs.update(children[node])
                self.assertEqual(set(nodes), set(expected_refs))
                actual_refs = {key[1:]: int.from_bytes(value, "big") for key, value in rows.items() if key[0] == 2}
                self.assertEqual(actual_refs, dict(expected_refs))
                todo, seen = list(roots), set()
                while todo:
                    node = todo.pop()
                    if node in seen:
                        continue
                    seen.add(node)
                    self.assertIn(node, nodes)
                    todo.extend(children[node])
                self.assertEqual(seen, set(nodes))

    def test_retention_and_rollback_boundaries_are_not_inferred(self):
        expected = {"archive": {"64": list(range(1, 65)), "65": list(range(1, 66)),
                                 "60": list(range(1, 61)), "fork-61": list(range(1, 62))},
                    "retain-5": {"64": list(range(59, 65)), "65": list(range(60, 66)),
                                  "60": [60], "fork-61": [60, 61]}}
        for policy, stores in expected.items():
            for name, heights in stores.items():
                actual = self.expected["policies"][policy]["stores"][name]
                self.assertEqual([row["identifier"]["height"] for row in actual["retained"]], heights)
            flow = self.expected["policies"][policy]["flow"]
            self.assertEqual([row["stage"] for row in flow], list(M.STAGES))
            self.assertEqual(flow[0]["store"], flow[1]["store"])

    def test_equal_state_root_never_substitutes_for_retained_identity(self):
        for policy in M.POLICIES:
            store = self.expected["policies"][policy]["stores"]["fork-61"]
            wanted = self.expected["witnesses"]["61"]["root"]
            selected = [row for row in store["root_queries"] if row["identifier"]["height"] == 61]
            self.assertEqual(len(selected), 2)
            self.assertEqual(selected[0]["identifier"], M.identifier(61))
            self.assertEqual(selected[0]["error"], "version-hash-mismatch")
            self.assertEqual(selected[0]["proof_error"], "version-hash-mismatch")
            self.assertEqual(selected[1]["identifier"], M.identifier(61, "X"))
            self.assertEqual(selected[1]["error"], "")
            self.assertEqual(selected[1]["root"], wanted)
            rows = dict(self.records(policy, "fork-61"))
            changed = dict(rows)
            changed[b"\x00"] = bytes.fromhex(M.identifier(61)["hash"]) + (61).to_bytes(8, "big")
            changed[b"\x06" + (61).to_bytes(8, "big")] = bytes.fromhex(M.identifier(61)["hash"])
            self.assertNotEqual(M.record_manifest(tuple(sorted(changed.items()))), store["record_manifest"])
            self.assertEqual(changed[b"\x03" + (61).to_bytes(8, "big")], rows[b"\x03" + (61).to_bytes(8, "big")])

    def test_complete_canonical_proofs_include_zero_and_absence(self):
        for witness in self.expected["witnesses"].values():
            root = bytes.fromhex(witness["root"])
            self.assertEqual(len(witness["proofs"]), 9)
            for row in witness["proofs"]:
                proof = bytes.fromhex(row["proof"])
                decoded = M.B.decode_proof(proof)
                self.assertTrue(decoded["canonical"])
                self.assertEqual(M.B.proof_result(root, M.B.digest(bytes.fromhex(row["key"])),
                                                bytes.fromhex(row["value"]), proof, row["present"]), "match")
            self.assertTrue(witness["proofs"][0]["present"])
            self.assertEqual(witness["proofs"][0]["value"], bytes(32).hex())
            self.assertFalse(witness["proofs"][1]["present"])
            self.assertFalse(witness["proofs"][-1]["present"])

    def test_record_preimages_are_complete_shared_and_not_silently_rebound(self):
        used = set()
        for policy in M.POLICIES:
            for store in self.expected["policies"][policy]["stores"].values():
                used.update(store["record_order"])
        self.assertEqual(used, set(self.expected["record_objects"]))
        altered = copy.deepcopy(self.expected)
        record = altered["policies"]["archive"]["stores"]["64"]["record_order"][0]
        altered["record_objects"][record]["value"] = "00"
        with self.assertRaises(ValueError):
            M.store_records(altered, "archive", "64")
        altered = copy.deepcopy(self.expected)
        order = altered["policies"]["archive"]["stores"]["64"]["record_order"]
        order.reverse()
        with self.assertRaises(ValueError):
            M.store_records(altered, "archive", "64")

    def test_cached_oracle_bytes_do_not_expose_mutable_aliases(self):
        changed = M.derive()
        changed["source"]["source_blobs"] = 0
        self.assertEqual(M.derive()["source"]["source_blobs"], 467)

    def test_source_identity_and_acceptance_limits_remain_explicit(self):
        source = self.expected["source"]
        self.assertEqual(source["node_revision"], "9c71ae82fc983e16f914ae085d4034030c8ebe3b")
        self.assertEqual(source["selected_runtime_tree"], "e60c875a06361f04d05301c0e4c61fd429995c5a")
        self.assertEqual(source["experimental_disk_format"], 3)
        self.assertEqual(source["L1_fold_sha256"], "b3f9712b23c179aaf7bda3f7df98d04fd83b20be77d2eda41f43a6965525a1f3")
        self.assertIn("raw_kv_roundtrip_successor_model.py", self.expected["source_inputs"])
        scope = self.expected["scope"]
        self.assertEqual(scope["consumer_result"], "REFUSED")
        for field in ("node_backend_executed", "accepted_header_binding", "authenticated_snapshot_import",
                      "production_state_value_accepted", "representative_resources_qualified"):
            self.assertIs(scope[field], False)


if __name__ == "__main__":
    unittest.main(verbosity=2)
