#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Shared-preimage losslessness and refusal controls, without node execution."""
import copy
import importlib.util
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


C = module("shared_raw_kv_controls", "raw_kv_roundtrip_successor_corpus.py")
F = module("shared_raw_kv_synthetic_fixtures", "check_raw_kv_roundtrip_successor_test.py")


class SharedRawKVCorpusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.expected = C.C.M.derive()
        cls.originals = tuple((policy, C.encoded(F.fixture(cls.expected, policy)))
                              for policy in C.C.M.POLICIES)
        cls.corpus = C.pack(cls.originals, cls.expected)

    def refused(self, change):
        value = copy.deepcopy(self.corpus)
        change(value)
        with self.assertRaises((ValueError, KeyError, TypeError, IndexError, AssertionError)):
            C.check(C.encoded(value), self.expected)

    def test_complete_semantics_and_raw_preimages_roundtrip(self):
        restored = C.unpack(self.corpus)
        for (_, original), (_, observed) in zip(self.originals, restored):
            C.C.P.exact(C.C.document(original, C.C.MAX_OBSERVATION_BYTES), observed)
        result = C.check(C.encoded(self.corpus), self.expected)
        self.assertEqual(sum(row["canonical_proof_positions"] for row in result["policies"]), 3015)
        self.assertEqual(result["shared_preimage_counts"], C.COUNTS)
        self.assertTrue(result["complete_raw_dump_and_proof_bytes_preserved"])
        self.assertFalse(result["original_transport_JSON_reconstructed"])
        self.assertFalse(result["reference_node_executed_by_this_checker"])
        self.assertLess(len(C.encoded(self.corpus)), sum(len(raw) for _, raw in self.originals))

    def test_boolean_negative_float_and_out_of_range_references_are_refused(self):
        for index in (True, -1, 0.0, C.COUNTS["record_orders"]):
            self.refused(lambda value, index=index:
                         value["observations"][0]["snapshots"][0].__setitem__("record_order", index))

    def test_missing_duplicate_or_unreferenced_preimages_are_refused(self):
        self.refused(lambda value: value["tables"]["records"].pop())
        self.refused(lambda value: value["tables"]["records"].append({"key": "ff", "value": "00"}))
        self.refused(lambda value: value["tables"]["records"].__setitem__(
            0, copy.deepcopy(value["tables"]["records"][1])))

    def test_changed_dump_preimage_is_not_hidden_by_references(self):
        self.refused(lambda value: value["tables"]["records"][0].__setitem__("value", "00"))

    def test_changed_proof_byte_and_identity_are_refused(self):
        self.refused(lambda value: value["tables"]["proofs"][0].__setitem__("proof", "00" * 99))
        self.refused(lambda value: value["observations"][0]["snapshots"][0]["proof_groups"][0]["identifier"].__setitem__(
            "hash", "0" * 64))

    def test_header_scope_and_transport_reconstruction_claims_are_refused(self):
        self.refused(lambda value: value.__setitem__("original_transport_JSON_reconstructed", True))
        self.refused(lambda value: value["observations"][0]["header"]["scope"].__setitem__("accepted_header_binding", True))
        self.refused(lambda value: value["observations"][0]["header"].__setitem__("dump_objects", {}))

    def test_shared_tables_do_not_authorize_partial_or_unbound_observations(self):
        self.refused(lambda value: value["observations"][0]["snapshots"].pop())
        self.refused(lambda value: value["observations"].reverse())
        self.refused(lambda value: value["observations"][0]["snapshots"][0]["proof_groups"].pop())
        self.refused(lambda value: value.__setitem__("unknown", False))

    def test_declared_transport_digests_are_metadata_not_recomputed_json(self):
        value = copy.deepcopy(self.corpus)
        # Original formatting and JSON field order are deliberately omitted.
        # Separate source-pinned execution metadata must bind these captures.
        value["observations"][0]["original_transport"]["sha256"] = "00" * 32
        restored = C.unpack(value)
        C.C.P.exact(restored[0][1], C.unpack(self.corpus)[0][1])
        self.assertFalse(value["original_transport_JSON_reconstructed"])


if __name__ == "__main__":
    unittest.main()
