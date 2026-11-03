#!/usr/bin/env python3
"""Small in-memory controls; no node, database, network or module cache."""

import copy
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location(
    "batch_witness_replay", Path(__file__).with_name("check_batch_entry_header_witness.py"))
replay = importlib.util.module_from_spec(spec)
spec.loader.exec_module(replay)


class ReplayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.corpus = replay.read_corpus()
        cls.harness = replay.HARNESS.read_bytes()

    def rejected(self, change):
        corpus = copy.deepcopy(self.corpus)
        change(corpus)
        with self.assertRaises((ValueError, KeyError)):
            replay.check_corpus(corpus, self.harness)

    def test_recorded_bytes(self):
        result = replay.check_corpus(self.corpus, self.harness)
        self.assertEqual((result["headers"], result["proofs"], result["ABI_fields"]), (3, 2, 17))
        self.assertFalse(result["production_qualified"])
        self.assertFalse(result["Ed25519_checked_by_Python"])

    def test_source_binding(self):
        self.rejected(lambda c: c["source"].update(revision="0" * 40))

    def test_harness_binding(self):
        with self.assertRaises(ValueError):
            replay.check_corpus(self.corpus, self.harness + b"\n")

    def test_original_failure_is_not_relabelled(self):
        self.rejected(lambda c: c["execution"]["prior_failed_capture"].update(outcome_preserved="SUCCESS"))

    def test_incomplete_execution(self):
        self.rejected(lambda c: c["execution"].update(output_complete=False))

    def test_execution_digest_binding(self):
        self.rejected(lambda c: c["execution"].update(output_sha256="0" * 64))

    def test_selected_network_claim(self):
        self.rejected(lambda c: c["scope"].update(selected_chain_69_executed=True))

    def test_boolean_scope_alias(self):
        self.rejected(lambda c: c["scope"].update(isolated_chain_100_fixture=1))

    def test_fixture_domain(self):
        self.rejected(lambda c: c["trace"].update(chain_id=69))

    def test_header_root_binding(self):
        self.rejected(lambda c: c["trace"]["bundle"]["momentums"][1].update(stateRoot="01" * 32))

    def test_full_key_binding(self):
        self.rejected(lambda c: c["trace"].update(ledger_key="00" * 35))

    def test_proof_root_binding(self):
        self.rejected(lambda c: c["trace"]["bundle"]["witness"].update(root="01" * 32))

    def test_value_hint(self):
        self.rejected(lambda c: c["trace"]["bundle"]["witness"].update(value=""))

    def test_noncanonical_zero_sibling(self):
        def change(c):
            witness = c["trace"]["bundle"]["witness"]
            raw = bytearray(replay.b64(witness["proof"]))
            self.assertEqual(raw[65] & 128, 0)
            raw[65] |= 128
            raw[97:99] = (int.from_bytes(raw[97:99], "big") + 1).to_bytes(2, "big")
            raw[99:99] = bytes(32)
            witness["proof"] = replay.base64.b64encode(raw).decode()
        self.rejected(change)

    def test_gateway_identity(self):
        self.rejected(lambda c: c["trace"]["bundle"]["gateway"].update(batchId=1))

    def test_all_stored_fields(self):
        gateway = self.corpus["trace"]["bundle"]["gateway"]
        names = set(gateway) - {"domainId", "batchId", "isFinalized"}
        self.assertEqual(len(names), 17)
        for name in sorted(names):
            with self.subTest(field=name):
                def change(c):
                    g = c["trace"]["bundle"]["gateway"]
                    old = g[name]
                    if type(old) is int:
                        g[name] = old + 1
                    elif name.endswith("Root") or name == "daHash":
                        g[name] = ("01" if old[:2] != "01" else "02") + old[2:]
                    else:
                        g[name] = old + "x"
                self.rejected(change)

    def test_frontier_hint_is_not_a_stored_field(self):
        changed = copy.deepcopy(self.corpus)
        changed["trace"]["bundle"]["gateway"]["isFinalized"] = True
        self.assertFalse(replay.check_corpus(changed, self.harness)["production_qualified"])

    def test_abi_padding_offset_integer_and_tail(self):
        value = replay.b64(self.corpus["trace"]["bundle"]["witness"]["value"])
        gateway = self.corpus["trace"]["bundle"]["gateway"]
        changed = bytearray(value)
        changed[544 + 32 + len(gateway["executorPillar"].encode())] = 1
        offset = bytearray(value)
        offset[14 * 32:15 * 32] = (544).to_bytes(32, "big")
        integer = bytearray(value)
        integer[0] = 1
        for raw in [changed, offset, integer, value + b"\0"]:
            with self.subTest(size=len(raw)), self.assertRaises(ValueError):
                replay.check_abi(raw, gateway)

    def test_schedule_entry(self):
        self.rejected(lambda c: c["test_selection"]["config"]["producer_schedule"]["entries"][0].update(timestamp_unix=0))

    def test_context_pin(self):
        self.rejected(lambda c: c["test_selection"].update(header_context="01" * 32))

    def test_exact_request(self):
        self.rejected(lambda c: c["test_selection"]["request"].update(batch_id=1))

    def test_query_fingerprint(self):
        self.rejected(lambda c: c["test_selection"].update(query_fingerprint="01" * 32))

    def test_duplicate_json(self):
        with self.assertRaises(ValueError):
            replay.json.loads('{"a":1,"a":2}', object_pairs_hook=replay.pairs)


if __name__ == "__main__":
    unittest.main()

