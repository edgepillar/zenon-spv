# SPDX-License-Identifier: MIT
"""Negative controls for the three-witness independent byte oracle."""
import copy
import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location("batch_context_oracle", Path(__file__).with_name("check_batch_context.py"))
ORACLE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ORACLE)


class BatchContextBytes(unittest.TestCase):
    def setUp(self):
        self.unit = ORACLE.read_fixture("batch-context-unit.json", ORACLE.UNIT_SHA)
        self.trace = ORACLE.read_fixture("batch-context-node-witness.json", ORACLE.TRACE_SHA)

    def test_original_math_and_synthetic_fingerprints(self):
        report = ORACLE.check(self.unit, self.trace)
        self.assertEqual(report["root_checks"], 4)
        self.assertFalse(report["selected_network_or_production_state_value_accepted"])

    def test_every_row_path_value_proof_and_root(self):
        for index in range(4):
            for field in ("path_hex", "proof_hex", "ledger_key_hex"):
                with self.subTest(row=index, field=field):
                    trace = copy.deepcopy(self.trace)
                    raw = bytearray.fromhex(trace["rows"][index][field])
                    raw[-1] ^= 1
                    trace["rows"][index][field] = raw.hex()
                    with self.assertRaises(ValueError):
                        ORACLE.check(self.unit, trace)

    def test_context_request_and_network_claim_changes(self):
        mutations = [
            lambda u, t: u["config"]["query_profile"]["limits"].update(max_total_siblings=7),
            lambda u, t: u["config"]["query_profile"]["domain_record"].update(max_dynamic_bytes=511),
            lambda u, t: u["config"]["query_profile"]["domain_config"].update(max_proof_bytes=8358),
            lambda u, t: u["request"].update(batch_id=1),
            lambda u, t: u["request"].update(height=88),
            lambda u, t: u["headers"][0].update(stateRoot="00"*32),
            lambda u, t: t.update(source_fixture_values_are_one_original_snapshot=True),
            lambda u, t: t.update(node_chain_wallet_RPC_or_transactions_started=True),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(mutation=index):
                unit, trace = copy.deepcopy(self.unit), copy.deepcopy(self.trace)
                mutate(unit, trace)
                with self.assertRaises(ValueError):
                    ORACLE.check(unit, trace)


if __name__ == "__main__":
    unittest.main()
