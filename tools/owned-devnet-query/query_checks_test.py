# SPDX-License-Identifier: GPL-3.0-only
"""Original source bytes and synthetic workflow controls, without native runs."""
import argparse
import base64
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys
import unittest

sys.dont_write_bytecode = True
HERE = Path(__file__).absolute().parent
sys.path.insert(0, str(HERE))
import model
import query_checks as q

FIXTURES = HERE.parents[1] / "internal/testdata/conformance"


def fixture(name, digest=None):
    raw = (FIXTURES / name).read_bytes()
    assert len(raw) < 256 << 10
    if digest is not None:
        assert hashlib.sha256(raw).hexdigest() == digest
    return json.loads(raw)


class QueryCheckTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.unit = fixture("batch-context-unit.json", "e4bfbdb7bff55f9719782c7e609240b2ba9aeefd0d0f42b7ee1948286e890366")
        cls.trace = fixture("batch-context-node-witness.json", "773cda402e08709ffd73adfea355f73269b1470b7336c5a027ddd5b331ab9d96")

    def witnesses(self):
        return {row["name"]: {"root": self.trace["root_hex"],
            "value": base64.b64encode(bytes.fromhex(row["value_hex"])).decode(),
            "proof": base64.b64encode(bytes.fromhex(row["proof_hex"])).decode()}
            for row in self.trace["rows"][:3]}

    def test_legacy_independent_fingerprints_match_the_retained_golden(self):
        got = q.fingerprints(self.unit["config"], self.unit["request"])
        for name, value in got.items():
            self.assertEqual(value, self.unit["expected"][name])

    def test_v2_namespace_and_source_rule_match_separate_native_golden_values(self):
        config = deepcopy(self.unit["config"])
        profile = config["query_profile"]
        profile["version"] = profile["entry"]["version"] = 2
        profile["entry"]["source_rule"] = "zenon-phase1-batch-fields/v1"
        request = deepcopy(self.unit["request"])
        pins = q.fingerprints(config)
        request["context"] = pins["context"]
        pins = q.fingerprints(config, request)
        # These pins are also frozen independently in the existing native
        # source-rule controls. This test does not execute those native tests.
        self.assertEqual(pins["entry_context"], "93cdf8e13f5a4251b6c6d978d41e79550399482b7b8f47979a2e962b13107c25")
        self.assertEqual(pins["context"], "478088778573e6080c550c686c7434928bf4f16d0306daea6fe5416090cb91fd")
        self.assertEqual(pins["query"], "b9b542757c5f0c1cdc1b982f153ad875450e57ea5a91bc247cefaa81e62b4f9e")
        for wrong in (1, 3):
            bad = deepcopy(config)
            bad["query_profile"]["entry"]["version"] = wrong
            with self.assertRaises(model.Refused):
                q.fingerprints(bad)

    def test_schedule_holes_and_changed_slots_do_not_reuse_a_context(self):
        for change in (lambda s: s["entries"].pop(),
                       lambda s: s["entries"][0].update(timestamp_unix=123),
                       lambda s: s["entries"][0].update(producing_addr="00" * 20)):
            config = deepcopy(self.unit["config"])
            change(config["producer_schedule"])
            with self.assertRaises(model.Refused):
                q.fingerprints(config)
        changed = deepcopy(self.unit["config"])
        changed["header_profile"]["source"] = "changed non-authoritative audit label"
        self.assertEqual(q.fingerprints(changed), q.fingerprints(self.unit["config"]))

    def test_exact_request_height_tip_and_batch_change_query_identity(self):
        original = q.fingerprints(self.unit["config"], self.unit["request"])
        for name in ("height", "tip_height", "batch_id"):
            request = deepcopy(self.unit["request"])
            request[name] += 1
            self.assertNotEqual(q.fingerprints(self.unit["config"], request)["query"], original["query"])
        changed = deepcopy(self.unit["request"])
        changed["context"] = "0" * 64
        with self.assertRaisesRegex(model.Refused, "independent_request_context"):
            q.fingerprints(self.unit["config"], changed)

    def test_original_pooled_proofs_match_only_locally_derived_keys_and_same_root(self):
        profile = self.unit["config"]["query_profile"]
        checked = q.witness_rows(profile, 0, self.trace["root_hex"], self.witnesses())
        self.assertEqual(checked["totals"]["proof"], 1781)
        self.assertEqual(checked["totals"]["value"], 1312)
        for row in self.trace["rows"][:3]:
            member = checked["memberships"][row["name"]]
            self.assertEqual(member["ledger_key"], row["ledger_key_hex"])
            self.assertEqual(member["path"], row["path_hex"])
        # These original trie outputs pool ABI fixtures, not a real ledger.
        self.assertFalse(self.trace["source_fixture_values_are_one_original_snapshot"])

    def test_wrong_key_root_value_and_missing_supporting_row_are_refused(self):
        profile, root = self.unit["config"]["query_profile"], self.trace["root_hex"]
        with self.assertRaises(model.Refused):
            q.witness_rows(profile, 1, root, self.witnesses())
        with self.assertRaises(model.Refused):
            q.witness_rows(profile, 0, "1" * 64, self.witnesses())
        for name in ("batch_entry", "domain_record", "domain_config"):
            for action in ("omit", "value", "root"):
                rows = self.witnesses()
                if action == "omit":
                    del rows[name]
                elif action == "value":
                    rows[name]["value"] = base64.b64encode(b"wrong").decode()
                else:
                    rows[name]["root"] = "1" * 64
                with self.subTest(name=name, action=action):
                    with self.assertRaises(model.Refused):
                        q.witness_rows(profile, 0, root, rows)

    def test_proof_and_value_aggregate_caps_remain_independent(self):
        for key in ("max_total_proof_bytes", "max_total_value_bytes", "max_total_siblings"):
            profile = deepcopy(self.unit["config"]["query_profile"])
            profile["limits"][key] = 0
            with self.assertRaises(model.Refused):
                q.witness_rows(profile, 0, self.trace["root_hex"], self.witnesses())

    def test_synthetic_rpc_headers_hash_to_the_independently_retained_hashes(self):
        for row, expected in zip(self.unit["momentums"], self.unit["headers"]):
            got = q.header_facts(row)
            self.assertEqual(got["hash"], expected["hash"])
            self.assertFalse(got["signature_verified_by_this_calculation"])
        for field, changed in (("height", 123), ("nextFusionPrice", 123), ("stateRoot", "1" * 64),
                ("producer", "z1" + "q" * 38), ("data", "AA=="), ("chainIdentifier", True)):
            row = deepcopy(self.unit["momentums"][0])
            row[field] = changed
            with self.subTest(field=field):
                with self.assertRaises(model.Refused):
                    q.header_facts(row)

    def test_decoded_rows_equal_the_original_node_abi_fields(self):
        profile = self.unit["config"]["query_profile"]
        rows = {row["name"]: bytes.fromhex(row["value_hex"]) for row in self.trace["rows"][:3]}
        decoded = q.decode_rows(profile, rows)
        # The pooled workflow deliberately changes its submission/finalization
        # heights. It is not byte-identical to the original ABI-case set.
        self.assertEqual(decoded["entry"]["SubmittedAtHeight"], self.trace["stored_submission_height"])
        self.assertEqual(decoded["entry"]["FinalizeAtHeight"], self.trace["stored_finalize_height"])
        for name, schema, caps in (("batch-entry-abi.json", q.ENTRY_SCHEMA,
                {"ExecutorPillar": 4096, "AssetFlowSummary": 4096, "ProofData": 4096}),
                ("domain-context-abi.json", q.RECORD_SCHEMA, {"ProfileConfig": 4096, "ChainBinding": 4096})):
            facts = fixture(name)
            for case in facts.get("cases", facts.get("records")):
                raw = bytes.fromhex(case["packed_hex"])
                if case["name"] == "non-utf8-packer":
                    with self.assertRaises(UnicodeError):
                        q.decode_abi(raw, schema, caps, 4096, 4096)
                    continue
                actual = q.decode_abi(raw, schema, caps, 4096, 4096)
                for field, value in actual.items():
                    key = field[0].lower() + field[1:]
                    if type(value) is bytes or field == "ExecutorPillar":
                        key += "Hex"
                        value = (value.encode() if type(value) is str else value).hex()
                    self.assertEqual(value, case["fields"][key], (name, case["name"], field))
        self.assertEqual(decoded["domain_config"], {"WithdrawalDelay": 30, "RuntimeUpgradeDelay": 64})

    def test_abi_offsets_padding_high_bits_and_trailing_data_are_refused(self):
        profile = self.unit["config"]["query_profile"]
        original = {row["name"]: bytes.fromhex(row["value_hex"]) for row in self.trace["rows"][:3]}
        mutations = []
        for offset, byte in ((0, 1), (11*32+31, 0), (544+32+39, 255)):
            raw = bytearray(original["batch_entry"])
            raw[offset] = byte
            mutations.append(bytes(raw))
        mutations.append(original["batch_entry"] + b"\0")
        for raw in mutations:
            with self.assertRaises(model.Refused):
                q.decode_rows(profile, {**original, "batch_entry": raw})

    def test_canonical_base64_and_address_checksums_are_required(self):
        for text in ("AB==", "AA==\n", "AA", None):
            with self.assertRaises(model.Refused):
                q.binary(text, 32)
        address = bytes.fromhex("00" + "12" * 19)
        self.assertEqual(q.address_bytes(q.address_text(address)), address)
        with self.assertRaises(model.Refused):
            q.address_bytes(q.address_text(address)[:-1] + "q")

    def test_consumer_requires_owned_result_and_independently_compares_gateway_fields(self):
        # The existing trie fixture supplies all three proof/ABI byte strings.
        # The envelope is a synthetic projection of the selected CLI schema.
        config, request, root = self.unit["config"], self.unit["request"], self.trace["root_hex"]
        witnesses = self.witnesses()
        checked = q.witness_rows(config["query_profile"], request["batch_id"], root, witnesses)
        pins = self.unit["expected"]
        context = {"fingerprint": pins["context"]}
        scope = "EXPERIMENTAL_CONFIGURED_HEADER_THREE_ROW_MEMBERSHIP"

        def encode(row):
            return {key: base64.b64encode(value).decode("ascii") if type(value) is bytes else value
                    for key, value in row.items()}

        fields = encode(checked["decoded"]["entry"])
        gateway = {key[0].lower() + key[1:]: value for key, value in fields.items()}
        gateway.update(domainId=1, batchId=0, isFinalized=False)
        result = {"scope": scope, "request": request, "query_fingerprint": pins["query"],
                  "root": root, "context": context}
        result.update({name: encode(value) for name, value in checked["decoded"].items()})
        for name, kind in (("batch_membership", "batch_entry"), ("record_membership", "domain_record"),
                           ("config_membership", "domain_config")):
            result[name] = encode(checked["memberships"][kind])
        report = {"schema_version": 1, "command": "query-experimental-batch-context", "status": "matched",
            "scope": scope, "exit_code": 0, "error": None, "production_state_value_guarantee": False,
            "persistence": "read_only", "rpc_requests": 0, "headers": {"outcome": "ACCEPT"},
            "header_context": {"fingerprint": pins["header_context"]}, "query_context": context,
            "gateway_comparison_requested": True, "result": result, "gateway_comparison": {
                "stored_fields_match": True, "frontier_is_finalized_hint": False,
                "frontier_identity_authenticated": False}}
        provider = {"witnesses": witnesses, "gateway": gateway}
        self.assertTrue(q.consumer_result(report, config, request, provider, root)["gateway_stored_fields_match"])
        for altered in (dict(report, rpc_requests=False),
                        dict(report, headers={"outcome": "REFUSE"}),
                        dict(report, result=dict(result, request=dict(request, batch_id=False))),
                        dict(report, result=dict(result, root="1" * 64))):
            with self.assertRaises(model.Refused):
                q.consumer_result(altered, config, request, provider, root)
        gateway["executorPillar"] += "Changed"
        with self.assertRaisesRegex(model.Refused, "consumer_gateway_comparison"):
            q.consumer_result(report, config, request, provider, root)
        report["gateway_comparison"]["stored_fields_match"] = False
        self.assertFalse(q.consumer_result(report, config, request, provider, root)["gateway_stored_fields_match"])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-revision")
    args = parser.parse_args()
    if args.source_revision is not None:
        model.digest(args.source_revision, model.HEX40)
    result = unittest.TextTestRunner(stream=sys.stderr, verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__]))
    sys.stdout.buffer.write(model.canonical({"format": "owned-devnet-query-byte-controls/v1",
        "source_revision": args.source_revision, "root_tests": result.testsRun,
        "errors": len(result.errors), "failures": len(result.failures), "skipped": len(result.skipped),
        "successful": result.wasSuccessful(), "scope": "ORIGINAL_POOLED_ABI_PROOFS_AND_SYNTHETIC_CONTEXTS",
        "real_devnet_or_native_verifier_executed": False}))
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
