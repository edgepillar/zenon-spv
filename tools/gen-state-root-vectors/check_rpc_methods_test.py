#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Adversarial controls for actual methods and separately selected synthetic consumers."""
import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("candidate_rpc_method_oracle", HERE / "check_rpc_methods.py")
RPC = importlib.util.module_from_spec(spec)
spec.loader.exec_module(RPC)
WIRE, BYTE = RPC.WIRE, RPC.BYTE


class RPCMethodControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _, cls.document = BYTE.read_corpus(HERE / "testdata/candidate-rpc-methods.json")
        cls.rows = {row["input"]["name"]: row for row in cls.document["cases"]}

    def row(self, name):
        return copy.deepcopy(self.rows[name])

    def decision(self, row):
        return RPC.consumer_decision(row, WIRE.selected_context(row["input"]["binding_name"]))

    def refused(self, document):
        with self.assertRaises((ValueError, KeyError, TypeError, UnicodeError)):
            RPC.check_corpus(document)

    def test_all_actual_methods_match_independent_trace_and_result_inventories(self):
        report = RPC.check_corpus(self.document)
        self.assertEqual(report["method_cases"], 40)
        self.assertEqual(report["actual_method_observations"], {"GetProof": 25, "GetStateRoot": 15})
        self.assertEqual(report["recorded_call_events"], 160)
        self.assertFalse(report["actual_chain_stateTree_qualified"])
        self.assertFalse(report["production_acceptance_enabled"])

    def test_zero_height_refuses_before_store_lookup(self):
        for method in RPC.METHODS:
            row = self.row(method + "/zero-height")
            self.assertEqual(row["trace"], [{"method": "Zenon.Chain"}])
            self.assertEqual(row["error"]["code"], -32000)
            self.assertEqual(self.decision(row), "reference_error")

    def test_reference_version_gates_do_not_authorize_later_versions(self):
        for method in RPC.METHODS:
            for version in ("zero", "one", "two"):
                row = self.row(method + "/version-" + version)
                self.assertEqual(len(row["trace"]), 3)
                self.assertEqual(row["error"]["code"], -32000)
            for version in ("four", "max"):
                row = self.row(method + "/version-" + version)
                self.assertIsNone(row["error"])
                self.assertEqual(self.decision(row), "unsupported_reference_version")

    def test_lookup_errors_and_missing_momentum_stop_before_tree_calls(self):
        for method in RPC.METHODS:
            error = self.row(method + "/lookup-error")
            missing = self.row(method + "/missing-momentum")
            self.assertIsNotNone(error["momentum"])
            self.assertEqual(error["error"]["stub_error_identity"], "lookup")
            self.assertEqual(error["error"]["code"], -32101)
            self.assertIsNone(missing["momentum"])
            self.assertIsNone(missing["error"]["stub_error_identity"])
            self.assertEqual(len(error["trace"]), len(missing["trace"]))
            self.assertEqual(len(error["trace"]), 3)

    def test_proof_error_precedes_root_lookup_and_root_errors_discard_proofs(self):
        row = self.row("GetProof/proof-error-before-root-error")
        self.assertEqual(row["error"]["stub_error_identity"], "proof")
        self.assertEqual(row["error"]["code"], -32102)
        self.assertEqual(row["trace"][-1]["method"], "Chain.GetProof")
        self.assertEqual(row["result_json"], "null")
        row = self.row("GetProof/root-error")
        self.assertEqual(row["trace"][-1]["method"], "Chain.StateRoot")
        self.assertEqual(row["error"]["stub_error_identity"], "root")
        self.assertEqual(row["result_json"], "null")

    def test_nonzero_root_with_error_is_never_a_consumer_success(self):
        row = self.row("GetStateRoot/root-error")
        self.assertNotEqual(json.loads(row["result_json"]), BYTE.ZERO.hex())
        with mock.patch.object(WIRE, "research_binding", side_effect=AssertionError("must not decode errored result")):
            self.assertEqual(self.decision(row), "reference_error")
        self.assertEqual(RPC.check_corpus(self.document)["nonzero_root_error_results"], 1)

    def test_stub_readiness_and_retention_errors_only_qualify_forwarding(self):
        for method in RPC.METHODS:
            for kind in ("not-ready", "not-retained"):
                row = self.row(method + "/" + kind)
                self.assertIsNone(row["error"]["code"])
                self.assertEqual(row["error"]["stub_error_identity"], "proof" if method == "GetProof" else "root")
                self.assertEqual(self.decision(row), "reference_error")
        for field in ("actual_chain_stateTree_executed", "node_database_opened", "node_lifecycle_executed"):
            self.assertFalse(self.document["scope"][field])

    def test_full_store_hashheight_forwarding_does_not_select_consumer_identity(self):
        for method in RPC.METHODS:
            for name, decision in (("store-height-diff", "selected_height_mismatch"),
                                   ("store-hash-diff", "selected_header_identifier_mismatch")):
                row = self.row(method + "/" + name)
                self.assertIsNone(row["error"])
                identifier = row["trace"][-1]["identifier"]
                self.assertEqual(identifier, {"height": row["momentum"]["height"], "hash": row["momentum"]["hash"]})
                self.assertEqual(self.decision(row), decision)

    def test_nil_and_empty_request_keys_are_distinct_recorded_bytes(self):
        nil = self.row("GetProof/nil-key")
        empty = self.row("GetProof/empty-key")
        self.assertIsNone(nil["request_key_hex"])
        self.assertEqual(empty["request_key_hex"], "")
        self.assertIsNone(nil["trace"][3]["key_hex"])
        self.assertEqual(empty["trace"][3]["key_hex"], "")
        self.assertEqual(nil["result_json"], empty["result_json"])
        self.assertEqual(self.decision(nil), "selected_key_bound_or_type_refusal")
        self.assertEqual(self.decision(empty), "selected_key_mismatch")

    def test_nil_absence_stored_zero_and_present_empty_keep_distinct_meanings(self):
        zero = WIRE.decode_wire(self.row("GetProof/active-three")["result_json"])[0]
        absent = WIRE.decode_wire(self.row("GetProof/missing-token")["result_json"])[0]
        empty = WIRE.decode_wire(self.row("GetProof/present-empty")["result_json"])[0]
        self.assertEqual(zero, bytes(32))
        self.assertIsNone(absent)
        self.assertEqual(empty, b"")
        self.assertEqual(self.decision(self.row("GetProof/present-empty")), "unsupported_balance_value")

    def test_selected_balance_observations_remain_unsigned_research(self):
        for name, expected in (("active-three", {"present": True, "amount": "0"}),
                               ("present-one", {"present": True, "amount": "1"}),
                               ("missing-token", {"present": False, "amount": "0"})):
            row = self.row("GetProof/" + name)
            context = WIRE.selected_context(row["input"]["binding_name"])
            result = WIRE.research_binding(row["result_json"], row["input"]["binding_name"], context)
            self.assertEqual(result["typed_balance"], expected)
            self.assertFalse(context["header_authenticated"])
            self.assertFalse(context["network_profile_agreed"])

    def test_coherent_provider_root_and_proof_substitution_is_refused(self):
        row = self.row("GetProof/coherent-root-substitution")
        value, proof, root = WIRE.decode_wire(row["result_json"])
        key = BYTE.hex_bytes(row["request_key_hex"])
        self.assertEqual(BYTE.proof_result(root, BYTE.digest(key), value, proof, True), "match")
        self.assertEqual(self.decision(row), "wire_binding_refusal")
        self.assertEqual(self.decision(self.row("GetStateRoot/coherent-root-substitution")), "selected_root_mismatch")
        self.assertEqual(self.decision(self.row("GetProof/root-substitution")), "wire_binding_refusal")

    def test_nil_value_with_a_present_proof_does_not_become_absence(self):
        self.assertEqual(self.decision(self.row("GetProof/nil-value-present-proof")), "wire_binding_refusal")

    def test_key_preflight_and_value_allocation_bound_refusals(self):
        with mock.patch.object(WIRE, "research_binding", side_effect=AssertionError("must bound the selected key first")):
            self.assertEqual(self.decision(self.row("GetProof/oversized-key")), "selected_key_bound_or_type_refusal")
        row = self.row("GetProof/oversized-value")
        with mock.patch.object(WIRE.base64, "b64decode", wraps=WIRE.base64.b64decode) as decode:
            self.assertEqual(self.decision(row), "wire_binding_refusal")
            self.assertEqual(decode.call_count, 1)
            self.assertLessEqual(len(decode.call_args[0][0]), ((WIRE.MAX_VALUE_BYTES + 2) // 3) * 4)
        _, proof, root = WIRE.decode_wire(self.row("GetProof/active-three")["result_json"])
        row["result_json"] = WIRE.encode_wire(bytes([119]) * 4099, proof, root)
        with mock.patch.object(WIRE.base64, "b64decode", side_effect=AssertionError("larger encoded width must refuse before decoding")):
            self.assertEqual(self.decision(row), "wire_binding_refusal")

    def test_fixed_readonly_method_inventory_and_case_order_are_closed(self):
        for change in ("method", "order", "extra", "missing"):
            document = copy.deepcopy(self.document)
            if change == "method": document["cases"][0]["input"]["method"] = "UnselectedMethod"
            elif change == "order": document["cases"].reverse()
            elif change == "extra": document["cases"].append(copy.deepcopy(document["cases"][0]))
            else: document["cases"].pop()
            self.refused(document)

    def test_closed_fixture_shapes_scalar_types_and_error_codes(self):
        for mutate in (lambda d: d.update({"extra": True}),
                       lambda d: d["cases"][0]["input"].update({"height": False}),
                       lambda d: d["cases"][4]["momentum"].update({"version": True}),
                       lambda d: d["cases"][1]["error"].update({"code": -32101.0}),
                       lambda d: d["cases"][6]["trace"][-1]["identifier"].update({"height": "42"})):
            document = copy.deepcopy(self.document); mutate(document); self.refused(document)

    def test_selected_context_root_key_hash_version_pin_and_types_cannot_change(self):
        row = self.row("GetProof/active-three")
        selected = WIRE.selected_context("stored-zero")
        for field, value in (("root", "44" * 32), ("raw_key", "00" * 32), ("header_hash", "aa" * 32),
                             ("header_version", 4), ("context_pin", "00" * 32), ("header_height", "42"),
                             ("header_authenticated", True)):
            with self.assertRaises(ValueError):
                RPC.consumer_decision(row, selected | {field: value})

    def test_wire_duplicate_fields_malformed_flags_and_trailing_bytes_refuse(self):
        original = self.row("GetProof/active-three")
        value, proof, root = WIRE.decode_wire(original["result_json"])
        variants = [original["result_json"][:-1] + ',"root":"' + root.hex() + '"}',
                    WIRE.encode_wire(value, proof + bytes([0]), root),
                    WIRE.encode_wire(value, bytes([255]) + proof[1:], root),
                    WIRE.encode_wire(None, proof, root)]
        for wire in variants:
            row = copy.deepcopy(original); row["result_json"] = wire
            self.assertEqual(self.decision(row), "wire_binding_refusal")

    def test_bounded_file_duplicate_fields_and_four_previous_corpora(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.json"
            path.write_text('{"format_version":1,"format_version":1}')
            with self.assertRaises(ValueError): BYTE.read_corpus(path)
            path.write_bytes(b" " * (BYTE.MAX_FILE_BYTES + 1))
            with self.assertRaises(ValueError): BYTE.read_corpus(path)
        for filename, pin in (("candidate-v3-balances.json", "8b69cdaf78ae4eeaad79cdfa493ed9633a1202e09819178da83e17be385f00d3"),
                              ("candidate-l1-fold-filter.json", "0a68118625d0f5df3497dd8d35ce39b9e0df3eb7dc8ccd73e703408031ff45ea"),
                              ("candidate-l1-applier.json", "08eeda1a69331109c50918f5f2a13eac2b0a9f52605d95dda1349fa1ac2e297e"),
                              ("candidate-state-proof-wire.json", "b7556e25de724f59aa1ff0b8551d527f9033769c7e4c195da1f4634bb1bdeca0")):
            self.assertEqual(RPC.hashlib.sha256((HERE / "testdata" / filename).read_bytes()).hexdigest(), pin)

    def test_source_scope_production_claims_and_cli_revision_are_strict(self):
        for field in RPC.SCOPE:
            document = copy.deepcopy(self.document); document["scope"][field] = not document["scope"][field]
            self.refused(document)
        document = copy.deepcopy(self.document); document["source"]["revision"] = "00" * 20; self.refused(document)
        for value in ("00", "A" * 40, "0" * 39 + "g"):
            with self.assertRaises(ValueError), contextlib.redirect_stdout(io.StringIO()): RPC.main(["--source-revision", value])
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()): RPC.main(["--unknown-mode"])
        output = io.StringIO()
        with contextlib.redirect_stdout(output): RPC.main(["--source-revision", "12" * 20])
        self.assertEqual(json.loads(output.getvalue())["source_revision"], "12" * 20)


if __name__ == "__main__":
    unittest.main(verbosity=2)
