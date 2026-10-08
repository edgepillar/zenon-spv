#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Adversarial controls for offline envelopes, argument forwarding and selections."""
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("candidate_dispatcher_oracle", HERE / "check_dispatcher.py")
DSP = importlib.util.module_from_spec(spec)
spec.loader.exec_module(DSP)
RPC, WIRE, BYTE = DSP.RPC, DSP.WIRE, DSP.BYTE


class DispatcherControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _, cls.document = BYTE.read_corpus(HERE / "testdata/candidate-rpc-dispatcher.json")
        cls.rows = {row["input"]["name"]: row for row in cls.document["cases"]}

    def row(self, name):
        return copy.deepcopy(self.rows[name])

    def decision(self, row):
        return DSP.consumer_decision(row, DSP.selected_consumer(row["input"]))

    def refused(self, document):
        with self.assertRaises((ValueError, KeyError, TypeError, UnicodeError)):
            DSP.check_corpus(document)

    def test_all_finite_requests_match_independent_bytes_calls_and_envelopes(self):
        report = DSP.check_corpus(self.document)
        self.assertEqual(report["dispatcher_cases"], 86)
        self.assertEqual([row["input"] for row in self.document["cases"]], DSP.selected_inputs())
        self.assertTrue(report["reference_http_handler_executed_in_memory"])
        self.assertFalse(report["http_listener_started"])
        self.assertFalse(report["native_reference_rpc_dispatcher_execution"])
        self.assertFalse(report["production_acceptance_enabled"])

    def test_integer_string_and_numeric_lexeme_ids_remain_distinct(self):
        for name, token in (("method/GetProof/active-three", "7"), ("codec/string-id", '"selected-7"'),
                            ("codec/fraction-id", "7.0"), ("codec/exponent-id", "7e0")):
            row = self.row(name)
            self.assertIn('"id":' + token + ',', row["response_body"])
            self.assertEqual(len(row["delegated_calls"]), 1)
        self.assertEqual(self.decision(self.row("codec/string-id")), "research_balance_match")
        for name in ("fraction-id", "exponent-id"):
            self.assertEqual(self.decision(self.row("codec/" + name)), "request_policy_refusal")

    def test_object_and_array_ids_refuse_before_delegation(self):
        for name in ("object-id", "array-id"):
            row = self.row("codec/" + name)
            self.assertEqual(row["delegated_calls"], [])
            self.assertEqual(row["trace"], [{"method": "Zenon.Chain"}])
            reply = json.loads(row["response_body"])
            self.assertIsNone(reply["id"])
            self.assertEqual(reply["error"]["code"], -32600)

    def test_null_boolean_and_wide_ids_do_not_select_consumer_requests(self):
        for name in ("null-id", "boolean-id", "wide-id"):
            row = self.row("codec/" + name)
            self.assertEqual(len(row["delegated_calls"]), 1)
            self.assertIn("result", json.loads(row["response_body"]))
            self.assertEqual(self.decision(row), "request_policy_refusal")

    def test_notifications_execute_only_readonly_delegate_without_a_reply(self):
        row = self.row("codec/notification")
        self.assertEqual(row["delegated_calls"], [{"method": "GetProof", "height": 42, "key_hex": RPC.selected_key("balance").hex()}])
        self.assertEqual(row["response_body"], "")
        self.assertEqual(self.decision(row), "request_policy_refusal")

    def test_duplicate_fields_and_trailing_input_never_become_consumer_success(self):
        for name in ("duplicate-id", "duplicate-params", "trailing-object", "trailing-garbage"):
            row = self.row("codec/" + name)
            self.assertEqual(len(row["delegated_calls"]), 1)
            self.assertIn("result", json.loads(row["response_body"]))
            self.assertEqual(self.decision(row), "request_policy_refusal")

    def test_exact_uint64_heights_and_null_zero_have_separate_error_gates(self):
        for name in ("negative-height", "fraction-height", "exponent-height", "text-height", "boolean-height", "overflow-height"):
            row = self.row("codec/" + name)
            self.assertEqual(row["delegated_calls"], [])
            self.assertEqual(json.loads(row["response_body"])["error"]["code"], -32602)
        row = self.row("codec/null-height")
        self.assertEqual(row["delegated_calls"][0]["height"], 0)
        self.assertEqual(len(row["trace"]), 1)
        self.assertEqual(json.loads(row["response_body"])["error"]["code"], -32000)
        row = self.row("codec/max-height")
        self.assertEqual(row["trace"][2]["height"], 2**64 - 1)
        self.assertEqual(row["trace"][-1]["identifier"]["height"], 42)
        self.assertEqual(self.decision(row), "request_policy_refusal")

    def test_missing_named_null_and_excess_arguments_stop_before_method_calls(self):
        for name in ("missing-params", "null-params", "named-params", "missing-key", "excess-params"):
            row = self.row("codec/" + name)
            self.assertEqual(row["delegated_calls"], [])
            self.assertEqual(len(row["trace"]), 1)
            self.assertEqual(json.loads(row["response_body"])["error"]["code"], -32602)

    def test_raw_base64_key_nil_and_byte_array_calls_keep_exact_forwarding(self):
        selected = RPC.selected_key("balance").hex()
        row = self.row("method/GetProof/active-three")
        self.assertEqual(row["delegated_calls"][0]["key_hex"], selected)
        self.assertEqual(row["trace"][-2]["key_hex"], selected)
        nil, array = self.row("codec/null-key"), self.row("codec/array-key")
        self.assertIsNone(nil["delegated_calls"][0]["key_hex"])
        self.assertIsNone(nil["trace"][-2]["key_hex"])
        self.assertEqual(array["delegated_calls"][0]["key_hex"], selected)
        self.assertEqual(self.decision(nil), "request_policy_refusal")
        self.assertEqual(self.decision(array), "request_policy_refusal")

    def test_invalid_base64_and_byte_array_elements_refuse_before_delegate(self):
        for name in ("bad-base64", "unpadded-base64", "invalid-byte-array"):
            row = self.row("codec/" + name)
            self.assertEqual(row["delegated_calls"], [])
            self.assertEqual(json.loads(row["response_body"])["error"]["code"], -32602)

    def test_error_envelopes_discard_nonzero_root_and_never_decode_success_data(self):
        row = self.row("method/GetStateRoot/root-error")
        reply = json.loads(row["response_body"])
        self.assertEqual(set(reply), {"jsonrpc", "id", "error"})
        self.assertEqual(reply["error"]["code"], -32103)
        with mock.patch.object(WIRE, "research_binding", side_effect=AssertionError("errored data must not decode")):
            self.assertEqual(self.decision(row), "reference_error")
        reply["result"] = WIRE.selected_context("stored-zero")["root"]
        row["response_body"] = DSP.compact(reply)
        self.assertEqual(self.decision(row), "response_envelope_refusal")

    def test_http_validation_health_and_metadata_size_limits_are_scoped(self):
        for name, status in (("wrong-content-type", 415), ("put-method", 405), ("declared-oversize", 413)):
            row = self.row("codec/" + name)
            self.assertEqual(row["http_status"], status)
            self.assertEqual(row["delegated_calls"], [])
            self.assertEqual(self.decision(row), "request_policy_refusal")
        health = self.row("codec/health-get")
        self.assertEqual(health["http_status"], 200)
        self.assertEqual(health["response_body"], "")
        large = self.row("codec/declared-oversize")
        self.assertLess(len(large["input"]["request_json"]), 200)
        self.assertEqual(large["input"]["declared_content_length"], 5242881)
        self.assertEqual(self.decision(self.row("codec/options-method")), "request_policy_refusal")

    def test_ignored_version_fields_and_unknown_fields_are_research_policy_refusals(self):
        for name in ("missing-version", "wrong-version", "unknown-field"):
            row = self.row("codec/" + name)
            self.assertEqual(len(row["delegated_calls"]), 1)
            self.assertIn("result", json.loads(row["response_body"]))
            self.assertEqual(self.decision(row), "request_policy_refusal")
        for name in ("unknown-method", "unknown-namespace"):
            row = self.row("codec/" + name)
            self.assertEqual(row["delegated_calls"], [])
            self.assertEqual(json.loads(row["response_body"])["error"]["code"], -32601)

    def test_coherent_provider_root_and_proof_cannot_replace_selected_context(self):
        row = self.row("method/GetProof/coherent-root-substitution")
        self.assertIn("result", json.loads(row["response_body"]))
        self.assertEqual(self.decision(row), "wire_binding_refusal")
        self.assertEqual(self.decision(self.row("method/GetStateRoot/coherent-root-substitution")), "selected_root_mismatch")
        for name in ("store-height-diff", "store-hash-diff", "version-four", "version-max"):
            row = self.row("method/GetProof/" + name)
            self.assertNotEqual(self.decision(row), "research_balance_match")

    def test_selected_zero_positive_absence_and_present_empty_keep_distinct_results(self):
        for name in ("active-three", "present-one", "missing-token"):
            row = self.row("method/GetProof/" + name)
            self.assertEqual(self.decision(row), "research_balance_match")
        present = json.loads(self.row("method/GetProof/active-three")["response_body"])["result"]
        absent = json.loads(self.row("method/GetProof/missing-token")["response_body"])["result"]
        self.assertIsNotNone(present["value"])
        self.assertIsNone(absent["value"])
        self.assertEqual(self.decision(self.row("method/GetProof/present-empty")), "unsupported_balance_value")
        for name in ("nil-value-present-proof", "oversized-value"):
            self.assertEqual(self.decision(self.row("method/GetProof/" + name)), "wire_binding_refusal")

    def test_response_ids_versions_duplicates_trailing_and_mixed_payloads_refuse(self):
        selected = self.row("method/GetProof/active-three")
        reply = json.loads(selected["response_body"])
        changes = [{"id": "7"}, {"id": 7.0}, {"id": True}, {"jsonrpc": "1.0"}, {"extra": 0},
                   {"error": {"code": -32000, "message": "synthetic"}}]
        for change in changes:
            row = copy.deepcopy(selected)
            row["response_body"] = DSP.compact(reply | change)
            self.assertEqual(self.decision(row), "response_envelope_refusal")
        for body in (selected["response_body"] + " {}", selected["response_body"].replace('"id":7', '"id":7,"id":7', 1),
                     '{"jsonrpc":"2.0","id":7}', '{"jsonrpc":"2.0","id":7,"error":{"code":true,"message":"x"}}',
                     '{"jsonrpc":"2.0","id":7,"error":{"code":-32000,"message":"x","data":0}}'):
            row = copy.deepcopy(selected)
            row["response_body"] = body
            self.assertEqual(self.decision(row), "response_envelope_refusal")
        for field, value in (("version", 3.0), ("height", 42.0), ("height", True), ("hash", None), ("state_root", "00")):
            row = copy.deepcopy(selected)
            row["momentum"][field] = value
            self.assertEqual(self.decision(row), "response_envelope_refusal")

    def test_closed_fixture_shapes_inventory_order_and_scalar_types_are_strict(self):
        for update in ({"format_version": True}, {"format_version": 1.0}, {"unknown": False}):
            self.refused(self.document | update)
        for field, value in (("http_status", 200.0), ("http_status", True), ("response_body", None), ("delegated_calls", {})):
            document = copy.deepcopy(self.document)
            document["cases"][0][field] = value
            self.refused(document)
        document = copy.deepcopy(self.document)
        document["cases"][0], document["cases"][1] = document["cases"][1], document["cases"][0]
        self.refused(document)
        self.refused(self.document | {"cases": self.document["cases"][:-1]})

    def test_message_byte_and_character_bounds_precede_json_or_base64_allocation(self):
        for text in (" " * (DSP.MAX_MESSAGE_BYTES + 1), "é" * (DSP.MAX_MESSAGE_BYTES // 2 + 1)):
            with mock.patch.object(DSP.json, "loads", side_effect=AssertionError("oversize message decoded")):
                with self.assertRaises(ValueError):
                    DSP.bounded_json(text)
        row = self.row("method/GetProof/active-three")
        chosen = json.loads(row["input"]["request_json"])
        chosen["params"][1] = "A" * (((WIRE.MAX_KEY_BYTES + 2) // 3) * 4 + 4)
        row["input"]["request_json"] = DSP.compact(chosen)
        with mock.patch.object(WIRE.base64, "b64decode", side_effect=AssertionError("oversize key decoded")):
            self.assertEqual(self.decision(row), "request_policy_refusal")

    def test_scope_context_pin_profile_and_source_revision_cannot_change(self):
        for field in ("http_listener_started", "actual_chain_stateTree_executed", "node_database_opened", "profile_agreed", "runtime_state_proof_acceptance"):
            document = copy.deepcopy(self.document)
            document["scope"][field] = True
            self.refused(document)
        row = self.row("method/GetProof/active-three")
        for field, value in (("profile", "candidate-production"), ("accepted_VerifiedState_binding", True), ("request_id", 8)):
            selection = DSP.selected_consumer(row["input"]) | {field: value}
            with self.assertRaises(ValueError):
                DSP.consumer_decision(row, selection)
        selection = DSP.selected_consumer(row["input"])
        selection["context"]["context_pin"] = "00" * 32
        with self.assertRaises(ValueError):
            DSP.consumer_decision(row, selection)
        with self.assertRaises(ValueError), contextlib.redirect_stdout(io.StringIO()):
            DSP.main(["--source-revision", "invalid"])

    def test_file_bounds_duplicate_fields_and_five_previous_corpora_are_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.json"
            for raw in (b'{"cases":[],"cases":[]}', b" " * (BYTE.MAX_FILE_BYTES + 1)):
                path.write_bytes(raw)
                with self.assertRaises(ValueError):
                    BYTE.read_corpus(path)
        pins = {"candidate-rpc-methods.json": "049a6e954682a142af91dfa64b723a3316056c527ea6e9439e452933bb0791cc",
                "candidate-state-proof-wire.json": "b7556e25de724f59aa1ff0b8551d527f9033769c7e4c195da1f4634bb1bdeca0",
                "candidate-l1-applier.json": "08eeda1a69331109c50918f5f2a13eac2b0a9f52605d95dda1349fa1ac2e297e",
                "candidate-l1-fold-filter.json": "0a68118625d0f5df3497dd8d35ce39b9e0df3eb7dc8ccd73e703408031ff45ea",
                "candidate-v3-balances.json": "8b69cdaf78ae4eeaad79cdfa493ed9633a1202e09819178da83e17be385f00d3"}
        for name, pin in pins.items():
            self.assertEqual(hashlib.sha256((HERE / "testdata" / name).read_bytes()).hexdigest(), pin)


if __name__ == "__main__":
    unittest.main(verbosity=2)
