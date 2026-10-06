#!/usr/bin/env python3
"""Controls for the independent, bounded consumer comparison oracle."""

import copy
import importlib.util
import json
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("consumer_oracle", Path(__file__).with_name("check-query-consumer.py"))
oracle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(oracle)


class OracleControls(unittest.TestCase):
    def test_all_selected_decisions_are_pinned(self):
        cases = oracle.cases()
        self.assertEqual(len({case["id"] for case in cases}), len(cases))
        for case in cases:
            with self.subTest(case=case["id"]):
                self.assertEqual(oracle.consume(case["report"], case["expectations"], case["process_exit"]), case["wanted"])

    def test_published_context_vectors(self):
        root = Path(__file__).resolve().parents[1] / "internal/testdata/verification-context"
        vectors = sorted(root.glob("*.json"))
        self.assertGreaterEqual(len(vectors), 2)
        for vector in vectors:
            with self.subTest(vector=vector.name):
                context = json.loads(vector.read_bytes())
                self.assertEqual(oracle.context_fingerprint(context), context["fingerprint"])

    def test_decoded_duplicate_keys(self):
        for raw in (b'{"x":0,"x":1}', b'{"x":0,"\\u0078":1}', b'{"\\ud800":0,"\\udfff":1}'):
            with self.subTest(raw=raw):
                with self.assertRaises(oracle.Invalid):
                    oracle.bounded_json(raw)

    def test_unicode_normalization_and_byte_bounds(self):
        self.assertEqual(oracle.bounded_json(b'["\\ud800","\\udfff","\\ud83d\\ude80"]'), ["\ufffd", "\ufffd", "\U0001f680"])
        oracle.bounded_json(oracle.encoded(["\U0001f680" * 1024]))
        with self.assertRaises(oracle.Invalid):
            oracle.bounded_json(oracle.encoded(["\U0001f680" * 1025]))

    def test_depth_and_value_boundaries(self):
        oracle.bounded_json(b"[" * 16 + b"0" + b"]" * 16)
        with self.assertRaises(oracle.Invalid):
            oracle.bounded_json(b"[" * 17 + b"0" + b"]" * 17)
        values = [[0] * 127 for _ in range(128)]
        values[0].pop()
        oracle.bounded_json(oracle.encoded(values))  # 16,384 values including containers.
        values[0].append(0)
        with self.assertRaises(oracle.Invalid):
            oracle.bounded_json(oracle.encoded(values))

    def test_object_array_and_key_boundaries(self):
        for value in ([0] * 256, {str(i): 0 for i in range(256)}, {"x" * 128: 0}):
            oracle.bounded_json(oracle.encoded(value))
        for value in ([0] * 257, {str(i): 0 for i in range(257)}, {"x" * 129: 0}):
            with self.assertRaises(oracle.Invalid):
                oracle.bounded_json(oracle.encoded(value))

    def test_lexical_and_typed_integer_boundaries(self):
        for token in (b"-0", b"0.0", b"0e0", b"NaN", b"1" * 22):
            with self.assertRaises(oracle.Invalid):
                oracle.bounded_json(token)
        for kind, low, high in (("u32", 0, (1 << 32) - 1), ("u64", 0, oracle.U64_MAX),
                                ("i64", -(1 << 63), oracle.I64_MAX)):
            for value in (low, high):
                self.assertEqual(oracle.typed(oracle.JSONInteger(str(value)), kind), value)
            for value in (low - 1, high + 1):
                with self.assertRaises(oracle.Invalid):
                    oracle.typed(oracle.JSONInteger(str(value)), kind)
        with self.assertRaises(oracle.Invalid):
            oracle.typed(True, "u64")

    def test_optional_required_and_nullable_shapes(self):
        schema = {"required": "u64", "optional": ("optional", "u64"), "nullable": ("nullable", "text")}
        self.assertEqual(oracle.decode(b'{"required":0,"nullable":null}', schema), {"required": 0, "nullable": None})
        for raw in (b'{"required":null,"nullable":null}', b'{"required":0,"optional":null,"nullable":null}',
                    b'{"nullable":null}', b'{"required":0,"Nullable":null}'):
            with self.assertRaises(oracle.Invalid):
                oracle.decode(raw, schema)

    def test_fingerprint_change_is_detected(self):
        report, _ = oracle.selected_inputs()
        context = report["verification_context"]
        self.assertTrue(oracle.valid_context(context))
        for field in ("w", *oracle.LIMITS, "retain_headers"):
            changed = copy.deepcopy(context)
            changed["policy"][field] += 1
            self.assertFalse(oracle.valid_context(changed))

    def test_status_precedes_every_input(self):
        self.assertEqual(oracle.consume(b"not JSON", b"not JSON", -9), oracle.summary("process_failure"))
        for value in (True, -(1 << 63) - 1, 1 << 63):
            with self.assertRaises(oracle.Invalid):
                oracle.consume(b"", b"", value)

    def test_permissive_match_mutant_is_detected(self):
        original = oracle.match
        try:
            oracle.match = lambda report, expected: None
            for case in oracle.cases():
                if case["id"] in {"missing_target", "wrong_hash", "wrong_expected_pin", "missing_required_guarantee"}:
                    with self.subTest(case=case["id"]):
                        self.assertNotEqual(oracle.consume(case["report"], case["expectations"], case["process_exit"]), case["wanted"])
        finally:
            oracle.match = original


if __name__ == "__main__":
    unittest.main()
