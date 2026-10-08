#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Adversarial controls for actual candidate L1 family-filter observations."""

import contextlib
import copy
import hashlib
import importlib.util
import io
from pathlib import Path
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location("candidate_filter_" + name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CHECK = load("check_fold")
DRIVER = load("regenerate")


class CandidateFoldControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _, cls.corpus = CHECK.BYTE.read_corpus(HERE / "testdata/candidate-l1-fold-filter.json")
        cls.cases = {case["name"]: case for case in cls.corpus["filter_cases"]}

    def check_case(self, case):
        return CHECK.check_case(case, CHECK.selected_keys()[case["name"]])

    def test_all_actual_candidate_filter_outcomes(self):
        report = CHECK.check_corpus(self.corpus)
        self.assertEqual((report["filter_cases"], report["input_operations"], report["output_operations"]), (22, 66, 18))
        self.assertEqual((report["included_cases"], report["excluded_cases"]), (6, 16))
        self.assertFalse(report["production_acceptance_enabled"])

    def test_empty_put_and_delete_remain_distinct_filter_events(self):
        case = self.cases["balance-32"]
        self.assertEqual((case["output"][1]["kind"], case["output"][1]["value"]), ("put", ""))
        self.assertEqual(case["output"][2]["kind"], "delete")
        changed = copy.deepcopy(case)
        changed["output"][1]["kind"] = "delete"
        with self.assertRaises(ValueError):
            self.check_case(changed)
        self.assertFalse(self.corpus["scope"]["l1_staged_applier_executed"])

    def test_replay_preserves_duplicate_key_order(self):
        for name in ("balance-32", "storage"):
            case = copy.deepcopy(self.cases[name])
            case["output"][0], case["output"][1] = case["output"][1], case["output"][0]
            with self.subTest(case=name), self.assertRaises(ValueError):
                self.check_case(case)
            case["output"] = case["output"][-1:]
            with self.subTest(case=name, collapsed=True), self.assertRaises(ValueError):
                self.check_case(case)

    def test_family_filter_is_not_a_typed_balance_key_validator(self):
        for name, width in (("balance-prefix-only-22", 22), ("balance-short-token-31", 31), ("balance-long-token-33", 33)):
            report = self.check_case(self.cases[name])
            with self.subTest(case=name):
                self.assertEqual((report["key_bytes"], report["output_operations"]), (width, 3))
                self.assertFalse(report["typed_balance_key_grammar"])
        self.assertTrue(self.check_case(self.cases["balance-32"])["typed_balance_key_grammar"])
        self.assertFalse(self.check_case(self.cases["storage"])["typed_balance_key_grammar"])

    def test_all_excluded_families_have_no_output_events(self):
        excluded = [case for case in self.cases.values() if not case["output"]]
        self.assertEqual(len(excluded), 16)
        for original in excluded:
            case = copy.deepcopy(original)
            case["output"] = case["input"][:1]
            with self.subTest(case=case["name"]), self.assertRaises(ValueError):
                self.check_case(case)

    def test_prefix_and_length_boundaries(self):
        selected = bytearray(CHECK.selected_keys()["balance-32"])
        for size in range(22):
            self.assertFalse(CHECK.filter_keeps(bytes(selected[:size])))
        for sub in range(256):
            selected[21] = sub
            self.assertEqual(CHECK.filter_keeps(bytes(selected[:22])), sub in (3, 4))
        selected[21] = 3
        for top in range(256):
            selected[0] = top
            self.assertEqual(CHECK.filter_keeps(bytes(selected)), top == 3)

    def test_coherent_selected_key_substitution_is_refused(self):
        case = copy.deepcopy(self.cases["balance-32"])
        key = bytearray(CHECK.BYTE.hex_bytes(case["key"]))
        key[1] ^= 1
        case["key"] = bytes(key).hex()
        for field in ("input", "output"):
            for row in case[field]:
                row["key"] = case["key"]
        with self.assertRaisesRegex(ValueError, "selected fixture key"):
            self.check_case(case)

    def test_output_key_value_kind_and_order_corruption(self):
        for field, value in (("key", "ff"), ("value", "01" * 32), ("kind", "delete")):
            case = copy.deepcopy(self.cases["balance-32"])
            case["output"][0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.check_case(case)

    def test_operation_shapes_and_scalar_types_are_strict(self):
        original = self.cases["balance-32"]["output"][0]
        for row in (None, [], original | {"extra": 1}, original | {"kind": True},
                    original | {"key": None}, original | {"value": 0}, {"kind": "delete", "key": "", "value": "00"}):
            with self.subTest(row=row), self.assertRaises(ValueError):
                CHECK.operation(row)

    def test_byte_and_operation_limits_apply_before_decoding(self):
        original = self.cases["balance-32"]["output"][0]
        for field, limit in (("key", CHECK.MAX_KEY_BYTES), ("value", CHECK.MAX_VALUE_BYTES)):
            row = original | {field: "00" * (limit + 1)}
            with self.subTest(field=field), mock.patch.object(CHECK.BYTE, "hex_bytes", wraps=CHECK.BYTE.hex_bytes) as decoder:
                with self.assertRaisesRegex(ValueError, "byte limit"):
                    CHECK.operation(row)
                self.assertLessEqual(decoder.call_count, int(field == "value"))
        with self.assertRaises(ValueError):
            CHECK.operations([original] * (CHECK.MAX_OPERATIONS + 1))
        with self.assertRaises(ValueError):
            CHECK.operations({})

    def test_hex_spelling_does_not_change_event_bytes(self):
        case = copy.deepcopy(self.cases["storage"])
        for field in ("input", "output"):
            for row in case[field]:
                row["key"] = row["key"].upper()
        case["key"] = case["key"].upper()
        self.check_case(case)
        for text in ("00 ", "0g", "0", " 00"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                CHECK.bounded_hex(text, 1024)

    def test_case_inventory_duplicate_ids_and_shapes(self):
        for changed in (self.corpus["filter_cases"][:-1], self.corpus["filter_cases"] + self.corpus["filter_cases"][:1],
                        self.corpus["filter_cases"] * (CHECK.MAX_CASES + 1), None):
            document = copy.deepcopy(self.corpus)
            document["filter_cases"] = changed
            with self.subTest(changed_type=type(changed).__name__), self.assertRaises(ValueError):
                CHECK.check_corpus(document)
        document = copy.deepcopy(self.corpus)
        document["filter_cases"][0]["name"] = "provider-selected"
        with self.assertRaises(ValueError):
            CHECK.check_corpus(document)

    def test_source_and_execution_claims_are_fixed(self):
        for flag in CHECK.SCOPE:
            document = copy.deepcopy(self.corpus)
            document["scope"][flag] = not document["scope"][flag]
            with self.subTest(flag=flag), self.assertRaises(ValueError):
                CHECK.check_corpus(document)
        for field, value in (("format_version", True), ("kind", "enabled-proof-profile"),
                             ("source", self.corpus["source"] | {"revision": "0" * 40})):
            document = copy.deepcopy(self.corpus)
            document[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                CHECK.check_corpus(document)

    def test_file_bounds_duplicate_fields_and_preserved_byte_corpus(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "fixture.json"
            path.write_bytes(b" " * (CHECK.BYTE.MAX_FILE_BYTES + 1))
            with self.assertRaises(ValueError):
                CHECK.BYTE.read_corpus(path)
            path.write_bytes(b'{"kind":"first","kind":"second"}')
            with self.assertRaisesRegex(ValueError, "duplicate JSON"):
                CHECK.BYTE.read_corpus(path)
        raw, corpus = CHECK.BYTE.read_corpus(HERE / "testdata/candidate-v3-balances.json")
        self.assertEqual(hashlib.sha256(raw).hexdigest(), "8b69cdaf78ae4eeaad79cdfa493ed9633a1202e09819178da83e17be385f00d3")
        self.assertEqual(CHECK.BYTE.check_corpus(corpus)["node_proof_comparisons"], 41)

    def test_reproduction_refuses_unknown_fixture_kinds(self):
        with mock.patch.object(DRIVER, "snapshot_source") as source, contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as error:
                DRIVER.main(["--node-source", "unused", "--go", "unused", "--output", "unused",
                             "--evidence-directory", "unused", "--fixture-kind", "unknown"])
            self.assertEqual(error.exception.code, 2)
            source.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
