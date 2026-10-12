#!/usr/bin/env python3
"""Finite corruption and completion controls for the static node corpus."""

import copy
import importlib.util
import json
from pathlib import Path
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("static_node_checker_test", HERE / "check.py")
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)
PATH = c.FIXTURES / "node-static-v1-v2.json"
DATA = c.read_selected(PATH, c.CORPUS_SHA256)


class StaticNodeControls(unittest.TestCase):
    def refuse(self, data):
        with self.assertRaises(c.signatures.Refused):
            c.validate(data)

    def changed(self, index, field, value):
        data = copy.deepcopy(DATA)
        data["observations"][index][field] = value
        return data

    def test_complete_selected_inventory(self):
        jobs = c.validate(DATA)
        self.assertEqual((len(DATA["observations"]), len(jobs), sum(j[-1] for j in jobs)), (55, 26, 22))
        self.assertEqual(sum(r["node_static_result"] == "MATCH" for r in DATA["observations"]), 22)

    def test_source_function_commit_module_and_sum(self):
        for field in c.NODE:
            data = copy.deepcopy(DATA); data["source"][field] = "unselected"
            self.refuse(data)
        data = copy.deepcopy(DATA); data["source"]["authority"] = True
        self.refuse(data)

    def test_historical_input_digest_selection(self):
        for field in c.INPUTS:
            data = copy.deepcopy(DATA); data["input_files_sha256"][field] = "00" * 32
            self.refuse(data)
        data = copy.deepcopy(DATA); data["input_files_sha256"].pop("momentum-v1-v2.json")
        self.refuse(data)

    def test_scope_cannot_promote_network_or_ledger_claims(self):
        for field, value in c.SCOPE.items():
            for replacement in (not value, int(value), None):
                data = copy.deepcopy(DATA); data["scope"][field] = replacement
                self.refuse(data)
        data = copy.deepcopy(DATA); data["scope"]["state_transition"] = True
        self.refuse(data)

    def test_root_and_row_fields_are_closed(self):
        data = copy.deepcopy(DATA); data["trusted"] = True
        self.refuse(data)
        self.refuse(self.changed(0, "producer_authorized", True))
        data = copy.deepcopy(DATA); data["observations"][0].pop("node_error")
        self.refuse(data)

    def test_format_types_do_not_alias_one(self):
        for value in (True, 1.0, "1", None, 2):
            data = copy.deepcopy(DATA); data["format_version"] = value
            self.refuse(data)

    def test_missing_extra_repeated_or_reordered_cases(self):
        for rows in (DATA["observations"][:-1], DATA["observations"] + [DATA["observations"][0]],
                     DATA["observations"][:-1] + [DATA["observations"][0]], list(reversed(DATA["observations"]))):
            data = copy.deepcopy(DATA); data["observations"] = rows
            self.refuse(data)

    def test_case_and_baseline_substitution(self):
        self.refuse(self.changed(0, "name", "baseline/v2-zero-prices"))
        self.refuse(self.changed(0, "baseline", "v2-zero-prices"))

    def test_selected_wire_cannot_be_replaced(self):
        data = copy.deepcopy(DATA)
        data["observations"][0]["momentum"]["chainIdentifier"] += 1
        header, digest = c.projection(data["observations"][0]["momentum"])
        data["observations"][0].update(header=header, computed_hash=digest.hex(),
                                       node_static_result="REJECT", node_error="hash_mismatch")
        self.refuse(data)

    def test_numeric_types_cannot_alias_selected_fields(self):
        for field in ("version", "chainIdentifier", "height", "timestamp", "nextFusionPrice", "nextWorkPrice"):
            data = copy.deepcopy(DATA)
            data["observations"][0]["momentum"][field] = float(data["observations"][0]["momentum"][field])
            self.refuse(data)
        data = copy.deepcopy(DATA); data["observations"][0]["momentum"]["version"] = True
        self.refuse(data)

    def test_header_and_computed_hash_are_independent_byte_results(self):
        for field in DATA["observations"][0]["header"]:
            data = copy.deepcopy(DATA); data["observations"][0]["header"][field] = None
            self.refuse(data)
        for value in ("00" * 32, DATA["observations"][0]["computed_hash"].upper(), None):
            self.refuse(self.changed(0, "computed_hash", value))

    def test_false_static_outcomes_and_error_precedence_refuse(self):
        self.refuse(self.changed(0, "node_static_result", "REJECT"))
        self.refuse(self.changed(0, "node_error", "hash_mismatch"))
        for name, wrong in (("v1-empty/both-empty", "public_key_missing"),
                            ("v2-nonzero-prices/hash-and-empty", "signature_missing"),
                            ("v1-empty/public-key-short", "signature_invalid")):
            index = next(i for i, row in enumerate(DATA["observations"]) if row["name"] == name)
            self.refuse(self.changed(index, "node_error", wrong))

    def test_nil_has_no_hash_or_header_projection(self):
        index = next(i for i, row in enumerate(DATA["observations"]) if row["name"] == "nil")
        self.refuse(self.changed(index, "header", DATA["observations"][0]["header"]))
        self.refuse(self.changed(index, "computed_hash", "00" * 32))

    def test_v1_price_exclusion_and_v2_price_binding(self):
        rows = {r["name"]: r for r in DATA["observations"]}
        self.assertEqual(rows["v1-empty/prices"]["computed_hash"], rows["baseline/v1-empty"]["computed_hash"])
        self.assertEqual(rows["v1-empty/prices"]["node_static_result"], "MATCH")
        self.assertNotEqual(rows["v2-nonzero-prices/prices"]["computed_hash"], rows["baseline/v2-nonzero-prices"]["computed_hash"])
        self.assertEqual(rows["v2-nonzero-prices/prices"]["node_static_result"], "REJECT")

    def test_unsigned_genesis_never_becomes_a_static_signature_match(self):
        index = next(i for i, row in enumerate(DATA["observations"]) if row["name"] == "historical-unsigned-genesis")
        self.assertEqual(DATA["observations"][index]["node_error"], "signature_missing")
        self.refuse(self.changed(index, "node_static_result", "MATCH"))

    def test_invalid_corpus_refuses_before_backend_construction(self):
        changed = copy.deepcopy(DATA); changed["observations"][0]["node_error"] = "hash_mismatch"
        original = c.read_selected
        def selected(path, pin):
            return changed if Path(path) == PATH else original(path, pin)
        with mock.patch.object(c, "read_selected", side_effect=selected), mock.patch.object(c.signatures, "Backend") as backend:
            with self.assertRaises(c.signatures.Refused): c.run(PATH, "unused", None)
        backend.assert_not_called()

    def test_invalid_revision_refuses_before_reads(self):
        with mock.patch.object(c, "read_selected", side_effect=AssertionError("unexpected read")):
            with self.assertRaises(c.signatures.Refused): c.run(PATH, "unused", "bad-ref")

    def test_signature_backend_failure_retains_completed_outcomes(self):
        jobs = c.validate(DATA)
        count = 0
        failure = c.signatures.Refused("backend_deadline", {"returncode": None, "stdout_sha256": "00" * 32, "stderr_sha256": "00" * 32})
        def verify(*args):
            nonlocal count
            if count == 3: raise failure
            expected = jobs[count][-1]; count += 1
            return expected, {"returncode": 0 if expected else 1}
        backend = mock.Mock(); backend.verify.side_effect = verify
        with mock.patch.object(c.signatures, "Backend", return_value=backend):
            with self.assertRaises(c.signatures.Refused) as caught: c.run(PATH, "unused", None)
        self.assertEqual(len(caught.exception.outcomes), 4)
        self.assertIsNone(caught.exception.outcomes[-1]["returncode"])
        backend.identity.assert_not_called()


if __name__ == "__main__":
    unittest.main()
