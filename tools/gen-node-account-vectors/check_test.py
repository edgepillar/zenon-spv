#!/usr/bin/env python3
"""Corruption, selection and completion controls for recorded method evidence."""

import copy
import importlib.util
from pathlib import Path
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("account_node_controls", HERE / "check.py")
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)
PATH = c.FIXTURES / "node-account-transactions.json"
DATA = c.read_selected(PATH, c.CORPUS_SHA256)


class AccountNodeControls(unittest.TestCase):
    def refuse(self, data):
        with self.assertRaises(c.signatures.Refused): c.validate(data)

    def changed(self, name, field, value):
        data = copy.deepcopy(DATA)
        next(r for r in data["observations"] if r["name"] == name)[field] = value
        return data

    def test_complete_inventory_and_signature_selection(self):
        jobs = c.validate(DATA)
        self.assertEqual((len(DATA["observations"]), len(jobs), sum(j[-1] for j in jobs)), (58, 16, 14))
        self.assertEqual({k: sum(r["node_transaction_result"] == k for r in DATA["observations"])
                          for k in ("MATCH", "REJECT", "PANIC")}, {"MATCH": 20, "REJECT": 36, "PANIC": 2})

    def test_source_module_sum_commit_function_closed(self):
        for key in c.NODE:
            data = copy.deepcopy(DATA); data["source"][key] = "unselected"; self.refuse(data)
        data = copy.deepcopy(DATA); data["source"]["authoritative"] = True; self.refuse(data)

    def test_selected_input_pins_cannot_substitute(self):
        for key in c.INPUTS:
            data = copy.deepcopy(DATA); data["input_files_sha256"][key] = "00" * 32; self.refuse(data)

    def test_scope_types_cannot_promote_context_or_full_node_claims(self):
        for key, value in c.SCOPE.items():
            for replacement in (not value, int(value), None):
                data = copy.deepcopy(DATA); data["scope"][key] = replacement; self.refuse(data)

    def test_root_and_row_fields_are_closed(self):
        data = copy.deepcopy(DATA); data["authority"] = True; self.refuse(data)
        self.refuse(self.changed("baseline/user-type-2", "trusted", True))
        data = copy.deepcopy(DATA); data["observations"][0].pop("context_calls"); self.refuse(data)

    def test_format_does_not_alias_one(self):
        for value in (True, 1.0, "1", None, 2):
            data = copy.deepcopy(DATA); data["format_version"] = value; self.refuse(data)

    def test_missing_extra_duplicate_reordered_cases(self):
        rows = DATA["observations"]
        for changed in (rows[:-1], rows + [rows[0]], rows[:-1] + [rows[0]], list(reversed(rows))):
            data = copy.deepcopy(DATA); data["observations"] = changed; self.refuse(data)

    def test_coherent_wire_and_hash_substitution_refuses(self):
        data = copy.deepcopy(DATA); row = data["observations"][0]
        row["account_block"]["chainIdentifier"] += 1
        block, digest = c.projection(row["account_block"])
        row.update(block=block, computed_hash=digest.hex(), node_transaction_result="REJECT", node_error="hash_mismatch")
        self.refuse(data)

    def test_numeric_boolean_float_aliases_refuse(self):
        for field in ("version", "chainIdentifier", "height", "blockType", "fusedPlasma", "difficulty", "basePlasma", "usedPlasma"):
            data = copy.deepcopy(DATA)
            data["observations"][0]["account_block"][field] = float(data["observations"][0]["account_block"][field])
            self.refuse(data)
        self.refuse(self.changed("user-type-2/amount-nil", "amount_is_nil", 1))
        self.refuse(self.changed("embedded-type-5/version-two", "recomputed_claimed_hash", 1))

    def test_projection_and_hash_checked_independently(self):
        for field in DATA["observations"][0]["block"]:
            data = copy.deepcopy(DATA); data["observations"][0]["block"][field] = None; self.refuse(data)
        for value in ("00" * 32, None, DATA["observations"][0]["computed_hash"].upper()):
            self.refuse(self.changed("baseline/user-type-2", "computed_hash", value))

    def test_context_calls_and_arguments_are_exact(self):
        for name in ("baseline/user-type-2", "baseline/embedded-type-5", "baseline/ordinary"):
            self.refuse(self.changed(name, "context_calls", []))
        data = copy.deepcopy(DATA); data["observations"][0]["context_calls"][0]["identifier"]["height"] = True
        self.refuse(data)

    def test_error_precedence_and_programmatic_panics_are_bound(self):
        for name, wrong in (("user-type-2/both-empty", "public_key_missing"),
                            ("embedded-type-5/both-present", "signature_must_be_zero"),
                            ("baseline/ordinary", "signature_invalid"), ("nil-block", "hash_missing")):
            self.refuse(self.changed(name, "node_error", wrong))
        self.refuse(self.changed("nil-transaction", "node_transaction_result", "REJECT"))

    def test_nil_inputs_have_no_projection_or_calls(self):
        for name in ("nil-transaction", "nil-block"):
            self.refuse(self.changed(name, "block", DATA["observations"][0]["block"]))
            self.refuse(self.changed(name, "computed_hash", "00" * 32))
            self.refuse(self.changed(name, "context_calls", [{"method": "GetFrontierMomentumStore"}]))

    def test_programmatic_nil_amount_does_not_become_rpc_zero(self):
        rows = {r["name"]: r for r in DATA["observations"]}
        self.assertEqual(rows["user-type-3/amount-nil"]["computed_hash"], rows["baseline/user-type-3"]["computed_hash"])
        self.assertNotEqual(rows["user-type-2/amount-nil"]["computed_hash"], rows["baseline/user-type-2"]["computed_hash"])
        data = copy.deepcopy(DATA)
        row = next(r for r in data["observations"] if r["name"] == "user-type-3/amount-nil")
        row["account_block"]["amount"] = "0"; row["block"]["amount"] = 0; row["amount_is_nil"] = False
        self.refuse(data)

    def test_signed_negative_and_unsigned_metadata_aliases_keep_hash(self):
        rows = {r["name"]: r for r in DATA["observations"]}
        for suffix in ("changes-hash-bit", "base-plasma-one", "used-plasma-one", "amount-negative"):
            row = rows["user-type-2/" + suffix]
            self.assertEqual((row["computed_hash"], row["node_transaction_result"]),
                             (rows["baseline/user-type-2"]["computed_hash"], "MATCH"))

    def test_preserved_descendants_are_rejected_after_signature(self):
        rows = {r["name"]: r for r in DATA["observations"]}
        row = rows["baseline/ordinary"]
        self.assertEqual(row["node_error"], "descendants_must_be_zero")
        self.assertEqual(row["context_calls"][0]["identifier"]["height"], (1 << 64) - 1)
        self.assertTrue(next(j[-1] for j in c.validate(DATA) if j[0] == "baseline/ordinary"))
        data = copy.deepcopy(DATA); row = next(r for r in data["observations"] if r["name"] == "baseline/ordinary")
        row["account_block"]["descendantBlocks"] = []; row["block"], digest = c.projection(row["account_block"])
        row["computed_hash"] = digest.hex(); self.refuse(data)

    def test_preflight_failure_precedes_backend(self):
        data = copy.deepcopy(DATA); data["observations"][0]["node_error"] = "hash_mismatch"
        original = c.read_selected
        def selected(path, pin): return data if Path(path) == PATH else original(path, pin)
        with mock.patch.object(c, "read_selected", side_effect=selected), mock.patch.object(c.signatures, "Backend") as backend:
            with self.assertRaises(c.signatures.Refused): c.run(PATH, "unused", None)
        backend.assert_not_called()

    def test_bad_revision_precedes_reads(self):
        with mock.patch.object(c, "read_selected", side_effect=AssertionError("unexpected read")):
            with self.assertRaises(c.signatures.Refused): c.run(PATH, "unused", "bad-ref")

    def test_backend_failure_preserves_actual_partial_outcomes(self):
        jobs = c.validate(DATA); count = 0
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
