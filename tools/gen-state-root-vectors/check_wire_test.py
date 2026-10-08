#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Negative controls for isolated serializer and synthetic selection conformance."""

import base64
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("wire_controls", HERE / "check_wire.py")
WIRE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(WIRE)
RAW, DOCUMENT = WIRE.BYTE.read_corpus(HERE / "testdata/candidate-state-proof-wire.json")


class WireControls(unittest.TestCase):
    def refuse_corpus(self, mutate):
        document = copy.deepcopy(DOCUMENT)
        mutate(document)
        with self.assertRaises(ValueError):
            WIRE.check_corpus(document)

    def wire_fields(self, index=0):
        return json.loads(DOCUMENT["binding_cases"][index]["wire"])

    def bind(self, fields, index=0, selection=None):
        name = DOCUMENT["binding_cases"][index]["name"]
        return WIRE.research_binding(json.dumps(fields), name, selection or WIRE.selected_context(name))

    def test_all_actual_state_proof_serializer_outputs(self):
        report = WIRE.check_corpus(DOCUMENT)
        self.assertEqual((report["serialization_cases"], report["binding_cases"], report["serializer_comparisons"]), (7, 7, 14))
        for row in DOCUMENT["serialization_cases"] + DOCUMENT["binding_cases"]:
            value, proof, root = WIRE.decode_wire(row["wire"])
            self.assertEqual(value, None if row["value_hex"] is None else bytes.fromhex(row["value_hex"]))
            self.assertEqual(proof, None if row["proof_hex"] is None else bytes.fromhex(row["proof_hex"]))
            self.assertEqual(root.hex(), row["root"])
        for flag in ("production_acceptance_enabled", "profile_agreed", "network_activation_authenticated", "header_authentication_qualified"):
            self.assertIs(report[flag], False)

    def test_all_primitive_proofs_and_research_balance_decisions(self):
        report = WIRE.check_corpus(DOCUMENT)
        self.assertEqual(report["node_proof_comparisons"], 7)
        self.assertEqual(report["research_balance_matches"], 4)
        self.assertEqual(report["binding_decisions"][0]["typed_balance"], {"present": True, "amount": "0"})
        self.assertEqual(report["binding_decisions"][1]["typed_balance"], {"present": True, "amount": "1"})
        for row in report["binding_decisions"][2:4]:
            self.assertEqual(row["typed_balance"], {"present": False, "amount": "0"})

    def test_nil_empty_and_stored_zero_remain_distinct(self):
        values = [WIRE.decode_wire(row["wire"])[0] for row in DOCUMENT["serialization_cases"]]
        self.assertEqual(values[:4], [None, b"", None, b""])
        self.assertEqual(values[-1], bytes(32))
        report = WIRE.check_corpus(DOCUMENT)
        self.assertEqual((report["nil_value_observations"], report["empty_value_observations"]), (6, 3))
        fields = self.wire_fields(2)
        fields["value"] = ""
        with self.assertRaises(ValueError):
            self.bind(fields, 2)
        fields = self.wire_fields()
        fields["value"] = None
        with self.assertRaises(ValueError):
            self.bind(fields)

    def test_base64_padding_alphabet_and_unused_bits_are_bounded(self):
        for value in ("-w==", "_w==", "/w", "/w===", "/w== ", "/w==\n", "éA==", "Zh==", True, 1, [], {}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                WIRE.decode_base64(value, 4096)
        self.assertEqual(WIRE.decode_base64("/w==", 1), bytes([255]))
        self.assertEqual(WIRE.decode_base64("/wA=", 2), bytes([255, 0]))
        self.assertEqual(WIRE.decode_base64("", 0), b"")
        self.assertIsNone(WIRE.decode_base64(None, 0))

    def test_wire_json_has_a_closed_shape_and_no_duplicate_fields(self):
        for text in ('{}', '[]', 'null', '{"value":null,"proof":null,"root":"' + '00' * 32 + '","value":""}'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                WIRE.decode_wire(text)
        fields = self.wire_fields()
        for key in fields:
            bad = dict(fields); del bad[key]
            with self.assertRaises(ValueError):
                WIRE.decode_wire(json.dumps(bad))
        for key in ("raw_key", "height", "hash", "trusted", "context_pin", "result"):
            bad = fields | {key: "provider"}
            with self.assertRaises(ValueError):
                WIRE.decode_wire(json.dumps(bad))

    def test_wire_scalar_types_and_root_widths_are_strict(self):
        fields = self.wire_fields()
        for key in ("value", "proof"):
            for value in (True, 0, [], {}):
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    WIRE.decode_wire(json.dumps(fields | {key: value}))
        for root in (None, True, 0, [], "", "00" * 31, "00" * 33, "0x" + "00" * 32, "gg" * 32, "00 " * 32):
            with self.subTest(root=root), self.assertRaises(ValueError):
                WIRE.decode_wire(json.dumps(fields | {"root": root}))

    def test_byte_bounds_refuse_work_before_base64_decoding(self):
        with mock.patch.object(WIRE.base64, "b64decode", side_effect=AssertionError("unexpected decoding")):
            for limit in (WIRE.MAX_VALUE_BYTES, WIRE.BYTE.MAX_PROOF_BYTES):
                with self.assertRaises(ValueError):
                    WIRE.decode_base64("A" * (((limit + 2) // 3) * 4 + 1), limit)
            with self.assertRaises(ValueError):
                WIRE.decode_wire(" " * (WIRE.MAX_WIRE_BYTES + 1))
            with self.assertRaises(ValueError):
                WIRE.decode_wire("é" * WIRE.MAX_WIRE_BYTES)
        with self.assertRaises(ValueError):
            WIRE.decode_base64(base64.b64encode(bytes(WIRE.MAX_VALUE_BYTES + 1)).decode(), WIRE.MAX_VALUE_BYTES)

    def test_corpus_source_scope_and_exact_inventories_are_selected(self):
        self.refuse_corpus(lambda d: d.update(format_version=True))
        self.refuse_corpus(lambda d: d.update(kind="candidate-l1-applier-research"))
        self.refuse_corpus(lambda d: d["source"].update(revision="0" * 40))
        self.refuse_corpus(lambda d: d["source"].update(tree="0" * 40))
        for flag, value in WIRE.SCOPE.items():
            self.refuse_corpus(lambda d, flag=flag, value=value: d["scope"].update({flag: not value}))
            self.refuse_corpus(lambda d, flag=flag, value=value: d["scope"].update({flag: int(value)}))
        for key in ("serialization_cases", "binding_cases"):
            self.refuse_corpus(lambda d, key=key: d[key].pop())
            self.refuse_corpus(lambda d, key=key: d[key].append(copy.deepcopy(d[key][0])))
            self.refuse_corpus(lambda d, key=key: d[key].reverse())
            self.refuse_corpus(lambda d, key=key: d.update({key: [d[key][0]] * (WIRE.MAX_CASES + 1)}))
        self.refuse_corpus(lambda d: d.update(provider_root="00" * 32))
        self.refuse_corpus(lambda d: d["binding_cases"][0].update(header_authenticated=True))

    def test_coherent_provider_root_and_proof_substitution_is_refused(self):
        one = self.wire_fields(1)
        with self.assertRaises(ValueError):
            self.bind(one)
        fields = self.wire_fields()
        fields["root"] = "00" * 32
        with self.assertRaises(ValueError):
            self.bind(fields)
        selection = WIRE.selected_context("stored-zero")
        selection["root"] = one["root"]
        with self.assertRaises(ValueError):
            self.bind(one, selection=selection)

    def test_header_identifier_version_and_context_pin_cannot_be_substituted(self):
        fields = self.wire_fields()
        substitutions = {"header_height": (41, 43, True), "header_version": (1, 2, 4, True),
                         "header_hash": ("00" * 32,), "context_pin": ("00" * 32,),
                         "profile": ("provider-selected",), "header_authenticated": (True,),
                         "network_profile_agreed": (True,), "synthetic": (False, 1)}
        for key, values in substitutions.items():
            for value in values:
                selection = WIRE.selected_context("stored-zero"); selection[key] = value
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    self.bind(fields, selection=selection)
        selection = WIRE.selected_context("stored-zero"); selection.pop("context_pin")
        with self.assertRaises(ValueError):
            self.bind(fields, selection=selection)

    def test_selected_raw_key_and_single_hash_path_are_bound_locally(self):
        fields = self.wire_fields()
        selected = WIRE.selected_context("stored-zero")
        key = bytes.fromhex(selected["raw_key"])
        for wrong in (bytes(32), WIRE.BYTE.digest(key), b"\x04\x01\x02"):
            selection = dict(selected); selection["raw_key"] = wrong.hex()
            with self.assertRaises(ValueError):
                self.bind(fields, selection=selection)
        for change in ("raw_key", "path"):
            self.refuse_corpus(lambda d, change=change: d["binding_cases"][0].update({change: "00" * 32}))
        value, proof, root = WIRE.decode_wire(json.dumps(fields))
        self.assertEqual(WIRE.BYTE.proof_result(root, WIRE.BYTE.digest(WIRE.BYTE.digest(key)), value, proof, True), "path_mismatch")

    def test_excluded_and_storage_absence_is_not_typed_ledger_absence(self):
        for index in (4, 5):
            result = self.bind(self.wire_fields(index), index)
            self.assertEqual(result["decision"], "unsupported_typed_query")
            self.assertIsNone(result["typed_balance"])
        report = WIRE.check_corpus(DOCUMENT)
        self.assertEqual(report["unsupported_typed_query_refusals"], 2)

    def test_present_empty_shared_core_value_is_not_a_balance(self):
        result = self.bind(self.wire_fields(6), 6)
        self.assertEqual(result["decision"], "unsupported_balance_value")
        self.assertIsNone(result["typed_balance"])
        self.assertEqual(WIRE.decode_wire(DOCUMENT["binding_cases"][6]["wire"])[0], b"")

    def test_proof_flags_lengths_paths_bitmap_and_trailing_bytes(self):
        fields = self.wire_fields()
        proof = base64.b64decode(fields["proof"])
        corruptions = [b"", proof[:98], proof + b"\x00"]
        for offset, value in ((0, proof[0] ^ 0x80), (1, proof[1] ^ 1), (65, proof[65] ^ 1), (98, proof[98] ^ 1)):
            changed = bytearray(proof); changed[offset] = value; corruptions.append(bytes(changed))
        for changed in corruptions:
            with self.subTest(bytes=len(changed)), self.assertRaises(ValueError):
                self.bind(fields | {"proof": base64.b64encode(changed).decode()})
        with self.assertRaises(ValueError):
            self.bind(fields | {"proof": None})

    def test_wire_presence_and_value_claims_must_match_the_proof(self):
        fields = self.wire_fields()
        for value in (None, "", base64.b64encode((1).to_bytes(32, "big")).decode()):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.bind(fields | {"value": value})
        self.refuse_corpus(lambda d: d["binding_cases"][0].update(present=False))
        self.refuse_corpus(lambda d: d["binding_cases"][0].update(node_result="mismatch"))
        self.refuse_corpus(lambda d: d["binding_cases"][0].update(value_hex=None))

    def test_equivalent_zero_sibling_proof_compatibility_is_preserved(self):
        fields = self.wire_fields()
        proof = bytearray(base64.b64decode(fields["proof"]))
        count = int.from_bytes(proof[97:99], "big")
        slot = next(index for index in range(256) if not proof[65 + index // 8] & (1 << (7 - index % 8)))
        position = sum(bool(proof[65 + index // 8] & (1 << (7 - index % 8))) for index in range(slot))
        proof[65 + slot // 8] |= 1 << (7 - slot % 8)
        proof[97:99] = (count + 1).to_bytes(2, "big")
        proof[99 + position * 32:99 + position * 32] = bytes(32)
        result = self.bind(fields | {"proof": base64.b64encode(proof).decode()})
        self.assertEqual(result["decision"], "research_balance_match")

    def test_hex_case_preserves_bytes_but_fixture_serializer_spelling_is_exact(self):
        document = copy.deepcopy(DOCUMENT)
        for row in document["serialization_cases"] + document["binding_cases"]:
            for key in ("value_hex", "proof_hex", "root", "raw_key", "path"):
                if key in row and row[key] is not None:
                    row[key] = row[key].upper()
        self.assertEqual(WIRE.check_corpus(document), WIRE.check_corpus(DOCUMENT))
        fields = self.wire_fields(); fields["root"] = fields["root"].upper()
        self.assertEqual(self.bind(fields)["decision"], "research_balance_match")
        self.refuse_corpus(lambda d: d["serialization_cases"][0].update(wire=d["serialization_cases"][0]["wire"] + " "))

    def test_json_whitespace_and_escaped_strings_preserve_transport_bytes(self):
        row = DOCUMENT["binding_cases"][0]
        fields = json.loads(row["wire"])
        spaced = json.dumps(fields, indent=2)
        escaped = row["wire"].replace('"value"', '"v\\u0061lue"')
        for text in (spaced, escaped, " \n" + row["wire"] + "\r\n"):
            self.assertEqual(WIRE.decode_wire(text), WIRE.decode_wire(row["wire"]))
            self.assertEqual(WIRE.research_binding(text, row["name"], WIRE.selected_context(row["name"]))["decision"], "research_balance_match")

    def test_file_bounds_duplicate_fields_and_three_previous_corpora(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "corpus.json"
            path.write_bytes(b" " * (WIRE.BYTE.MAX_FILE_BYTES + 1))
            with self.assertRaises(ValueError):
                WIRE.BYTE.read_corpus(path)
            path.write_text('{"format_version":1,"format_version":1}')
            with self.assertRaises(ValueError):
                WIRE.BYTE.read_corpus(path)
        pins = {"candidate-v3-balances.json": "8b69cdaf78ae4eeaad79cdfa493ed9633a1202e09819178da83e17be385f00d3",
                "candidate-l1-fold-filter.json": "0a68118625d0f5df3497dd8d35ce39b9e0df3eb7dc8ccd73e703408031ff45ea",
                "candidate-l1-applier.json": "08eeda1a69331109c50918f5f2a13eac2b0a9f52605d95dda1349fa1ac2e297e"}
        for name, digest in pins.items():
            self.assertEqual(hashlib.sha256((HERE / "testdata" / name).read_bytes()).hexdigest(), digest)

    def test_cli_source_revision_is_strict_metadata_and_unknown_modes_refuse(self):
        selected = "a" * 40
        result = subprocess.run([sys.executable, "-I", "-B", str(HERE / "check_wire.py"), "--source-revision", selected], capture_output=True)
        self.assertEqual(result.returncode, 0)
        report = json.loads(result.stdout)
        self.assertEqual(report["source_revision"], selected)
        self.assertFalse(report["header_authentication_qualified"])
        for source in ("A" * 40, "a" * 39, "a" * 41, "z" * 40):
            result = subprocess.run([sys.executable, "-I", "-B", str(HERE / "check_wire.py"), "--source-revision", source], capture_output=True)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stdout, b"")
        result = subprocess.run([sys.executable, "-I", "-B", str(HERE / "regenerate.py"), "--fixture-kind", "unknown"], capture_output=True)
        self.assertEqual(result.returncode, 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
