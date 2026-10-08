#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Adversarial controls for the independent candidate byte oracle and driver."""

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location("state_root_" + name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CHECK = load("check")
DRIVER = load("regenerate")


class CandidateByteControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _, cls.corpus = CHECK.read_corpus(HERE / "testdata/candidate-v3-balances.json")
        cls.proofs = {p["name"]: p for p in cls.corpus["proofs"]}
        cls.states = {s["name"]: s for s in cls.corpus["states"]}
        cls.headers = {h["name"]: h for h in cls.corpus["headers"]}

    def result(self, case):
        return CHECK.proof_result(CHECK.hex_bytes(case["root"], 32), CHECK.hex_bytes(case["path"], 32),
                                  CHECK.hex_bytes(case["value"]), CHECK.hex_bytes(case["proof"]), case["present"])

    def test_all_original_node_outputs(self):
        report = CHECK.check_corpus(self.corpus)
        self.assertEqual((report["header_preimages"], report["state_roots"], report["node_proof_comparisons"]), (10, 6, 41))
        self.assertEqual((report["matched_proofs"], report["nonmatching_or_malformed_proofs"]), (24, 17))
        self.assertFalse(report["production_acceptance_enabled"])

    def test_every_node_negative_verdict(self):
        controls = [p for p in self.corpus["proofs"] if p["node_result"] != "match"]
        self.assertEqual(len(controls), 17)
        for case in controls:
            with self.subTest(case=case["name"]):
                self.assertEqual(self.result(case), case["node_result"])

    def test_present_zero_and_missing_balance_remain_distinct(self):
        state = self.states["synthetic-balance-magnitudes"]
        present = CHECK.check_balance_claim(self.proofs["stored-zero"], state)
        absent = CHECK.check_balance_claim(self.proofs["missing-token"], state)
        self.assertEqual(present, {"present": True, "amount": "0"})
        self.assertEqual(absent, {"present": False, "amount": "0"})
        self.assertEqual(CHECK.hex_bytes(self.proofs["stored-zero"]["value"]), bytes(32))

    def test_256_bit_boundary_is_not_a_node_balance_maximum_claim(self):
        self.assertEqual(CHECK.balance_magnitude("0"), bytes(32))
        self.assertEqual(CHECK.balance_magnitude(str((1 << 256) - 1)), b"\xff" * 32)
        self.assertEqual(CHECK.balance_magnitude(str(1 << 256)), b"\x01" + bytes(32))
        self.assertEqual(len(CHECK.hex_bytes(self.proofs["257-bit-magnitude-only"]["value"])), 33)
        self.assertFalse(self.corpus["scope"]["balance_maximum_pinned"])

    def test_present_empty_is_shared_core_only(self):
        case = self.proofs["present-empty-core-only"]
        self.assertTrue(case["present"])
        self.assertEqual(case["value"], "")
        self.assertEqual(self.result(case), "match")
        self.assertNotEqual(CHECK.hex_bytes(case["root"], 32), CHECK.ZERO)
        self.assertEqual(self.states["empty-shared-core"]["root"], CHECK.ZERO.hex())
        with self.assertRaisesRegex(ValueError, "unsupported typed balance domain"):
            CHECK.check_balance_claim(case, self.states[case["state"]])

    def test_excluded_domain_absence_is_refused_as_a_balance(self):
        cases = [p for p in self.corpus["proofs"] if p["domain"] == "excluded"]
        self.assertEqual(len(cases), 5)
        for case in cases:
            with self.subTest(case=case["name"]):
                self.assertEqual(self.result(case), "match")
                with self.assertRaisesRegex(ValueError, "unsupported typed balance domain"):
                    CHECK.check_balance_claim(case, self.states[case["state"]])

    def test_selected_address_and_token_are_not_provider_keys(self):
        for field in ("address", "token"):
            case = copy.deepcopy(self.proofs["stored-zero"])
            value = bytearray(CHECK.hex_bytes(case[field]))
            value[-1] ^= 1
            case[field] = value.hex()
            with self.subTest(field=field), self.assertRaises(ValueError):
                CHECK.check_balance_claim(case, self.states[case["state"]])

    def test_provider_raw_key_substitution(self):
        case = copy.deepcopy(self.proofs["stored-zero"])
        key = bytearray(CHECK.hex_bytes(case["raw_key"]))
        key[21] = 5
        case["raw_key"] = key.hex()
        with self.assertRaisesRegex(ValueError, "substituted raw balance key"):
            CHECK.check_balance_claim(case, self.states[case["state"]])

    def test_raw_keys_are_hashed_exactly_once(self):
        case = self.proofs["stored-zero"]
        self.assertEqual(CHECK.hex_bytes(case["path"], 32), CHECK.digest(CHECK.hex_bytes(case["raw_key"])))
        self.assertEqual(self.result(self.proofs["double-hashed-selected-path"]), "path_mismatch")

    def test_bitmap_and_path_bit_boundaries(self):
        decoded = CHECK.decode_proof(CHECK.hex_bytes(self.proofs["branch-bit-0"]["proof"]))
        self.assertEqual(set(decoded["siblings"]), {255, 248, 247, 7, 0})
        bitmap = CHECK.hex_bytes(self.proofs["branch-bit-0"]["proof"])[65:97]
        self.assertEqual(bitmap, b"\x81\x80" + bytes(29) + b"\x81")

    def test_full_bitmap_proof_size_boundaries(self):
        for name, size, present in (("full-bitmap-absent-8291-bytes", 8291, False),
                                    ("full-bitmap-present-8327-bytes", 8327, True)):
            with self.subTest(case=name):
                proof = CHECK.hex_bytes(self.proofs[name]["proof"])
                self.assertEqual(len(proof), size)
                self.assertEqual(proof[65:97], b"\xff" * 32)
                self.assertEqual(int.from_bytes(proof[97:99], "big"), 256)
                self.assertEqual(CHECK.decode_proof(proof)["present"], present)
                self.assertEqual(self.result(self.proofs[name]), "match")

    def test_node_accepts_equivalent_stored_zero_siblings(self):
        for name in ("stored-zero-sibling-equivalent", "absent-stored-zero-sibling-equivalent"):
            with self.subTest(case=name):
                case = self.proofs[name]
                self.assertEqual(case["node_result"], "match")
                self.assertEqual(self.result(case), "match")
                self.assertFalse(CHECK.decode_proof(CHECK.hex_bytes(case["proof"]))["canonical"])

    def test_sha3_and_zero_parent_conventions(self):
        self.assertEqual(CHECK.digest(b"").hex(), "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a")
        self.assertNotEqual(CHECK.digest(b"").hex(), "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
        self.assertEqual(CHECK.parent(CHECK.ZERO, CHECK.ZERO), CHECK.ZERO)
        self.assertNotEqual(CHECK.parent(CHECK.ZERO, CHECK.ZERO), CHECK.digest(bytes(64)))

    def test_v3_state_root_is_in_hash_preimage(self):
        original = self.headers["v3-balance-root"]
        self.assertEqual(CHECK.check_header(original)[176:208], CHECK.hex_bytes(original["fields"]["state_root"], 32))
        altered = copy.deepcopy(original)
        altered["fields"]["state_root"] = CHECK.ZERO.hex()
        with self.assertRaises(ValueError):
            CHECK.check_header(altered)

    def test_v1_v2_ignore_root_value_but_validate_its_width(self):
        for version in (1, 2):
            h = copy.deepcopy(self.headers[f"v{version}-zero-root"])
            h["fields"]["state_root"] = "ff" * 32
            CHECK.check_header(h)
            h["fields"]["state_root"] = "ff" * 31
            with self.subTest(version=version), self.assertRaises(ValueError):
                CHECK.check_header(h)

    def test_every_v3_unsigned_integer_is_strict(self):
        for field in ("version", "chain_identifier", "height", "timestamp", "next_fusion_price", "next_work_price"):
            for alias in (True, 3.0, -1, 1 << 64, "3"):
                h = copy.deepcopy(self.headers["v3-balance-root"])
                h["fields"][field] = alias
                with self.subTest(field=field, alias=repr(alias)), self.assertRaises(ValueError):
                    CHECK.check_header(h)

    def test_unknown_header_versions_are_refused(self):
        for version in (0, 4, 255):
            h = copy.deepcopy(self.headers["v3-balance-root"])
            h["fields"]["version"] = version
            with self.subTest(version=version), self.assertRaisesRegex(ValueError, "unsupported research header version"):
                CHECK.check_header(h)

    def test_content_member_width_and_order(self):
        h = copy.deepcopy(self.headers["v3-binary-content"])
        h["fields"]["content"].reverse()
        with self.assertRaisesRegex(ValueError, "noncanonical"):
            CHECK.check_header(h)
        for field in ("address", "hash"):
            h = copy.deepcopy(self.headers["v3-binary-content"])
            h["fields"]["content"][0][field] += "00"
            with self.subTest(field=field), self.assertRaises(ValueError):
                CHECK.check_header(h)

    def test_hex_whitespace_width_and_case(self):
        for invalid in (" " + "00" * 32, "00" * 31, "0g" * 32, "00\n" * 32):
            with self.subTest(value=invalid[:8]), self.assertRaises(ValueError):
                CHECK.hex_bytes(invalid, 32)
        h = copy.deepcopy(self.headers["v3-binary-content"])
        for field in ("previous_hash", "data", "changes_hash", "state_root"):
            h["fields"][field] = h["fields"][field].upper()
        for row in h["fields"]["content"]:
            row["address"], row["hash"] = row["address"].upper(), row["hash"].upper()
        for field in ("preimage", "hash", "data_hash", "content_hash"):
            h[field] = h[field].upper()
        CHECK.check_header(h)

    def test_flags_lengths_counts_and_trailing_bytes(self):
        original = CHECK.hex_bytes(self.proofs["stored-zero"]["proof"])
        controls = [original[:98], original[:-1], original + b"\x00"]
        for flag in (2, 128, 255):
            controls.append(bytes([flag]) + original[1:])
        for count in (257, 65535):
            controls.append(original[:97] + count.to_bytes(2, "big") + original[99:])
        for proof in controls:
            with self.subTest(proof_bytes=len(proof)), self.assertRaises(CHECK.ProofError):
                CHECK.decode_proof(proof)

    def test_oversized_value_is_refused_before_hashing(self):
        original = bytearray(CHECK.hex_bytes(self.proofs["stored-zero"]["proof"]))
        offset = 99 + int.from_bytes(original[97:99], "big") * 32
        original[offset:offset + 4] = (CHECK.MAX_VALUE_BYTES + 1).to_bytes(4, "big")
        with mock.patch.object(CHECK, "digest", side_effect=AssertionError("unexpected hash")):
            with self.assertRaises(CHECK.ProofError):
                CHECK.decode_proof(bytes(original))

    def test_duplicate_leaf_paths_and_leaf_count(self):
        leaves = self.states["synthetic-balance-magnitudes"]["leaves"]
        with self.assertRaisesRegex(ValueError, "duplicate leaf path"):
            CHECK.tree_levels([leaves[0], leaves[0]])
        with self.assertRaisesRegex(ValueError, "leaf count"):
            CHECK.tree_levels([leaves[0]] * 1025)

    def test_fixture_file_size_and_duplicate_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / "fixture.json"
            file.write_bytes(b" " * (CHECK.MAX_FILE_BYTES + 1))
            with self.assertRaisesRegex(ValueError, "file exceeds"):
                CHECK.read_corpus(file)
            file.write_text('{"a":1,"a":2}', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "duplicate JSON field"):
                CHECK.read_corpus(file)

    def test_corpus_source_and_trust_claims_are_fixed(self):
        for field in ("network_activation_authenticated", "profile_agreed", "runtime_state_proof_acceptance"):
            d = copy.deepcopy(self.corpus)
            d["scope"][field] = True
            with self.subTest(field=field), self.assertRaises(ValueError):
                CHECK.check_corpus(d)
        d = copy.deepcopy(self.corpus)
        d["scope"]["synthetic"] = 1
        with self.assertRaisesRegex(ValueError, "scope flag type"):
            CHECK.check_corpus(d)
        d = copy.deepcopy(self.corpus)
        d["source"]["revision"] = "00" * 20
        with self.assertRaisesRegex(ValueError, "source pin"):
            CHECK.check_corpus(d)

    def test_reproduction_manifest_reconstructs_selected_git_tree(self):
        _, manifest = DRIVER.source_manifest()
        self.assertEqual(DRIVER.reconstruct_tree(manifest["files"]), CHECK.NODE_TREE)
        corrupted = copy.deepcopy(manifest["files"])
        corrupted["common/trie/proof.go"]["git_blob"] = "00" * 20
        self.assertNotEqual(DRIVER.reconstruct_tree(corrupted), CHECK.NODE_TREE)
        corrupted["../outside"] = corrupted.pop("common/trie/proof.go")
        with self.assertRaisesRegex(ValueError, "unsafe"):
            DRIVER.reconstruct_tree(corrupted)

    def test_reproduction_refuses_changed_or_extra_source_files(self):
        value = b"package example\n"
        pins = {"sample.go": {"bytes": len(value), "sha256": hashlib.sha256(value).hexdigest(),
                              "git_blob": DRIVER.git_hash("blob", value)}}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "sample.go").write_bytes(value)
            self.assertEqual(DRIVER.snapshot_source(root, pins), {"sample.go": value})
            (root / "unexpected.json").write_bytes(b"{}")
            with self.assertRaisesRegex(ValueError, "inventory differs"):
                DRIVER.snapshot_source(root, pins)
            (root / "unexpected.json").unlink()
            (root / "sample.go").write_bytes(b"package changed\n")
            with self.assertRaisesRegex(ValueError, "source bytes differ"):
                DRIVER.snapshot_source(root, pins)

    def test_reproduction_preserves_existing_output_and_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output, evidence = root / "output.json", root / "evidence"
            output.write_bytes(b"retain original\n")
            arguments = ["--node-source", str(root), "--go", "unused", "--output", str(output),
                         "--evidence-directory", str(evidence)]
            with mock.patch.object(DRIVER.subprocess, "run", side_effect=AssertionError("unexpected child")):
                with self.assertRaisesRegex(ValueError, "preserve existing output"):
                    DRIVER.main(arguments)
                self.assertEqual(output.read_bytes(), b"retain original\n")
                self.assertFalse(evidence.exists())
                output.unlink()
                evidence.mkdir()
                with self.assertRaisesRegex(ValueError, "preserve existing evidence"):
                    DRIVER.main(arguments)


if __name__ == "__main__":
    unittest.main(verbosity=2)
