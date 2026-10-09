#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Independent corpus comparisons and adversarial offline consumer controls."""

import base64
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("balance_observation_controls", HERE / "check_balance_observations.py")
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)
c = check.consumer
SELECTED = json.loads((HERE / "testdata/balance-observation-selection.json").read_bytes())
RESPONSE = json.loads((HERE / "testdata/balance-observation-response.json").read_bytes())


UNSET = object()


class BalanceObservationControls(unittest.TestCase):
    def refuse(self, selected=UNSET, response=UNSET):
        with self.assertRaises(c.Refusal):
            c.observe(SELECTED if selected is UNSET else selected, RESPONSE if response is UNSET else response)

    def changed_selection(self, section, key, value):
        chosen = copy.deepcopy(SELECTED)
        (chosen if section is None else chosen[section])[key] = value
        return chosen

    def changed_proof(self, mutate):
        response = copy.deepcopy(RESPONSE)
        raw = bytearray(base64.b64decode(response["result"]["proof"]))
        mutate(raw)
        response["result"]["proof"] = base64.b64encode(raw).decode("ascii")
        return response

    def test_preserved_actual_node_bytes_and_separate_oracles(self):
        report = check.check_observations()
        self.assertEqual((report["preserved_node_observations"], report["candidate_matches"],
                          report["research_policy_refusals"], report["example_matches"]), (18, 17, 1, 1))
        self.assertEqual(report["consumer_result"], "REFUSED")
        self.assertFalse(report["new_node_execution"])
        self.assertFalse(report["network_transport_executed"])

    def test_all_match_reports_keep_acceptance_gates_closed(self):
        for _, chosen, response, error, _ in check.preserved_cases():
            if error:
                continue
            report = c.observe(chosen, response)
            self.assertEqual(report["consumer_result"], "REFUSED")
            self.assertEqual(report["proven"], [])
            self.assertEqual(report["not_proven"], c.NOT_PROVEN)
            self.assertFalse(report["production_state_value_accepted"])
            self.assertFalse(report["header_authentication_executed"])

    def test_stored_zero_and_absence_are_distinct(self):
        zero = c.observe(SELECTED, RESPONSE)
        absent = next(row for row in check.preserved_cases() if not row[1]["claim"]["present"])
        missing = c.observe(absent[1], absent[2])
        self.assertEqual((zero["amount"], missing["amount"]), ("0", "0"))
        self.assertTrue(zero["present"])
        self.assertFalse(missing["present"])

    def test_absent_null_and_empty_value_use_proof_presence(self):
        _, chosen, response, _, _ = next(row for row in check.preserved_cases() if not row[1]["claim"]["present"])
        for value in (None, ""):
            changed = copy.deepcopy(response); changed["result"]["value"] = value
            self.assertFalse(c.observe(chosen, changed)["present"])
        for value in (base64.b64encode(bytes(32)).decode(), 0, False):
            changed = copy.deepcopy(response); changed["result"]["value"] = value
            self.refuse(chosen, changed)

    def test_present_null_empty_or_inconsistent_value_refuses(self):
        for value in (None, "", base64.b64encode(b"\x01" * 32).decode()):
            changed = copy.deepcopy(RESPONSE); changed["result"]["value"] = value
            self.refuse(response=changed)

    def test_positive_maximum_and_257_bit_policy_boundary(self):
        rows = check.preserved_cases()
        maximum = next(row for row in rows if row[0] == "primitive/maximum-256-bit-magnitude")
        self.assertEqual(c.observe(maximum[1], maximum[2])["amount"], str((1 << 256) - 1))
        oversized = next(row for row in rows if row[0] == "primitive/257-bit-magnitude-only")
        self.refuse(oversized[1], oversized[2])

    def test_closed_selection_rejects_trust_flags_and_raw_keys(self):
        for field in ("trusted", "verified", "activation", "raw_key", "accept", "profile_agreed", "endpoint"):
            self.refuse(SELECTED | {field: True})
        for field in SELECTED:
            changed = dict(SELECTED); del changed[field]; self.refuse(changed)

    def test_exact_research_version_and_profile(self):
        for version in (1, 2, 4, True, "3", 3.0):
            self.refuse(self.changed_selection("header", "version", version))
        for profile in ("IAVL_STATE", "production", None, True):
            self.refuse(self.changed_selection(None, "profile", profile))

    def test_uint64_height_chain_and_bool_types(self):
        for value in (0, -1, 1 << 64, True, "17", 17.0):
            self.refuse(self.changed_selection("header", "height", value))
        for value in (-1, 1 << 64, True, "99", 99.0):
            self.refuse(self.changed_selection("header", "chain_identifier", value))

    def test_selected_identity_is_unsigned_and_echoed_without_authentication(self):
        chosen = copy.deepcopy(SELECTED)
        chosen["header"]["hash"] = "11" * 32
        chosen["header"]["chain_identifier"] = 123
        chosen["genesis_hash"] = "22" * 32
        chosen["context_pin"] = "33" * 32
        report = c.observe(chosen, RESPONSE)
        self.assertEqual(report["selected_header_hash"], "11" * 32)
        self.assertEqual(report["selected_chain_identifier"], 123)
        self.assertEqual(report["selected_genesis_hash"], "22" * 32)
        self.assertEqual(report["selected_context_pin"], "33" * 32)
        self.assertFalse(report["header_authentication_executed"])
        self.assertEqual(report["consumer_result"], "REFUSED")

    def test_hash_encodings_and_root_substitution(self):
        for value in ("", "0x" + "00" * 32, "00" * 31, "gg" * 32, None, True):
            self.refuse(self.changed_selection("header", "state_root", value))
        self.refuse(self.changed_selection("header", "state_root", "00" * 32))
        changed = copy.deepcopy(RESPONSE); changed["result"]["root"] = "00" * 32
        self.refuse(response=changed)

    def test_address_and_token_checksums_prefixes_and_widths(self):
        for field, prefix, width in (("address", "z", 20), ("token_standard", "zts", 10)):
            text = SELECTED[field]
            for value in (text[:-1], text + "q", text[:-1] + ("q" if text[-1] != "q" else "p"),
                          check.text_identifier("other", bytes(width)), None, True):
                self.refuse(self.changed_selection(None, field, value))

    def test_upper_case_identifiers_preserve_bytes_mixed_case_refuses(self):
        chosen = SELECTED | {"address": SELECTED["address"].upper(), "token_standard": SELECTED["token_standard"].upper()}
        self.assertEqual(c.prepare_request(chosen), c.prepare_request(SELECTED))
        self.refuse(SELECTED | {"address": "Z" + SELECTED["address"][1:]})

    def test_known_node_identifier_strings_and_bech32m_refusal(self):
        self.assertEqual(c.identifier("z1qxemdeddedxplasmaxxxxxxxxxxxxxxxxsctrp", "z", 20)[0], 1)
        self.assertEqual(check.text_identifier("zts", c.identifier("zts1znnxxxxxxxxxxxxx9z4ulx", "zts", 10)), "zts1znnxxxxxxxxxxxxx9z4ulx")
        # Bech32m differs by the checksum constant; a valid original checksum
        # replaced with its Bech32m counterpart must not enter this profile.
        text = SELECTED["address"]; words = [c.ALPHABET.index(x) for x in text[-6:]]
        original = sum(x << shift for x, shift in zip(words, (25, 20, 15, 10, 5, 0)))
        changed = original ^ 1 ^ 0x2bc830a3
        alternate = text[:-6] + "".join(c.ALPHABET[(changed >> shift) & 31] for shift in (25, 20, 15, 10, 5, 0))
        self.refuse(SELECTED | {"address": alternate})

    def test_wrong_selected_address_or_token_cannot_substitute_path(self):
        self.refuse(SELECTED | {"address": check.text_identifier("z", bytes(20))})
        self.refuse(SELECTED | {"token_standard": check.text_identifier("zts", bytes(10))})

    def test_claim_amount_format_presence_and_absence_semantics(self):
        for amount in ("", "00", "+0", "-1", " 0", "1.0", "0" * 79, True, 0):
            self.refuse(self.changed_selection("claim", "amount", amount))
        for present in (False, 0, 1, None, "true"):
            self.refuse(self.changed_selection("claim", "present", present))
        self.refuse(self.changed_selection("claim", "amount", "1"))

    def test_rpc_envelope_closed_shape_and_typed_identity(self):
        for response in ([], None, RESPONSE | {"error": None}, RESPONSE | {"height": 17},
                         RESPONSE | {"jsonrpc": "1.0"}, RESPONSE | {"id": 1}, RESPONSE | {"id": True}):
            self.refuse(response=response)
        chosen = SELECTED | {"request_id": 1}; response = RESPONSE | {"id": 1}
        self.assertEqual(c.observe(chosen, response)["candidate_observation"], "MATCH")
        self.refuse(chosen, RESPONSE | {"id": True})
        self.refuse(chosen, RESPONSE | {"id": 1.0})

    def test_selected_request_id_limits(self):
        for value in (True, None, "", "x" * 65, "a\n", -1, 1 << 53, 1.0):
            self.refuse(SELECTED | {"request_id": value})

    def test_base64_size_is_checked_before_decoding(self):
        with mock.patch.object(c.base64, "b64decode", side_effect=AssertionError("unexpected decode")):
            with self.assertRaises(c.Refusal): c.b64("A" * 11105, c.MAX_PROOF)
            with self.assertRaises(c.Refusal): c.b64("A" * 45, 32)

    def test_base64_alphabet_padding_and_unused_bits_are_strict(self):
        for value in ("/w", "/w===", "/w==\n", "_w==", "Zh==", None, True, []):
            with self.assertRaises(c.Refusal): c.b64(value, 32)
        self.assertEqual(c.b64("/w==", 32), b"\xff")

    def test_proof_flags_path_leaf_and_exact_lengths(self):
        for position in (0, 1, 33):
            self.refuse(response=self.changed_proof(lambda raw, p=position: raw.__setitem__(p, raw[p] ^ 2)))
        self.refuse(response=self.changed_proof(lambda raw: raw.extend(b"\x00")))
        self.refuse(response=self.changed_proof(lambda raw: raw.pop()))

    def test_bitmap_counts_and_sibling_bytes_are_bound(self):
        row = next(row for row in check.preserved_cases() if row[0] == "primitive/stored-zero")
        for index in (65, 97, 98, 99):
            changed = copy.deepcopy(row[2])
            raw = bytearray(base64.b64decode(changed["result"]["proof"]))
            raw[index] ^= 1
            changed["result"]["proof"] = base64.b64encode(raw).decode()
            self.refuse(row[1], changed)

    def test_present_value_length_policy_refuses_before_leaf_hashing(self):
        raw = bytearray(base64.b64decode(RESPONSE["result"]["proof"]))
        offset = 99 + 32 * int.from_bytes(raw[97:99], "big")
        for size in (0, 31, 33, (1 << 32) - 1):
            changed = bytearray(raw); changed[offset:offset + 4] = size.to_bytes(4, "big")
            with mock.patch.object(c.hashlib, "sha3_256", side_effect=AssertionError("unexpected hashing")):
                with self.assertRaises(c.Refusal):
                    c.proof_observation(bytes(changed), raw[1:33], bytes.fromhex(RESPONSE["result"]["root"]))

    def test_excluded_key_absence_cannot_become_balance(self):
        path = check.oracle.digest(b"\x03" + bytes(20) + b"\x05")
        proof = b"\x00" + path + bytes(66)
        chosen = SELECTED | {"claim": {"present": False, "amount": "0"}}
        chosen = copy.deepcopy(chosen); chosen["header"]["state_root"] = "00" * 32
        response = check.fixture_response("00" * 32, False, b"", proof)
        self.refuse(chosen, response)

    def test_zero_siblings_are_refused_by_explicit_research_policy(self):
        absent = next(row for row in check.preserved_cases() if not row[1]["claim"]["present"])
        chosen = copy.deepcopy(absent[1]); chosen["header"]["state_root"] = "00" * 32
        path = c.selection(chosen); path = check.oracle.digest(path)
        raw = b"\x00" + path + bytes(32) + b"\x80" + bytes(31) + b"\x00\x01" + bytes(32)
        self.assertEqual(check.oracle.proof_result(bytes(32), path, b"", raw, False), "match")
        self.refuse(chosen, check.fixture_response("00" * 32, False, b"", raw))

    def test_response_result_has_no_key_or_trust_override(self):
        for field in ("key", "path", "trusted", "hash", "height", "profile"):
            changed = copy.deepcopy(RESPONSE); changed["result"][field] = True
            self.refuse(response=changed)

    def test_bounded_json_duplicate_depth_constants_and_bad_utf8(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input.json"
            for raw in (b'{"x":1,"x":2}', b"[" * 9 + b"]" * 9, b'{"x":NaN}', b"\xff", b"0" * 8193):
                path.write_bytes(raw)
                with self.assertRaises(c.Refusal): c.read_document(path, c.MAX_SELECTION)
            path.write_bytes(b'{"x":"[[[[[[[[[["}')
            self.assertEqual(c.read_document(path, c.MAX_SELECTION)[1], {"x": "[[[[[[[[[["})

    def test_owned_regular_files_close_and_symlinks_refuse(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input.json"; path.write_text("{}")
            self.assertEqual(c.read_document(path, 2)[1], {})
            path.unlink()  # Windows also requires the opened descriptor closed.
            with self.assertRaises((OSError, c.Refusal)): c.read_document(directory, 100)
            if sys.platform != "win32":
                target = Path(directory) / "target.json"; target.write_text("{}")
                path.symlink_to(target)
                with self.assertRaises(c.Refusal): c.read_document(path, 100)

    def test_file_size_and_nonregular_inputs_refuse_before_json(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "oversize.json"; path.write_bytes(b" " * (c.MAX_SELECTION + 1))
            with mock.patch.object(c.json, "loads", side_effect=AssertionError("unexpected JSON parsing")):
                with self.assertRaises(c.Refusal): c.read_document(path, c.MAX_SELECTION)
            if sys.platform != "win32":
                fifo = Path(directory) / "input.fifo"; c.os.mkfifo(fifo)
                with self.assertRaises(c.Refusal): c.read_document(fifo, 100)

    def test_portable_reader_without_unix_open_flags(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input.json"; path.write_bytes(b"{}")
            with mock.patch.dict(c.os.__dict__):
                c.os.__dict__.pop("O_NONBLOCK", None)
                c.os.__dict__.pop("O_NOFOLLOW", None)
                self.assertEqual(c.read_document(path, 2)[1], {})

    def test_request_and_observe_cli_and_private_error_redaction(self):
        command = [sys.executable, "-I", "-B", str(HERE / "observe_balance.py")]
        paths = ["--selection", str(HERE / "testdata/balance-observation-selection.json")]
        requested = subprocess.run(command + ["request"] + paths, capture_output=True, timeout=20)
        self.assertEqual(requested.returncode, 0)
        self.assertEqual(json.loads(requested.stdout)["request"], c.prepare_request(SELECTED))
        observed = subprocess.run(command + ["observe"] + paths + ["--response", str(HERE / "testdata/balance-observation-response.json")], capture_output=True, timeout=20)
        self.assertEqual(observed.returncode, 0)
        self.assertEqual(json.loads(observed.stdout)["consumer_result"], "REFUSED")
        refused = subprocess.run(command + ["observe", "--selection", "private-secret-missing-file", "--response", "other"], capture_output=True, timeout=20)
        self.assertEqual(refused.returncode, 1)
        self.assertNotIn(b"private-secret", refused.stdout + refused.stderr)
        self.assertEqual(json.loads(refused.stdout)["error"], "file_io")

    def test_cli_wrong_claim_and_mode_return_nonzero(self):
        command = [sys.executable, "-I", "-B", str(HERE / "observe_balance.py")]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "selection.json"
            path.write_text(json.dumps(self.changed_selection("claim", "amount", "1")))
            result = subprocess.run(command + ["observe", "--selection", str(path), "--response", str(HERE / "testdata/balance-observation-response.json")], capture_output=True, timeout=20)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(json.loads(result.stdout)["error"], "selected_claim")
            result = subprocess.run(command + ["request", "--selection", str(path), "--response", str(path)], capture_output=True, timeout=20)
            self.assertEqual(result.returncode, 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
