#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""RAM-only byte controls. Fixtures do not authenticate headers or execute Go."""
import copy
import hashlib
import importlib.util
from pathlib import Path
import struct
import sys
import unittest
from unittest import mock

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("independent_patch_bytes", HERE / "cache_replay_patch_bytes.py")
H = importlib.util.module_from_spec(spec)
spec.loader.exec_module(H)
GENESIS = "9e204601d1b7b1427fe12bc82622e610d8a6ad43c40abf020eb66e538bb8eeb0"
SECOND = "fbe4d2002715d5993894e36fe23eefab052ffe697861465b1be8c07d786beed0"


def varint(value):
    output = []
    while value > 127:
        output.append(128 + value % 128)
        value //= 128
    return bytes(output + [value])


def integer(number, value):
    return varint(number * 8) + varint(value)


def message(number, value):
    return varint(number * 8 + 2) + varint(len(value)) + value


def hash_proto(value):
    return message(1, value)


def put(key, value):
    return b"\x01" + varint(len(key)) + key + varint(len(value)) + value


def fixture(source=b"", accounts=(), data=b""):
    previous = bytes.fromhex(GENESIS)
    timestamp, height = 1637755210, 2
    changes = hashlib.sha3_256(source).digest()
    account_bytes = b"".join(address + struct.pack(">Q", level) + digest for address, level, digest in accounts)
    frame = struct.pack(">QQ", 1, 1) + previous + struct.pack(">QQ", height, timestamp)
    frame += hashlib.sha3_256(data).digest() + hashlib.sha3_256(account_bytes).digest() + changes
    digest = hashlib.sha3_256(frame).digest()
    identifier = {"hash": digest.hex(), "height": height}
    body = integer(1, 1) + integer(2, 1) + message(3, hash_proto(digest)) + message(4, hash_proto(previous))
    body += integer(5, height) + integer(6, timestamp)
    if data:
        body += message(7, data)
    for address, level, account_hash in accounts:
        header = message(1, message(1, address)) + message(2, message(1, hash_proto(account_hash)) + integer(2, level))
        body += message(8, header)
    body += message(9, hash_proto(changes))
    hh = message(1, hash_proto(digest)) + integer(2, height)
    rows = [(b"\0", hh), (b"\1" + digest, struct.pack(">Q", height)), (b"\2" + struct.pack(">Q", height), body)]
    return {"raw": b"".join(put(*row) for row in rows), "rows": rows, "frame": frame,
            "identifier": identifier, "previous": GENESIS, "timestamp": timestamp,
            "source": source, "content_count": len(accounts)}


def check(value, raw=None):
    return H.verify_stored_patch(value["source"], value["raw"] if raw is None else raw,
                                 value["identifier"], value["previous"], value["timestamp"], value["content_count"])


class StoredPatchByteTests(unittest.TestCase):
    def test_empty_successor_matches_previously_recorded_go_metadata(self):
        value = fixture()
        self.assertEqual(value["identifier"], {"hash": SECOND, "height": 2})
        self.assertEqual(len(value["raw"]), 218)
        self.assertEqual(hashlib.sha256(value["raw"]).hexdigest(),
                         "f67ba4ddbf4cf699d3dc6515d24a657897c09e4cea02c028bd7f123094d3d539")
        report = check(value)
        self.assertEqual(report["independent_v1_frame_hex"], value["frame"].hex())
        self.assertEqual(report["expected_stored_bytes"], 218)
        self.assertEqual(report["content_headers"], 0)

    def test_synthetic_ordered_accounts_data_and_source_concatenation(self):
        accounts = [(b"a" * 20, 2, b"x" * 32), (b"b" * 20, 300, b"y" * 32)]
        value = fixture(b"synthetic source changes, not execution evidence", accounts, b"selected data")
        report = check(value)
        self.assertEqual(report["content_headers"], 2)
        self.assertEqual(report["independent_v1_frame_hex"], value["frame"].hex())
        self.assertEqual(report["expected_stored_sha256"], hashlib.sha256(value["source"] + value["raw"]).hexdigest())
        self.assertEqual(report["expected_stored_bytes"], len(value["source"]) + len(value["raw"]))

    def test_batch_operation_and_framing_changes_are_refused(self):
        value = fixture()
        rows = value["rows"]
        encoded = [put(*row) for row in rows]
        changes = {
            "missing-put": b"".join(encoded[:2]),
            "extra-put": value["raw"] + encoded[0],
            "reordered-puts": b"".join(reversed(encoded)),
            "delete-operation": b"\0" + value["raw"][1:],
            "truncated-value": value["raw"][:-1],
            "noncanonical-varint": b"\x01\x81\x00" + value["raw"][2:],
            "truncated-varint": b"\x01\x80",
            "empty-key": b"\x01\0\0" + b"".join(encoded[1:]),
            "log-batch-header": bytes(12) + value["raw"],
        }
        for name, raw in changes.items():
            with self.subTest(name=name), self.assertRaises(ValueError):
                check(value, raw)

    def test_full_index_identities_and_header_fields_are_refused(self):
        value = fixture()
        rows = value["rows"]
        body = rows[2][1]
        changes = {
            "wrong-indexed-height": [(rows[0]), (rows[1][0], struct.pack(">Q", 3)), rows[2]],
            "wrong-height-key": [*rows[:2], (b"\2" + struct.pack(">Q", 3), body)],
            "wrong-frontier-identifier": [(rows[0][0], rows[0][1][:-1] + b"\3"), *rows[1:]],
            "duplicate-header-scalar": [*rows[:2], (rows[2][0], integer(1, 1) + body)],
            "unexpected-state-root-field": [*rows[:2], (rows[2][0], body + message(14, hash_proto(bytes(32))))],
            "unsupported-wire": [*rows[:2], (rows[2][0], b"\x0d" + body[1:])],
        }
        for name, altered in changes.items():
            with self.subTest(name=name), self.assertRaises(ValueError):
                check(value, b"".join(put(*row) for row in altered))

    def test_selected_expectations_cannot_be_taken_from_substituted_metadata(self):
        original = fixture()
        for key, replacement in (
            ("identifier", {"hash": "0" * 64, "height": 2}),
            ("previous", "0" * 64), ("timestamp", 1637755211),
            ("content_count", 1), ("source", b"changed source bytes"),
        ):
            changed = copy.deepcopy(original)
            changed[key] = replacement
            with self.subTest(key=key), self.assertRaises(ValueError):
                check(changed)

    def test_unordered_accounts_are_refused_even_for_their_matching_hash(self):
        value = fixture(accounts=[(b"b" * 20, 2, b"x" * 32), (b"a" * 20, 1, b"y" * 32)])
        with self.assertRaisesRegex(ValueError, "not ordered"):
            check(value)

    def test_nested_account_shapes_and_widths_have_specific_refusals(self):
        address, digest, height = b"a" * 20, b"x" * 32, 2
        value = fixture(accounts=[(address, height, digest)])
        address_field = message(1, message(1, address))
        identifier = message(1, hash_proto(digest)) + integer(2, height)
        good = address_field + message(2, identifier)
        body = value["rows"][2][1]
        self.assertEqual(body.count(message(8, good)), 1)
        controls = {
            "short-address": (message(1, message(1, address[:-1])) + message(2, identifier), "Wrong address width"),
            "long-address": (message(1, message(1, address + b"a")) + message(2, identifier), "Wrong address width"),
            "short-account-hash": (address_field + message(2, message(1, hash_proto(digest[:-1])) + integer(2, height)), "Wrong hash width"),
            "zero-account-height": (address_field + message(2, message(1, hash_proto(digest)) + integer(2, 0)), "Wrong account height"),
            "missing-identifier": (address_field, "Wrong account header shape"),
            "extra-account-field": (good + integer(3, 1), "Wrong account header shape"),
            "duplicate-address": (message(1, message(1, address) + message(1, address)) + message(2, identifier), "Duplicate protobuf scalar"),
            "wrong-height-wire": (address_field + message(2, message(1, hash_proto(digest)) + message(2, b"a")), "Wrong protobuf wire type"),
            "reversed-account-fields": (message(2, identifier) + address_field, "Unexpected protobuf field ordering"),
        }
        for name, (altered, refusal) in controls.items():
            changed = body.replace(message(8, good), message(8, altered))
            raw = b"".join(put(*row) for row in [*value["rows"][:2], (value["rows"][2][0], changed)])
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, refusal):
                check(value, raw)

    def test_input_types_widths_and_bounds_are_strict(self):
        original = fixture()
        for key, replacement in (
            ("identifier", None), ("identifier", {"hash": SECOND, "height": True}),
            ("identifier", {"hash": SECOND.upper(), "height": 2}),
            ("identifier", {"hash": SECOND, "height": 2, "extra": True}),
            ("previous", "00"), ("timestamp", True), ("timestamp", 1 << 64),
            ("content_count", True), ("content_count", -1), ("content_count", H.MAX_HEADERS + 1),
            ("source", bytearray(b"source")),
        ):
            changed = copy.deepcopy(original)
            changed[key] = replacement
            with self.subTest(key=key, replacement=str(replacement)[:70]), self.assertRaises(ValueError):
                check(changed)
        for raw in (None, bytearray(original["raw"]), b""):
            with self.assertRaises(ValueError):
                check(original, raw) if raw is not None else H.metadata_records(raw)
        with mock.patch.object(H, "MAX_SOURCE_BYTES", 1), self.assertRaises(ValueError):
            H.verify_stored_patch(b"ab", original["raw"], original["identifier"], GENESIS, original["timestamp"], 0)
        with mock.patch.object(H, "MAX_METADATA_BYTES", 1), self.assertRaises(ValueError):
            check(original)
        self.assertEqual(H.MAX_SOURCE_BYTES, 16 << 20)
        self.assertEqual(H.MAX_METADATA_BYTES, 4 << 20)

    def test_varint_integer_limits_offsets_and_canonical_encoding(self):
        for number in (0, 1, 127, 128, 300, (1 << 64) - 1):
            self.assertEqual(H.uvar(varint(number), 0), (number, len(varint(number))))
            self.assertEqual(H.encode_uvar(number), varint(number))
        for raw, offset in ((b"\0", -1), (b"\0", 2), (b"\0", True), (bytearray(b"\0"), 0),
                            (b"\x80", 0), (b"\x80\0", 0), (b"\xff" * 9 + b"\x02", 0)):
            with self.subTest(raw=str(raw), offset=offset), self.assertRaises(ValueError):
                H.uvar(raw, offset)
        for number in (True, -1, 1 << 64, 1.0):
            with self.assertRaises(ValueError):
                H.encode_uvar(number)


if __name__ == "__main__":
    unittest.main()
