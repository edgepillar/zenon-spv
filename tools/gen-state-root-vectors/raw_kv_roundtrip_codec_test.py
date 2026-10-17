#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Literal framing, completeness and hostile-boundary controls for raw dumps."""
import copy
import hashlib
import importlib.util
from pathlib import Path
import random
import unittest


HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("raw_store_codec_controls", HERE / "raw_kv_roundtrip_codec.py")
C = importlib.util.module_from_spec(spec)
spec.loader.exec_module(C)
GOLDEN = bytes.fromhex("01010001610101050103")
RECORDS = ((b"\x00", b"a"), (b"\x05", b"\x03"))
PIN = {"bytes": 10, "records": 2,
       "sha256": hashlib.sha256(GOLDEN).hexdigest()}


def limits(**values):
    return dict({"bytes": 8 << 20, "records": 32768,
                 "key_bytes": 128, "value_bytes": 1 << 20}, **values)


class RawStoreCodecControls(unittest.TestCase):
    def test_literal_body_framing_has_no_journal_header(self):
        self.assertEqual(C.encode_dump(RECORDS), GOLDEN)
        self.assertEqual(C.decode_dump(GOLDEN), RECORDS)
        self.assertEqual(C.decode_selected_dump(GOLDEN, PIN), RECORDS)
        self.assertEqual(C.BATCH_SOURCE_SHA256,
                         "299129fbb88354f140bd7e7c83ffda6554e9af906ab68589f72e7c212f49c096")

    def test_empty_grammar_does_not_establish_a_store(self):
        self.assertEqual(C.encode_dump(()), b"")
        self.assertEqual(C.decode_dump(b""), ())
        self.assertEqual(C.scope()["consumer_result"], "REFUSED")
        for field in ("DAG_or_refcounts_verified", "authenticated_snapshot_import",
                      "accepted_header_binding", "production_state_value_accepted"):
            self.assertIs(C.scope()[field], False)

    def test_valid_record_boundary_prefix_needs_independent_selection(self):
        self.assertEqual(C.decode_dump(GOLDEN[:5]), RECORDS[:1])
        with self.assertRaisesRegex(ValueError, "selection_bytes"):
            C.decode_selected_dump(GOLDEN[:5], PIN)
        for size in (1, 2, 3, 4, 6, 7, 8, 9):
            with self.assertRaises(ValueError):
                C.decode_dump(GOLDEN[:size])

    def test_literal_varint_width_boundaries(self):
        for length, width in ((0, b"\x00"), (127, b"\x7f"),
                              (128, b"\x80\x01"), (16383, b"\xff\x7f"),
                              (16384, b"\x80\x80\x01")):
            value = b"V" * length
            raw = b"\x01\x01\x00" + width + value
            self.assertEqual(C.encode_dump(((b"\x00", value),)), raw)
            self.assertEqual(C.decode_dump(raw), ((b"\x00", value),))
        key = b"K" * 128
        self.assertEqual(C.encode_dump(((key, b""),)), b"\x01\x80\x01" + key + b"\x00")

    def test_independent_single_byte_width_fixture_maps(self):
        randomizer = random.Random(0x9C71)
        for _ in range(256):
            rows = tuple((b"K" + bytes([index]), randomizer.randbytes(randomizer.randrange(41)))
                         for index in range(randomizer.randrange(33)))
            raw = b"".join(b"\x01" + bytes([len(k)]) + k + bytes([len(v)]) + v for k, v in rows)
            self.assertEqual(C.encode_dump(rows), raw)
            self.assertEqual(C.decode_dump(raw), rows)

    def test_nonminimal_varints_are_not_canonical_exports(self):
        for raw in (b"\x01\x81\x00\x00\x00", b"\x01\x01\x00\x80\x00"):
            with self.assertRaisesRegex(ValueError, "nonminimal_varint"):
                C.decode_dump(raw)

    def test_uint64_overflow_is_bounded_before_field_slicing(self):
        for data in (b"\xff" * 9 + b"\x02", b"\x80" * 100000):
            with self.assertRaisesRegex(ValueError, "varint_overflow"):
                C.decode_dump(b"\x01" + data)
        with self.assertRaisesRegex(ValueError, "key_size"):
            C.decode_dump(b"\x01" + b"\xff" * 9 + b"\x01")

    def test_truncated_declared_fields_are_refused(self):
        for raw, reason in ((b"\x01", "truncated_varint"),
                            (b"\x01\x01", "truncated_key"),
                            (b"\x01\x01\x00", "truncated_varint"),
                            (b"\x01\x01\x00\x02A", "truncated_value")):
            with self.assertRaisesRegex(ValueError, reason):
                C.decode_dump(raw)

    def test_deletes_unknown_tags_and_journal_headers_are_refused(self):
        for raw in (b"\x00\x01K", b"\x02", b"\xff", bytes(12), GOLDEN + b"\x00"):
            with self.assertRaisesRegex(ValueError, "put_records_only"):
                C.decode_dump(raw)

    def test_duplicate_unordered_and_empty_keys_are_refused(self):
        for rows in ((RECORDS[0], RECORDS[0]), tuple(reversed(RECORDS))):
            with self.assertRaisesRegex(ValueError, "key_order"):
                C.encode_dump(rows)
        for raw in (GOLDEN[:5] + GOLDEN[:5], GOLDEN[5:] + GOLDEN[:5]):
            with self.assertRaisesRegex(ValueError, "key_order"):
                C.decode_dump(raw)
        with self.assertRaisesRegex(ValueError, "key_size"):
            C.encode_dump(((b"", b"V"),))
        with self.assertRaisesRegex(ValueError, "key_size"):
            C.decode_dump(b"\x01\x00\x00")

    def test_dump_and_record_count_caps_apply_on_both_paths(self):
        with self.assertRaisesRegex(ValueError, "dump_size"):
            C.encode_dump(RECORDS, limits(bytes=9))
        with self.assertRaisesRegex(ValueError, "dump_size"):
            C.decode_dump(GOLDEN, limits(bytes=9))
        with self.assertRaises(ValueError):
            C.encode_dump(RECORDS, limits(records=1))
        with self.assertRaisesRegex(ValueError, "record_count"):
            C.decode_dump(GOLDEN, limits(records=1))

    def test_key_and_value_caps_precede_declared_slicing(self):
        with self.assertRaisesRegex(ValueError, "key_size"):
            C.decode_dump(b"\x01\x02", limits(key_bytes=1))
        with self.assertRaisesRegex(ValueError, "value_size"):
            C.decode_dump(b"\x01\x01\x00\x02", limits(value_bytes=1))
        with self.assertRaisesRegex(ValueError, "key_size"):
            C.encode_dump(((b"KK", b""),), limits(key_bytes=1))
        with self.assertRaisesRegex(ValueError, "value_size"):
            C.encode_dump(((b"K", b"VV"),), limits(value_bytes=1))

    def test_bool_float_unknown_and_excess_limits_are_refused(self):
        for field in limits():
            for value in (True, 0, -1, 1.0, None, limits()[field] + 1):
                with self.assertRaisesRegex(ValueError, "limits"):
                    C.decode_dump(GOLDEN, limits(**{field: value}))
        for value in ({}, {"extra": 1}, [1], object()):
            with self.assertRaisesRegex(ValueError, "limits"):
                C.decode_dump(GOLDEN, value)

    def test_mutable_subclassed_or_nonbyte_inputs_are_refused(self):
        class HostileBytes(bytes):
            def __len__(self):
                raise AssertionError("Untrusted length hook executed")
        for raw in (bytearray(GOLDEN), memoryview(GOLDEN), HostileBytes(GOLDEN), "text"):
            with self.assertRaisesRegex(ValueError, "immutable_bytes_required"):
                C.decode_dump(raw)
        for value in (bytearray(b"V"), memoryview(b"V"), HostileBytes(b"V"), None):
            with self.assertRaisesRegex(ValueError, "record_bytes"):
                C.encode_dump(((b"K", value),))

    def test_unbounded_iterators_and_malformed_record_shapes_are_refused(self):
        class HostileMeta(type):
            def __eq__(cls, other):
                raise AssertionError("Untrusted type equality executed")
        class HostileRecords(metaclass=HostileMeta):
            def __iter__(self):
                raise AssertionError("Untrusted iterator executed")
        with self.assertRaises(ValueError):
            C.encode_dump(HostileRecords())
        for rows in (([b"K", b"V"],), ((b"K",),), ((b"K", b"V", b"X"),), (None,)):
            with self.assertRaisesRegex(ValueError, "record_shape"):
                C.encode_dump(rows)

    def test_selected_digest_count_shapes_and_types_are_bound(self):
        for field, value in (("bytes", True), ("records", True), ("records", -1),
                             ("sha256", PIN["sha256"].upper()), ("sha256", "00")):
            pin = dict(PIN, **{field: value})
            with self.assertRaisesRegex(ValueError, "selection"):
                C.decode_selected_dump(GOLDEN, pin)
        for pin in ({}, dict(PIN, extra=1), list(PIN)):
            with self.assertRaisesRegex(ValueError, "selection"):
                C.decode_selected_dump(GOLDEN, pin)
        with self.assertRaisesRegex(ValueError, "selection_records"):
            C.decode_selected_dump(GOLDEN, dict(PIN, records=1))

    def test_equal_size_mutation_does_not_satisfy_selected_digest(self):
        changed = GOLDEN[:4] + b"b" + GOLDEN[5:]
        self.assertEqual(len(changed), PIN["bytes"])
        with self.assertRaisesRegex(ValueError, "selection_digest"):
            C.decode_selected_dump(changed, PIN)

    def test_decoded_records_are_independent_immutable_bytes(self):
        pin = copy.deepcopy(PIN)
        result = C.decode_selected_dump(GOLDEN, pin)
        pin["records"] = 0
        self.assertEqual(result, RECORDS)
        with self.assertRaises(TypeError):
            result[0][1][0] = 0
        first = C.scope()
        first["consumer_result"] = "ACCEPTED"
        self.assertEqual(C.scope()["consumer_result"], "REFUSED")


if __name__ == "__main__":
    unittest.main(verbosity=2)
