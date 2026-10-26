#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Finite byte, refusal, CLI and bounded-read controls; no representative dataset."""
import argparse
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import time
import tracemalloc
import unittest
from unittest import mock

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("ledger_inventory", HERE / "inventory.py")
INV = importlib.util.module_from_spec(spec)
spec.loader.exec_module(INV)
PROVENANCE = hashlib.sha256(b"synthetic owner intake, not authenticated").hexdigest()
MEASUREMENTS = {}


def varint(number):
    # Independent fixture encoder, not the implementation's parser.
    out = []
    while True:
        digit, number = number % 128, number // 128
        out.append(digit + (128 if number else 0))
        if not number:
            return bytes(out)


def dump(rows):
    return b"".join(b"\x01" + varint(len(k)) + k + varint(len(v)) + v for k, v in rows)


def pin(raw, records):
    return {"bytes": len(raw), "records": records,
            "sha256": hashlib.sha256(raw).hexdigest(),
            "provenance_sha256": PROVENANCE, "record_space": "effective-raw-ledger"}


def inspect(rows, **options):
    raw = dump(rows)
    return INV.inventory(io.BytesIO(raw), pin(raw, len(rows)), **options)


class ShortReads(io.BytesIO):
    def read(self, size):
        if size < 0 or size > INV.CHUNK_BYTES:
            raise AssertionError("unbounded read requested")
        return super().read(min(size, 3))


class CountedReads(io.BytesIO):
    def __init__(self, raw):
        super().__init__(raw)
        self.requests = []

    def read(self, size):
        if not 0 < size <= INV.CHUNK_BYTES:
            raise AssertionError("unbounded read requested")
        self.requests.append(size)
        return super().read(size)


class VirtualValue:
    """A large logical value with a tiny prefix and no retained full payload."""
    def __init__(self, size):
        self.prefix = b"\x01\x01\x03" + varint(size)
        self.size, self.offset, self.max_request = size, 0, 0

    def read(self, size):
        if not 0 < size <= INV.CHUNK_BYTES:
            raise AssertionError("unbounded read requested")
        self.max_request = max(self.max_request, size)
        if self.offset < len(self.prefix):
            part = self.prefix[self.offset:self.offset + size]
        else:
            part = b"\x7f" * min(size, max(0, self.size + len(self.prefix) - self.offset))
        self.offset += len(part)
        return part


class LedgerInventoryTests(unittest.TestCase):
    def refused(self, raw, records=1, selected=None, caps=None):
        with self.assertRaises(INV.Refused):
            INV.inventory(io.BytesIO(raw), pin(raw, records) if selected is None else selected, caps)

    def cli(self, raw, records, extra=()):
        selected = pin(raw, records)
        argv = [sys.executable, "-I", "-B", str(HERE / "inventory.py"),
                "--expect-bytes", str(selected["bytes"]),
                "--expect-records", str(selected["records"]),
                "--expect-sha256", selected["sha256"], "--provenance-sha256", PROVENANCE]
        return subprocess.run(argv + list(extra), input=raw, capture_output=True, timeout=20)

    def test_empty_selected_stream_has_no_completeness_authority(self):
        report = inspect([])
        self.assertEqual(report["records"], 0)
        self.assertTrue(report["selection_matched"])
        self.assertTrue(report["end_of_stream_observed"])
        self.assertEqual(report["distinct_typed_balance_addresses"], 0)
        self.assertTrue(all(row["key_bytes"]["count"] == 0 for row in report["families"].values()))
        for key, value in report["scope"].items():
            if isinstance(value, bool):
                self.assertFalse(value, key)

    def test_literal_three_byte_empty_key_empty_value(self):
        raw = bytes.fromhex("010000")
        report = INV.inventory(io.BytesIO(raw), pin(raw, 1))
        row = report["families"]["empty_key"]
        self.assertEqual(row["present_empty_values"], 1)
        self.assertEqual(row["key_bytes"], {"count": 1, "total": 0, "min": 0, "max": 0, "bins": [[0, 0, 1]]})
        self.assertEqual(row["put_wire_bytes"]["total"], 3)

    def test_candidate_family_prefixes_are_measured_separately(self):
        account = b"\x03" + bytes.fromhex("11" * 20)
        fixtures = [(b"", "empty_key"), (b"\x03", "account_prefix_short"),
                    (account, "account_prefix_short"),
                    (account + b"\x00", "frontier"),
                    (account + b"\x00\x01", "frontier_other_width"),
                    (account + b"\x01", "account_other"),
                    (account + b"\x03", "balance_prefix_other_width"),
                    (account + b"\x03" + b"t" * 9, "balance_prefix_other_width"),
                    (account + b"\x03" + b"t" * 10, "typed_balance"),
                    (account + b"\x03" + b"t" * 11, "balance_prefix_other_width"),
                    (account + b"\x04", "contract_storage"),
                    (account + b"\x04\x00\xff", "contract_storage"),
                    (account + b"\x05", "plasma"),
                    (account + b"\x05\x00", "plasma_other_width"),
                    (account + b"\x06\x01", "receive_index_06"),
                    (account + b"\x07\x01", "receive_index_07"),
                    (b"\x04", "mailbox_prefix_short"),
                    (b"\x04" + b"a" * 20, "mailbox"),
                    (b"\x08\x00", "znn_balance_index"), (b"\xff", "other_namespace")]
        for key, expected in fixtures:
            with self.subTest(family=expected, width=len(key)):
                report = inspect([(key, b"v")])
                self.assertEqual(report["families"][expected]["key_bytes"]["count"], 1)
                self.assertEqual(sum(row["key_bytes"]["count"] for row in report["families"].values()), 1)
                self.assertFalse(report["scope"]["profile_agreed"])

    def test_exact_byte_accounting_and_histogram_bins(self):
        sizes = [0, 1, 2, 3, 4, 31, 32, 33, 128]
        rows = [(bytes([160 + i]), bytes(n) if n == 32 else b"v" * n) for i, n in enumerate(sizes)]
        report = inspect(rows)
        row = report["families"]["other_namespace"]
        self.assertEqual(report["input_bytes"], 271)
        self.assertEqual(row["key_bytes"], {"count": 9, "total": 9, "min": 1, "max": 1, "bins": [[1, 1, 9]]})
        self.assertEqual(row["raw_value_bytes"], {"count": 9, "total": 234, "min": 0, "max": 128,
                         "bins": [[0, 0, 1], [1, 1, 1], [2, 3, 2], [4, 7, 1], [16, 31, 1], [32, 63, 2], [128, 255, 1]]})
        self.assertEqual(row["put_wire_bytes"], {"count": 9, "total": 271, "min": 4, "max": 133,
                         "bins": [[4, 7, 4], [8, 15, 1], [32, 63, 3], [128, 255, 1]]})
        self.assertEqual((row["present_empty_values"], row["raw_zero32_values"], row["values_over32"]), (1, 1, 2))
        self.assertEqual(report["quantile_method"], "not computed")

    def test_storage_suffix_sizes_are_not_mailbox_sizes(self):
        prefix = b"\x03" + b"a" * 20 + b"\x04"
        rows = [(prefix, b""), (prefix + b"xyz", b"long"), (b"\x04" + b"a" * 20, b"pending")]
        report = inspect(rows)
        self.assertEqual(report["storage_suffix_bytes"], {"count": 2, "total": 3, "min": 0, "max": 3, "bins": [[0, 0, 1], [2, 3, 1]]})
        self.assertEqual(report["families"]["mailbox"]["key_bytes"]["count"], 1)

    def test_unknown_namespaces_keep_bounded_prefix_counts(self):
        account = b"\x03" + b"a" * 20
        rows = [(b"", b""), (b"\x00", b""), (account + b"\x00", b""),
                (account + b"\xf0", b""), (b"\x09", b""), (b"\xff", b"")]
        report = inspect(rows)
        self.assertEqual(report["top_level_prefix_counts"], [["00", 1], ["03", 2], ["09", 1], ["ff", 1]])
        self.assertEqual(report["account_subprefix_counts"], [["00", 1], ["f0", 1]])
        self.assertEqual(sum(n for _, n in report["top_level_prefix_counts"]) +
                         report["families"]["empty_key"]["key_bytes"]["count"], report["records"])

    def test_distinct_typed_addresses_without_global_token_set(self):
        a, b = b"\x03" + b"a" * 20, b"\x03" + b"b" * 20
        rows = [(a + b"\x03", b""), (a + b"\x03" + bytes(10), bytes(32)),
                (a + b"\x03" + bytes(11), b"odd"),
                (a + b"\x03" + b"\x01" * 10, b""), (a + b"\x04", b""),
                (b + b"\x03" + bytes(10), b"x" * 33)]
        report = inspect(rows)
        self.assertEqual(report["distinct_typed_balance_addresses"], 2)
        self.assertFalse(report["distinct_tokens_computed"])
        self.assertEqual(report["families"]["typed_balance"]["key_bytes"]["count"], 3)

    def test_present_empty_zero_and_oversized_value_are_not_deletions(self):
        report = inspect([(b"a", b""), (b"b", bytes(32)), (b"c", bytes(33))])
        row = report["families"]["other_namespace"]
        self.assertEqual((row["present_empty_values"], row["raw_zero32_values"], row["values_over32"]), (1, 1, 1))
        self.assertEqual(report["records"], 3)
        self.assertFalse(report["scope"]["absence_or_delete_proof"])
        self.refused(bytes.fromhex("000100"))

    def test_delete_and_unknown_record_tags_refuse(self):
        for tag in (0, 2, 127, 255):
            with self.subTest(tag=tag):
                self.refused(bytes([tag, 0, 0]))

    def test_nonminimal_varints_refuse(self):
        for raw in (bytes.fromhex("01800000"), bytes.fromhex("01008000"), bytes.fromhex("0181006100")):
            with self.subTest(raw=raw.hex()):
                self.refused(raw)

    def test_uint64_overflow_and_continued_varints_refuse(self):
        for raw in (b"\x01" + b"\x80" * 9 + b"\x02", b"\x01" + b"\x80" * 10 + b"\x00"):
            self.refused(raw)

    def test_truncated_key_value_and_length_refuse(self):
        for raw in (bytes.fromhex("010561"), bytes.fromhex("010005"), bytes.fromhex("018080"), bytes.fromhex("010180")):
            with self.subTest(raw=raw.hex()):
                self.refused(raw)

    def test_every_truncated_prefix_of_a_selected_complete_stream_refuses(self):
        raw = dump([(b"a", b"x" * 129), (b"b", b"y")])
        selected = pin(raw, 2)
        for length in range(len(raw)):
            with self.subTest(prefix=length):
                self.refused(raw[:length], selected=selected)

    def test_valid_reselected_prefix_does_not_authenticate_full_snapshot(self):
        report = inspect([(b"a", b"first")])
        self.assertTrue(report["selection_matched"])
        self.assertFalse(report["scope"]["snapshot_completeness_authenticated"])
        self.assertFalse(report["scope"]["ledger_consistency_authenticated"])
        self.assertFalse(report["scope"]["representative_dataset_accepted"])

    def test_duplicate_and_unsorted_keys_refuse(self):
        for rows in ([(b"a", b""), (b"a", b"x")], [(b"b", b""), (b"a", b"")], [(b"", b""), (b"", b"")]):
            self.refused(dump(rows), records=2)

    def test_selection_count_digest_bytes_and_provenance_are_checked(self):
        raw = dump([(b"a", b"one"), (b"b", b"two")])
        for key, value in (("records", 1), ("records", 3), ("bytes", len(raw) - 1),
                           ("bytes", len(raw) + 1), ("sha256", "0" * 64), ("provenance_sha256", "bad")):
            with self.subTest(field=key, value=value):
                changed = pin(raw, 2); changed[key] = value
                self.refused(raw, selected=changed)

    def test_trailing_bytes_refuse_even_after_matching_selected_digest(self):
        raw = dump([(b"a", b"v")])
        self.refused(raw + b"x", selected=pin(raw, 1))

    def test_selection_shapes_types_and_authority_fields_refuse(self):
        raw = dump([(b"a", b"v")])
        cases = [None, [], dict(pin(raw, 1), profile_agreed=True)]
        for key, value in (("bytes", True), ("records", True), ("records", -1),
                           ("sha256", "F" * 64), ("sha256", 7), ("record_space", "derived-node-tree")):
            changed = pin(raw, 1); changed[key] = value; cases.append(changed)
        changed = pin(raw, 1); changed.pop("provenance_sha256"); cases.append(changed)
        class Equal:
            def __eq__(self, other): return True
        cases.append(dict(pin(raw, 1), record_space=Equal()))
        for selected in cases:
            with self.subTest(selected=selected):
                with self.assertRaises(INV.Refused):
                    INV.inventory(io.BytesIO(raw), selected)

    def test_limits_must_be_complete_positive_integers_within_hard_caps(self):
        raw = dump([(b"a", b"v")])
        cases = [{}, [], dict(INV.DEFAULT_LIMITS, unknown=1)]
        for key in INV.DEFAULT_LIMITS:
            for value in (True, 0, -1, INV.HARD_LIMITS[key] + 1):
                cases.append(dict(INV.DEFAULT_LIMITS, **{key: value}))
        for caps in cases:
            with self.subTest(caps=caps):
                self.refused(raw, caps=caps)

    def test_provisional_key_and_value_caps_do_not_truncate(self):
        raw = dump([(b"ab", b"xyz")])
        report = INV.inventory(io.BytesIO(raw), pin(raw, 1), dict(INV.DEFAULT_LIMITS, key_bytes=2, value_bytes=3))
        self.assertEqual(report["records"], 1)
        for key, size in (("key_bytes", 1), ("value_bytes", 2)):
            self.refused(raw, caps=dict(INV.DEFAULT_LIMITS, **{key: size}))

    def test_input_byte_and_record_caps_precede_scanning(self):
        raw = dump([(b"a", b"v"), (b"b", b"v")])
        self.refused(raw, records=2, caps=dict(INV.DEFAULT_LIMITS, bytes=len(raw) - 1))
        self.refused(raw, records=2, caps=dict(INV.DEFAULT_LIMITS, records=1))

    def test_fragmented_reads_preserve_exact_result(self):
        raw = dump([(b"a" * 130, b"v" * 129), (b"b", b"")])
        self.assertEqual(INV.inventory(ShortReads(raw), pin(raw, 2)), INV.inventory(io.BytesIO(raw), pin(raw, 2)))

    def test_small_records_amortize_underlying_reads_and_hash_updates(self):
        count = 8192
        raw = dump([(b"\x09" + index.to_bytes(4, "big"), bytes(32))
                    for index in range(count)])
        selected, stream = pin(raw, count), CountedReads(raw)
        real_sha256 = hashlib.sha256
        hashes = []

        class CountedHash:
            def __init__(self):
                self.inner = real_sha256()
                self.updates = self.bytes = 0
                hashes.append(self)

            def update(self, part):
                self.updates += 1
                self.bytes += len(part)
                self.inner.update(part)

            def hexdigest(self):
                return self.inner.hexdigest()

        started = time.perf_counter()
        with mock.patch.object(INV.hashlib, "sha256", CountedHash):
            report = INV.inventory(stream, selected)
        elapsed = time.perf_counter() - started
        fills = (len(raw) + INV.CHUNK_BYTES - 1) // INV.CHUNK_BYTES
        self.assertEqual(len(stream.requests), fills + 1)
        self.assertEqual(stream.requests[-1], 1)
        self.assertEqual(stream.tell(), len(raw))
        self.assertEqual(len(hashes), 1)
        self.assertEqual((hashes[0].updates, hashes[0].bytes), (fills, len(raw)))
        self.assertEqual(report["selection"], selected)
        self.assertEqual(report["families"]["other_namespace"]["raw_zero32_values"], count)
        MEASUREMENTS["buffered_records"] = {
            "logical_records": count, "logical_put_wire_bytes": len(raw),
            "read_calls_including_eof": len(stream.requests), "hash_update_calls": fills,
            "max_read_request_bytes": max(stream.requests), "wall_seconds": elapsed,
            "scope": "inventory call on a finite in-memory stream; not syscall or RSS accounting",
            "fixture_files_created": 0, "representative_workload": False}

    def test_prefetch_stops_at_selection_before_one_byte_eof_probe(self):
        raw = dump([(b"a", b"v")])
        stream = CountedReads(raw + b"private-trailing-marker")
        with self.assertRaises(INV.Refused) as raised:
            INV.inventory(stream, pin(raw, 1))
        self.assertEqual(str(raised.exception), "trailing_input")
        self.assertEqual(stream.requests, [len(raw), 1])
        self.assertEqual(stream.tell(), len(raw) + 1)

    def test_one_byte_reads_preserve_exact_result(self):
        class OneByte(io.BytesIO):
            def read(self, size):
                if not 0 < size <= INV.CHUNK_BYTES:
                    raise AssertionError("unbounded read requested")
                return super().read(1)
        raw = dump([(b"a" * 128, bytes(32)), (b"b", b"v" * 129)])
        self.assertEqual(INV.inventory(OneByte(raw), pin(raw, 2)),
                         INV.inventory(io.BytesIO(raw), pin(raw, 2)))

    def test_varint_crosses_a_full_buffer_boundary(self):
        raw = b"x" * (INV.CHUNK_BYTES - 1) + varint(129)
        stream = CountedReads(raw)
        reader = INV.Reader(stream, len(raw))
        self.assertEqual(reader.take(INV.CHUNK_BYTES - 1), raw[:-2])
        self.assertEqual(reader.length(), 129)
        self.assertEqual(reader.position, len(raw))
        self.assertEqual(reader.hash.hexdigest(), hashlib.sha256(raw).hexdigest())
        self.assertEqual(stream.requests, [INV.CHUNK_BYTES, 1])

    def test_zero32_and_skipped_values_cross_full_buffer_boundaries(self):
        prefix = b"x" * (INV.CHUNK_BYTES - 16)
        value = b"v" * (3 * INV.CHUNK_BYTES + 17)
        raw = prefix + bytes(32) + value
        stream = CountedReads(raw)
        reader = INV.Reader(stream, len(raw))
        self.assertEqual(reader.take(len(prefix)), prefix)
        self.assertTrue(reader.value(32))
        self.assertFalse(reader.value(len(value)))
        self.assertFalse(reader.value(0))
        self.assertEqual(reader.position, len(raw))
        self.assertEqual(reader.hash.hexdigest(), hashlib.sha256(raw).hexdigest())
        self.assertEqual(len(stream.requests), 5)
        self.assertFalse(reader.raw_read(1))

    def test_read_errors_at_refill_and_eof_are_not_success(self):
        raw = dump([(b"a", b"v" * INV.CHUNK_BYTES)])
        for cutoff in (INV.CHUNK_BYTES, len(raw)):
            class BrokenAfter(io.BytesIO):
                def read(self, size):
                    if self.tell() >= cutoff:
                        raise OSError("private read failure")
                    return super().read(min(size, cutoff - self.tell()))
            with self.subTest(cutoff=cutoff):
                with self.assertRaises(INV.Refused) as raised:
                    INV.inventory(BrokenAfter(raw), pin(raw, 1))
                self.assertEqual(str(raised.exception), "input_read")

    def test_invalid_selection_and_limits_do_not_prefetch(self):
        class Unread:
            def read(self, _):
                raise AssertionError("input must not be read")
        raw = dump([(b"a", b"v")])
        for selected, caps in ((dict(pin(raw, 1), sha256="bad"), None),
                               (pin(raw, 1), dict(INV.DEFAULT_LIMITS, bytes=0)),
                               (dict(pin(raw, 1), records=2), None)):
            with self.assertRaises(INV.Refused):
                INV.inventory(Unread(), selected, caps)

    def test_negative_value_skip_refuses_without_reading(self):
        stream = CountedReads(b"x")
        reader = INV.Reader(stream, 1)
        with self.assertRaises(INV.Refused):
            reader.value(-1)
        self.assertEqual(stream.requests, [])
        self.assertEqual(reader.position, 0)

    def test_key_crossing_chunk_boundary_uses_bounded_reads(self):
        raw = dump([(b"k" * 65537, b"")])
        report = INV.inventory(ShortReads(raw), pin(raw, 1), dict(INV.DEFAULT_LIMITS, key_bytes=128 << 10))
        self.assertEqual(report["input_bytes"], 65542)
        self.assertEqual(report["families"]["other_namespace"]["key_bytes"]["max"], 65537)

    def test_bad_stream_contract_and_io_errors_refuse(self):
        class Bad:
            def __init__(self, value): self.value = value
            def read(self, size): return self.value
        raw = bytes.fromhex("010000")
        for value in (None, "text", bytearray(b"x"), b"xx"):
            with self.subTest(kind=type(value).__name__):
                with self.assertRaises(INV.Refused): INV.inventory(Bad(value), pin(raw, 1))
        class Broken:
            def read(self, size): raise OSError("private path and operational details")
        with self.assertRaises(INV.Refused) as raised: INV.inventory(Broken(), pin(raw, 1))
        self.assertEqual(str(raised.exception), "input_read")

    def test_selection_and_limits_are_snapshotted_before_reading(self):
        raw = dump([(b"a", b"v")]); selected = pin(raw, 1); caps = dict(INV.DEFAULT_LIMITS)
        original = copy.deepcopy(selected)
        class Mutating(io.BytesIO):
            def read(self, size):
                selected["sha256"] = "0" * 64; selected["bytes"] = 0; caps["value_bytes"] = 0
                return super().read(size)
        report = INV.inventory(Mutating(raw), selected, caps)
        self.assertEqual(report["selection"], original)
        self.assertEqual(report["limits"], INV.DEFAULT_LIMITS)

    def test_large_logical_value_uses_bounded_reads_and_small_python_heap(self):
        size = 32 << 20
        stream = VirtualValue(size)
        digest = hashlib.sha256(stream.prefix)
        for _ in range(size // INV.CHUNK_BYTES): digest.update(b"\x7f" * INV.CHUNK_BYTES)
        selected = {"bytes": len(stream.prefix) + size, "records": 1,
                    "sha256": digest.hexdigest(), "provenance_sha256": PROVENANCE,
                    "record_space": "effective-raw-ledger"}
        tracemalloc.start()
        started = time.perf_counter()
        try:
            report = INV.inventory(stream, selected, dict(INV.DEFAULT_LIMITS, value_bytes=64 << 20))
            _, peak = tracemalloc.get_traced_memory()
            elapsed = time.perf_counter() - started
        finally:
            tracemalloc.stop()
        self.assertLess(peak, 2 << 20)
        self.assertLessEqual(stream.max_request, 64 << 10)
        self.assertEqual(report["families"]["account_prefix_short"]["raw_value_bytes"]["total"], size)
        self.assertEqual(stream.offset, len(stream.prefix) + size)
        MEASUREMENTS["generated_value"] = {"logical_value_bytes": size,
            "traced_python_peak_bytes": peak, "max_read_request_bytes": stream.max_request,
            "wall_seconds": elapsed, "scope": "inventory call, excludes fixture digest construction",
            "fixture_files_created": 0, "representative_workload": False}

    def test_many_records_do_not_accumulate_a_key_map(self):
        count = 65536
        def record(index): return b"\x01\x04" + index.to_bytes(4, "big") + b"\x01v"
        digest = hashlib.sha256()
        for index in range(count): digest.update(record(index))
        class Rows:
            def __init__(self): self.index, self.pending = 0, b""
            def read(self, size):
                if not 0 < size <= INV.CHUNK_BYTES: raise AssertionError("unbounded read")
                if not self.pending and self.index < count:
                    self.pending = record(self.index); self.index += 1
                out, self.pending = self.pending[:size], self.pending[size:]
                return out
        selected = {"bytes": count * 8, "records": count, "sha256": digest.hexdigest(),
                    "provenance_sha256": PROVENANCE, "record_space": "effective-raw-ledger"}
        tracemalloc.start()
        started = time.perf_counter()
        try:
            report = INV.inventory(Rows(), selected)
            _, peak = tracemalloc.get_traced_memory()
            elapsed = time.perf_counter() - started
        finally:
            tracemalloc.stop()
        self.assertLess(peak, 2 << 20)
        self.assertEqual(report["records"], count)
        self.assertEqual(report["families"]["other_namespace"]["put_wire_bytes"]["total"], count * 8)
        MEASUREMENTS["generated_records"] = {"logical_records": count,
            "logical_put_wire_bytes": count * 8, "traced_python_peak_bytes": peak,
            "wall_seconds": elapsed, "scope": "inventory call, excludes fixture digest construction",
            "fixture_files_created": 0, "representative_workload": False}

    def test_reports_do_not_include_raw_keys_values_or_addresses(self):
        key = b"\x03" + b"z" * 20 + b"\x03" + b"t" * 10
        report = inspect([(key, b"private-value-marker")])
        encoded = INV.encoded(report)
        self.assertNotIn(key.hex().encode(), encoded)
        self.assertNotIn(b"private-value-marker", encoded)
        self.assertNotIn(b"zzzzzzzzzzzzzzzzzzzz", encoded)
        self.assertLess(len(encoded), INV.REPORT_BYTES)

    def test_serialized_output_has_an_explicit_cap(self):
        with self.assertRaises(INV.Refused): INV.encoded({"oversized": "x" * INV.REPORT_BYTES})

    def test_cli_success_is_one_bounded_json_document(self):
        result = self.cli(bytes.fromhex("010000"), 1)
        self.assertEqual((result.returncode, result.stderr), (0, b""))
        report = json.loads(result.stdout)
        self.assertEqual(report["status"], "SELECTED_STREAM_INVENTORIED")
        self.assertFalse(report["scope"]["state_value_acceptance_enabled"])
        self.assertEqual(len(result.stdout.splitlines()), 1)

    def test_cli_failure_is_unknown_without_partial_success_or_private_text(self):
        result = self.cli(bytes.fromhex("000000"), 1)
        self.assertEqual(result.returncode, 1)
        report = json.loads(result.stdout)
        self.assertEqual(report["status"], "UNKNOWN")
        self.assertFalse(report["selection_matched"])
        self.assertNotIn("families", report)
        self.assertEqual(result.stderr, b"")

    def test_cli_invalid_options_do_not_echo_supplied_private_strings(self):
        for extra in (("--private-option", "/private/operational-marker"), ("--max-bytes", "+4"),
                      ("--max-value-bytes", "0"), ("--max-records", "9" * 50)):
            result = self.cli(bytes.fromhex("010000"), 1, extra)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(json.loads(result.stdout)["status"], "UNKNOWN")
            self.assertNotIn(b"operational-marker", result.stdout + result.stderr)

    def test_cli_help_does_not_open_a_stream(self):
        result = subprocess.run([sys.executable, "-I", "-B", str(HERE / "inventory.py"), "--help"], capture_output=True, timeout=20)
        self.assertEqual(result.returncode, 0)
        self.assertIn(b"effective raw-ledger", result.stdout)


class RecordedResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.attempted_names, self.passed_names = [], []

    def startTest(self, test):
        self.attempted_names.append(type(test).__name__ + "." + test._testMethodName)
        super().startTest(test)

    def addSuccess(self, test):
        self.passed_names.append(type(test).__name__ + "." + test._testMethodName)
        super().addSuccess(test)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-revision")
    args = parser.parse_args()
    if args.source_revision is not None and not (len(args.source_revision) == 40 and all(c in "0123456789abcdef" for c in args.source_revision)):
        parser.error("invalid source revision")
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(LedgerInventoryTests)
    result = unittest.TextTestRunner(verbosity=1, resultclass=RecordedResult).run(suite)
    success = (result.wasSuccessful() and not result.skipped and not result.expectedFailures
               and result.attempted_names == result.passed_names
               and set(MEASUREMENTS) == {"generated_value", "generated_records", "buffered_records"})
    print(json.dumps({"kind": "bounded-ledger-inventory-controls", "status": "PASS" if success else "FAIL",
                      "tests": result.testsRun, "passed_names": result.passed_names,
                      "attempted_names": result.attempted_names, "skipped": len(result.skipped),
                      "source_revision": args.source_revision,
                      "source_pins": {name: hashlib.sha256((HERE / name).read_bytes()).hexdigest()
                                      for name in ("inventory.py", "inventory_test.py")},
                      "large_value_is_generated_in_memory": True, "large_fixture_files_created": False,
                      "measurements": MEASUREMENTS,
                      "representative_dataset_collected": False, "state_value_acceptance_enabled": False}, sort_keys=True))
    sys.exit(0 if success else 1)
