#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite completion controls; no database, network, path opening or large files."""
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import unittest


spec = importlib.util.spec_from_file_location("completion", Path(__file__).with_name("consume_completion.py"))
completion = importlib.util.module_from_spec(spec)
spec.loader.exec_module(completion)


def fixture(height=3000):
    # Select literal wire records independently of the producer implementation.
    number, height_bytes = height, bytearray()
    while number >= 128:
        height_bytes.append((number & 127) | 128)
        number >>= 7
    height_bytes.append(number)
    metadata = bytes.fromhex("0a220a20" + "11" * 32)
    if height:
        metadata += b"\x10" + bytes(height_bytes)
    wire = b"\x01\x01\x00" + bytes([len(metadata)]) + metadata
    wire += bytes.fromhex("0101610001016220" + "00" * 32)
    digest = hashlib.sha256(wire).hexdigest()
    caps = {"output_bytes": 268435456, "records": 2000000,
            "scan_key_and_encoded_value_bytes": 268435456, "scan_records": 2000000,
            "key_bytes": 1024, "value_bytes": 1048576}
    scope = {"input_role_required": "declared-immutable-copy",
             "input_immutability_authenticated": False, "ledger_origin_authenticated": False,
             "snapshot_completeness_authenticated": False, "representative_dataset_accepted": False,
             "profile_agreed": False, "network_activation_authenticated": False,
             "header_authentication_executed": False, "canonical_chain_qualified": False,
             "absence_or_delete_proof": False, "state_value_acceptance_enabled": False}
    report = {"format": "zenon-frontier-export/v1", "status": "SELECTED_FRONTIER_EXPORTED",
              "put_stream_complete": True, "iterator_eof_observed": True,
              "source_layout_node_revision": "9c71ae82fc983e16f914ae085d4034030c8ebe3b",
              "layout": "zenon-9c71-frontier-v1", "scope": scope,
              "selection": {"height": height, "hash": "11" * 32, "provenance_sha256": "22" * 32},
              "limits": caps, "statistics": {"records": 3, "put_wire_bytes": len(wire),
                    "scanned_records": 4, "scanned_key_and_encoded_value_bytes": len(wire) - 1,
                    "physical_tombstones_omitted": 1, "present_empty_values": 1,
                    "put_stream_sha256": digest}}
    args = ["--layout", "zenon-9c71-frontier-v1", "--expect-height", str(height),
            "--expect-hash", "11" * 32, "--provenance-sha256", "22" * 32,
            "--producer-exit", "0", "--capture-status", "complete",
            "--capture-bytes", str(len(wire)), "--capture-sha256", digest]
    return report, args, wire


def changed(args, option, value):
    result = list(args)
    result[result.index(option) + 1] = value
    return result


class NoRead:
    def read(self, _):
        raise AssertionError("unfinished or refused input must not be read")


class Completion(unittest.TestCase):
    def invoke(self, report=None, args=None, reader=None, raw=None):
        selected, defaults, _ = fixture()
        if report is None:
            report = selected
        if args is None:
            args = defaults
        if reader is None:
            reader = io.BytesIO(json.dumps(report).encode() if raw is None else raw)
        output, diagnostics = io.StringIO(), io.StringIO()
        code = completion.run(args, reader, output, diagnostics)
        result = json.loads(output.getvalue())
        self.assertEqual(result["format"], "zenon-frontier-export-completion/v1")
        self.assertTrue(all(value is False for value in result["scope"].values() if type(value) is bool))
        if code != 0:
            self.assertEqual(result["status"], "UNKNOWN")
            self.assertFalse(result["capture_matched"])
            self.assertIsNone(result["inventory_selection"])
        return code, result

    def test_literal_success_selects_same_retained_stream(self):
        report, args, wire = fixture()
        raw = json.dumps(report).encode()
        code, result = self.invoke(raw=raw)
        self.assertEqual(code, 0)
        self.assertEqual(result["status"], "SELECTED_EXPORT_COMPLETION_MATCHED")
        self.assertEqual(result["producer_receipt_sha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(result["inventory_selection"], {
            "record_space": "effective-raw-ledger", "records": 3, "bytes": 83,
            "sha256": hashlib.sha256(wire).hexdigest(), "provenance_sha256": "22" * 32})
        self.assertEqual(result["selected_frontier"], report["selection"])
        self.assertEqual(result["inventory_limits"], {
            "bytes": 268435456, "records": 2000000, "key_bytes": 1024, "value_bytes": 1048576})
        self.assertFalse(result["scope"]["independent_stream_inventory_executed"])

    def test_real_exit_precedes_success_looking_receipt(self):
        _, args, _ = fixture()
        for exit_code in ("1", "130", "-9", str(-(1 << 31)), str((1 << 31) - 1)):
            with self.subTest(exit=exit_code):
                code, result = self.invoke(args=changed(args, "--producer-exit", exit_code), reader=NoRead())
                self.assertEqual((code, result["reason"]), (2, "process_failure"))

    def test_partial_and_unknown_capture_are_not_read(self):
        _, args, _ = fixture()
        for status in ("incomplete", "unknown"):
            with self.subTest(status=status):
                code, result = self.invoke(args=changed(args, "--capture-status", status), reader=NoRead())
                self.assertEqual((code, result["reason"]), (2, "capture_incomplete"))

    def test_over_budget_capture_is_not_read(self):
        _, args, _ = fixture()
        code, result = self.invoke(args=changed(args, "--capture-bytes", str((256 << 20) + 1)), reader=NoRead())
        self.assertEqual((code, result["reason"]), (2, "capture_limit"))

    def test_full_identifier_and_provenance_are_caller_selected(self):
        _, args, _ = fixture()
        for key, value in (("--expect-height", "3001"), ("--expect-hash", "33" * 32),
                           ("--provenance-sha256", "44" * 32)):
            with self.subTest(key=key):
                self.assertEqual(self.invoke(args=changed(args, key, value))[1]["reason"], "selection_mismatch")

    def test_capture_count_and_digest_are_not_selected_from_receipt(self):
        _, args, _ = fixture()
        for key, value in (("--capture-bytes", "82"), ("--capture-sha256", "33" * 32)):
            with self.subTest(key=key):
                self.assertEqual(self.invoke(args=changed(args, key, value))[1]["reason"], "capture_mismatch")

    def test_all_selected_limits_must_match(self):
        _, args, _ = fixture()
        for key in completion.LIMITS:
            with self.subTest(key=key):
                self.assertEqual(self.invoke(args=args + [key, "100"])[1]["reason"], "limits_mismatch")

    def test_uint64_height_and_protobuf_width_boundaries(self):
        for height in (0, 127, 128, 3000, (1 << 64) - 1):
            with self.subTest(height=height):
                report, args, _ = fixture(height)
                self.assertEqual(self.invoke(report, args)[0], 0)

    def test_canonical_options_and_privacy(self):
        _, args, _ = fixture()
        bad = [args + ["--unknown", "PRIVATE_TEST_PATH"], args + ["--layout", "PRIVATE_TEST_PATH"],
               args[:-1], args + ["unexpected"], args + ["--max-records", "0"],
               args + ["--max-key-bytes", str((1 << 20) + 1)], ["x" * 8193], ["x"] * 33]
        for key, values in (("--expect-height", ("-1", "+1", "01", " 1", "1 ", "١", str(1 << 64))),
                            ("--producer-exit", ("-0", "+0", "01", str(1 << 31), str(-(1 << 31) - 1))),
                            ("--capture-sha256", ("A" * 64, "a" * 63, "PRIVATE_TEST_PATH")),
                            ("--capture-status", ("COMPLETE", "PRIVATE_TEST_PATH"))):
            bad.extend(changed(args, key, value) for value in values)
        for ordinal, selected in enumerate(bad):
            with self.subTest(case=ordinal):
                code, result = self.invoke(args=selected, reader=NoRead())
                self.assertEqual((code, result["reason"]), (64, "options"))
                self.assertNotIn("PRIVATE_TEST_PATH", json.dumps(result))

    def test_inline_options_are_supported(self):
        _, args, _ = fixture()
        self.assertEqual(self.invoke(args=[args[i] + "=" + args[i + 1] for i in range(0, len(args), 2)])[0], 0)

    def test_help_is_not_a_completed_export(self):
        for option in ("--help", "-h"):
            with self.subTest(option=option):
                code, result = self.invoke(args=[option], reader=NoRead())
                self.assertEqual((code, result["status"], result["reason"]), (0, "UNKNOWN", "help_only"))
                self.assertIsNone(result["inventory_selection"])
                self.assertFalse(result["capture_matched"])

    def test_incomplete_help_and_wrong_layout_receipts_refuse(self):
        original, _, _ = fixture()
        mutations = [lambda r: r.update(status="UNKNOWN"), lambda r: r.update(put_stream_complete=False),
                     lambda r: r.update(iterator_eof_observed=False), lambda r: r.update(layout="other"),
                     lambda r: r.update(source_layout_node_revision="f" * 40), lambda r: r.update(format="other"),
                     lambda r: r.update(reason="help_only"), lambda r: r.pop("statistics"),
                     lambda r: r.update(extra="PRIVATE_TEST_PATH")]
        for ordinal, mutate in enumerate(mutations):
            with self.subTest(case=ordinal):
                report = copy.deepcopy(original)
                mutate(report)
                self.assertNotEqual(self.invoke(report)[0], 0)

    def test_authority_claims_and_unknown_scope_fields_refuse(self):
        original, _, _ = fixture()
        for key in original["scope"]:
            for value in (True, 0, None, "PRIVATE_TEST_PATH"):
                with self.subTest(key=key, value=value):
                    report = copy.deepcopy(original)
                    report["scope"][key] = value
                    self.assertEqual(self.invoke(report)[1]["reason"], "producer_scope")
        report = copy.deepcopy(original)
        report["scope"]["unknown_guarantee"] = False
        self.assertEqual(self.invoke(report)[1]["reason"], "producer_scope")

    def test_counter_types_and_ranges_refuse(self):
        original, _, _ = fixture()
        for key in original["statistics"]:
            for value in (True, -1, None, "1", 1 << 64):
                with self.subTest(key=key, value=value):
                    report = copy.deepcopy(original)
                    report["statistics"][key] = value
                    self.assertNotEqual(self.invoke(report)[0], 0)
        for key in ("height",):
            report = copy.deepcopy(original)
            report["selection"][key] = True
            self.assertNotEqual(self.invoke(report)[0], 0)

    def test_present_empty_metadata_and_tombstone_arithmetic(self):
        original, _, _ = fixture()
        for change in ({"records": 0}, {"scanned_records": 3}, {"physical_tombstones_omitted": 0},
                       {"present_empty_values": 3}, {"scanned_key_and_encoded_value_bytes": 1},
                       {"scanned_key_and_encoded_value_bytes": 268435457}, {"scanned_records": 2000001},
                       {"scanned_key_and_encoded_value_bytes": 10000}):
            with self.subTest(change=change):
                report = copy.deepcopy(original)
                report["statistics"].update(change)
                self.assertNotEqual(self.invoke(report)[0], 0)

    def test_metadata_value_cannot_exceed_selected_value_cap(self):
        report, args, _ = fixture()
        report["limits"]["value_bytes"] = 38
        self.assertEqual(self.invoke(report, args + ["--max-value-bytes", "38"])[1]["reason"], "statistics_bytes")

    def test_unknown_nested_fields_refuse(self):
        original, _, _ = fixture()
        for field in ("selection", "limits", "statistics"):
            with self.subTest(field=field):
                report = copy.deepcopy(original)
                report[field]["unknown"] = 0
                self.assertNotEqual(self.invoke(report)[0], 0)

    def test_strict_json_numbers_duplicates_and_encoding(self):
        report, _, _ = fixture()
        raw = json.dumps(report).encode()
        bad = [b"", b"null", b"[]", b"\xff", b"\xef\xbb\xbf" + raw, raw + raw,
               raw.replace(b'"records": 3', b'"records": 3.0'),
               raw.replace(b'"records": 3', b'"records": 3e0'),
               raw.replace(b'"present_empty_values": 1', b'"present_empty_values": -0'),
               raw.replace(b'"records": 3', b'"records": NaN'),
               raw.replace(b'"records": 3', b'"records": Infinity'),
               raw.replace(b'"height": 3000', b'"height": 3000, "height": 3000'),
               raw.replace(b'"records": 3', b'"records": 3, "records": 3'),
               b"[" * 2000 + b"]" * 2000]
        for ordinal, data in enumerate(bad):
            with self.subTest(case=ordinal):
                self.assertNotEqual(self.invoke(raw=data)[0], 0)

    def test_report_byte_limit_and_short_reads(self):
        class Bounded(io.BytesIO):
            largest = 0
            def read(self, size):
                self.largest = max(self.largest, size)
                return super().read(min(size, 3))
        data = json.dumps(fixture()[0]).encode()
        reader = Bounded(data)
        self.assertEqual(self.invoke(reader=reader)[0], 0)
        self.assertLessEqual(reader.largest, 4096)
        code, result = self.invoke(reader=io.BytesIO(b" " * (completion.REPORT_BYTES + 1)))
        self.assertEqual((code, result["reason"]), (2, "receipt_size"))
        self.assertEqual(self.invoke(raw=data + b" " * (completion.REPORT_BYTES - len(data)))[0], 0)

    def test_invalid_reader_results_refuse(self):
        for bad in (None, "text", b"x" * 4097):
            class Invalid:
                def read(self, _):
                    return bad
            with self.subTest(value=type(bad).__name__):
                self.assertEqual(self.invoke(reader=Invalid())[1]["reason"], "receipt_input")

    def test_input_errors_and_interruptions_remain_unknown(self):
        for error, expected in ((OSError("PRIVATE_TEST_PATH"), 70), (KeyboardInterrupt(), 130)):
            class Broken:
                def read(self, _):
                    raise error
            with self.subTest(code=expected):
                self.assertEqual(self.invoke(reader=Broken())[0], expected)

    def test_output_failure_returns_nonzero(self):
        class Broken:
            def write(self, _):
                return 0
        _, args, _ = fixture()
        self.assertEqual(completion.run(args, io.BytesIO(json.dumps(fixture()[0]).encode()), Broken(), io.StringIO()), 70)


if __name__ == "__main__":
    unittest.main(verbosity=2)
