#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Finite completion-to-inventory controls with no dataset or fixture files."""
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import unittest


sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PROGRAM = load("selected_completed_export", "inventory_completed_export.py")
FIXTURE = load("literal_completion_fixture", "consume_completion_test.py")


class NoRead:
    def read(self, _):
        raise AssertionError("unmatched completion must not consume stream bytes")


class CountedReads(io.BytesIO):
    def __init__(self, raw):
        super().__init__(raw)
        self.requests = []

    def read(self, size):
        if not 0 < size <= 64 << 10:
            raise AssertionError("bounded stream read required")
        self.requests.append(size)
        return super().read(size)


class CompletedExport(unittest.TestCase):
    def invoke(self, receipt=None, args=None, stream=None, raw=None):
        report, selected, wire = FIXTURE.fixture()
        if receipt is None:
            receipt = report
        if args is None:
            args = selected
        if raw is None:
            raw = json.dumps(receipt)
        output, diagnostics = io.StringIO(), io.StringIO()
        code = PROGRAM.run(args + [PROGRAM.RECEIPT_OPTION, raw],
                           io.BytesIO(wire) if stream is None else stream, output, diagnostics)
        result = json.loads(output.getvalue())
        self.assertEqual(result["format"], PROGRAM.FORMAT)
        self.assertTrue(all(value is False for value in result["scope"].values()))
        self.assertNotIn("PRIVATE_TEST_MARKER", output.getvalue() + diagnostics.getvalue())
        if code:
            self.assertEqual(result["status"], "UNKNOWN")
            self.assertFalse(result["stream_recount_completed"])
            self.assertIsNone(result["stream_inventory"])
        return code, result

    def test_literal_stream_matches_independently_selected_inventory_fields(self):
        receipt, _, wire = FIXTURE.fixture()
        code, result = self.invoke()
        self.assertEqual((code, result["status"]), (0, "SELECTED_EXPORT_INVENTORIED"))
        self.assertTrue(result["producer_completion_matched"])
        self.assertTrue(result["stream_recount_completed"])
        completion = result["producer_completion"]
        inventory = result["stream_inventory"]
        self.assertEqual(inventory["format"], "zenon-effective-ledger-inventory/v1")
        self.assertEqual((inventory["records"], inventory["input_bytes"]), (3, 83))
        self.assertEqual(inventory["selection"], {
            "record_space": "effective-raw-ledger", "records": 3, "bytes": 83,
            "sha256": hashlib.sha256(wire).hexdigest(), "provenance_sha256": "22" * 32})
        self.assertTrue(inventory["selection_matched"])
        self.assertTrue(inventory["end_of_stream_observed"])
        other = inventory["families"]["other_namespace"]
        self.assertEqual((other["key_bytes"]["count"], other["present_empty_values"],
                          other["raw_zero32_values"]), (3, 1, 1))
        self.assertEqual((other["key_bytes"]["total"], other["raw_value_bytes"]["total"],
                          other["put_wire_bytes"]["total"]), (3, 71, 83))
        self.assertEqual(inventory["top_level_prefix_counts"], [["00", 1], ["61", 1], ["62", 1]])
        self.assertEqual(completion["selected_frontier"], receipt["selection"])
        self.assertEqual(completion["producer_receipt_sha256"],
                         hashlib.sha256(json.dumps(receipt).encode()).hexdigest())

    def test_all_explicit_caps_are_carried_into_inventory(self):
        receipt, args, _ = FIXTURE.fixture()
        caps = {"--max-bytes": 128, "--max-records": 3, "--max-scan-bytes": 128,
                "--max-scan-records": 4, "--max-key-bytes": 1, "--max-value-bytes": 64}
        for flag, value in caps.items():
            receipt["limits"][PROGRAM.COMPLETION.LIMITS[flag][0]] = value
            args += [flag, str(value)]
        code, result = self.invoke(receipt=receipt, args=args)
        self.assertEqual(code, 0)
        self.assertEqual(result["stream_inventory"]["limits"],
                         {"bytes": 128, "records": 3, "key_bytes": 1, "value_bytes": 64})

    def test_failed_producer_exit_never_reads_stream(self):
        _, args, _ = FIXTURE.fixture()
        for value in ("1", "130", "-9"):
            with self.subTest(exit=value):
                code, result = self.invoke(args=FIXTURE.changed(args, "--producer-exit", value), stream=NoRead())
                self.assertEqual((code, result["reason"]), (2, "completion_process_failure"))

    def test_incomplete_capture_never_reads_stream(self):
        _, args, _ = FIXTURE.fixture()
        for value in ("incomplete", "unknown"):
            with self.subTest(status=value):
                self.assertEqual(self.invoke(args=FIXTURE.changed(args, "--capture-status", value),
                                             stream=NoRead())[1]["reason"], "completion_capture_incomplete")

    def test_selected_frontier_provenance_and_capture_must_match_first(self):
        _, args, _ = FIXTURE.fixture()
        for flag, value in (("--expect-height", "3001"), ("--expect-hash", "33" * 32),
                            ("--provenance-sha256", "44" * 32), ("--capture-bytes", "82"),
                            ("--capture-sha256", "55" * 32)):
            with self.subTest(flag=flag):
                self.assertNotEqual(self.invoke(args=FIXTURE.changed(args, flag, value), stream=NoRead())[0], 0)

    def test_producer_limits_cannot_select_their_own_caps(self):
        receipt, _, _ = FIXTURE.fixture()
        receipt["limits"]["output_bytes"] = 128
        self.assertEqual(self.invoke(receipt=receipt, stream=NoRead())[1]["reason"],
                         "completion_limits_mismatch")

    def test_bad_receipt_json_never_reads_stream(self):
        receipt, _, _ = FIXTURE.fixture()
        valid = json.dumps(receipt)
        for raw in ("", "{", "null", "[]", valid[:-1], valid[:-1] + ',"format":"duplicate"}',
                    '{"secret":"PRIVATE_TEST_MARKER"}'):
            with self.subTest(case=len(raw)):
                self.assertNotEqual(self.invoke(raw=raw, stream=NoRead())[0], 0)

    def test_authority_claims_and_incomplete_receipts_never_read_stream(self):
        original, _, _ = FIXTURE.fixture()
        for key in original["scope"]:
            receipt = copy.deepcopy(original)
            receipt["scope"][key] = True
            with self.subTest(scope=key):
                self.assertNotEqual(self.invoke(receipt=receipt, stream=NoRead())[0], 0)
        for key in ("put_stream_complete", "iterator_eof_observed"):
            receipt = copy.deepcopy(original)
            receipt[key] = False
            self.assertNotEqual(self.invoke(receipt=receipt, stream=NoRead())[0], 0)

    def test_bad_options_missing_duplicate_and_oversize_receipt_never_read(self):
        _, args, _ = FIXTURE.fixture()
        cases = [[], args, args + [PROGRAM.RECEIPT_OPTION],
                 args + [PROGRAM.RECEIPT_OPTION, "{}", PROGRAM.RECEIPT_OPTION, "{}"],
                 args + [PROGRAM.RECEIPT_OPTION, "x" * ((16 << 10) + 1)],
                 args + [PROGRAM.RECEIPT_OPTION, "é" * (16 << 10)],
                 args + [PROGRAM.RECEIPT_OPTION, "\ud800"],
                 [False], ["x"] * 35, ["x" * ((32 << 10) + 1)]]
        for ordinal, selected in enumerate(cases):
            with self.subTest(case=ordinal):
                output = io.StringIO()
                self.assertEqual(PROGRAM.run(selected, NoRead(), output, io.StringIO()), 64)
                self.assertEqual(json.loads(output.getvalue())["status"], "UNKNOWN")

    def test_inline_options_and_receipt_are_supported(self):
        receipt, args, wire = FIXTURE.fixture()
        selected = [args[i] + "=" + args[i + 1] for i in range(0, len(args), 2)]
        selected += [PROGRAM.RECEIPT_OPTION + "=" + json.dumps(receipt)]
        output = io.StringIO()
        self.assertEqual(PROGRAM.run(selected, io.BytesIO(wire), output, io.StringIO()), 0)
        self.assertEqual(json.loads(output.getvalue())["stream_inventory"]["records"], 3)

    def test_empty_short_changed_and_trailing_streams_are_unknown(self):
        _, _, wire = FIXTURE.fixture()
        for raw in (b"", wire[:-1], wire[:-1] + b"\x01", wire + b"PRIVATE_TEST_MARKER"):
            with self.subTest(bytes=len(raw)):
                code, result = self.invoke(stream=io.BytesIO(raw))
                self.assertEqual((code, result["reason"]), (2, "stream_inventory_refused"))
                self.assertTrue(result["producer_completion_matched"])

    def test_actual_recount_rejects_incorrect_producer_record_count(self):
        receipt, _, _ = FIXTURE.fixture()
        receipt["statistics"].update(records=2, scanned_records=3)
        self.assertEqual(self.invoke(receipt=receipt)[1]["reason"], "stream_inventory_refused")

    def test_matching_capture_hash_does_not_accept_duplicate_wire_keys(self):
        receipt, args, wire = FIXTURE.fixture()
        altered = wire[:-34] + b"a" + wire[-33:]
        digest = hashlib.sha256(altered).hexdigest()
        receipt["statistics"]["put_stream_sha256"] = digest
        code, result = self.invoke(receipt=receipt,
                                   args=FIXTURE.changed(args, "--capture-sha256", digest),
                                   stream=io.BytesIO(altered))
        self.assertEqual((code, result["reason"]), (2, "stream_inventory_refused"))
        self.assertTrue(result["producer_completion_matched"])

    def test_one_stream_uses_bounded_prefetch_and_actual_eof(self):
        _, _, wire = FIXTURE.fixture()
        stream = CountedReads(wire)
        self.assertEqual(self.invoke(stream=stream)[0], 0)
        self.assertEqual(stream.requests, [len(wire), 1])
        self.assertEqual(stream.tell(), len(wire))

    def test_fragmented_reads_preserve_exact_inventory(self):
        class Fragmented(io.BytesIO):
            def read(self, size):
                return super().read(min(1, size))
        _, _, wire = FIXTURE.fixture()
        self.assertEqual(self.invoke(stream=Fragmented(wire)), self.invoke())

    def test_eof_read_error_and_cancellation_preserve_unknown(self):
        _, _, wire = FIXTURE.fixture()
        for error, expected in ((OSError("PRIVATE_TEST_MARKER"), 2), (KeyboardInterrupt(), 130)):
            class Broken(io.BytesIO):
                def read(self, size):
                    if self.tell() == len(wire):
                        raise error
                    return super().read(size)
            with self.subTest(code=expected):
                self.assertEqual(self.invoke(stream=Broken(wire))[0], expected)

    def test_help_does_not_inventory_input(self):
        for flag in ("--help", "-h"):
            output = io.StringIO()
            self.assertEqual(PROGRAM.run([flag], NoRead(), output, io.StringIO()), 0)
            result = json.loads(output.getvalue())
            self.assertEqual((result["status"], result["reason"]), ("UNKNOWN", "help_only"))
            self.assertFalse(result["stream_recount_completed"])

    def test_short_and_failed_output_are_nonzero_even_after_valid_inventory(self):
        receipt, args, wire = FIXTURE.fixture()
        class Short(io.StringIO):
            def write(self, text):
                return super().write(text) - 1
        class FailedFlush(io.StringIO):
            def flush(self):
                raise OSError("PRIVATE_TEST_MARKER")
        for output in (Short(), FailedFlush()):
            self.assertEqual(PROGRAM.run(args + [PROGRAM.RECEIPT_OPTION, json.dumps(receipt)],
                                         io.BytesIO(wire), output, io.StringIO()), 70)

    def test_fresh_cli_success_failure_and_help_use_no_fixture_files(self):
        receipt, args, wire = FIXTURE.fixture()
        cases = [(args + [PROGRAM.RECEIPT_OPTION, json.dumps(receipt)], wire, 0,
                  "SELECTED_EXPORT_INVENTORIED"),
                 (args + [PROGRAM.RECEIPT_OPTION, json.dumps(receipt)], wire[:-1], 2, "UNKNOWN"),
                 (["--help"], b"", 0, "UNKNOWN"), ([], b"", 64, "UNKNOWN")]
        for selected, data, code, status in cases:
            with self.subTest(code=code, status=status):
                completed = subprocess.run([sys.executable, "-I", "-B",
                                            str(HERE / "inventory_completed_export.py"), *selected],
                                           input=data, capture_output=True, timeout=10)
                self.assertEqual(completed.returncode, code, completed.stderr)
                self.assertEqual(json.loads(completed.stdout)["status"], status)


if __name__ == "__main__":
    unittest.main()
