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
from unittest import mock


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


def manifest_for(receipt, wire, chunk_bytes=17):
    chunks = [wire[offset:offset + chunk_bytes] for offset in range(0, len(wire), chunk_bytes)]
    return {"format": "zenon-r1-transport-manifest/v1",
            "selection": {**receipt["selection"], "record_space": "effective-raw-ledger",
                          "bytes": len(wire), "sha256": hashlib.sha256(wire).hexdigest()},
            "chunk_bytes": chunk_bytes, "chunks": [{"bytes": len(chunk), "sha256": hashlib.sha256(chunk).hexdigest()}
                                         for chunk in chunks],
            "scope": PROGRAM.TRANSPORT.scope()}


def frame_options(value):
    manifest = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return manifest, [PROGRAM.MANIFEST_BYTES_OPTION, str(len(manifest)),
                      PROGRAM.MANIFEST_SHA_OPTION, hashlib.sha256(manifest).hexdigest()]


ACCOUNT = b"\x03" + b"A" * 20
PROJECTION_ROOT = "8236700379edfe10683f1cce9a35b797879d23499d94e4850fa2a25696a93f68"
PROJECTION_MAP = "b6076a59c3c13ee8de2d3229471eb8b26e247b3f54acfdbe2eaeb09b25f7fde7"
PROJECTION_ROWS = ((ACCOUNT + b"\x03", b"wide-prefix"),
                   (ACCOUNT + b"\x03" + b"Z" * 10, bytes(32)),
                   (ACCOUNT + b"\x04empty", b""), (ACCOUNT + b"\x04value", b"V" * 33),
                   (ACCOUNT + b"\x05", b"PRIVATE_TEST_MARKER"),
                   (b"\x04" + b"B" * 20, b"mailbox"))


def projection_options(root=PROJECTION_ROOT):
    return [PROGRAM.PROJECTION_PROFILE_OPTION, PROGRAM.PROJECTION.PROFILE,
            PROGRAM.PROJECTION_ROOT_OPTION, root]


def projection_fixture(rows=PROJECTION_ROWS, frontier=None, chunk_bytes=17, height=3000, hash_hex="11" * 32):
    receipt, args, literal = FIXTURE.fixture(height)
    receipt["selection"]["hash"] = hash_hex
    args = FIXTURE.changed(args, "--expect-hash", hash_hex)
    if frontier is None:
        frontier = [(b"\0", literal[4:8] + bytes.fromhex(hash_hex) + literal[40:4 + literal[3]])]
    records = sorted([*frontier, *rows])

    def length(value):
        out = []
        while value >= 128:
            value, low = divmod(value, 128)
            out.append(128 + low)
        return bytes([*out, value])

    wire = b"".join(b"\x01" + length(len(key)) + key + length(len(value)) + value
                    for key, value in records)
    pin = hashlib.sha256(wire).hexdigest()
    receipt["statistics"].update(records=len(records), put_wire_bytes=len(wire),
        scanned_records=len(records), scanned_key_and_encoded_value_bytes=sum(
            len(key) + len(value) + 2 for key, value in records), physical_tombstones_omitted=0,
        present_empty_values=sum(not value for _, value in records), put_stream_sha256=pin)
    args = FIXTURE.changed(FIXTURE.changed(args, "--capture-bytes", str(len(wire))), "--capture-sha256", pin)
    manifest, options = frame_options(manifest_for(receipt, wire, chunk_bytes))
    return receipt, args + options, manifest, wire


class CompletedExport(unittest.TestCase):
    def invoke(self, receipt=None, args=None, stream=None, raw=None, format_name=PROGRAM.FORMAT):
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
        self.assertEqual(result["format"], format_name)
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

    def test_transport_and_inventory_share_one_pass(self):
        receipt, args, wire = FIXTURE.fixture()
        manifest, options = frame_options(manifest_for(receipt, wire))
        stream = CountedReads(manifest + wire)
        code, result = self.invoke(args=args + options, stream=stream, format_name=PROGRAM.TRANSPORT_FORMAT)
        self.assertEqual((code, result.pop("format")), (0, PROGRAM.TRANSPORT_FORMAT))
        transport = result.pop("transport_verification")
        self.assertEqual(transport["status"], "SELECTED_TRANSPORT_MATCHED")
        self.assertEqual(transport["chunks_checked"], 5)
        self.assertTrue(transport["stream_eof_observed"])
        self.assertEqual(transport["manifest"], {"bytes": len(manifest), "sha256": options[-1]})
        self.assertEqual(transport["selection"]["hash"], receipt["selection"]["hash"])
        self.assertEqual(stream.requests, [len(manifest), 17, 17, 17, 17, 15, 1])
        self.assertEqual(stream.tell(), len(manifest) + len(wire))
        self.assertEqual({**result, "format": PROGRAM.FORMAT}, self.invoke()[1])

    def test_projection_joins_transport_and_exact_inventory_in_one_pass(self):
        receipt, args, manifest, wire = projection_fixture()
        stream = CountedReads(manifest + wire)
        code, result = self.invoke(receipt=receipt, args=args + projection_options(), stream=stream,
                                   format_name=PROGRAM.PROJECTION_FORMAT)
        self.assertEqual((code, result["status"]), (0, "SELECTED_CANDIDATE_PROJECTION_MATCHED"))
        self.assertEqual(result["candidate_projection"], {
            "profile": PROGRAM.PROJECTION.PROFILE, "qualification": "MATH_ONLY",
            "expected_root": PROJECTION_ROOT, "computed_root": PROJECTION_ROOT,
            "mapping_sha256": PROJECTION_MAP, "leaves": 3, "balance_prefix_leaves": 2,
            "contract_storage_leaves": 1, "empty_folded_records": 1,
            "max_leaves": PROGRAM.PROJECTION.DEFAULT_LEAVES, "value_files_written": 0,
            "raw_frontier_metadata_matched": True, "accepted_header_binding": False,
            "excluded_state_authenticated": False})
        transport_only = self.invoke(receipt=receipt, args=args, stream=io.BytesIO(manifest + wire),
                                     format_name=PROGRAM.TRANSPORT_FORMAT)[1]
        for name in ("producer_completion", "transport_verification", "stream_inventory"):
            self.assertEqual(result[name], transport_only[name])
        self.assertEqual(result["stream_inventory"]["families"]["typed_balance"]["raw_zero32_values"], 1)
        self.assertEqual(stream.tell(), len(manifest) + len(wire))
        self.assertEqual(stream.requests, [len(manifest)] + [17] * (len(wire) // 17)
                         + ([len(wire) % 17] if len(wire) % 17 else []) + [1])

    def test_projection_checks_options_before_consuming_input(self):
        receipt, args, _, _ = projection_fixture()
        for selected in (args[:-4] + projection_options(), args + projection_options()[:2],
                         args + projection_options("A" * 64), args + projection_options() + [
                             PROGRAM.PROJECTION_LIMIT_OPTION, str(PROGRAM.PROJECTION.MAX_LEAVES + 1)],
                         args + [PROGRAM.PROJECTION_PROFILE_OPTION, "other/v1",
                                 PROGRAM.PROJECTION_ROOT_OPTION, PROJECTION_ROOT]):
            with self.subTest(options=len(selected)):
                code, result = self.invoke(receipt=receipt, args=selected, stream=NoRead())
                self.assertEqual((code, result["reason"]), (64, "options"))

    def test_projection_wrong_root_or_leaf_limit_has_no_partial_result(self):
        receipt, args, manifest, wire = projection_fixture()
        for selected, reason in (
                (projection_options("00" * 32), "projection_root_mismatch"),
                (projection_options() + [PROGRAM.PROJECTION_LIMIT_OPTION, "2"], "projection_leaf_limit")):
            with self.subTest(reason=reason):
                code, result = self.invoke(receipt=receipt, args=args + selected,
                                           stream=io.BytesIO(manifest + wire))
                self.assertEqual((code, result["reason"]), (2, reason))
                self.assertNotIn("candidate_projection", result)
                self.assertNotIn("transport_verification", result)

    def test_projection_binds_raw_frontier_even_when_transport_matches(self):
        wrong = b"\x0a\x22\x0a\x20" + b"\x12" * 32 + b"\x10\xb8\x17"
        for frontier, reason in (([(b"\0", wrong)], "projection_frontier_mismatch"),
                                 ([], "projection_frontier_missing")):
            with self.subTest(reason=reason):
                receipt, args, manifest, wire = projection_fixture(frontier=frontier)
                code, result = self.invoke(receipt=receipt, args=args + projection_options(),
                                           stream=io.BytesIO(manifest + wire))
                self.assertEqual((code, result["reason"]), (2, reason))
                self.assertNotIn("candidate_projection", result)

    def test_projection_does_not_fold_tree_before_transport_eof(self):
        receipt, args, manifest, wire = projection_fixture()
        with mock.patch.object(PROGRAM.PROJECTION.Projector, "finish",
                               side_effect=AssertionError("premature projection result")):
            code, result = self.invoke(receipt=receipt, args=args + projection_options(),
                                       stream=io.BytesIO(manifest + wire + b"x"))
        self.assertEqual((code, result["reason"]), (2, "transport_trailing_input"))
        self.assertNotIn("candidate_projection", result)

    def test_projection_hashes_large_raw_value_across_chunks(self):
        rows = ((ACCOUNT + b"\x04stream", b"\x7f" * (128 * 1024 + 7)),)
        expected = "5ef03ee44645659923cfecb2e724d53e5b2d3f57422e2249c886a39f97e8cb9a"
        receipt, args, manifest, wire = projection_fixture(rows, chunk_bytes=64 << 10)
        stream = CountedReads(manifest + wire)
        code, result = self.invoke(receipt=receipt, args=args + projection_options(expected),
                                   stream=stream, format_name=PROGRAM.PROJECTION_FORMAT)
        self.assertEqual(code, 0)
        self.assertEqual(result["candidate_projection"]["mapping_sha256"],
                         "e48b82aff7d74e2f938bef9f8a368cd3b7c8f24df6207f86ee0bb291f28ca401")
        self.assertEqual(result["transport_verification"]["chunks_checked"], 3)
        self.assertEqual(stream.tell(), len(manifest) + len(wire))
        self.assertEqual(max(stream.requests), 64 << 10)

    def test_root_fold_handles_shared_prefixes_and_path_collision(self):
        paths = (0, 1, (1 << 128) - 1, 1 << 255, (1 << 256) - 1)
        leaves = [(path, bytes([index]) * 32) for index, path in enumerate(paths, 1)]
        self.assertEqual(PROGRAM.PROJECTION.root_from_digests(leaves[::-1]).hex(),
                         "6302da4a5b709630fbe236a1952eb572d0bcf92979e7ff933746d3363915bda2")
        self.assertEqual(PROGRAM.PROJECTION.root_from_digests([]), bytes(32))
        with self.assertRaisesRegex(PROGRAM.PROJECTION.Refused, "projection_path_collision"):
            PROGRAM.PROJECTION.root_from_digests([leaves[0], leaves[0]])

    def test_projection_matches_seven_recorded_nodetree_roots(self):
        fixture = HERE.parent / "gen-state-root-vectors/testdata/candidate-l1-applier.json"
        with fixture.open("rb") as stream:
            raw = stream.read(56 << 10)
        self.assertEqual(len(raw), 55336)
        self.assertEqual(hashlib.sha256(raw).hexdigest(),
                         "08eeda1a69331109c50918f5f2a13eac2b0a9f52605d95dda1349fa1ac2e297e")
        recorded = json.loads(raw)
        self.assertEqual(recorded["source"]["revision"], "56ce2c384966f2f1940967257a0788d3998a5eef")
        self.assertEqual(recorded["backend"], "NodeTree")
        self.assertEqual(len(recorded["checkpoints"]), 7)
        self.assertEqual(sum(len(row["input"]) for row in recorded["checkpoints"]), 88)
        ledger = {}
        for row in recorded["checkpoints"]:
            with self.subTest(height=row["height"]):
                # Replay raw ledger Puts and Deletes. The projection itself
                # decides which keys and present-empty values reach the SMT.
                for event in row["input"]:
                    key = bytes.fromhex(event["key"])
                    if event["kind"] == "delete":
                        ledger.pop(key, None)
                    else:
                        self.assertEqual(event["kind"], "put")
                        ledger[key] = bytes.fromhex(event["value"])
                receipt, args, manifest, wire = projection_fixture(
                    ledger.items(), height=row["height"], hash_hex=row["hash"])
                code, result = self.invoke(receipt=receipt, args=args + projection_options(row["root"]),
                                           stream=io.BytesIO(manifest + wire),
                                           format_name=PROGRAM.PROJECTION_FORMAT)
                self.assertEqual(code, 0)
                self.assertEqual(result["candidate_projection"]["computed_root"], row["root"])
                self.assertTrue(result["candidate_projection"]["raw_frontier_metadata_matched"])

    def test_joined_options_and_producer_completion_precede_reads(self):
        receipt, args, wire = FIXTURE.fixture()
        _, options = frame_options(manifest_for(receipt, wire))
        for extra in (options[:2], options[2:], options + options[:2],
                      FIXTURE.changed(options, PROGRAM.MANIFEST_BYTES_OPTION, "0"),
                      FIXTURE.changed(options, PROGRAM.MANIFEST_SHA_OPTION, "Z" * 64)):
            with self.subTest(extra=extra):
                self.assertEqual(self.invoke(args=args + extra, stream=NoRead())[0], 64)
        code, result = self.invoke(args=FIXTURE.changed(args, "--producer-exit", "-9") + options,
                                   stream=NoRead())
        self.assertEqual((code, result["reason"]), (2, "completion_process_failure"))

    def test_selected_manifest_verified_before_payload(self):
        receipt, args, wire = FIXTURE.fixture()
        value = manifest_for(receipt, wire)
        manifest, options = frame_options(value)
        wrong_digest = FIXTURE.changed(options, PROGRAM.MANIFEST_SHA_OPTION, "0" * 64)
        value["selection"]["height"] += 1
        wrong_frontier, wrong_options = frame_options(value)
        for raw, extra, reason in ((manifest, wrong_digest, "transport_manifest_digest"),
                                   (wrong_frontier, wrong_options, "transport_manifest_selection")):
            with self.subTest(reason=reason):
                stream = CountedReads(raw + wire)
                code, result = self.invoke(args=args + extra, stream=stream)
                self.assertEqual((code, result["reason"]), (2, reason))
                self.assertEqual(stream.tell(), len(raw))

    def test_failed_transport_does_not_report_partial_inventory(self):
        receipt, args, wire = FIXTURE.fixture()
        manifest, options = frame_options(manifest_for(receipt, wire))
        for payload, reason in ((wire[:-1], "stream_truncated"), (wire[:-1] + b"\x01", "chunk_digest"),
                                (wire + b"x", "trailing_input")):
            with self.subTest(reason=reason):
                code, result = self.invoke(args=args + options, stream=io.BytesIO(manifest + payload))
                self.assertEqual((code, result["reason"]), (2, "transport_" + reason))
                self.assertTrue(result["producer_completion_matched"])
                self.assertFalse(result["stream_recount_completed"])
                self.assertIsNone(result["stream_inventory"])
                self.assertNotIn("transport_verification", result)

    def test_matching_transport_does_not_accept_duplicate_keys(self):
        receipt, args, wire = FIXTURE.fixture()
        altered = wire[:-34] + b"a" + wire[-33:]
        digest = hashlib.sha256(altered).hexdigest()
        receipt["statistics"]["put_stream_sha256"] = digest
        manifest, options = frame_options(manifest_for(receipt, altered))
        code, result = self.invoke(receipt=receipt, args=FIXTURE.changed(args, "--capture-sha256", digest) + options,
                                   stream=io.BytesIO(manifest + altered))
        self.assertEqual((code, result["reason"]), (2, "stream_inventory_refused"))
        self.assertIsNone(result["stream_inventory"])

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
        legacy = args + [PROGRAM.RECEIPT_OPTION, json.dumps(receipt)]
        manifest, options = frame_options(manifest_for(receipt, wire))
        cases = [(legacy, wire, 0, "SELECTED_EXPORT_INVENTORIED", PROGRAM.FORMAT),
                 (legacy, wire[:-1], 2, "UNKNOWN", PROGRAM.FORMAT),
                 (legacy + options, manifest + wire, 0, "SELECTED_EXPORT_INVENTORIED", PROGRAM.TRANSPORT_FORMAT),
                 (legacy + options + projection_options("00" * 32), manifest + wire, 0,
                  "SELECTED_CANDIDATE_PROJECTION_MATCHED", PROGRAM.PROJECTION_FORMAT),
                 (legacy + options, manifest + wire + b"x", 2, "UNKNOWN", PROGRAM.FORMAT),
                 (["--help"], b"", 0, "UNKNOWN", PROGRAM.FORMAT), ([], b"", 64, "UNKNOWN", PROGRAM.FORMAT)]
        for selected, data, code, status, format_name in cases:
            with self.subTest(code=code, status=status):
                completed = subprocess.run([sys.executable, "-I", "-B",
                                            str(HERE / "inventory_completed_export.py"), *selected],
                                           input=data, capture_output=True, timeout=10)
                self.assertEqual(completed.returncode, code, completed.stderr)
                result = json.loads(completed.stdout)
                self.assertEqual((result["status"], result["format"]), (status, format_name))


if __name__ == "__main__":
    unittest.main()
