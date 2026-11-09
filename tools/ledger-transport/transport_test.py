#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Finite transport controls; no dataset, network, database or chunk files."""
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


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("r1_transport", HERE / "transport.py")
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def selected(raw):
    return {"bytes": len(raw), "sha256": sha(raw), "height": 19,
            "hash": "12" * 32, "provenance_sha256": "34" * 32,
            "record_space": "effective-raw-ledger"}


def oracle_manifest(raw, chunk_size=3):
    # Separate literal framing, independent of the implementation's planner.
    return {"format": "zenon-r1-transport-manifest/v1", "selection": selected(raw),
            "chunk_bytes": chunk_size,
            "chunks": [{"bytes": len(raw[offset:offset + chunk_size]),
                        "sha256": sha(raw[offset:offset + chunk_size])}
                       for offset in range(0, len(raw), chunk_size)],
            "scope": {name: False for name in (
                "ledger_record_syntax_checked", "ledger_origin_authenticated",
                "ledger_consistency_authenticated", "snapshot_completeness_authenticated",
                "representative_dataset_accepted", "state_tree_reconstructed",
                "header_authentication_executed", "profile_agreed",
                "network_activation_authenticated", "state_value_acceptance_enabled")}}


def json_bytes(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


class ObservedReader:
    def __init__(self, raw, short=None):
        self.raw, self.position, self.requests, self.short = raw, 0, [], short

    def read(self, requested):
        if not 0 < requested <= 64 << 10:
            raise AssertionError("unbounded input request")
        self.requests.append(requested)
        size = requested if self.short is None else min(requested, self.short)
        part = self.raw[self.position:self.position + size]
        self.position += len(part)
        return part


class NeverRead:
    def read(self, _):
        raise AssertionError("input consumed before admission")


class TransportTests(unittest.TestCase):
    def check(self, raw, manifest=None, caps=None):
        value = oracle_manifest(raw) if manifest is None else manifest
        encoded = json_bytes(value)
        return tool.verify(ObservedReader(encoded + raw), len(encoded), sha(encoded), selected(raw), caps)

    def test_literal_descriptions(self):
        for raw in (b"", b"a", b"abc", b"abcdefgh", bytes(range(256))):
            with self.subTest(size=len(raw)):
                expected = oracle_manifest(raw)
                actual = tool.describe(ObservedReader(raw, short=2), selected(raw),
                                       {"bytes": 1024, "chunk_bytes": 3, "chunks": 128})
                self.assertEqual(actual, expected)
                self.assertTrue(all(item is False for item in actual["scope"].values()))

    def test_independent_manifest_and_short_reads(self):
        raw = b"abcdefgh"
        manifest = json_bytes(oracle_manifest(raw))
        reader = ObservedReader(manifest + raw, short=2)
        report = tool.verify(reader, len(manifest), sha(manifest), selected(raw))
        self.assertEqual(report["status"], "SELECTED_TRANSPORT_MATCHED")
        self.assertEqual(report["selection"], selected(raw))
        self.assertEqual(report["chunks_checked"], 3)
        self.assertEqual(reader.position, len(manifest) + len(raw))
        self.assertEqual(reader.requests[-1], 1)
        self.assertTrue(report["stream_eof_observed"])

    def test_resume_plan_selects_exact_middle_and_final_chunk_offsets(self):
        raw = b"abcdefgh"
        value = oracle_manifest(raw)
        manifest = json_bytes(value)
        for first, count, length in ((0, 1, 3), (1, 2, 5), (2, 1, 2)):
            with self.subTest(first=first, count=count):
                plan_reader = ObservedReader(manifest, short=2)
                plan = tool.check_range(plan_reader, len(manifest), sha(manifest), selected(raw), first, count)
                self.assertEqual(plan["format"], "zenon-r1-transport-range/v1")
                self.assertEqual(plan["status"], "SELECTED_RANGE_PLANNED")
                self.assertEqual(plan["range"], {"first_chunk": first, "chunk_count": count,
                    "offset": 3 * first, "bytes": length, "chunks": value["chunks"][first:first + count]})
                self.assertFalse(plan["range_eof_observed"])
                self.assertEqual(plan_reader.position, len(manifest))
                self.assertEqual(plan_reader.requests[-1], 1)
                reader = ObservedReader(manifest + raw[3 * first:3 * first + length], short=1)
                matched = tool.check_range(reader, len(manifest), sha(manifest), selected(raw),
                                           first, count, verify_payload=True)
                self.assertEqual(matched, {**plan, "status": "SELECTED_RANGE_MATCHED",
                                           "range_eof_observed": True})
                self.assertFalse(matched["whole_stream_digest_verified"])
                self.assertTrue(all(item is False for item in matched["scope"].values()))
                self.assertEqual(reader.position, len(manifest) + length)
                self.assertEqual(reader.requests[-1], 1)

    def test_resume_rejects_invalid_range_before_payload(self):
        raw = b"abcdefgh"
        manifest = json_bytes(oracle_manifest(raw))
        for first, count in ((True, 1), (0, False), (-1, 1), (0, 0), (1023, 2), (1 << 64, 1)):
            with self.subTest(first=first, count=count), self.assertRaisesRegex(tool.Refused, "range_selection"):
                tool.check_range(NeverRead(), len(manifest), sha(manifest), selected(raw), first, count)
        for first, count in ((1, 3), (3, 1), (4, 2)):
            reader = ObservedReader(manifest + raw)
            with self.subTest(first=first, count=count), self.assertRaisesRegex(tool.Refused, "range_selection"):
                tool.check_range(reader, len(manifest), sha(manifest), selected(raw), first, count, verify_payload=True)
            self.assertEqual(reader.position, len(manifest))
        empty = json_bytes(oracle_manifest(b""))
        with self.assertRaisesRegex(tool.Refused, "range_selection"):
            tool.check_range(ObservedReader(empty), len(empty), sha(empty), selected(b""), 0, 1)

    def test_resume_checks_manifest_and_each_selected_chunk_and_eof(self):
        raw = b"abcdefgh"
        manifest = json_bytes(oracle_manifest(raw))
        reader = ObservedReader(manifest + raw[3:])
        with self.assertRaisesRegex(tool.Refused, "manifest_digest"):
            tool.check_range(reader, len(manifest), "0" * 64, selected(raw), 1, 2, verify_payload=True)
        self.assertEqual(reader.position, len(manifest))
        for payload, reason in ((b"de", "stream_truncated"), (b"deFgH", "chunk_digest"),
                                (b"ghdef", "chunk_digest"), (b"defde", "chunk_digest"),
                                (b"defghx", "trailing_input")):
            with self.subTest(payload=payload), self.assertRaisesRegex(tool.Refused, reason):
                tool.check_range(ObservedReader(manifest + payload, short=2), len(manifest), sha(manifest),
                                 selected(raw), 1, 2, verify_payload=True)
        reader = ObservedReader(manifest + b"not a manifest-only stream")
        with self.assertRaisesRegex(tool.Refused, "trailing_input"):
            tool.check_range(reader, len(manifest), sha(manifest), selected(raw), 1, 2)
        self.assertEqual(reader.position, len(manifest) + 1)

    def test_even_a_full_range_does_not_match_the_whole_stream_digest(self):
        raw = b"abcdefgh"
        value = oracle_manifest(raw)
        value["selection"]["sha256"] = "0" * 64
        manifest = json_bytes(value)
        report = tool.check_range(ObservedReader(manifest + raw), len(manifest), sha(manifest),
                                  value["selection"], 0, 3, verify_payload=True)
        self.assertEqual(report["status"], "SELECTED_RANGE_MATCHED")
        self.assertFalse(report["whole_stream_digest_verified"])
        with self.assertRaisesRegex(tool.Refused, "stream_digest"):
            tool.verify(ObservedReader(manifest + raw), len(manifest), sha(manifest), value["selection"])

    def test_actual_resume_cli_and_final_ordered_verification(self):
        raw = b"abcdefgh"
        manifest = json_bytes(oracle_manifest(raw))
        command = [sys.executable, "-I", "-B", str(HERE / "transport.py")]
        base = self.arguments(raw)[1:] + ["--manifest-bytes", str(len(manifest)),
                                        "--manifest-sha256", sha(manifest)]
        span = ["--first-chunk", "1", "--chunk-count", "1"]
        planned = subprocess.run(command + ["plan-range"] + base + span,
                                 input=manifest, capture_output=True, timeout=10)
        self.assertEqual(planned.returncode, 0, planned.stderr)
        plan = json.loads(planned.stdout)["range"]
        replacement = raw[plan["offset"]:plan["offset"] + plan["bytes"]]
        for payload, exit_code, status in ((replacement, 0, "SELECTED_RANGE_MATCHED"),
                                          (b"wrong", 2, "UNKNOWN")):
            checked = subprocess.run(command + ["verify-range"] + base + span,
                                     input=manifest + payload, capture_output=True, timeout=10)
            self.assertEqual(checked.returncode, exit_code, checked.stderr)
            self.assertEqual(json.loads(checked.stdout)["status"], status)
        for args in (["verify-range"] + base, ["plan-range"] + base + ["--first-chunk", "0", "--chunk-count", "0"],
                     ["verify"] + base + span):
            out = io.BytesIO()
            self.assertEqual(tool.main(args, NeverRead(), out, io.StringIO()), 64)
            self.assertEqual(json.loads(out.getvalue())["status"], "UNKNOWN")
        checked = subprocess.run(command + ["verify"] + base,
                                 input=manifest + raw[:3] + replacement + raw[6:], capture_output=True, timeout=10)
        self.assertEqual(checked.returncode, 0, checked.stderr)
        self.assertEqual(json.loads(checked.stdout)["status"], "SELECTED_TRANSPORT_MATCHED")

    def test_first_chunk_bytes_are_hashed_once_in_describe_and_verify(self):
        original_sha256 = hashlib.sha256
        updates = []

        class MeasuredSHA256:
            def __init__(self, raw=b""):
                self.digest = original_sha256(raw)

            def update(self, raw):
                updates.append(len(raw))
                self.digest.update(raw)

            def hexdigest(self):
                return self.digest.hexdigest()

        for raw in (b"", b"abc", b"abcdefg"):
            with self.subTest(payload_bytes=len(raw)):
                expected = oracle_manifest(raw)
                manifest, pin = json_bytes(expected), selected(raw)
                manifest_pin = sha(manifest)
                caps = {"bytes": 8, "chunk_bytes": 3, "chunks": 3}
                hashed_payload_bytes = 2 * len(raw) - min(len(raw), caps["chunk_bytes"])
                updates.clear()
                with mock.patch.object(tool.hashlib, "sha256", MeasuredSHA256):
                    described = tool.describe(ObservedReader(raw, short=2), pin, caps)
                    self.assertEqual(described, expected)
                    self.assertEqual(sum(updates), hashed_payload_bytes)
                    updates.clear()
                    report = tool.verify(ObservedReader(manifest + raw, short=2),
                                         len(manifest), manifest_pin, pin, caps)
                    self.assertEqual(report["chunks_checked"], len(expected["chunks"]))
                    self.assertTrue(report["stream_eof_observed"])
                    self.assertEqual(sum(updates), hashed_payload_bytes)

    def test_single_chunk_still_requires_both_selected_digests(self):
        raw = b"abc"
        for field, reason in (("chunks", "chunk_digest"), ("selection", "stream_digest")):
            with self.subTest(field=field):
                value = oracle_manifest(raw)
                selected_digest = value["chunks"][0] if field == "chunks" else value["selection"]
                selected_digest["sha256"] = "0" * 64
                manifest = json_bytes(value)
                with self.assertRaisesRegex(tool.Refused, "^" + reason + "$"):
                    tool.verify(ObservedReader(manifest + raw), len(manifest),
                                sha(manifest), value["selection"])

    def test_large_virtual_stream_without_files_or_chunk_buffers(self):
        size, chunk_size = (8 << 20) + 19, 512 << 10
        pattern = bytes(range(256))

        class Virtual:
            position = 0
            requests = []

            def read(self, requested):
                if not 0 < requested <= 64 << 10:
                    raise AssertionError("unbounded read")
                self.requests.append(requested)
                count = min(requested, size - self.position)
                offset = self.position % 256
                part = (pattern * ((offset + count + 255) // 256))[offset:offset + count]
                self.position += count
                return part

        whole = hashlib.sha256()
        expected = []
        for offset in range(0, size, chunk_size):
            count = min(chunk_size, size - offset)
            raw = (pattern * ((count + 255) // 256))[:count]
            whole.update(raw)
            expected.append({"bytes": count, "sha256": sha(raw)})
        pin = {**selected(b""), "bytes": size, "sha256": whole.hexdigest()}
        reader = Virtual()
        value = tool.describe(reader, pin, {"bytes": size, "chunk_bytes": chunk_size, "chunks": 17})
        self.assertEqual(value["chunks"], expected)
        self.assertEqual(reader.position, size)
        self.assertLessEqual(max(reader.requests), 64 << 10)
        self.assertEqual(reader.requests[-1], 1)
        # This checks requests and retained metadata, not RSS or real-network performance.
        self.assertLess(len(tool.encoded(value)), 4096)

    def test_selection_rejected_before_read(self):
        cases = []
        for key, bad_values in (("bytes", (True, -1, 1 << 40)),
                                ("height", (False, -1, 1 << 64)),
                                ("sha256", ("A" * 64, "g" * 64, None)),
                                ("hash", ("aa", 123)),
                                ("provenance_sha256", ("", "A" * 64)),
                                ("record_space", ("physical-leveldb", None))):
            for bad in bad_values:
                cases.append({**selected(b"abc"), key: bad})
        cases.extend(({**selected(b"abc"), "authenticated": True}, {}))
        for index, pin in enumerate(cases):
            with self.subTest(case=index), self.assertRaises(tool.Refused):
                tool.describe(NeverRead(), pin)

    def test_limits_and_chunk_count_rejected_before_read(self):
        for key, maximum in tool.HARD_LIMITS.items():
            for bad in (0, -1, True, maximum + 1, "1"):
                with self.subTest(key=key, bad=bad), self.assertRaises(tool.Refused):
                    tool.describe(NeverRead(), selected(b"abc"), {**tool.DEFAULT_LIMITS, key: bad})
        with self.assertRaisesRegex(tool.Refused, "chunk_count"):
            tool.describe(NeverRead(), selected(b"abcd"), {"bytes": 4, "chunk_bytes": 1, "chunks": 3})

    def test_manifest_pins_rejected_before_stream(self):
        for size, fingerprint in ((0, "a" * 64), (True, "a" * 64),
                                  (tool.MANIFEST_BYTES + 1, "a" * 64), (1, "PRIVATE")):
            with self.subTest(size=size), self.assertRaisesRegex(tool.Refused, "manifest_pin"):
                tool.verify(NeverRead(), size, fingerprint, selected(b"abc"))
        raw = json_bytes(oracle_manifest(b"abc"))
        reader = ObservedReader(raw + b"abc")
        with self.assertRaisesRegex(tool.Refused, "manifest_digest"):
            tool.verify(reader, len(raw), "0" * 64, selected(b"abc"))
        self.assertEqual(reader.position, len(raw))

    def test_manifest_schema_and_scope_before_payload(self):
        raw = b"abcdefgh"
        base = oracle_manifest(raw)
        cases = [None, [], {}, {**base, "authenticated": True}, {**base, "format": "STATE_ROOT"},
                 {**base, "scope": {**base["scope"], "state_value_acceptance_enabled": True}},
                 {**base, "scope": {**base["scope"], "profile_agreed": 0}},
                 {**base, "selection": {**base["selection"], "height": True}},
                 {**base, "selection": {**base["selection"], "height": 20}},
                 {**base, "selection": {**base["selection"], "hash": "56" * 32}},
                 {**base, "selection": {**base["selection"], "provenance_sha256": "78" * 32}},
                 {**base, "chunk_bytes": True}, {**base, "chunk_bytes": 0},
                 {**base, "chunk_bytes": tool.HARD_LIMITS["chunk_bytes"] + 1},
                 {**base, "chunks": {}}, {**base, "chunks": base["chunks"][:-1]},
                 {**base, "chunks": base["chunks"] + [base["chunks"][0]]}]
        for key, value in (("bytes", True), ("bytes", 0), ("bytes", 2),
                           ("sha256", "F" * 64), ("sha256", None), ("offset", 0)):
            variant = copy.deepcopy(base)
            variant["chunks"][0][key] = value
            cases.append(variant)
        for index, value in enumerate(cases):
            manifest = json_bytes(value)
            reader = ObservedReader(manifest + raw)
            with self.subTest(case=index), self.assertRaises(tool.Refused):
                tool.verify(reader, len(manifest), sha(manifest), selected(raw))
            self.assertEqual(reader.position, len(manifest))

    def test_malformed_json_before_payload(self):
        base = json_bytes(oracle_manifest(b"abc"))
        cases = [b"{", b"\xff", b'{"x":NaN}', b'{"x":1.0}', b'{"x":-0}',
                 b'{"x":18446744073709551616}', b"[" * 2000 + b"]" * 2000,
                 base.replace(b'"bytes":3', b'"bytes":3,"bytes":3', 1),
                 base.replace(b'"height":19', b'"height":19,"height":19', 1),
                 base + b"{}"]
        for index, manifest in enumerate(cases):
            reader = ObservedReader(manifest + b"abc")
            with self.subTest(case=index), self.assertRaises(tool.Refused):
                tool.verify(reader, len(manifest), sha(manifest), selected(b"abc"))
            self.assertEqual(reader.position, len(manifest))

    def test_truncation_and_trailing_data(self):
        raw = b"abcdefgh"
        manifest = json_bytes(oracle_manifest(raw))
        frame = manifest + raw
        for cut in (0, 1, len(manifest) - 1, len(manifest), len(frame) - 1):
            with self.subTest(cut=cut), self.assertRaises(tool.Refused):
                tool.verify(ObservedReader(frame[:cut]), len(manifest), sha(manifest), selected(raw))
        reader = ObservedReader(frame + b"x" * 1000)
        with self.assertRaisesRegex(tool.Refused, "trailing_input"):
            tool.verify(reader, len(manifest), sha(manifest), selected(raw))
        self.assertEqual(reader.position, len(frame) + 1)

    def test_inspector_must_observe_eof(self):
        raw = b"abc"
        manifest = json_bytes(oracle_manifest(raw))
        reader = ObservedReader(manifest + raw)
        with self.assertRaisesRegex(tool.Refused, "stream_incomplete"):
            tool.verify_with(reader, len(manifest), sha(manifest), selected(raw),
                             lambda payload: payload.read(3))
        self.assertEqual(reader.requests, [len(manifest), 3])

    def test_inspector_cannot_retry_after_a_failed_eof_check(self):
        raw = b"abc"
        manifest = json_bytes(oracle_manifest(raw))
        reader = ObservedReader(manifest + raw + b"x")

        def inspect(payload):
            self.assertEqual(payload.read(3), raw)
            with self.assertRaisesRegex(tool.Refused, "trailing_input"):
                payload.read(1)
            with self.assertRaisesRegex(tool.Refused, "stream_refused"):
                payload.read(1)

        with self.assertRaisesRegex(tool.Refused, "stream_incomplete"):
            tool.verify_with(reader, len(manifest), sha(manifest), selected(raw), inspect)
        self.assertEqual(reader.requests, [len(manifest), 3, 1])

    def test_changed_missing_reordered_and_repeated_chunks(self):
        raw = b"abcdefgh"
        manifest = json_bytes(oracle_manifest(raw))
        for changed in (b"Abcdefgh", b"defabcgh", b"abcabcgh", b"abcgh"):
            with self.subTest(payload=changed), self.assertRaises(tool.Refused):
                tool.verify(ObservedReader(manifest + changed), len(manifest), sha(manifest), selected(raw))
        value = oracle_manifest(raw)
        value["selection"]["sha256"] = "0" * 64
        changed = json_bytes(value)
        with self.assertRaisesRegex(tool.Refused, "stream_digest"):
            tool.verify(ObservedReader(changed + raw), len(changed), sha(changed), value["selection"])

    def test_identical_chunks_and_empty_stream(self):
        self.assertEqual(self.check(b"abcabc")["chunks_checked"], 2)
        report = self.check(b"")
        self.assertEqual(report["chunks_checked"], 0)
        self.assertFalse(report["scope"]["snapshot_completeness_authenticated"])

    def test_selected_manifest_resource_caps_before_payload(self):
        raw = b"abcdefgh"
        manifest = json_bytes(oracle_manifest(raw))
        for caps in ({"bytes": 8, "chunk_bytes": 2, "chunks": 3},
                     {"bytes": 8, "chunk_bytes": 3, "chunks": 2}):
            reader = ObservedReader(manifest + raw)
            with self.subTest(caps=caps), self.assertRaises(tool.Refused):
                tool.verify(reader, len(manifest), sha(manifest), selected(raw), caps)
            self.assertEqual(reader.position, len(manifest))
        # Exercise the actual hard row count without allocating a large payload.
        count = tool.HARD_LIMITS["chunks"]
        pin = selected(b"a" * count)
        value = tool.describe(ObservedReader(b"a" * count), pin,
                              {"bytes": count, "chunk_bytes": 1, "chunks": count})
        self.assertEqual(len(value["chunks"]), count)
        self.assertLessEqual(len(tool.encoded(value)), tool.MANIFEST_BYTES)

    def test_reader_contract_rejects_invalid_returns(self):
        for value in (None, bytearray(b"abc"), b"abcd"):
            class Invalid:
                def read(self, _):
                    return value
            with self.subTest(kind=type(value).__name__), self.assertRaisesRegex(tool.Refused, "input_read"):
                tool.describe(Invalid(), selected(b"abc"))

    def test_selection_and_limits_copied_before_read(self):
        raw, pin = b"abc", selected(b"abc")
        caps = {"bytes": 3, "chunk_bytes": 2, "chunks": 2}

        class Mutating(ObservedReader):
            def read(self, size):
                pin["sha256"] = "0" * 64
                caps["chunk_bytes"] = 0
                return super().read(size)

        actual = tool.describe(Mutating(raw), pin, caps)
        self.assertEqual(actual, oracle_manifest(raw, 2))

    def arguments(self, raw):
        pin = selected(raw)
        return ["describe", "--expect-bytes", str(pin["bytes"]), "--expect-sha256", pin["sha256"],
                "--expect-height", str(pin["height"]), "--expect-hash", pin["hash"],
                "--provenance-sha256", pin["provenance_sha256"]]

    def test_options_and_help_do_not_read_or_echo(self):
        normal = self.arguments(b"abc")
        cases = [[], ["PRIVATE"], normal + ["--private", "PRIVATE"],
                 normal + ["--expect-hash", "PRIVATE"], normal + ["--max-bytes=0"],
                 normal + ["--max-chunks=PRIVATE"], normal + ["--manifest-bytes=1"],
                 [arg.replace("3", "03") if i == 2 else arg for i, arg in enumerate(normal)]]
        for index, args in enumerate(cases):
            out, err = io.BytesIO(), io.StringIO()
            with self.subTest(case=index):
                code = tool.main(args, NeverRead(), out, err)
                self.assertEqual(code, 64)
                self.assertEqual(json.loads(out.getvalue())["status"], "UNKNOWN")
                self.assertNotIn("PRIVATE", out.getvalue().decode() + err.getvalue())
        out, err = io.BytesIO(), io.StringIO()
        self.assertEqual(tool.main(["--help"], NeverRead(), out, err), 0)
        self.assertEqual(json.loads(out.getvalue())["status"], "UNKNOWN")
        self.assertTrue(err.getvalue().startswith("ledger-transport"))

    def test_io_interruption_and_output_completion(self):
        for exception, code in ((OSError("PRIVATE"), 70), (KeyboardInterrupt(), 130)):
            class Failing:
                def read(self, _):
                    raise exception
            out = io.BytesIO()
            self.assertEqual(tool.main(self.arguments(b"abc"), Failing(), out, io.StringIO()), code)
            self.assertEqual(json.loads(out.getvalue())["status"], "UNKNOWN")
            self.assertNotIn(b"PRIVATE", out.getvalue())

        class Partial(io.BytesIO):
            def write(self, raw):
                super().write(raw[:1])
                return 1

        class FlushFailure(io.BytesIO):
            def flush(self):
                raise OSError("PRIVATE")

        for writer in (Partial(), FlushFailure()):
            with self.subTest(writer=type(writer).__name__):
                self.assertEqual(tool.main(self.arguments(b"abc"), ObservedReader(b"abc"),
                                           writer, io.StringIO()), 70)

    def test_actual_cli_and_independent_inventory(self):
        # Two independently encoded, sorted typed balance puts, including present zero.
        key = b"\x03" + bytes(20) + b"\x03" + bytes(10)
        second = key[:-1] + b"\x01"
        raw = b"\x01\x20" + key + b"\x20" + bytes(32) + b"\x01\x20" + second + b"\x00"
        command = [sys.executable, "-I", "-B", str(HERE / "transport.py")]
        created = subprocess.run(command + self.arguments(raw), input=raw, capture_output=True, timeout=10)
        self.assertEqual(created.returncode, 0, created.stderr)
        manifest = json.loads(created.stdout)
        self.assertEqual(manifest, oracle_manifest(raw, tool.DEFAULT_LIMITS["chunk_bytes"]))
        verify_args = self.arguments(raw)
        verify_args[0] = "verify"
        checked = subprocess.run(command + verify_args + ["--manifest-bytes", str(len(created.stdout)),
                                 "--manifest-sha256", sha(created.stdout)],
                                 input=created.stdout + raw, capture_output=True, timeout=10)
        self.assertEqual(checked.returncode, 0, checked.stderr)
        self.assertEqual(json.loads(checked.stdout)["status"], "SELECTED_TRANSPORT_MATCHED")
        self.assertFalse(json.loads(checked.stdout)["scope"]["ledger_record_syntax_checked"])
        # Feed exactly the same raw bytes to the separate existing record parser.
        inventory = subprocess.run([sys.executable, "-I", "-B",
            str(HERE.parent / "ledger-inventory" / "inventory.py"),
            "--expect-bytes", str(len(raw)), "--expect-records", "2", "--expect-sha256", sha(raw),
            "--provenance-sha256", "34" * 32], input=raw, capture_output=True, timeout=10)
        self.assertEqual(inventory.returncode, 0, inventory.stderr)
        report = json.loads(inventory.stdout)
        self.assertEqual(report["status"], "SELECTED_STREAM_INVENTORIED")
        self.assertEqual(report["families"]["typed_balance"]["raw_zero32_values"], 1)
        self.assertEqual(report["families"]["typed_balance"]["present_empty_values"], 1)
        for failed_input in (created.stdout + raw[:-1], created.stdout + raw + b"x"):
            failed = subprocess.run(command + verify_args + ["--manifest-bytes", str(len(created.stdout)),
                                    "--manifest-sha256", sha(created.stdout)], input=failed_input,
                                    capture_output=True, timeout=10)
            self.assertEqual(failed.returncode, 2)
            self.assertEqual(json.loads(failed.stdout)["status"], "UNKNOWN")

    def test_qualification_license_material(self):
        root = HERE.parent.parent
        sources = [HERE / "transport.py", HERE / "transport_test.py",
                   HERE.parent / "ledger-inventory" / "inventory.py"]
        for source in sources:
            self.assertIn(b"# SPDX-License-Identifier: GPL-3.0-only\n", source.read_bytes())
        license_text = (HERE.parent / "gen-state-root-vectors" / "LICENSE").read_bytes()
        self.assertIn(b"GNU GENERAL PUBLIC LICENSE", license_text)
        self.assertIn(b"Version 3, 29 June 2007", license_text)
        self.assertIn(b"END OF TERMS AND CONDITIONS", license_text)
        self.assertTrue((root / "LICENSE").read_bytes().startswith(b"MIT License"))
        notices = (HERE / "THIRD_PARTY_NOTICES").read_text()
        for name in ("transport.py", "transport_test.py", "inventory.py",
                     "tools/gen-state-root-vectors/LICENSE", "GPL-3.0-only"):
            self.assertIn(name, notices)
        workflow = (root / ".github/workflows/ledger-transport.yml").read_text()
        self.assertIn("'tools/ledger-transport/THIRD_PARTY_NOTICES'", workflow)
        self.assertIn("'tools/gen-state-root-vectors/LICENSE'", workflow)
        self.assertIn("include-hidden-files: true", workflow)


class RecordingResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.roots, self.subtests = [], {"passed": 0, "failed": 0}

    def addSuccess(self, test):
        super().addSuccess(test)
        self.roots.append({"name": test._testMethodName, "status": "PASS"})

    def addSubTest(self, test, subtest, error):
        super().addSubTest(test, subtest, error)
        self.subtests["passed" if error is None else "failed"] += 1


def run_tests(args):
    destination = None
    if args:
        if len(args) != 2 or args[0] != "--report":
            raise SystemExit("expected optional --report PATH")
        destination = Path(args[1])  # Trusted qualification output, never a tool input.
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(TransportTests)
    expected = [test._testMethodName for test in suite]
    result = unittest.TextTestRunner(verbosity=2, resultclass=RecordingResult).run(suite)
    report = {"format": "zenon-r1-transport-tests/v1", "passed": result.wasSuccessful(),
              "selected_roots": expected, "roots": result.roots, "tests_run": result.testsRun,
              "failures": len(result.failures), "errors": len(result.errors),
              "skips": [{"name": test._testMethodName, "reason": reason} for test, reason in result.skipped],
              "subtests": result.subtests, "real_R1_dataset_used": False,
              "root_state_acceptance_enabled": False}
    raw = json_bytes(report)
    if destination is not None:
        with destination.open("xb") as stream:
            stream.write(raw)
    sys.stdout.buffer.write(raw)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(run_tests(sys.argv[1:]))
