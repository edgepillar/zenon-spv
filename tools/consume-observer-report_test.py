#!/usr/bin/env python3
"""Observable controls for bounded diagnostic consumption and process failures."""

import copy
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import unittest


PATH = Path(__file__).with_name("consume-observer-report.py")
spec = importlib.util.spec_from_file_location("observer_reader", PATH)
reader = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reader)


def report(mode="local-file", count=5):
    child = {"exit_code": 0, "elapsed_ns": 0, "stdout_bytes": 80, "stderr_bytes": 0}
    value = {"schema_version": 1 if mode == "local-file" else 2, "status": "matched", "category": None,
             "checked_targets": count, "elapsed_ns": 0, "verifier": dict(child), "consumer": dict(child)}
    if mode == "collected":
        value["collector"] = dict(child)
    return value


def encoded(value):
    return json.dumps(value, separators=(",", ":")).encode() + b"\n"


class Unreadable:
    def read(self, _):
        raise AssertionError("selected failure must not read stdin")


class ObserverReaderControls(unittest.TestCase):
    def run_reader(self, raw, mode="local-file", expected=5, actual=0, args=None, stream=None):
        output, diagnostics = io.StringIO(), io.StringIO()
        flags = args if args is not None else ["--mode", mode, "--expected-targets", str(expected), "--observer-exit-code", str(actual)]
        code = reader.run(flags, stream if stream is not None else io.BytesIO(raw), output, diagnostics)
        return code, output.getvalue(), diagnostics.getvalue()

    def assert_refused(self, raw, **options):
        code, stdout, stderr = self.run_reader(raw, **options)
        self.assertEqual(code, 2)
        self.assertEqual(stderr, "")
        value = json.loads(stdout)
        self.assertEqual(value["status"], "not_matched")
        self.assertEqual(value["checked_targets"], 0)
        self.assertNotIn("PRIVATE", stdout)
        return value

    def test_complete_local_and_collected_reports(self):
        for mode in ("local-file", "collected"):
            code, stdout, stderr = self.run_reader(encoded(report(mode)), mode=mode)
            self.assertEqual((code, stderr), (0, ""))
            self.assertEqual(stdout, '{"schema_version":1,"status":"matched","category":null,"checked_targets":5}\n')

    def test_expected_count_boundaries_and_large_lossless_counter(self):
        for count in (1, 256):
            value = report(count=count)
            value["elapsed_ns"] = (1 << 63) - 1
            self.assertEqual(self.run_reader(encoded(value), expected=count)[0], 0)

    def test_zero_clock_tick_is_valid(self):
        self.assertEqual(self.run_reader(encoded(report()))[0], 0)

    def test_whitespace_key_order_and_utf8_json_bytes(self):
        raw = json.dumps(dict(reversed(list(report().items()))), indent=2).encode()
        self.assertEqual(self.run_reader(raw)[0], 0)

    def test_actual_failure_precedes_any_stdin(self):
        for actual in (2, 64, 70, 130, -9):
            value = self.assert_refused(b"", actual=actual, stream=Unreadable())
            self.assertEqual(value["category"], "process_failure")

    def test_wrong_count_and_schema_mode(self):
        for mode, raw in (("local-file", encoded(report("collected"))), ("collected", encoded(report())),
                          ("local-file", encoded(report(count=6)))):
            self.assert_refused(raw, mode=mode)

    def test_missing_and_unknown_root_fields(self):
        for key in report():
            value = report(); del value[key]
            self.assert_refused(encoded(value))
        value = report(); value["PRIVATE_PATH"] = "PRIVATE_SECRET"
        self.assert_refused(encoded(value))

    def test_missing_and_unknown_child_fields(self):
        for mode in ("local-file", "collected"):
            for name in ("verifier", "consumer") + (("collector",) if mode == "collected" else ()):
                for key in report(mode)[name]:
                    value = report(mode); del value[name][key]
                    self.assert_refused(encoded(value), mode=mode)
                value = report(mode); value[name]["PRIVATE_PATH"] = "PRIVATE_SECRET"
                self.assert_refused(encoded(value), mode=mode)

    def test_child_exit_requires_integer_zero_and_actual_completion(self):
        for mode in ("local-file", "collected"):
            for name in ("verifier", "consumer") + (("collector",) if mode == "collected" else ()):
                for invalid in (None, False, True, 2, -1, "0", 0.0, []):
                    value = report(mode); value[name]["exit_code"] = invalid
                    self.assert_refused(encoded(value), mode=mode)

    def test_numbers_cannot_be_booleans_floats_or_strings(self):
        for field in ("schema_version", "checked_targets", "elapsed_ns"):
            for invalid in (False, True, None, "0", 1.0, [], {}):
                value = report(); value[field] = invalid
                self.assert_refused(encoded(value))
        for field in ("elapsed_ns", "stdout_bytes", "stderr_bytes"):
            for invalid in (False, True, None, "0", 0.0, [], {}):
                value = report(); value["verifier"][field] = invalid
                self.assert_refused(encoded(value))

    def test_negative_or_overflow_counters_and_stream_bounds(self):
        for key in ("elapsed_ns", "stdout_bytes", "stderr_bytes"):
            for invalid in (-1, 1 << 63):
                value = report(); value["verifier"][key] = invalid
                self.assert_refused(encoded(value))
        for name, cap in (("verifier", 4 << 20), ("consumer", 1024), ("collector", 64 << 20)):
            mode = "collected" if name == "collector" else "local-file"
            value = report(mode); value[name]["stdout_bytes"] = cap
            self.assertEqual(self.run_reader(encoded(value), mode=mode)[0], 0)
            for invalid in (0, cap + 1):
                value[name]["stdout_bytes"] = invalid
                self.assert_refused(encoded(value), mode=mode)
        value = report(); value["verifier"]["stderr_bytes"] = (16 << 10) + 1
        self.assert_refused(encoded(value))

    def test_status_category_and_nonobject_values(self):
        for field, values in (("status", ("not_matched", "ACCEPT", None, True, {})),
                              ("category", ("PRIVATE_SECRET", False, {}, [])),
                              ("schema_version", (0, 3)), ("checked_targets", (0, 257))):
            for invalid in values:
                value = report(); value[field] = invalid
                self.assert_refused(encoded(value))
        for invalid in (None, [], True, 0, "PRIVATE_SECRET"):
            self.assert_refused(encoded(invalid))

    def test_duplicates_and_escaped_aliases_at_each_depth(self):
        raw = encoded(report())
        for changed in (raw.replace(b'"schema_version":1', b'"schema_version":1,"schema_version":1'),
                        raw.replace(b'"schema_version":1', b'"schema_version":1,"schema_vers\\u0069on":1'),
                        raw.replace(b'"exit_code":0', b'"exit_code":0,"exit_code":0'),
                        raw.replace(b'"exit_code":0', b'"exit_code":0,"exit_c\\u006fde":0'),
                        raw.replace(b'"schema_version":1', b'"Schema_version":1')):
            self.assert_refused(changed)

    def test_nonfinite_and_noninteger_numeric_tokens(self):
        raw = encoded(report())
        for token in (b"NaN", b"Infinity", b"-Infinity", b"0e0", b"0.0", b"999999999999999999999999999999"):
            self.assert_refused(raw.replace(b'"elapsed_ns":0', b'"elapsed_ns":' + token))

    def test_trailing_document_partial_invalid_utf8_and_bom(self):
        raw = encoded(report())
        for changed in (raw + b"{}", raw + b"PRIVATE_SECRET", raw[:-2], b"", b"\xff", b"\xef\xbb\xbf" + raw):
            self.assert_refused(changed)

    def test_bounded_report_and_one_overflow_byte(self):
        raw = encoded(report())
        exact = raw + b" " * ((16 << 10) - len(raw))
        self.assertEqual(self.run_reader(exact)[0], 0)
        self.assert_refused(exact + b" ")
        self.assert_refused(b"[" * 6000 + b"]" * 6000)

    def test_short_reads_still_require_complete_eof(self):
        class Chunks(io.BytesIO):
            def read(self, limit):
                return super().read(min(limit, 3))
        self.assertEqual(self.run_reader(b"", stream=Chunks(encoded(report())))[0], 0)
        self.assert_refused(b"", stream=Chunks(encoded(report()) + b"{}"))

    def test_read_error_after_successful_looking_bytes_is_failure(self):
        class Failing:
            def __init__(self): self.first = True
            def read(self, _):
                if self.first:
                    self.first = False
                    return encoded(report())
                raise OSError("PRIVATE_PATH")
        code, stdout, stderr = self.run_reader(b"", stream=Failing())
        self.assertEqual((code, stderr), (70, ""))
        self.assertEqual(json.loads(stdout)["category"], "input_unavailable")
        self.assertNotIn("PRIVATE", stdout)

    def test_reader_none_or_excess_bytes_cannot_promote_partial_data(self):
        for result in (None, "PRIVATE_SECRET", b" " * 4097):
            class Broken:
                def read(self, _): return result
            self.assert_refused(b"", stream=Broken())

    def test_interrupt_is_recorded_without_traceback(self):
        class Interrupted:
            def read(self, _): raise KeyboardInterrupt()
        code, stdout, stderr = self.run_reader(b"", stream=Interrupted())
        self.assertEqual((code, stderr), (130, ""))
        self.assertEqual(json.loads(stdout)["category"], "cancelled")

    def test_invalid_duplicate_or_abbreviated_options_read_nothing(self):
        base = ["--mode", "local-file", "--observer-exit-code", "0", "--expected-targets", "5"]
        invalid = [[], base[:-1], base + ["PRIVATE_SECRET"], base + ["--mode", "collected"],
                   base + ["--observer-exit-code=0"], ["--mo", "local-file", *base[2:]]]
        for value in ("0", "257", "true", "1.0", "+5", " 5", "05", "PRIVATE_SECRET"):
            invalid.append(base[:-1] + [value])
        for flags in invalid:
            code, stdout, stderr = self.run_reader(b"", args=flags, stream=Unreadable())
            self.assertEqual((code, stdout), (64, ""))
            self.assertEqual(stderr, reader.USAGE)
            self.assertNotIn("PRIVATE", stderr)

    def test_equals_options_and_signed_actual_exit(self):
        flags = ["--mode=local-file", "--observer-exit-code=0", "--expected-targets=5"]
        self.assertEqual(self.run_reader(encoded(report()), args=flags)[0], 0)

    def test_output_short_write_and_flush_failure_are_nonzero(self):
        class Short(io.StringIO):
            def write(self, value): return super().write(value[:10])
        class FailedFlush(io.StringIO):
            def flush(self): raise OSError("PRIVATE_PATH")
        for output in (Short(), FailedFlush()):
            diagnostics = io.StringIO()
            code = reader.run(["--mode", "local-file", "--observer-exit-code", "0", "--expected-targets", "5"],
                              io.BytesIO(encoded(report())), output, diagnostics)
            self.assertEqual(code, 70)
            self.assertEqual(diagnostics.getvalue(), "consume-observer-report: cannot write result\n")

    def test_actual_cli_preserves_fixed_summary_and_private_error(self):
        flags = [sys.executable, "-I", "-B", str(PATH), "--mode", "local-file", "--observer-exit-code", "0", "--expected-targets", "5"]
        good = subprocess.run(flags, input=encoded(report()), capture_output=True, timeout=10)
        self.assertEqual(good.returncode, 0)
        self.assertEqual(good.stderr, b"")
        bad = subprocess.run(flags, input=b"PRIVATE_SECRET", capture_output=True, timeout=10)
        self.assertEqual(bad.returncode, 2)
        self.assertEqual(bad.stderr, b"")
        self.assertNotIn(b"PRIVATE", bad.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
