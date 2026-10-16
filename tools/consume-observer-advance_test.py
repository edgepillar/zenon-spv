#!/usr/bin/env python3
"""Explicit schema-3 process metadata controls, never network qualification."""

import copy
import importlib.util
import io
import json
from pathlib import Path
import unittest


SPEC = importlib.util.spec_from_file_location("observer_consumer", Path(__file__).with_name("consume-observer-report.py"))
CONSUMER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONSUMER)


def report(version=3):
    value = {"schema_version": version, "status": "matched", "category": None,
             "checked_targets": 1, "elapsed_ns": 0,
             "verifier": {"exit_code": 0, "elapsed_ns": 0, "stdout_bytes": 10, "stderr_bytes": 0},
             "consumer": {"exit_code": 0, "elapsed_ns": 0, "stdout_bytes": 10, "stderr_bytes": 0}}
    if version >= 2:
        value["collector"] = copy.deepcopy(value["verifier"])
    if version == 3:
        value["watch"] = copy.deepcopy(value["verifier"])
    return value


def consume(value, mode="advancing", actual="0", reader=None):
    raw = value if type(value) is bytes else json.dumps(value, separators=(",", ":")).encode()
    output, diagnostics = io.StringIO(), io.StringIO()
    code = CONSUMER.run(["--mode", mode, "--observer-exit-code", actual, "--expected-targets", "1"],
                        io.BytesIO(raw) if reader is None else reader, output, diagnostics)
    return code, output.getvalue(), diagnostics.getvalue()


class AdvancingConsumerControls(unittest.TestCase):
    def test_explicit_mode_requires_complete_four_child_success(self):
        code, raw, diagnostics = consume(report())
        self.assertEqual(code, 0)
        self.assertEqual(diagnostics, "")
        self.assertEqual(raw, '{"schema_version":1,"status":"matched","category":null,"checked_targets":1}\n')

    def test_original_modes_keep_exact_output_and_reject_new_schema(self):
        for version, mode in ((1, "local-file"), (2, "collected")):
            self.assertEqual(consume(report(version), mode), consume(report()))
            self.assertEqual(consume(report(), mode)[0], 2)
            self.assertEqual(consume(report(version))[0], 2)

    def test_each_required_field_and_extra_field_refused(self):
        original = report()
        for key in original:
            changed = copy.deepcopy(original)
            del changed[key]
            self.assertEqual(consume(changed)[0], 2, key)
        original["PRIVATE_FIELD"] = "PRIVATE_VALUE"
        code, raw, _ = consume(original)
        self.assertEqual(code, 2)
        self.assertNotIn("PRIVATE", raw)

    def test_every_child_requires_actual_zero_and_complete_bounded_streams(self):
        for child in ("watch", "collector", "verifier", "consumer"):
            for field, values in (("exit_code", (None, True, "0", -1, 2, 64, 70)),
                                  ("elapsed_ns", (None, True, -1, "0")),
                                  ("stdout_bytes", (None, True, 0, CONSUMER.STDOUT_LIMITS[child] + 1)),
                                  ("stderr_bytes", (None, True, -1, (16 << 10) + 1))):
                for value in values:
                    changed = report()
                    changed[child][field] = value
                    self.assertEqual(consume(changed)[0], 2, (child, field, value))
            changed = report()
            changed[child]["PRIVATE_EXTRA"] = 0
            self.assertEqual(consume(changed)[0], 2)

    def test_outer_failure_cannot_be_replaced_by_successful_diagnostic(self):
        class NoRead:
            def read(self, _):
                raise AssertionError("failed producer output was read")
        for actual in ("-1", "2", "64", "70"):
            code, raw, _ = consume(report(), actual=actual, reader=NoRead())
            self.assertEqual(code, 2)
            self.assertEqual(json.loads(raw)["category"], "process_failure")

    def test_duplicate_aliased_nonfinite_and_partial_documents_refused(self):
        raw = json.dumps(report(), separators=(",", ":")).encode()
        for changed in (raw.replace(b'"schema_version":3', b'"schema_version":3,"schema_version":3', 1),
                        raw.replace(b'"schema_version":3', b'"schema_version":3,"schema_vers\\u0069on":3', 1),
                        raw.replace(b'"watch":', b'"Watch":', 1),
                        raw.replace(b'"elapsed_ns":0', b'"elapsed_ns":NaN', 1),
                        raw.replace(b'"exit_code":0', b'"exit_code":0.0', 1),
                        raw[:-1], raw + b'{}', b'\xef\xbb\xbf' + raw, b'PRIVATE'):
            self.assertEqual(consume(changed)[0], 2)

    def test_schema_count_and_status_must_match_exactly(self):
        for field, values in (("schema_version", (1, 2, True, "3")),
                              ("checked_targets", (0, 2, True, "1")),
                              ("status", (None, "ACCEPT", "not_matched")),
                              ("category", ("PRIVATE", False))):
            for value in values:
                changed = report()
                changed[field] = value
                self.assertEqual(consume(changed)[0], 2, (field, value))

    def test_selection_cannot_silently_enable_or_repeat_advancing_mode(self):
        args = ["--mode", "advancing", "--observer-exit-code", "0", "--expected-targets", "1"]
        self.assertEqual(CONSUMER.selections(args), ("advancing", 0, 1))
        for changed in (args + ["--mode", "advancing"], args + ["--mode=collected"],
                        ["--mode", "advance", *args[2:]], ["--mode", "", *args[2:]]):
            with self.assertRaises(CONSUMER.Invalid):
                CONSUMER.selections(changed)

    def test_complete_stdin_bound_still_applies(self):
        code, raw, _ = consume(b" " * (CONSUMER.REPORT_BYTES + 1))
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(raw)["category"], "invalid_report")


if __name__ == "__main__":
    unittest.main()
