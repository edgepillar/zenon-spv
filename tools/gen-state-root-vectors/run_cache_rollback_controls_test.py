#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Explicit complete-suite discovery, source pin and terminal-result controls."""
import argparse
import contextlib
import hashlib
import importlib.util
import io
from pathlib import Path
import tempfile
from types import ModuleType, SimpleNamespace
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("cache_controls_driver", HERE / "run_cache_rollback_controls.py")
C = importlib.util.module_from_spec(spec)
spec.loader.exec_module(C)


def fake_program(names=C.METHODS):
    value = ModuleType("complete_cache_rollback_controls")
    methods = {name: lambda self: None for name in names}
    methods["__module__"] = value.__name__
    value.CacheIdentifierRecordingTests = type("CacheIdentifierRecordingTests", (unittest.TestCase,), methods)
    return value


def result(count=18, success=True, **changes):
    value = {"testsRun": count, "wasSuccessful": lambda: success,
             "skipped": [], "expectedFailures": [], "unexpectedSuccesses": []}
    value.update(changes)
    return SimpleNamespace(**value)


class CompleteSuiteDriverControls(unittest.TestCase):
    def test_complete_literal_inventory_loads_all_eighteen_original_names(self):
        suite, identities = C.complete_suite(fake_program())
        self.assertEqual(suite.countTestCases(), 18)
        self.assertEqual(identities, ["CacheIdentifierRecordingTests." + name for name in C.METHODS])

    def test_zero_discovered_tests_cannot_be_a_successful_profile_or_run(self):
        with self.assertRaises(ValueError):
            C.complete_suite(ModuleType("empty"))
        with mock.patch.object(C.unittest, "TextTestRunner") as runner:
            runner.return_value.run.return_value = result(count=0)
            with self.assertRaises(ValueError):
                C.run_suite(unittest.TestSuite())

    def test_missing_or_extra_control_is_refused_before_execution(self):
        for names in (C.METHODS[:-1], C.METHODS + ("test_unselected",)):
            with self.subTest(names=names), self.assertRaises(ValueError):
                C.complete_suite(fake_program(names))

    def test_duplicate_control_identities_are_refused(self):
        value = fake_program()
        suite, _ = C.complete_suite(value)
        duplicate = unittest.TestSuite(list(suite) + list(suite))
        with mock.patch.object(C.unittest.defaultTestLoader, "loadTestsFromModule", return_value=duplicate), \
                self.assertRaises(ValueError):
            C.complete_suite(value)

    def test_failed_skipped_expected_or_unexpected_success_is_not_complete(self):
        values = [result(count=17), result(success=False), result(skipped=[("case", "reason")]),
                  result(expectedFailures=[("case", "failure")]), result(unexpectedSuccesses=["case"])]
        for value in values:
            with self.subTest(result=value), mock.patch.object(C.unittest, "TextTestRunner") as runner:
                runner.return_value.run.return_value = value
                with self.assertRaises(ValueError):
                    C.run_suite(unittest.TestSuite())

    def test_exact_terminal_result_is_required_without_skips(self):
        value = result()
        with mock.patch.object(C.unittest, "TextTestRunner") as runner:
            runner.return_value.run.return_value = value
            self.assertIs(C.run_suite(unittest.TestSuite()), value)

    def test_known_helper_source_matches_its_explicit_pin(self):
        self.assertEqual(hashlib.sha256(C.source_bytes(C.HELPER)).hexdigest(), C.HELPER_SHA256)
        helper = C.pinned_helper()
        self.assertEqual(helper.PROGRAM, C.PROGRAM)
        self.assertEqual(helper.verify_sources()[C.PROGRAM], "4e40153dc28746afabfac3f5bae16c58781ed9a4d3745b4d4399b6d007faa996")

    def test_changed_helper_pin_refuses_before_import(self):
        with mock.patch.object(C, "HELPER_SHA256", "0" * 64), self.assertRaises(ValueError):
            C.pinned_helper()

    def test_empty_and_oversize_source_is_bounded_and_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "source.py"
            for raw in (b"", b"x" * ((1 << 20) + 1)):
                path.write_bytes(raw)
                with self.assertRaises(ValueError):
                    C.source_bytes(path)

    def test_a_link_is_refused_before_opening_its_target(self):
        path = mock.Mock(spec=Path)
        path.is_file.return_value = True
        path.is_symlink.return_value = True
        path.open.side_effect = AssertionError("unselected target opened")
        with self.assertRaises(ValueError):
            C.source_bytes(path)
        path.open.assert_not_called()

    def test_source_revision_has_exact_type_width_and_case(self):
        self.assertEqual(C.revision("a" * 40), "a" * 40)
        for value in ("main", "a" * 39, "A" * 40, "0x" + "a" * 40, None, True):
            with self.subTest(value=value), self.assertRaises(argparse.ArgumentTypeError):
                C.revision(value)

    def test_unselected_mode_or_missing_revision_refuses_before_loading_program(self):
        for argv in (["--mode", "other", "--source-revision", "a" * 40], ["--mode", "bounded"]):
            with self.subTest(argv=argv), mock.patch.object(C, "pinned_helper", side_effect=AssertionError("unexpected load")), \
                    contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                C.main(argv)


if __name__ == "__main__":
    unittest.main()
