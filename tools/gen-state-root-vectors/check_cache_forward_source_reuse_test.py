#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Check the lifetime and source guards of the serial recorded-test cache."""
import copy
import importlib.util
import itertools
from pathlib import Path
import socket
import subprocess
import sys
import unittest
from unittest import mock

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
TARGET = HERE / "check_cache_forward_replay_test.py"
SERIAL = itertools.count()


class SourceSelectionReuseBoundaryTests(unittest.TestCase):
    def setUp(self):
        name = "source_selection_reuse_subject_" + str(next(SERIAL))
        spec = importlib.util.spec_from_file_location(name, TARGET)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        self.addCleanup(sys.modules.pop, name, None)
        spec.loader.exec_module(module)
        self.module = module
        self.cls = module.CacheForwardRecordingTests
        self.C = module.C
        self.real = self.C.expected_source

    def start(self):
        self.cls.setUpClass()
        self.addCleanup(self.cls.doClassCleanups)

    def test_original_corpus_still_has_complete_positive_checks(self):
        self.start()
        result = self.C.check_file(HERE / "testdata" / self.C.CORPUS)
        self.assertEqual(result["recorded_cases"], 8)
        self.assertEqual(result["consumer_result"], "REFUSED")
        self.cls.tearDownClass()

    def test_cached_returns_and_nested_results_are_independent(self):
        self.start()
        wanted = copy.deepcopy(self.cls._selected_source)
        selected = self.C.expected_source()
        selected["revision"] = "0" * 40
        selected["native_controls"].clear()
        self.assertEqual(self.C.expected_source(), wanted)
        result = self.C.check_file(HERE / "testdata" / self.C.CORPUS)
        result["source"]["native_controls"].clear()
        self.assertEqual(self.C.expected_source(), wanted)
        self.cls.tearDownClass()

    def test_source_byte_drift_refuses_without_touching_files(self):
        self.start()
        read = self.C.P.read_regular
        selected = Path(self.C.__file__)

        def altered(path, limit):
            value = read(path, limit)
            return value + b"\n" if Path(path) == selected else value

        with mock.patch.object(self.C.P, "read_regular", side_effect=altered):
            with self.assertRaisesRegex(AssertionError, "Source input changed"):
                self.cls.tearDownClass()

    def test_fresh_selection_drift_refuses_with_unchanged_files(self):
        self.start()
        changed = copy.deepcopy(self.cls._selected_source)
        changed["revision"] = "0" * 40
        self.cls._uncached_expected_source = staticmethod(lambda: changed)
        with self.assertRaisesRegex(AssertionError, "Complete source selection changed"):
            self.cls.tearDownClass()

    def test_registered_cleanup_restores_builder_after_body_exception(self):
        self.start()
        try:
            raise RuntimeError("Selected diagnostic body failure")
        except RuntimeError:
            pass
        finally:
            self.cls.doClassCleanups()
        self.assertIs(self.C.expected_source, self.real)

    def test_no_backend_control_runs_the_real_builder(self):
        self.start()
        spy = mock.Mock(wraps=self.real)
        self.cls._uncached_expected_source = staticmethod(spy)
        self.cls("test_reader_cannot_launch_backend_or_network").test_reader_cannot_launch_backend_or_network()
        self.assertEqual(spy.call_count, 2)
        self.cls._uncached_expected_source = staticmethod(self.real)
        self.cls.tearDownClass()

    def test_cache_ends_with_class_and_reader_stays_fresh_outside(self):
        self.start()
        self.cls.tearDownClass()
        self.cls.doClassCleanups()
        self.assertIs(self.C.expected_source, self.real)
        with mock.patch.object(self.C, "expected_source", wraps=self.real) as spy:
            self.C.check_file(HERE / "testdata" / self.C.CORPUS)
        self.assertEqual(spy.call_count, 2)

    def test_failed_source_admission_does_not_install_cache(self):
        with mock.patch.object(self.C, "expected_source", side_effect=ValueError("Selected source refused")) as refused:
            with self.assertRaisesRegex(ValueError, "Selected source refused"):
                self.cls.setUpClass()
            self.assertIs(self.C.expected_source, refused)
        self.cls.doClassCleanups()
        self.assertIs(self.C.expected_source, self.real)


if __name__ == "__main__":
    with mock.patch.object(subprocess, "run", side_effect=AssertionError("No backend")), \
         mock.patch.object(subprocess, "Popen", side_effect=AssertionError("No backend")), \
         mock.patch.object(socket, "socket", side_effect=AssertionError("No network")):
        unittest.main()
