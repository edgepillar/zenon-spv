#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Orchestration controls use tiny in-memory graphs, not the long SMT replay."""

import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("retention_joint_driver_controls", HERE / "run_default_retention_checks.py")
D = importlib.util.module_from_spec(spec)
spec.loader.exec_module(D)


def encoded(value):
    return (json.dumps(value, sort_keys=True) + "\n").encode()


class Cache:
    def __init__(self, graph):
        self.graph, self.ready, self.hits, self.misses = graph, False, 0, 0

    def cache_info(self):
        return SimpleNamespace(hits=self.hits, misses=self.misses, maxsize=1, currsize=int(self.ready))

    def __call__(self, _):
        if self.ready:
            self.hits += 1
        else:
            self.ready = True
            self.misses += 1
        return self.graph


class Fixture:
    def __init__(self):
        self.raw = b"owned unit corpus"
        self.graph = {"history": {"height": 32768}, "marker": "sealed"}
        self.document = {"presealed_expectations_without_history": {"marker": "admitted"}}
        self.cache = Cache(self.graph)
        self.count, self.loader_errors, self.warm = 27, [], True
        self.main_calls, self.args, self.after = 0, None, None
        self.returned, self.extra_model, self.test_stdout = None, False, ""
        self.result = SimpleNamespace(
            testsRun=27, shouldStop=False, failures=[], errors=[], skipped=[],
            expectedFailures=[], unexpectedSuccesses=[], wasSuccessful=lambda: True)
        self.report = {
            "kind": "recorded-source-default-retention-background-check", "consumer_result": "REFUSED",
            "corpus_sha256": hashlib.sha256(self.raw).hexdigest(),
            **{field: False for field in D.FALSE_FIELDS},
        }
        self.reader = SimpleNamespace(
            expected_from_presealed_witnesses=self.cache,
            read_corpus=lambda _: (self.raw, self.document),
            M=SimpleNamespace(encoded=encoded),
            BASE_SHA256=hashlib.sha256(encoded(self.document["presealed_expectations_without_history"])).hexdigest(),
            EXPECTED_SHA256=hashlib.sha256(encoded(self.graph)).hexdigest(), main=self.main,
        )
        self.module = SimpleNamespace(C=self.reader)
        self.runner = SimpleNamespace(run=self.run)

    def run(self, _):
        if self.warm:
            self.cache(b"admitted")
        if self.test_stdout:
            print(self.test_stdout)
        return self.result

    def main(self, args):
        self.main_calls += 1
        self.args = args
        if self.extra_model:
            self.cache.ready = False
        self.cache(b"admitted")
        report = dict(self.report)
        if args:
            report["source_revision"] = args[1]
        print(json.dumps(report, sort_keys=True))
        if self.after:
            self.after()
        return self.returned

    @contextlib.contextmanager
    def patched(self):
        loader = SimpleNamespace(
            errors=self.loader_errors,
            loadTestsFromModule=lambda _: SimpleNamespace(countTestCases=lambda: self.count))
        pin = (1024, hashlib.sha256(b"owned unit corpus").hexdigest())
        with mock.patch.object(D.unittest, "TestLoader", return_value=loader), \
                mock.patch.dict(D.PINS, {"testdata/candidate-default-retention.json": pin}):
            yield self

    def execute(self, revision=None):
        with self.patched():
            return D.execute(self.module, revision, self.runner)


class RetentionJointDriverControls(unittest.TestCase):
    def test_original_sources_and_complete_suite_are_pinned_and_cold(self):
        raw = D.pinned_sources()
        self.assertEqual(set(raw), set(D.PINS))
        module = D.load_controls()
        suite = unittest.TestLoader().loadTestsFromModule(module)
        self.assertEqual(suite.countTestCases(), 27)
        self.assertEqual(module.C.expected_from_presealed_witnesses.cache_info().currsize, 0)

    def test_success_preserves_comparison_and_reuses_exact_cache(self):
        f = Fixture()
        text, receipt = f.execute("ab" * 20)
        self.assertEqual(json.loads(text), {**f.report, "source_revision": "ab" * 20})
        self.assertEqual(f.args, ["--source-revision", "ab" * 20])
        self.assertEqual((f.cache.misses, f.cache.hits), (1, 2))
        self.assertEqual((receipt["original_tests_run"], receipt["comparison_cache_misses"]), (27, 0))
        self.assertEqual(receipt["cached_graph_sha256"], f.reader.EXPECTED_SHA256)
        self.assertFalse(receipt["comparison_added_history_derivation"])
        self.assertEqual(receipt["consumer_result"], "REFUSED")

    def test_no_revision_preserves_the_original_output_shape(self):
        f = Fixture()
        text, receipt = f.execute()
        self.assertNotIn("source_revision", json.loads(text))
        self.assertIsNone(receipt["source_revision"])
        self.assertEqual(f.args, [])

    def test_partial_or_expanded_control_selection_refuses(self):
        for count in (0, 26, 28):
            with self.subTest(count=count):
                f = Fixture()
                f.count = count
                with self.assertRaises(ValueError):
                    f.execute()
                self.assertEqual(f.main_calls, 0)

    def test_loader_errors_refuse(self):
        f = Fixture()
        f.loader_errors.append("incomplete discovery")
        with self.assertRaises(ValueError):
            f.execute()
        self.assertEqual(f.main_calls, 0)

    def test_preexisting_cache_is_not_a_fresh_qualification(self):
        f = Fixture()
        f.cache(b"earlier invocation")
        with self.assertRaises(ValueError):
            f.execute()
        self.assertEqual(f.main_calls, 0)

    def test_failure_skip_expected_failure_and_stop_do_not_publish_comparison(self):
        mutations = [
            ("testsRun", 26), ("testsRun", True), ("shouldStop", True),
            ("failures", ["failed"]), ("errors", ["error"]), ("skipped", ["skipped"]),
            ("expectedFailures", ["expected failure"]), ("unexpectedSuccesses", ["unexpected"]),
            ("wasSuccessful", lambda: False),
        ]
        for field, value in mutations:
            with self.subTest(field=field):
                f = Fixture()
                setattr(f.result, field, value)
                with self.assertRaises(ValueError):
                    f.execute()
                self.assertEqual(f.main_calls, 0)

    def test_control_stdout_is_not_a_comparison_report(self):
        f = Fixture()
        f.test_stdout = "unexpected record"
        with self.assertRaises(ValueError):
            f.execute()
        self.assertEqual(f.main_calls, 0)

    def test_missing_admitted_graph_refuses(self):
        f = Fixture()
        f.warm = False
        with self.assertRaises(ValueError):
            f.execute()
        self.assertEqual(f.main_calls, 0)

    def test_corpus_and_admitted_byte_identity_are_rechecked(self):
        for mutation in ("corpus", "base"):
            with self.subTest(mutation=mutation):
                f = Fixture()
                if mutation == "corpus":
                    f.raw += b"changed"
                else:
                    f.reader.BASE_SHA256 = "0" * 64
                with self.assertRaises(ValueError):
                    f.execute()
                self.assertEqual(f.main_calls, 0)

    def test_changed_cached_graph_refuses_before_comparison(self):
        f = Fixture()
        f.graph["marker"] = "changed"
        with self.assertRaises(ValueError):
            f.execute()
        self.assertEqual(f.main_calls, 0)

    def test_comparison_cannot_add_another_model_derivation(self):
        f = Fixture()
        f.extra_model = True
        output = io.StringIO()
        with contextlib.redirect_stdout(output), self.assertRaises(ValueError):
            f.execute()
        self.assertEqual(output.getvalue(), "")

    def test_graph_integrity_is_rechecked_after_comparison(self):
        f = Fixture()
        f.after = lambda: f.graph.update(marker="changed after comparison")
        output = io.StringIO()
        with contextlib.redirect_stdout(output), self.assertRaises(ValueError):
            f.execute()
        self.assertEqual(output.getvalue(), "")

    def test_non_none_comparison_return_refuses(self):
        for value in (0, 1, False):
            with self.subTest(value=value):
                f = Fixture()
                f.returned = value
                with self.assertRaises(ValueError):
                    f.execute()

    def test_comparison_cannot_upgrade_authority_or_change_corpus(self):
        for field, value in (
                ("kind", "other"), ("consumer_result", "ACCEPT"), ("corpus_sha256", "0" * 64),
                *[(field, True) for field in D.FALSE_FIELDS]):
            with self.subTest(field=field):
                f = Fixture()
                f.report[field] = value
                with self.assertRaises(ValueError):
                    f.execute()

    def test_pinned_source_change_refuses_without_original_file_mutation(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get("SPV_TASK_SCRATCH")) as temporary:
            root = Path(temporary)
            raw = b"owned pin fixture"
            path = root / "source.py"
            path.write_bytes(raw)
            pins = {"source.py": (64, hashlib.sha256(raw).hexdigest())}
            with mock.patch.object(D, "HERE", root), mock.patch.object(D, "PINS", pins):
                self.assertEqual(D.pinned_sources(), {"source.py": raw})
                path.write_bytes(raw + b"changed")
                with self.assertRaises(ValueError):
                    D.pinned_sources()

    def test_post_comparison_source_check_holds_stdout(self):
        f = Fixture()
        output, error = io.StringIO(), io.StringIO()
        with f.patched(), mock.patch.object(D, "load_controls", return_value=f.module), \
                mock.patch.object(D, "pinned_sources", side_effect=ValueError("DO_NOT_ECHO")), \
                mock.patch.object(D.unittest, "TextTestRunner", return_value=f.runner), \
                contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
            self.assertEqual(D.main([]), 1)
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(error.getvalue(), D.REFUSAL + "\n")

    def test_main_success_emits_one_original_report_and_a_separate_receipt(self):
        f = Fixture()
        output, error = io.StringIO(), io.StringIO()
        with f.patched(), mock.patch.object(D, "load_controls", return_value=f.module), \
                mock.patch.object(D, "pinned_sources", return_value={}), \
                mock.patch.object(D.unittest, "TextTestRunner", return_value=f.runner), \
                contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
            self.assertEqual(D.main([]), 0)
        self.assertEqual(json.loads(output.getvalue()), f.report)
        self.assertEqual(error.getvalue().count("recorded-retention-joint "), 1)

    def test_actual_usage_processes_do_not_load_or_replay_the_model(self):
        script = HERE / "run_default_retention_checks.py"
        for args, status in ((["--source-revision", "main"], 2), (["--unknown"], 2), (["--help"], 0)):
            with self.subTest(args=args):
                result = subprocess.run(
                    [sys.executable, "-I", "-B", str(script), *args],
                    capture_output=True, timeout=20)
                self.assertEqual(result.returncode, status)
                self.assertNotIn(b"recorded-retention-joint ", result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
