#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Record-byte, failure-semantics and scope controls; no backend execution."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("cache_read_record_controls", HERE / "check_cache_read_errors.py")
C = importlib.util.module_from_spec(spec)
spec.loader.exec_module(C)
M = C.M

def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()

class CacheReadModelControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = C.PREP.selected_fixture()
        cls.document = json.loads((HERE / "testdata" / C.CORPUS).read_bytes())
        cls.first, cls.reopen = [row["jsonl"].encode() for row in cls.document["variants"]["candidate"]["streams"]]

    def refused(self, first=None, reopen=None, fixture=None, variant="candidate"):
        with self.assertRaises((ValueError, TypeError, KeyError)):
            M.check(self.first if first is None else first, self.reopen if reopen is None else reopen,
                    self.fixture if fixture is None else fixture, variant)

    def changed(self, change):
        rows = [json.loads(line) for line in self.first.splitlines()]
        change(rows)
        return b"".join(encoded(row) for row in rows)

    def query(self, rows, checkpoint, method="plasma"):
        return next(row for row in rows if row["stage"] == "query" and
                    row["checkpoint"] == checkpoint and row["method"] == method)

    def test_both_exact_variants_retain_all_events_and_queries(self):
        for variant in C.PREP.VARIANTS:
            first, reopen = [row["jsonl"].encode() for row in self.document["variants"][variant]["streams"]]
            report = M.check(first, reopen, self.fixture, variant)
            self.assertEqual((report["event_count"], report["query_count"]), (29, 19))
            self.assertEqual(report["observed_error_propagation_mismatches"], 6 if variant == "baseline" else 0)
            self.assertFalse(report["backend_executed"])

    def test_complete_raw_image_is_computed_from_selected_inputs(self):
        image = M.expected_image(json.loads(self.fixture))
        self.assertEqual(image["records"], 4)
        self.assertEqual(image["sha256"], "7b6cfee7dd05b8cd1192f13458e4871b47a07e851394537c52de5609bc85050f")

    def test_wrong_variant_cannot_select_its_own_outcome(self):
        self.refused(variant="baseline")
        for variant in (None, True, 1, "other"):
            with self.subTest(variant=repr(variant)):
                self.refused(variant=variant)

    def test_closed_error_cannot_be_promoted_to_zero(self):
        self.refused(first=self.changed(lambda rows: self.query(rows, "closed").update(integer="0")))

    def test_genuine_empty_result_keeps_normal_absence(self):
        self.refused(first=self.changed(lambda rows: self.query(rows, "empty").update(error="leveldb-closed")))

    def test_populated_values_are_independently_selected(self):
        self.refused(first=self.changed(lambda rows: self.query(rows, "populated").update(integer="18")))

    def test_missing_event_refused(self):
        self.refused(first=self.changed(lambda rows: rows.pop()))

    def test_extra_event_refused(self):
        self.refused(first=self.first + self.first.splitlines(keepends=True)[0])

    def test_reordered_events_refused(self):
        def swap(rows):
            rows[1], rows[2] = rows[2], rows[1]
        self.refused(first=self.changed(swap))

    def test_extraction_patch_bytes_bound(self):
        def change(rows):
            next(row for row in rows if row["stage"] == "extracted")["cache_patch_dump"] = "00"
        self.refused(first=self.changed(change))

    def test_complete_raw_key_and_value_records_bound(self):
        def change(rows):
            next(row for row in rows if row["stage"] == "closed-store")["rows"][0]["value"] = "00"
        self.refused(first=self.changed(change))

    def test_raw_image_digest_bound(self):
        def change(rows):
            next(row for row in rows if row["stage"] == "closed-store")["sha256"] = "00" * 32
        self.refused(first=self.changed(change))

    def test_actual_direct_iterator_error_required(self):
        def change(rows):
            next(row for row in rows if row["stage"] == "closed-iterator")["error"] = "none"
        self.refused(first=self.changed(change))

    def test_exact_boolean_types_required(self):
        self.refused(first=self.changed(lambda rows: rows[0].update(public_Chain_selected=0)))

    def test_no_ordinary_execution_scope_promotion(self):
        self.refused(first=self.changed(lambda rows: rows[0].update(public_Chain_selected=True)))

    def test_unknown_fields_refused(self):
        self.refused(first=self.changed(lambda rows: rows[0].update(extra=False)))

    def test_duplicate_JSON_keys_refused(self):
        raw = self.first.replace(b'"cache_manager_selected":true',
            b'"cache_manager_selected":true,"cache_manager_selected":true', 1)
        self.assertNotEqual(raw, self.first)
        self.refused(first=raw)

    def test_incomplete_stream_refused(self):
        self.refused(first=self.first[:-1])

    def test_oversized_stream_refused(self):
        self.refused(first=self.first + b"x" * (M.MAX_STREAM + 1))

    def test_fixture_source_and_authority_bound(self):
        raw = self.fixture.replace(b'"state_value_accepted": false', b'"state_value_accepted": true')
        self.assertNotEqual(raw, self.fixture)
        self.refused(fixture=raw)

class CacheReadRecordedControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.document = json.loads((HERE / "testdata" / C.CORPUS).read_bytes())

    def bad(self, change):
        selected = copy.deepcopy(self.document)
        change(selected)
        with self.assertRaises((ValueError, TypeError, KeyError)):
            C.check_corpus(selected)

    def test_complete_recorded_comparison_and_closed_consumer(self):
        result = C.check_file()
        self.assertEqual((result["event_count"], result["query_count"]), (58, 38))
        self.assertEqual((result["baseline_error_mismatches"], result["candidate_error_mismatches"]), (6, 0))
        self.assertEqual((result["recorded_unit_root_count"], result["recorded_unit_pass_results"]), (41, 50))
        self.assertEqual(result["consumer_result"], "REFUSED")
        self.assertFalse(result["backend_reexecuted"])
        self.assertFalse(result["production_state_value_accepted"])

    def test_full_build_source_trees_and_counts_bound(self):
        for field in ("parent_build_tree", "candidate_runtime_tree", "candidate_build_tree"):
            with self.subTest(field=field):
                self.bad(lambda value: value["source"].update({field: "00" * 20}))
        self.bad(lambda value: value["source"].update(candidate_source_files=471))

    def test_probe_unit_model_and_fixture_pins_bound(self):
        for field in ("probe", "unit_source", "independent_model", "fixture"):
            with self.subTest(field=field):
                self.bad(lambda value: value["source"][field].update(sha256="00" * 32))

    def test_actual_native_unit_inventory_cannot_be_filtered(self):
        self.bad(lambda value: value["recorded_native"]["native_unit_passes"].pop())
        self.bad(lambda value: value["recorded_native"].update(native_unit_root_count=40))
        self.bad(lambda value: value["recorded_native"].update(native_unit_pass_results=True))

    def test_ordinary_probe_and_separate_unit_execution_scopes_bound(self):
        self.bad(lambda value: value["recorded_native"].update(ordinary_probe_executes_cache_manager_and_extractor_only=False))
        self.bad(lambda value: value["recorded_native"].update(native_units_include_selected_public_chain_manager_regressions=False))

    def test_no_authentication_or_activation_scope_promotion(self):
        for field in self.document["scope"]:
            with self.subTest(field=field):
                self.bad(lambda value: value["scope"].update({field: True}))

    def test_binary_bytes_and_digests_bound(self):
        self.bad(lambda value: value["variants"]["baseline"]["binary"].update(sha256="00" * 32))
        self.bad(lambda value: value["variants"]["candidate"]["binary"].update(bytes=True))

    def test_missing_extra_or_reordered_streams_refused(self):
        self.bad(lambda value: value["variants"]["baseline"]["streams"].pop())
        self.bad(lambda value: value["variants"]["candidate"]["streams"].append(value["variants"]["candidate"]["streams"][0]))
        self.bad(lambda value: value["variants"]["candidate"]["streams"].reverse())

    def test_exact_stream_bytes_digest_and_length_bound(self):
        self.bad(lambda value: value["variants"]["baseline"]["streams"][0].update(jsonl="{}\n"))
        self.bad(lambda value: value["variants"]["baseline"]["streams"][0].update(sha256="00" * 32))
        self.bad(lambda value: value["variants"]["baseline"]["streams"][0].update(bytes=True))

    def test_variant_inventory_cannot_be_dropped_or_extended(self):
        self.bad(lambda value: value["variants"].pop("baseline"))
        self.bad(lambda value: value["variants"].update(extra={}))

    def test_native_platform_and_compiler_are_record_specific(self):
        self.bad(lambda value: value["recorded_native"].update(platform="linux/amd64"))
        self.bad(lambda value: value["recorded_native"].update(go_version="go1.25.15"))

    def test_unknown_top_level_and_source_fields_refused(self):
        self.bad(lambda value: value.update(extra=False))
        self.bad(lambda value: value["source"].update(extra=False))

    def test_actual_CLI_success_and_invalid_revision_refusal(self):
        command = [sys.executable, "-I", "-B", str(HERE / "check_cache_read_errors.py")]
        success = subprocess.run(command + ["--source-revision", "ab" * 20],
                                 capture_output=True, timeout=30)
        self.assertEqual(success.returncode, 0)
        self.assertEqual(success.stderr, b"")
        self.assertEqual(json.loads(success.stdout)["source_revision"], "ab" * 20)
        refused = subprocess.run(command + ["--source-revision", "invalid"],
                                 capture_output=True, timeout=30)
        self.assertEqual(refused.returncode, 1)
        self.assertEqual(refused.stdout, b"")
        self.assertEqual(refused.stderr.strip(),
            b"Recorded cache read error evidence refused; state values remain disabled.")

    def test_actual_CLI_rejects_changed_regular_corpus(self):
        selected = copy.deepcopy(self.document)
        selected["scope"]["production_qualified"] = True
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "changed.json"
            path.write_text(json.dumps(selected))
            result = subprocess.run([sys.executable, "-I", "-B", str(HERE / "check_cache_read_errors.py"),
                                     "--file", str(path)], capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, b"")

if __name__ == "__main__":
    unittest.main(verbosity=2)
