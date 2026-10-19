#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Portable adverse controls for the frozen recorded patch experiment."""
import contextlib
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
spec = importlib.util.spec_from_file_location("patch_corpus_controls", HERE / "check_cache_replay_patches.py")
H = importlib.util.module_from_spec(spec)
spec.loader.exec_module(H)


def rewrite(row, mutate):
    events = [H.document(line.encode()) for line in row["stdout_utf8"].splitlines()]
    mutate(events)
    raw = b"".join((json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n").encode() for event in events)
    row["stdout_utf8"] = raw.decode()
    row["command"]["stdout"] = {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


class RecordedCacheReplayPatchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = H.P.read_regular(HERE / "testdata" / H.CORPUS, H.MAX_BYTES)
        H.P.require(len(cls.raw) == H.CORPUS_BYTES and H.P.sha(cls.raw) == H.CORPUS_SHA256)
        cls.original = H.document(cls.raw)
        cls.source_pins = {name: H.P.sha(H.P.read_regular(HERE / name, 1 << 20)) for name in H.INPUTS}
        cls.real_source = H.expected_source
        cls.source_selection = H.expected_source()
        # Reuse only this test class's immutable source selection. The metadata
        # payload reader and every corpus observation check still execute.
        cls.source_cache = mock.patch.object(H, "expected_source", side_effect=lambda: copy.deepcopy(cls.source_selection))
        cls.source_cache.start()

    @classmethod
    def tearDownClass(cls):
        cls.source_cache.stop()
        if H.expected_source() != cls.source_selection:
            raise AssertionError("Source selection changed during recorded controls")
        after = {name: H.P.sha(H.P.read_regular(HERE / name, 1 << 20)) for name in H.INPUTS}
        if after != cls.source_pins:
            raise AssertionError("Source bytes changed during recorded controls")

    def changed(self):
        return copy.deepcopy(self.original)

    def refuse(self, value):
        with self.assertRaises((ValueError, TypeError, KeyError)):
            H.check_corpus(value)

    def test_complete_record_and_independent_models(self):
        result = H.check_file(HERE / "testdata" / H.CORPUS)
        self.assertEqual(result["recorded_cases"], 10)
        self.assertEqual(result["recorded_event_observations"], 260)
        self.assertEqual(result["recorded_public_queries"], 36)
        self.assertEqual(result["recorded_parent_Init_panics"], 2)
        self.assertEqual(result["recorded_candidate_Init_panics"], 0)
        self.assertEqual(result["recorded_candidate_prewrite_refusals"], 2)
        self.assertEqual(result["independent_genesis_account_headers"], 14094)
        self.assertEqual(result["recorded_native_unit_pass_results"], 58)
        self.assertEqual(result["consumer_result"], "REFUSED")
        self.assertFalse(result["genesis_source_augmented_patch_digest_rehashed_by_this_check"])

    def test_source_and_probe_substitutions_refused(self):
        for key, replacement in (("candidate_runtime_tree", "0" * 40), ("parent_remaining_build_tree", "0" * 40),
                                 ("retained_positive_build_tree", "0" * 40), ("module_sha256", "0" * 64),
                                 ("candidate_probe", {"bytes": 1, "sha256": "0" * 64})):
            value = self.changed()
            value["source"][key] = replacement
            self.refuse(value)

    def test_scope_and_consumer_promotion_refused(self):
        for key in ("accepted_header_binding", "runtime_state_value_acceptance", "whole_window_IO_atomicity_claimed",
                    "network_activation_authenticated", "private_execution_receipts_authenticated",
                    "complete_augmented_genesis_patch_rehashed_by_public_reader"):
            value = self.changed()
            value["scope"][key] = True
            self.refuse(value)
        value = self.changed()
        value["consumer_result"] = "ACCEPTED"
        self.refuse(value)

    def test_execution_failures_and_count_inflation_preserved(self):
        for key, replacement in (("intended_case_processes", 11), ("retained_parent_ordinary_builds", 1),
                                 ("separate_failed_pre_Init_fixture_processes", 0), ("candidate_task_outcome", "FAILURE"),
                                 ("whole_module_graph_verification", "QUALIFIED"), ("parent_backend_reexecuted", True)):
            value = self.changed()
            value["execution"][key] = replacement
            self.refuse(value)
        value = self.changed()
        value["execution"]["prior_candidate_control_compile_failure"]["actual_exit"] = 0
        self.refuse(value)

    def test_case_order_and_completeness_refused(self):
        for mutate in (lambda rows: rows.pop(), lambda rows: rows.append(rows[-1]),
                       lambda rows: rows.reverse(), lambda rows: rows.__setitem__(0, rows[1])):
            value = self.changed()
            mutate(value["cases"])
            self.refuse(value)

    def test_case_build_and_binary_bindings_required(self):
        for key, replacement in (("build_tree", H.H.PARENT_BUILD_TREE),
                                 ("ordinary_binary", self.original["execution"]["retained_positive_binary"])):
            value = self.changed()
            value["cases"][5][key] = replacement
            self.refuse(value)

    def test_command_exit_completeness_and_reason_required(self):
        for key, replacement in (("actual_exit", 1), ("output_complete", False), ("reason", "INTERRUPTED_UNVERIFIED"),
                                 ("state", "RUNNING"), ("actual_exit", False)):
            value = self.changed()
            value["cases"][6]["command"][key] = replacement
            self.refuse(value)

    def test_stdout_digest_binding_required(self):
        value = self.changed()
        value["cases"][0]["command"]["stdout"]["sha256"] = "0" * 64
        self.refuse(value)

    def test_parent_panic_cannot_be_hidden(self):
        value = self.changed()
        def conceal(events):
            start = next(event for event in events if event["stage"] == "public-init-observed")
            start.update(panicked=False, panic_type="", panic_functions=None)
        rewrite(value["cases"][1], conceal)
        self.refuse(value)

    def test_candidate_panic_cannot_be_qualified(self):
        value = self.changed()
        def inject(events):
            start = next(event for event in events if event["stage"] == "public-init-observed")
            start.update(panicked=True, panic_type="synthetic panic",
                         panic_functions=["github.com/zenon-network/go-zenon/chain.(*chainCache).Init"])
        rewrite(value["cases"][6], inject)
        self.refuse(value)

    def test_missing_patch_error_category_is_exact(self):
        value = self.changed()
        rewrite(value["cases"][6], lambda events: next(event for event in events if event["stage"] == "public-init-observed").update(error="other"))
        self.refuse(value)

    def test_failed_startup_cannot_expose_a_query_result(self):
        for key, replacement in (("root", H.W.ROOT), ("root_error", "none"), ("value", H.W.VALUE)):
            value = self.changed()
            rewrite(value["cases"][6], lambda events: next(event for event in events if event["stage"] == "public-state-query").update({key: replacement}))
            self.refuse(value)

    def test_required_patch_refusal_preserves_the_complete_cache_image(self):
        value = self.changed()
        rewrite(value["cases"][6], lambda events: next(event for event in events if event["stage"] == "cache-after-public-stop").update(records=1))
        self.refuse(value)

    def test_explicit_restore_is_exact_and_not_runtime_repair(self):
        for stage, changes in (("ledger-after-explicit-fixture-restore", {"raw_store_sha256": "0" * 64}),
                               ("explicit-fixture-ledger-entry-restored", {"runtime_repair_selected": True})):
            value = self.changed()
            rewrite(value["cases"][6], lambda events: next(event for event in events if event["stage"] == stage).update(changes))
            self.refuse(value)

    def test_stop_withdraws_readiness(self):
        value = self.changed()
        rewrite(value["cases"][5], lambda events: next(event for event in events if event["stage"] == "public-stop-observed").update(ready=True))
        self.refuse(value)

    def test_all_candidate_final_images_cannot_drift_from_parent(self):
        value = self.changed()
        for row in value["cases"][5:]:
            def drift(events):
                for event in events:
                    if event["stage"] == "cache-after-public-stop" and not (row["case"] == H.H.CASES[1] and event["attempt"] < 2):
                        event["raw_store_sha256"] = "1" * 64
            rewrite(row, drift)
        self.refuse(value)

    def test_metadata_payload_binding_executes_without_modifying_the_fixture(self):
        original = H.P.read_regular
        def altered(path, limit):
            raw = original(path, limit)
            return raw[:-1] + bytes([raw[-1] ^ 1]) if Path(path).name == Path(H.GENESIS_METADATA).name else raw
        with mock.patch.object(H.P, "read_regular", side_effect=altered):
            self.refuse(self.changed())

    def test_metadata_report_cannot_replace_the_decoded_payload(self):
        value = self.changed()
        value["cases"][6]["metadata_report"]["metadata_sha256"] = "0" * 64
        self.refuse(value)

    def test_bounds_duplicate_names_and_missing_events_refused(self):
        for raw in (bytes(H.MAX_BYTES + 1), b'{"name":1,"name":2}', b'{"value":NaN}'):
            with self.assertRaises(ValueError):
                H.document(raw)
        value = self.changed()
        rewrite(value["cases"][0], lambda events: events.clear())
        self.refuse(value)

    def test_real_source_selection_and_checker_start_no_backend(self):
        with mock.patch.object(H, "expected_source", side_effect=type(self).real_source), \
             mock.patch.object(subprocess, "run", side_effect=AssertionError("A backend or compiler was started")), \
             mock.patch.object(subprocess, "Popen", side_effect=AssertionError("A child was started")):
            result = H.check_file(HERE / "testdata" / H.CORPUS)
        self.assertEqual(result["reference_processes_executed_by_this_check"], 0)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            H.main(["--source-revision", "a" * 40])
        self.assertEqual(json.loads(out.getvalue())["source_revision"], "a" * 40)


if __name__ == "__main__":
    unittest.main()
