#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Recorded rollback evidence controls; no reference backend is executed."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
import unittest

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("rollback_target_recorded_controls", HERE / "check_momentum_rollback_target.py")
C = importlib.util.module_from_spec(spec)
spec.loader.exec_module(C)


class MomentumRollbackTargetRecordedTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = C.P.read_regular(HERE / "testdata" / C.CORPUS, C.MAX_BYTES)
        cls.corpus = C.document(cls.raw)

    def case(self, variant="candidate"):
        return copy.deepcopy(self.corpus["cases"][0 if variant == "parent" else 1])

    def changed_case(self, change, variant="candidate"):
        row = self.case(variant)
        events = [C.document(line.encode()) for line in row["stdout_utf8"].splitlines()]
        change(events)
        row["stdout_utf8"] = "".join(json.dumps(event, sort_keys=True) + "\n" for event in events)
        raw = row["stdout_utf8"].encode()
        row["command"]["stdout"] = {"bytes": len(raw), "sha256": C.P.sha(raw)}
        with self.assertRaises((ValueError, KeyError, TypeError)):
            C.check_case(row, variant)

    def test_pinned_recording_checks_without_node_execution(self):
        report = C.check_file(HERE / "testdata" / C.CORPUS)
        self.assertEqual(report["recorded_events"], 26)
        self.assertEqual(report["recorded_parent_API_panics"], 4)
        self.assertEqual(report["recorded_candidate_API_panics"], 0)
        self.assertEqual(report["recorded_native_unit_pass_results"], 11)
        self.assertEqual(report["recorded_native_skips"], 0)
        self.assertEqual(report["reference_processes_executed_by_this_check"], 0)
        self.assertEqual(report["consumer_result"], "REFUSED")

    def test_small_frame_preserves_empty_value_without_deleted_row(self):
        model = C.presence_image()
        self.assertEqual((model["records"], model["key_bytes"], model["value_bytes"]), (1, 1, 0))
        self.assertNotEqual(model["sha256"], C.P.sha(b""))
        self.assertEqual(model["sha256"], C.P.sha(bytes.fromhex("0000000000000001110000000000000000")))

    def test_second_momentum_hash_is_independently_derived(self):
        second = C.R.second_momentum()
        self.assertEqual(second["hash"], "fbe4d2002715d5993894e36fe23eefab052ffe697861465b1be8c07d786beed0")
        self.assertEqual(second["previousHash"], C.R.identifiers()["A1"]["hash"])
        self.assertIsNone(second["publicKey"])
        self.assertIsNone(second["signature"])
        self.assertEqual(second["stateRoot"], C.R.ZERO)

    def test_process_exit_zero_does_not_hide_parent_api_panics(self):
        row = self.case("parent")
        self.assertEqual(row["command"]["actual_exit"], 0)
        self.assertEqual(C.check_case(row, "parent")["recovered_API_panics"], 4)
        self.changed_case(lambda events: events[5]["result"].update(panic=False), "parent")

    def test_changed_missing_target_result_or_panic_text_refuses(self):
        for change, variant in ((lambda e: e[5]["result"].update(error_class="none"), "candidate"),
                                (lambda e: e[5]["result"].update(panic_text="other"), "parent"),
                                (lambda e: e[11]["result"].update(error_class="none"), "candidate")):
            self.changed_case(change, variant)

    def test_missing_duplicate_extra_or_reordered_event_refuses(self):
        for change in (lambda e: e.pop(), lambda e: e.append(e[-1]),
                       lambda e: e.__setitem__(6, e[5]), lambda e: e.reverse()):
            self.changed_case(change)

    def test_changed_logical_image_identifier_or_counter_type_refuses(self):
        for change in (lambda e: e[5]["after"].update(sha256="0" * 64),
                       lambda e: e[5]["before"]["identifier"].update(height=1),
                       lambda e: e[5].update(insert_callbacks=True),
                       lambda e: e[5]["after"].update(records=True)):
            self.changed_case(change)

    def test_wrong_hash_and_maximum_height_are_exact(self):
        for change in (lambda e: e[7]["target"].update(height=(1 << 64) - 2),
                       lambda e: e[8]["target"].update(hash=C.R.identifiers()["A2"]["hash"])):
            self.changed_case(change)

    def test_valid_rollback_callbacks_and_reopen_must_match(self):
        for change in (lambda e: e[10].update(deleted_identifiers=[]),
                       lambda e: e[10].update(insert_callbacks=1),
                       lambda e: e[12].update(removed_height_absent=False),
                       lambda e: e[12]["image"].update(sha256="0" * 64)):
            self.changed_case(change)

    def test_logical_presence_semantics_cannot_be_weakened(self):
        for change in (lambda e: e[0].update(present_empty_retained=False),
                       lambda e: e[0].update(nil_deletion_marker_omitted=False),
                       lambda e: e[0]["image"].update(value_bytes=1)):
            self.changed_case(change)

    def test_native_command_failure_incompleteness_or_digest_substitution_refuses(self):
        for key, value in (("actual_exit", 1), ("actual_exit", False), ("output_complete", False),
                           ("state", "UNKNOWN"), ("reason", "timeout")):
            row = self.case()
            row["command"][key] = value
            with self.assertRaises(ValueError):
                C.check_case(row, "candidate")
        row = self.case()
        row["command"]["stdout"]["sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            C.check_case(row, "candidate")

    def test_unit_missing_extra_failed_or_skipped_names_refuse(self):
        for change in (lambda u: u["test_pass_names"].pop(),
                       lambda u: u["test_pass_names"].append("unexecuted"),
                       lambda u: u["explicit_skips"].append(C.H.ROOTS[0]),
                       lambda u: u["failed_tests"].append(C.H.ROOTS[0]),
                       lambda u: u.update(build_tree=C.H.BUILD_TREE),
                       lambda u: u.update(race_detector=True)):
            unit = copy.deepcopy(self.corpus["unit_run"])
            change(unit)
            with self.assertRaises(ValueError):
                C.check_units(unit)

    def test_scope_and_state_acceptance_inflation_refuse(self):
        for key, value in C.SCOPE.items():
            corpus = copy.deepcopy(self.corpus)
            corpus["scope"][key] = not value
            with self.assertRaises(ValueError):
                C.check_corpus(corpus)
        corpus = copy.deepcopy(self.corpus)
        corpus["consumer_result"] = "ACCEPTED"
        with self.assertRaises(ValueError):
            C.check_corpus(corpus)

    def test_changed_source_tree_or_execution_metadata_refuses(self):
        for section, key, value in (("source", "candidate_unit_build_tree", C.H.BUILD_TREE),
                                    ("execution", "new_archive_downloads", 1),
                                    ("execution", "reference_platform", "linux/amd64")):
            corpus = copy.deepcopy(self.corpus)
            corpus[section][key] = value
            with self.assertRaises(ValueError):
                C.check_corpus(corpus)

    def test_original_observer_failure_is_not_relabelled(self):
        failure = self.corpus["execution"]["initial_observer_attempt"]
        self.assertEqual(failure["outcome"], "FAILURE")
        self.assertEqual(failure["command"]["actual_exit"], 2)
        self.assertEqual(failure["observed_missing_target_API_panics"], 3)
        self.assertIs(failure["candidate_executed"], False)
        self.assertIs(failure["old_task_relabelled"], False)
        self.assertIs(failure["valid_rollback_post_image_emitted"], False)

    def test_duplicate_keys_nonfinite_and_oversized_documents_refuse(self):
        for raw in (b'{"a":1,"a":2}', b'{"x":NaN}', b'{"x":Infinity}', b" " * (C.MAX_BYTES + 1)):
            with self.assertRaises(ValueError):
                C.document(raw)


if __name__ == "__main__":
    unittest.main()
