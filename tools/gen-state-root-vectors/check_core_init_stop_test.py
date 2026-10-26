#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Source and retained-observation controls; no node execution or download."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("core_init_stop_controls", HERE / "check_core_init_stop.py")
C = importlib.util.module_from_spec(spec)
spec.loader.exec_module(C)
P, M = C.P, C.M


class InitStopSourceControls(unittest.TestCase):
    def test_guard_preserves_the_existing_Start_and_Stop_bytes(self):
        patch = P.patch()
        for method in ("Start", "Stop"):
            marker = "func (z *zenon) " + method + "() error {"
            self.assertEqual(patch["before"].split(marker, 1)[1], patch["after"].split(marker, 1)[1])
        self.assertIn("if z.stopStarted && !z.stopComplete", patch["after"])
        self.assertEqual(patch["after"].count("z.stopMu.Lock()"), 2)

    def test_both_source_plans_bind_exact_runtime_and_build_trees(self):
        for variant, tree in (("baseline", P.PARENT_TREE), ("candidate", P.CANDIDATE_TREE)):
            with self.subTest(variant=variant):
                result = P.plan("NEW_OWNED_WORKSPACE", "PINNED_GO", variant)
                self.assertEqual(result["runtime_tree"], tree)
                self.assertEqual(result["source_blobs"], 484)
                self.assertEqual(result["build_tree"], P.P.UTIL.reconstruct_tree(P.build_pins(variant)))
                self.assertFalse(result["reference_backend_executed"])
                self.assertFalse(result["core_Start_selected"])
                self.assertFalse(result["production_state_value_accepted"])
                self.assertEqual(result["consumer_result"], "REFUSED")

    def test_only_one_runtime_file_changes_between_variants(self):
        base = P.selection("baseline")[2]
        candidate = P.selection("candidate")[2]
        self.assertEqual(set(base), set(candidate))
        self.assertEqual([name for name in base if base[name] != candidate[name]], ["zenon/zenon.go"])

    def test_all_source_extras_are_pinned_and_no_transport_is_requested(self):
        extras = P.extra_sources()
        self.assertEqual(len(extras), 13)
        for name, target, size, digest in P.EXTRAS:
            raw = extras[target]
            self.assertEqual(len(raw), size)
            self.assertEqual(hashlib.sha256(raw).hexdigest(), digest)
        result = P.plan("NEW_OWNED_WORKSPACE", "PINNED_GO")
        self.assertFalse(result["new_dependency_transports_permitted"])
        self.assertEqual(result["within_case_retries"], 0)

    def test_production_floor_and_finite_case_budgets_are_explicit(self):
        result = P.plan("NEW_OWNED_WORKSPACE", "PINNED_GO")
        self.assertEqual(result["minimum_free_floor_bytes"], 10 << 30)
        self.assertEqual(result["expected_allocation_bytes"], 2 << 30)
        self.assertEqual(result["suggested_task_quota_bytes"], 4 << 30)
        self.assertEqual(result["case_timeout_seconds"], 120)
        self.assertEqual(len(result["run_argv_templates"]), 2)

    def test_unknown_variant_or_go_value_refuses(self):
        for variant in (None, True, [], "parent", ""):
            with self.subTest(variant=variant), self.assertRaises((ValueError, TypeError)):
                P.selection(variant)
        for go in (None, True, [], "", "go\x00other"):
            with self.subTest(go=go), self.assertRaises((ValueError, TypeError)):
                P.plan("NEW_OWNED_WORKSPACE", go)

    def test_existing_workspace_is_never_adopted(self):
        with tempfile.TemporaryDirectory() as root:
            workspace = Path(root).resolve() / "existing"
            workspace.mkdir()
            marker = workspace / "keep"
            marker.write_bytes(b"existing input")
            with self.assertRaises((ValueError, OSError)):
                P.prepare(Path(root).resolve() / "source", workspace, "PINNED_GO")
            self.assertEqual(marker.read_bytes(), b"existing input")

    def test_source_overlap_refuses_before_creating_workspace(self):
        with tempfile.TemporaryDirectory() as root:
            source = Path(root).resolve() / "source"
            source.mkdir()
            workspace = source / "child"
            with self.assertRaises((ValueError, OSError)):
                P.prepare(source, workspace, "PINNED_GO")
            self.assertFalse(workspace.exists())

    def test_missing_source_does_not_create_destination(self):
        with tempfile.TemporaryDirectory() as root:
            workspace = Path(root).resolve() / "new"
            with self.assertRaises((ValueError, OSError)):
                P.prepare(Path(root).resolve() / "missing", workspace, "PINNED_GO")
            self.assertFalse(workspace.exists())

    def test_corrupt_source_refuses_before_any_staging(self):
        with tempfile.TemporaryDirectory() as root:
            source = Path(root).resolve() / "source"
            source.mkdir()
            (source / "go.mod").write_bytes(b"unexpected source")
            workspace = Path(root).resolve() / "new"
            with self.assertRaises((ValueError, OSError)):
                P.prepare(source, workspace, "PINNED_GO")
            self.assertFalse(workspace.exists())

    def test_verify_refuses_unknown_entries(self):
        with tempfile.TemporaryDirectory() as root:
            workspace = Path(root).resolve()
            (workspace / "node").mkdir()
            (workspace / "unexpected").write_bytes(b"preserve")
            with self.assertRaises((ValueError, OSError)):
                P.verify(workspace, "PINNED_GO")
            self.assertEqual((workspace / "unexpected").read_bytes(), b"preserve")

    def test_preparation_plans_do_not_execute_commands(self):
        with mock.patch.object(subprocess, "run", side_effect=AssertionError("unexpected execution")), \
                mock.patch.object(subprocess, "check_output", side_effect=AssertionError("unexpected execution")):
            for variant in P.VARIANTS:
                self.assertEqual(P.plan("NEW_OWNED_WORKSPACE", "PINNED_GO", variant)["source_blobs"], 484)


class InitStopObservationControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.document = json.loads((HERE / "testdata" / C.CORPUS).read_bytes())

    def altered(self, change):
        value = copy.deepcopy(self.document)
        change(value)
        raw = P.encoded(value)
        # Repair the outer recording pin only, to reach semantic checks.
        with mock.patch.object(C, "CORPUS_BYTES", len(raw)), mock.patch.object(
                C, "CORPUS_SHA256", hashlib.sha256(raw).hexdigest()), self.assertRaises((ValueError, TypeError, KeyError)):
            C.check_corpus(value)

    def model_bad(self, change, variant="candidate", case="incomplete-Stop"):
        row = next(row for row in self.document["streams"] if row["variant"] == variant and row["case"] == case)
        value = json.loads(row["jsonl"])
        change(value)
        raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        with self.assertRaises((ValueError, TypeError, KeyError)):
            C.observation(raw, variant, case)

    def test_complete_capture_preserves_ordinary_race_and_refusal_scope(self):
        report = C.check_file()
        self.assertEqual((report["ordinary_builds"], report["ordinary_processes"]), (2, 4))
        self.assertEqual((report["race_builds"], report["race_processes"]), (1, 2))
        self.assertEqual((report["focused_native_roots"], report["focused_native_passes"]), (5, 9))
        self.assertEqual(report["focused_native_skips"], 0)
        self.assertEqual(report["reader_reference_backend_executions"], 0)
        self.assertEqual(report["consumer_result"], "REFUSED")
        self.assertFalse(report["production_state_value_accepted"])
        self.assertFalse(report["scope"]["concurrent_Init_Start_Stop_qualified"])

    def test_every_stream_matches_the_independently_selected_contract(self):
        for row in self.document["streams"]:
            with self.subTest(variant=row["variant"], case=row["case"]):
                variant = "candidate" if row["variant"] == "race" else row["variant"]
                result = C.observation(row["jsonl"].encode(), variant, row["case"])
                self.assertFalse(result["observation"]["ready_after_teardown"])
                self.assertEqual(result["observation"]["consensus_after_teardown"], "closed")

    def test_parent_incomplete_Stop_still_records_successful_initialization(self):
        row = next(row for row in self.document["streams"] if row["variant"] == "baseline" and row["case"] == "incomplete-Stop")
        result = C.observation(row["jsonl"].encode(), "baseline", row["case"])
        self.assertTrue(result["observation"]["ready_after_Init"])
        self.assertEqual(result["observation"]["Init"]["error"], "none")

    def test_incomplete_Stop_cannot_be_relabelled_as_successful_admission(self):
        self.model_bad(lambda value: value["observation"]["Init"].update(error="none"))
        self.model_bad(lambda value: value["observation"].update(ready_after_Init=True))
        self.model_bad(lambda value: value["observation"]["Stop"].update(panic=""))

    def test_selected_ordinary_overlap_and_teardown_cannot_be_erased(self):
        self.model_bad(lambda value: value["observation"].update(Stop_completed_before_Init_release=True),
                       case="overlapping-Init-Stop")
        for name, wrong in (("ready_before_Stop", False), ("controlled_Init_scheduling", False),
                            ("consensus_after_teardown", "open"), ("ready_after_teardown", True)):
            with self.subTest(name=name):
                self.model_bad(lambda value: value["observation"].update({name: wrong}), case="overlapping-Init-Stop")

    def test_primitive_types_and_field_sets_are_exact(self):
        self.model_bad(lambda value: value["genesis"].update(height=True))
        self.model_bad(lambda value: value.update(core_Start_selected=0))
        self.model_bad(lambda value: value["observation"].update(ready_after_Init=0))
        self.model_bad(lambda value: value["observation"].update(extra=False))
        self.model_bad(lambda value: value["observation"].pop("explicit_teardown"))

    def test_state_acceptance_or_network_execution_cannot_be_promoted(self):
        for key in ("core_Start_selected", "network_or_wallet_or_signing_selected",
                    "accepted_header_binding", "production_state_value_accepted"):
            with self.subTest(key=key):
                self.model_bad(lambda value: value.update({key: True}))
        self.altered(lambda value: value["scope"].update(concurrent_Init_Start_Stop_qualified=True))
        self.altered(lambda value: value["scope"].update(independent_human_acceptance=True))

    def test_duplicate_truncated_or_nonfinite_wire_refuses(self):
        raw = self.document["streams"][0]["jsonl"].encode()
        bad = (raw[:-1], raw + raw, b"x" * (C.MAX_STREAM + 1), b"\xff\n", raw.decode(),
               raw.replace(b'"schema":', b'"schema":"duplicate","schema":', 1),
               raw.replace(b'"height":1', b'"height":NaN'))
        for item in bad:
            with self.subTest(size=len(item)), self.assertRaises((ValueError, TypeError, KeyError)):
                C.observation(item, "baseline", "incomplete-Stop")

    def test_selection_cannot_be_taken_from_the_observation(self):
        raw = self.document["streams"][0]["jsonl"].encode()
        for variant, case in (("candidate", "incomplete-Stop"), (True, "incomplete-Stop"),
                              ("baseline", None), ("baseline", "different")):
            with self.subTest(variant=variant, case=case), self.assertRaises((ValueError, TypeError, KeyError)):
                C.observation(raw, variant, case)

    def test_command_completeness_and_exact_types_are_required(self):
        for key, bad in (("actual_exit", None), ("actual_exit", False), ("actual_exit", 1),
                         ("output_complete", 1), ("output_complete", False), ("reason", "unknown"), ("state", "RUNNING")):
            with self.subTest(key=key):
                self.altered(lambda value: value["streams"][0]["command"].update({key: bad}))

    def test_capture_bytes_cannot_be_detached_from_their_command(self):
        self.altered(lambda value: value["streams"][0].update(jsonl="{}\n"))
        self.altered(lambda value: value["bindings"]["candidate"]["capture"]["stdout"].update(bytes=0))

    def test_binary_and_runtime_sources_cannot_be_substituted(self):
        self.altered(lambda value: value["source"].update(candidate_runtime_tree=P.PARENT_TREE))
        self.altered(lambda value: value["bindings"]["candidate"].update(binary=value["bindings"]["baseline"]["binary"]))

    def test_missing_duplicate_or_unselected_case_is_refused(self):
        self.altered(lambda value: value["streams"].pop())
        self.altered(lambda value: value["streams"].append(copy.deepcopy(value["streams"][0])))
        self.altered(lambda value: value["streams"].__setitem__(3, copy.deepcopy(value["streams"][2])))

    def test_linked_module_catalog_is_bound_to_retained_inputs(self):
        self.altered(lambda value: value["linked_module_inputs"][0].update(h1="h1:changed"))
        self.altered(lambda value: value["bindings"]["race"]["linked_module_catalog"].update(bytes=0))

    def test_recorded_native_passes_and_skips_cannot_be_hidden(self):
        self.altered(lambda value: value["native"]["focused_native"].update(jsonl="{}\n"))
        self.altered(lambda value: value["native"].update(ordinary_processes=True))
        self.altered(lambda value: value["native"].update(public_preparer_matches_both_actual_build_sources=False))

    def test_reading_capture_executes_no_backend_or_download(self):
        with mock.patch.object(subprocess, "run", side_effect=AssertionError("unexpected execution")), \
                mock.patch.object(subprocess, "check_output", side_effect=AssertionError("unexpected execution")), \
                mock.patch.object(P, "prepare", side_effect=AssertionError("unexpected preparation")):
            self.assertEqual(C.check_file()["reader_reference_backend_executions"], 0)

    def test_invalid_source_revision_refuses_without_output(self):
        with self.assertRaises(ValueError):
            C.main(["--source-revision", "not-a-revision"])


if __name__ == "__main__":
    unittest.main()
