#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Budget, byte selection, measurement-boundary and offline CLI controls."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("resource_budget_tests", HERE / "check_resource_budgets.py")
CHECK = importlib.util.module_from_spec(spec)
spec.loader.exec_module(CHECK)
ASSESS = CHECK.ASSESS


class ResourceBudgetControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.budget_raw = CHECK.BUDGET.read_bytes()
        cls.selected = json.loads(cls.budget_raw)
        cls.raw, cls.sample_raw = CHECK.CORPUS.read_bytes(), CHECK.SAMPLES.read_bytes()
        cls.corpus, cls.samples = json.loads(cls.raw), json.loads(cls.sample_raw)
        cls.pins = ASSESS.digest(cls.raw), ASSESS.digest(cls.sample_raw)

    def assess(self, selected=None, corpus=None, samples=None, pins=None):
        return ASSESS.assess(self.selected if selected is None else selected,
                             self.raw, self.corpus if corpus is None else corpus,
                             self.sample_raw, self.samples if samples is None else samples,
                             *(self.pins if pins is None else pins))

    def reject_budget(self, mutate):
        selected = copy.deepcopy(self.selected)
        mutate(selected)
        with self.assertRaises((ValueError, KeyError, TypeError)):
            self.assess(selected=selected)

    def reject_samples(self, mutate):
        samples = copy.deepcopy(self.samples)
        mutate(samples)
        raw = json.dumps(samples).encode("utf-8")
        with self.assertRaises((ValueError, KeyError, TypeError)):
            ASSESS.assess(self.selected, self.raw, self.corpus, raw, samples,
                          self.pins[0], ASSESS.digest(raw))

    def measured(self):
        selected = copy.deepcopy(self.selected)
        selected["limits"] = selected["limits"][:10]
        return selected

    def cli(self, raw=None, selected=None, sample_raw=None, pins=None):
        with tempfile.TemporaryDirectory() as directory:
            budget = Path(directory) / "budget.json"
            budget.write_bytes(raw if raw is not None else json.dumps(
                self.selected if selected is None else selected).encode("utf-8"))
            args = [sys.executable, "-I", "-B", str(HERE / "assess_tree_resources.py"),
                    "--budget", str(budget), "--expect-corpus-sha256", (pins or self.pins)[0],
                    "--expect-samples-sha256", (pins or self.pins)[1]]
            if sample_raw is not None:
                sample = Path(directory) / "samples.json"
                sample.write_bytes(sample_raw)
                args += ["--samples", str(sample)]
            result = subprocess.run(args, capture_output=True, timeout=60)
        self.assertFalse(result.stderr)
        return result.returncode, json.loads(result.stdout)

    def test_independent_original_sample_column_oracle(self):
        report = CHECK.evaluate()
        self.assertEqual((report["budget_comparison_contracts_checked"],
                          report["independent_sample_comparisons"], report["recorded_child_samples_checked"]),
                         (3, 60, 96))

    def test_all_generations_and_repetitions_are_reported(self):
        for row in self.assess()["comparisons"][:10]:
            self.assertEqual([(s["generation"], s["repetition"]) for s in row["observations"]],
                             [(g, r) for g in range(2) for r in range(3)])
            self.assertEqual(row["observed_max"], max(s["value"] for s in row["observations"]))

    def test_exact_selected_ceiling_is_inclusive(self):
        selected = self.measured()
        previous = self.assess(selected)
        for rule, row in zip(selected["limits"], previous["comparisons"]):
            rule["ceiling"] = row["observed_max"]
        report = self.assess(selected)
        self.assertEqual(report["comparison_result"], "WITHIN_SELECTED_LIMITS")
        self.assertFalse(report["production_resource_budgets_qualified"])

    def test_exceeded_limit_retains_every_failure(self):
        selected = self.measured()
        selected["limits"][0]["ceiling"] = 0
        report = self.assess(selected)
        self.assertEqual(report["comparison_result"], "EXCEEDED")
        self.assertEqual(report["exceeded_limits"], ["seed-file"])
        self.assertEqual(len(report["comparisons"][0]["observations"]), 6)
        self.assertTrue(all(not s["within_selected_limit"] for s in report["comparisons"][0]["observations"]))

    def test_exceeded_and_unmeasured_are_both_preserved(self):
        selected = copy.deepcopy(self.selected)
        selected["limits"][0]["ceiling"] = 0
        report = self.assess(selected)
        self.assertEqual(report["comparison_result"], "EXCEEDED")
        self.assertEqual(len(report["unmeasured_limits"]), 5)

    def test_plain_and_instrumented_elapsed_modes_stay_distinct(self):
        selected = self.measured()
        rule = copy.deepcopy(selected["limits"][0])
        rule.update(id="instrumented-seed-file", mode="allocation")
        selected["limits"].append(rule)
        row = self.assess(selected)["comparisons"][-1]
        expected = [s["phase_resources"][0]["elapsed_ns"] for run in self.samples["samples"]
                    for s in run if s["case"] == "retained-32" and s["mode"] == "allocation"]
        self.assertEqual([s["value"] for s in row["observations"]], expected)

    def test_plain_mode_cannot_supply_allocation(self):
        self.reject_budget(lambda d: d["limits"][3].update(mode="plain"))

    def test_zero_GC_cycles_are_a_measured_value(self):
        selected = self.measured()
        selected["limits"] = [dict(id="gc", metric="phase_go_gc_cycles", phase="clean-close",
                                   mode="allocation", ceiling=0)]
        row = self.assess(selected)["comparisons"][0]
        self.assertEqual(row["comparison"], "WITHIN_SELECTED_LIMIT")
        self.assertEqual([s["value"] for s in row["observations"]], [0] * 6)

    def test_malloc_count_is_not_allocation_bytes(self):
        selected = self.measured()
        selected["limits"] = [dict(id="mallocs", metric="phase_go_mallocs_delta", phase="clean-close",
                                   mode="allocation", ceiling=1 << 32)]
        row = self.assess(selected)["comparisons"][0]
        expected = [next(p for p in s["phase_resources"] if p["phase"] == "clean-close")["go_mallocs_delta"]
                    for run in self.samples["samples"] for s in run
                    if s["case"] == "retained-32" and s["mode"] == "allocation"]
        self.assertEqual([s["value"] for s in row["observations"]], expected)

    def test_process_RSS_cannot_supply_live_Go_heap(self):
        rows = self.assess()["comparisons"]
        self.assertIsNotNone(rows[8]["observed_max"])
        self.assertEqual(rows[11]["comparison"], "UNMEASURED")
        self.assertIsNone(rows[11]["observed_max"])

    def test_closed_lengths_cannot_supply_allocated_or_peak_disk(self):
        rows = self.assess()["comparisons"]
        self.assertIsNotNone(rows[9]["observed_max"])
        self.assertEqual(rows[12]["comparison"], "UNMEASURED")

    def test_queries_and_whole_pipeline_are_not_phase_sums(self):
        rows = self.assess()["comparisons"]
        for row in (rows[10], rows[14]):
            self.assertEqual((row["comparison"], row["observations"], row["observed_max"]),
                             ("UNMEASURED", [], None))

    def test_RSS_through_serialization_is_unmeasured(self):
        report = self.assess()
        self.assertTrue(report["RSS_excludes_final_result_binding_and_serialization"])
        self.assertEqual(report["comparisons"][13]["comparison"], "UNMEASURED")

    def test_missing_measurement_is_not_zero_or_within(self):
        selected = self.measured()
        selected["limits"] = [dict(id="query", metric="query_elapsed_ns", phase=None, mode="plain", ceiling=0)]
        report = self.assess(selected)
        self.assertEqual(report["comparison_result"], "INCOMPLETE")
        self.assertEqual(report["unmeasured_limits"], ["query"])

    def test_consumer_declaration_authenticates_neither_budget_nor_hardware(self):
        selected = self.measured()
        selected.update(budget_basis="consumer-declared", device_label="selected-consumer-device")
        report = self.assess(selected)
        self.assertEqual(report["comparison_result"], "WITHIN_SELECTED_LIMITS")
        for flag in ("budget_independent_selection_authenticated", "target_hardware_identity_recorded",
                     "execution_provenance_authenticated", "production_resource_budgets_qualified"):
            self.assertFalse(report[flag])
        self.assertEqual((report["consumer_result"], report["proven"]), ("REFUSED", []))

    def test_unknown_or_promotion_fields_refuse(self):
        self.reject_budget(lambda d: d.update(production_resource_budgets_qualified=True))
        self.reject_budget(lambda d: d["runtime"].update(trusted=True))
        self.reject_budget(lambda d: d["limits"][0].update(optional=True))

    def test_source_revision_and_tree_are_exact(self):
        self.reject_budget(lambda d: d["source"].update(revision="0" * 40))
        self.reject_budget(lambda d: d["source"].update(tree="0" * 40))

    def test_device_and_selection_labels_cannot_embed_private_paths(self):
        for value in ("/private/path", "https://endpoint.invalid", "user@example.invalid", "a" * 65, ""):
            self.reject_budget(lambda d, v=value: d.update(device_label=v))

    def test_platform_architecture_and_Go_version_must_match(self):
        for field, value in (("platform", "linux/arm64"), ("platform", "darwin/amd64"),
                             ("go_version", "go1.25.13")):
            self.reject_budget(lambda d, f=field, v=value: d["runtime"].update({f: v}))

    def test_concurrency_and_other_workloads_are_not_qualified(self):
        self.reject_budget(lambda d: d["workload"].update(serial_callers=2))
        self.reject_budget(lambda d: d["workload"].update(serial_callers=True))
        self.reject_budget(lambda d: d["workload"].update(case="real-network-archive"))
        self.reject_budget(lambda d: d["workload"].update(case="tail-root-refusal"))

    def test_ceilings_are_unsigned_integers_without_boolean_coercion(self):
        for value in (True, -1, 1 << 64, 1.0, "10", None):
            self.reject_budget(lambda d, v=value: d["limits"][0].update(ceiling=v))

    def test_unknown_phase_metric_mode_and_nonphase_alias_refuse(self):
        for update in ({"metric": "peak_memory_bytes"}, {"phase": "query"}, {"mode": "best"}):
            self.reject_budget(lambda d, u=update: d["limits"][0].update(u))
        self.reject_budget(lambda d: d["limits"][8].update(phase="clean-close"))

    def test_duplicate_limit_ids_and_measurement_cells_refuse(self):
        self.reject_budget(lambda d: d["limits"][1].update(id=d["limits"][0]["id"]))
        def duplicate(d):
            row = copy.deepcopy(d["limits"][0]); row["id"] = "different-id"; d["limits"].append(row)
        self.reject_budget(duplicate)

    def test_empty_and_excessive_limit_inventories_refuse(self):
        self.reject_budget(lambda d: d.update(limits=[]))
        self.reject_budget(lambda d: d.update(limits=d["limits"] * 5))

    def test_every_actual_child_outcome_is_required_including_other_cases(self):
        self.reject_samples(lambda d: d["commands"][0].pop())
        self.reject_samples(lambda d: d["commands"][0][-1].update(actual_exit=1))
        self.reject_samples(lambda d: d["commands"][0][-1].update(completed=False))

    def test_missing_generations_repetitions_and_modes_refuse(self):
        self.reject_samples(lambda d: d["samples"].pop())
        self.reject_samples(lambda d: d["samples"][0].pop())
        self.reject_samples(lambda d: d["samples"][0][0].update(mode="allocation"))
        self.reject_samples(lambda d: d["samples"][0][0].update(repetition=1))

    def test_changed_measurement_cannot_keep_original_command_binding(self):
        self.reject_samples(lambda d: d["samples"][0][0]["phase_resources"][0].update(elapsed_ns=1))
        self.reject_samples(lambda d: d["samples"][0][0]["closed_database_files"].update(bytes=1))
        self.reject_samples(lambda d: d["samples"][0][0].update(process_peak_rss_bytes=1))

    def test_reference_binary_and_resource_methods_remain_bound(self):
        self.reject_samples(lambda d: d.update(reference_binary_sha256="bad"))
        self.reject_samples(lambda d: d["samples"][0][0].update(process_peak_rss_method="phase allocation"))
        self.reject_samples(lambda d: d["samples"][0][0]["phase_resources"].reverse())

    def test_wrong_corpus_or_sample_byte_selection_refuses(self):
        for pins in (("0" * 64, self.pins[1]), (self.pins[0], "0" * 64)):
            with self.assertRaises(ValueError):
                self.assess(pins=pins)

    def test_selected_raw_bytes_cannot_bind_another_decoded_binary_label(self):
        samples = copy.deepcopy(self.samples)
        samples["reference_binary_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "selected_evidence_document"):
            self.assess(samples=samples)

    def test_decoded_corpus_must_match_selected_raw_bytes(self):
        corpus = copy.deepcopy(self.corpus)
        corpus["cases"][0]["consumer_result"] = "ACCEPTED"
        with self.assertRaisesRegex(ValueError, "selected_evidence_document"):
            self.assess(corpus=corpus)

    def test_cli_outcomes_distinguish_within_incomplete_and_exceeded(self):
        code, report = self.cli()
        self.assertEqual((code, report["comparison_result"]), (2, "INCOMPLETE"))
        selected = self.measured()
        code, report = self.cli(selected=selected)
        self.assertEqual((code, report["comparison_result"]), (0, "WITHIN_SELECTED_LIMITS"))
        selected["limits"][0]["ceiling"] = 0
        code, report = self.cli(selected=selected)
        self.assertEqual((code, report["comparison_result"]), (2, "EXCEEDED"))
        self.assertFalse(report["production_state_value_accepted"])

    def test_cli_budget_and_original_evidence_bytes_are_pinned(self):
        code, report = self.cli(raw=self.budget_raw)
        self.assertEqual(code, 2)
        self.assertEqual((report["budget_sha256"], report["corpus_sha256"], report["samples_sha256"]),
                         (ASSESS.digest(self.budget_raw), *self.pins))
        self.assertEqual(self.cli(sample_raw=b"\n" + self.sample_raw)[0], 1)

    def test_cli_byte_pinned_failed_child_still_refuses_before_case_selection(self):
        samples = copy.deepcopy(self.samples)
        samples["commands"][1][-1]["actual_exit"] = 1
        raw = json.dumps(samples).encode("utf-8")
        code, report = self.cli(sample_raw=raw, pins=(self.pins[0], ASSESS.digest(raw)))
        self.assertEqual((code, report["comparison_result"]), (1, "REFUSED"))

    def test_cli_refusal_output_does_not_expose_input_or_paths(self):
        code, report = self.cli(raw=b'{"secret":"credential-sentinel"}')
        self.assertEqual((code, report["comparison_result"]), (1, "REFUSED"))
        self.assertNotIn("credential-sentinel", json.dumps(report))
        self.assertNotIn("budget.json", json.dumps(report))

    def test_cli_duplicate_fields_nonfinite_and_depth_refuse(self):
        for raw in (b'{"kind":1,"kind":2}', b'{"kind":NaN}', b"[" * 9 + b"0" + b"]" * 9):
            self.assertEqual(self.cli(raw=raw)[0], 1)

    def test_cli_UTF16_UTF32_and_oversize_refuse(self):
        for raw in (self.budget_raw.decode().encode("utf-16"), self.budget_raw.decode().encode("utf-32"),
                    b" " * (ASSESS.MAX_BUDGET_BYTES + 1)):
            self.assertEqual(self.cli(raw=raw)[0], 1)

    def test_standalone_source_bound_checker(self):
        result = subprocess.run([sys.executable, "-I", "-B", str(HERE / "check_resource_budgets.py"),
                                 "--source-revision", "a" * 40], capture_output=True, timeout=60)
        self.assertEqual(result.returncode, 0)
        self.assertFalse(result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["source_revision"], "a" * 40)
        self.assertFalse(report["new_NodeTree_execution"])
        self.assertFalse(report["production_resource_budgets_qualified"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
