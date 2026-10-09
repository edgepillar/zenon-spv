#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Independently bind the offline budget example to every recorded sample."""
import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("resource_budget_controls_oracle", HERE / "assess_tree_resources.py")
ASSESS = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ASSESS)
BUDGET = HERE / "testdata/tree-resource-budget-example.json"
CORPUS = HERE / "testdata/candidate-patch-tree-tail.json"
SAMPLES = HERE / "testdata/candidate-patch-tree-tail-samples.json"
INPUT_NAMES = ASSESS.TAIL.INPUT_NAMES + (
    "observe_balance.py", "assess_tree_resources.py", "check_resource_budgets.py",
    "check_resource_budgets_test.py", "testdata/tree-resource-budget-example.json",
    "testdata/candidate-patch-tree-tail.json", "testdata/candidate-patch-tree-tail-samples.json")


def evaluate():
    budget_raw, selected = ASSESS.INPUT.read_document(BUDGET, ASSESS.MAX_BUDGET_BYTES)
    raw, corpus = ASSESS.INPUT.read_document(CORPUS, ASSESS.TAIL.BYTE.MAX_FILE_BYTES)
    sample_raw, samples = ASSESS.INPUT.read_document(SAMPLES, ASSESS.TAIL.BYTE.MAX_FILE_BYTES)
    pins = ASSESS.digest(raw), ASSESS.digest(sample_raw)
    report = ASSESS.assess(selected, raw, corpus, sample_raw, samples, *pins)
    require = ASSESS.need
    require(report["comparison_result"] == "INCOMPLETE", "example_incomplete")
    require(len(report["comparisons"]) == 15 and len(report["unmeasured_limits"]) == 5,
            "example_metric_inventory")
    # Read the original metric columns directly. Do not use the assessor's
    # metric lookup, maximum or comparison result as the expected outcome.
    field = {"phase_elapsed_ns": "elapsed_ns",
             "phase_go_total_alloc_delta_bytes": "go_total_alloc_delta_bytes"}
    count = 0
    for row, rule in zip(report["comparisons"], selected["limits"]):
        if rule["metric"] in ("query_elapsed_ns", "peak_live_go_heap_bytes", "peak_allocated_disk_bytes",
                              "process_peak_rss_through_serialization_bytes", "whole_pipeline_elapsed_ns"):
            require(row["observations"] == [] and row["observed_max"] is None and
                    row["comparison"] == "UNMEASURED", "unmeasured_not_zero")
            continue
        values = []
        for generation, run in enumerate(samples["samples"]):
            chosen = [s for s in run if s["case"] == "retained-32" and s["mode"] == rule["mode"]]
            require([s["repetition"] for s in chosen] == [0, 1, 2], "literal_repetitions")
            for sample in chosen:
                if rule["metric"] in field:
                    phases = {p["phase"]: p for p in sample["phase_resources"]}
                    value = phases[rule["phase"]][field[rule["metric"]]]
                elif rule["metric"] == "closed_database_file_bytes":
                    value = sample["closed_database_files"]["bytes"]
                else:
                    require(rule["metric"] == "process_peak_rss_bytes", "example_metric")
                    value = sample["process_peak_rss_bytes"]
                values.append({"generation": generation, "repetition": sample["repetition"],
                               "value": value, "within_selected_limit": value <= rule["ceiling"]})
        require(row["observations"] == values and row["observed_max"] == max(v["value"] for v in values)
                and row["comparison"] == "WITHIN_SELECTED_LIMIT", "independent_sample_comparison")
        count += len(values)
    require(count == 60 and report["complete_recorded_child_samples_checked"] == 96,
            "complete_recorded_samples")
    measured = copy.deepcopy(selected)
    measured["limits"] = measured["limits"][:10]
    within = ASSESS.assess(measured, raw, corpus, sample_raw, samples, *pins)
    require(within["comparison_result"] == "WITHIN_SELECTED_LIMITS", "measured_only_comparison")
    exceeded = copy.deepcopy(measured)
    exceeded["limits"][0]["ceiling"] = 0
    outside = ASSESS.assess(exceeded, raw, corpus, sample_raw, samples, *pins)
    require(outside["comparison_result"] == "EXCEEDED" and
            outside["exceeded_limits"] == ["seed-file"] and
            all(not v["within_selected_limit"] for v in outside["comparisons"][0]["observations"]),
            "exceeded_is_not_acceptance")
    for document in (report, within, outside):
        require(document["consumer_result"] == "REFUSED" and document["proven"] == [] and
                not document["production_resource_budgets_qualified"] and
                not document["production_state_value_accepted"] and
                not document["budget_independent_selection_authenticated"] and
                not document["target_hardware_identity_recorded"] and
                not document["execution_provenance_authenticated"], "trust_boundaries")
    return {"budget_comparison_contracts_checked": 3, "recorded_child_samples_checked": 96,
            "measured_limits": 10, "unmeasured_limits": 5, "independent_sample_comparisons": count,
            "corpus_sha256": pins[0], "samples_sha256": pins[1], "budget_sha256": ASSESS.digest(budget_raw),
            "new_NodeTree_execution": False, "new_resource_measurements": False,
            "production_resource_budgets_qualified": False, "consumer_result": "REFUSED",
            "production_state_value_accepted": False,
            "selected_source_inputs": {name: hashlib.sha256((HERE / name).read_bytes()).hexdigest()
                                       for name in INPUT_NAMES}}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-revision")
    args = parser.parse_args(argv)
    ASSESS.need(args.source_revision is None or
                re.fullmatch(r"[0-9a-f]{40}", args.source_revision) is not None, "source_revision")
    print(json.dumps(evaluate() | {"source_revision": args.source_revision},
                     sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError, StopIteration):
        print("Offline resource budget evidence refused; production qualification remains disabled.", file=sys.stderr)
        sys.exit(1)
