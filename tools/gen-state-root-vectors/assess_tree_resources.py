#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Compare an unsigned budget with recorded, finite NodeTree tail samples.

This offline diagnostic checks every selected repetition in both generations.
It never qualifies hardware, independently selected budgets or production use.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys

HERE = Path(__file__).resolve().parent


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


INPUT = module("resource_budget_input", "observe_balance.py")
TAIL = module("resource_budget_tail", "check_patch_tree_tail.py")
need, closed, Refusal = INPUT.need, INPUT.closed, INPUT.Refusal
MAX_BUDGET_BYTES = 16384
PHASE_METRICS = {
    "phase_elapsed_ns": "elapsed_ns",
    "phase_go_total_alloc_delta_bytes": "go_total_alloc_delta_bytes",
    "phase_go_mallocs_delta": "go_mallocs_delta",
    "phase_go_gc_cycles": "go_gc_cycles",
}
LIFETIME_METRICS = {"process_peak_rss_bytes", "closed_database_file_bytes"}
UNMEASURED_METRICS = {"query_elapsed_ns", "whole_pipeline_elapsed_ns",
                      "peak_live_go_heap_bytes", "peak_allocated_disk_bytes",
                      "process_peak_rss_through_serialization_bytes"}


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def label(value):
    need(type(value) is str and re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", value)
         is not None, "public_label")


def contract(value, corpus):
    closed(value, ("kind", "selection_id", "budget_basis", "device_label",
                   "source", "runtime", "workload", "limits"), "budget_shape")
    need(value["kind"] == "unsigned-tree-tail-resource-budget-v1", "budget_kind")
    for field in ("selection_id", "device_label"):
        label(value[field])
    need(value["budget_basis"] in ("illustrative", "consumer-declared"), "budget_basis")
    need(value["source"] == corpus["source"], "budget_source")
    closed(value["runtime"], ("platform", "go_version"), "runtime_shape")
    runtime = value["runtime"]
    need(type(runtime["platform"]) is str and
         re.fullmatch(r"(darwin|linux)/(amd64|arm64)", runtime["platform"]) is not None,
         "runtime_platform")
    need(type(runtime["go_version"]) is str and
         re.fullmatch(r"go1\.25\.[0-9]+", runtime["go_version"]) is not None, "runtime_go")
    closed(value["workload"], ("case", "serial_callers"), "workload_shape")
    workload = value["workload"]
    need(workload["case"] in ("retained-8", "retained-32", "empty-transitions") and
         type(workload["serial_callers"]) is int and workload["serial_callers"] == 1,
         "finite_serial_workload")
    case = next(c for c in corpus["cases"] if c["name"] == workload["case"])
    phases = TAIL.phase_inventory(case)
    limits = value["limits"]
    need(type(limits) is list and 0 < len(limits) <= 64, "limit_count")
    names, cells = set(), set()
    for rule in limits:
        closed(rule, ("id", "metric", "phase", "mode", "ceiling"), "limit_shape")
        label(rule["id"])
        need(rule["id"] not in names, "duplicate_limit")
        names.add(rule["id"])
        metric, phase, mode = rule["metric"], rule["phase"], rule["mode"]
        need(type(metric) is str and metric in
             set(PHASE_METRICS) | LIFETIME_METRICS | UNMEASURED_METRICS, "limit_metric")
        need(type(mode) is str and mode in ("plain", "allocation"), "limit_mode")
        INPUT.u64(rule["ceiling"])
        if metric in PHASE_METRICS:
            need(type(phase) is str and phase in phases, "limit_phase")
            need(metric == "phase_elapsed_ns" or mode == "allocation", "allocation_mode")
        else:
            need(phase is None, "nonphase_metric")
        cell = metric, phase, mode
        need(cell not in cells, "duplicate_measurement_limit")
        cells.add(cell)
    return case


def assess(selected, corpus_raw, corpus, samples_raw, samples, expected_corpus, expected_samples):
    INPUT.hash32(expected_corpus)
    INPUT.hash32(expected_samples)
    need(digest(corpus_raw) == expected_corpus and digest(samples_raw) == expected_samples,
         "selected_evidence_bytes")
    # Programmatic callers must not pair selected raw bytes with a different
    # decoded document, including a coherently changed binary label.
    try:
        for raw, document in ((corpus_raw, corpus), (samples_raw, samples)):
            need(len(raw) <= TAIL.BYTE.MAX_FILE_BYTES, "selected_evidence_bound")
            decoded = json.loads(raw.decode("utf-8"), object_pairs_hook=INPUT.pairs,
                                 parse_constant=lambda _: (_ for _ in ()).throw(Refusal("json_constant")))
            TAIL.DEC.RET.exact(document, decoded)
    except (ValueError, KeyError, TypeError, UnicodeError, RecursionError):
        raise Refusal("selected_evidence_document") from None
    # The complete recorded corpus, phases and actual command outcomes are
    # checked before selecting a case or mode. No failed child is filtered out.
    try:
        conformance = TAIL.check_samples(samples, corpus_raw, corpus)
    except (ValueError, KeyError, TypeError, OSError):
        raise Refusal("recorded_evidence_conformance") from None
    case = contract(selected, corpus)
    runtime = selected["runtime"]
    for generation in samples["samples"]:
        for sample in generation:
            need(sample["platform"] == runtime["platform"] and
                 sample["go_version"] == runtime["go_version"], "selected_runtime")
    comparisons = []
    for rule in selected["limits"]:
        observations = []
        if rule["metric"] not in UNMEASURED_METRICS:
            for generation, run in enumerate(samples["samples"]):
                for sample in run:
                    if sample["case"] != case["name"] or sample["mode"] != rule["mode"]:
                        continue
                    if rule["metric"] in PHASE_METRICS:
                        phase = next(row for row in sample["phase_resources"]
                                     if row["phase"] == rule["phase"])
                        observed = phase[PHASE_METRICS[rule["metric"]]]
                    elif rule["metric"] == "closed_database_file_bytes":
                        observed = sample["closed_database_files"]["bytes"]
                    else:
                        observed = sample["process_peak_rss_bytes"]
                    INPUT.u64(observed)
                    observations.append({"generation": generation,
                                         "repetition": sample["repetition"], "value": observed,
                                         "within_selected_limit": observed <= rule["ceiling"]})
            need([(s["generation"], s["repetition"]) for s in observations] ==
                 [(g, r) for g in range(2) for r in range(3)], "all_selected_samples")
        maximum = max((s["value"] for s in observations), default=None)
        status = ("UNMEASURED" if maximum is None else "EXCEEDED" if
                  maximum > rule["ceiling"] else "WITHIN_SELECTED_LIMIT")
        comparisons.append(rule | {"observations": observations, "observed_max": maximum,
                                   "comparison": status})
    exceeded = [c["id"] for c in comparisons if c["comparison"] == "EXCEEDED"]
    unmeasured = [c["id"] for c in comparisons if c["comparison"] == "UNMEASURED"]
    result = "EXCEEDED" if exceeded else "INCOMPLETE" if unmeasured else "WITHIN_SELECTED_LIMITS"
    return {"kind": "unsigned-tree-tail-resource-assessment-v1",
            "selection_id": selected["selection_id"], "budget_basis": selected["budget_basis"],
            "device_label": selected["device_label"], "runtime": runtime, "source": samples["source"],
            "workload": selected["workload"], "comparison_result": result,
            "comparisons": comparisons, "exceeded_limits": exceeded, "unmeasured_limits": unmeasured,
            "corpus_sha256": digest(corpus_raw), "samples_sha256": digest(samples_raw),
            "reference_binary_sha256": samples["reference_binary_sha256"],
            "complete_recorded_child_samples_checked": conformance["recorded_fresh_child_samples"],
            "samples_per_measured_limit": 6, "new_resource_measurements": False,
            "allocation_is_cumulative_not_peak": True, "closed_file_lengths_are_not_peak_disk": True,
            "RSS_excludes_final_result_binding_and_serialization": True,
            "query_latency_measured": False, "target_hardware_identity_recorded": False,
            "budget_independent_selection_authenticated": False, "execution_provenance_authenticated": False,
            "production_resource_budgets_qualified": False, "consumer_result": "REFUSED",
            "production_state_value_accepted": False, "proven": []}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--budget", required=True, type=Path)
    parser.add_argument("--corpus", type=Path, default=HERE / "testdata/candidate-patch-tree-tail.json")
    parser.add_argument("--samples", type=Path, default=HERE / "testdata/candidate-patch-tree-tail-samples.json")
    parser.add_argument("--expect-corpus-sha256", required=True)
    parser.add_argument("--expect-samples-sha256", required=True)
    args = parser.parse_args(argv)
    try:
        budget_raw, selected = INPUT.read_document(args.budget, MAX_BUDGET_BYTES)
        corpus_raw, corpus = INPUT.read_document(args.corpus, TAIL.BYTE.MAX_FILE_BYTES)
        samples_raw, samples = INPUT.read_document(args.samples, TAIL.BYTE.MAX_FILE_BYTES)
        report = assess(selected, corpus_raw, corpus, samples_raw, samples,
                        args.expect_corpus_sha256, args.expect_samples_sha256)
        report["budget_sha256"] = digest(budget_raw)
        print(json.dumps(report, sort_keys=True, separators=(",", ":")))
        return 0 if report["comparison_result"] == "WITHIN_SELECTED_LIMITS" else 2
    except (Refusal, OSError, ValueError, KeyError, TypeError, StopIteration):
        print(json.dumps({"comparison_result": "REFUSED", "consumer_result": "REFUSED",
                          "production_resource_budgets_qualified": False,
                          "production_state_value_accepted": False, "proven": []}))
        return 1


if __name__ == "__main__":
    sys.exit(main())
