#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Reconcile fixed cache read-error observations without executing a backend."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("cache_read_preparation", HERE / "prepare_cache_read_errors.py")
PREP = importlib.util.module_from_spec(spec)
spec.loader.exec_module(PREP)
M = PREP.M
PRIOR = PREP.load("cache_read_prior_native_inventory", "check_cache_store_context.py")
CORPUS = "native-cache-read-errors.json"
STREAMS = {
    "baseline": (
        ("initialize-extract-query-close", "fc5eb3fb9f1937ce0593aa924674b36f0c02e8e76d8e6ff4b64cd6e05d76c4ba", 4064),
        ("reopen-query-close", "204f58a6712d1ce35c8900587184492a40bd24b7235b4eff8d8ba6dd78fb1af1", 3334)),
    "candidate": (
        ("initialize-extract-query-close", "bc167eeb37c2b12ceaf2ee1142fae92c6e75b00ebce10cfa9273378b37403f9c", 4096),
        ("reopen-query-close", "ca27c4e332a3d3bb2f97d6a10e635e05bc42b705b47c0bcf28c5a79ee42d36aa", 3366)),
}
BINARY_PINS = {
    "baseline": {"bytes": 13711250, "sha256": "7b20e4b5a4cc6353cec4edbb6573d2598543712c29e5c4d692a182efec7ac303"},
    "candidate": {"bytes": 13711250, "sha256": "b633c4c8aa36295aab3265382fab1f3d2e207ddf3d3403293d8ca3d58ab2c295"},
}
SCOPE = {name: False for name in (
    "ordinary_public_Chain_execution", "ordinary_ledger_or_state_tree_execution",
    "account_block_execution", "verified_momentum_headers", "cache_value_authentication",
    "profile_agreement", "network_activation_authenticated", "concurrent_lifecycle_qualified",
    "full_node_recovery_qualified", "private_capture_or_distribution_authenticated",
    "accepted_header_binding", "runtime_state_value_acceptance", "production_qualified")}

def native_passes():
    result = [{"package": "github.com/zenon-network/go-zenon/chain", "name": name}
              for name in PRIOR.NATIVE_PASS_NAMES]
    result += [{"package": "github.com/zenon-network/go-zenon/" + package, "name": name}
               for package, name in PREP.EXISTING_CACHE_ROOTS]
    names = PREP.new_roots() + [
        "TestCacheReadError_RealClosedManagerViews/" + child for child in ("chain-plasma", "spork", "stake")]
    result += [{"package": "github.com/zenon-network/go-zenon/chain/cache", "name": name}
               for name in names]
    result.sort(key=lambda row: (row["package"], row["name"]))
    M.require(len(result) == 50 and len(PRIOR.NATIVE_PASS_NAMES) == 29 and len(names) == 15)
    M.exact(sorted({row["name"] for row in result if "/" not in row["name"]}), PREP.roots())
    return result

def check_corpus(document):
    M.require(type(document) is dict and set(document) == {
        "format_version", "kind", "source", "recorded_native", "scope", "variants"})
    M.exact(document["format_version"], 1)
    M.exact(document["kind"], "recorded-cache-initial-read-error-comparison")
    M.exact(document["scope"], SCOPE)
    M.exact(document["source"], {
        "repository": "digitalSloth/go-zenon", "revision": PREP.P.REVISION,
        "parent_runtime_tree": PREP.PARENT_TREE, "candidate_runtime_tree": PREP.CANDIDATE_TREE,
        "parent_build_tree": PREP.BUILD_TREES["baseline"], "candidate_build_tree": PREP.BUILD_TREES["candidate"],
        "parent_source_files": 471, "candidate_source_files": 472,
        "probe": {"bytes": PREP.PROBE_BYTES, "sha256": PREP.PROBE_SHA256},
        "unit_source": {"bytes": PREP.UNIT_BYTES, "sha256": PREP.UNIT_SHA256},
        "independent_model": {"bytes": PREP.MODEL_BYTES, "sha256": PREP.MODEL_SHA256},
        "fixture": {"bytes": PREP.FIXTURE_BYTES, "sha256": PREP.FIXTURE_SHA256}})
    for variant, count in (("baseline", 471), ("candidate", 472)):
        pins = PREP.build_pins(variant)
        M.require(len(pins) == count and PREP.P.UTIL.reconstruct_tree(pins) == PREP.BUILD_TREES[variant])
    M.exact(document["recorded_native"], {
        "go_version": "go1.25.14", "platform": "darwin/arm64",
        "ordinary_builds": 2, "ordinary_processes": 4, "Go_unit_invocations": 1, "Go_unit_packages": 3,
        "native_unit_root_count": 41, "native_unit_pass_results": 50, "new_cache_unit_roots": 12,
        "new_cache_unit_pass_results": 15, "preserved_chain_pass_results": 29,
        "preserved_existing_cache_storage_roots": 6, "native_unit_passes": native_passes(),
        "ordinary_probe_executes_cache_manager_and_extractor_only": True,
        "native_units_include_selected_public_chain_manager_regressions": True})
    M.require(type(document["variants"]) is dict and set(document["variants"]) == set(PREP.VARIANTS))
    fixture = PREP.selected_fixture()
    summaries = {}
    images = []
    for variant in PREP.VARIANTS:
        row = document["variants"][variant]
        M.require(type(row) is dict and set(row) == {"binary", "streams"})
        M.exact(row["binary"], BINARY_PINS[variant])
        M.require(type(row["streams"]) is list and len(row["streams"]) == 2)
        streams = []
        for recording, (mode, digest, size) in zip(row["streams"], STREAMS[variant]):
            M.require(type(recording) is dict and set(recording) == {"case", "sha256", "bytes", "jsonl"})
            M.exact([recording["case"], recording["sha256"], recording["bytes"]], [mode, digest, size])
            M.require(type(recording["jsonl"]) is str)
            raw = recording["jsonl"].encode()
            M.require(len(raw) == size and hashlib.sha256(raw).hexdigest() == digest)
            streams.append(raw)
            images.extend(event["sha256"] for event in M.stream(raw)
                          if event["stage"] in ("closed-store", "closed-store-before-reopen"))
        summaries[variant] = M.check(streams[0], streams[1], fixture, variant)
    M.require(len(images) == 6 and len(set(images)) == 1)
    M.exact([summaries[name]["observed_error_propagation_mismatches"] for name in PREP.VARIANTS], [6, 0])
    return {"kind": "recorded-cache-read-error-check", "node_revision": PREP.P.REVISION,
        "parent_runtime_tree": PREP.PARENT_TREE, "candidate_runtime_tree": PREP.CANDIDATE_TREE,
        "event_count": 58, "query_count": 38, "baseline_error_mismatches": 6, "candidate_error_mismatches": 0,
        "direct_iterator_errors": 4, "recorded_ordinary_processes": 4, "recorded_ordinary_builds": 2,
        "recorded_unit_root_count": 41, "recorded_unit_pass_results": 50,
        "new_cache_unit_roots": 12, "new_cache_unit_pass_results": 15,
        "preserved_chain_pass_results": 29, "preserved_existing_cache_storage_roots": 6,
        "raw_logical_image_observations": 6, "raw_logical_records": 4,
        "raw_logical_images_equal_across_variants": True, "raw_logical_image_sha256": images[0],
        "fixture_sha256": PREP.FIXTURE_SHA256, "consumer_result": "REFUSED",
        "backend_reexecuted": False, "production_state_value_accepted": False,
        "private_execution_or_distribution_authenticated": False, "cache_value_authentication_qualified": False,
        "full_node_or_network_validity_qualified": False, "scope": document["scope"],
        "reader_inputs_sha256": {name: hashlib.sha256((HERE / name).read_bytes()).hexdigest()
            for name in ("prepare_cache_read_errors.py", "check_cache_read_errors.py", "cache_read_error_model.py")}}

def check_file(path=None):
    selected = HERE / "testdata" / CORPUS if path is None else Path(path)
    raw = M.read_bounded(selected, 128 << 10)
    return check_corpus(json.loads(raw, object_pairs_hook=M.pairs, parse_constant=M.constant))

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--file")
    parser.add_argument("--source-revision")
    args = parser.parse_args(argv)
    M.require(args.source_revision is None or re.fullmatch("[0-9a-f]{40}", args.source_revision))
    result = check_file(args.file)
    if args.source_revision is not None:
        result["source_revision"] = args.source_revision
    print(json.dumps(result, sort_keys=True))

if __name__ == "__main__":
    try:
        main()
    except (ValueError, TypeError, KeyError, OSError):
        print("Recorded cache read error evidence refused; state values remain disabled.", file=sys.stderr)
        raise SystemExit(1)
