#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Check fixed local cache-context observations without executing a backend."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import stat

def require(ok):
    if not ok:
        raise ValueError("Cache context observation refused")

def pairs(items):
    out = {}
    for key, value in items:
        require(key not in out)
        out[key] = value
    return out

def constant(_):
    raise ValueError("Non-finite observation refused")

def decode(raw):
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)

def exact(actual, expected):
    require(type(actual) is type(expected))
    if type(expected) is dict:
        require(set(actual) == set(expected))
        for key in expected:
            exact(actual[key], expected[key])
    elif type(expected) is list:
        require(len(actual) == len(expected))
        for left, right in zip(actual, expected):
            exact(left, right)
    else:
        require(actual == expected)

def read(path, limit):
    path = Path(path)
    row = path.lstat()
    require(stat.S_ISREG(row.st_mode) and row.st_nlink == 1 and row.st_size <= limit)
    raw = path.read_bytes()
    require(len(raw) == row.st_size)
    return raw

def valid_images(images):
    require(type(images) is dict and set(images) == {"ledger", "cache", "tree"})
    for image in images.values():
        require(type(image) is dict and set(image) == {
            "records", "key_bytes", "value_bytes", "zero_length_values", "sha256"})
        for key in ("records", "key_bytes", "value_bytes", "zero_length_values"):
            require(type(image[key]) is int and image[key] >= 0)
        require(type(image["sha256"]) is str and re.fullmatch("[0-9a-f]{64}", image["sha256"]))
        require(image["records"] > 0 and image["zero_length_values"] <= image["records"])

def check(first, reopened, fixture, fixture_sha, variant):
    require(variant in ("baseline", "candidate"))
    origin = fixture["states"]["A1"]["identifier"]
    exact(fixture["schema"], "zenon-public-chain-reorg-reopen-fixture-v1")
    require(type(origin["height"]) is int and origin["height"] == 1)
    require(type(origin["hash"]) is str and re.fullmatch("[0-9a-f]{64}", origin["hash"]))
    changed_first, changed_last = bytearray.fromhex(origin["hash"]), bytearray.fromhex(origin["hash"])
    changed_first[0] ^= 128
    changed_last[-1] ^= 128
    choices = [
        ("canonical-origin", origin, True, "none"),
        ("same-height-first-byte-flip", dict(origin, hash=changed_first.hex()), False, "identity-mismatch"),
        ("same-height-last-byte-flip", dict(origin, hash=changed_last.hex()), False, "identity-mismatch"),
        ("unavailable-next-height", dict(origin, height=origin["height"] + 1), False, "missing-version"),
    ]
    query_groups = []
    for mode, events in (("initialize-and-query", first), ("reopen-and-query", reopened)):
        expected_stages = (["selection"] + (["closed-stores-before-reopen"] if mode == "reopen-and-query" else []) +
                           ["fresh-source-genesis", "ready"] + ["cache-context-query"] * 4 + ["closed-stores"])
        require(type(events) is list and len(events) == len(expected_stages))
        exact([row["stage"] for row in events], expected_stages)
        for row in events:
            exact(row["case"], mode)
        exact(events[0], {
            "case": mode, "stage": "selection", "fixture_sha256": fixture_sha,
            "consumer_result": "REFUSED", "public_read_only_cache_context_selected": True,
            "new_account_blocks_added": False, "network_or_full_node_started": False,
            "consensus_validation_executed": False, "wallet_signing_or_broadcast": False,
            "cache_value_correctness_or_state_proof_acceptance_qualified": False})
        offset = 2 if mode == "reopen-and-query" else 1
        exact(events[offset], {"case": mode, "stage": "fresh-source-genesis", "identifier": origin,
            "patch_sha256": fixture["source"]["genesis_patch"]["sha256"],
            "patch_bytes": fixture["source"]["genesis_patch"]["bytes"]})
        exact(events[offset + 1], {"case": mode, "stage": "ready", "ledger": origin, "cache": origin,
            "query_address_hex": fixture["raw_key"][2:42]})
        rows = events[offset + 2:offset + 6]
        for row, (name, selected, should_be_available, root_error) in zip(rows, choices):
            actual_return = should_be_available or (variant == "baseline" and name.startswith("same-height-"))
            expected = {"case": mode, "stage": "cache-context-query", "name": name,
                "requested_identifier": selected, "expected_available": should_be_available,
                "returned": actual_return, "contract_mismatch": actual_return != should_be_available,
                "cache_values_used_as_state_proof": False, "state_root_error": root_error,
                "state_root": fixture["states"]["A1"]["root"] if should_be_available else "00" * 32}
            if actual_return:
                expected.update(reported_identifier=selected, chain_plasma_error="none", fused_error="none",
                                chain_plasma=row.get("chain_plasma"), fused_amount=row.get("fused_amount"))
                for field in ("chain_plasma", "fused_amount"):
                    require(type(row.get(field)) is str and re.fullmatch("0|[1-9][0-9]*", row[field]))
            exact(row, expected)
        canonical = rows[0]
        for row in rows:
            if row["returned"]:
                exact([row["chain_plasma"], row["fused_amount"]],
                      [canonical["chain_plasma"], canonical["fused_amount"]])
        query_groups.append(rows)
        require(set(events[-1]) == {"case", "stage", "images"})
        valid_images(events[-1]["images"])
    require(set(reopened[1]) == {"case", "stage", "images"})
    valid_images(reopened[1]["images"])
    exact(first[-1]["images"], reopened[1]["images"])
    exact(first[-1]["images"], reopened[-1]["images"])
    exact([{key: value for key, value in row.items() if key != "case"} for row in query_groups[0]],
          [{key: value for key, value in row.items() if key != "case"} for row in query_groups[1]])
    return {"kind": "checked-local-cache-store-identifier-context", "variant": variant,
        "event_count": len(first) + len(reopened), "query_count": 8,
        "foreign_identifier_cache_stores": 4 if variant == "baseline" else 0,
        "foreign_identifier_state_root_refusals": 4, "contract_mismatches": 4 if variant == "baseline" else 0,
        "closed_logical_store_images_unchanged": True, "consumer_result": "REFUSED",
        "backend_reexecuted": False, "private_execution_authenticated": False,
        "full_node_or_network_validity_qualified": False, "cache_value_correctness_qualified": False,
        "production_state_value_accepted": False}


HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("cache_context_corpus_preparer", HERE / "prepare_cache_store_context.py")
PREP = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(PREP)
CORPUS = "native-cache-store-context.json"
STREAMS = {
 "baseline": [
  ("initialize-and-query", "11a2b433623023a18cd12ba280f199256f4d15fed4d10230a67a1e27b3f60021", 3856),
  ("reopen-and-query", "6936b00a097d9ada7a06c34a831718169812b8dcf6e15e63d725d3f6b38362e5", 4390)],
 "candidate": [
  ("initialize-and-query", "0cfc7be1505e94a88688fc311af26046460a61f318203fc02709cec370d41c59", 3468),
  ("reopen-and-query", "c8c517733c2c476398d95ba205299aada84700cd435a32b23285ca1c407e4340", 4002)]}
BINARY_PINS = {
 "baseline": {"sha256": "a264ccd82460b77c3530495d0b1c8ec5ce43c8d82e7f632f61c9791129dd200f", "bytes": 19815442},
 "candidate": {"sha256": "fe9811cae50dbadcdfcf0d54811b83376a7ec4143bb9b0ebc555f9acaec0eda8", "bytes": 19815522}}
NATIVE_PASS_NAMES = ('TestCacheContext_BehindCacheKeepsExistingRefusal', 'TestCacheContext_ForeignHashBytes', 'TestCacheContext_HeightAndHashBothRequired', 'TestCacheContext_HistoricalAndCurrent', 'TestCacheContext_LookupErrorPrecedesCache', 'TestCacheContext_MalformedLedgerRowPrecedesCache', 'TestCacheContext_NilDependencies', 'TestCacheContext_NilLedgerSnapshot', 'TestCacheContext_ReorgChangesSelectedBranch', 'TestCacheContext_ReturnedHeightMismatch', 'TestCacheContext_RollbackRemovesFutureView', 'TestCacheContext_UnknownHeights', 'TestCandidateMomentumRollbackTargetChecksCompleteIdentifier', 'TestCandidateMomentumRollbackTargetPreflight', 'TestCandidateMomentumRollbackTargetPreflight/above', 'TestCandidateMomentumRollbackTargetPreflight/matching-frontier', 'TestCandidateMomentumRollbackTargetPreflight/maximum', 'TestCandidateMomentumRollbackTargetPreflight/nil-locker', 'TestCandidateMomentumRollbackTargetPreflight/wrong-hash', 'TestCandidateMomentumRollbackTargetPreflight/zero', 'TestCandidateMomentumRollbackTargetPreservesLookupError', 'TestCandidatePublicChainStartupClosedCacheDoesNotInsertGenesis', 'TestCandidatePublicChainStartupEmptyRealManagers', 'TestCandidatePublicChainStartupPreservesGenesisLookupError', 'TestCandidatePublicChainStartupStoppedInstanceRefusesInit', 'TestChainStopReportsEveryManagerError', 'TestChainStopStopsEveryManagerAfterCacheError', 'TestRollbackToFailureAfterPopIsUnrecoverable', 'TestRollbackToFirstPopFailureLeavesCanonicalStateCertain')

def check_corpus(document):
    require(type(document) is dict and set(document) == {"format_version", "kind", "source", "recorded_native", "scope", "variants"})
    exact(document["format_version"], 1)
    exact(document["kind"], "recorded-public-cache-store-context-comparison")
    expected_source = {
        "repository": "digitalSloth/go-zenon", "revision": PREP.P.REVISION,
        "parent_runtime_tree": PREP.PARENT_TREE, "candidate_runtime_tree": PREP.CANDIDATE_TREE,
        "parent_build_tree": PREP.BUILD_TREES["baseline"], "candidate_build_tree": PREP.BUILD_TREES["candidate"],
        "parent_source_files": 468, "candidate_source_files": 471,
        "probe": {"bytes": PREP.PROBE_BYTES, "sha256": PREP.PROBE_SHA256},
        "unit_source": {"bytes": PREP.UNIT_BYTES, "sha256": PREP.UNIT_SHA256},
        "fixture": {"bytes": PREP.R.FIXTURE_BYTES, "sha256": PREP.R.FIXTURE_SHA256}}
    exact(document["source"], expected_source)
    for variant, count in (("baseline", 468), ("candidate", 471)):
        pins = PREP.build_pins(variant)
        require(len(pins) == count and PREP.P.UTIL.reconstruct_tree(pins) == PREP.BUILD_TREES[variant])
    exact(document["scope"], {name: False for name in (
        "new_account_blocks_added", "cache_value_correctness_qualified", "full_node_or_network_validity_qualified",
        "concurrent_history_changes_qualified", "stored_row_body_hash_authenticated",
        "private_execution_or_distribution_authenticated", "accepted_header_binding",
        "runtime_state_value_acceptance", "production_qualified")})
    exact(document["recorded_native"], {
        "go_version": "go1.25.14", "platform": "darwin/arm64", "ordinary_builds": 2, "ordinary_processes": 4,
        "Go_unit_invocations": 1, "native_unit_root_count": 23, "native_unit_pass_results": 29,
        "new_context_unit_roots": 12, "prior_native_unit_pass_results": 17,
        "native_unit_pass_names": list(NATIVE_PASS_NAMES)})
    require(len(NATIVE_PASS_NAMES) == 29 and len(set(NATIVE_PASS_NAMES)) == 29)
    exact(sorted(name for name in NATIVE_PASS_NAMES if "/" not in name), PREP.roots())
    fixture_raw = PREP.selected_fixture()
    fixture = decode(fixture_raw)
    require(type(document["variants"]) is dict and set(document["variants"]) == set(PREP.VARIANTS))
    summaries, decoded = {}, {}
    for variant in PREP.VARIANTS:
        row = document["variants"][variant]
        require(type(row) is dict and set(row) == {"binary", "streams"})
        exact(row["binary"], BINARY_PINS[variant])
        require(type(row["streams"]) is list and len(row["streams"]) == 2)
        groups = []
        for stream, (mode, digest, size) in zip(row["streams"], STREAMS[variant]):
            require(type(stream) is dict and set(stream) == {"case", "sha256", "bytes", "jsonl"})
            exact([stream["case"], stream["sha256"], stream["bytes"]], [mode, digest, size])
            require(type(stream["jsonl"]) is str)
            raw = stream["jsonl"].encode()
            require(len(raw) == size and hashlib.sha256(raw).hexdigest() == digest and raw.endswith(b"\n"))
            groups.append([decode(line) for line in raw.splitlines()])
        summaries[variant] = check(groups[0], groups[1], fixture, PREP.R.FIXTURE_SHA256, variant)
        decoded[variant] = groups
    exact(decoded["baseline"][0][-1]["images"], decoded["candidate"][0][-1]["images"])
    return {"kind": "recorded-public-cache-store-context-check",
        "node_revision": PREP.P.REVISION, "parent_runtime_tree": PREP.PARENT_TREE,
        "candidate_runtime_tree": PREP.CANDIDATE_TREE, "event_count": 34, "query_count": 16,
        "baseline_context_mismatches": 4, "candidate_context_mismatches": 0,
        "foreign_identifier_state_root_refusals": 8, "recorded_ordinary_processes": 4,
        "recorded_ordinary_builds": 2, "recorded_unit_root_count": 23, "recorded_unit_pass_results": 29,
        "closed_logical_images_equal_across_variants": True,
        "fixture_sha256": PREP.R.FIXTURE_SHA256, "consumer_result": "REFUSED",
        "backend_reexecuted": False, "production_state_value_accepted": False,
        "private_execution_or_distribution_authenticated": False,
        "cache_value_correctness_qualified": False, "full_node_or_network_validity_qualified": False,
        "scope": document["scope"], "reader_inputs_sha256": {
            name: hashlib.sha256((HERE / name).read_bytes()).hexdigest()
            for name in ("prepare_cache_store_context.py", "check_cache_store_context.py")}}

def check_file(path=None):
    selected = HERE / "testdata" / CORPUS if path is None else Path(path)
    return check_corpus(decode(read(selected, 128 << 10)))

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--file")
    parser.add_argument("--source-revision")
    args = parser.parse_args(argv)
    require(args.source_revision is None or re.fullmatch("[0-9a-f]{40}", args.source_revision))
    result = check_file(args.file)
    if args.source_revision is not None:
        result["source_revision"] = args.source_revision
    print(json.dumps(result, sort_keys=True))

if __name__ == "__main__":
    main()
