#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Check a finite experimental startup quarantine comparison without a node.

A complete selected state machine and byte oracle precede the observations.
This unsigned component evidence does not repair retained hash identity, qualify
the current complete node, authenticate a header or enable state-value proofs.
"""
import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys

HERE = Path(__file__).resolve().parent


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, HERE / file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


START = load("quarantine_startup_bytes", "check_chain_startup.py")
BYTE = START.BYTE
PREP = load("quarantine_source_contract", "prepare_startup_quarantine.py")
VARIANTS = PREP.VARIANTS
BLOCKED = "state tree: ahead frontier requires authenticated retained-version recovery"
PRODUCER_INPUTS = ("startup_quarantine_probe_test.go", "prepare_startup_quarantine.py",
                  "startup-quarantine-patch.json", "source-pins.json", "regenerate.py", "go.mod", "go.sum")
SCOPE = {
    "synthetic_unsigned_chain_cache_genesis_inputs": True,
    "actual_component_Init_and_read_APIs_recorded_locally": True,
    "complete_logical_database_bytes_checked": True,
    "clean_close_and_reopen_recorded": True,
    "previously_ready_component_reinitialization_recorded": True,
    "conservative_ahead_rollback_availability_loss": True,
    "only_Init_changed_in_experimental_node_variant": True,
    "upstream_node_test_suite_executed": False,
    "full_node_or_Chain_Start_executed": False,
    "background_builder_executed": False,
    "network_or_RPC_executed": False,
    "wallet_signing_transactions_or_deployment": False,
    "reference_execution_in_native_fixture_CI": False,
    "execution_provenance_authenticated": False,
    "complete_current_node_revision_qualified": False,
    "low_level_height_only_APIs_repaired": False,
    "authenticated_retained_version_provenance_qualified": False,
    "runtime_reorg_repair_qualified": False,
    "accepted_header_or_profile_binding_qualified": False,
    "physical_storage_crash_or_resource_budgets_qualified": False,
    "production_state_value_accepted": False,
}


def exact(actual, expected):
    START.RPC.strict_equal(actual, expected)


def selections():
    rows = [dict(row, prime_ready=False) for row in START.selected_inputs()]
    rows += [
        dict(name="previously-ready-divergent", seed_fork="A", seed_height=3,
             chain_fork="B", chain_height=2, rounds=1, prime_ready=True),
        dict(name="previously-ready-same-height-other-hash", seed_fork="A", seed_height=3,
             chain_fork="B", chain_height=3, rounds=1, prime_ready=True),
    ]
    return rows


def records(versions, frontier):
    # This fixture has one selected raw balance key. Physical leaves, refcounts,
    # height records and the full frontier are independently serialized here.
    key_path = BYTE.digest(START.selected_key())
    rows = {b"\x05": b"\x02"}
    refs = {}
    for height, fork in sorted(versions.items()):
        _, value, _, _ = START.state_bytes(fork, height)
        leaf = BYTE.digest(key_path + value)
        rows[b"\x01" + leaf] = b"\x00" + key_path + value
        refs[leaf] = refs.get(leaf, 0) + 1
        rows[b"\x03" + height.to_bytes(8, "big")] = leaf
    for node, count in refs.items():
        rows[b"\x02" + node] = count.to_bytes(8, "big")
    if frontier["height"]:
        rows[b"\x00"] = bytes.fromhex(frontier["hash"]) + frontier["height"].to_bytes(8, "big")
    return [{"key": key.hex(), "value": value.hex()} for key, value in sorted(rows.items())]


def queries(target, versions, ready):
    result = []
    selected_height = target["height"]
    if ready:
        fork = versions[selected_height]
        root, value, levels, values = START.state_bytes(fork, selected_height)
        computed = START.state_bytes("A", 99)[0]
    for name in ("root", "root-wrong-hash", "balance", "balance-wrong-hash", "absent-token", "compute"):
        is_proof = name in ("balance", "balance-wrong-hash", "absent-token")
        key = START.selected_key(name == "absent-token") if is_proof else None
        row = {"name": name, "identifier": START.identifier("X", selected_height) if "wrong-hash" in name else target,
               "key": key.hex() if key is not None else None, "root": None, "value": None,
               "proof": None, "error": None if ready else START.NOT_READY}
        if not is_proof:
            row["root"] = (computed if ready and name == "compute" else root if ready else BYTE.ZERO).hex()
        elif ready:
            row["value"] = None if name == "absent-token" else value.hex()
            row["proof"] = BYTE.canonical_proof(levels, values, BYTE.digest(key)).hex()
        result.append(row)
    return result


def phase(variant, versions, frontier, ready_before, fork, height, prime, final):
    before = records(versions, frontier)
    target = START.identifier(fork, height)
    ready = False if variant == "startup-quarantine" else ready_before
    error, lookups = None, []
    ahead = frontier["height"] > height
    large_gap = height > frontier["height"] and height - frontier["height"] > 10
    blocked = variant == "startup-quarantine" and ahead
    if blocked:
        error = BLOCKED
    elif large_gap:
        pass
    else:
        invalid = ((frontier["height"] == height and frontier["hash"] != target["hash"]) or
                   (0 < frontier["height"] < height and frontier != START.identifier(fork, frontier["height"])))
        if invalid:
            error = START.WRONG_ANCESTRY
        else:
            if ahead:
                versions = {h: owner for h, owner in versions.items() if h <= height}
            elif frontier["height"] < height:
                for h in range(frontier["height"] + 1, height + 1):
                    versions[h] = fork
                    lookups.append({"method": "GetPatch", "identifier": START.identifier(fork, h)})
            frontier, ready = target, True
    trace = [{"method": "Frontier"} for _ in range(5 if blocked or large_gap else 6)] + lookups
    if final:
        trace.append({"method": "Stop"})
    observation = {"prime": prime, "init_error": error, "ready": ready,
                   "selected_identifier": target, "retained_frontier": frontier,
                   "queries": queries(target, versions, ready),
                   "records_before": before, "records_after": records(versions, frontier),
                   "manager_trace": trace, "cache_trace": ["DB", "Stop"] if final else ["DB"],
                   "genesis_trace": ["GetGenesisMomentum", "GetSporkAddress"]}
    return observation, versions, frontier, ready


def expected_variant(variant):
    BYTE.require(variant in VARIANTS, "select a source variant")
    cases = []
    for item in selections():
        versions = {h: item["seed_fork"] for h in range(1, item["seed_height"] + 1)}
        frontier = START.identifier(item["seed_fork"], item["seed_height"]) if versions else {"height": 0, "hash": "00" * 32}
        rounds = []
        for number in range(1, item["rounds"] + 1):
            ready, phases = False, []
            if item["prime_ready"]:
                row, versions, frontier, ready = phase(variant, versions, frontier, ready,
                    item["seed_fork"], item["seed_height"], True, False)
                phases.append(row)
            row, versions, frontier, ready = phase(variant, versions, frontier, ready,
                item["chain_fork"], item["chain_height"], False, True)
            phases.append(row)
            rounds.append({"round": number, "phases": phases, "records_after_close_reopen": records(versions, frontier)})
        cases.append({"input": item, "rounds": rounds})
    return {"format_version": 1, "kind": "candidate-startup-quarantine-research", "variant": variant, "cases": cases}


def producer_pins():
    return {name: hashlib.sha256((HERE / name).read_bytes()).hexdigest() for name in PRODUCER_INPUTS}


def expected_document():
    return {"format_version": 1, "kind": "candidate-startup-quarantine-comparison",
            "source": {"repository": "https://github.com/digitalSloth/go-zenon",
                       "base_revision": BYTE.NODE_REVISION, "base_tree": BYTE.NODE_TREE,
                       "baseline_state_tree_sha256": PREP.BASE_FILE_SHA256,
                       "guarded_state_tree_sha256": PREP.GUARDED_FILE_SHA256,
                       "guarded_node_tree_without_probe": PREP.GUARDED_NODE_TREE,
                       "producer_inputs": producer_pins()},
            "scope": SCOPE, "consumer_result": "REFUSED",
            "variants": {variant: expected_variant(variant) for variant in VARIANTS}}


def check_corpus(document):
    expected = expected_document()
    exact(document, expected)
    variants = document["variants"]
    phases = {variant: [p for c in value["cases"] for r in c["rounds"] for p in r["phases"]]
              for variant, value in variants.items()}
    BYTE.require(all(len(rows) == 15 for rows in phases.values()), "phase inventory differs")
    guarded = phases["startup-quarantine"]
    BYTE.require(sum(row["init_error"] == BLOCKED for row in guarded) == 5, "ahead refusals differ")
    for row in guarded:
        if row["init_error"] is not None:
            BYTE.require(row["ready"] is False and row["records_before"] == row["records_after"],
                         "quarantine changed a refused database or retained readiness")
    return {"startup_quarantine_variants": 2, "cases_per_variant": 12,
            "component_initializations": 30, "read_api_observations": 180,
            "complete_logical_database_snapshots": 86,
            "ahead_refusals_in_guarded_variant": 5,
            "previously_ready_refusals_in_guarded_variant": 2,
            "explicit_conservative_availability_loss": True,
            "reference_execution_in_checker": False,
            "low_level_height_only_APIs_repaired": False,
            "authenticated_retained_version_provenance_qualified": False,
            "accepted_VerifiedState_binding_qualified": False,
            "production_acceptance_enabled": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, default=HERE / "testdata/candidate-startup-quarantine.json")
    parser.add_argument("--source-revision")
    args = parser.parse_args(argv)
    raw, document = BYTE.read_corpus(args.corpus)
    result = check_corpus(document)
    if args.source_revision is not None:
        BYTE.require(type(args.source_revision) is str and len(args.source_revision) == 40 and
                     all(c in "0123456789abcdef" for c in args.source_revision), "invalid source label")
        result["source_revision"] = args.source_revision
    result["corpus_sha256"] = hashlib.sha256(raw).hexdigest()
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, IndexError):
        print("Startup quarantine fixture refused; preserve failures and disabled production acceptance.", file=sys.stderr)
        sys.exit(1)

