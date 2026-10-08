#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Independent finite startup observations and retained-root provenance checks.

This checks offline fixtures. It never opens the node backend. The selected
chain input and expected state are independent of the reference observations;
readiness and a height-only root lookup cannot select a consumer's context.
"""

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("startup_rpc_oracle", HERE / "check_rpc_methods.py")
RPC = importlib.util.module_from_spec(spec)
spec.loader.exec_module(RPC)
BYTE = RPC.BYTE
MAX_CASES = 16
NOT_READY = "state tree: not yet built to the chain frontier"
WRONG_ANCESTRY = ("the state tree's state is incorrect. "
                  "You can fix the problem by removing the state-tree database manually.")
SCOPE = {"synthetic": True, "unsigned": True, "actual_chain_component_Init_executed": True,
         "actual_chain_stateTree_executed": True, "actual_momentum_store_executed": True,
         "recording_manager_cache_genesis_inputs": True, "small_temporary_disk_LevelDB": True,
         "databases_closed_and_removed": True, "controlled_clean_reopen_executed": True,
         "component_init_messages_discarded": True, "chain_Start_executed": False,
         "background_build_executed": False, "full_node_started": False, "node_tests_executed": False,
         "network_execution": False, "RPC_executed": False, "signing": False, "transactions": False,
         "crash_recovery_qualified": False, "pruning_qualified": False,
         "retention_resource_budgets_qualified": False, "header_authentication_executed": False,
         "profile_agreed": False, "network_activation_authenticated": False,
         "runtime_state_proof_acceptance": False}


def same_types_and_bytes(actual, expected):
    try:
        RPC.strict_equal(actual, expected)
    except ValueError:
        return False
    return True


def selected_inputs():
    rows = (("empty-short", "A", 0, "A", 2, 1),
            ("empty-tail-bound", "A", 0, "A", 10, 1),
            ("empty-tail-plus-one", "A", 0, "A", 11, 1),
            ("matching-prebuild", "A", 2, "A", 2, 1),
            ("same-height-other-hash", "A", 2, "B", 2, 1),
            ("below-matching-ancestor", "A", 1, "A", 2, 1),
            ("below-other-ancestor", "X", 1, "A", 2, 1),
            ("above-matching-retained", "A", 3, "A", 2, 1),
            ("above-divergent-retained", "A", 3, "B", 2, 1),
            ("reopened-divergent-retained", "A", 3, "B", 2, 2))
    keys = ("name", "seed_fork", "seed_height", "chain_fork", "chain_height", "rounds")
    return [dict(zip(keys, row)) for row in rows]


def identifier(fork, height):
    BYTE.require(fork in ("A", "B", "X") and type(height) is int and 1 <= height <= 11,
                 "unselected synthetic identifier")
    if fork == "B" and height == 1:
        fork = "A"
    return {"hash": BYTE.digest(("synthetic-chain-startup-v1/%s/%d" % (fork, height)).encode("ascii")).hex(),
            "height": height}


def selected_key(missing=False):
    BYTE.require(type(missing) is bool, "invalid selected key kind")
    return BYTE.balance_key("11" * 20, ("44" if missing else "22") * 10)


def state_bytes(fork, height):
    BYTE.require(type(height) is int and 1 <= height <= 99 and fork in ("A", "B", "X"),
                 "unselected synthetic state")
    number = 22 if fork == "B" and height == 2 else 91 if fork == "X" else height
    value = number.to_bytes(32, "big")
    levels, values = BYTE.tree_levels([{"path": BYTE.digest(selected_key()).hex(), "value": value.hex()}])
    return levels[0].get(0, BYTE.ZERO), value, levels, values


def expected_round(item, number):
    # Independent source-flow model: a large gap returns before catchUp; equal
    # heights compare hashes; a below-frontier tree checks its ancestor. The
    # above-frontier branch truncates by height without a target hash/root check.
    target = identifier(item["chain_fork"], item["chain_height"])
    gap = item["seed_height"] == 0 and item["chain_height"] == 11
    invalid = item["name"] in ("same-height-other-hash", "below-other-ancestor")
    ready = not gap and not invalid
    if gap:
        retained = {"height": 0, "hash": "00" * 32}
    elif invalid:
        retained = identifier(item["seed_fork"], item["seed_height"])
    else:
        retained = target
    trace = [{"method": "Frontier"} for _ in range(5 if gap else 6)]
    if item["name"] in ("empty-short", "empty-tail-bound", "below-matching-ancestor"):
        for h in range(item["seed_height"] + 1, item["chain_height"] + 1):
            trace.append({"method": "GetPatch", "identifier": identifier(item["chain_fork"], h)})
    trace.append({"method": "Stop"})
    # All successful reference roots at height two come from A, including the
    # divergent rollback and its clean reopen. B's independently selected value
    # remains 22, so those observations are explicitly refused below.
    root, value, levels, values = state_bytes("A", item["chain_height"])
    computed = state_bytes("A", 99)[0]
    wrong = identifier("X", item["chain_height"])
    queries = []
    for name in ("root", "root-wrong-hash", "balance", "balance-wrong-hash", "absent-token", "compute"):
        is_proof = name in ("balance", "balance-wrong-hash", "absent-token")
        key = selected_key(name == "absent-token") if is_proof else None
        row = {"name": name, "identifier": wrong if "wrong-hash" in name else target,
               "key": None if key is None else key.hex(), "root": None, "value": None,
               "proof": None, "error": None if ready else NOT_READY}
        if is_proof and ready:
            row["value"] = None if name == "absent-token" else value.hex()
            row["proof"] = BYTE.canonical_proof(levels, values, BYTE.digest(key)).hex()
        elif not is_proof:
            row["root"] = (computed if name == "compute" and ready else root if ready else BYTE.ZERO).hex()
        queries.append(row)
    return {"round": number, "init_error": WRONG_ANCESTRY if invalid else None, "ready": ready,
            "selected_identifier": target, "retained_frontier": retained, "queries": queries,
            "manager_trace": trace, "cache_trace": ["DB", "Stop"],
            "genesis_trace": ["GetGenesisMomentum", "GetSporkAddress"]}


def consumer_decision(observation, selected_identifier, selected_root, selected_value):
    BYTE.require(type(selected_root) is bytes and len(selected_root) == 32 and
                 type(selected_value) is bytes and len(selected_value) == 32, "invalid independent selection")
    if observation["init_error"] is not None or observation["ready"] is not True:
        return "reference_not_ready"
    if not same_types_and_bytes(observation["selected_identifier"], selected_identifier):
        return "selected_identifier_refusal"
    root, balance = observation["queries"][0], observation["queries"][2]
    if not same_types_and_bytes(root["identifier"], selected_identifier) or not same_types_and_bytes(balance["identifier"], selected_identifier):
        return "selected_identifier_refusal"
    if root["error"] is not None or balance["error"] is not None:
        return "reference_error"
    if BYTE.hex_bytes(root["root"], 32) != selected_root:
        return "retained_root_provenance_refusal"
    if BYTE.hex_bytes(balance["key"], 32) != selected_key() or BYTE.hex_bytes(balance["value"], 32) != selected_value:
        return "selected_value_refusal"
    proof = BYTE.hex_bytes(balance["proof"])
    if BYTE.proof_result(selected_root, BYTE.digest(selected_key()), selected_value, proof, True) != "match":
        return "proof_refusal"
    return "synthetic_selected_state_match"


def check_corpus(document):
    BYTE.require(type(document) is dict and set(document) == {"format_version", "kind", "source", "scope", "cases"},
                 "invalid startup corpus shape")
    BYTE.require(type(document["format_version"]) is int and document["format_version"] == 1 and
                 document["kind"] == "candidate-chain-startup-research", "invalid startup corpus kind")
    BYTE.require(same_types_and_bytes(document["source"], {"repository": "https://github.com/digitalSloth/go-zenon",
                 "revision": BYTE.NODE_REVISION, "tree": BYTE.NODE_TREE}), "wrong selected node source")
    BYTE.require(same_types_and_bytes(document["scope"], SCOPE), "wrong startup execution boundary")
    inputs = selected_inputs()
    BYTE.require(type(document["cases"]) is list and len(document["cases"]) <= MAX_CASES and
                 len(document["cases"]) == len(inputs), "unselected startup cases")
    counts, rounds, reads, patches = {}, 0, 0, 0
    for row, item in zip(document["cases"], inputs):
        BYTE.require(type(row) is dict and set(row) == {"input", "rounds"} and same_types_and_bytes(row["input"], item),
                     "startup input was substituted")
        BYTE.require(type(row["rounds"]) is list and len(row["rounds"]) == item["rounds"], "startup round inventory differs")
        for number, observation in enumerate(row["rounds"], 1):
            expected = expected_round(item, number)
            BYTE.require(same_types_and_bytes(observation, expected), "reference startup bytes, results or traces differ")
            selected_root, selected_value, _, _ = state_bytes(item["chain_fork"], item["chain_height"])
            decision = consumer_decision(observation, identifier(item["chain_fork"], item["chain_height"]), selected_root, selected_value)
            counts[decision] = counts.get(decision, 0) + 1
            rounds += 1
            reads += len(expected["queries"])
            patches += sum(event["method"] == "GetPatch" for event in expected["manager_trace"])
    return {"startup_cases": len(inputs), "component_initializations": rounds, "read_api_observations": reads,
            "patch_lookups": patches, "consumer_decision_counts": counts,
            "reference_execution_in_checker": False, "native_reference_CGO_qualified": False,
            "authenticated_retained_version_provenance_qualified": False,
            "crash_recovery_qualified": False, "retention_resource_budgets_qualified": False,
            "accepted_VerifiedState_binding_qualified": False, "profile_agreed": False,
            "network_activation_authenticated": False, "production_acceptance_enabled": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, default=HERE / "testdata/candidate-chain-startup.json")
    parser.add_argument("--source-revision")
    args = parser.parse_args(argv)
    if args.source_revision is not None:
        BYTE.require(len(args.source_revision) == 40 and all(c in "0123456789abcdef" for c in args.source_revision),
                     "invalid source revision")
    raw, document = BYTE.read_corpus(args.corpus)
    report = check_corpus(document)
    report.update({"source_revision": args.source_revision, "corpus_sha256": hashlib.sha256(raw).hexdigest(),
                   "node_revision": BYTE.NODE_REVISION, "node_tree": BYTE.NODE_TREE})
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError, RecursionError):
        print("Candidate chain startup check failed; retain the original fixture and inspect locally.", file=sys.stderr)
        sys.exit(1)
