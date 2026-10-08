#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Independent bounded operations, roots and proofs for synthetic NodeTree commits.

Reference generation opens only a temporary in-memory database. This checker
does not run that backend or qualify disk recovery, retention, RPC or a profile.
"""

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("candidate_filter_reference", HERE / "check_fold.py")
FOLD = importlib.util.module_from_spec(spec)
spec.loader.exec_module(FOLD)
BYTE = FOLD.BYTE
MAX_CHECKPOINTS = 64
SCOPE = {"synthetic": True, "unsigned": True, "l1_staged_applier_executed": True,
         "node_database_opened": True, "database_storage_in_memory_only": True,
         "temporary_database_closed": True, "persisted_disk_lifecycle_executed": False,
         "node_lifecycle_executed": False, "node_tests_executed": False, "rpc_executed": False,
         "profile_agreed": False, "network_activation_authenticated": False,
         "runtime_state_proof_acceptance": False}
STEPS = (("initial-empty", ()), ("stored-zero", (0,)), ("empty-then-overwrite", (-1, 1, 2)),
         ("delete-then-overwrite", (3, -2, 4)), ("empty-put-deletes", (-1,)),
         ("restore-stored-zero", (0,)), ("delete-wins", (1, -2)))


def selected_keys():
    prefix = bytes([3]) + bytes([17]) * 20
    return {"balance-a": prefix + bytes([3]) + bytes([34]) * 10,
            "balance-b": bytes([3]) + bytes([51]) * 20 + bytes([3]) + bytes([68]) * 10,
            "storage": prefix + bytes([4, 0, 255, 128]),
            "balance-prefix-only": prefix + bytes([3]), "storage-prefix-only": prefix + bytes([4]),
            "excluded-account-subprefix-0": prefix + bytes([0]),
            "excluded-mailbox": bytes([4, 1, 2]), "excluded-znn-index": bytes([8, 1, 2])}


def selected_operations(keys, numbers):
    result = []
    for key in keys.values():
        for number in numbers:
            kind = "delete" if number == -2 else "put"
            value = b"" if number < 0 else number.to_bytes(32, "big")
            result.append((kind, key, value))
    return result


def apply_operations(leaves, operations):
    # Replay against an independently maintained path/value map. Last event wins.
    for kind, key, value in operations:
        if not FOLD.filter_keeps(key):
            continue
        position = BYTE.digest(key)
        if kind == "delete" or not value:
            leaves.pop(position, None)
        else:
            leaves[position] = value


def check_observation(row, name, key, root, levels, values):
    BYTE.require(type(row) is dict and set(row) == {"name", "key", "path", "value", "present", "proof", "node_result"},
                 "invalid observation shape")
    BYTE.require(row["name"] == name and FOLD.bounded_hex(row["key"], FOLD.MAX_KEY_BYTES) == key,
                 "substituted selected query")
    position = BYTE.digest(key)
    BYTE.require(BYTE.hex_bytes(row["path"], 32) == position, "selected path differs")
    index = int.from_bytes(position, "big")
    present, value = index in values, values.get(index, b"")
    BYTE.require(type(row["present"]) is bool and row["present"] == present, "selected presence differs")
    BYTE.require(FOLD.bounded_hex(row["value"], FOLD.MAX_VALUE_BYTES) == value, "selected value differs")
    proof = BYTE.hex_bytes(row["proof"])
    BYTE.require(proof == BYTE.canonical_proof(levels, values, position), "canonical node proof bytes differ")
    BYTE.require(row["node_result"] == BYTE.proof_result(root, position, value, proof, present) == "match",
                 "independent node verdict differs")
    typed = name in ("balance-a", "balance-b")
    return {"name": name, "present": present, "value_bytes": len(value),
            "typed_balance": {"present": present, "amount": str(int.from_bytes(value, "big"))} if typed else None,
            "unsupported_typed_query_refused": not typed}


def check_corpus(document):
    BYTE.require(type(document) is dict and set(document) == {"format_version", "kind", "backend", "source", "scope", "selected_keys", "checkpoints"},
                 "invalid applier corpus shape")
    BYTE.require(type(document["format_version"]) is int and document["format_version"] == 1, "unsupported applier format")
    BYTE.require(document["kind"] == "candidate-l1-applier-research" and document["backend"] == "NodeTree", "wrong applier reference")
    BYTE.require(document["source"] == {"repository": "https://github.com/digitalSloth/go-zenon",
                                        "revision": BYTE.NODE_REVISION, "tree": BYTE.NODE_TREE}, "wrong source pin")
    BYTE.require(type(document["scope"]) is dict and document["scope"] == SCOPE and
                 all(type(value) is bool for value in document["scope"].values()), "unsupported applier scope claim")
    keys = selected_keys()
    selected = document["selected_keys"]
    BYTE.require(type(selected) is list and len(selected) == len(keys), "wrong selected key inventory")
    for row, (name, key) in zip(selected, keys.items()):
        BYTE.require(type(row) is dict and set(row) == {"name", "key"} and row["name"] == name, "selected key inventory differs")
        BYTE.require(FOLD.bounded_hex(row["key"], FOLD.MAX_KEY_BYTES) == key, "selected key bytes differ")
    checkpoints = document["checkpoints"]
    BYTE.require(type(checkpoints) is list and len(checkpoints) <= MAX_CHECKPOINTS and len(checkpoints) == len(STEPS),
                 "wrong checkpoint inventory or limit")
    leaves, decisions, count, matched, present_count = {}, [], 0, 0, 0
    for height, (checkpoint, (name, numbers)) in enumerate(zip(checkpoints, STEPS)):
        BYTE.require(type(checkpoint) is dict and set(checkpoint) == {"name", "height", "hash", "input", "root", "observations"},
                     "invalid checkpoint shape")
        BYTE.require(checkpoint["name"] == name and type(checkpoint["height"]) is int and checkpoint["height"] == height,
                     "selected checkpoint identity differs")
        identifier = BYTE.ZERO if height == 0 else BYTE.digest(("synthetic-l1-applier-v1/" + name).encode("ascii"))
        BYTE.require(BYTE.hex_bytes(checkpoint["hash"], 32) == identifier, "synthetic identifier hash differs")
        operations = FOLD.operations(checkpoint["input"])
        BYTE.require(operations == selected_operations(keys, numbers), "selected operation sequence differs")
        apply_operations(leaves, operations)
        levels, values = BYTE.tree_levels([{"path": position.hex(), "value": value.hex()} for position, value in leaves.items()])
        root = levels[0].get(0, BYTE.ZERO)
        BYTE.require(BYTE.hex_bytes(checkpoint["root"], 32) == root, "independent committed root differs")
        observations = checkpoint["observations"]
        BYTE.require(type(observations) is list and len(observations) == len(keys), "wrong selected observation inventory")
        rows = [check_observation(row, selected_name, key, root, levels, values)
                for row, (selected_name, key) in zip(observations, keys.items())]
        count += len(operations)
        matched += len(rows)
        present_count += sum(row["present"] for row in rows)
        decisions.append({"name": name, "height": height, "input_operations": len(operations),
                          "leaf_count": len(leaves), "root": root.hex(), "observations": rows})
    return {"checkpoint_decisions": decisions, "selected_keys": len(keys), "checkpoints": len(decisions),
            "commits": len(decisions) - 1, "input_operations": count, "node_proof_comparisons": matched,
            "present_observations": present_count, "absent_observations": matched - present_count,
            "typed_balance_research_observations": len(decisions) * 2,
            "unsupported_typed_query_refusals": len(decisions) * (len(keys) - 2),
            "reference_staged_applier_executed": True, "reference_database_storage_in_memory_only": True,
            "persisted_disk_lifecycle_qualified": False, "node_lifecycle_qualified": False,
            "production_acceptance_enabled": False, "profile_agreed": False, "network_activation_authenticated": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, default=HERE / "testdata/candidate-l1-applier.json")
    parser.add_argument("--source-revision")
    args = parser.parse_args(argv)
    if args.source_revision is not None:
        BYTE.require(len(args.source_revision) == 40 and all(c in "0123456789abcdef" for c in args.source_revision), "invalid source revision")
    raw, document = BYTE.read_corpus(args.corpus)
    report = check_corpus(document)
    report.update({"source_revision": args.source_revision, "corpus_sha256": hashlib.sha256(raw).hexdigest(),
                   "node_revision": BYTE.NODE_REVISION, "node_tree": BYTE.NODE_TREE})
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError, RecursionError):
        print("Candidate L1 applier check failed; retain the original fixture and inspect locally.", file=sys.stderr)
        sys.exit(1)
