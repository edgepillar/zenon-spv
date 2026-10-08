#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Independent finite process-exit/reopen bytes, versions and logical storage.

The checker never executes a node/backend or child process. Small synthetic
fixtures cannot qualify power loss, production recovery or resource budgets.
"""

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("disk_byte_oracle", HERE / "check.py")
BYTE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(BYTE)
NO_VERSION = "trie: no such version"
MAX_CASES = 8
SCOPE = {"synthetic": True, "unsigned": True, "actual_NodeTree_disk_APIs_executed": True,
         "small_owned_temporary_disk_LevelDB": True, "controlled_process_exit_executed": True,
         "child_defer_close_marker_checked": True, "controlled_clean_close_control": True,
         "controlled_clean_reopen_executed": True, "logical_storage_records_measured": True,
         "owned_databases_removed": True, "chain_component_Init_executed": False,
         "chain_Start_executed": False, "background_build_executed": False, "full_node_started": False,
         "node_tests_executed": False, "network_execution": False, "RPC_executed": False,
         "signing": False, "transactions": False, "power_loss_qualified": False,
         "torn_write_qualified": False, "production_crash_recovery_qualified": False,
         "authenticated_retained_version_provenance_qualified": False,
         "realistic_retention_resource_budgets_qualified": False, "header_authentication_executed": False,
         "profile_agreed": False, "network_activation_authenticated": False,
         "runtime_state_proof_acceptance": False}


def exact(actual, expected):
    BYTE.require(type(actual) is type(expected), "disk fixture scalar/container type differs")
    if type(expected) is dict:
        BYTE.require(set(actual) == set(expected), "disk fixture fields differ")
        for key, value in expected.items():
            exact(actual[key], value)
    elif type(expected) is list:
        BYTE.require(len(actual) == len(expected), "disk fixture inventory differs")
        for a, b in zip(actual, expected):
            exact(a, b)
    else:
        BYTE.require(actual == expected, "disk fixture bytes or selected operation differ")


def identifier(fork, height):
    BYTE.require(fork in ("A", "X") and type(height) is int and 0 <= height <= 4,
                 "unselected synthetic disk identifier")
    text = "synthetic-disk-lifecycle-v1/%s/%d" % (fork, height)
    return {"height": height, "hash": "00" * 32 if height == 0 else BYTE.digest(text.encode("ascii")).hex()}


def selected_key(missing=False):
    BYTE.require(type(missing) is bool, "invalid synthetic disk key selection")
    return BYTE.balance_key("11" * 20, ("44" if missing else "22") * 10)


def state_bytes(height):
    BYTE.require(type(height) is int and 0 <= height <= 4, "unselected synthetic disk state")
    value = height.to_bytes(32, "big")
    leaves = [] if height == 0 else [{"path": BYTE.digest(selected_key()).hex(), "value": value.hex()}]
    levels, values = BYTE.tree_levels(leaves)
    return levels[0].get(0, BYTE.ZERO), value, levels, values


def selections():
    # Independent finite selections: staged writes are volatile; returned commit,
    # truncate and prune calls have the observed versions after this process exit.
    # This is not an assertion about in-flight writes or power-loss durability.
    return (("exit-after-open", 2, "after-open", 2, [1, 2], ["OpenFile", "NewNodeTree"]),
            ("exit-after-stage", 2, "after-stage", 2, [1, 2], ["OpenFile", "NewNodeTree", "Update"]),
            ("exit-after-commit", 2, "after-commit", 3, [1, 2, 3], ["OpenFile", "NewNodeTree", "Update", "Commit"]),
            ("exit-after-truncate", 3, "after-truncate", 2, [1, 2], ["OpenFile", "NewNodeTree", "Truncate"]),
            ("exit-after-prune", 3, "after-prune", 3, [3], ["OpenFile", "NewNodeTree", "Prune"]),
            ("clean-close", 2, "after-commit", 3, [1, 2, 3], ["OpenFile", "NewNodeTree", "Update", "Commit"]))


def expected_cases():
    expected = []
    for name, seed, boundary, target, heights, trace in selections():
        count = len(heights)
        # Actual NodeTree key/value layout: frontier 1+40, format 1+1;
        # one distinct leaf 33+65, refcount 33+8 and version 9+32 per height.
        storage = {"records": 2 + 3 * count, "key_bytes": 2 + 75 * count, "value_bytes": 41 + 105 * count,
                   "family_counts": {"frontier": 1, "node": count, "refcount": count, "version": count, "format": 1},
                   "retained_heights": heights}
        reads = []
        for height in range(5):
            root, value, levels, values = state_bytes(height)
            retained = height == 0 or height in heights
            for query in ("root", "root-other-hash", "balance", "absent-token"):
                key = selected_key(query == "absent-token")
                row = {"name": query, "identifier": identifier("X" if query == "root-other-hash" else "A", height),
                       "key": None, "root": None, "value": None, "proof": None,
                       "error": None if retained else NO_VERSION}
                if query.startswith("root"):
                    row["root"] = (root if retained else BYTE.ZERO).hex()
                else:
                    row["key"] = key.hex()
                    if retained:
                        row["proof"] = BYTE.canonical_proof(levels, values, BYTE.digest(key)).hex()
                        row["value"] = value.hex() if height > 0 and query == "balance" else None
                reads.append(row)
        expected.append({"input": {"name": name, "seed_height": seed, "boundary": boundary},
                         "child_exit": 0 if name == "clean-close" else 73,
                         "child_clean_close_marker": name == "clean-close",
                         "child_observation": {"boundary": boundary, "method_trace": trace,
                                               "frontier_before_exit": identifier("A", target)},
                         "rounds": [{"round": r, "frontier": identifier("A", target),
                                     "storage": storage, "reads": reads} for r in (1, 2)]})
    return expected


def check_corpus(document):
    BYTE.require(type(document) is dict and set(document) == {"format_version", "kind", "backend", "source", "scope", "cases"},
                 "invalid disk lifecycle corpus shape")
    exact(document["format_version"], 1)
    exact(document["kind"], "candidate-disk-lifecycle-research")
    exact(document["backend"], "NodeTree")
    exact(document["source"], {"repository": "https://github.com/digitalSloth/go-zenon",
                              "revision": BYTE.NODE_REVISION, "tree": BYTE.NODE_TREE})
    exact(document["scope"], SCOPE)
    BYTE.require(type(document["cases"]) is list and len(document["cases"]) <= MAX_CASES,
                 "disk lifecycle case bound exceeded")
    exact(document["cases"], expected_cases())
    rounds = reads = errors = present = absent = records = key_bytes = value_bytes = 0
    for case in document["cases"]:
        for observed in case["rounds"]:
            rounds += 1
            storage = observed["storage"]
            records += storage["records"]
            key_bytes += storage["key_bytes"]
            value_bytes += storage["value_bytes"]
            for row in observed["reads"]:
                reads += 1
                if row["error"] is not None:
                    errors += 1
                elif row["name"] in ("balance", "absent-token"):
                    root, _, _, _ = state_bytes(row["identifier"]["height"])
                    value = b"" if row["value"] is None else BYTE.hex_bytes(row["value"], 32)
                    is_present = row["value"] is not None
                    BYTE.require(BYTE.proof_result(root, BYTE.digest(BYTE.hex_bytes(row["key"], 32)), value,
                                                  BYTE.hex_bytes(row["proof"]), is_present) == "match",
                                 "reopened canonical proof does not match independently selected state")
                    present += int(is_present)
                    absent += int(not is_present)
    return {"disk_cases": len(document["cases"]), "controlled_abrupt_child_exits": 5,
            "clean_child_close_controls": 1, "reopen_rounds": rounds, "read_api_observations": reads,
            "unretained_version_errors": errors, "recovered_inclusion_proof_matches": present,
            "recovered_absence_proof_matches": absent, "logical_storage_records_all_rounds": records,
            "logical_storage_key_bytes_all_rounds": key_bytes, "logical_storage_value_bytes_all_rounds": value_bytes,
            "other_hash_query_slots": 60, "different_hash_query_slots": 48,
            "reference_backend_execution_in_checker": False, "native_reference_node_execution": False,
            "native_reference_CGO_qualified": False, "power_loss_qualified": False,
            "torn_write_qualified": False, "production_crash_recovery_qualified": False,
            "authenticated_retained_version_provenance_qualified": False,
            "realistic_retention_resource_budgets_qualified": False,
            "accepted_VerifiedState_binding_qualified": False, "profile_agreed": False,
            "network_activation_authenticated": False, "production_acceptance_enabled": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, default=HERE / "testdata/candidate-disk-lifecycle.json")
    parser.add_argument("--source-revision")
    args = parser.parse_args(argv)
    raw, document = BYTE.read_corpus(args.corpus)
    report = check_corpus(document)
    report.update({"source_revision": args.source_revision, "corpus_sha256": hashlib.sha256(raw).hexdigest(),
                   "node_revision": BYTE.NODE_REVISION, "node_tree": BYTE.NODE_TREE})
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError):
        print("Candidate disk lifecycle conformance failed; production acceptance remains disabled.", file=sys.stderr)
        sys.exit(1)
