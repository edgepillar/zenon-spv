#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Independent operation oracle for the candidate's L1 family filter only.

This bounds synthetic fixture work. It does not execute the later empty-to-delete
applier, validate a ledger state, open a tree/database or enable a proof profile.
"""

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("candidate_byte_reference", HERE / "check.py")
BYTE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(BYTE)
MAX_KEY_BYTES = 1024
MAX_VALUE_BYTES = 4096
MAX_CASES = 128
MAX_OPERATIONS = 64
SCOPE = {"synthetic": True, "unsigned": True, "l1_fold_filter_api_executed": True,
         "l1_staged_applier_executed": False, "node_database_opened": False,
         "node_lifecycle_executed": False, "node_tests_executed": False, "rpc_executed": False,
         "profile_agreed": False, "network_activation_authenticated": False,
         "runtime_state_proof_acceptance": False}


def selected_keys():
    account = bytearray(22)
    account[0], account[1:21] = 3, bytes([17]) * 20

    def family(sub, tail=b""):
        key = account.copy()
        key[21] = sub
        return bytes(key) + tail

    keys = {"balance-32": family(3, bytes([34]) * 10), "storage": family(4, bytes([0, 255, 128])),
            "balance-prefix-only-22": family(3), "storage-prefix-only-22": family(4),
            "balance-short-token-31": family(3, bytes([34]) * 9),
            "balance-long-token-33": family(3, bytes([34]) * 11),
            "empty": b"", "account-prefix": bytes([3]), "partial-address": bytes(account[:11]),
            "address-without-subprefix": bytes(account[:21]), "mailbox": bytes([4, 1, 2]),
            "znn-index": bytes([8, 1, 2])}
    keys.update({"account-subprefix-" + str(sub): family(sub, bytes([1])) for sub in (0, 1, 2, 6, 7)})
    keys.update({"momentum-history-" + str(top): bytes([top, 1]) for top in (0, 1, 2, 5, 9)})
    return keys


def bounded_hex(value, maximum):
    BYTE.require(type(value) is str and len(value) <= maximum * 2, "fixture byte limit or type")
    return BYTE.hex_bytes(value)


def filter_keeps(key):
    BYTE.require(type(key) is bytes and len(key) <= MAX_KEY_BYTES, "invalid bounded key bytes")
    return len(key) >= 22 and key[0] == 3 and key[21] in (3, 4)


def operation(row):
    BYTE.require(type(row) is dict and set(row) == {"kind", "key", "value"}, "invalid operation shape")
    BYTE.require(type(row["kind"]) is str and row["kind"] in ("put", "delete"), "invalid operation kind")
    key, value = bounded_hex(row["key"], MAX_KEY_BYTES), bounded_hex(row["value"], MAX_VALUE_BYTES)
    BYTE.require(row["kind"] != "delete" or value == b"", "delete carries a value")
    return row["kind"], key, value


def operations(rows):
    BYTE.require(type(rows) is list and len(rows) <= MAX_OPERATIONS, "fixture operation limit or type")
    return [operation(row) for row in rows]


def check_case(case, expected_key):
    BYTE.require(type(case) is dict and set(case) == {"name", "key", "input", "output"}, "invalid case shape")
    key = bounded_hex(case["key"], MAX_KEY_BYTES)
    BYTE.require(key == expected_key, "substituted selected fixture key")
    inputs, outputs = operations(case["input"]), operations(case["output"])
    BYTE.require(inputs == [("put", key, bytes(32)), ("put", key, b""), ("delete", key, b"")],
                 "selected synthetic patch differs")
    expected = [row for row in inputs if filter_keeps(row[1])]
    BYTE.require(outputs == expected, "independent filter events differ from candidate")
    kept = filter_keeps(key)
    family = ("balance" if key[21] == 3 else "storage") if kept else "excluded"
    return {"name": case["name"], "key_bytes": len(key), "family": family,
            "input_operations": len(inputs), "output_operations": len(outputs),
            "typed_balance_key_grammar": kept and family == "balance" and len(key) == 32}


def check_corpus(document):
    BYTE.require(type(document) is dict and set(document) == {"format_version", "kind", "source", "scope", "filter_cases"},
                 "invalid filter corpus shape")
    BYTE.require(type(document["format_version"]) is int and document["format_version"] == 1, "unsupported filter format")
    BYTE.require(document["kind"] == "candidate-l1-fold-filter-research", "wrong filter fixture kind")
    BYTE.require(document["source"] == {"repository": "https://github.com/digitalSloth/go-zenon",
                                        "revision": BYTE.NODE_REVISION, "tree": BYTE.NODE_TREE}, "wrong source pin")
    BYTE.require(type(document["scope"]) is dict and document["scope"] == SCOPE and
                 all(type(value) is bool for value in document["scope"].values()), "unsupported filter scope claim")
    cases = document["filter_cases"]
    BYTE.require(type(cases) is list and len(cases) <= MAX_CASES, "fixture case limit or type")
    keys, names, decisions = selected_keys(), set(), []
    for case in cases:
        BYTE.require(type(case) is dict and type(case.get("name")) is str and case["name"] in keys,
                     "unknown selected filter case")
        BYTE.require(case["name"] not in names, "duplicate filter case")
        names.add(case["name"])
        decisions.append(check_case(case, keys[case["name"]]))
    BYTE.require(names == set(keys), "incomplete selected filter cases")
    return {"case_decisions": decisions, "filter_cases": len(decisions),
            "input_operations": sum(row["input_operations"] for row in decisions),
            "output_operations": sum(row["output_operations"] for row in decisions),
            "included_cases": sum(row["family"] != "excluded" for row in decisions),
            "excluded_cases": sum(row["family"] == "excluded" for row in decisions),
            "l1_staged_applier_executed": False, "node_database_opened": False,
            "node_lifecycle_qualified": False, "production_acceptance_enabled": False,
            "profile_agreed": False, "network_activation_authenticated": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, default=HERE / "testdata/candidate-l1-fold-filter.json")
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
        print("Candidate L1 filter check failed; retain the original fixture and inspect locally.", file=sys.stderr)
        sys.exit(1)
