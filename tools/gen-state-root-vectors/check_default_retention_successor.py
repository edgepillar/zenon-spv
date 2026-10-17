#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Check a fresh successor observation with the retained byte-level algorithms.

Require exact new source identity before adapting source-neutral table fields.
No historical record is changed and no backend, network or state proof is run.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("successor_retention_model", HERE / "default_retention_successor_model.py")
M = importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)
C = M.module("successor_retention_neutral_table_checker", "check_default_retention.py")
SOURCE_FIELDS = {"node_revision": M.P.REVISION, "node_tree": M.P.TREE, "runtime_tree": M.T.MODIFIED_TREE}


def selected_expectations(document):
    C.require(type(document) is dict and type(document.get("format_version")) is int
              and document["format_version"] == 1
              and document["kind"] == "successor-source-default-retention-independent-expectations")
    C.exact(document["source_identity"], M.source_identity())
    C.require(document["historical_source_records_rebound"] is False)
    for name, value in SOURCE_FIELDS.items():
        C.exact(document[name], value)
        C.exact(document["selection"][name], value)
    C.require(document["selection"]["kind"] == "successor-source-default-retention-component-selection")
    C.require(document["source_initial"]["raw_input"] == M.M.G.RAW
              and document["source_initial"]["expected_root"] == M.M.G.INITIAL_ROOT
              and document["source_initial"]["admitted_nonempty_leaf_keys"] == 19257
              and document["source_balances_independently_checked"] == 14091
              and document["selected_mutation_keys"] == document["selected_mutation_addresses"] == 256
              and len(document["selection"]["mutation_keys"]) == 256)
    C.require(document["full_initial_and_final_projection_recomputed"] is True
              and all(document[name] is False for name in (
                  "reference_backend_executed", "network_executed", "profile_agreed",
                  "accepted_header_root_binding", "production_resources_qualified"))
              and document["consumer_result"] == "REFUSED")
    C.require(type(document["history"]["height"]) is int and document["history"]["height"] == 32768
              and type(document["history"]["retention"]) is int and document["history"]["retention"] == 17380
              and type(document["selection"]["retention_override"]) is int
              and document["selection"]["retention_override"] == 0
              and type(document["selection"]["bulk_batch_override"]) is int
              and document["selection"]["bulk_batch_override"] == 0)
    C.require(hashlib.sha256(M.encoded(document["selection"])).hexdigest() == document["selection_sha256"])


def check_tables(raw, observation, expected):
    C.require(type(observation) is dict and set(observation) == C.FIELDS | set(SOURCE_FIELDS))
    C.require(observation["kind"] == "successor-source-default-retention-component-observation")
    for name, value in SOURCE_FIELDS.items():
        C.exact(observation[name], value)
    row = {k: v for k, v in observation.items() if k not in SOURCE_FIELDS}
    row["kind"] = "source-default-retention-component-observation"
    result = C.check_tables(raw, row, expected)
    result.update(kind="successor-source-default-retention-component-check", **SOURCE_FIELDS)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tables", type=Path, required=True)
    parser.add_argument("--observation", type=Path, required=True)
    parser.add_argument("--expectations", type=Path, required=True)
    parser.add_argument("--expectations-sha256", required=True)
    args = parser.parse_args(argv)
    raw = M.P.read_regular(args.expectations, 16 << 20)
    C.require(C.digest(args.expectations_sha256) and hashlib.sha256(raw).hexdigest() == args.expectations_sha256)
    expected = json.loads(raw, object_pairs_hook=M.P.pairs)
    selected_expectations(expected)
    observation = json.loads(M.P.read_regular(args.observation, 1 << 20), object_pairs_hook=M.P.pairs)
    C.require((observation["rollback_cache"], observation["retention_margin"]) == (100, 17280))
    print(json.dumps(check_tables(M.P.read_regular(args.tables, 64 << 20), observation, expected), sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError, IndexError, AssertionError):
        print("Successor retention observation refused; preserve the complete original output.", file=sys.stderr)
        sys.exit(1)
