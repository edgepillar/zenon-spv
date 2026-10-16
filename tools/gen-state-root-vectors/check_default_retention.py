#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Compare actual component tables with independently preselected expectations.

No node or network is executed. Roots, retained identifiers and canonical proof
bytes are checked completely within the declared finite observation. Generic
proof matches never become production state-value or network-activation claims.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("default_retention_independent_model", HERE / "default_retention_model.py")
M = importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)
ZERO = "00" * 32
TIMERS = {"fixture_initialization_ns", "component_init_ns", "background_worker_elapsed_ns",
          "stop_elapsed_ns", "clean_reopen_elapsed_ns"}
TRUE = {"each_patch_requested_once", "logical_snapshots_equal", "proof_query_sets_equal",
        "actual_chain_Init_Start_Stop_executed", "actual_background_batches_executed",
        "manager_and_genesis_are_controlled_adapters", "source_identifiers_and_suffix_patches_are_synthetic"}
FALSE = {"full_node_started", "network_executed", "signing_or_broadcast_executed",
         "accepted_header_root_binding", "profile_agreed", "production_resources_qualified"}
FIELDS = TIMERS | TRUE | FALSE | {
    "kind", "policy", "Go_version", "platform", "history_height", "selection_sha256", "raw_input_sha256",
    "retention_override", "bulk_batch_override", "effective_retention", "rollback_cache", "retention_margin",
    "bulk_batch_cap", "tail_batch_cap", "batch_budget_ns", "initial_root", "initial_root_error",
    "post_stop_public_root", "post_stop_public_error", "post_stop_direct_root", "post_stop_direct_error",
    "patch_heights_requested", "actual_patch_frame_sha256", "logical_snapshots_observed",
    "proof_query_sets_observed", "logical_tables_sha256", "logical_tables_bytes",
    "physical_files_after_final_close", "consumer_result",
}


def require(value):
    if not value:
        raise ValueError("Default-retention observation refused")


def uint(value, minimum=0, maximum=(1 << 64) - 1):
    return type(value) is int and minimum <= value <= maximum


def digest(value):
    return type(value) is str and re.fullmatch("[0-9a-f]{64}", value) is not None


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


def identifier(fork, height):
    require(fork in ("G", "X") and uint(height, 1, 65536))
    return {"height": height, "hash": hashlib.sha3_256(
        ("synthetic-hash-bound-node-v1/%s/%d" % (fork, height)).encode()).hexdigest()}


def selected_expectations(document):
    require(document["format_version"] == 1 and type(document["format_version"]) is int
            and document["kind"] == "source-default-retention-independent-expectations")
    require(document["node_revision"] == "33d7d1ee1b6a915c40aea196e2a10f1e893d171f"
            and document["node_tree"] == "40d71efb7e462d5bbd0f27d83ed7588e121c3cb6")
    require(document["source_balances_independently_checked"] == 14091
            and document["source_initial"]["admitted_nonempty_leaf_keys"] == 19257
            and document["full_initial_and_final_projection_recomputed"] is True
            and document["reference_backend_executed"] is False
            and document["network_executed"] is False and document["profile_agreed"] is False
            and document["accepted_header_root_binding"] is False
            and document["production_resources_qualified"] is False and document["consumer_result"] == "REFUSED")
    require(document["history"]["height"] == 32768 and document["history"]["retention"] == 17380
            and document["selection"]["retention_override"] == 0
            and document["selection"]["bulk_batch_override"] == 0)
    require(document["selected_mutation_keys"] == document["selected_mutation_addresses"] == 256
            and len(document["selection"]["mutation_keys"]) == 256)
    require(hashlib.sha256(M.encoded(document["selection"])).hexdigest() == document["selection_sha256"])


def check_tables(raw, observation, expected):
    """Core also admits small presealed model fixtures; the CLI fixes real defaults."""
    require(type(raw) is bytes and 0 < len(raw) <= 64 << 20)
    tables = json.loads(raw, object_pairs_hook=M.G.B.object_pairs)
    require(type(tables) is dict and set(tables) == {"snapshot", "queries"})
    row = observation
    require(type(row) is dict and set(row) == FIELDS)
    require(row["kind"] == "source-default-retention-component-observation"
            and row["policy"] in ("pruned", "archive") and row["consumer_result"] == "REFUSED")
    require(all(row[key] is True for key in TRUE) and all(row[key] is False for key in FALSE))
    require(type(row["Go_version"]) is str and re.fullmatch(r"go[0-9]+\.[0-9]+\.[0-9]+", row["Go_version"])
            and type(row["platform"]) is str and re.fullmatch("(darwin|linux)/(arm64|amd64)", row["platform"]))
    require(all(uint(row[key], 0, 600_000_000_000) for key in TIMERS))
    height, retention = expected["history"]["height"], expected["history"]["retention"]
    require(uint(height, 3, 65536) and uint(retention, 2, height - 1))
    require(uint(row["history_height"]) and row["history_height"] == height
            and uint(row["effective_retention"]) and row["effective_retention"] == retention)
    require(type(row["retention_override"]) is int and row["retention_override"] == 0
            and type(row["bulk_batch_override"]) is int and row["bulk_batch_override"] == 0)
    require(uint(row["rollback_cache"]) and uint(row["retention_margin"], 1)
            and row["rollback_cache"] + row["retention_margin"] == retention)
    require(uint(row["bulk_batch_cap"], 1) and row["bulk_batch_cap"] == 10000
            and uint(row["tail_batch_cap"], 1) and row["tail_batch_cap"] == 10
            and uint(row["batch_budget_ns"], 1) and row["batch_budget_ns"] == 1000000000)
    require(row["selection_sha256"] == expected["selection_sha256"]
            and row["raw_input_sha256"] == M.G.RAW["sha256"]
            and uint(row["patch_heights_requested"]) and row["patch_heights_requested"] == height
            and row["actual_patch_frame_sha256"] == expected["history"]["mutation_frame_sha256"])
    require(type(row["logical_snapshots_observed"]) is int and row["logical_snapshots_observed"] == 3
            and type(row["proof_query_sets_observed"]) is int and row["proof_query_sets_observed"] == 2)
    require(row["initial_root"] == row["post_stop_public_root"] == row["post_stop_direct_root"] == ZERO
            and row["initial_root_error"] == row["post_stop_public_error"] == "not-ready"
            and row["post_stop_direct_error"] == "database-closed")
    require(digest(row["logical_tables_sha256"]) and uint(row["logical_tables_bytes"], 1, 64 << 20)
            and row["logical_tables_bytes"] == len(raw)
            and hashlib.sha256(raw).hexdigest() == row["logical_tables_sha256"])
    roots = expected["history"]["roots"]
    require(type(roots) is list and len(roots) == height)
    for h, root in enumerate(roots, 1):
        require(type(root) is dict and set(root) == {"height", "root"}
                and type(root["height"]) is int and root["height"] == h and digest(root["root"]))
    lookup = {r["height"]: r["root"] for r in roots}
    archive = row["policy"] == "archive"
    retained = range(1 if archive else height - retention, height + 1)
    snapshot = tables["snapshot"]
    require(type(snapshot) is dict and set(snapshot) == {"format", "logical_records", "logical_key_value_bytes",
            "logical_records_sha256", "record_prefix_counts", "retained_roots"})
    require(snapshot["format"] == "03" and uint(snapshot["logical_records"], 1, 4_000_000)
            and uint(snapshot["logical_key_value_bytes"], 1, 1 << 30) and digest(snapshot["logical_records_sha256"]))
    counts = snapshot["record_prefix_counts"]
    require(type(counts) is dict and set(counts) == {"00", "01", "02", "03", "05", "06"}
            and all(uint(v, 1, 4_000_000) for v in counts.values()))
    require(counts["00"] == counts["05"] == 1 and counts["01"] == counts["02"]
            and counts["03"] == counts["06"] == len(retained)
            and sum(counts.values()) == snapshot["logical_records"])
    expected_roots = [{"height": h, "root": lookup[h], "hash": identifier("G", h)["hash"]} for h in retained]
    exact(snapshot["retained_roots"], expected_roots)
    queries, matched, refused = [], 0, 0
    selected = expected["selection"]["selected_proofs"]
    for h in expected["selection"]["query_heights"]:
        require(type(h) is int and h in lookup)
        present, proof_rows = h in retained, []
        samples = expected["history"]["checkpoints"][str(h)]
        require(len(samples) == len(selected))
        for sample, chosen in zip(samples, selected):
            require(sample["selection"] == chosen["selection"] and sample["raw_key"] == chosen["raw_key"])
            if present:
                value = None if sample["value"] is None else bytes.fromhex(sample["value"])
                require(M.G.B.proof_result(bytes.fromhex(lookup[h]), M.G.F.digest(bytes.fromhex(sample["raw_key"])),
                        value or b"", bytes.fromhex(sample["proof"]), sample["present_in_projection"]) == "match")
                matched += 1
            else:
                refused += 1
            proof_rows.append({"selection": sample["selection"], "raw_key": sample["raw_key"],
                               "value": sample["value"] if present else None,
                               "proof": sample["proof"] if present else None,
                               "error": None if present else "no-version", "consumer_result": "REFUSED"})
        queries.append({"height": h, "root": lookup[h] if present else ZERO,
                        "root_error": None if present else "no-version", "proofs": proof_rows})
    queries += [{"identifier": identifier("X", height), "root": ZERO, "root_error": "version-hash-mismatch"},
                {"identifier": {"height": 0, "hash": ZERO}, "root": ZERO, "root_error": None}]
    exact(tables["queries"], queries)
    files = row["physical_files_after_final_close"]
    require(type(files) is list and 0 < len(files) <= 1024)
    names, physical_bytes = set(), 0
    for file in files:
        require(type(file) is dict and set(file) == {"name", "bytes", "sha256"}
                and type(file["name"]) is str and re.fullmatch("[A-Za-z0-9][A-Za-z0-9._-]{0,127}", file["name"])
                and file["name"].casefold() not in names and uint(file["bytes"], 0, 256 << 20) and digest(file["sha256"]))
        names.add(file["name"].casefold())
        physical_bytes += file["bytes"]
    require(0 < physical_bytes <= 2 << 30)
    return {"kind": "source-default-retention-component-check", "policy": row["policy"],
            "history_height": height, "retention": retention, "retained_roots": len(retained),
            "query_heights": len(expected["selection"]["query_heights"]),
            "canonical_proofs_matched": matched, "pruned_proof_refusals": refused,
            "recorded_query_sets": 2, "physical_file_bytes": physical_bytes,
            "full_node_qualified": False, "profile_agreed": False, "accepted_header_binding": False,
            "production_resources_qualified": False, "consumer_result": "REFUSED"}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tables", type=Path, required=True)
    parser.add_argument("--observation", type=Path, required=True)
    parser.add_argument("--expectations", type=Path, required=True)
    parser.add_argument("--expectations-sha256", required=True)
    args = parser.parse_args(argv)
    P = M.module("default_retention_observation_reader", "prepare_hash_bound_versions.py")
    expected_raw = P.read_regular(args.expectations, 16 << 20)
    require(digest(args.expectations_sha256) and hashlib.sha256(expected_raw).hexdigest() == args.expectations_sha256)
    expected = json.loads(expected_raw, object_pairs_hook=P.pairs)
    selected_expectations(expected)
    observation = json.loads(P.read_regular(args.observation, 1 << 20), object_pairs_hook=P.pairs)
    require((observation["rollback_cache"], observation["retention_margin"]) == (100, 17280))
    print(json.dumps(check_tables(P.read_regular(args.tables, 64 << 20), observation, expected), sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError, IndexError, AssertionError):
        print("Default-retention observation refused; preserve the original component output.", file=sys.stderr)
        sys.exit(1)
