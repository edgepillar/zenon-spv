#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Compare complete finite raw-store observations with the sealed independent model.

An exact byte comparison qualifies only this synthetic component flow. It does
not authenticate a snapshot, a chain, a StateRoot, or a production state value.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("raw_kv_independent_oracle", HERE / "raw_kv_roundtrip_successor_model.py")
M = importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)
P = M.R.P
MAX_OBSERVATION_BYTES = 32 << 20
SCOPE = {
    "component": "common/trie with raw LevelDB and common/db Patch primitives",
    "chain_wrappers_executed": False, "full_node_started": False,
    "existing_database_adopted": False, "authenticated_snapshot_import": False,
    "accepted_header_binding": False, "balance_value_encoding_agreed": False,
    "representative_resources_qualified": False, "consumer_result": "REFUSED",
    "production_state_value_accepted": False,
}


def require(condition):
    if not condition:
        raise ValueError("Raw KV roundtrip observation refused")


def selected_expectations(document):
    P.exact(document, M.derive())
    return document


def document(raw, limit):
    require(type(raw) is bytes and 0 < len(raw) <= limit)
    return json.loads(raw, object_pairs_hook=P.pairs)


def raw_hex(text, limit, minimum=0):
    require(type(text) is str and minimum * 2 <= len(text) <= limit * 2
            and len(text) % 2 == 0 and re.fullmatch("[0-9a-f]*", text) is not None)
    return bytes.fromhex(text)


def expected_proofs(expected, store):
    witnesses = expected["witnesses"]
    retained = {row["identifier"]["height"]: row for row in store["retained"]}
    rows = []
    for query in store["root_queries"]:
        if query["error"]:
            continue
        height = query["identifier"]["height"]
        P.exact(retained[height]["identifier"], query["identifier"])
        for proof in witnesses[str(height)]["proofs"]:
            rows.append(dict(proof, identifier=query["identifier"], error=""))
    return rows


def check_observation(raw, expected, policy, platform=None, go_version=None):
    require(type(policy) is str and policy in M.POLICIES)
    selected_expectations(expected)
    observed = document(raw, MAX_OBSERVATION_BYTES)
    keys = {"format_version", "kind", "policy", "selection_sha256", "source",
            "scope", "snapshots", "dump_objects", "replay"}
    require(type(observed) is dict and set(observed) == keys)
    P.exact({key: observed[key] for key in ("format_version", "kind", "policy", "selection_sha256")},
            {"format_version": 1, "kind": "successor-raw-kv-roundtrip-observation",
             "policy": policy, "selection_sha256": expected["selection_sha256"]})
    P.exact(observed["scope"], SCOPE)
    source = observed["source"]
    fixed_source = {key: expected["source"][key] for key in
                    ("node_revision", "original_node_tree", "selected_runtime_tree",
                     "experimental_disk_format", "source_blobs")}
    require(type(source) is dict and set(source) == set(fixed_source) | {"Go_version", "GOOS", "GOARCH"})
    P.exact({key: source[key] for key in fixed_source}, fixed_source)
    require(type(source["Go_version"]) is str
            and re.fullmatch(r"go1\.[0-9]+\.[0-9]+", source["Go_version"]) is not None
            and type(source["GOOS"]) is str and source["GOOS"] in ("darwin", "linux", "windows")
            and type(source["GOARCH"]) is str and source["GOARCH"] in ("arm64", "amd64"))
    if platform is not None:
        require(type(platform) is tuple and len(platform) == 2)
        P.exact([source["GOOS"], source["GOARCH"]], list(platform))
    if go_version is not None:
        P.exact(source["Go_version"], go_version)
    flow = expected["policies"][policy]["flow"]
    snapshots, objects = observed["snapshots"], observed["dump_objects"]
    require(type(snapshots) is list and len(snapshots) == len(flow)
            and type(objects) is dict and 0 < len(objects) <= len(flow))
    used, unique_proofs, counts, report = set(), set(), 0, []
    for row, selected in zip(snapshots, flow):
        require(type(row) is dict and set(row) == {"name", "frontier", "record_manifest",
                                                  "dump_selection", "root_queries", "proofs"})
        store = expected["policies"][policy]["stores"][selected["store"]]
        P.exact(row["name"], selected["stage"])
        for field in ("frontier", "record_manifest", "dump_selection", "root_queries"):
            P.exact(row[field], store[field])
        digest = row["dump_selection"]["sha256"]
        require(digest in objects)
        dump = raw_hex(objects[digest], 8 << 20, minimum=1)
        require(hashlib.sha256(dump).hexdigest() == digest)
        records = M.C.decode_selected_dump(dump, store["dump_selection"])
        P.exact(records, M.store_records(expected, policy, selected["store"]))
        P.exact(M.record_manifest(records), row["record_manifest"])
        used.add(digest)
        proofs = expected_proofs(expected, store)
        P.exact(row["proofs"], proofs)
        for proof in proofs:
            root = expected["witnesses"][str(proof["identifier"]["height"])]["root"]
            identity = (root, proof["key"], proof["value"], proof["proof"], proof["present"])
            if identity not in unique_proofs:
                require(M.B.proof_result(bytes.fromhex(root), M.B.digest(bytes.fromhex(proof["key"])),
                                        bytes.fromhex(proof["value"]), bytes.fromhex(proof["proof"]),
                                        proof["present"]) == "match")
                unique_proofs.add(identity)
        counts += len(proofs)
        report.append({"stage": row["name"], "records": len(records), "dump_sha256": digest,
                       "dump_bytes": len(dump), "canonical_proof_positions": len(proofs),
                       "root_and_probe_error_queries": len(row["root_queries"])})
    require(used == set(objects))
    seed = expected["policies"][policy]["stores"]["64"]["dump_selection"]["sha256"]
    P.exact(observed["replay"], {
        "input_sha256_before": seed, "input_sha256_after": seed,
        "load_error": "", "replay_error": "", "write_error": "",
        "raw_batch_write_calls": 1, "write_sync": True,
        "crash_or_hardware_power_loss_qualified": False,
    })
    return {
        "format_version": 1, "kind": "successor-raw-kv-roundtrip-exact-comparison",
        "policy": policy, "observation_sha256": hashlib.sha256(raw).hexdigest(),
        "observation_bytes": len(raw), "selection_sha256": expected["selection_sha256"],
        "independent_expectations_sha256": hashlib.sha256(M.encoded(expected)).hexdigest(),
        "source": source, "stages": report, "unique_dump_preimages": len(objects),
        "unique_canonical_proofs_verified": len(unique_proofs), "canonical_proof_positions": counts,
        "all_raw_records_compared": True, "all_root_and_probe_error_queries_compared": True,
        "all_canonical_proof_bytes_compared": True, "scope": dict(SCOPE),
        "ordinary_functional_component_not_representative_resource_qualification": True,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--observation", type=Path, required=True)
    parser.add_argument("--expectations", type=Path, required=True)
    parser.add_argument("--policy", choices=M.POLICIES, required=True)
    args = parser.parse_args(argv)
    result = check_observation(P.read_regular(args.observation, MAX_OBSERVATION_BYTES),
                               document(P.read_regular(args.expectations, 8 << 20), 8 << 20), args.policy)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError, IndexError, AssertionError):
        print("Raw KV roundtrip comparison refused; preserve inputs and observations.", file=sys.stderr)
        sys.exit(1)
