#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Independently preselect source-genesis proof requests and exact byte results.

No backend, wallet, signing or network execution occurs here. The source-derived
root is not an authenticated header root. Excluded ledger keys establish absence
only in this partial projection, never absence from the complete ledger.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import stat
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, HERE / file)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


H = load("proof_workload_independent_genesis", "derive_genesis_background.py")
REVISION = "9c71ae82fc983e16f914ae085d4034030c8ebe3b"
RUNTIME_TREE = "053c87e5bc4addd1bb70a467cb34facd439e66bc"
GENESIS = {"hash": "9e204601d1b7b1427fe12bc82622e610d8a6ad43c40abf020eb66e538bb8eeb0", "height": 1}
REQUESTS = 4096
WORKERS = (1, 4, 16)
DOMAIN_COUNTS = {"balance": 80, "contract_storage": 32, "absent_balance": 8, "excluded_ledger_key": 8}


def require(value, message="Independent proof workload refused"):
    if not value:
        raise ValueError(message)


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()


def framed(root, key, value, proof):
    digest = hashlib.sha256()
    for raw in (key, value, root, proof):
        require(raw is None or type(raw) is bytes, "byte frame type")
        digest.update(bytes([int(raw is not None)]))
        digest.update((0 if raw is None else len(raw)).to_bytes(8, "big"))
        digest.update(b"" if raw is None else raw)
    return digest.digest()


def ranked(keys, label):
    return sorted(keys, key=lambda key: (hashlib.sha256(label + key).digest(), key))


def snapshot_source(root, pins, parent):
    root = Path(root).absolute()
    require(root.is_dir() and not any(path.is_symlink() for path in (root, *root.parents)))
    for name, pin in pins.items():
        info = (root / name).lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1)
        require(sys.platform == "win32" or stat.S_IMODE(info.st_mode) == (int(pin["mode"], 8) & 0o777))
    return parent.UTIL.snapshot_source(root, pins)


def targets(state, leaves):
    balances = sorted(key for key in leaves if key[21] == 3)
    storage = sorted(key for key in leaves if key[21] == 4)
    tokens = sorted({key[22:] for key in balances})
    require(len(tokens) == 2 and all(len(token) == 10 for token in tokens))
    selected = []
    for token in tokens:
        keys = ranked((key for key in balances if key[22:] == token), b"proof-workload-v1/balance/" + token)
        selected.extend(("balance", key) for key in keys[:40])
    # One source token has only three rows. Keep the eighty-key balance budget,
    # cover that complete small family, and fill from distinct remaining rows.
    chosen = {key for _, key in selected}
    remaining = ranked((key for key in balances if key not in chosen), b"proof-workload-v1/balance-fill/")
    selected.extend(("balance", key) for key in remaining[:80-len(selected)])
    require(len(selected) == 80)
    # Include the sixteen largest values as well as a dispersed storage sample.
    # The selection is fixed from the input map, before any backend response.
    largest = sorted(storage, key=lambda key: (-len(leaves[key]), key))[:16]
    dispersed = [key for key in ranked(storage, b"proof-workload-v1/storage/") if key not in largest][:16]
    require(len(largest) == len(dispersed) == 16)
    selected.extend(("contract_storage", key) for key in largest + dispersed)
    for index in range(8):
        address = b"\x00" + hashlib.sha256(b"proof-workload-v1/absent/" + bytes([index])).digest()[:19]
        key = b"\x03" + address + b"\x03" + tokens[index % 2]
        require(key not in state)
        selected.append(("absent_balance", key))
    excluded = ranked((key for key in state if not H.admitted(key)), b"proof-workload-v1/excluded/")[:8]
    require(len(excluded) == 8)
    selected.extend(("excluded_ledger_key", key) for key in excluded)
    require(len(selected) == len({key for _, key in selected}) == 128)
    require({domain: sum(d == domain for d, _ in selected) for domain in DOMAIN_COUNTS} == DOMAIN_COUNTS)
    return selected


def derive(raw, source_config):
    require(type(raw) is bytes and len(raw) == H.RAW["bytes"] and hashlib.sha256(raw).hexdigest() == H.RAW["sha256"], "pinned source-genesis bytes")
    counts, state = H.I.counts_and_state(raw, H.D)
    source_balances = H.I.balances(source_config)
    require({key: value for key, value in state.items() if len(key) >= 22 and key[0] == 3 and key[21] == 3} == source_balances,
            "independent source balance map")
    leaves = {key: value for key, value in state.items() if H.admitted(key) and value}
    require(len(state) == 103821 and len(leaves) == 19257)
    require(sum(key[21] == 3 for key in leaves) == 14091 and sum(key[21] == 4 for key in leaves) == 5166)
    selected = targets(state, leaves)
    paths = {H.L.digest(key): value for key, value in leaves.items()}
    require(len(paths) == len(leaves), "distinct projected paths")
    root, proofs, stats = H.L.model(paths, [H.L.digest(key) for _, key in selected])
    require(root.hex() == H.INITIAL_ROOT, "complete independent source-genesis root")
    rows = []
    for domain, key in selected:
        value, proof = leaves.get(key), proofs[H.L.digest(key)]
        require(len(key) <= 4096 and len(proof) <= 128 << 10, "preselected response bound")
        require(H.B.proof_result(root, H.L.digest(key), value or b"", proof, value is not None) == "match",
                "independent canonical proof reconstruction")
        rows.append({"domain": domain, "raw_key": key.hex(), "root": root.hex(),
                     "present_in_projection": value is not None, "value_hex": "" if value is None else value.hex(),
                     "proof_hex": proof.hex(), "proof_sha256": hashlib.sha256(proof).hexdigest(),
                     "proof_bytes": len(proof), "row_sha256": framed(root, key, value, proof).hex(),
                     "ledger_raw_input_has_key": key in state})
    aggregate = hashlib.sha256(b"".join(bytes.fromhex(rows[index % len(rows)]["row_sha256"]) for index in range(REQUESTS))).hexdigest()
    selection = {"schema": "source-genesis-public-chain-proof-workload-v1", "node_revision": REVISION,
                 "runtime_tree": RUNTIME_TREE, "genesis_patch": dict(H.RAW), "genesis_identifier": dict(GENESIS),
                 "keys": [{"domain": domain, "raw_key": key.hex()} for domain, key in selected],
                 "requests": REQUESTS, "workers": list(WORKERS), "accepted_header_binding": False,
                 "production_state_value_accepted": False, "consumer_result": "REFUSED"}
    expected = {"schema": "source-genesis-public-chain-proof-expectations-v1", "node_revision": REVISION,
                "runtime_tree": RUNTIME_TREE, "source_genesis_input": dict(H.RAW), "source_balance_rows_checked": 14091,
                "logical_input_keys": len(state), "projected_nonempty_leaves": len(leaves), "domain_counts": dict(DOMAIN_COUNTS),
                "complete_projection_mapping_sha256": H.I.mapping_sha(leaves), "expected_root": root.hex(),
                "selection_sha256": hashlib.sha256(encoded(selection)).hexdigest(), "input_replay_counts": counts,
                "source_balance_token_distribution": {token.hex(): sum(key[22:] == token for key in source_balances) for token in sorted({key[22:] for key in source_balances})},
                "selected_balance_token_distribution": {token.hex(): sum(domain == "balance" and key[22:] == token for domain, key in selected) for token in sorted({key[22:] for key in source_balances})},
                "sparse_model_accounting": stats, "expected_rows": rows, "ordered_request_rows_sha256": aggregate,
                "requests": REQUESTS, "whole_projection_independently_recomputed": True,
                "selected_proof_bytes_independently_reconstructed": True, "backend_executed": False,
                "accepted_header_binding": False, "production_state_value_accepted": False, "consumer_result": "REFUSED"}
    require(len(encoded(selection)) <= 128 << 10 and len(encoded(expected)) <= 1 << 20, "finite fixture bytes")
    return selection, expected


def check_expected(selection, expected):
    require(type(selection) is dict and set(selection) == {"schema", "node_revision", "runtime_tree", "genesis_patch", "genesis_identifier", "keys", "requests", "workers", "accepted_header_binding", "production_state_value_accepted", "consumer_result"})
    require(type(expected) is dict and set(expected) == {"schema", "node_revision", "runtime_tree", "source_genesis_input", "source_balance_rows_checked", "logical_input_keys", "projected_nonempty_leaves", "domain_counts", "complete_projection_mapping_sha256", "expected_root", "selection_sha256", "input_replay_counts", "sparse_model_accounting", "source_balance_token_distribution", "selected_balance_token_distribution", "expected_rows", "ordered_request_rows_sha256", "requests", "whole_projection_independently_recomputed", "selected_proof_bytes_independently_reconstructed", "backend_executed", "accepted_header_binding", "production_state_value_accepted", "consumer_result"})
    require(selection["schema"] == "source-genesis-public-chain-proof-workload-v1" and selection["node_revision"] == REVISION and selection["runtime_tree"] == RUNTIME_TREE)
    require(selection["genesis_patch"] == H.RAW and selection["genesis_identifier"] == GENESIS)
    require(type(selection["requests"]) is int and selection["requests"] == REQUESTS and selection["workers"] == list(WORKERS) and all(type(n) is int for n in selection["workers"]))
    require(selection["accepted_header_binding"] is False and selection["production_state_value_accepted"] is False and selection["consumer_result"] == "REFUSED")
    require(expected["schema"] == "source-genesis-public-chain-proof-expectations-v1" and expected["node_revision"] == REVISION and expected["runtime_tree"] == RUNTIME_TREE)
    require(expected["source_genesis_input"] == H.RAW and expected["expected_root"] == H.INITIAL_ROOT)
    for key, value in (("source_balance_rows_checked", 14091), ("logical_input_keys", 103821), ("projected_nonempty_leaves", 19257)):
        require(type(expected[key]) is int and expected[key] == value)
    require(expected["whole_projection_independently_recomputed"] is True and expected["selected_proof_bytes_independently_reconstructed"] is True)
    distribution = expected["source_balance_token_distribution"]
    require(type(distribution) is dict and len(distribution) == 2 and all(type(n) is int and n > 0 for n in distribution.values()) and sum(distribution.values()) == 14091)
    require(expected["selection_sha256"] == hashlib.sha256(encoded(selection)).hexdigest())
    require(expected["requests"] == REQUESTS and type(expected["requests"]) is int)
    require(expected["domain_counts"] == DOMAIN_COUNTS and len(expected["expected_rows"]) == len(selection["keys"]) == 128)
    require(expected["backend_executed"] is False and expected["accepted_header_binding"] is False and expected["production_state_value_accepted"] is False and expected["consumer_result"] == "REFUSED")
    root = bytes.fromhex(H.INITIAL_ROOT)
    seen, domain_counts, digests = set(), dict.fromkeys(DOMAIN_COUNTS, 0), []
    for selected, row in zip(selection["keys"], expected["expected_rows"]):
        require(type(row) is dict and set(row) == {"domain", "raw_key", "root", "present_in_projection", "value_hex", "proof_hex", "proof_sha256", "proof_bytes", "row_sha256", "ledger_raw_input_has_key"})
        require(selected == {"domain": row["domain"], "raw_key": row["raw_key"]})
        require(row["domain"] in DOMAIN_COUNTS and row["raw_key"] not in seen)
        seen.add(row["raw_key"]); domain_counts[row["domain"]] += 1
        key, proof = bytes.fromhex(row["raw_key"]), bytes.fromhex(row["proof_hex"])
        require(key.hex() == row["raw_key"] and proof.hex() == row["proof_hex"])
        require(0 < len(key) <= 4096 and len(proof) <= 128 << 10 and type(row["present_in_projection"]) is bool)
        value = bytes.fromhex(row["value_hex"]) if row["present_in_projection"] else None
        require(value is None or value.hex() == row["value_hex"])
        require(row["root"] == H.INITIAL_ROOT and row["proof_sha256"] == hashlib.sha256(proof).hexdigest() and type(row["proof_bytes"]) is int and row["proof_bytes"] == len(proof))
        require(row["present_in_projection"] or row["value_hex"] == "")
        require(H.B.proof_result(root, H.L.digest(key), value or b"", proof, value is not None) == "match")
        require(row["row_sha256"] == framed(root, key, value, proof).hex())
        if row["domain"] in ("balance", "contract_storage"):
            require(row["present_in_projection"] is True and row["ledger_raw_input_has_key"] is True)
            require(H.admitted(key) and key[21] == (3 if row["domain"] == "balance" else 4))
            if row["domain"] == "balance":
                require(len(key) == len(value) == 32)
        elif row["domain"] == "excluded_ledger_key":
            require(row["present_in_projection"] is False and row["ledger_raw_input_has_key"] is True and not H.admitted(key))
        else:
            require(row["present_in_projection"] is False and row["ledger_raw_input_has_key"] is False)
            require(len(key) == 32 and key[0] == 3 and key[21] == 3)
        digests.append(bytes.fromhex(row["row_sha256"]))
    require(domain_counts == DOMAIN_COUNTS)
    selected_distribution = {token: sum(row["domain"] == "balance" and bytes.fromhex(row["raw_key"])[22:].hex() == token for row in expected["expected_rows"]) for token in distribution}
    require(selected_distribution == expected["selected_balance_token_distribution"] and sum(selected_distribution.values()) == 80)
    require(all(0 < selected_distribution[token] <= distribution[token] for token in distribution))
    require(expected["ordered_request_rows_sha256"] == hashlib.sha256(b"".join(digests[i % 128] for i in range(REQUESTS))).hexdigest())
    return {"independent_canonical_witnesses_checked": 128, "ordered_requests": REQUESTS,
            "projected_absence_is_not_full_ledger_absence": True, "accepted_header_binding": False,
            "production_state_value_accepted": False, "consumer_result": "REFUSED"}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--node-source", required=True, type=Path)
    args = parser.parse_args(argv)
    parent = load("proof_workload_source_parent", "prepare_core_stop_errors.py")
    manifest, _, _ = parent.selection("candidate")
    source = snapshot_source(args.node_source, manifest["files"], parent.P)
    config = json.loads(source["chain/genesis/embedded_genesis_string.go"].split(b"`")[1], object_pairs_hook=H.B.object_pairs)
    selection, expected = derive(parent.P.read_regular(args.input, H.RAW["bytes"]), config)
    check_expected(selection, expected)
    print(encoded({"selection": selection, "expectations": expected}).decode(), end="")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, IndexError, AssertionError):
        print("Independent proof workload refused; preserve selected inputs and failure diagnostics.", file=sys.stderr)
        sys.exit(1)
