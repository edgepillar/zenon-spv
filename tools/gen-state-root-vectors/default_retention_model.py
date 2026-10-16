#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Independent source-genesis expectations beyond the default retained horizon.

This module executes no node, network, wallet or database. The CLI always selects
the pinned source defaults and freezes its complete expectations before a caller
starts a component process. Small function arguments are for finite model tests.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
HISTORY_HEIGHT = 32768
RETENTION = 17380
MUTATION_KEYS = 256
WITNESS_BATCH = 128
MAX_TARGETS = 384
MAX_FOREST_NODES = 262144
FRAME_FORMAT = "height_u64_be || raw_key_32 || tag_0_delete_or_1_put || value_32_on_put"


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


G = module("default_retention_genesis_contract", "derive_genesis_background.py")


def require(condition):
    if not condition:
        raise ValueError("Independent default-retention derivation refused")


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def select_balances(leaves, count=MUTATION_KEYS):
    require(type(leaves) is dict and type(count) is int and 2 <= count <= MUTATION_KEYS)
    require(all(type(k) is bytes and type(v) is bytes for k, v in leaves.items()))
    keys = sorted(k for k in leaves if len(k) == 32 and k[0] == 3 and k[21] == 3)
    require(len(keys) >= count and all(len(leaves[k]) == 32 for k in keys))
    selected = [keys[i * (len(keys) - 1) // (count - 1)] for i in range(count)]
    require(len(set(selected)) == count and selected[0] == keys[0] and selected[-1] == keys[-1])
    return selected


def checkpoint_heights(height=HISTORY_HEIGHT, retention=RETENTION):
    require(type(height) is int and type(retention) is int
            and 2 <= retention < height <= 65536)
    horizon = height - retention
    return sorted({1, max(1, horizon - 1), horizon, horizon + 1, max(1, height - 10), height})


def mutation(height, keys):
    require(type(height) is int and 2 <= height <= 65536
            and type(keys) is list and 2 <= len(keys) <= MUTATION_KEYS)
    key = keys[(height - 2) % len(keys)]
    require(type(key) is bytes and len(key) == 32 and key[0] == 3 and key[21] == 3)
    value = None if height % 11 == 0 else (0 if height % 7 == 0 else 1000000 + height).to_bytes(32, "big")
    return key, value


def mutation_frame(height, key, value):
    require(type(height) is int and 2 <= height <= 65536 and type(key) is bytes
            and len(key) == 32 and (value is None or type(value) is bytes and len(value) == 32))
    return height.to_bytes(8, "big") + key + (b"\0" if value is None else b"\1" + value)


def initial_witnesses(leaves, targets, expected_root, labels=None):
    """Keep the original model's 128-target cap; recompute each complete root."""
    require(type(leaves) is dict and type(targets) is list and 0 < len(targets) <= MAX_TARGETS)
    require(all(type(k) is bytes for k in targets) and len(set(targets)) == len(targets))
    require(type(expected_root) is bytes and len(expected_root) == 32)
    positions = {G.L.digest(k): v for k, v in leaves.items()}
    require(len(positions) == len(leaves))
    paths = [G.L.digest(k) for k in targets]
    require(len(set(paths)) == len(paths))
    rows, observations = [], []
    for start in range(0, len(targets), WITNESS_BATCH):
        chunk = paths[start:start + WITNESS_BATCH]
        root, proofs, stats = G.L.model(positions, chunk)
        require(root == expected_root and stats["selected_witness_paths"] == len(chunk))
        observations.append(stats)
        for key, path in zip(targets[start:start + WITNESS_BATCH], chunk):
            value = leaves.get(key)
            proof = proofs[path]
            require(G.B.proof_result(root, path, value or b"", proof, value is not None) == "match")
            rows.append({"selection": (labels or {}).get(key, "mutation_balance"),
                         "raw_key": key.hex(), "path": path.hex(),
                         "present_in_projection": value is not None,
                         "value": None if value is None else value.hex(), "proof": proof.hex(),
                         "consumer_result": "REFUSED"})
    require(len(rows) == len(targets))
    return rows, observations


def history(initial_root, witnesses, keys, query_keys, height=HISTORY_HEIGHT, retention=RETENTION):
    require(type(initial_root) is bytes and len(initial_root) == 32
            and type(witnesses) is list and 0 < len(witnesses) <= MAX_TARGETS)
    require(type(keys) is list and 2 <= len(keys) <= MUTATION_KEYS and len(set(keys)) == len(keys))
    require(all(type(k) is bytes and len(k) == 32 and k[0] == 3 and k[21] == 3 for k in keys))
    require(type(query_keys) is list and 0 < len(query_keys) <= 32
            and len(set(query_keys)) == len(query_keys))
    checkpoints = checkpoint_heights(height, retention)
    by_key = {}
    for row in witnesses:
        key, path = bytes.fromhex(row["raw_key"]), bytes.fromhex(row["path"])
        value = None if row["value"] is None else bytes.fromhex(row["value"])
        proof = bytes.fromhex(row["proof"])
        require(key not in by_key and path == G.F.digest(key)
                and type(row["present_in_projection"]) is bool
                and row["present_in_projection"] == (value is not None))
        require(G.B.proof_result(initial_root, path, value or b"", proof, value is not None) == "match")
        by_key[key] = row
    require(set(keys) <= set(by_key) and set(query_keys) <= set(by_key))
    forest = G.F.Forest(initial_root, witnesses)
    require(len(forest.nodes) <= MAX_FOREST_NODES)
    roots, queries = [{"height": 1, "root": initial_root.hex()}], {}
    frames = hashlib.sha256()
    action_counts = {"Delete": 0, "present_zero": 0, "other_Put": 0}

    def capture(h, root):
        rows = []
        for key in query_keys:
            path = G.F.digest(key)
            value, proof = forest.values.get(path), forest.proof(path)
            require(G.B.proof_result(root, path, value or b"", proof, path in forest.values) == "match")
            rows.append({"selection": by_key[key]["selection"], "raw_key": key.hex(),
                         "path": path.hex(), "present_in_projection": path in forest.values,
                         "value": None if value is None else value.hex(), "proof": proof.hex(),
                         "consumer_result": "REFUSED"})
        queries[str(h)] = rows

    capture(1, initial_root)
    for h in range(2, height + 1):
        key, value = mutation(h, keys)
        frames.update(mutation_frame(h, key, value))
        action_counts["Delete" if value is None else "present_zero" if value == b"\0" * 32 else "other_Put"] += 1
        root = forest.update(G.F.digest(key), value)
        roots.append({"height": h, "root": root.hex()})
        if h in checkpoints:
            capture(h, root)
    require(len(forest.nodes) <= MAX_FOREST_NODES and len(roots) == height
            and sorted(map(int, queries)) == checkpoints and sum(action_counts.values()) == height - 1)
    return {"height": height, "retention": retention, "horizon_inclusive": height - retention,
            "expected_pruned_roots": retention + 1, "expected_archive_roots": height,
            "roots": roots, "checkpoints": queries, "final_root": roots[-1]["root"],
            "mutation_frame_format": FRAME_FORMAT, "mutation_frame_sha256": frames.hexdigest(),
            "mutation_counts": action_counts, "selected_forest_nodes": len(forest.nodes)}, forest


def derive(raw, source_config):
    base, leaves, counts = G.derive_initial(raw, source_config)
    keys = select_balances(leaves)
    original = base["selected_proofs"]
    queries = [bytes.fromhex(row["raw_key"]) for row in original]
    targets = sorted(set(keys) | set(queries))
    labels = {bytes.fromhex(row["raw_key"]): row["selection"] for row in original}
    initial = bytes.fromhex(base["expected_root"])
    witnesses, batches = initial_witnesses(leaves, targets, initial, labels)
    expected, forest = history(initial, witnesses, keys, queries)
    final_leaves = dict(leaves)
    for h in range(2, HISTORY_HEIGHT + 1):
        key, value = mutation(h, keys)
        if value is None:
            final_leaves.pop(key, None)
        else:
            final_leaves[key] = value
    final_rows, final_batches = initial_witnesses(final_leaves, targets, forest.root(), labels)
    require(all(bytes.fromhex(row["proof"]) == forest.proof(bytes.fromhex(row["path"])) for row in final_rows))
    selection = {"format_version": 1, "kind": "source-default-retention-component-selection",
                 "history_height": HISTORY_HEIGHT, "retention_override": 0, "bulk_batch_override": 0,
                 "source_effective_retention": RETENTION, "raw_input": dict(G.RAW),
                 "mutation_keys": [key.hex() for key in keys],
                 "selected_proofs": [{"selection": row["selection"], "raw_key": row["raw_key"]} for row in original],
                 "query_heights": checkpoint_heights()}
    return {"format_version": 1, "kind": "source-default-retention-independent-expectations",
            "source_initial": base, "input_replay_counts": counts,
            "selection": selection, "selection_sha256": hashlib.sha256(encoded(selection)).hexdigest(),
            "initial_witnesses": witnesses, "initial_layer_batches": batches,
            "final_layer_batches": final_batches, "full_initial_and_final_projection_recomputed": True,
            "history": expected, "source_balances_independently_checked": 14091,
            "selected_mutation_keys": len(keys), "selected_mutation_addresses": len({k[1:21] for k in keys}),
            "reference_backend_executed": False, "network_executed": False,
            "profile_agreed": False, "accepted_header_root_binding": False,
            "production_resources_qualified": False, "consumer_result": "REFUSED"}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--node-source", type=Path, required=True)
    args = parser.parse_args(argv)
    P = module("default_retention_complete_node_source", "prepare_hash_bound_versions.py")
    _, manifest = P.source_manifest()
    files = P.snapshot_source(args.node_source, manifest["files"])
    config = json.loads(files["chain/genesis/embedded_genesis_string.go"].split(b"`")[1],
                        object_pairs_hook=G.B.object_pairs)
    result = derive(P.read_regular(args.input, G.RAW["bytes"]), config)
    result["node_revision"], result["node_tree"] = P.REVISION, P.TREE
    sys.stdout.buffer.write(encoded(result))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError, IndexError, AssertionError):
        print("Default-retention derivation refused; preserve owned inputs and failure output.", file=sys.stderr)
        sys.exit(1)
