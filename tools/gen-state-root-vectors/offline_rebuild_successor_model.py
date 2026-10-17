#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Replay 64 finite heights from an unchanged, independently sealed witness set.

No node, database, compiler or network is executed. Reuse the previous source
genesis/witness provenance explicitly; never relabel an old backend process.
The separate caller patch changes no sparse-tree arithmetic or key domain.
"""
import functools
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent


def module(name, filename):
    selected = importlib.util.spec_from_file_location(name, HERE / filename)
    value = importlib.util.module_from_spec(selected)
    selected.loader.exec_module(value)
    return value


R = module("offline_rebuild_selected_source", "prepare_offline_rebuild_successor.py")
M = module("offline_rebuild_finite_sparse_algorithms", "default_retention_model.py")
P = R.P
encoded = M.encoded
WITNESS_FILE = "testdata/successor-default-retention.json"
WITNESS_SHA256 = "da7f26c8d99aea2f14b3d3950d8dd3fecf2798cf99aa6aaa3114cbebd002f0a1"
WITNESS_BASE_SHA256 = "97463c1b2720f277e59cf2d8abd55d90d286c9d359130377fc0f4658e7b28c4b"
GENESIS_FILE = "testdata/successor-genesis-input-execution.json"
GENESIS_SHA256 = "8d80a7160bf0e7ff4fcae8bc4c18ca40b64dd65200c8fd1de5dca8fc16f8c0f0"


def source_identity():
    manifest, _, _, _ = R.runtime_selection("full-identifier")
    return {
        "node_revision": P.REVISION, "node_tree": P.TREE, "source_blobs": 467,
        "source_manifest_sha256": P.SOURCE_SHA256,
        "terminal_parent_tree": R.T.MODIFIED_TREE, "caller_runtime_tree": R.MODIFIED_TREE,
        "hash_identity_patch_sha256": P.PATCH_SHA256,
        "terminal_patch_sha256": R.T.PATCH_SHA256, "caller_patch_sha256": R.PATCH_SHA256,
        "module_sha256": manifest["files"]["go.mod"]["sha256"],
        "sum_sha256": manifest["files"]["go.sum"]["sha256"],
    }


def identifier(height, fork="G"):
    P.require(type(height) is int and 1 <= height <= 65 and fork in ("G", "X"))
    return {"height": height, "hash": hashlib.sha3_256(
        ("synthetic-hash-bound-node-v1/" + fork + "/" + str(height)).encode()).hexdigest()}


@functools.lru_cache(maxsize=1)
def derived_bytes(raw):
    P.require(type(raw) is bytes and len(raw) <= 4 << 20 and P.sha(raw) == WITNESS_SHA256)
    container = json.loads(raw, object_pairs_hook=P.pairs)
    base = container["presealed_expectations_without_history"]
    P.require(P.sha(encoded(base)) == WITNESS_BASE_SHA256)
    P.require(base["node_revision"] == P.REVISION and base["node_tree"] == P.TREE
              and base["runtime_tree"] == R.T.MODIFIED_TREE)
    genesis_raw = P.read_regular(HERE / GENESIS_FILE, 64 << 10)
    P.require(P.sha(genesis_raw) == GENESIS_SHA256)
    genesis = json.loads(genesis_raw, object_pairs_hook=P.pairs)
    P.require(genesis["node_revision"] == P.REVISION and genesis["node_tree"] == P.TREE
              and genesis["source_module_sha256"] == source_identity()["module_sha256"]
              and genesis["source_sum_sha256"] == source_identity()["sum_sha256"]
              and genesis["NodeTree_backend_executed"] is False)
    selection = base["selection"]
    P.exact(selection["raw_input"], genesis["raw_input"])
    keys = [bytes.fromhex(key) for key in selection["mutation_keys"]]
    queries = [bytes.fromhex(row["raw_key"]) for row in selection["selected_proofs"]]
    P.require(len(keys) == 256 and len(queries) == 15)
    history, _ = M.history(bytes.fromhex(base["source_initial"]["expected_root"]),
                           base["initial_witnesses"], keys, queries, height=64, retention=5)
    selected = {
        "format_version": 1, "kind": "successor-offline-rebuild-component-selection",
        "node_revision": P.REVISION, "node_tree": P.TREE,
        "terminal_parent_tree": R.T.MODIFIED_TREE, "caller_patch_sha256": R.PATCH_SHA256,
        "history_height": 64, "mutation_keys": selection["mutation_keys"],
        "selected_proofs": selection["selected_proofs"],
        "query_heights": sorted(map(int, history["checkpoints"])),
    }
    P.exact(selected["query_heights"], [1, 54, 58, 59, 60, 64])
    return encoded({
        "format_version": 1, "kind": "successor-offline-rebuild-independent-expectations",
        "source": source_identity(), "selection": selected,
        "selection_sha256": P.sha(encoded(selected)), "raw_input": genesis["raw_input"],
        "history": history,
        "witness_origin": {"file": WITNESS_FILE, "sha256": WITNESS_SHA256,
                           "presealed_base_sha256": WITNESS_BASE_SHA256},
        "source_genesis_origin": {"file": GENESIS_FILE, "sha256": GENESIS_SHA256,
                                  "fresh_generator_executed_in_this_derivation": False},
        "earlier_full_projection_prefix_derivation_sha256": "9d9e748adb5811c2064e38b68d690083d1e5e314a9cdff7bc58e86f62428bbf9",
        "reference_backend_executed": False, "old_backend_process_results_relabelled": False,
        "accepted_header_root_binding": False, "production_resources_qualified": False,
        "consumer_result": "REFUSED",
    })


def derive():
    return json.loads(derived_bytes(P.read_regular(HERE / WITNESS_FILE, 4 << 20)), object_pairs_hook=P.pairs)


if __name__ == "__main__":
    try:
        sys.stdout.buffer.write(encoded(derive()))
    except (OSError, ValueError, KeyError, TypeError, IndexError, AssertionError):
        print("Successor offline rebuild derivation refused; preserve inputs and output.", file=sys.stderr)
        sys.exit(1)
