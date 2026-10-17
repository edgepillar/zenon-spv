#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Derive new successor expectations before any NodeTree backend execution.

Reuse only the independent byte, sparse-tree and mutation algorithms. Original
source selectors and observations are never relabelled. Fresh source-genesis
process evidence is a separate required binding in the recorded comparison.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


M = module("successor_retention_pure_algorithms", "default_retention_model.py")
T = module("successor_retention_runtime_selection", "prepare_terminal_stop_successor.py")
P = T.P
encoded = M.encoded


def source_identity():
    manifest = P.source_manifest()
    return {"node_revision": P.REVISION, "node_tree": P.TREE,
            "runtime_tree": T.MODIFIED_TREE, "source_blobs": 467,
            "source_manifest_sha256": P.SOURCE_SHA256,
            "module_sha256": manifest["files"]["go.mod"]["sha256"],
            "sum_sha256": manifest["files"]["go.sum"]["sha256"],
            "hash_identity_patch_sha256": P.PATCH_SHA256,
            "terminal_patch_sha256": T.PATCH_SHA256}


def checked_source(files):
    manifest = P.source_manifest()
    P.require(type(files) is dict and set(files) == set(manifest["files"]))
    for name, pin in manifest["files"].items():
        raw = files[name]
        P.require(type(raw) is bytes and len(raw) == pin["bytes"] and P.sha(raw) == pin["sha256"])
    # These are source checks, not a claim that a network uses these defaults.
    state, cache = files["chain/state_tree.go"], files["chain/cache/storage/db.go"]
    for declaration in (b"const stateTreeRetentionMargin = uint64(17280)",
                        b"const stateTreeBuildBulkBatchSize = uint64(10000)",
                        b"const stateTreeBuildTailBatchSize = uint64(10)",
                        b"const stateTreeBuildBatchBudget = time.Second"):
        P.require(state.count(declaration) == 1)
    P.require(b"rollbackCacheSize = 100" in cache)
    return json.loads(files["chain/genesis/embedded_genesis_string.go"].split(b"`")[1],
                      object_pairs_hook=P.pairs)


def derive(raw, files):
    config = checked_source(files)
    # The newly executed input must independently match this finite byte
    # contract. Equality permits algorithm reuse, never old process provenance.
    result = M.derive(raw, config)
    identity = source_identity()
    result.update(kind="successor-source-default-retention-independent-expectations",
                  node_revision=P.REVISION, node_tree=P.TREE,
                  runtime_tree=T.MODIFIED_TREE, source_identity=identity,
                  historical_source_records_rebound=False)
    selection = result["selection"]
    selection.update(kind="successor-source-default-retention-component-selection",
                     node_revision=P.REVISION, node_tree=P.TREE, runtime_tree=T.MODIFIED_TREE)
    result["selection_sha256"] = hashlib.sha256(encoded(selection)).hexdigest()
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--node-source", type=Path, required=True)
    args = parser.parse_args(argv)
    manifest = P.source_manifest()
    files = P.UTIL.snapshot_source(args.node_source, manifest["files"])
    sys.stdout.buffer.write(encoded(derive(P.read_regular(args.input, M.G.RAW["bytes"]), files)))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError, IndexError, AssertionError):
        print("Successor retention derivation refused; preserve owned inputs and output.", file=sys.stderr)
        sys.exit(1)
