#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Prepare a fresh source-default retention probe; execute no returned command.

The verified terminal-node runtime and earlier helper probes stay byte-identical.
The earlier tests are compiled as helpers but only the new test is selected.
Source acquisition, compilation and resource supervision remain caller-owned.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import stat
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


G = module("default_retention_genesis_preparation", "prepare_genesis_background.py")
P = G.P
PROBE = "default_retention_probe_test.go"
TAG = "candidate_default_retention"


def plan(workspace, go, parent):
    build = list(parent["build_argv"])
    build[build.index("-tags") + 1] += "," + TAG
    binary = workspace / "generator/default-retention.test"
    build[build.index("-o") + 1] = str(binary)
    probe = P.read_regular(HERE / PROBE, 128 << 10)
    return {
        "format_version": 1, "kind": "source-default-retention-prepared-component",
        "node_revision": P.REVISION, "original_node_tree": P.TREE,
        "runtime_tree_without_probes": G.L.MODIFIED_TREE,
        "node_source_blobs": 439, "probe_source_files_added": 3,
        "parent_probe_compiled_but_not_selected": [P.PROBE, G.PROBE],
        "selected_probe": PROBE, "selected_probe_sha256": P.sha(probe),
        "parent_genesis_prepared_sha256": P.sha(P.UTIL.encoded(parent)),
        "history_height": 32768, "mutation_keys": 256,
        "retention_override": 0, "bulk_batch_override": 0,
        "source_effective_retention": 17380,
        "expected_pruned_horizon_inclusive": 15388,
        "expected_pruned_roots": 17381, "expected_archive_roots": 32768,
        "working_directory": str(workspace / "generator"), "binary": str(binary),
        "build_argv": build,
        "run_argv": [str(binary), "-test.v", "-test.timeout=540s",
                     "-test.run=^TestCandidateDefaultRetention$"],
        "required_run_environment": {
            "ZENON_DEFAULT_RETENTION_INPUT": "PINNED_SOURCE_GENESIS_DUMP",
            "ZENON_DEFAULT_RETENTION_SELECTION": "PINNED_INDEPENDENT_SELECTION",
            "ZENON_DEFAULT_RETENTION_SELECTION_SHA256": "SELECTED_BEFORE_BACKEND_EXECUTION",
            "ZENON_DEFAULT_RETENTION_WORKSPACE": "NEW_EMPTY_OWNED_CASE_DIRECTORY",
            "ZENON_DEFAULT_RETENTION_POLICY": "pruned or archive",
        },
        "build_mode": "ordinary_resource_measurement_not_race_instrumented",
        "scheduler_checkpoints_injected": False,
        "runtime_changes_beyond_existing_retained_identity_and_terminal_stop_patches": False,
        "upstream_tests_excluded_by_explicit_overlay": list(P.UPSTREAM_TESTS),
        "source_identifiers_and_suffix_changes_are_synthetic": True,
        "manager_and_genesis_are_controlled_adapters": True,
        "new_network_or_source_acquisition": False, "reference_backend_executed": False,
        "existing_database_adopted": False, "full_node_started": False,
        "profile_agreed": False, "accepted_header_root_binding": False,
        "production_resources_qualified": False, "consumer_result": "REFUSED",
    }


def prepare(node_source, workspace, go):
    workspace = P.private_destination(workspace)
    parent = G.prepare(node_source, workspace, "resource", go)
    P.exact(G.verify(workspace, "resource"), parent)
    probe = P.read_regular(HERE / PROBE, 128 << 10)
    P.require(probe.startswith(("//go:build " + TAG + "\n").encode()))
    with (workspace / "node/chain" / PROBE).open("xb") as stream:
        stream.write(probe)
    result = plan(workspace, go, parent)
    P.UTIL.seal(workspace / "default-retention-prepared.json", P.UTIL.encoded(result))
    P.exact(verify(workspace), result)
    return result


def verify(workspace):
    workspace = Path(workspace).absolute()
    P.require(workspace.is_dir() and not any(p.is_symlink() for p in (workspace, *workspace.parents)))
    _, manifest = P.source_manifest()
    node = workspace / "node"
    probes = {P.PROBE, G.PROBE, PROBE}
    actual = set()
    for path in node.rglob("*"):
        P.require(not path.is_symlink())
        if path.is_file():
            info = path.lstat()
            P.require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1)
            actual.add(path.relative_to(node).as_posix())
    P.require(actual == set(manifest["files"]) | {"chain/" + name for name in probes})
    prior_state = P.read_regular(workspace / G.BACKUP, 128 << 10)
    P.require(P.sha(prior_state) == P.AFTER[G.STATE])
    P.require(P.sha(G.L.patch_state(prior_state)) == G.L.AFTER)
    pins, parent_pins = {}, {}
    for name, old in manifest["files"].items():
        raw = P.read_regular(node / name, 16 << 20)
        digest = G.L.AFTER if name == G.STATE else P.AFTER.get(name, old["sha256"])
        P.require(P.sha(raw) == digest)
        pins[name] = dict(old, sha256=digest, bytes=len(raw), git_blob=P.UTIL.git_hash("blob", raw))
        earlier = prior_state if name == G.STATE else raw
        parent_pins[name] = dict(old, sha256=P.sha(earlier), bytes=len(earlier),
                                 git_blob=P.UTIL.git_hash("blob", earlier))
    P.require(P.UTIL.reconstruct_tree(pins) == G.L.MODIFIED_TREE)
    P.require(P.UTIL.reconstruct_tree(parent_pins) == P.MODIFIED_TREE)
    for name in probes:
        P.require(P.read_regular(node / "chain" / name, 128 << 10) ==
                  P.read_regular(HERE / name, 128 << 10))
    modules = P.frozen_module()
    P.require(P.read_regular(workspace / "generator/go.mod", 1 << 20) ==
              modules["go.mod"] + b"\nreplace github.com/zenon-network/go-zenon => ../node\n")
    P.require(P.read_regular(workspace / "generator/go.sum", 1 << 20) == modules["go.sum"])
    overlay = {"Replace": {str(node / "chain" / name): str(workspace / "test-overlays" / name)
                           for name in P.UPSTREAM_TESTS}}
    P.require(P.read_regular(workspace / "test-overlay.json", 128 << 10) == P.UTIL.encoded(overlay))
    for name in P.UPSTREAM_TESTS:
        P.require(P.read_regular(workspace / "test-overlays" / name, 1 << 20) ==
                  b"//go:build !" + P.TAG.encode() + b"\n\n" +
                  P.read_regular(node / "chain" / name, 1 << 20))
    selected = json.loads(P.read_regular(workspace / "default-retention-prepared.json", 128 << 10),
                          object_pairs_hook=P.pairs)
    parent = json.loads(P.read_regular(workspace / "genesis-background-prepared.json", 128 << 10),
                        object_pairs_hook=P.pairs)
    hash_parent = json.loads(P.read_regular(workspace / "prepared.json", 128 << 10), object_pairs_hook=P.pairs)
    go = selected["build_argv"][0]
    P.exact(hash_parent, P.plan(workspace, "hash-bound", go, parent_pins,
                               P.read_regular(HERE / P.PROBE, 128 << 10), overlay))
    P.exact(parent, G.plan(workspace, "resource", go, hash_parent,
                           P.read_regular(HERE / G.PROBE, 128 << 10)))
    P.exact(selected, plan(workspace, go, parent))
    return selected


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node-source", type=Path, required=True)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--go", required=True)
    args = parser.parse_args(argv)
    print(json.dumps(prepare(args.node_source, args.workspace, args.go), sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError, IndexError, AssertionError):
        print("Default-retention preparation refused; preserve owned inputs and partial source.", file=sys.stderr)
        sys.exit(1)
