#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Stage the exact terminal-node source for an owned genesis background probe.

Execute no returned command. Source-derived genesis input and independent
expectations are separate caller-pinned files; no existing database is adopted.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import stat
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
def module(name, file):
    spec = importlib.util.spec_from_file_location(name, HERE / file)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value
P = module("genesis_build_hash_identity_parent", "prepare_hash_bound_versions.py")
L = module("genesis_build_terminal_parent", "prepare_lifecycle_stop.py")
PROBE = "genesis_background_probe_test.go"
TAG = "candidate_genesis_background"
MODES = ("resource", "race")
STATE = "chain/state_tree.go"
BACKUP = "hash-identity-parent-state-tree.go"

def require(value):
    if not value:
        raise ValueError("Genesis background preparation refused")

def plan(workspace, mode, go, parent, probe):
    build = list(parent["build_argv"])
    if mode == "race":
        build.insert(build.index("-c") + 1, "-race")
    build[build.index("-tags") + 1] = P.TAG + "," + TAG
    binary = workspace / "generator" / ("genesis-background-" + mode + ".test")
    build[build.index("-o") + 1] = str(binary)
    return {
        "format_version": 1, "kind": "source-genesis-background-prepared-source",
        "mode": mode, "base_revision": P.REVISION, "base_tree": P.TREE,
        "hash_identity_parent_tree": P.MODIFIED_TREE,
        "runtime_tree_without_probes": L.MODIFIED_TREE,
        "source_blobs": 439, "probe_source_files_added": 2,
        "parent_probe_compiled_but_not_selected": P.PROBE,
        "selected_probe": PROBE, "selected_probe_sha256": P.sha(probe),
        "parent_prepared_sha256": P.sha(P.UTIL.encoded(parent)),
        "terminal_patch_sha256": L.PATCH_SHA256, "scheduler_checkpoints_injected": False,
        "upstream_tests_excluded_by_explicit_overlay": list(P.UPSTREAM_TESTS),
        "working_directory": str(workspace / "generator"), "binary": str(binary),
        "build_argv": build,
        "run_argv": [str(binary), "-test.v", "-test.run=^TestCandidateGenesisBackground$"],
        "required_run_environment": {
            "ZENON_GENESIS_BUILD_INPUT": "PINNED_RAW_SOURCE_GENESIS_INPUT",
            "ZENON_GENESIS_BUILD_SAMPLES": "PINNED_INDEPENDENT_BASE_EXPECTATIONS",
            "ZENON_GENESIS_BUILD_WORKSPACE": "NEW_EMPTY_CALLER_OWNED_CASE_DIRECTORY",
            "ZENON_GENESIS_BUILD_POLICY": "archive, pruned, or stop-resume",
        },
        "raw_input_sha256": "a222aac55304b1a489d395235c61af4182ac08b887d24d0c3f654aa402f35e75",
        "raw_input_bytes": 10849399, "history_height": 4096,
        "initial_admitted_leaf_keys": 19257,
        "retention_test_override": 256, "final_pruned_horizon_inclusive": 3840,
        "expected_final_pruned_root_records": 257,
        "header_identifiers_and_suffix_changes_are_synthetic": True,
        "manager_and_genesis_are_controlled_adapters": True,
        "network_acquisition_performed": False, "reference_execution_performed": False,
        "existing_database_adopted": False, "full_node_started": False,
        "profile_agreed": False, "production_qualified": False,
    }

def prepare(node_source, workspace, mode, go):
    require(mode in MODES)
    workspace = P.private_destination(workspace)
    parent = P.prepare(node_source, workspace, "hash-bound", go)
    P.exact(P.verify(workspace, "hash-bound"), parent)
    original = P.read_regular(workspace / "node" / STATE, 128 << 10)
    with (workspace / BACKUP).open("xb") as stream:
        stream.write(original)
    (workspace / BACKUP).chmod(0o400)
    modified = L.patch_state(original)
    require(P.sha(modified) == L.AFTER)
    (workspace / "node" / STATE).write_bytes(modified)
    probe = P.read_regular(HERE / PROBE, 128 << 10)
    require(probe.startswith(("//go:build " + TAG + "\n").encode()))
    with (workspace / "node/chain" / PROBE).open("xb") as stream:
        stream.write(probe)
    result = plan(workspace, mode, go, parent, probe)
    P.UTIL.seal(workspace / "genesis-background-prepared.json", P.UTIL.encoded(result))
    P.exact(verify(workspace, mode), result)
    return result

def verify(workspace, mode):
    require(mode in MODES)
    workspace = Path(workspace).absolute()
    require(workspace.is_dir() and not any(p.is_symlink() for p in (workspace, *workspace.parents)))
    _, manifest = P.source_manifest()
    parent = json.loads(P.read_regular(workspace / "prepared.json", 128 << 10), object_pairs_hook=P.pairs)
    selected = json.loads(P.read_regular(workspace / "genesis-background-prepared.json", 128 << 10), object_pairs_hook=P.pairs)
    original = P.read_regular(workspace / BACKUP, 128 << 10)
    require(P.sha(original) == P.AFTER[STATE])
    modified = L.patch_state(original)
    probe = P.read_regular(HERE / PROBE, 128 << 10)
    expected = plan(workspace, mode, selected["build_argv"][0], parent, probe)
    P.exact(selected, expected)
    node = workspace / "node"
    actual = set()
    for file in node.rglob("*"):
        require(not file.is_symlink())
        if file.is_file():
            info = file.lstat()
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1)
            actual.add(file.relative_to(node).as_posix())
    require(actual == set(manifest["files"]) | {"chain/" + P.PROBE, "chain/" + PROBE})
    pins, parent_pins = {}, {}
    for name, old in manifest["files"].items():
        raw = P.read_regular(node / name, 16 << 20)
        digest = L.AFTER if name == STATE else P.AFTER.get(name, old["sha256"])
        require(P.sha(raw) == digest)
        pins[name] = dict(old, sha256=digest, bytes=len(raw), git_blob=P.UTIL.git_hash("blob", raw))
        inherited = original if name == STATE else raw
        parent_pins[name] = dict(old, sha256=P.sha(inherited), bytes=len(inherited), git_blob=P.UTIL.git_hash("blob", inherited))
    require(P.UTIL.reconstruct_tree(pins) == L.MODIFIED_TREE)
    require(P.UTIL.reconstruct_tree(parent_pins) == P.MODIFIED_TREE)
    require(P.read_regular(node / "chain" / PROBE, 128 << 10) == probe)
    require(P.read_regular(node / "chain" / P.PROBE, 128 << 10) == P.read_regular(HERE / P.PROBE, 128 << 10))
    modules = P.frozen_module()
    require(P.read_regular(workspace / "generator/go.mod", 1 << 20) ==
            modules["go.mod"] + b"\nreplace github.com/zenon-network/go-zenon => ../node\n")
    require(P.read_regular(workspace / "generator/go.sum", 1 << 20) == modules["go.sum"])
    overlay = {"Replace": {str(node / "chain" / name): str(workspace / "test-overlays" / name)
                           for name in P.UPSTREAM_TESTS}}
    require(P.read_regular(workspace / "test-overlay.json", 128 << 10) == P.UTIL.encoded(overlay))
    for name in P.UPSTREAM_TESTS:
        require(P.read_regular(workspace / "test-overlays" / name, 1 << 20) ==
                b"//go:build !" + P.TAG.encode() + b"\n\n" + P.read_regular(node / "chain" / name, 1 << 20))
    P.exact(parent, P.plan(workspace, "hash-bound", selected["build_argv"][0], parent_pins,
                          P.read_regular(HERE / P.PROBE, 128 << 10), overlay))
    return selected

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node-source", type=Path, required=True)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--mode", choices=MODES, required=True)
    parser.add_argument("--go", required=True)
    args = parser.parse_args(argv)
    print(json.dumps(prepare(args.node_source, args.workspace, args.mode, args.go), sort_keys=True))

if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError, IndexError):
        print("Genesis background preparation refused; preserve incomplete owned inputs.", file=sys.stderr)
        sys.exit(1)
