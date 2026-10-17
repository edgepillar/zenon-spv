#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Prepare one ordinary resource probe on the separately pinned successor.

Execute no build or returned command. Verify the complete selected source, its
own module files, both experimental runtime patches and every compiler overlay.
Historical source selectors and recorded observations remain unchanged.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import stat
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("retention_successor_terminal", HERE / "prepare_terminal_stop_successor.py")
T = importlib.util.module_from_spec(spec)
spec.loader.exec_module(T)
P = T.P
PROBE = "default_retention_successor_probe_test.go"
TAG = "candidate_default_retention_successor"
HELPER = "genesis_background_probe_test.go"
HELPER_TAG = "candidate_genesis_background"
BACKUP = "parent-state-tree.go"


def require(value):
    if not value:
        raise ValueError("Successor default-retention preparation refused")


def plan(workspace, go, parent, probe, helper):
    require(type(go) is str and bool(go))
    build = list(parent["build_argv"])
    require(build[0] == go and "-race" not in build and build[-1] == "./chain")
    binary = workspace / "default-retention-successor.test"
    build[build.index("-tags") + 1] = ",".join((P.TAG, HELPER_TAG, TAG))
    build[build.index("-o") + 1] = str(binary)
    return {
        "format_version": 1, "kind": "successor-source-default-retention-prepared-component",
        "node_revision": P.REVISION, "original_node_tree": P.TREE,
        "runtime_tree_without_probes": T.MODIFIED_TREE, "node_source_blobs": 467,
        "hash_identity_patch_sha256": P.PATCH_SHA256, "terminal_patch_sha256": T.PATCH_SHA256,
        "parent_prepared_sha256": P.sha(P.UTIL.encoded(parent)),
        "selected_probe": PROBE, "selected_probe_sha256": P.sha(probe),
        "parent_helpers_compiled_but_not_selected": [P.PROBE, HELPER],
        "genesis_helper_sha256": P.sha(helper), "compiled_test_source_files_added": 3,
        "module_selection": parent["module_selection"], "module_sha256": parent["module_sha256"],
        "sum_sha256": parent["sum_sha256"],
        "history_height": 32768, "mutation_addresses": 256,
        "retention_override": 0, "bulk_batch_override": 0,
        "source_effective_retention": 17380, "expected_pruned_horizon_inclusive": 15388,
        "expected_pruned_roots": 17381, "expected_archive_roots": 32768,
        "working_directory": parent["working_directory"], "binary": str(binary),
        "build_argv": build,
        "run_argv": [str(binary), "-test.v", "-test.timeout=540s",
                     "-test.run=^TestCandidateDefaultRetentionSuccessor$"],
        "required_run_environment": {
            "ZENON_DEFAULT_RETENTION_INPUT": "FRESH_PINNED_SUCCESSOR_SOURCE_GENESIS_DUMP",
            "ZENON_DEFAULT_RETENTION_SELECTION": "PINNED_INDEPENDENT_SUCCESSOR_SELECTION",
            "ZENON_DEFAULT_RETENTION_SELECTION_SHA256": "SELECTED_BEFORE_BACKEND_EXECUTION",
            "ZENON_DEFAULT_RETENTION_WORKSPACE": "NEW_EMPTY_OWNED_CASE_DIRECTORY",
            "ZENON_DEFAULT_RETENTION_POLICY": "pruned or archive",
        },
        "build_mode": "ordinary_resource_measurement_not_race_instrumented",
        "scheduler_checkpoints_injected": False,
        "runtime_changes_beyond_identity_and_terminal_stop_patches": False,
        "upstream_tests_excluded_by_explicit_overlay": list(P.UPSTREAM_TESTS),
        "source_identifiers_and_suffix_changes_are_synthetic": True,
        "manager_and_genesis_are_controlled_adapters": True,
        "source_acquisition_performed": False, "reference_backend_executed": False,
        "existing_database_adopted": False, "full_node_started": False,
        "historical_source_records_rebound": False, "profile_agreed": False,
        "accepted_header_root_binding": False, "production_resources_qualified": False,
        "consumer_result": "REFUSED",
    }


def prepare(node_source, workspace, go):
    workspace = P.private_destination(workspace)
    parent = P.prepare(node_source, workspace, "hash-bound", go)
    P.exact(P.verify(workspace, "hash-bound", go), parent)
    original = P.read_regular(workspace / "node" / T.STATE, 128 << 10)
    with (workspace / BACKUP).open("xb") as stream:
        stream.write(original)
    (workspace / BACKUP).chmod(0o400)
    (workspace / "node" / T.STATE).write_bytes(T.patch_state(original))
    for name, tag in ((HELPER, HELPER_TAG), (PROBE, TAG)):
        raw = P.read_regular(HERE / name, 128 << 10)
        require(raw.startswith(("//go:build " + tag + "\n").encode()))
        with (workspace / "node/chain" / name).open("xb") as stream:
            stream.write(raw)
    result = plan(workspace, go, parent, P.read_regular(HERE / PROBE, 128 << 10),
                  P.read_regular(HERE / HELPER, 128 << 10))
    P.UTIL.seal(workspace / "successor-retention-prepared.json", P.UTIL.encoded(result))
    P.exact(verify(workspace, go), result)
    return result


def verify(workspace, go):
    workspace = Path(workspace).absolute()
    require(workspace.is_dir() and not any(p.is_symlink() for p in (workspace, *workspace.parents)))
    manifest, modified, parent_pins = T.parent_selection()
    original = P.read_regular(workspace / BACKUP, 128 << 10)
    require(original == modified[T.STATE])
    terminal = T.patch_state(original)
    node = workspace / "node"
    require(node.is_dir() and not node.is_symlink())
    actual = set()
    for path in node.rglob("*"):
        require(not path.is_symlink())
        info = path.lstat()
        require(stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode))
        if stat.S_ISREG(info.st_mode):
            require(info.st_nlink == 1)
            actual.add(path.relative_to(node).as_posix())
    require(actual == set(manifest["files"]) | {"chain/" + name for name in (P.PROBE, HELPER, PROBE)})
    pins = {}
    for name, old in parent_pins.items():
        raw = P.read_regular(node / name, 16 << 20)
        expected = terminal if name == T.STATE else None
        require(P.sha(raw) == (P.sha(expected) if expected is not None else old["sha256"]))
        require(len(raw) == (len(expected) if expected is not None else old["bytes"]))
        pins[name] = dict(old, bytes=len(raw), sha256=P.sha(raw), git_blob=P.UTIL.git_hash("blob", raw))
    require(P.UTIL.reconstruct_tree(pins) == T.MODIFIED_TREE)
    for name in (P.PROBE, HELPER, PROBE):
        require(P.read_regular(node / "chain" / name, 128 << 10) == P.read_regular(HERE / name, 128 << 10))
    overlay = {"Replace": {str(node / "chain" / name): str(workspace / "test-overlays" / name)
                           for name in P.UPSTREAM_TESTS}}
    overlay_raw = P.read_regular(workspace / "test-overlay.json", 128 << 10)
    require(overlay_raw == P.UTIL.encoded(overlay))
    for name in P.UPSTREAM_TESTS:
        require(P.read_regular(workspace / "test-overlays" / name, 1 << 20) ==
                b"//go:build !" + P.TAG.encode() + b"\n\n" + P.read_regular(node / "chain" / name, 1 << 20))
    parent = json.loads(P.read_regular(workspace / "prepared.json", 128 << 10), object_pairs_hook=P.pairs)
    P.exact(parent, P.plan(workspace, "hash-bound", go, parent_pins,
                          P.read_regular(HERE / P.PROBE, 128 << 10), overlay_raw,
                          P.read_regular(node / "go.mod", 1 << 20), P.read_regular(node / "go.sum", 1 << 20)))
    selected = json.loads(P.read_regular(workspace / "successor-retention-prepared.json", 128 << 10),
                          object_pairs_hook=P.pairs)
    P.exact(selected, plan(workspace, go, parent, P.read_regular(HERE / PROBE, 128 << 10),
                           P.read_regular(HERE / HELPER, 128 << 10)))
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
        print("Successor default-retention preparation refused; preserve inputs and partial source.", file=sys.stderr)
        sys.exit(1)
