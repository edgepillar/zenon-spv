#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Prepare a bounded offline rebuild experiment; execute no returned command.

Keep the complete selected source, its own modules, the identity/terminal parent
and the separate caller patch independently pinned. Only fresh caller-owned
workspaces are accepted. Historical selectors and observations stay unchanged.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import stat
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("rebuild_successor_terminal", HERE / "prepare_terminal_stop_successor.py")
T = importlib.util.module_from_spec(spec)
spec.loader.exec_module(T)
P = T.P
PATCH = "node-offline-rebuild-9c71-patch.json"
PATCH_SHA256 = "674baa97de325e69517d730f2fc638399db4411e69b079f6a4bbe2365ffe39fb"
MODIFIED_TREE = "e60c875a06361f04d05301c0e4c61fd429995c5a"
AFTER = "31ace48cb9b0f50b66d421f2acb7220ee151dd8209cf2b86d6359d192044d45e"
AFTER_BLOB = "a5e3804c3ce58c4759c2b52897ee738dc5307228"
AFTER_BYTES = 32090
PROBE = "offline_rebuild_successor_probe_test.go"
TAG = "candidate_offline_rebuild_successor"
VARIANTS = ("terminal-parent", "full-identifier")
BACKUP = "rebuild-identity-parent-state-tree.go"


def require(value):
    if not value:
        raise ValueError("Successor offline rebuild preparation refused")


def patch_state(raw):
    value = P.document(PATCH, PATCH_SHA256)
    require(type(raw) is bytes and len(raw) == T.AFTER_BYTES and P.sha(raw) == T.AFTER)
    expected = {
        "format_version": 1, "kind": "experimental-successor-full-identifier-offline-rebuild",
        "base_revision": P.REVISION, "base_tree": P.TREE, "base_blob_count": 467,
        "terminal_parent_tree": T.MODIFIED_TREE, "terminal_patch_sha256": T.PATCH_SHA256,
        "modified_node_tree_without_probes": MODIFIED_TREE, "file": T.STATE, "mode": "100644",
        "before_bytes": T.AFTER_BYTES, "before_sha256": T.AFTER,
        "before_git_blob": P.UTIL.git_hash("blob", raw),
        "after_bytes": AFTER_BYTES, "after_sha256": AFTER, "after_git_blob": AFTER_BLOB,
        "replacements": value["replacements"], "experimental_only": True,
        "disk_format_changed_relative_to_terminal_parent": False, "SMT_profile_changed": False,
        "public_Root_identity_checks_relaxed": False, "automatic_migration_added": False,
        "network_activation_authenticated": False, "state_value_acceptance_enabled": False,
        "historical_source_records_rebound": False, "production_qualified": False,
    }
    P.exact(value, expected)
    require(type(value["replacements"]) is list and len(value["replacements"]) == 1)
    row = value["replacements"][0]
    require(type(row) is dict and set(row) == {"before", "after"})
    require(all(type(text) is str and bool(text) for text in row.values()))
    before, after = row["before"].encode(), row["after"].encode()
    require(raw.count(before) == 1)
    result = raw.replace(before, after, 1)
    require(result.count(after) == 1 and result.replace(after, before, 1) == raw)
    require(len(result) == AFTER_BYTES and P.sha(result) == AFTER
            and P.UTIL.git_hash("blob", result) == AFTER_BLOB)
    return result


def runtime_selection(variant):
    require(variant in VARIANTS)
    manifest, modified, pins = T.parent_selection()
    selected = T.patch_state(modified[T.STATE])
    pins[T.STATE].update(bytes=len(selected), sha256=P.sha(selected), git_blob=P.UTIL.git_hash("blob", selected))
    require(P.UTIL.reconstruct_tree(pins) == T.MODIFIED_TREE)
    if variant == "full-identifier":
        selected = patch_state(selected)
        pins[T.STATE].update(bytes=len(selected), sha256=P.sha(selected), git_blob=P.UTIL.git_hash("blob", selected))
    require(P.UTIL.reconstruct_tree(pins) == (MODIFIED_TREE if variant == "full-identifier" else T.MODIFIED_TREE))
    return manifest, modified, selected, pins


def plan(workspace, variant, go, parent, probe):
    require(type(go) is str and bool(go) and variant in VARIANTS)
    binary = workspace / "offline-rebuild-successor.test"
    build = list(parent["build_argv"])
    require(build[0] == go and "-race" not in build and build[-1] == "./chain")
    build[build.index("-tags") + 1] = P.TAG + "," + TAG
    build[build.index("-o") + 1] = str(binary)
    return {
        "format_version": 1, "kind": "successor-offline-rebuild-prepared-component", "variant": variant,
        "node_revision": P.REVISION, "original_node_tree": P.TREE,
        "terminal_parent_tree": T.MODIFIED_TREE,
        "runtime_tree_without_probes": MODIFIED_TREE if variant == "full-identifier" else T.MODIFIED_TREE,
        "source_blobs": 467, "hash_identity_patch_sha256": P.PATCH_SHA256,
        "terminal_patch_sha256": T.PATCH_SHA256, "caller_patch_sha256": PATCH_SHA256,
        "parent_prepared_sha256": P.sha(P.UTIL.encoded(parent)),
        "selected_probe": PROBE, "selected_probe_sha256": P.sha(probe),
        "parent_probe_compiled_but_not_selected": P.PROBE, "compiled_test_source_files_added": 2,
        "module_selection": parent["module_selection"], "module_sha256": parent["module_sha256"],
        "sum_sha256": parent["sum_sha256"], "upstream_tests_excluded_by_explicit_overlay": list(P.UPSTREAM_TESTS),
        "history_height": 64, "mutation_addresses": 256, "short_functional_retention_override": 5,
        "scheduler_checkpoints_injected": False, "Go_race_detector_selected": False,
        "working_directory": parent["working_directory"], "binary": str(binary), "build_argv": build,
        "run_argv": [str(binary), "-test.v", "-test.timeout=180s", "-test.run=^TestCandidateOfflineRebuildSuccessor$"],
        "required_run_environment": {
            "ZENON_OFFLINE_REBUILD_VARIANT": variant,
            "ZENON_OFFLINE_REBUILD_INPUT": "PINNED_SUCCESSOR_SOURCE_GENESIS_DUMP",
            "ZENON_OFFLINE_REBUILD_SELECTION": "SEALED_INDEPENDENT_FINITE_SELECTION",
            "ZENON_OFFLINE_REBUILD_SELECTION_SHA256": "SELECTED_BEFORE_BACKEND_EXECUTION",
            "ZENON_OFFLINE_REBUILD_WORKSPACE": "NEW_EMPTY_OWNED_CASE_DIRECTORY",
        },
        "ordinary_functional_component_not_resource_benchmark": True,
        "source_acquisition_performed": False, "reference_backend_executed": False,
        "existing_database_adopted": False, "full_node_started": False,
        "historical_source_records_rebound": False, "profile_agreed": False,
        "accepted_header_root_binding": False, "production_resources_qualified": False,
        "consumer_result": "REFUSED",
    }


def prepare(node_source, workspace, variant, go):
    require(variant in VARIANTS and type(go) is str and bool(go))
    workspace = P.private_destination(workspace)
    parent = P.prepare(node_source, workspace, "hash-bound", go)
    P.exact(P.verify(workspace, "hash-bound", go), parent)
    _, modified, chosen, _ = runtime_selection(variant)
    original = P.read_regular(workspace / "node" / T.STATE, 128 << 10)
    require(original == modified[T.STATE])
    with (workspace / BACKUP).open("xb") as stream:
        stream.write(original)
    (workspace / BACKUP).chmod(0o400)
    (workspace / "node" / T.STATE).write_bytes(chosen)
    probe = P.read_regular(HERE / PROBE, 128 << 10)
    require(probe.startswith(("//go:build " + TAG + "\n").encode()))
    with (workspace / "node/chain" / PROBE).open("xb") as stream:
        stream.write(probe)
    result = plan(workspace, variant, go, parent, probe)
    P.UTIL.seal(workspace / "offline-rebuild-prepared.json", P.UTIL.encoded(result))
    P.exact(verify(workspace, variant, go), result)
    return result


def verify(workspace, variant, go):
    require(variant in VARIANTS and type(go) is str and bool(go))
    workspace = Path(workspace).absolute()
    require(workspace.is_dir() and not any(p.is_symlink() for p in (workspace, *workspace.parents)))
    manifest, modified, chosen, runtime_pins = runtime_selection(variant)
    original = P.read_regular(workspace / BACKUP, 128 << 10)
    require(original == modified[T.STATE])
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
    require(actual == set(manifest["files"]) | {"chain/" + P.PROBE, "chain/" + PROBE})
    for name, pin in runtime_pins.items():
        raw = P.read_regular(node / name, 16 << 20)
        require(len(raw) == pin["bytes"] and P.sha(raw) == pin["sha256"])
    require(P.read_regular(node / T.STATE, 128 << 10) == chosen)
    for name in (P.PROBE, PROBE):
        require(P.read_regular(node / "chain" / name, 128 << 10) == P.read_regular(HERE / name, 128 << 10))
    parent = json.loads(P.read_regular(workspace / "prepared.json", 128 << 10), object_pairs_hook=P.pairs)
    _, _, parent_pins = T.parent_selection()
    overlay = {"Replace": {str(node / "chain" / name): str(workspace / "test-overlays" / name)
                           for name in P.UPSTREAM_TESTS}}
    overlay_raw = P.read_regular(workspace / "test-overlay.json", 128 << 10)
    require(overlay_raw == P.UTIL.encoded(overlay))
    for name in P.UPSTREAM_TESTS:
        require(P.read_regular(workspace / "test-overlays" / name, 1 << 20) ==
                b"//go:build !" + P.TAG.encode() + b"\n\n" + P.read_regular(node / "chain" / name, 1 << 20))
    P.exact(parent, P.plan(workspace, "hash-bound", go, parent_pins,
                         P.read_regular(HERE / P.PROBE, 128 << 10), overlay_raw,
                         P.read_regular(node / "go.mod", 1 << 20), P.read_regular(node / "go.sum", 1 << 20)))
    selected = json.loads(P.read_regular(workspace / "offline-rebuild-prepared.json", 128 << 10), object_pairs_hook=P.pairs)
    P.exact(selected, plan(workspace, variant, go, parent, P.read_regular(HERE / PROBE, 128 << 10)))
    return selected


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node-source", type=Path, required=True)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--variant", choices=VARIANTS, required=True)
    parser.add_argument("--go", required=True)
    args = parser.parse_args(argv)
    print(json.dumps(prepare(args.node_source, args.workspace, args.variant, args.go), sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError, IndexError, AssertionError):
        print("Successor offline rebuild preparation refused; preserve owned inputs and partial workspace.", file=sys.stderr)
        sys.exit(1)
