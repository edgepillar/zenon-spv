#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Prepare ordinary public Chain lifecycle builds; execute no returned command.

Select the complete 9c71 source and its own module files. Layer the existing
identity/terminal/offline-caller parent and a separate public Chain guard.
The caller owns acquisition, dependency checks, supervision and fresh scratch.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import stat
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("public_chain_lifecycle_parent", HERE / "prepare_offline_rebuild_successor.py")
R = importlib.util.module_from_spec(spec)
spec.loader.exec_module(R)
P = R.P
PATCH = "node-public-chain-lifecycle-9c71-patch.json"
PATCH_SHA256 = "a72bb29d7b42eb22529de8a9c1d4c978936e300bcbade11b72e681442bbc7020"
AFTER = "dc60bef56e43ff00e10b73a737562c78d4e1971376ce2d31c1eb9496341a24c4"
BEFORE = "58215f89a8148481369d38256dbd7b6eaeba5b4eb3d9e11a315f60b5f0b3fdbc"
MODIFIED_TREE = "8420610538a6a51fd43ed4c6f0e2feb2db8f120f"
CHAIN = "chain/chain.go"
PROBE = "public_chain_lifecycle_probe.go"
PROBE_SHA256 = "d3d5221300f7face9a213ef67470a66af86673eda39ac5bc6ab0eab272e68efe"
ENTRYPOINT = "cmd/candidate-public-chain-lifecycle/main.go"
TAG = "candidate_public_chain_lifecycle"
VARIANTS = ("offline-identity-parent", "public-chain-terminal")
CASES = ("init-after-stop", "start-after-stop", "stop-before-init")


def patch_chain(raw):
    value = P.document(PATCH, PATCH_SHA256)
    require = P.require
    require(type(raw) is bytes and len(raw) == 5155 and P.sha(raw) == BEFORE)
    header = {
        "format_version": 1, "kind": "experimental-successor-public-chain-terminal-lifecycle",
        "node_revision": P.REVISION, "original_node_tree": P.TREE,
        "runtime_parent_tree": R.MODIFIED_TREE, "runtime_after_tree": MODIFIED_TREE,
        "file": CHAIN, "mode": "100644", "before_bytes": 5155, "before_sha256": BEFORE,
        "before_git_blob": "880f16cfea797aacc4ca5a26441bf5d25e5d00d2",
        "after_bytes": 5532, "after_sha256": AFTER,
        "after_git_blob": "5d7f2cdd94d803a95e5f219d91c4e7ff38a35321",
        "experimental_only": True, "disk_format_changed": False, "SMT_profile_changed": False,
        "accepted_header_or_consumer_acceptance_changed": False, "upstream_mutated": False,
    }
    require(type(value) is dict and set(value) == set(header) | {"replacements"})
    P.exact({k: value[k] for k in header}, header)
    rows = value["replacements"]
    require(type(rows) is list and len(rows) == 1 and type(rows[0]) is dict)
    require(set(rows[0]) == {"before", "after"} and all(type(v) is str for v in rows[0].values()))
    require(rows[0]["before"].encode() == raw)
    after = rows[0]["after"].encode()
    require(len(after) == 5532 and P.sha(after) == AFTER)
    require(P.UTIL.git_hash("blob", raw) == header["before_git_blob"])
    require(P.UTIL.git_hash("blob", after) == header["after_git_blob"])
    require(after.replace(after, raw, 1) == raw)
    return after


def selection(variant):
    P.require(variant in VARIANTS)
    manifest, modified, state, pins = R.runtime_selection("full-identifier")
    P.require(P.UTIL.reconstruct_tree(pins) == R.MODIFIED_TREE)
    modified = dict(modified, **{R.T.STATE: state})
    descriptor = P.document(PATCH, PATCH_SHA256)
    before = descriptor["replacements"][0]["before"].encode()
    P.require(P.sha(before) == manifest["files"][CHAIN]["sha256"])
    after = patch_chain(before)
    if variant == "public-chain-terminal":
        modified[CHAIN] = after
        pins[CHAIN].update(bytes=len(after), sha256=P.sha(after), git_blob=P.UTIL.git_hash("blob", after))
    P.require(P.UTIL.reconstruct_tree(pins) == (MODIFIED_TREE if variant == VARIANTS[1] else R.MODIFIED_TREE))
    return manifest, modified, pins


def probe_bytes():
    raw = P.read_regular(HERE / PROBE, 128 << 10)
    P.require(len(raw) == 4585 and P.sha(raw) == PROBE_SHA256)
    P.require(raw.startswith(("//go:build " + TAG + "\n").encode()))
    return raw


def plan(workspace, variant, go):
    P.require(variant in VARIANTS and type(go) is str and bool(go) and "\x00" not in go)
    manifest, _, pins = selection(variant)
    probe = probe_bytes()
    build_pins = dict(pins)
    build_pins[ENTRYPOINT] = {"mode": "100644", "bytes": len(probe), "sha256": P.sha(probe),
                             "git_blob": P.UTIL.git_hash("blob", probe)}
    binary = workspace / "public-chain-lifecycle"
    return {
        "format_version": 1, "kind": "prepared-public-chain-terminal-lifecycle", "variant": variant,
        "node_revision": P.REVISION, "original_node_tree": P.TREE, "node_source_blobs": 467,
        "source_manifest_sha256": P.SOURCE_SHA256,
        "runtime_tree_without_entrypoint": P.UTIL.reconstruct_tree(pins),
        "build_tree_with_entrypoint": P.UTIL.reconstruct_tree(build_pins),
        "public_chain_patch_sha256": PATCH_SHA256, "probe_sha256": P.sha(probe),
        "parent_identity_patch_sha256": P.PATCH_SHA256, "parent_terminal_patch_sha256": R.T.PATCH_SHA256,
        "parent_offline_caller_patch_sha256": R.PATCH_SHA256,
        "module_selection": "selected-node-own-go.mod-and-go.sum",
        "module_sha256": manifest["files"]["go.mod"]["sha256"],
        "sum_sha256": manifest["files"]["go.sum"]["sha256"],
        "working_directory": str(workspace / "node"), "binary": str(binary),
        "build_argv": [go, "build", "-mod=readonly", "-trimpath", "-buildvcs=false", "-tags", TAG,
                       "-o", str(binary), "./cmd/candidate-public-chain-lifecycle"],
        "run_argv_template": [str(binary), "--case", "SELECT_ONE_DECLARED_CASE", "--root",
                              "NEW_EMPTY_OWNED_CASE_DIRECTORY", "--key", "PRESELECTED_COVERED_KEY_HEX"],
        "cases": list(CASES), "build_timeout_seconds": 240, "case_timeout_seconds": 90,
        "stdout_limit_bytes": 4 << 20, "expected_allocation_bytes": 2 << 30,
        "minimum_free_floor_bytes_before_reservations": 10 << 30, "task_quota_bytes": 3 << 30,
        "required_environment_policy": "private bounded caches; local pinned Go; no implicit module transport",
        "ordinary_build": True, "Go_race_detector_selected": False,
        "test_overlays_or_scheduler_hooks": False, "upstream_test_suite_selected": False,
        "source_acquisition_performed": False, "reference_backend_executed": False,
        "existing_database_adopted": False, "full_node_or_network_started": False,
        "node_client_profile_agreed": False, "runtime_state_value_acceptance": False,
        "production_qualified": False, "consumer_result": "REFUSED",
    }


def prepare(node_source, workspace, variant, go):
    expected = plan(Path(workspace).absolute(), variant, go)
    workspace = P.private_destination(workspace)
    node_source = Path(node_source).absolute()
    P.require(not any(p.is_symlink() for p in (node_source, *node_source.parents)))
    manifest, modified, _ = selection(variant)
    original = P.UTIL.snapshot_source(node_source, manifest["files"])
    for name, raw in original.items():
        P.require(P.read_regular(node_source / name, 16 << 20) == raw)
    # Validate everything before creating the exclusive destination. A failure
    # afterwards preserves the caller's partial workspace for supervised cleanup.
    workspace.mkdir(mode=0o700)
    node = workspace / "node"
    for name, pin in manifest["files"].items():
        path = node / name
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as stream:
            stream.write(modified.get(name, original[name]))
        path.chmod(int(pin["mode"], 8) & 0o777)
    entrypoint = node / ENTRYPOINT
    entrypoint.parent.mkdir(parents=True, exist_ok=True)
    with entrypoint.open("xb") as stream:
        stream.write(probe_bytes())
    P.UTIL.seal(workspace / "public-chain-prepared.json", P.UTIL.encoded(expected))
    P.exact(verify(workspace, variant, go), expected)
    return expected


def verify(workspace, variant, go):
    workspace = Path(workspace).absolute()
    P.require(workspace.is_dir() and not any(p.is_symlink() for p in (workspace, *workspace.parents)))
    _, _, pins = selection(variant)
    expected = plan(workspace, variant, go)
    node = workspace / "node"
    P.require(node.is_dir() and not node.is_symlink())
    actual = set()
    for path in node.rglob("*"):
        info = path.lstat()
        P.require(not path.is_symlink() and (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)))
        if stat.S_ISREG(info.st_mode):
            P.require(info.st_nlink == 1)
            actual.add(path.relative_to(node).as_posix())
    P.require(actual == set(pins) | {ENTRYPOINT})
    for name, pin in pins.items():
        raw = P.read_regular(node / name, 16 << 20)
        P.require(len(raw) == pin["bytes"] and P.sha(raw) == pin["sha256"])
        P.require(stat.S_IMODE((node / name).stat().st_mode) == (int(pin["mode"], 8) & 0o777) or sys.platform == "win32")
    P.require(P.read_regular(node / ENTRYPOINT, 128 << 10) == probe_bytes())
    recorded = json.loads(P.read_regular(workspace / "public-chain-prepared.json", 128 << 10), object_pairs_hook=P.pairs)
    P.exact(recorded, expected)
    return recorded


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
    except (OSError, ValueError, TypeError, KeyError, IndexError):
        print("Public Chain preparation refused; preserve owned inputs and partial workspace.", file=sys.stderr)
        sys.exit(1)
