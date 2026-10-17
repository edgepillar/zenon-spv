#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Stage one new source-pinned recovery experiment; execute no commands.

This successor keeps every historical selector, patch and result unchanged.
Acquisition, private dependency caches, process supervision and cleanup belong
to the caller. Only fresh owned directories are accepted.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import stat
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
REVISION = "9c71ae82fc983e16f914ae085d4034030c8ebe3b"
TREE = "d0f5dfb09e737a806cfc743bb6ba9ddd101ebcd6"
MODIFIED_TREE = "249f3e33e54263efc7c3cad16c02a4784df74040"
SOURCE_MANIFEST = "node-recovery-9c71-source-pins.json"
SOURCE_SHA256 = "80104c7c6b5086a6b851c9c5e82920c5bd196c4252781acf88fc9c4b74d6cc84"
PATCH = "node-recovery-9c71-patch.json"
PATCH_SHA256 = "6d7508cc0ef0dd01a0ccb136a1f562d9ea356a0c18c4e68a2f33f5c32503564b"
PROBE = "hash_bound_versions_successor_probe_test.go"
TAG = "candidate_hash_bound_versions_successor"
VARIANTS = ("baseline", "hash-bound")
UPSTREAM_TESTS = (
    "account_pool_replacement_test.go", "account_pool_rollback_regression_test.go",
    "account_pool_test.go", "chain_stop_test.go", "momentum_pool_test.go",
    "state_tree_ready_test.go", "state_tree_update_test.go", "test_suffix_fix_test.go",
)
CHANGED = {"chain/state_tree.go", "common/trie/nodestore.go"}


def require(value):
    if not value:
        raise ValueError("Successor recovery preparation refused")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def pairs(items):
    result = {}
    for key, value in items:
        require(key not in result)
        result[key] = value
    return result


def exact(actual, expected):
    require(type(actual) is type(expected))
    if type(expected) is dict:
        require(set(actual) == set(expected))
        for key in expected:
            exact(actual[key], expected[key])
    elif type(expected) is list:
        require(len(actual) == len(expected))
        for left, right in zip(actual, expected):
            exact(left, right)
    else:
        require(actual == expected)


def read_regular(path, limit):
    path = Path(path).absolute()
    require(not any(parent.is_symlink() for parent in (path, *path.parents)))
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 <= info.st_size <= limit)
    with path.open("rb") as stream:
        raw = stream.read(limit + 1)
    after = path.lstat()
    fields = ("st_dev", "st_ino", "st_size", "st_mode", "st_nlink", "st_uid", "st_mtime_ns", "st_ctime_ns")
    require(len(raw) == info.st_size and all(getattr(after, key) == getattr(info, key) for key in fields))
    return raw


def document(name, digest):
    raw = read_regular(HERE / name, 256 << 10)
    require(sha(raw) == digest)
    return json.loads(raw, object_pairs_hook=pairs)


def load_utilities():
    # Only pure Git/blob/inventory helpers are reused. Historical selectors and
    # reference-execution globals are not invoked or replaced.
    selected = importlib.util.spec_from_file_location("successor_git_utilities", HERE / "regenerate.py")
    module = importlib.util.module_from_spec(selected)
    selected.loader.exec_module(module)
    return module


UTIL = load_utilities()


def source_manifest():
    value = document(SOURCE_MANIFEST, SOURCE_SHA256)
    expected = {
        "format_version": 1, "kind": "selected-node-recovery-successor-source",
        "repository": "https://github.com/digitalSloth/go-zenon", "revision": REVISION, "tree": TREE,
        "blob_count": 467, "logical_blob_bytes": 7549463, "historical_source_and_records_rebound": False,
    }
    require(type(value) is dict and set(value) == set(expected) | {"files"})
    exact({key: value[key] for key in expected}, expected)
    require(type(value["files"]) is dict and len(value["files"]) == 467)
    for row in value["files"].values():
        require(type(row) is dict and set(row) == {"mode", "git_blob", "sha256", "bytes"})
        require(type(row["bytes"]) is int and 0 <= row["bytes"] <= 16 << 20)
        require(type(row["sha256"]) is str and re.fullmatch("[0-9a-f]{64}", row["sha256"]))
        require(type(row["git_blob"]) is str and re.fullmatch("[0-9a-f]{40}", row["git_blob"]))
    require(sum(row["bytes"] for row in value["files"].values()) == 7549463)
    require(UTIL.reconstruct_tree(value["files"]) == TREE)
    tests = sorted(name[6:] for name in value["files"] if name.startswith("chain/")
                   and name.count("/") == 1 and name.endswith("_test.go"))
    require(tests == list(UPSTREAM_TESTS))
    return value


def patch_files(original, manifest):
    patch = document(PATCH, PATCH_SHA256)
    header = {
        "format_version": 1, "kind": "experimental-successor-hash-bound-retained-node-versions",
        "repository": "https://github.com/digitalSloth/go-zenon", "base_revision": REVISION, "base_tree": TREE,
        "base_blob_count": 467, "modified_node_tree_without_probe": MODIFIED_TREE,
        "disk_format_before": 2, "disk_format_after": 3,
        "retained_hash_record": "06 || uint64_be(height) -> Momentum_hash_32",
        "baseline_already_refuses_incompatible_databases": True, "historical_patch_or_records_rebound": False,
        "experimental_only": True, "automatic_existing_database_migration": False,
        "automatic_incompatible_database_wipe": False, "SMT_root_and_proof_profile_changed": False,
        "node_client_protocol_profile_agreed": False, "accepted_v3_header_binding_qualified": False,
        "production_qualified": False,
    }
    require(type(patch) is dict and set(patch) == set(header) | {"files"})
    exact({key: patch[key] for key in header}, header)
    require(manifest["repository"] == header["repository"])
    require(type(patch["files"]) is dict and set(patch["files"]) == CHANGED and set(original) == CHANGED)
    modified, pins = {}, {name: dict(row) for name, row in manifest["files"].items()}
    for name, row in patch["files"].items():
        require(type(row) is dict and set(row) == {"mode", "before_sha256", "before_git_blob", "before_bytes",
            "after_sha256", "after_git_blob", "after_bytes", "replacements"})
        before = original[name]
        require(type(before) is bytes and type(row["before_bytes"]) is int and len(before) == row["before_bytes"])
        require(sha(before) == row["before_sha256"] == manifest["files"][name]["sha256"])
        require(UTIL.git_hash("blob", before) == row["before_git_blob"] == manifest["files"][name]["git_blob"])
        require(row["mode"] == manifest["files"][name]["mode"] == "100644")
        require(type(row["replacements"]) is list and len(row["replacements"]) == 1)
        replacement = row["replacements"][0]
        require(type(replacement) is dict and set(replacement) == {"before", "after"})
        require(all(type(value) is str and bool(value) for value in replacement.values()))
        # Complete before/after pins and inverse avoid fuzzy rebases across
        # the divergent node history.
        require(replacement["before"].encode() == before)
        after = replacement["after"].encode()
        require(type(row["after_bytes"]) is int and len(after) == row["after_bytes"])
        require(sha(after) == row["after_sha256"] and UTIL.git_hash("blob", after) == row["after_git_blob"])
        require(after != before and after.decode().replace(replacement["after"], replacement["before"], 1).encode() == before)
        modified[name] = after
        pins[name] = dict(mode="100644", sha256=sha(after), git_blob=UTIL.git_hash("blob", after), bytes=len(after))
    require(UTIL.reconstruct_tree(pins) == MODIFIED_TREE)
    return modified, patch


def private_destination(path):
    path = Path(path).absolute()
    require(not path.exists() and not any(parent.is_symlink() for parent in (path, *path.parents)))
    require(path.parent.is_dir())
    return path


def plan(workspace, variant, go, pins, probe, overlay_raw, module, sums):
    return {
        "format_version": 1, "kind": "successor-node-recovery-prepared-source", "variant": variant,
        "base_revision": REVISION, "base_tree": TREE, "selected_node_tree_without_probe": UTIL.reconstruct_tree(pins),
        "node_blob_count": 467, "source_manifest_sha256": SOURCE_SHA256, "patch_sha256": PATCH_SHA256,
        "probe_sha256": sha(probe), "overlay_sha256": sha(overlay_raw),
        "upstream_tests_excluded_by_explicit_compiler_overlay": list(UPSTREAM_TESTS),
        "upstream_source_files_changed_by_overlay": False,
        "changed_runtime_files": sorted(CHANGED) if variant == "hash-bound" else [],
        "module_sha256": sha(module), "sum_sha256": sha(sums),
        "module_selection": "complete selected node source go.mod/go.sum; no historical research-lock substitution",
        "working_directory": str(workspace / "node"), "binary": str(workspace / "recovery-successor.test"),
        "build_argv": [go, "test", "-c", "-p=1", "-mod=readonly", "-trimpath", "-buildvcs=false",
            "-overlay=" + str(workspace / "test-overlay.json"), "-tags", TAG,
            "-o", str(workspace / "recovery-successor.test"), "./chain"],
        "run_argv": [str(workspace / "recovery-successor.test"), "-test.v", "-test.run=^TestCandidateHashBoundVersions$"],
        "required_run_environment": {"ZENON_HASH_BOUND_SUCCESSOR_VARIANT": variant},
        "network_acquisition_performed": False, "reference_execution_performed": False,
        "node_client_protocol_profile_agreed": False, "production_qualified": False,
    }


def prepare(node_source, workspace, variant, go):
    require(variant in VARIANTS and type(go) is str and bool(go))
    workspace = private_destination(workspace)
    manifest = source_manifest()
    node_source = Path(node_source).absolute()
    require(not any(parent.is_symlink() for parent in (node_source, *node_source.parents)))
    for name in manifest["files"]:
        require((node_source / name).lstat().st_nlink == 1)
    original = UTIL.snapshot_source(node_source, manifest["files"])
    modified, _ = patch_files({name: original[name] for name in CHANGED}, manifest)
    selected = dict(original)
    if variant == "hash-bound":
        selected.update(modified)
    probe = read_regular(HERE / PROBE, 128 << 10)
    require(probe.startswith(("//go:build " + TAG + "\n").encode()))
    require(("\"source_revision\": \"" + REVISION + "\"").encode() in probe)
    workspace.mkdir(mode=0o700)
    node, backing = workspace / "node", workspace / "test-overlays"
    backing.mkdir(mode=0o700)
    for name, raw in selected.items():
        destination = node / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(raw)
        destination.chmod(0o755 if manifest["files"][name]["mode"] == "100755" else 0o644)
    inserted = node / "chain" / PROBE
    require(not inserted.exists())
    inserted.write_bytes(probe)
    overlays = {}
    for name in UPSTREAM_TESTS:
        raw = original["chain/" + name]
        require(b"//go:build" not in raw and b"// +build" not in raw)
        target = backing / name
        target.write_bytes(b"//go:build !" + TAG.encode() + b"\n\n" + raw)
        overlays[str(node / "chain" / name)] = str(target)
    overlay_raw = UTIL.encoded({"Replace": overlays})
    (workspace / "test-overlay.json").write_bytes(overlay_raw)
    pins = {name: dict(row, sha256=sha(selected[name]), git_blob=UTIL.git_hash("blob", selected[name]), bytes=len(selected[name]))
            for name, row in manifest["files"].items()}
    require(UTIL.reconstruct_tree(pins) == (MODIFIED_TREE if variant == "hash-bound" else TREE))
    result = plan(workspace, variant, go, pins, probe, overlay_raw, selected["go.mod"], selected["go.sum"])
    UTIL.seal(workspace / "prepared.json", UTIL.encoded(result))
    require(UTIL.snapshot_source(node_source, manifest["files"]) == original)
    verify(workspace, variant, go)
    return result


def verify(workspace, variant, go):
    require(variant in VARIANTS)
    workspace = Path(workspace).absolute()
    require(not any(parent.is_symlink() for parent in (workspace, *workspace.parents)))
    selected = json.loads(read_regular(workspace / "prepared.json", 128 << 10), object_pairs_hook=pairs)
    manifest = source_manifest()
    descriptor = document(PATCH, PATCH_SHA256)
    before = {name: row["replacements"][0]["before"].encode() for name, row in descriptor["files"].items()}
    modified, _ = patch_files(before, manifest)
    pins = {name: dict(row) for name, row in manifest["files"].items()}
    if variant == "hash-bound":
        for name, raw in modified.items():
            pins[name].update(sha256=sha(raw), git_blob=UTIL.git_hash("blob", raw), bytes=len(raw))
    probe = read_regular(HERE / PROBE, 128 << 10)
    pins["chain/" + PROBE] = dict(mode="100644", sha256=sha(probe), git_blob=UTIL.git_hash("blob", probe), bytes=len(probe))
    node = workspace / "node"
    require(not node.is_symlink())
    actual = set()
    for path in node.rglob("*"):
        require(not path.is_symlink())
        if path.is_file():
            require(stat.S_ISREG(path.stat().st_mode) and path.stat().st_nlink == 1)
            actual.add(path.relative_to(node).as_posix())
    require(actual == set(pins))
    source_bytes = UTIL.snapshot_source(node, pins)
    overlays = {}
    for name in UPSTREAM_TESTS:
        target = workspace / "test-overlays" / name
        require(read_regular(target, 1 << 20) == b"//go:build !" + TAG.encode() + b"\n\n" + source_bytes["chain/" + name])
        overlays[str(node / "chain" / name)] = str(target)
    overlay_raw = read_regular(workspace / "test-overlay.json", 128 << 10)
    require(overlay_raw == UTIL.encoded({"Replace": overlays}))
    original_pins = {name: row for name, row in pins.items() if name != "chain/" + PROBE}
    exact(selected, plan(workspace, variant, go, original_pins, probe, overlay_raw, source_bytes["go.mod"], source_bytes["go.sum"]))
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
    except (OSError, ValueError, KeyError, TypeError, IndexError):
        print("Successor recovery preparation refused; preserve inputs and partial workspace.", file=sys.stderr)
        sys.exit(1)
