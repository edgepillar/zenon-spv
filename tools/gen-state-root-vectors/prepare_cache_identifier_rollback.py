#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Prepare the experimental native cache rollback fix without executing it.

Select all 467 original node blobs and the existing experimental runtime. Apply
two complete-file replacements, then add the ordinary command and two explicit
native test sources. Acquisition and supervised execution belong to the caller.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import stat
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("cache_identifier_parent", HERE / "prepare_public_chain_cache_startup.py")
F = importlib.util.module_from_spec(spec)
spec.loader.exec_module(F)
P = F.P
PATCH = "node-cache-identifier-rollback-9c71-patch.json"
PATCH_SHA256 = "b6c2f6750a8f448ae31d0155327e717e40508e16125f4c9af23fefbbfbffb003"
MODIFIED_TREE = "49db80f94e48e980f84de35299f80c6f3b4dcb54"
AFTER = {
    "chain/cache.go": (5035, "dac58de1b57e9e4cb31db1424acd3a899d1174e242de639da86701f0c0f91504"),
    "chain/cache/storage/db.go": (9147, "a502415c2ab7be0c68d7f53dc2d4c0dbfc56af24a82e7b2643bc0d8d03850410"),
}
CONTROL_SOURCES = {
    "cache_identifier_rollback_storage_test.go.txt": {
        "target": "chain/cache/storage/candidate_identifier_rollback_test.go",
        "bytes": 7400, "sha256": "761254b2e781a4a1a52f9867c9b817ddff74e3c6ef7df7e538fd6487e9c756b6",
    },
    "cache_identifier_rollback_chain_test.go.txt": {
        "target": "chain/candidate_cache_identifier_rollback_test.go",
        "bytes": 3054, "sha256": "b7a219fd17b5ef71f8f2b8b5a9400532a01a4083407f297efb836711f12788fb",
    },
}


def selection():
    manifest, modified, pins = F.selection()
    value = P.document(PATCH, PATCH_SHA256)
    header = {
        "format_version": 1, "kind": "experimental-native-cache-identifier-rollback",
        "node_revision": P.REVISION, "original_node_tree": P.TREE,
        "runtime_parent_tree": F.C.MODIFIED_TREE, "runtime_after_tree": MODIFIED_TREE,
        "experimental_only": True, "disk_format_changed": False, "SMT_profile_changed": False,
        "legacy_cache_manager_interface_changed": False, "new_optional_native_rollback_capability": True,
        "whole_window_atomicity_claimed": False,
        "accepted_header_or_consumer_acceptance_changed": False, "upstream_mutated": False,
    }
    P.require(type(value) is dict and set(value) == set(header) | {"replacements"})
    P.exact({k: value[k] for k in header}, header)
    rows = value["replacements"]
    P.require(type(rows) is list and len(rows) == 2)
    P.require([row["file"] for row in rows] == list(AFTER))
    for row in rows:
        name = row["file"]
        P.require(set(row) == {"file", "mode", "before_bytes", "before_sha256", "before_git_blob",
                               "after_bytes", "after_sha256", "after_git_blob", "before", "after"})
        P.require(row["mode"] == pins[name]["mode"] == "100644")
        before, after = row["before"].encode(), row["after"].encode()
        P.require(len(before) == row["before_bytes"] == pins[name]["bytes"])
        P.require(P.sha(before) == row["before_sha256"] == pins[name]["sha256"])
        P.require(P.UTIL.git_hash("blob", before) == row["before_git_blob"] == pins[name]["git_blob"])
        P.require((len(after), P.sha(after)) == AFTER[name])
        P.require(len(after) == row["after_bytes"] and P.sha(after) == row["after_sha256"])
        P.require(P.UTIL.git_hash("blob", after) == row["after_git_blob"])
        modified[name] = after
        pins[name].update(bytes=len(after), sha256=P.sha(after), git_blob=row["after_git_blob"])
    P.require(P.UTIL.reconstruct_tree(pins) == MODIFIED_TREE)
    return manifest, modified, pins


def extra_sources():
    result = {F.ENTRYPOINT: F.probe_bytes()}
    for name, pin in CONTROL_SOURCES.items():
        raw = P.read_regular(HERE / name, 128 << 10)
        P.require(len(raw) == pin["bytes"] and P.sha(raw) == pin["sha256"])
        P.require(pin["target"] not in result)
        result[pin["target"]] = raw
    return result


def plan(workspace, go):
    expected = F.plan(workspace, go)
    _, _, pins = selection()
    extras = extra_sources()
    for name, raw in extras.items():
        P.require(name not in pins)
        pins[name] = {"mode": "100644", "bytes": len(raw), "sha256": P.sha(raw),
                      "git_blob": P.UTIL.git_hash("blob", raw)}
    expected.update(kind="prepared-native-cache-identifier-rollback", runtime_changed=True,
                    runtime_tree=MODIFIED_TREE, runtime_parent_tree=F.C.MODIFIED_TREE,
                    build_tree=P.UTIL.reconstruct_tree(pins), cache_patch_sha256=PATCH_SHA256,
                    added_source_files=sorted(extras), legacy_cache_manager_interface_changed=False,
                    whole_window_atomicity_claimed=False, native_control_execution_selected=False)
    return expected


def prepare(node_source, workspace, go):
    expected = plan(Path(workspace).absolute(), go)
    workspace = P.private_destination(workspace)
    node_source = Path(node_source).absolute()
    P.require(not any(p.is_symlink() for p in (node_source, *node_source.parents)))
    manifest, modified, _ = selection()
    original = P.UTIL.snapshot_source(node_source, manifest["files"])
    extras = extra_sources()
    workspace.mkdir(mode=0o700)
    node = workspace / "node"
    for name, pin in manifest["files"].items():
        path = node / name
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as stream:
            stream.write(modified.get(name, original[name]))
        path.chmod(int(pin["mode"], 8) & 0o777)
    for name, raw in extras.items():
        path = node / name
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as stream:
            stream.write(raw)
        path.chmod(0o644)
    P.UTIL.seal(workspace / "cache-identifier-rollback-prepared.json", P.UTIL.encoded(expected))
    P.exact(verify(workspace, go), expected)
    return expected


def verify(workspace, go):
    workspace = Path(workspace).absolute()
    P.require(workspace.is_dir() and not any(p.is_symlink() for p in (workspace, *workspace.parents)))
    _, _, pins = selection()
    extras = extra_sources()
    for name, raw in extras.items():
        pins[name] = {"mode": "100644", "bytes": len(raw), "sha256": P.sha(raw)}
    expected = plan(workspace, go)
    node = workspace / "node"
    P.require(node.is_dir() and not node.is_symlink())
    files = set()
    for path in node.rglob("*"):
        info = path.lstat()
        P.require(not path.is_symlink() and (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)))
        if stat.S_ISREG(info.st_mode):
            P.require(info.st_nlink == 1)
            files.add(path.relative_to(node).as_posix())
    P.require(files == set(pins))
    for name, pin in pins.items():
        raw = P.read_regular(node / name, 16 << 20)
        P.require(len(raw) == pin["bytes"] and P.sha(raw) == pin["sha256"])
        P.require(stat.S_IMODE((node / name).stat().st_mode) == (int(pin["mode"], 8) & 0o777) or sys.platform == "win32")
    recorded = json.loads(P.read_regular(workspace / "cache-identifier-rollback-prepared.json", 128 << 10), object_pairs_hook=P.pairs)
    P.exact(recorded, expected)
    return expected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node-source", type=Path, required=True)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--go", required=True)
    args = parser.parse_args()
    print(json.dumps(prepare(args.node_source, args.workspace, args.go), sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, IndexError):
        print("Cache identifier rollback preparation refused; preserve owned inputs.", file=sys.stderr)
        sys.exit(1)
