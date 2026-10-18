#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Prepare a source-pinned cache forward-replay preflight experiment.

No compiler, reference backend, network or existing database is started here.
The caller owns acquisition, resource admission, native execution and cleanup.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import stat
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("cache_replay_parent", HERE / "prepare_cache_identifier_rollback.py")
G = importlib.util.module_from_spec(spec)
spec.loader.exec_module(G)
P = G.P
PATCH = "node-cache-forward-replay-9c71-patch.json"
PATCH_SHA256 = "85dc1076191b993921ce71786421b447debd5ce0efe7989eb9ce5e2de0ff2ea2"
MODIFIED_TREE = "57759bee9f143a10ef5a60880170b62a61ede7de"
AFTER = {"chain/cache.go": (5531, "c268035608b3acb4afd2d3cd3d4e135a51236656c1cb9800f14312051ef7f83a")}
PROBE = "public_chain_cache_forward_replay_probe.go"
PROBE_BYTES = 9805
PROBE_SHA256 = "59eb8a0e779be33813b1af82d84170b81058af4486464b84b1d5a4f44ee44e02"
ENTRYPOINT = "cmd/candidate-public-cache-forward-replay/main.go"
PARENT_BUILD_TREE = "3acbde3941bdc25522e950f9e5ca03b27ead9ac1"
CONTROL = "cache_forward_replay_chain_test.go.txt"
CONTROL_TARGET = "chain/candidate_cache_forward_replay_test.go"
CONTROL_BYTES = 4889
CONTROL_SHA256 = "fa49ada6826d9d099247cd4f3356ff82a7fd1d453fdf746566880c3141e84229"
CASES = (
    "canonical-height-two-cache-clean-reopen",
    "canonical-height-one-cache-under-height-two-ledger",
    "foreign-height-one-cache-under-height-two-ledger",
    "empty-cache-replay-through-height-two-ledger",
)


def probe_bytes():
    raw = P.read_regular(HERE / PROBE, 64 << 10)
    P.require(len(raw) == PROBE_BYTES and P.sha(raw) == PROBE_SHA256)
    return raw


def parent_build_tree():
    _, _, pins = G.selection()
    raw = probe_bytes()
    pins[ENTRYPOINT] = {"mode": "100644", "bytes": len(raw), "sha256": P.sha(raw),
                       "git_blob": P.UTIL.git_hash("blob", raw)}
    P.require(P.UTIL.reconstruct_tree(pins) == PARENT_BUILD_TREE)
    return PARENT_BUILD_TREE


def selection():
    manifest, modified, pins = G.selection()
    value = P.document(PATCH, PATCH_SHA256)
    header = {
        "format_version": 1, "kind": "experimental-native-cache-forward-replay",
        "node_revision": P.REVISION, "original_node_tree": P.TREE,
        "runtime_parent_tree": G.MODIFIED_TREE, "runtime_after_tree": MODIFIED_TREE,
        "experimental_only": True, "disk_format_changed": False, "SMT_profile_changed": False,
        "legacy_cache_manager_interface_changed": False,
        "cache_empty_identifier": "ZERO_HASH_HEIGHT_ONLY",
        "nonzero_cache_predecessor_lookup_required": True,
        "prewrite_parent_identity_required": True, "whole_window_atomicity_claimed": False,
        "accepted_header_or_consumer_acceptance_changed": False, "upstream_mutated": False,
    }
    P.require(type(value) is dict and set(value) == set(header) | {"replacements"})
    P.exact({k: value[k] for k in header}, header)
    rows = value["replacements"]
    P.require(type(rows) is list and len(rows) == 1 and rows[0]["file"] == "chain/cache.go")
    row = rows[0]
    P.require(set(row) == {"file", "mode", "before_bytes", "before_sha256", "before_git_blob",
                           "after_bytes", "after_sha256", "after_git_blob", "before", "after"})
    name = row["file"]
    before, after = row["before"].encode(), row["after"].encode()
    P.require(row["mode"] == pins[name]["mode"] == "100644")
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
    result = {name: raw for name, raw in G.extra_sources().items() if name != G.F.ENTRYPOINT}
    result[ENTRYPOINT] = probe_bytes()
    raw = P.read_regular(HERE / CONTROL, 64 << 10)
    P.require(len(raw) == CONTROL_BYTES and P.sha(raw) == CONTROL_SHA256)
    P.require(CONTROL_TARGET not in result)
    result[CONTROL_TARGET] = raw
    P.require(len(result) == 4)
    return result


def plan(workspace, go):
    expected = G.plan(workspace, go)
    _, _, pins = selection()
    extras = extra_sources()
    for name, raw in extras.items():
        P.require(name not in pins)
        pins[name] = {"mode": "100644", "bytes": len(raw), "sha256": P.sha(raw),
                      "git_blob": P.UTIL.git_hash("blob", raw)}
    binary = str(Path(workspace).absolute() / "public-chain-cache-forward-replay")
    expected.update(
        kind="prepared-native-cache-forward-replay", runtime_tree=MODIFIED_TREE,
        runtime_parent_tree=G.MODIFIED_TREE, build_tree=P.UTIL.reconstruct_tree(pins),
        parent_build_tree=parent_build_tree(), cache_patch_sha256=PATCH_SHA256,
        added_source_files=sorted(extras), cases=list(CASES), binary=binary,
        probe={"bytes": PROBE_BYTES, "sha256": PROBE_SHA256},
        build_argv=[go, "build", "-mod=readonly", "-trimpath", "-buildvcs=false",
                    "-tags", "candidate_public_cache_forward_replay", "-o", binary,
                    "./cmd/candidate-public-cache-forward-replay"],
        run_argv_template=[binary, "--case", "ONE_SELECTED_CASE", "--root", "NEW_EMPTY_OWNED_CASE_ROOT"],
        task_quota_bytes=4 << 30, native_control_execution_selected=False,
        cache_predecessor_full_identifier_required=True,
        zero_height_nonzero_hash_refused=True, nil_predecessor_refused=True,
    )
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
    P.UTIL.seal(workspace / "cache-forward-replay-prepared.json", P.UTIL.encoded(expected))
    P.exact(verify(workspace, go), expected)
    return expected


def verify(workspace, go):
    workspace = Path(workspace).absolute()
    P.require(workspace.is_dir() and not any(p.is_symlink() for p in (workspace, *workspace.parents)))
    _, _, pins = selection()
    for name, raw in extra_sources().items():
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
    recorded = json.loads(P.read_regular(workspace / "cache-forward-replay-prepared.json", 128 << 10), object_pairs_hook=P.pairs)
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
        print("Cache forward-replay preparation refused; preserve owned inputs.", file=sys.stderr)
        sys.exit(1)
