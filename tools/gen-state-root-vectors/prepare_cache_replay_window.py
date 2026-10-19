#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Prepare the selected native cache replay-window experiment.

Preparation neither starts a compiler/backend nor acquires source or opens an
existing database. The caller owns resource admission, execution and cleanup.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import stat
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("window_parent_preparer", HERE / "prepare_cache_forward_replay.py")
H = importlib.util.module_from_spec(spec)
spec.loader.exec_module(H)
P = H.P
PATCH = "node-cache-replay-window-9c71-patch.json"
PATCH_SHA256 = "e80a5131695fc73bdcb882d248134abfc748a8c0f57c88d85822fb729b7bd3b2"
MODIFIED_TREE = "40cc88bb9671cef130cb87ccb3c726f7e8977299"
BUILD_TREE = "cde719c8defa1b25f7e043815ebf27ec49ea05a0"
PARENT_BUILD_TREE = "7d7c469edb3e7d934cc9333db69d49011a73f773"
AFTER = {"chain/cache.go": (7204, "d5e850f920dd41ec4d3c5874535f9ba0636c2b091b047ef44623c35c084f13d9")}
PROBE = "public_chain_cache_replay_window_probe.go"
PROBE_BYTES = 14146
PROBE_SHA256 = "299fd6f04a5abb10e97400662122c42a5482fea834dd11cd0c71dfa44509ecfb"
ENTRYPOINT = "cmd/candidate-public-cache-replay-window/main.go"
CONTROL = "cache_replay_window_chain_test.go.txt"
CONTROL_TARGET = "chain/candidate_cache_replay_window_test.go"
CONTROL_BYTES = 9173
CONTROL_SHA256 = "4bacb2e3a352dae3083ee24554c20033a6972a45d655beb7f41a7b63e0f4cb7f"
COMPAT_CONTROL = "cache_replay_window_forward_compat_test.go.txt"
COMPAT_BYTES = 4924
COMPAT_SHA256 = "ee2d394fdddfc721651ff17ef912cc1c336ddd5937e2f29ae850e0e1f4043b84"
CASES = (
    "canonical-behind-cache-replay", "canonical-current-cache-clean-reopen",
    "empty-cache-replay", "missing-first-replay-momentum", "missing-later-replay-momentum",
)
NATIVE_ROOTS = tuple(sorted((
    "TestCandidateCacheRollbackAndReopen", "TestCandidateCacheRollbackCorruptHistory",
    "TestCandidateCacheRollbackMissingEarlierPatch", "TestCandidateCacheRollbackStop",
    "TestCandidateCacheRollbackToEmpty", "TestCandidateCacheRollbackWindow",
    "TestCandidateCacheRollbackWriteFailure", "TestCandidateCacheRollbackWrongRetainedHash",
    "TestCandidateChainCacheExactTarget", "TestCandidateChainCacheForwardReplayPreflight",
    "TestCandidateChainCacheIncompleteOptionalRollback", "TestCandidateChainCacheLegacyRollbackRefused",
    "TestCandidateChainCacheRollbackError", "TestCandidateChainCacheReplayWindow",
)))


def source_bytes(name, size, digest):
    raw = P.read_regular(HERE / name, 64 << 10)
    P.require(len(raw) == size and P.sha(raw) == digest)
    return raw


def probe_bytes():
    return source_bytes(PROBE, PROBE_BYTES, PROBE_SHA256)


def parent_build_tree():
    _, _, pins = H.selection()
    extras = {name: raw for name, raw in H.extra_sources().items() if name != H.ENTRYPOINT}
    extras[ENTRYPOINT] = probe_bytes()
    for name, raw in extras.items():
        P.require(name not in pins)
        pins[name] = {"mode": "100644", "bytes": len(raw), "sha256": P.sha(raw),
                      "git_blob": P.UTIL.git_hash("blob", raw)}
    P.require(len(pins) == 471 and P.UTIL.reconstruct_tree(pins) == PARENT_BUILD_TREE)
    return PARENT_BUILD_TREE


def selection():
    manifest, modified, pins = H.selection()
    value = P.document(PATCH, PATCH_SHA256)
    header = {
        "format_version": 1, "kind": "experimental-native-cache-replay-window",
        "node_revision": P.REVISION, "original_node_tree": P.TREE,
        "runtime_parent_tree": H.MODIFIED_TREE, "runtime_after_tree": MODIFIED_TREE,
        "experimental_only": True, "disk_format_changed": False, "SMT_profile_changed": False,
        "legacy_cache_manager_interface_changed": False,
        "cache_predecessor_full_identifier_required": True,
        "replay_window_full_linkage_preflight_required": True,
        "missing_momentum_refused_before_write": True, "replay_prefetch_identity_required": True,
        "replay_final_uint64_break_required": True, "whole_window_atomicity_claimed": False,
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
    extras = {name: raw for name, raw in H.extra_sources().items() if name != H.ENTRYPOINT}
    # Preserve the old adverse predecessor controls. The two positive fixtures
    # now include a predecessor hash and the complete preflight/reread trace.
    extras[H.CONTROL_TARGET] = source_bytes(COMPAT_CONTROL, COMPAT_BYTES, COMPAT_SHA256)
    extras[CONTROL_TARGET] = source_bytes(CONTROL, CONTROL_BYTES, CONTROL_SHA256)
    extras[ENTRYPOINT] = probe_bytes()
    P.require(len(extras) == 5)
    return extras


def build_pins():
    _, _, pins = selection()
    for name, raw in extra_sources().items():
        P.require(name not in pins)
        pins[name] = {"mode": "100644", "bytes": len(raw), "sha256": P.sha(raw),
                      "git_blob": P.UTIL.git_hash("blob", raw)}
    P.require(len(pins) == 472 and P.UTIL.reconstruct_tree(pins) == BUILD_TREE)
    return pins


def plan(workspace, go):
    expected = H.plan(workspace, go)
    pins = build_pins()
    binary = str(Path(workspace).absolute() / "public-chain-cache-replay-window")
    expected.update(
        kind="prepared-native-cache-replay-window", runtime_tree=MODIFIED_TREE,
        runtime_parent_tree=H.MODIFIED_TREE, build_tree=P.UTIL.reconstruct_tree(pins),
        parent_build_tree=parent_build_tree(), cache_patch_sha256=PATCH_SHA256,
        added_source_files=sorted(extra_sources()), cases=list(CASES), binary=binary,
        probe={"bytes": PROBE_BYTES, "sha256": PROBE_SHA256},
        native_control_roots=list(NATIVE_ROOTS), expected_native_unit_pass_results=46,
        replay_window_linkage_preflight_required=True, missing_replay_momentum_refused=True,
        prefetch_identity_checked=True, final_uint64_increment_avoided=True,
        explicit_fixture_restore_is_not_runtime_repair=True,
        build_argv=[go, "build", "-mod=readonly", "-trimpath", "-buildvcs=false",
                    "-tags", "candidate_public_cache_replay_window", "-o", binary,
                    "./cmd/candidate-public-cache-replay-window"],
        run_argv_template=[binary, "--case", "ONE_SELECTED_CASE", "--root", "NEW_EMPTY_OWNED_CASE_ROOT"],
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
    P.UTIL.seal(workspace / "cache-replay-window-prepared.json", P.UTIL.encoded(expected))
    P.exact(verify(workspace, go), expected)
    return expected


def verify(workspace, go):
    workspace = Path(workspace).absolute()
    P.require(workspace.is_dir() and not any(p.is_symlink() for p in (workspace, *workspace.parents)))
    pins = build_pins()
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
    recorded = json.loads(P.read_regular(workspace / "cache-replay-window-prepared.json", 128 << 10), object_pairs_hook=P.pairs)
    P.exact(recorded, expected)
    return expected


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for command in ("plan", "prepare", "verify"):
        sub = commands.add_parser(command)
        sub.add_argument("--workspace", required=True)
        sub.add_argument("--go", default="go")
        if command == "prepare":
            sub.add_argument("--node-source", required=True)
    args = parser.parse_args(argv)
    try:
        result = prepare(args.node_source, args.workspace, args.go) if args.command == "prepare" else \
            plan(args.workspace, args.go) if args.command == "plan" else verify(args.workspace, args.go)
    except (ValueError, OSError, KeyError, TypeError):
        print(json.dumps({"kind": "cache-replay-window-preparation", "result": "REFUSED"}))
        return 1
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
