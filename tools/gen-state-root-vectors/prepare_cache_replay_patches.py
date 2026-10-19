#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Prepare the selected native cache replay-patch experiment.

Preparation starts no compiler, backend, listener or transport. The caller owns
resource admission, registered capture files, bounded execution and cleanup.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import stat
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("patch_window_parent", HERE / "prepare_cache_replay_window.py")
H = importlib.util.module_from_spec(spec)
spec.loader.exec_module(H)
P = H.P
PATCH = "node-cache-replay-patch-9c71-patch.json"
PATCH_SHA256 = "f8800e7118ee3479f26ca0c7d180345696a0054af0c55414f46fa5ba2fbebe34"
MODIFIED_TREE = "0cf17322154e55ce77a4e51c834af5219d8161f3"
BUILD_TREE = "09b42a6c73d98e9d79e419f78e0405d4d12bed22"
PARENT_BUILD_TREE = "9653bd305d8c5d8ee818a06dea5c9fa956660677"
AFTER = {"chain/cache.go": (7603, "00d0b0d8cfb850099004a19fe3683d7ecfcec54a0b9ca9d56eed594253eb96aa")}
PROBE = "public_chain_cache_replay_patch_probe.go"
PROBE_BYTES = 17265
PROBE_SHA256 = "2ff613e8e9553bda6b0ded5d7767f4e37a522de7b4df031703e3b140338d756c"
PARENT_PROBE_BYTES = 17110
PARENT_PROBE_SHA256 = "566bd3fae2276962c5f3d231a9e7884a877bf7b7cc87540531d8586a1810c046"
RETAINED_PROBE = "public_chain_cache_replay_patch_retained_probe.go.txt"
RETAINED_PROBE_BYTES = 14645
RETAINED_PROBE_SHA256 = "0b6f3baf96108082eba4b8bdd6db15a02fd8751dc16cd099f330181353fcb80d"
RETAINED_POSITIVE_BUILD_TREE = "79407b35b780db4d7f36c17ec085f42e5b20d197"
ENTRYPOINT = "cmd/candidate-public-cache-replay-patch/main.go"
CONTROL = "cache_replay_patch_chain_test.go.txt"
CONTROL_TARGET = "chain/candidate_cache_replay_patch_test.go"
CONTROL_BYTES = 5057
CONTROL_SHA256 = "1fee9886c5da2f39c418cbe7b31d5d473f548b57e182926da2dfc1907236ff05"
COMPAT_CONTROL = "cache_replay_patch_window_compat_test.go.txt"
COMPAT_BYTES = 9178
COMPAT_SHA256 = "03a0cd4bc65f34ecc1c7f8dc71a0720f699e23fbc8c965bad8e2899ccb2641e4"
CASES = (
    "intact-empty-cache", "missing-genesis-patch-empty-cache",
    "missing-genesis-patch-current-cache", "missing-genesis-patch-behind-cache",
    "missing-empty-successor-patch-empty-cache",
)
CAPTURE_FILES = ("expected-ledger-metadata.bin", "unexpected-stored-patch.bin")
NATIVE_ROOTS = tuple(sorted((*H.NATIVE_ROOTS, "TestCandidateChainCacheReplayPatches")))


def source_bytes(name, size, digest):
    return H.source_bytes(name, size, digest)


def probe_bytes():
    return source_bytes(PROBE, PROBE_BYTES, PROBE_SHA256)


def parent_probe_bytes():
    # The recorded parent's source remains independently pinned. Reconstruct
    # it by removing only the added diagnostic category; never relabel the
    # retained native process as execution of the new candidate probe.
    raw = probe_bytes()
    category = (b'\tcase strings.HasPrefix(err.Error(), "cache replay patch for momentum ") && strings.HasSuffix(err.Error(), " is missing"):\n'
                b'\t\treturn "missing-replay-patch"\n')
    P.require(raw.count(category) == 1)
    parent = raw.replace(category, b"")
    P.require(len(parent) == PARENT_PROBE_BYTES and P.sha(parent) == PARENT_PROBE_SHA256)
    return parent


def add_pin(pins, name, raw):
    P.require(name not in pins)
    pins[name] = {"mode": "100644", "bytes": len(raw), "sha256": P.sha(raw),
                  "git_blob": P.UTIL.git_hash("blob", raw)}


def parent_build_tree():
    _, _, pins = H.selection()
    extras = {name: raw for name, raw in H.extra_sources().items() if name != H.ENTRYPOINT}
    extras[ENTRYPOINT] = parent_probe_bytes()
    for name, raw in extras.items():
        add_pin(pins, name, raw)
    P.require(len(pins) == 472 and P.UTIL.reconstruct_tree(pins) == PARENT_BUILD_TREE)
    return PARENT_BUILD_TREE


def retained_positive_build_tree():
    # Only the completed intact case is reused from this older probe. Its
    # later fault-fixture assertion remains failed and is not a native result.
    _, _, pins = H.selection()
    extras = {name: raw for name, raw in H.extra_sources().items() if name != H.ENTRYPOINT}
    extras[ENTRYPOINT] = source_bytes(RETAINED_PROBE, RETAINED_PROBE_BYTES, RETAINED_PROBE_SHA256)
    for name, raw in extras.items():
        add_pin(pins, name, raw)
    P.require(len(pins) == 472 and P.UTIL.reconstruct_tree(pins) == RETAINED_POSITIVE_BUILD_TREE)
    return RETAINED_POSITIVE_BUILD_TREE


def selection():
    manifest, modified, pins = H.selection()
    value = P.document(PATCH, PATCH_SHA256)
    header = {
        "format_version": 1, "kind": "experimental-native-cache-replay-patch-preflight",
        "node_revision": P.REVISION, "original_node_tree": P.TREE,
        "runtime_parent_tree": H.MODIFIED_TREE, "runtime_after_tree": MODIFIED_TREE,
        "experimental_only": True, "disk_format_changed": False, "SMT_profile_changed": False,
        "legacy_cache_manager_interface_changed": False,
        "required_patch_availability_preflight": True, "empty_content_nil_patch_allowed": True,
        "apply_pass_patch_rechecked": True, "whole_window_atomicity_claimed": False,
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
    # Preserve every earlier window scenario and assertion. Its sole source
    # change supplies the new internal helper's manager argument.
    extras[H.CONTROL_TARGET] = source_bytes(COMPAT_CONTROL, COMPAT_BYTES, COMPAT_SHA256)
    extras[CONTROL_TARGET] = source_bytes(CONTROL, CONTROL_BYTES, CONTROL_SHA256)
    extras[ENTRYPOINT] = probe_bytes()
    P.require(len(extras) == 6)
    return extras


def build_pins():
    _, _, pins = selection()
    for name, raw in extra_sources().items():
        add_pin(pins, name, raw)
    P.require(len(pins) == 473 and P.UTIL.reconstruct_tree(pins) == BUILD_TREE)
    return pins


def plan(workspace, go):
    expected = H.plan(workspace, go)
    pins = build_pins()
    binary = str(Path(workspace).absolute() / "public-chain-cache-replay-patch")
    expected.update(
        kind="prepared-native-cache-replay-patch", runtime_tree=MODIFIED_TREE,
        runtime_parent_tree=H.MODIFIED_TREE, build_tree=P.UTIL.reconstruct_tree(pins),
        parent_build_tree=parent_build_tree(), cache_patch_sha256=PATCH_SHA256,
        added_source_files=sorted(extra_sources()), cases=list(CASES), binary=binary,
        probe={"bytes": PROBE_BYTES, "sha256": PROBE_SHA256},
        recorded_parent_probe={"bytes": PARENT_PROBE_BYTES, "sha256": PARENT_PROBE_SHA256},
        retained_positive_probe={"bytes": RETAINED_PROBE_BYTES, "sha256": RETAINED_PROBE_SHA256},
        retained_positive_build_tree=retained_positive_build_tree(),
        retained_positive_case=CASES[0],
        native_control_roots=list(NATIVE_ROOTS), expected_native_unit_pass_results=58,
        required_patch_availability_preflight=True, empty_content_nil_patch_allowed=True,
        apply_pass_patch_rechecked=True, registered_capture_files=list(CAPTURE_FILES),
        capture_initial_state="Exactly two registered zero-length regular files for missing-patch cases; empty root for intact case",
        metadata_capture_limit_bytes=4 << 20, mismatch_capture_limit_bytes=16 << 20,
        build_argv=[go, "build", "-mod=readonly", "-trimpath", "-buildvcs=false",
                    "-tags", "candidate_public_cache_replay_patch", "-o", binary,
                    "./cmd/candidate-public-cache-replay-patch"],
        run_argv_template=[binary, "--case", "ONE_SELECTED_CASE", "--root", "NEW_REGISTERED_OWNED_CASE_ROOT"],
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
    P.UTIL.seal(workspace / "cache-replay-patch-prepared.json", P.UTIL.encoded(expected))
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
    recorded = json.loads(P.read_regular(workspace / "cache-replay-patch-prepared.json", 128 << 10), object_pairs_hook=P.pairs)
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
        print(json.dumps({"kind": "cache-replay-patch-preparation", "result": "REFUSED"}))
        return 1
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
