#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Prepare a finite public Chain startup experiment without executing a node."""
import argparse
import importlib.util
import json
from pathlib import Path
import stat
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("startup_record_parent", HERE / "prepare_momentum_rollback_target.py")
H = importlib.util.module_from_spec(spec)
spec.loader.exec_module(H)
P = H.P
PATCH = "node-public-chain-startup-record-9c71-patch.json"
PATCH_SHA256 = "63076c8b407ebfa3d4a6fb86c15ae1593015c874efeea551d918f87889db4364"
FILE = "chain/chain.go"
MODIFIED_TREE = "d56bf37a23ddf0ec0f8af2eca62be01bb6c54dbc"
PARENT_BUILD_TREE = "1ec0bc16975ac70441d7cf5bbf964192de9e3c6e"
BUILD_TREE = "3b48a658f6dbae71057bdd3c424018e0a0830749"
UNIT_BUILD_TREE = "81804b7564687d8fcb49cfb7c3575886206f7188"
PROBE = "public_chain_startup_record_probe.go"
PROBE_BYTES = 12965
PROBE_SHA256 = "2998c49a90e736e3151310a0ee7cd3a23b27a2328a313c49a389f0945959b223"
PROBE_TARGET = "cmd/candidate-public-startup-record-identity/main.go"
UNIT = "public_chain_startup_record_test.go.txt"
UNIT_BYTES = 5393
UNIT_SHA256 = "406dbdb937126003a41654a4f0dfdd8ea64a57847663596765a45365a16a477f"
UNIT_TARGET = "chain/candidate_public_chain_startup_record_test.go"
ROOTS = tuple(sorted((*H.ROOTS,
    "TestChainStopStopsEveryManagerAfterCacheError", "TestChainStopReportsEveryManagerError",
    "TestCandidatePublicChainStartupEmptyRealManagers",
    "TestCandidatePublicChainStartupPreservesGenesisLookupError",
    "TestCandidatePublicChainStartupClosedCacheDoesNotInsertGenesis",
    "TestCandidatePublicChainStartupStoppedInstanceRefusesInit")))


def selection():
    manifest, modified, pins = H.selection()
    row = P.document(PATCH, PATCH_SHA256)
    header = {
        "format_version": 1, "kind": "experimental-public-chain-startup-record-preflight",
        "node_revision": P.REVISION, "runtime_parent_tree": H.MODIFIED_TREE,
        "runtime_candidate_tree": MODIFIED_TREE, "file": FILE, "mode": "100644",
        "experimental_only": True, "disk_format_changed": False, "SMT_profile_changed": False,
        "consensus_or_state_value_acceptance_changed": False, "upstream_mutated": False,
    }
    fields = {phase + suffix for phase in ("before", "after")
              for suffix in ("", "_bytes", "_sha256", "_git_blob")}
    P.require(type(row) is dict and set(row) == set(header) | fields)
    P.exact({key: row[key] for key in header}, header)
    before, after = row["before"].encode(), row["after"].encode()
    for phase, raw in (("before", before), ("after", after)):
        P.require(len(raw) == row[phase + "_bytes"])
        P.require(P.sha(raw) == row[phase + "_sha256"])
        P.require(P.UTIL.git_hash("blob", raw) == row[phase + "_git_blob"])
    P.exact({key: row["before_" + key] for key in ("bytes", "sha256", "git_blob")},
            {key: pins[FILE][key] for key in ("bytes", "sha256", "git_blob")})
    P.require(before == modified[FILE] and len(after) == 6959)
    P.require(P.sha(after) == "4175fbe331d953a76c0f2f0ef83909311cdc8e026f69d916c7009f828b70c7dc")
    modified[FILE] = after
    pins[FILE].update(bytes=len(after), sha256=P.sha(after), git_blob=row["after_git_blob"])
    P.require(len(pins) == 467 and P.UTIL.reconstruct_tree(pins) == MODIFIED_TREE)
    return manifest, modified, pins


def extras(unit=False):
    P.require(type(unit) is bool)
    result = {}
    for name, target, count, digest in ((PROBE, PROBE_TARGET, PROBE_BYTES, PROBE_SHA256),
                                       (UNIT, UNIT_TARGET, UNIT_BYTES, UNIT_SHA256)):
        if name == UNIT and not unit:
            continue
        raw = P.read_regular(HERE / name, 64 << 10)
        P.require(len(raw) == count and P.sha(raw) == digest)
        result[target] = raw
    if unit:
        name, raw = H.extra_source(True)
        result[name] = raw
    return result


def build_pins(variant="candidate", unit=False):
    P.require(variant in ("parent", "candidate") and type(unit) is bool)
    P.require(not unit or variant == "candidate")
    _, _, pins = H.selection() if variant == "parent" else selection()
    for name, raw in extras(unit).items():
        P.require(name not in pins)
        pins[name] = {"mode": "100644", "bytes": len(raw), "sha256": P.sha(raw),
                      "git_blob": P.UTIL.git_hash("blob", raw)}
    expected = UNIT_BUILD_TREE if unit else PARENT_BUILD_TREE if variant == "parent" else BUILD_TREE
    P.require(len(pins) == (470 if unit else 468) and P.UTIL.reconstruct_tree(pins) == expected)
    return pins


def plan(workspace, go, variant="candidate", unit=False):
    P.require(type(go) is str and go and "\x00" not in go)
    pins = build_pins(variant, unit)
    workspace = Path(workspace).absolute()
    return {
        "kind": "prepared-public-chain-startup-record", "node_revision": P.REVISION,
        "original_node_tree": P.TREE, "runtime_parent_tree": H.MODIFIED_TREE,
        "runtime_tree": H.MODIFIED_TREE if variant == "parent" else MODIFIED_TREE,
        "build_tree": P.UTIL.reconstruct_tree(pins), "source_blobs": len(pins),
        "variant": variant, "unit_controls": unit, "patch_sha256": PATCH_SHA256,
        "added_source_files": sorted(extras(unit)), "minimum_free_floor_bytes": 10 << 30,
        "native_test_roots": list(ROOTS), "expected_native_unit_pass_results": 17,
        "native_test_argv": [go, "test", "-mod=readonly", "-count=1", "-json", "-p=2",
                             "-trimpath", "-buildvcs=false", "-tags",
                             "candidate_public_startup_record_identity,candidate_momentum_rollback_target",
                             "-run", "^(" + "|".join(ROOTS) + ")$", "./chain"],
        "build_argv": [go, "build", "-mod=readonly", "-p=2", "-trimpath", "-buildvcs=false",
                       "-tags", "candidate_public_startup_record_identity", "-o",
                       str(workspace / "startup-record"), "./cmd/candidate-public-startup-record-identity"],
        "native_working_directory": str(workspace / "node"),
        "run_argv_template": [str(workspace / "startup-record"), "--root", "NEW_REGISTERED_EMPTY_ROOT"],
        "reference_backend_executed": False, "new_dependency_transports_permitted": False,
        "public_Chain_Init_and_Stop_selected": True, "Chain_Start_or_network_selected": False,
        "full_node_or_concurrent_lifecycle_qualified": False, "accepted_header_binding": False,
        "runtime_state_value_acceptance": False, "consumer_result": "REFUSED",
    }


def prepare(node_source, workspace, go, variant="candidate", unit=False):
    expected = plan(workspace, go, variant, unit)
    workspace = P.private_destination(workspace)
    node_source = Path(node_source).absolute()
    P.require(not any(path.is_symlink() for path in (node_source, *node_source.parents)))
    manifest, modified, _ = H.selection() if variant == "parent" else selection()
    original = P.UTIL.snapshot_source(node_source, manifest["files"])
    rows = {name: modified.get(name, raw) for name, raw in original.items()}
    rows.update(extras(unit))
    workspace.mkdir(mode=0o700)
    for name, pin in build_pins(variant, unit).items():
        path = workspace / "node" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as stream:
            stream.write(rows[name])
        path.chmod(int(pin["mode"], 8) & 0o777)
    P.UTIL.seal(workspace / "startup-record-prepared.json", P.UTIL.encoded(expected))
    P.exact(verify(workspace, go, variant, unit), expected)
    return expected


def verify(workspace, go, variant="candidate", unit=False):
    workspace = Path(workspace).absolute()
    P.require(workspace.is_dir() and not any(path.is_symlink() for path in (workspace, *workspace.parents)))
    pins, expected = build_pins(variant, unit), plan(workspace, go, variant, unit)
    node, files = workspace / "node", set()
    P.require(node.is_dir() and not node.is_symlink())
    for path in node.rglob("*"):
        info = path.lstat()
        P.require(not path.is_symlink() and (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)))
        if stat.S_ISREG(info.st_mode):
            P.require(info.st_nlink == 1)
            files.add(path.relative_to(node).as_posix())
    P.require(files == set(pins))
    for name, pin in pins.items():
        path = node / name
        raw = P.read_regular(path, 16 << 20)
        P.require(len(raw) == pin["bytes"] and P.sha(raw) == pin["sha256"])
        P.require(sys.platform == "win32" or stat.S_IMODE(path.stat().st_mode) == (int(pin["mode"], 8) & 0o777))
    recorded = json.loads(P.read_regular(workspace / "startup-record-prepared.json", 128 << 10),
                          object_pairs_hook=P.pairs)
    P.exact(recorded, expected)
    return expected


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("plan", "prepare", "verify"):
        sub = commands.add_parser(name)
        sub.add_argument("--workspace", required=True)
        sub.add_argument("--go", default="go")
        sub.add_argument("--variant", choices=("parent", "candidate"), default="candidate")
        sub.add_argument("--unit-controls", action="store_true")
        if name == "prepare":
            sub.add_argument("--node-source", required=True)
    args = parser.parse_args(argv)
    try:
        values = (args.workspace, args.go, args.variant, args.unit_controls)
        result = prepare(args.node_source, *values) if args.command == "prepare" else \
            plan(*values) if args.command == "plan" else verify(*values)
    except (OSError, ValueError, KeyError, TypeError):
        print(json.dumps({"kind": "public-chain-startup-record-preparation", "result": "REFUSED"}))
        return 1
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
