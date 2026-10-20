#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Prepare the selected ledger rollback-target experiment without executing it."""
import argparse
import importlib.util
import json
from pathlib import Path
import stat
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("rollback_target_parent", HERE / "prepare_patch_snapshot_lifetime.py")
H = importlib.util.module_from_spec(spec)
spec.loader.exec_module(H)
P = H.P
PATCH = "node-momentum-rollback-target-9c71-patch.json"
PATCH_SHA256 = "b580f394535f6d14108443da548e3171ffeeb6980fe9acf10dd33b305545f9fa"
FILE = "chain/momentum_pool.go"
MODIFIED_TREE = "cac9fa0446b0372ca37e9b15b0be2276f6d33cdf"
PARENT_BUILD_TREE = "f37671741ec343600b5eb336fd830b3625ee7ce5"
BUILD_TREE = "3d84ab1bdcfc9ae823c71086a1ef37f67be199e1"
UNIT_BUILD_TREE = "35f941e588e8cd784bac5d1c62a2000eee38dc5f"
AFTER_BYTES = 10031
AFTER_SHA256 = "71185adc2dcb41dcd3c7d30527928fa99422a4a5b73daaffc0c019bbafdd77bf"
PROBE = "momentum_rollback_target_probe.go"
PROBE_BYTES = 9703
PROBE_SHA256 = "d997d8c95ac72d422431f0f0bb43404062a9cabe306ff3b52c1a42bf85d5271b"
PROBE_TARGET = "cmd/candidate-momentum-rollback-target/main.go"
UNIT = "momentum_rollback_target_test.go.txt"
UNIT_BYTES = 3823
UNIT_SHA256 = "54b3e2512e63559e49097beba5d18a5816a5c793a1020a59b46f97af069fb26e"
UNIT_TARGET = "chain/candidate_momentum_rollback_target_test.go"
ROOTS = (
    "TestCandidateMomentumRollbackTargetPreflight",
    "TestCandidateMomentumRollbackTargetChecksCompleteIdentifier",
    "TestCandidateMomentumRollbackTargetPreservesLookupError",
    "TestRollbackToFailureAfterPopIsUnrecoverable",
    "TestRollbackToFirstPopFailureLeavesCanonicalStateCertain",
)


def selection():
    manifest, modified, pins = H.selection()
    row = P.document(PATCH, PATCH_SHA256)
    header = {
        "format_version": 1, "kind": "experimental-selected-ledger-rollback-target-preflight",
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
    P.require(len(before) == row["before_bytes"] == pins[FILE]["bytes"])
    P.require(P.sha(before) == row["before_sha256"] == pins[FILE]["sha256"])
    P.require(P.UTIL.git_hash("blob", before) == row["before_git_blob"] == pins[FILE]["git_blob"])
    P.require(len(after) == row["after_bytes"] == AFTER_BYTES)
    P.require(P.sha(after) == row["after_sha256"] == AFTER_SHA256)
    P.require(P.UTIL.git_hash("blob", after) == row["after_git_blob"])
    old = b"\tif momentum.Hash != identifier.Hash {\n"
    new = (b"\tif momentum == nil {\n"
           b"\t\treturn errors.Errorf(\"can't rollback momentums. No momentum at height %v\", identifier.Height)\n"
           b"\t}\n\tif momentum.Identifier() != identifier {\n")
    P.require(before.count(old) == 1 and before.replace(old, new) == after)
    modified[FILE] = after
    pins[FILE].update(bytes=len(after), sha256=P.sha(after), git_blob=row["after_git_blob"])
    P.require(len(pins) == 467 and P.UTIL.reconstruct_tree(pins) == MODIFIED_TREE)
    return manifest, modified, pins


def extra_source(unit=False):
    P.require(type(unit) is bool)
    name, count, digest = (UNIT, UNIT_BYTES, UNIT_SHA256) if unit else (PROBE, PROBE_BYTES, PROBE_SHA256)
    raw = P.read_regular(HERE / name, 64 << 10)
    P.require(len(raw) == count and P.sha(raw) == digest)
    return (UNIT_TARGET if unit else PROBE_TARGET), raw


def build_pins(variant="candidate", unit=False):
    P.require(variant in ("parent", "candidate") and type(unit) is bool)
    P.require(not unit or variant == "candidate")
    _, _, pins = H.selection() if variant == "parent" else selection()
    name, raw = extra_source(unit)
    P.require(name not in pins)
    pins[name] = {"mode": "100644", "bytes": len(raw), "sha256": P.sha(raw),
                  "git_blob": P.UTIL.git_hash("blob", raw)}
    expected = UNIT_BUILD_TREE if unit else PARENT_BUILD_TREE if variant == "parent" else BUILD_TREE
    P.require(len(pins) == 468 and P.UTIL.reconstruct_tree(pins) == expected)
    return pins


def plan(workspace, go, variant="candidate", unit=False):
    P.require(type(go) is str and go and "\x00" not in go)
    pins = build_pins(variant, unit)
    workspace = Path(workspace).absolute()
    return {
        "kind": "prepared-native-momentum-rollback-target", "node_revision": P.REVISION,
        "original_node_tree": P.TREE, "runtime_parent_tree": H.MODIFIED_TREE,
        "runtime_tree": H.MODIFIED_TREE if variant == "parent" else MODIFIED_TREE,
        "build_tree": P.UTIL.reconstruct_tree(pins), "source_blobs": 468,
        "variant": variant, "unit_controls": unit, "patch_sha256": PATCH_SHA256,
        "added_source_file": extra_source(unit)[0], "minimum_free_floor_bytes": 10 << 30,
        "native_test_roots": sorted(ROOTS), "expected_native_unit_pass_results": 11,
        "native_test_argv": [go, "test", "-mod=readonly", "-count=1", "-json", "-p=2",
                             "-trimpath", "-buildvcs=false", "-tags", "candidate_momentum_rollback_target",
                             "-run", "^(" + "|".join(ROOTS) + ")$", "./chain"],
        "build_argv": [go, "build", "-mod=readonly", "-p=2", "-trimpath", "-buildvcs=false",
                       "-tags", "candidate_momentum_rollback_target", "-o",
                       str(workspace / "rollback-target"), "./cmd/candidate-momentum-rollback-target"],
        "native_working_directory": str(workspace / "node"),
        "run_argv_template": [str(workspace / "rollback-target"), "--root", "NEW_REGISTERED_CASE_ROOT"],
        "reference_backend_executed": False, "new_dependency_transports_permitted": False,
        "Chain_Init_or_Start_selected": False, "cache_or_state_tree_selected": False,
        "consensus_or_network_selected": False, "accepted_header_binding": False,
        "runtime_state_value_acceptance": False, "consumer_result": "REFUSED",
    }


def prepare(node_source, workspace, go, variant="candidate", unit=False):
    expected = plan(workspace, go, variant, unit)
    workspace = P.private_destination(workspace)
    node_source = Path(node_source).absolute()
    P.require(not any(path.is_symlink() for path in (node_source, *node_source.parents)))
    manifest, modified, _ = H.selection() if variant == "parent" else selection()
    original = P.UTIL.snapshot_source(node_source, manifest["files"])
    workspace.mkdir(mode=0o700)
    node = workspace / "node"
    rows = {name: modified.get(name, raw) for name, raw in original.items()}
    name, raw = extra_source(unit)
    rows[name] = raw
    for name, pin in build_pins(variant, unit).items():
        path = node / name
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as stream:
            stream.write(rows[name])
        path.chmod(int(pin["mode"], 8) & 0o777)
    P.UTIL.seal(workspace / "momentum-rollback-target-prepared.json", P.UTIL.encoded(expected))
    P.exact(verify(workspace, go, variant, unit), expected)
    return expected


def verify(workspace, go, variant="candidate", unit=False):
    workspace = Path(workspace).absolute()
    P.require(workspace.is_dir() and not any(path.is_symlink() for path in (workspace, *workspace.parents)))
    pins = build_pins(variant, unit)
    expected = plan(workspace, go, variant, unit)
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
        path = node / name
        raw = P.read_regular(path, 16 << 20)
        P.require(len(raw) == pin["bytes"] and P.sha(raw) == pin["sha256"])
        P.require(sys.platform == "win32" or stat.S_IMODE(path.stat().st_mode) == (int(pin["mode"], 8) & 0o777))
    recorded = json.loads(P.read_regular(workspace / "momentum-rollback-target-prepared.json", 128 << 10),
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
        print(json.dumps({"kind": "momentum-rollback-target-preparation", "result": "REFUSED"}))
        return 1
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
