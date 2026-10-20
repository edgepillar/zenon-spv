#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Prepare the selected short-lived patch-snapshot experiment without execution."""
import argparse
import importlib.util
import json
from pathlib import Path
import stat
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("snapshot_patch_parent", HERE / "prepare_cache_replay_patches.py")
H = importlib.util.module_from_spec(spec)
spec.loader.exec_module(H)
P = H.P
PATCH = "node-patch-snapshot-release-9c71-patch.json"
PATCH_SHA256 = "d2fe705cc3db7270f5853ebfda753e75c44715e823a1d0ce6503bd6855f7b950"
MODIFIED_TREE = "890520349329851e2d39bd134d5643baf59531b6"
BUILD_TREE = "3102dcb18c0b2e7f069be060420be67544f89b13"
COMPONENT_RUNTIME_TREE = "664df2f156262f056fb77f51deda10fe1e90e94d"
COMPONENT_PARENT_BUILD_TREE = "90df13e378af5662f1d885a1b41b666d3629fb02"
COMPONENT_CANDIDATE_BUILD_TREE = "6c658c226b189724286e8f78fab9e9de8f327310"
FILE = "common/db/versioned_db.go"
AFTER_BYTES = 14579
AFTER_SHA256 = "d1d2809ca2800d69e82cc67150ea31bbefb5e11d982c4465b3feec5c143497fc"
PROBE = "patch_snapshot_lifetime_probe_test.go.txt"
PROBE_BYTES = 10368
PROBE_SHA256 = "64a36654bf1efd97c1f648140d1c38c1ccf85fb49c08222efdfdb449dbafe18b"
PARENT_PROBE_BYTES = 6941
PARENT_PROBE_SHA256 = "11795fd16ed9727ca659a92a5bc983c0ce83e04426ebaa66037a44f913d82eec"
PROBE_TARGET = "common/db/candidate_patch_snapshot_lifetime_test.go"
SNAPSHOT_ROOTS = (
    "TestCandidatePatchSnapshotLifetime",
    "TestCandidateSnapshotReturnedPatchLifetime",
    "TestCandidateSnapshotAcquisitionError",
)
NATIVE_ROOTS = tuple(sorted((*H.NATIVE_ROOTS, *SNAPSHOT_ROOTS)))
DB_ROOTS = ('TestChanges', 'TestFrontierWriteKeysAreCopies', 'TestLevelDBManagerAddRejectsNonFrontierPrevious', 'TestLevelDBManagerAddWriteFailureIsAtomic', 'TestLevelDBManagerHistoricalViewHidesLaterKeys', 'TestLevelDBManagerPopInvalidatesRollbackCaches', 'TestLevelDBManagerPopWriteFailureIsAtomic', 'TestLevelDBManagerStopAfterFailedClose', 'TestManagerStopIsIdempotent', 'TestMemDBManagerAddRechecksFrontierAtCommit', 'TestMemDBManagerCloneDivergesIndependently', 'TestMemDBManagerStopConcurrentWithAdd', 'TestMemDBManagerStopDuringAdd', 'TestMergedIterators', 'TestNewPatchFromDump_Malformed', 'TestNewPatchFromDump_Valid', 'TestPatchDumpBaselineIsIndependentOfLaterMutation', 'TestRemoveKeys', 'TestRollbackPatch', 'TestStressMemDB', 'TestVersionedDBConcurrentUse', 'TestVersionedDBVersions')


def probe_bytes():
    return H.source_bytes(PROBE, PROBE_BYTES, PROBE_SHA256)


def parent_probe_bytes():
    raw = probe_bytes()[:PARENT_PROBE_BYTES]
    P.require(P.sha(raw) == PARENT_PROBE_SHA256)
    return raw


def selection():
    manifest, modified, pins = H.selection()
    value = P.document(PATCH, PATCH_SHA256)
    header = {
        "format_version": 1, "kind": "experimental-patch-read-snapshot-release",
        "node_revision": P.REVISION, "original_node_tree": P.TREE,
        "runtime_parent_tree": H.MODIFIED_TREE, "runtime_after_tree": MODIFIED_TREE,
        "experimental_only": True, "disk_format_changed": False,
        "SMT_profile_changed": False, "legacy_manager_interface_changed": False,
        "snapshot_acquisition_error_diagnostic_changed": True,
        "returned_version_DB_snapshot_ownership_changed": False,
        "accepted_header_or_consumer_acceptance_changed": False,
        "permanent_leak_claimed": False, "production_resource_budget_qualified": False,
        "upstream_mutated": False,
    }
    P.require(type(value) is dict and set(value) == set(header) | {"replacements"})
    P.exact({k: value[k] for k in header}, header)
    rows = value["replacements"]
    P.require(type(rows) is list and len(rows) == 1)
    row = rows[0]
    P.require(set(row) == {"file", "mode", "before_bytes", "before_sha256", "before_git_blob",
                           "after_bytes", "after_sha256", "after_git_blob", "before", "after"})
    P.require(row["file"] == FILE and row["mode"] == pins[FILE]["mode"] == "100644")
    before, after = row["before"].encode(), row["after"].encode()
    P.require(len(before) == row["before_bytes"] == pins[FILE]["bytes"])
    P.require(P.sha(before) == row["before_sha256"] == pins[FILE]["sha256"])
    P.require(P.UTIL.git_hash("blob", before) == row["before_git_blob"] == pins[FILE]["git_blob"])
    P.require(len(after) == row["after_bytes"] == AFTER_BYTES)
    P.require(P.sha(after) == row["after_sha256"] == AFTER_SHA256)
    P.require(P.UTIL.git_hash("blob", after) == row["after_git_blob"])
    modified[FILE] = after
    pins[FILE].update(bytes=len(after), sha256=P.sha(after), git_blob=row["after_git_blob"])
    P.require(P.UTIL.reconstruct_tree(pins) == MODIFIED_TREE)
    return manifest, modified, pins


def extra_sources():
    extras = H.extra_sources()
    P.require(PROBE_TARGET not in extras)
    extras[PROBE_TARGET] = probe_bytes()
    P.require(len(extras) == 7)
    return extras


def build_pins():
    _, _, pins = selection()
    for name, raw in extra_sources().items():
        H.add_pin(pins, name, raw)
    P.require(len(pins) == 474 and P.UTIL.reconstruct_tree(pins) == BUILD_TREE)
    return pins


def component_build_trees():
    manifest, modified, _ = selection()
    pins = {name: dict(pin) for name, pin in manifest["files"].items()}
    parent = {name: dict(pin) for name, pin in pins.items()}
    H.add_pin(parent, PROBE_TARGET, parent_probe_bytes())
    P.require(P.UTIL.reconstruct_tree(parent) == COMPONENT_PARENT_BUILD_TREE)
    raw = modified[FILE]
    pins[FILE].update(bytes=len(raw), sha256=P.sha(raw), git_blob=P.UTIL.git_hash("blob", raw))
    P.require(P.UTIL.reconstruct_tree(pins) == COMPONENT_RUNTIME_TREE)
    H.add_pin(pins, PROBE_TARGET, probe_bytes())
    P.require(P.UTIL.reconstruct_tree(pins) == COMPONENT_CANDIDATE_BUILD_TREE)
    return COMPONENT_PARENT_BUILD_TREE, COMPONENT_CANDIDATE_BUILD_TREE


def plan(workspace, go):
    expected = H.plan(workspace, go)
    pins = build_pins()
    node = str(Path(workspace).absolute() / "node")
    component_parent, component_candidate = component_build_trees()
    expected.update(
        kind="prepared-native-patch-snapshot-lifetime", runtime_tree=MODIFIED_TREE,
        runtime_parent_tree=H.MODIFIED_TREE, build_tree=P.UTIL.reconstruct_tree(pins),
        source_blobs=474, snapshot_patch_sha256=PATCH_SHA256,
        added_source_files=sorted(extra_sources()), native_control_roots=list(NATIVE_ROOTS),
        expected_native_unit_pass_results=73, native_packages=["./common/db", "./chain", "./chain/cache/storage"],
        snapshot_control_roots=list(SNAPSHOT_ROOTS), snapshot_core_cases=12,
        snapshot_supplemental_cases=["returned_patch_after_stop", "closed_underlying_handle"],
        snapshot_case_root="NEW_REGISTERED_SNAPSHOT_CASE_ROOT",
        snapshot_environment={"SPV_SNAPSHOT_CASE_ROOT": "NEW_REGISTERED_SNAPSHOT_CASE_ROOT",
                              "SPV_EXPECT_PATCH_SNAPSHOT_RELEASE": "true"},
        native_test_argv=[go, "test", "-mod=readonly", "-race", "-count=1", "-json", "-p=2",
                          "-trimpath", "-buildvcs=false", "-tags", "candidate_patch_snapshot_lifetime",
                          "-run", "^(" + "|".join(NATIVE_ROOTS) + ")$",
                          "./common/db", "./chain", "./chain/cache/storage"],
        original_DB_root_tests=list(DB_ROOTS), original_DB_root_count=22,
        original_DB_test_argv=[go, "test", "-mod=readonly", "-race", "-count=1", "-json", "-p=2",
                              "-trimpath", "-buildvcs=false", "-run", "^(" + "|".join(DB_ROOTS) + ")$",
                              "./common/db"],
        native_test_working_directory=node,
        snapshot_probe={"bytes": PROBE_BYTES, "sha256": PROBE_SHA256},
        component_parent_probe={"bytes": PARENT_PROBE_BYTES, "sha256": PARENT_PROBE_SHA256},
        component_parent_build_tree=component_parent, component_candidate_build_tree=component_candidate,
        component_candidate_runtime_tree=COMPONENT_RUNTIME_TREE,
        snapshot_acquisition_error_diagnostic_changed=True,
        returned_version_DB_snapshot_ownership_changed=False,
        permanent_leak_claimed=False, production_resource_budgets_qualified=False,
        new_dependency_transports_permitted=False,
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
    P.UTIL.seal(workspace / "patch-snapshot-lifetime-prepared.json", P.UTIL.encoded(expected))
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
    recorded = json.loads(P.read_regular(workspace / "patch-snapshot-lifetime-prepared.json", 128 << 10), object_pairs_hook=P.pairs)
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
        print(json.dumps({"kind": "patch-snapshot-lifetime-preparation", "result": "REFUSED"}))
        return 1
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
