#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Prepare finite owned core-manager close-error cases; never launch them."""
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
spec = importlib.util.spec_from_file_location("core_stop_error_source_parent", HERE / "prepare_zenon_worker_stop.py")
BASE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(BASE)
P = BASE.P
MODEL = "core_stop_error_model.py"
MODEL_BYTES = 3089
MODEL_SHA256 = "7c5649cb057a73afa8cbb46b5c8e7cd1de61cabf2f942bf64227e4557c584a82"
PATCH = "testdata/candidate-core-stop-error-patch.json"
PATCH_SHA256 = "1dfb238a31f9a04b9ab870d3c8e0d4e92db52943977a73819c3c08187bd62e1e"
PARENT_TREE = "2887e4d8ee4c8c148f94c119719853c7f4a4df74"
CANDIDATE_TREE = "053c87e5bc4addd1bb70a467cb34facd439e66bc"
NATIVE_TREE = "2147eba7ef3a1ae06970f2f692b16c1af98419bc"
BUILD_TREES = {"baseline": "fa3062878b04dbe233b2233f596abe46b93c46ec",
               "candidate": "99db5c9f9f25360426c310bb089e1bf4be4942ea"}
TAG = "candidate_core_stop_errors"
TAGS = BASE.TAGS + "," + TAG
INPUT_FILE = BASE.INPUT_FILE
PREPARED_FILE = "prepared-core-stop-errors.json"
VARIANTS = ("baseline", "candidate")
MODES = ("healthy", "cache-closed", "both-closed")
EXTRAS = (
    ("core_stop_error_cache_handle.go.txt", "chain/cache/storage/candidate_core_stop_handle.go", 706,
     "4fca3b6f921151ea9c34693168534030b2e93150f3ed5fa4d25ea049c61b80a2"),
    ("core_stop_error_chain_handle.go.txt", "chain/candidate_core_stop_handle.go", 373,
     "1f3bdc1f568d15af1e62b62086a9700c60be1cf667da7f7c4e84f41c43e43dd9"),
    ("core_stop_error_probe.go", "cmd/candidate-core-stop-errors/main.go", 7492,
     "f2be13a1e9aeca5cc2506dc4fe4c25b32d3b900eef7aaad99b185d507ea9bda7"),
    ("core_stop_error_native_test.go.txt", "zenon/candidate_core_stop_errors_test.go", 2529,
     "2db70279c976ce58c02c257ed5bf9fabe2fb351821c27da9f7f3b8533909d32d"),
    ("core_stop_error_consensus_handle.go.txt", "zenon/candidate_core_stop_handle.go", 920,
     "2f60e0f91e933aa038293a171f86b1edab8874b2b11c4cf5824e8d435a22b1c5"),
)
QUIET_EXTRA = ("core_stop_error_quiet_test.go.txt", "zenon/candidate_core_stop_quiet_test.go", 541,
               "5ae606fbbe8d06783e908f5530401718e42004d4e598802c037b03f9346790d8")

def require(ok):
    if not ok:
        raise ValueError("Core Stop error preparation refused")

def pinned(name, size, digest):
    raw = P.read_regular(HERE / name, size)
    require(len(raw) == size and hashlib.sha256(raw).hexdigest() == digest)
    return raw

pinned(MODEL, MODEL_BYTES, MODEL_SHA256)
M = BASE.BASE.load("core_stop_error_independent_model", MODEL)

def selected_input():
    pinned(MODEL, MODEL_BYTES, MODEL_SHA256)
    return M.selected_input()

def new_roots():
    name, _, size, digest = EXTRAS[3]
    raw = pinned(name, size, digest)
    names = re.findall(rb"(?m)^func (TestCandidateCoreStopError_[A-Za-z0-9_]+)\(t \*testing.T\)", raw)
    require(len(names) == len(set(names)) == 3)
    return sorted(name.decode() for name in names)

def roots():
    result = sorted(set(BASE.roots()) | set(new_roots()))
    require(len(BASE.roots()) == 50 and len(result) == 53)
    return result

def selection(variant="candidate"):
    require(type(variant) is str and variant in VARIANTS)
    manifest, modified, pins = BASE.selection("candidate")
    require(len(pins) == 471 and P.UTIL.reconstruct_tree(pins) == PARENT_TREE)
    raw = P.read_regular(HERE / PATCH, 16 << 10)
    require(hashlib.sha256(raw).hexdigest() == PATCH_SHA256)
    patch = json.loads(raw, object_pairs_hook=M.pairs, parse_constant=M.constant)
    require(set(patch) == {"kind", "node_revision", "parent_tree", "candidate_tree", "file",
        "before", "after", "before_sha256", "after_sha256", "before_git_blob", "after_git_blob",
        "source_only_experimental"})
    M.exact({key: patch[key] for key in ("kind", "node_revision", "parent_tree", "candidate_tree",
                                       "file", "source_only_experimental")}, {
        "kind": "experimental-core-Zenon-Stop-error-cleanup", "node_revision": P.REVISION,
        "parent_tree": PARENT_TREE, "candidate_tree": CANDIDATE_TREE, "file": "zenon/zenon.go",
        "source_only_experimental": True})
    before, after = patch["before"].encode(), patch["after"].encode()
    for label, payload in (("before", before), ("after", after)):
        require(hashlib.sha256(payload).hexdigest() == patch[label + "_sha256"])
        require(P.UTIL.git_hash("blob", payload) == patch[label + "_git_blob"])
    require(patch["before_sha256"] == "e8d653b72c6e90d842d504dc3007f5191644d808c9ebebc128406a867e675796")
    require(patch["after_sha256"] == "d5cdfc3ed1ab824df333462ef2b38c960ff7962e52281744ed42df0a3cc98ffc")
    require(pins[patch["file"]]["sha256"] == patch["before_sha256"])
    if variant == "candidate":
        modified[patch["file"]] = after
        pins[patch["file"]] = {"mode": "100644", "bytes": len(after),
            "sha256": patch["after_sha256"], "git_blob": patch["after_git_blob"]}
    require(len(pins) == 471 and P.UTIL.reconstruct_tree(pins) ==
            (PARENT_TREE if variant == "baseline" else CANDIDATE_TREE))
    return manifest, modified, pins

def extra_sources():
    result = BASE.extra_sources()
    result.update({target: pinned(name, size, digest) for name, target, size, digest in EXTRAS})
    return result

def build_pins(variant="candidate", native_tests=False):
    require(type(native_tests) is bool and (not native_tests or variant == "candidate"))
    _, _, pins = selection(variant)
    for name, raw in extra_sources().items():
        require(name not in pins)
        pins[name] = {"mode": "100644", "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
                      "git_blob": P.UTIL.git_hash("blob", raw)}
    require(len(pins) == 480 and P.UTIL.reconstruct_tree(pins) == BUILD_TREES[variant])
    if native_tests:
        name, target, size, digest = QUIET_EXTRA
        raw = pinned(name, size, digest)
        require(target not in pins and target.endswith("_test.go"))
        pins[target] = {"mode": "100644", "bytes": len(raw), "sha256": digest,
                        "git_blob": P.UTIL.git_hash("blob", raw)}
        require(len(pins) == 481 and P.UTIL.reconstruct_tree(pins) == NATIVE_TREE)
    return pins

def plan(workspace, go, variant="candidate", native_tests=False):
    require(type(go) is str and bool(go) and "\x00" not in go)
    workspace = Path(workspace).absolute()
    pins = build_pins(variant, native_tests)
    selected_input()
    return {"kind": "prepared-owned-core-Zenon-Stop-errors", "variant": variant,
        "node_revision": P.REVISION, "parent_runtime_tree": PARENT_TREE,
        "runtime_tree": PARENT_TREE if variant == "baseline" else CANDIDATE_TREE,
        "build_tree": NATIVE_TREE if native_tests else BUILD_TREES[variant], "source_blobs": len(pins),
        "native_tests": native_tests, "native_test_preparation_required": variant == "candidate" and not native_tests,
        "selection": {"bytes": M.SELECTION_BYTES, "sha256": M.SELECTION_SHA256},
        "minimum_free_floor_bytes": 10 << 30, "expected_allocation_bytes": 3 << 30,
        "suggested_task_quota_bytes": 4 << 30,
        "native_test_roots": roots() if variant == "candidate" else [],
        "expected_native_root_tests": 53 if variant == "candidate" else 0,
        "expected_native_pass_results": 62 if variant == "candidate" else 0,
        "native_test_argv": [go, "test", "-mod=readonly", "-count=1", "-json", "-p=2",
            "-trimpath", "-buildvcs=false", "-tags", TAGS, "-run", "^(" + "|".join(roots()) + ")$",
            "./chain", "./chain/cache", "./chain/cache/storage", "./pillar", "./zenon"] if native_tests else [],
        "build_argv": [go, "build", "-mod=readonly", "-p=2", "-trimpath", "-buildvcs=false",
            "-tags", TAG, "-o", str(workspace / "core-stop"), "./cmd/candidate-core-stop-errors"],
        "ordinary_node_entrypoint_build_argv": [go, "build", "-mod=readonly", "-p=2", "-trimpath",
            "-buildvcs=false", "-o", str(workspace / "znnd-not-executed"), "./cmd/znnd"],
        "native_working_directory": str(workspace / "node"),
        "cases": [{"case": mode, "requires_empty_root": True} for mode in MODES],
        "run_argv_templates": [[str(workspace / "core-stop"), "--case", mode, "--root", "OWNED_EMPTY_CASE_ROOT",
            "--selection", str(workspace / INPUT_FILE), "--selection-sha256", M.SELECTION_SHA256] for mode in MODES],
        "ordinary_comparison_builds": 1, "ordinary_comparison_processes": 3,
        "controlled_handle_close_not_hardware_failure": True,
        "expected_values_are_not_input_to_child": True, "core_Start_selected": False,
        "reference_backend_executed": False, "new_dependency_transports_permitted": False,
        "node_entrypoint_execution_selected": False, "wallet_or_peer_server_or_RPC_listener_selected": False,
        "repeated_Stop_or_concurrent_lifecycle_qualified": False, "full_node_or_network_qualified": False,
        "accepted_header_binding": False, "production_state_value_accepted": False, "consumer_result": "REFUSED"}

def prepare(node_source, workspace, go, variant="candidate", native_tests=False):
    expected = plan(workspace, go, variant, native_tests)
    workspace = P.private_destination(workspace)
    # The parent validates its own original-source preparation before any new
    # patch is applied. The final 480-file view is checked by this recipe.
    BASE.prepare(node_source, workspace, go, "candidate")
    _, modified, _ = selection(variant)
    if variant == "candidate":
        (workspace / "node/zenon/zenon.go").write_bytes(modified["zenon/zenon.go"])
    for name, target, size, digest in EXTRAS + ((QUIET_EXTRA,) if native_tests else ()):
        path = workspace / "node" / target
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as stream:
            stream.write(pinned(name, size, digest))
        path.chmod(0o644)
    P.UTIL.seal(workspace / PREPARED_FILE, P.UTIL.encoded(expected))
    M.exact(verify(workspace, go, variant, native_tests), expected)
    return expected

def verify(workspace, go, variant="candidate", native_tests=False):
    workspace = Path(workspace).absolute()
    require(workspace.is_dir() and not any(path.is_symlink() for path in (workspace, *workspace.parents)))
    expected, pins = plan(workspace, go, variant, native_tests), build_pins(variant, native_tests)
    node, files = workspace / "node", set()
    require(node.is_dir() and not node.is_symlink())
    for path in node.rglob("*"):
        row = path.lstat()
        require(not path.is_symlink() and (stat.S_ISREG(row.st_mode) or stat.S_ISDIR(row.st_mode)))
        if stat.S_ISREG(row.st_mode):
            require(row.st_nlink == 1)
            files.add(path.relative_to(node).as_posix())
    require(files == set(pins))
    for name, pin in pins.items():
        path = node / name
        raw = P.read_regular(path, 16 << 20)
        require(len(raw) == pin["bytes"] and hashlib.sha256(raw).hexdigest() == pin["sha256"])
        require(sys.platform == "win32" or stat.S_IMODE(path.stat().st_mode) == (int(pin["mode"], 8) & 0o777))
    require(P.read_regular(workspace / INPUT_FILE, 8192) == selected_input())
    recorded = json.loads(P.read_regular(workspace / PREPARED_FILE, 128 << 10),
                          object_pairs_hook=M.pairs, parse_constant=M.constant)
    M.exact(recorded, expected)
    return expected

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("plan", "prepare", "verify"):
        child = commands.add_parser(name)
        child.add_argument("--workspace", required=True)
        child.add_argument("--go", required=True)
        child.add_argument("--variant", choices=VARIANTS, default="candidate")
        child.add_argument("--native-tests", action="store_true")
        if name == "prepare":
            child.add_argument("--node-source", required=True)
    args = parser.parse_args(argv)
    if args.command == "prepare":
        result = prepare(args.node_source, args.workspace, args.go, args.variant, args.native_tests)
    else:
        result = (plan if args.command == "plan" else verify)(args.workspace, args.go, args.variant, args.native_tests)
    print(json.dumps(result, sort_keys=True, indent=2))

if __name__ == "__main__":
    try:
        main()
    except (ValueError, TypeError, KeyError, OSError):
        print("Core Stop error preparation refused; state values remain disabled.", file=sys.stderr)
        raise SystemExit(1)
