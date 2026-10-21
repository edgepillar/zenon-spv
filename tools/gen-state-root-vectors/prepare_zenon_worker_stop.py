#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Prepare a finite keyless core-manager Stop recipe; never execute it."""
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
spec = importlib.util.spec_from_file_location("worker_stop_source_parent", HERE / "prepare_cache_read_errors.py")
BASE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(BASE)
P = BASE.P
MODEL = "zenon_worker_stop_model.py"
MODEL_BYTES = 4282
MODEL_SHA256 = "89ff7e2f682554069ee611972457639457370d6d86521d0e284ff309ce5a0993"
VARIANTS = ("baseline", "candidate")
MODES = ("construct-stop", "init-stop", "reopen-start-stop")
PATCH = "testdata/candidate-zenon-worker-stop-patch.json"
PATCH_SHA256 = "5e5ec8a94a3295b56eb4706b0ba31534ce10bde4d4c4f8796123f0883187528e"
PARENT_TREE = "c5e413c43794b3ba32763484670db2b100295a15"
CANDIDATE_TREE = "2887e4d8ee4c8c148f94c119719853c7f4a4df74"
BUILD_TREES = {"baseline": "a460d088e6072dd1655cebaa877a108e6e68ac44",
               "candidate": "d76ff3928998b096c172ff6871c69d0a56cad3b7"}
TAG = "candidate_zenon_worker_stop"
TAGS = BASE.TAGS + "," + TAG
INPUT_FILE = "worker-stop-selection.json"
PREPARED_FILE = "prepared-zenon-worker-stop.json"
EXTRAS = (
    ("zenon_worker_stop_probe.go", "cmd/candidate-core-worker-stop/main.go", 6243,
     "73e30974380e7bc165ecf2c3577a19ce689362f81543760826f888c6a284e0d9"),
    ("zenon_worker_stop_cleanup.go.txt", "zenon/candidate_worker_stop_cleanup.go", 1403,
     "2005a9efa1df1bbbaba6a69b88a74c31fd1fc1f10bc0afe1f535e33cb71f4458"),
    ("zenon_worker_prestart_stop_test.go.txt", "pillar/candidate_worker_prestart_stop_test.go", 3161,
     "e2495f9960523f305476a4e3e9bf7c9f06b6d42ad619881b51017f04e8f4de6f"),
)

def require(ok):
    if not ok:
        raise ValueError("Core-manager Stop preparation refused")

def pinned(name, size, digest):
    raw = P.read_regular(HERE / name, size)
    require(len(raw) == size and hashlib.sha256(raw).hexdigest() == digest)
    return raw

pinned(MODEL, MODEL_BYTES, MODEL_SHA256)
M = BASE.load("worker_stop_independent_model", MODEL)

def selected_input():
    pinned(MODEL, MODEL_BYTES, MODEL_SHA256)
    return M.selected_input()

def new_roots():
    name, _, size, digest = EXTRAS[2]
    raw = pinned(name, size, digest)
    names = re.findall(rb"(?m)^func (TestCandidateWorkerPreStart_[A-Za-z0-9_]+)\(t \*testing.T\)", raw)
    require(len(names) == len(set(names)) == 9)
    return sorted(name.decode() for name in names)

def roots():
    result = sorted(set(BASE.roots()) | set(new_roots()))
    require(len(BASE.roots()) == 41 and len(result) == 50)
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
    M.exact({k: patch[k] for k in ("kind", "node_revision", "parent_tree", "candidate_tree",
                                 "file", "source_only_experimental")}, {
        "kind": "experimental-core-Zenon-prestart-worker-stop", "node_revision": P.REVISION,
        "parent_tree": PARENT_TREE, "candidate_tree": CANDIDATE_TREE, "file": "pillar/worker.go",
        "source_only_experimental": True})
    before, after = patch["before"].encode(), patch["after"].encode()
    for label, payload in (("before", before), ("after", after)):
        require(hashlib.sha256(payload).hexdigest() == patch[label + "_sha256"])
        require(P.UTIL.git_hash("blob", payload) == patch[label + "_git_blob"])
    require(patch["before_sha256"] == "ee54feb64979cdf1fbed9e1b064a912902828e8122ece3733b6c8faff0f5bf9b")
    require(patch["after_sha256"] == "101bf07e60650cfce7e8dc1a1abdc92dd008069ffab989c7181770a4bcc62484")
    require(pins[patch["file"]]["sha256"] == patch["before_sha256"])
    fragment = b'\t\tlog:         common.PillarLogger.New("submodule", "worker"),\n'
    require(before.count(fragment) == 1 and
            before.replace(fragment, fragment + b"\t\tclosed:      make(chan struct{}),\n") == after)
    if variant == "candidate":
        modified[patch["file"]] = after
        pins[patch["file"]] = {"mode": "100644", "bytes": len(after),
            "sha256": patch["after_sha256"], "git_blob": patch["after_git_blob"]}
    require(len(pins) == 471 and P.UTIL.reconstruct_tree(pins) ==
            (PARENT_TREE if variant == "baseline" else CANDIDATE_TREE))
    return manifest, modified, pins

def extra_sources():
    result = {BASE.PROBE_TARGET: BASE.pinned(BASE.PROBE, BASE.PROBE_BYTES, BASE.PROBE_SHA256)}
    result.update({target: pinned(name, size, digest) for name, target, size, digest in EXTRAS})
    return result

def build_pins(variant="candidate"):
    _, _, pins = selection(variant)
    for name, raw in extra_sources().items():
        require(name not in pins)
        pins[name] = {"mode": "100644", "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
                      "git_blob": P.UTIL.git_hash("blob", raw)}
    require(len(pins) == 475 and P.UTIL.reconstruct_tree(pins) == BUILD_TREES[variant])
    return pins

def plan(workspace, go, variant="candidate"):
    require(type(go) is str and bool(go) and "\x00" not in go)
    workspace = Path(workspace).absolute()
    pins = build_pins(variant)
    selected_input()
    return {"kind": "prepared-keyless-core-Zenon-prestart-Stop", "variant": variant,
        "node_revision": P.REVISION, "parent_runtime_tree": PARENT_TREE,
        "runtime_tree": PARENT_TREE if variant == "baseline" else CANDIDATE_TREE,
        "build_tree": BUILD_TREES[variant], "source_blobs": len(pins),
        "selection": {"bytes": M.SELECTION_BYTES, "sha256": M.SELECTION_SHA256},
        "minimum_free_floor_bytes": 10 << 30, "expected_allocation_bytes": 3 << 30,
        "suggested_task_quota_bytes": 4 << 30,
        "native_test_roots": roots() if variant == "candidate" else [],
        "expected_native_root_tests": 50 if variant == "candidate" else 0,
        "expected_native_pass_results": 59 if variant == "candidate" else 0,
        "native_test_argv": [go, "test", "-mod=readonly", "-count=1", "-json", "-p=2",
            "-trimpath", "-buildvcs=false", "-tags", TAGS, "-run", "^(" + "|".join(roots()) + ")$",
            "./chain", "./chain/cache", "./chain/cache/storage", "./pillar"] if variant == "candidate" else [],
        "build_argv": [go, "build", "-mod=readonly", "-p=2", "-trimpath", "-buildvcs=false",
            "-tags", TAG, "-o", str(workspace / "worker-stop"), "./cmd/candidate-core-worker-stop"],
        "native_working_directory": str(workspace / "node"),
        "cases": [{"case": mode, "root": "constructed" if mode == MODES[0] else "initialized",
                   "requires_empty_root": mode != MODES[2]} for mode in MODES],
        "run_argv_templates": [[str(workspace / "worker-stop"), "--case", mode,
            "--root", "OWNED_CONSTRUCTED_ROOT" if mode == MODES[0] else "OWNED_INITIALIZED_ROOT",
            "--selection", str(workspace / INPUT_FILE), "--selection-sha256", M.SELECTION_SHA256]
            for mode in MODES],
        "ordinary_builds": 1, "ordinary_processes": 3,
        "expected_API_panics": 2 if variant == "baseline" else 0,
        "reopen_uses_same_closed_initialized_root": True,
        "expected_values_are_not_input_to_child": True,
        "keyless_internal_services_start_in_reopen_control": True,
        "reference_backend_executed": False, "new_dependency_transports_permitted": False,
        "node_wrapper_or_wallet_or_peer_server_selected": False,
        "repeated_Stop_or_concurrent_lifecycle_qualified": False,
        "full_node_or_network_qualified": False, "accepted_header_binding": False,
        "production_state_value_accepted": False, "consumer_result": "REFUSED"}

def prepare(node_source, workspace, go, variant="candidate"):
    expected = plan(workspace, go, variant)
    workspace = P.private_destination(workspace)
    node_source = Path(node_source).absolute()
    require(not any(path.is_symlink() for path in (node_source, *node_source.parents)))
    original_root, prepared_root = node_source.resolve(), workspace.resolve()
    require(original_root != prepared_root and original_root not in prepared_root.parents and
            prepared_root not in original_root.parents)
    manifest, modified, _ = selection(variant)
    original = P.UTIL.snapshot_source(node_source, manifest["files"])
    rows = {name: modified.get(name, raw) for name, raw in original.items()}
    rows.update(modified)
    rows.update(extra_sources())
    workspace.mkdir(mode=0o700)
    for name, pin in build_pins(variant).items():
        path = workspace / "node" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as stream:
            stream.write(rows[name])
        path.chmod(int(pin["mode"], 8) & 0o777)
    P.UTIL.seal(workspace / INPUT_FILE, selected_input())
    P.UTIL.seal(workspace / PREPARED_FILE, P.UTIL.encoded(expected))
    M.exact(verify(workspace, go, variant), expected)
    return expected

def verify(workspace, go, variant="candidate"):
    workspace = Path(workspace).absolute()
    require(workspace.is_dir() and not any(path.is_symlink() for path in (workspace, *workspace.parents)))
    expected, pins = plan(workspace, go, variant), build_pins(variant)
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
        if name == "prepare":
            child.add_argument("--node-source", required=True)
    args = parser.parse_args(argv)
    if args.command == "prepare":
        result = prepare(args.node_source, args.workspace, args.go, args.variant)
    else:
        result = (plan if args.command == "plan" else verify)(args.workspace, args.go, args.variant)
    print(json.dumps(result, sort_keys=True, indent=2))

if __name__ == "__main__":
    try:
        main()
    except (ValueError, TypeError, KeyError, OSError):
        print("Core-manager Stop preparation refused; state values remain disabled.", file=sys.stderr)
        raise SystemExit(1)
