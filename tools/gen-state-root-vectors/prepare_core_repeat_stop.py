#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Prepare bounded repeated Stop experiments; never download or run a backend."""
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
spec = importlib.util.spec_from_file_location("core_repeat_stop_preparation_parent", HERE / "prepare_core_stop_errors.py")
BASE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(BASE)
P = BASE.P
MODEL = "core_repeat_stop_model.py"
MODEL_BYTES = 2972
MODEL_SHA256 = "63b2c850486d094a7a771beb12c3fb6561f773ac4604b543ee133d874e6eae07"
PATCH = "testdata/candidate-core-repeated-stop-patch.json"
PATCH_BYTES = 8005
PATCH_SHA256 = "2e2c83f62f30cab0d16b445103839f92fe3f918935b6f0fe434be58a692e499c"
PARENT_TREE = "053c87e5bc4addd1bb70a467cb34facd439e66bc"
CANDIDATE_TREE = "0581880cedda66b02cbc40bd54babd19c29340ce"
VARIANTS = ("baseline", "candidate")
MODES = BASE.MODES
TAGS = BASE.TAGS
INPUT_FILE = BASE.INPUT_FILE
PREPARED_FILE = "prepared-core-repeated-stop.json"
EXTRAS = (
    ("core_repeat_stop_probe.go", "cmd/candidate-core-stop-errors/main.go", 7722,
     "98859bdcdbf7d47c5c43b12968e77f77de497a662a87f46dc9e306a60542de58"),
    ("core_repeat_stop_native_test.go.txt", "zenon/candidate_core_repeat_stop_test.go", 4332,
     "30d6bb8059dffddc912265f69eb5c73b534426fec6bd01ba3b4523f29be79fff"),
)

def require(ok):
    if not ok:
        raise ValueError("Repeated Stop preparation refused")

def pinned(name, size, digest):
    raw = P.read_regular(HERE / name, size)
    require(len(raw) == size and hashlib.sha256(raw).hexdigest() == digest)
    return raw

pinned(MODEL, MODEL_BYTES, MODEL_SHA256)
spec = importlib.util.spec_from_file_location("core_repeat_stop_independent_model", HERE / MODEL)
M = importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)

def selected_input():
    pinned(MODEL, MODEL_BYTES, MODEL_SHA256)
    return M.selected_input()

def new_roots():
    name, _, size, digest = EXTRAS[1]
    raw = pinned(name, size, digest)
    found = re.findall(rb"(?m)^func (TestCandidateCoreRepeatStop_[A-Za-z0-9_]+)\(t \*testing.T\)", raw)
    require(len(found) == len(set(found)) == 5)
    return sorted(name.decode() for name in found)

def roots():
    result = sorted(set(BASE.roots()) | set(new_roots()))
    require(len(BASE.roots()) == 53 and len(result) == 58)
    return result

def patch():
    value = json.loads(pinned(PATCH, PATCH_BYTES, PATCH_SHA256), object_pairs_hook=M.pairs, parse_constant=M.constant)
    require(set(value) == {"kind", "node_revision", "parent_tree", "candidate_tree", "file", "before", "after",
                          "before_sha256", "after_sha256", "before_git_blob", "after_git_blob", "source_only_experimental"})
    M.exact({key: value[key] for key in ("kind", "node_revision", "parent_tree", "candidate_tree", "file", "source_only_experimental")}, {
        "kind": "experimental-core-Zenon-repeated-Stop-result", "node_revision": P.REVISION,
        "parent_tree": PARENT_TREE, "candidate_tree": CANDIDATE_TREE,
        "file": "zenon/zenon.go", "source_only_experimental": True})
    for label in ("before", "after"):
        raw = value[label].encode()
        require(hashlib.sha256(raw).hexdigest() == value[label + "_sha256"])
        require(P.UTIL.git_hash("blob", raw) == value[label + "_git_blob"])
    require(value["before_sha256"] == "d5cdfc3ed1ab824df333462ef2b38c960ff7962e52281744ed42df0a3cc98ffc")
    return value

def selection(variant="candidate"):
    require(type(variant) is str and variant in VARIANTS)
    manifest, modified, pins = BASE.selection("candidate")
    require(len(pins) == 471 and P.UTIL.reconstruct_tree(pins) == PARENT_TREE)
    change = patch()
    require(pins[change["file"]]["sha256"] == change["before_sha256"])
    if variant == "candidate":
        raw = change["after"].encode()
        modified[change["file"]] = raw
        pins[change["file"]] = {"mode": "100644", "bytes": len(raw),
            "sha256": change["after_sha256"], "git_blob": change["after_git_blob"]}
    require(P.UTIL.reconstruct_tree(pins) == (CANDIDATE_TREE if variant == "candidate" else PARENT_TREE))
    return manifest, modified, pins

def build_pins(variant="candidate"):
    require(type(variant) is str and variant in VARIANTS)
    result = BASE.build_pins("candidate", native_tests=variant == "candidate")
    _, _, runtime = selection(variant)
    result["zenon/zenon.go"] = runtime["zenon/zenon.go"]
    for index, (name, target, size, digest) in enumerate(EXTRAS):
        if index and variant == "baseline":
            continue
        raw = pinned(name, size, digest)
        require((target in result) == (index == 0))
        result[target] = {"mode": "100644", "bytes": len(raw), "sha256": digest,
                          "git_blob": P.UTIL.git_hash("blob", raw)}
    require(len(result) == (482 if variant == "candidate" else 480))
    return result

def plan(workspace, go, variant="candidate"):
    require(type(go) is str and bool(go) and "\x00" not in go)
    workspace = Path(workspace).absolute()
    pins = build_pins(variant)
    selected_input()
    candidate = variant == "candidate"
    return {"kind": "prepared-owned-core-repeated-Stop", "variant": variant,
        "node_revision": P.REVISION, "runtime_tree": CANDIDATE_TREE if candidate else PARENT_TREE,
        "build_tree": P.UTIL.reconstruct_tree(pins), "source_files": len(pins),
        "selection": {"sha256": M.SELECTION_SHA256, "bytes": M.SELECTION_BYTES},
        "minimum_free_floor_bytes": 10 << 30, "expected_allocation_bytes": 2 << 30,
        "suggested_task_quota_bytes": 3 << 30,
        "ordinary_timeout_seconds": 90, "native_test_timeout_seconds": 300, "native_race_timeout_seconds": 600,
        "build_argv": [go, "build", "-mod=readonly", "-p=2", "-trimpath", "-buildvcs=false",
            "-tags", BASE.TAG, "-o", str(workspace / "core-repeat-stop"), "./cmd/candidate-core-stop-errors"],
        "working_directory": str(workspace / "node"),
        "run_argv_templates": [[str(workspace / "core-repeat-stop"), "--case", mode,
            "--root", "OWNED_EMPTY_CASE_ROOT", "--selection", str(workspace / INPUT_FILE),
            "--selection-sha256", M.SELECTION_SHA256] for mode in MODES],
        "native_test_argv": [go, "test", "-mod=readonly", "-count=1", "-json", "-p=2", "-trimpath",
            "-buildvcs=false", "-tags", TAGS, "-run", "^(" + "|".join(roots()) + ")$",
            "./chain", "./chain/cache", "./chain/cache/storage", "./pillar", "./zenon"] if candidate else [],
        "native_race_argv": [go, "test", "-race", "-mod=readonly", "-count=1", "-json", "-p=2", "-trimpath",
            "-buildvcs=false", "-tags", TAGS, "-run", "^(" + "|".join(new_roots()) + ")$", "./zenon"] if candidate else [],
        "native_root_tests": 58 if candidate else 0, "native_pass_results": 71 if candidate else 0,
        "race_root_tests": 5 if candidate else 0, "race_pass_results": 9 if candidate else 0,
        "expected_values_not_supplied_to_child": True, "new_dependency_transports_permitted": False,
        "core_Start_or_wallet_or_peer_or_RPC_selected": False,
        "concurrent_Init_Start_Stop_qualified": False, "full_node_or_network_qualified": False,
        "accepted_header_binding": False, "production_state_value_accepted": False, "consumer_result": "REFUSED"}

def prepare(node_source, workspace, go, variant="candidate"):
    expected = plan(workspace, go, variant)
    workspace = P.private_destination(workspace)
    BASE.prepare(node_source, workspace, go, "candidate", native_tests=variant == "candidate")
    _, modified, _ = selection(variant)
    if variant == "candidate":
        (workspace / "node/zenon/zenon.go").write_bytes(modified["zenon/zenon.go"])
    for index, (name, target, size, digest) in enumerate(EXTRAS):
        if index and variant == "baseline":
            continue
        path = workspace / "node" / target
        if index:
            require(not path.exists())
            with path.open("xb") as stream:
                stream.write(pinned(name, size, digest))
        else:
            require(hashlib.sha256(path.read_bytes()).hexdigest() == BASE.EXTRAS[2][3])
            path.write_bytes(pinned(name, size, digest))
        path.chmod(0o644)
    P.UTIL.seal(workspace / PREPARED_FILE, P.UTIL.encoded(expected))
    M.exact(verify(workspace, go, variant), expected)
    return expected

def verify(workspace, go, variant="candidate"):
    workspace = Path(workspace).absolute()
    require(workspace.is_dir() and not any(path.is_symlink() for path in (workspace, *workspace.parents)))
    expected, pins = plan(workspace, go, variant), build_pins(variant)
    node = workspace / "node"
    require(node.is_dir() and not node.is_symlink())
    files = set()
    for path in node.rglob("*"):
        info = path.lstat()
        require(not path.is_symlink() and (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)))
        if stat.S_ISREG(info.st_mode):
            require(info.st_nlink == 1)
            files.add(path.relative_to(node).as_posix())
    require(files == set(pins))
    for name, pin in pins.items():
        path = node / name
        raw = P.read_regular(path, 16 << 20)
        require(len(raw) == pin["bytes"] and hashlib.sha256(raw).hexdigest() == pin["sha256"])
        require(sys.platform == "win32" or stat.S_IMODE(path.stat().st_mode) == (int(pin["mode"], 8) & 0o777))
    require(P.read_regular(workspace / INPUT_FILE, 8192) == selected_input())
    recorded = json.loads(P.read_regular(workspace / PREPARED_FILE, 128 << 10), object_pairs_hook=M.pairs, parse_constant=M.constant)
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
    result = (prepare(args.node_source, args.workspace, args.go, args.variant) if args.command == "prepare"
              else (plan if args.command == "plan" else verify)(args.workspace, args.go, args.variant))
    print(json.dumps(result, sort_keys=True, indent=2))

if __name__ == "__main__":
    try:
        main()
    except (ValueError, TypeError, KeyError, OSError):
        print("Repeated Stop preparation refused; state values remain disabled.", file=sys.stderr)
        raise SystemExit(1)
