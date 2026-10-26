#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Prepare the finite experimental core Init/Stop comparison; execute nothing."""
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
spec = importlib.util.spec_from_file_location("core_init_stop_preceding_source", HERE / "prepare_core_repeat_stop.py")
R = importlib.util.module_from_spec(spec)
spec.loader.exec_module(R)
P, M = R.P, R.M
PATCH = "testdata/candidate-core-init-stop-patch.json"
PATCH_BYTES = 8619
PATCH_SHA256 = "0b65fcea113fb6bc0f5704a62e9024747ee39078e8b021beb724518ccf38f65c"
PARENT_TREE = R.CANDIDATE_TREE
CANDIDATE_TREE = "d0d1116e23cae298d4e8f4bd604d5894ec07bebb"
TAG = "candidate_core_init_stop"
TAGS = R.TAGS + "," + TAG
VARIANTS = ("baseline", "candidate")
CASES = ("incomplete-Stop", "overlapping-Init-Stop")
PREPARED = "prepared-core-init-stop.json"
EXTRAS = (
    ("core_init_stop_capture.go", "zenon/candidate_core_init_stop_capture.go", 4244,
     "fece16d5e789acfbe3c52bcd30080e1a27e8d67013528eb9765c1fbc71e9ae56"),
    ("core_init_stop_probe.go", "cmd/candidate-core-init-stop/main.go", 1637,
     "5d0eae41d0aa5260407efc192b86b8162e0ddfaa64bae861a87f6cf24b466ba9"),
)


def require(value):
    if not value:
        raise ValueError("Core Init/Stop preparation refused")


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()


def pinned(name, size, digest):
    raw = P.read_regular(HERE / name, size)
    require(len(raw) == size and hashlib.sha256(raw).hexdigest() == digest)
    return raw


def patch():
    raw = pinned(PATCH, PATCH_BYTES, PATCH_SHA256)
    value = json.loads(raw, object_pairs_hook=M.pairs, parse_constant=M.constant)
    require(type(value) is dict and set(value) == {
        "kind", "file", "node_revision", "parent_tree", "candidate_tree", "before", "after",
        "before_sha256", "after_sha256", "before_git_blob", "after_git_blob", "source_only_experimental"})
    M.exact({key: value[key] for key in ("kind", "file", "node_revision", "parent_tree", "candidate_tree", "source_only_experimental")}, {
        "kind": "experimental-core-Init-stop-admission", "file": "zenon/zenon.go",
        "node_revision": P.REVISION, "parent_tree": PARENT_TREE,
        "candidate_tree": CANDIDATE_TREE, "source_only_experimental": True})
    for name in ("before", "after"):
        require(type(value[name]) is str)
        payload = value[name].encode()
        require(hashlib.sha256(payload).hexdigest() == value[name + "_sha256"])
        require(P.UTIL.git_hash("blob", payload) == value[name + "_git_blob"])
    needle = b"func (z *zenon) Init() error {\n"
    before, after = value["before"].encode(), value["after"].encode()
    guard = b"\tz.stopMu.Lock()\n\tdefer z.stopMu.Unlock()\n\tif z.stopStarted && !z.stopComplete {\n\t\treturn ErrStopIncomplete\n\t}\n\n"
    require(before.count(needle) == 1 and before.replace(needle, needle + guard, 1) == after)
    return value


def selection(variant="candidate"):
    require(type(variant) is str and variant in VARIANTS)
    manifest, modified, pins = R.selection("candidate")
    change = patch()
    require(modified["zenon/zenon.go"] == change["before"].encode())
    if variant == "candidate":
        raw = change["after"].encode()
        modified["zenon/zenon.go"] = raw
        pins["zenon/zenon.go"] = {
            "mode": "100644", "bytes": len(raw), "sha256": change["after_sha256"],
            "git_blob": change["after_git_blob"]}
    require(len(pins) == 471 and P.UTIL.reconstruct_tree(pins) ==
            (PARENT_TREE if variant == "baseline" else CANDIDATE_TREE))
    return manifest, modified, pins


def extra_sources():
    values = R.BASE.extra_sources()
    name, target, size, digest = R.BASE.QUIET_EXTRA
    values[target] = R.BASE.pinned(name, size, digest)
    for name, target, size, digest in R.EXTRAS:
        values[target] = R.pinned(name, size, digest)
    values.update({target: pinned(name, size, digest) for name, target, size, digest in EXTRAS})
    return values


def build_pins(variant="candidate"):
    _, _, runtime = selection(variant)
    pins = R.build_pins("candidate")
    pins["zenon/zenon.go"] = runtime["zenon/zenon.go"]
    for name, target, size, digest in EXTRAS:
        raw = pinned(name, size, digest)
        require(target not in pins)
        pins[target] = {"mode": "100644", "bytes": len(raw), "sha256": digest,
                        "git_blob": P.UTIL.git_hash("blob", raw)}
    require(len(pins) == 484)
    return pins


def plan(workspace, go, variant="candidate"):
    require(type(go) is str and bool(go) and "\x00" not in go)
    workspace = Path(workspace).absolute()
    pins = build_pins(variant)
    build = [go, "build", "-mod=readonly", "-p=2", "-trimpath", "-buildvcs=false",
             "-tags", TAGS, "-o", str(workspace / "core-init-stop"), "./cmd/candidate-core-init-stop"]
    return {
        "kind": "prepared-experimental-core-Init-Stop", "variant": variant,
        "node_revision": P.REVISION, "original_node_tree": P.TREE,
        "parent_runtime_tree": PARENT_TREE,
        "runtime_tree": PARENT_TREE if variant == "baseline" else CANDIDATE_TREE,
        "build_tree": P.UTIL.reconstruct_tree(pins), "source_blobs": len(pins),
        "patch": {"bytes": PATCH_BYTES, "sha256": PATCH_SHA256},
        "extras": {name: {"bytes": size, "sha256": digest} for name, _, size, digest in EXTRAS},
        "working_directory": str(workspace / "node"), "build_argv": build,
        "run_argv_templates": [[str(workspace / "core-init-stop"), "--case", mode,
                                "--root", "NEW_OWNED_EMPTY_CASE_" + str(index)]
                               for index, mode in enumerate(CASES)],
        "focused_native_argv": [go, "test", "-mod=readonly", "-count=1", "-json", "-p=2",
                                "-trimpath", "-buildvcs=false", "-tags", TAGS,
                                "-run", "^(" + "|".join(R.new_roots()) + ")$", "./zenon"],
        "minimum_free_floor_bytes": 10 << 30, "expected_allocation_bytes": 2 << 30,
        "suggested_task_quota_bytes": 4 << 30, "build_timeout_seconds": 300,
        "case_timeout_seconds": 120, "within_case_retries": 0,
        "new_dependency_transports_permitted": False, "reference_backend_executed": False,
        "controlled_protocol_close_selected": True, "controlled_Init_scheduling_selected": True,
        "core_Start_selected": False, "full_node_or_network_execution_selected": False,
        "accepted_header_binding": False, "production_state_value_accepted": False,
        "consumer_result": "REFUSED"}


def prepare(node_source, workspace, go, variant="candidate"):
    workspace = P.private_destination(workspace)
    node_source = Path(node_source).absolute()
    require(node_source.is_dir() and not node_source.is_symlink())
    require(workspace != node_source and node_source not in workspace.parents and workspace not in node_source.parents)
    expected = plan(workspace, go, variant)
    manifest, modified, _ = selection(variant)
    original = {}
    for name, pin in manifest["files"].items():
        raw = P.read_regular(node_source / name, 16 << 20)
        require(len(raw) == pin["bytes"] and hashlib.sha256(raw).hexdigest() == pin["sha256"])
        original[name] = raw
    payloads = dict(original, **modified)
    payloads.update(extra_sources())
    pins = build_pins(variant)
    require(set(payloads) == set(pins))
    workspace.mkdir(mode=0o700)
    node = workspace / "node"
    node.mkdir(mode=0o700)
    for name, pin in pins.items():
        raw = payloads[name]
        require(len(raw) == pin["bytes"] and hashlib.sha256(raw).hexdigest() == pin["sha256"])
        target = node / name
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with target.open("xb") as stream:
            stream.write(raw)
        target.chmod(int(pin["mode"], 8) & 0o777)
    P.UTIL.seal(workspace / PREPARED, encoded(expected))
    require(verify(workspace, go, variant) == expected)
    return expected


def verify(workspace, go, variant="candidate"):
    workspace = Path(workspace).absolute()
    require(workspace.is_dir() and not any(p.is_symlink() for p in (workspace, *workspace.parents)))
    require({p.name for p in workspace.iterdir()} == {"node", PREPARED})
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
        raw = P.read_regular(node / name, 16 << 20)
        require(len(raw) == pin["bytes"] and hashlib.sha256(raw).hexdigest() == pin["sha256"])
        require(sys.platform == "win32" or stat.S_IMODE((node / name).stat().st_mode) == (int(pin["mode"], 8) & 0o777))
    recorded = json.loads(P.read_regular(workspace / PREPARED, 128 << 10),
                          object_pairs_hook=M.pairs, parse_constant=M.constant)
    M.exact(recorded, expected)
    return expected


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("plan", "prepare", "verify"):
        child = sub.add_parser(name)
        child.add_argument("--workspace", required=True)
        child.add_argument("--go", required=True)
        child.add_argument("--variant", choices=VARIANTS, default="candidate")
        if name == "prepare":
            child.add_argument("--node-source", required=True)
    args = parser.parse_args(argv)
    result = (prepare(args.node_source, args.workspace, args.go, args.variant) if args.command == "prepare"
              else (plan if args.command == "plan" else verify)(args.workspace, args.go, args.variant))
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, TypeError, KeyError, OSError):
        print("Experimental core Init/Stop source refused; state values remain disabled.", file=sys.stderr)
        raise SystemExit(1)
