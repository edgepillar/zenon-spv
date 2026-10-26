#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Prepare two real-manager failed-Init cleanup observations; execute nothing."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import stat
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
PARENT_FILE = HERE / "prepare_core_init_stop.py"
PARENT_SHA256 = "c847e227fa9045d761222aba4b643a56e8cebf8edae2ca49c3c424ea6f723104"
if hashlib.sha256(PARENT_FILE.read_bytes()).hexdigest() != PARENT_SHA256:
    raise ValueError("Selected parent source changed")
spec = importlib.util.spec_from_file_location("core_init_failure_parent_source", PARENT_FILE)
K = importlib.util.module_from_spec(spec)
spec.loader.exec_module(K)
P, M = K.P, K.M

CASES = ("ledger-closed-before-Init", "state-tree-path-file")
TAG = "candidate_core_init_failure"
TAGS = K.TAGS + "," + TAG
PREPARED = "prepared-core-init-failure.json"
EXTRAS = (
    ("core_init_failure_chain.go", "chain/candidate_core_init_failure.go", 724,
     "8b7b74d0b3528e0249c2ecf9247a0614533f29aca520d0e2d1a523608aead4d8"),
    ("core_init_failure_capture.go", "zenon/candidate_core_init_failure_capture.go", 8508,
     "ff18bc51a71278e279def5c7035d9239aaecb000b8228b526e75b6721587d870"),
    ("core_init_failure_probe.go", "cmd/candidate-core-init-failure/main.go", 1817,
     "b689e73371f2a428adf6793bc17e6e5eb3d69ce190f960d9262d3e5d9659be28"),
)


def require(value):
    if not value:
        raise ValueError("Core failed-Init source preparation refused")


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()


def pinned(name, size, digest):
    raw = P.read_regular(HERE / name, size)
    require(len(raw) == size and hashlib.sha256(raw).hexdigest() == digest)
    return raw


def build_pins():
    pins = K.build_pins("candidate")
    for name, target, size, digest in EXTRAS:
        raw = pinned(name, size, digest)
        require(target not in pins)
        pins[target] = {"mode": "100644", "bytes": size, "sha256": digest,
                        "git_blob": P.UTIL.git_hash("blob", raw)}
    require(len(pins) == 487)
    return pins


def plan(workspace, go):
    require(type(go) is str and bool(go) and "\x00" not in go)
    workspace = Path(workspace).absolute()
    pins = build_pins()
    executable = workspace / "core-init-failure"
    return {
        "kind": "prepared-experimental-core-failed-Init-cleanup",
        "node_revision": P.REVISION, "original_node_tree": P.TREE,
        "runtime_tree": K.CANDIDATE_TREE,
        "build_tree": P.UTIL.reconstruct_tree(pins), "source_blobs": len(pins),
        "parent_preparer_sha256": PARENT_SHA256,
        "extras": {name: {"bytes": size, "sha256": digest} for name, _, size, digest in EXTRAS},
        "working_directory": str(workspace / "node"),
        "build_argv": [go, "build", "-mod=readonly", "-p=2", "-trimpath", "-buildvcs=false",
                       "-tags", TAGS, "-o", str(executable), "./cmd/candidate-core-init-failure"],
        "run_argv_templates": [[str(executable), "--case", mode, "--root",
                                "NEW_OWNED_EMPTY_CASE_" + str(index)]
                               for index, mode in enumerate(CASES)],
        "minimum_free_floor_bytes": 10 << 30, "expected_allocation_bytes": 2 << 30,
        "suggested_task_quota_bytes": 4 << 30,
        "build_timeout_seconds": 300, "case_timeout_seconds": 120,
        "stdout_limit_bytes": 64 << 10, "within_case_retries": 0,
        "new_dependency_transports_permitted": False,
        "additional_runtime_patch_selected": False, "reference_backend_executed": False,
        "recorded_fixture_consulted": False,
        "fresh_process_per_case_required": True,
        "selected_manager_faults": list(CASES),
        "core_Start_selected": False, "full_node_or_network_execution_selected": False,
        "accepted_header_binding": False, "production_state_value_accepted": False,
        "consumer_result": "REFUSED",
    }


def prepare(node_source, workspace, go):
    workspace = P.private_destination(workspace)
    node_source = Path(node_source).absolute()
    require(node_source.is_dir() and not node_source.is_symlink())
    require(workspace != node_source and node_source not in workspace.parents and workspace not in node_source.parents)
    expected = plan(workspace, go)
    manifest, modified, _ = K.selection("candidate")
    payloads = {}
    for name, pin in manifest["files"].items():
        raw = P.read_regular(node_source / name, 16 << 20)
        require(len(raw) == pin["bytes"] and hashlib.sha256(raw).hexdigest() == pin["sha256"])
        payloads[name] = raw
    payloads.update(modified)
    payloads.update(K.extra_sources())
    for name, target, size, digest in EXTRAS:
        payloads[target] = pinned(name, size, digest)
    pins = build_pins()
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
    require(verify(workspace, go) == expected)
    return expected


def verify(workspace, go):
    workspace = Path(workspace).absolute()
    require(workspace.is_dir() and not any(path.is_symlink() for path in (workspace, *workspace.parents)))
    require({path.name for path in workspace.iterdir()} == {"node", PREPARED})
    expected, pins = plan(workspace, go), build_pins()
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
    observed = json.loads(P.read_regular(workspace / PREPARED, 128 << 10),
                          object_pairs_hook=M.pairs, parse_constant=M.constant)
    M.exact(observed, expected)
    return expected


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("plan", "prepare", "verify"):
        child = sub.add_parser(name)
        child.add_argument("--workspace", required=True)
        child.add_argument("--go", required=True)
        if name == "prepare":
            child.add_argument("--node-source", required=True)
    args = parser.parse_args(argv)
    result = (prepare(args.node_source, args.workspace, args.go) if args.command == "prepare"
              else (plan if args.command == "plan" else verify)(args.workspace, args.go))
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, TypeError, KeyError, OSError):
        print("Experimental failed-Init source refused; state values remain disabled.", file=sys.stderr)
        raise SystemExit(1)
