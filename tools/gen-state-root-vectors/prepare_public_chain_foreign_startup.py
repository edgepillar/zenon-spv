#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Prepare a fresh ordinary public-Chain foreign-startup experiment.

Keep the existing experimental runtime unchanged. Only add a tagged command
entrypoint; the caller owns acquisition, dependency checks and bounded execution.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import stat
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("foreign_startup_terminal_parent", HERE / "prepare_public_chain_lifecycle_successor.py")
C = importlib.util.module_from_spec(spec)
spec.loader.exec_module(C)
P = C.P
VARIANT = "public-chain-terminal"
PROBE = "public_chain_foreign_startup_probe.go"
PROBE_SHA256 = "fe68017e2386db2565c4b1724cc21f0045c83434b46bbe4d3bd20c75d042d729"
PROBE_BYTES = 9182
TAG = "candidate_public_chain_foreign_startup"
ENTRYPOINT = "cmd/candidate-public-chain-foreign-startup/main.go"
CASES = (
    "canonical-source-genesis-clean-reopen",
    "foreign-same-height-frontier-identity",
    "foreign-ahead-frontier-without-canonical-retained-version",
    "canonical-retained-genesis-under-foreign-ahead-frontier",
)


def probe_bytes():
    raw = P.read_regular(HERE / PROBE, 128 << 10)
    P.require(len(raw) == PROBE_BYTES and P.sha(raw) == PROBE_SHA256)
    P.require(raw.startswith(("//go:build " + TAG + "\n").encode()))
    return raw


def selection():
    manifest, modified, pins = C.selection(VARIANT)
    P.require(P.UTIL.reconstruct_tree(pins) == C.MODIFIED_TREE)
    return manifest, modified, pins


def plan(workspace, go):
    P.require(type(go) is str and bool(go) and "\x00" not in go)
    workspace = Path(workspace).absolute()
    manifest, _, pins = selection()
    probe = probe_bytes()
    build_pins = dict(pins)
    build_pins[ENTRYPOINT] = {"mode": "100644", "bytes": len(probe), "sha256": P.sha(probe),
                             "git_blob": P.UTIL.git_hash("blob", probe)}
    binary = workspace / "public-chain-foreign-startup"
    return {
        "format_version": 1, "kind": "prepared-public-chain-foreign-identity-startup",
        "node_revision": P.REVISION, "original_tree": P.TREE, "source_blobs": 467,
        "source_manifest_sha256": P.SOURCE_SHA256, "runtime_tree": C.MODIFIED_TREE,
        "build_tree": P.UTIL.reconstruct_tree(build_pins), "runtime_changed": False,
        "probe": {"sha256": PROBE_SHA256, "bytes": PROBE_BYTES}, "cases": list(CASES),
        "module_sha256": manifest["files"]["go.mod"]["sha256"],
        "sum_sha256": manifest["files"]["go.sum"]["sha256"],
        "working_directory": str(workspace / "node"), "binary": str(binary),
        "build_argv": [go, "build", "-mod=readonly", "-trimpath", "-buildvcs=false", "-tags", TAG,
                       "-o", str(binary), "./cmd/candidate-public-chain-foreign-startup"],
        "run_argv_template": [str(binary), "--case", "ONE_SELECTED_CASE", "--root", "NEW_EMPTY_OWNED_CASE_ROOT"],
        "build_timeout_seconds": 240, "case_timeout_seconds": 90, "stdout_limit_bytes": 4 << 20,
        "expected_allocation_bytes": 2 << 30, "task_quota_bytes": 3 << 30,
        "minimum_free_floor_bytes": 10 << 30, "ordinary_build": True,
        "reference_backend_executed": False, "test_overlays_or_scheduler_hooks": False,
        "source_acquisition_performed": False, "existing_database_adopted": False,
        "full_node_service_network_or_consensus": False, "node_client_profile_agreed": False,
        "accepted_header_binding": False, "runtime_state_value_acceptance": False,
        "production_qualified": False, "consumer_result": "REFUSED",
    }


def prepare(node_source, workspace, go):
    expected = plan(workspace, go)
    workspace = P.private_destination(workspace)
    node_source = Path(node_source).absolute()
    P.require(not any(p.is_symlink() for p in (node_source, *node_source.parents)))
    manifest, modified, _ = selection()
    original = P.UTIL.snapshot_source(node_source, manifest["files"])
    workspace.mkdir(mode=0o700)
    node = workspace / "node"
    for name, pin in manifest["files"].items():
        path = node / name
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as stream:
            stream.write(modified.get(name, original[name]))
        path.chmod(int(pin["mode"], 8) & 0o777)
    entrypoint = node / ENTRYPOINT
    entrypoint.parent.mkdir(parents=True, exist_ok=True)
    with entrypoint.open("xb") as stream:
        stream.write(probe_bytes())
    entrypoint.chmod(0o644)
    P.UTIL.seal(workspace / "public-chain-foreign-startup-prepared.json", P.UTIL.encoded(expected))
    P.exact(verify(workspace, go), expected)
    return expected


def verify(workspace, go):
    workspace = Path(workspace).absolute()
    P.require(workspace.is_dir() and not any(p.is_symlink() for p in (workspace, *workspace.parents)))
    _, _, pins = selection()
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
    P.require(files == set(pins) | {ENTRYPOINT})
    for name, pin in pins.items():
        raw = P.read_regular(node / name, 16 << 20)
        P.require(len(raw) == pin["bytes"] and P.sha(raw) == pin["sha256"])
        P.require(stat.S_IMODE((node / name).stat().st_mode) == (int(pin["mode"], 8) & 0o777) or sys.platform == "win32")
    P.require(P.read_regular(node / ENTRYPOINT, 128 << 10) == probe_bytes())
    P.require(stat.S_IMODE((node / ENTRYPOINT).stat().st_mode) == 0o644 or sys.platform == "win32")
    recorded = json.loads(P.read_regular(workspace / "public-chain-foreign-startup-prepared.json", 128 << 10), object_pairs_hook=P.pairs)
    P.exact(recorded, expected)
    return expected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node-source", type=Path, required=True)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--go", required=True)
    args = parser.parse_args()
    print(json.dumps(prepare(args.node_source, args.workspace, args.go), sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, IndexError):
        print("Public Chain foreign-startup preparation refused; preserve owned inputs.", file=sys.stderr)
        sys.exit(1)
