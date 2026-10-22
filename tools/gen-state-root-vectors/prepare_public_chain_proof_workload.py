#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Stage an ordinary read-only Chain proof workload; never execute it.

Original source, independent byte expectations and generated namespaces remain
separate. Existing destinations, databases and overlapping source trees refuse.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import stat
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, HERE / file)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


C = load("proof_workload_integrated_runtime", "prepare_core_stop_errors.py")
M = load("proof_workload_independent_contract", "public_chain_proof_workload_model.py")
P = C.P
PROBE = "public_chain_proof_workload.go"
PROBE_BYTES = 11651
PROBE_SHA256 = "941d7e1a6fbb966e8af15558c55bccb72ac36d3394e7284dae8a750141b23584"
PROBE_TARGET = "cmd/candidate-public-chain-proof-workload/main.go"
TAG = "candidate_public_chain_proof_workload"
FIXTURES = {
    "selection": (14935, "e7d0c92ad88490b1167806b4b70cef88792bf974cec0725257c1b0f24979c006"),
    "expectations": (245661, "527c6ec3257f8e883204306055d7b1789ee6902537d38303e06d6394c7f94946"),
}
PREPARED = "prepared-public-chain-proof-workload.json"


def require(value):
    if not value:
        raise ValueError("Public Chain proof workload preparation refused")


def fixtures():
    values = {}
    for label, (size, digest) in FIXTURES.items():
        raw = P.read_regular(HERE / "testdata" / ("public-chain-proof-workload-" + label + ".json"), 1 << 20)
        require(len(raw) == size and hashlib.sha256(raw).hexdigest() == digest)
        value = json.loads(raw, object_pairs_hook=M.H.B.object_pairs)
        require(M.encoded(value) == raw)
        values[label] = value
    M.check_expected(values["selection"], values["expectations"])
    return {label: M.encoded(value) for label, value in values.items()}


def probe():
    raw = P.read_regular(HERE / PROBE, 64 << 10)
    require(len(raw) == PROBE_BYTES and hashlib.sha256(raw).hexdigest() == PROBE_SHA256)
    return raw


def build_pins():
    _, _, pins = C.selection("candidate")
    require(len(pins) == 471 and P.UTIL.reconstruct_tree(pins) == M.RUNTIME_TREE)
    require(PROBE_TARGET not in pins)
    raw = probe()
    pins[PROBE_TARGET] = {"mode": "100644", "bytes": len(raw), "sha256": PROBE_SHA256,
                          "git_blob": P.UTIL.git_hash("blob", raw)}
    require(len(pins) == 472)
    return pins


def plan(workspace, go):
    require(type(go) is str and bool(go) and "\x00" not in go)
    workspace = Path(workspace).absolute()
    pins = build_pins()
    fixtures()
    cases = [{"workers": n, "reopen": False, "root_role": "fresh-" + str(n)} for n in M.WORKERS]
    cases.append({"workers": 4, "reopen": True, "root_role": "fresh-16-closed"})
    return {"kind": "prepared-public-Chain-proof-workload", "node_revision": M.REVISION,
            "original_node_tree": C.P.TREE, "runtime_tree": M.RUNTIME_TREE,
            "build_tree": P.UTIL.reconstruct_tree(pins), "source_blobs": len(pins),
            "probe": {"sha256": PROBE_SHA256, "bytes": PROBE_BYTES},
            "fixtures": {label: {"bytes": size, "sha256": digest} for label, (size, digest) in FIXTURES.items()},
            "minimum_free_floor_bytes": 10 << 30, "expected_allocation_bytes": 2 << 30,
            "suggested_task_quota_bytes": 3 << 30, "requests_per_process": M.REQUESTS,
            "independent_selected_keys": 128, "cases": cases,
            "build_argv": [go, "build", "-mod=readonly", "-p=2", "-trimpath", "-buildvcs=false",
                           "-tags", TAG, "-o", str(workspace / "proof-workload"), "./cmd/candidate-public-chain-proof-workload"],
            "vet_argv": [go, "vet", "-mod=readonly", "-tags", TAG, "./cmd/candidate-public-chain-proof-workload"],
            "working_directory": str(workspace / "node"),
            "run_argv_templates": [[str(workspace / "proof-workload"), "--root", "OWNED_CASE_WORKERS_" + str(16 if case["reopen"] else case["workers"]),
                                    "--selection", str(workspace / "selection.json"), "--selection-sha256", FIXTURES["selection"][1],
                                    "--workers", str(case["workers"])] + (["--reopen"] if case["reopen"] else []) for case in cases],
            "ordinary_builds": 1, "ordinary_processes": 4, "within_case_retries": 0,
            "source_copy_method": "explicit-independent-quota-accounted-files-from-verified-bytes",
            "reference_backend_executed": False, "new_dependency_transports_permitted": False,
            "public_Chain_Init_selected": True, "Chain_Start_selected": False,
            "Node_or_wallet_or_network_execution_selected": False,
            "controlled_ledger_or_cache_adapters_selected": False,
            "accepted_header_binding": False, "production_state_value_accepted": False,
            "full_node_or_representative_VM_workload_qualified": False, "consumer_result": "REFUSED"}


def prepare(node_source, workspace, go):
    workspace = P.private_destination(workspace)
    node_source = Path(node_source).absolute()
    require(workspace != node_source and node_source not in workspace.parents and workspace not in node_source.parents)
    require(node_source.is_dir())
    expected = plan(workspace, go)
    manifest, modified, pins = C.selection("candidate")
    original = M.snapshot_source(node_source, manifest["files"], P)
    node = workspace / "node"
    workspace.mkdir(mode=0o700)
    node.mkdir(mode=0o700)
    for name, pin in pins.items():
        raw = modified[name] if name in modified else original[name]
        require(len(raw) == pin["bytes"] and hashlib.sha256(raw).hexdigest() == pin["sha256"])
        target = node / name
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with target.open("xb") as stream:
            stream.write(raw)
        target.chmod(int(pin["mode"], 8) & 0o777)
    target = node / PROBE_TARGET
    target.parent.mkdir(mode=0o700, parents=True)
    with target.open("xb") as stream:
        stream.write(probe())
    target.chmod(0o644)
    for label, raw in fixtures().items():
        with (workspace / (label + ".json")).open("xb") as stream:
            stream.write(raw)
    P.UTIL.seal(workspace / PREPARED, P.UTIL.encoded(expected))
    require(verify(workspace, go) == expected)
    return expected


def verify(workspace, go):
    workspace = Path(workspace).absolute()
    require(workspace.is_dir() and not any(p.is_symlink() for p in (workspace, *workspace.parents)))
    expected, pins = plan(workspace, go), build_pins()
    node, actual = workspace / "node", set()
    require(node.is_dir() and not node.is_symlink())
    for path in node.rglob("*"):
        value = path.lstat()
        require(not path.is_symlink() and (stat.S_ISDIR(value.st_mode) or stat.S_ISREG(value.st_mode)))
        if stat.S_ISREG(value.st_mode):
            require(value.st_nlink == 1)
            actual.add(path.relative_to(node).as_posix())
    require(actual == set(pins))
    for name, pin in pins.items():
        path = node / name
        raw = P.read_regular(path, 16 << 20)
        require(len(raw) == pin["bytes"] and hashlib.sha256(raw).hexdigest() == pin["sha256"])
        require(sys.platform == "win32" or stat.S_IMODE(path.stat().st_mode) == (int(pin["mode"], 8) & 0o777))
    for label, raw in fixtures().items():
        require(P.read_regular(workspace / (label + ".json"), 1 << 20) == raw)
    recorded = json.loads(P.read_regular(workspace / PREPARED, 128 << 10), object_pairs_hook=M.H.B.object_pairs)
    require(recorded == expected)
    return expected


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("plan", "prepare", "verify"):
        sub = commands.add_parser(name)
        sub.add_argument("--workspace", required=True)
        sub.add_argument("--go", required=True)
        if name == "prepare":
            sub.add_argument("--node-source", required=True)
    args = parser.parse_args(argv)
    if args.command == "prepare":
        result = prepare(args.node_source, args.workspace, args.go)
    else:
        result = (plan if args.command == "plan" else verify)(args.workspace, args.go)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, IndexError, AssertionError):
        print("Public Chain proof preparation refused; preserve owned diagnostics.", file=sys.stderr)
        sys.exit(1)
