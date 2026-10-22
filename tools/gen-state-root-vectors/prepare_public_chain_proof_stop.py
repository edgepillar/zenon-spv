#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Stage a finite public Chain read/Stop component probe without executing it."""
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

W = load("read_Stop_parent_workload", "prepare_public_chain_proof_workload.py")
S = load("read_Stop_contract_model", "public_chain_proof_stop_model.py")
C, M, P = W.C, W.M, W.P
PROBE = "public_chain_proof_stop.go"
PROBE_BYTES = 11396
PROBE_SHA256 = "89e6b0cfa6c9507a79dea4e7b4faf0da6c257f95f3d5162fcd29c44c21082da1"
PROBE_TARGET = "cmd/candidate-public-chain-proof-stop/main.go"
TAG = "candidate_public_chain_proof_stop"
FIXTURES = {
    "selection": (18558, "800c9770437a056199403a2602325c7e7a579ff8aa638d3848f06c4af490720a"),
    "contract": (44772, "e211b1f8b7679b77480aeb31e390d9c5c39ebc1a57ae5b03c216a93bc6000688"),
}
PREPARED = "prepared-public-chain-proof-stop.json"

def require(value):
    if not value:
        raise ValueError("Public Chain read/Stop preparation refused")

def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()

def fixtures():
    values = {}
    for label, (size, digest) in FIXTURES.items():
        raw = P.read_regular(HERE / "testdata" / ("public-chain-proof-stop-" + label + ".json"), 1 << 20)
        require(len(raw) == size and hashlib.sha256(raw).hexdigest() == digest)
        value = json.loads(raw, object_pairs_hook=M.H.B.object_pairs)
        require(encoded(value) == raw)
        values[label] = value
    wire, contract = values["selection"], values["contract"]
    old = {key: json.loads(raw) for key, raw in W.fixtures().items()}
    require(set(wire) == {"schema", "node_revision", "runtime_tree", "genesis_patch", "genesis_identifier", "keys", "workers", "warmup_pairs", "concurrent_request_pairs", "post_Stop_request_pairs", "stop_trigger", "stop_after_completed_pairs", "accepted_header_binding", "production_state_value_accepted", "consumer_result"})
    require(wire["schema"] == "source-genesis-public-Chain-proof-Stop-selection-v1")
    require(wire["node_revision"] == M.REVISION and wire["runtime_tree"] == M.RUNTIME_TREE)
    require(wire["genesis_patch"] == M.H.RAW and wire["genesis_identifier"] == M.GENESIS)
    require(wire["keys"] == old["selection"]["keys"])
    for name, expected in (("workers", 16), ("warmup_pairs", 128), ("concurrent_request_pairs", 2048), ("post_Stop_request_pairs", 1), ("stop_after_completed_pairs", 32)):
        require(type(wire[name]) is int and wire[name] == expected)
    require(wire["stop_trigger"] == "after 32 completed concurrent query pairs; successful caller intervals must overlap Stop")
    require(wire["consumer_result"] == "REFUSED" and wire["accepted_header_binding"] is False and wire["production_state_value_accepted"] is False)
    require(S.CONTRACT_SHA256 == FIXTURES["contract"][1])
    require(contract["reference_node_revision"] == M.REVISION and contract["reference_runtime_tree"] == M.RUNTIME_TREE)
    require(contract["successful_root"] == M.H.INITIAL_ROOT)
    require(contract["blinded_wire_selection"]["sha256"] == FIXTURES["selection"][1] and contract["blinded_wire_selection"]["bytes"] == FIXTURES["selection"][0])
    require(contract["successful_proof_rows"] == [{name: row[name] for name in ("raw_key", "row_sha256", "proof_sha256", "present_in_projection")} for row in old["expectations"]["expected_rows"]])
    require(contract["minimum_completed_concurrent_pairs_before_Stop"] == 32 and contract["minimum_successful_caller_intervals_overlapping_Stop"] == 1)
    require(contract["profiles"] == [{"build": "ordinary", "race_detector": False, "selected_process_attempts": 1}, {"build": "race", "race_detector": True, "selected_process_attempts": 1}])
    require(contract["consumer_result"] == "REFUSED" and contract["accepted_header_binding"] is False and contract["production_state_value_accepted"] is False)
    return {label: encoded(value) for label, value in values.items()}

def probe():
    raw = P.read_regular(HERE / PROBE, 64 << 10)
    require(len(raw) == PROBE_BYTES and hashlib.sha256(raw).hexdigest() == PROBE_SHA256)
    return raw

def build_pins():
    _, _, pins = C.selection("candidate")
    require(len(pins) == 471 and P.UTIL.reconstruct_tree(pins) == M.RUNTIME_TREE)
    require(PROBE_TARGET not in pins)
    raw = probe()
    pins[PROBE_TARGET] = {"mode": "100644", "bytes": len(raw), "sha256": PROBE_SHA256, "git_blob": P.UTIL.git_hash("blob", raw)}
    require(len(pins) == 472)
    return pins

def plan(workspace, go):
    require(type(go) is str and bool(go) and "\x00" not in go)
    workspace = Path(workspace).absolute()
    pins = build_pins()
    fixtures()
    profiles = []
    for name, race in (("ordinary", False), ("race", True)):
        build = [go, "build"] + (["-race"] if race else []) + ["-mod=readonly", "-p=2", "-trimpath", "-buildvcs=false", "-tags", TAG, "-o", str(workspace / ("proof-stop-" + name)), "./cmd/candidate-public-chain-proof-stop"]
        profiles.append({"profile": name, "race_detector": race, "selected_process_attempts": 1,
                         "build_argv": build,
                         "run_argv_template": [str(workspace / ("proof-stop-" + name)), "--root", "NEW_OWNED_CASE_" + name.upper(), "--selection", str(workspace / "selection.json"), "--selection-sha256", FIXTURES["selection"][1]]})
    return {"kind": "prepared-public-Chain-read-Stop-component-probe", "node_revision": M.REVISION,
            "original_node_tree": C.P.TREE, "runtime_tree": M.RUNTIME_TREE,
            "build_tree": P.UTIL.reconstruct_tree(pins), "source_blobs": len(pins),
            "probe": {"sha256": PROBE_SHA256, "bytes": PROBE_BYTES},
            "fixtures": {label: {"bytes": size, "sha256": digest} for label, (size, digest) in FIXTURES.items()},
            "working_directory": str(workspace / "node"), "profiles": profiles,
            "vet_argv": [go, "vet", "-mod=readonly", "-tags", TAG, "./cmd/candidate-public-chain-proof-stop"],
            "minimum_free_floor_bytes": 10 << 30, "expected_allocation_bytes": 1536 << 20,
            "suggested_task_quota_bytes": 4 << 30, "safety_reserve_bytes": 1 << 30,
            "selected_reference_builds": 2, "selected_reference_processes": 2, "automatic_component_retries": 0,
            "warmup_pairs_per_process": 128, "concurrent_pairs_per_process": 2048,
            "individual_Root_and_GetProof_calls_per_process": 4354,
            "stop_after_completed_concurrent_pairs": 32, "minimum_successful_caller_interval_overlap": 1,
            "missing_overlap_outcome": "INCONCLUSIVE", "internal_database_interleaving_proven": False,
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
    result = prepare(args.node_source, args.workspace, args.go) if args.command == "prepare" else (plan if args.command == "plan" else verify)(args.workspace, args.go)
    print(json.dumps(result, sort_keys=True))

if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, IndexError, AssertionError):
        print("Public Chain read/Stop preparation refused; preserve owned diagnostics.", file=sys.stderr)
        sys.exit(1)

