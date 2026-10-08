#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Reproduce fixtures from a complete, pinned node source snapshot, offline.

Source acquisition is separate. This driver never fetches a branch, changes a
repository, starts a node/RPC, signs data or replaces an existing output.
The chain-startup and disk-lifecycle modes use small owned temporary disk trees.
The disk mode ends only its own children at explicit returned-API boundaries.
The reference dependency is a temporary local replacement in this separate
research module; it does not change the SPV runtime dependency graph.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
NODE_REVISION = "56ce2c384966f2f1940967257a0788d3998a5eef"
NODE_TREE = "d5abff528566a561e1a53a46103cb4b15ff63c6c"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def git_hash(kind, raw):
    return hashlib.sha1(kind.encode("ascii") + b" " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()


def reconstruct_tree(pins):
    directories = {"": {}}
    for name, pin in pins.items():
        parts = PurePosixPath(name).parts
        require(parts and "/".join(parts) == name and all(part not in ("", ".", "..", ".git") for part in parts), "unsafe pinned path")
        require(not name.startswith("/") and "\\" not in name and ":" not in name, "unsafe pinned path")
        require(pin["mode"] in ("100644", "100755"), "unsupported pinned mode")
        parent = ""
        for part in parts[:-1]:
            child = parent + "/" + part if parent else part
            directories.setdefault(child, {})
            directories[parent][part] = ("40000", child)
            parent = child
        require(parts[-1] not in directories[parent], "duplicate pinned entry")
        directories[parent][parts[-1]] = (pin["mode"], pin["git_blob"])

    def tree(directory):
        rows = directories[directory]
        result = bytearray()
        for name in sorted(rows, key=lambda name: (name + ("/" if rows[name][0] == "40000" else "")).encode("utf-8")):
            mode, target = rows[name]
            oid = tree(target) if mode == "40000" else target
            result += mode.encode("ascii") + b" " + name.encode("utf-8") + b"\0" + bytes.fromhex(oid)
        return git_hash("tree", bytes(result))

    return tree("")


def source_manifest():
    raw = (HERE / "source-pins.json").read_bytes()
    pins = json.loads(raw)
    require(pins["format_version"] == 1 and pins["revision"] == NODE_REVISION and pins["tree"] == NODE_TREE,
            "wrong selected source pin")
    require(pins["repository"] == "https://github.com/digitalSloth/go-zenon" and len(pins["files"]) == 394,
            "incomplete candidate source pin")
    require(reconstruct_tree(pins["files"]) == NODE_TREE, "pinned Git tree differs")
    return raw, pins


def snapshot_source(root, pins):
    root = Path(root)
    require(root.is_dir() and not root.is_symlink(), "expected complete node source directory")
    inventory = set()
    for directory, subdirectories, files in os.walk(root, followlinks=False):
        directory = Path(directory)
        if directory == root and ".git" in subdirectories:
            subdirectories.remove(".git")
        for name in subdirectories:
            require(not (directory / name).is_symlink(), "source symlink refused")
        for name in files:
            file = directory / name
            relative = file.relative_to(root).as_posix()
            if directory == root and name == ".git":
                continue
            require(file.is_file() and not file.is_symlink(), "source file type refused")
            inventory.add(relative)
    require(inventory == set(pins), "candidate source inventory differs")
    contents = {}
    for name, pin in pins.items():
        with (root / name).open("rb") as stream:
            raw = stream.read(pin["bytes"] + 1)
        require(len(raw) == pin["bytes"] and hashlib.sha256(raw).hexdigest() == pin["sha256"], "candidate source bytes differ")
        require(git_hash("blob", raw) == pin["git_blob"], "candidate Git blob differs")
        contents[name] = raw
    return contents


def seal(path, raw):
    with Path(path).open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    Path(path).chmod(0o400)


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node-source", type=Path, required=True)
    parser.add_argument("--go", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--evidence-directory", type=Path, required=True)
    parser.add_argument("--fixture-kind", choices=("bytes", "fold-filter", "applier", "wire", "rpc-methods", "rpc-dispatcher", "chain-startup", "disk-lifecycle"), default="bytes")
    args = parser.parse_args(argv)
    require(not args.output.exists() and not args.output.is_symlink(), "preserve existing output")
    require(not args.evidence_directory.exists() and not args.evidence_directory.is_symlink(), "preserve existing evidence")
    manifest_raw, manifest = source_manifest()
    original = snapshot_source(args.node_source, manifest["files"])
    args.evidence_directory.mkdir(mode=0o700)
    seal(args.evidence_directory / "source-selection.json", encoded({
        "revision": NODE_REVISION, "tree": NODE_TREE, "matched_blobs": len(original),
        "manifest_sha256": hashlib.sha256(manifest_raw).hexdigest(), "network_acquisition": False}))
    environment = {key: value for key, value in os.environ.items() if not key.startswith("GO")}
    environment.update(GOTOOLCHAIN="local", GOWORK="off", GOFLAGS="", GOENV="off",
                       GOPROXY="off", GOSUMDB="off", CGO_ENABLED="1" if args.fixture_kind in ("wire", "rpc-methods", "rpc-dispatcher", "chain-startup") else "0")
    commands = []

    def execute(label, command, working_directory):
        try:
            result = subprocess.run(command, cwd=working_directory, env=environment,
                                    capture_output=True, timeout=240)
            stdout, stderr, code, completed = result.stdout, result.stderr, result.returncode, True
        except subprocess.TimeoutExpired as error:
            stdout, stderr, code, completed = error.stdout or b"", error.stderr or b"", None, False
        seal(args.evidence_directory / (label + ".stdout"), stdout)
        seal(args.evidence_directory / (label + ".stderr"), stderr)
        record = {"label": label, "completed": completed, "actual_exit": code,
                  "stdout_sha256": hashlib.sha256(stdout).hexdigest(), "stderr_sha256": hashlib.sha256(stderr).hexdigest()}
        commands.append(record)
        seal(args.evidence_directory / (label + ".json"), encoded(record))
        require(completed and code == 0, "reference command failed; keep its private evidence")
        return stdout

    with tempfile.TemporaryDirectory(prefix="candidate-state-root-") as temporary:
        root = Path(temporary)
        candidate, generator = root / "reference-node", root / "generator"
        candidate.mkdir()
        generator.mkdir()
        for name, raw in original.items():
            file = candidate / name
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_bytes(raw)
            file.chmod(0o755 if manifest["files"][name]["mode"] == "100755" else 0o644)
        for name in ("main.go", "go.mod", "go.sum"):
            (generator / name).write_bytes((HERE / name).read_bytes())
        if args.fixture_kind == "wire":
            (generator / "wire.go").write_bytes((HERE / "wire.go").read_bytes())
        if args.fixture_kind in ("rpc-methods", "rpc-dispatcher"):
            (generator / "rpc_methods.go").write_bytes((HERE / "rpc_methods.go").read_bytes())
        if args.fixture_kind == "rpc-dispatcher":
            (generator / "rpc_dispatcher.go").write_bytes((HERE / "rpc_dispatcher.go").read_bytes())
        if args.fixture_kind == "chain-startup":
            (generator / "chain_startup.go").write_bytes((HERE / "chain_startup.go").read_bytes())
        if args.fixture_kind == "disk-lifecycle":
            (generator / "disk_lifecycle.go").write_bytes((HERE / "disk_lifecycle.go").read_bytes())
        with (generator / "go.mod").open("ab") as stream:
            stream.write(b"\nreplace github.com/zenon-network/go-zenon => ../reference-node\n")
        version = execute("go-version", [args.go, "version"], generator).decode("ascii").strip()
        require(version.startswith("go version go1.25."), "select a Go 1.25 toolchain")
        executable = generator / ("reference-generator.exe" if os.name == "nt" else "reference-generator")
        build = [args.go, "build", "-mod=readonly", "-trimpath"]
        if args.fixture_kind == "wire":
            build += ["-tags", "candidate_wire"]
        if args.fixture_kind == "rpc-methods":
            build += ["-tags", "candidate_rpc"]
        if args.fixture_kind == "rpc-dispatcher":
            build += ["-tags", "candidate_dispatcher"]
        if args.fixture_kind == "chain-startup":
            build += ["-tags", "candidate_chain_startup"]
        if args.fixture_kind == "disk-lifecycle":
            build += ["-tags", "candidate_disk_lifecycle"]
        execute("go-build", build + ["-o", str(executable), "."], generator)
        execute("go-buildinfo", [args.go, "version", "-m", str(executable)], generator)
        command = [str(executable), "--verified-node-tree", NODE_TREE]
        if args.fixture_kind != "bytes":
            command += ["--fixture-kind", args.fixture_kind]
        first = execute("generate-first", command, generator)
        second = execute("generate-second", command, generator)
        require(first == second, "reference generation was nondeterministic")
        require(snapshot_source(candidate, manifest["files"]) == original, "copied node source changed during generation")
        require(snapshot_source(args.node_source, manifest["files"]) == original, "selected source changed during generation")
        document = json.loads(first)
        require(document["source"]["revision"] == NODE_REVISION and document["source"]["tree"] == NODE_TREE,
                "generated corpus source pin differs")
        require(document["scope"]["unsigned"] and not document["scope"]["runtime_state_proof_acceptance"], "wrong generated scope")
        expected_kind = {"bytes": "candidate-state-root-byte-research", "fold-filter": "candidate-l1-fold-filter-research",
                         "applier": "candidate-l1-applier-research", "wire": "candidate-state-proof-wire-research",
                         "rpc-methods": "candidate-rpc-method-research",
                         "rpc-dispatcher": "candidate-rpc-dispatcher-research",
                         "chain-startup": "candidate-chain-startup-research",
                         "disk-lifecycle": "candidate-disk-lifecycle-research"}[args.fixture_kind]
        require(document["kind"] == expected_kind, "generated fixture kind differs")
        if args.fixture_kind == "fold-filter":
            require(document["scope"]["l1_fold_filter_api_executed"] and
                    not document["scope"]["l1_staged_applier_executed"] and
                    not document["scope"]["node_database_opened"], "wrong filter execution boundary")
        if args.fixture_kind == "applier":
            require(document["scope"]["l1_staged_applier_executed"] and document["scope"]["node_database_opened"] and
                    document["scope"]["database_storage_in_memory_only"] and document["scope"]["temporary_database_closed"] and
                    not document["scope"]["persisted_disk_lifecycle_executed"], "wrong applier execution boundary")
        if args.fixture_kind == "wire":
            require(document["scope"]["StateProof_serializer_executed"] and document["scope"]["primitive_proof_api_executed"] and
                    not document["scope"]["LedgerApi_method_executed"] and not document["scope"]["rpc_transport_executed"] and
                    not document["scope"]["node_database_opened"] and not document["scope"]["header_authentication_executed"],
                    "wrong wire execution boundary")
        if args.fixture_kind == "rpc-methods":
            require(document["scope"]["LedgerApi_methods_executed"] and document["scope"]["recording_chain_store_stubs"] and
                    not document["scope"]["actual_chain_stateTree_executed"] and not document["scope"]["rpc_dispatcher_executed"] and
                    not document["scope"]["node_database_opened"], "wrong RPC method execution boundary")
        if args.fixture_kind == "rpc-dispatcher":
            require(document["scope"]["LedgerApi_methods_executed"] and document["scope"]["recording_chain_store_stubs"] and
                    document["scope"]["rpc_dispatcher_executed"] and document["scope"]["rpc_parameter_decoder_executed"] and
                    document["scope"]["rpc_http_handler_executed_in_memory"] and document["scope"]["read_only_delegates_only"] and
                    document["scope"]["server_stopped_after_each_case"] and document["scope"]["request_body_closed_after_each_case"] and
                    not document["scope"]["http_listener_started"] and not document["scope"]["live_transport_executed"] and
                    not document["scope"]["actual_chain_stateTree_executed"] and not document["scope"]["node_database_opened"],
                    "wrong offline RPC dispatcher execution boundary")
        if args.fixture_kind == "chain-startup":
            require(document["scope"]["actual_chain_component_Init_executed"] and
                    document["scope"]["actual_chain_stateTree_executed"] and
                    document["scope"]["actual_momentum_store_executed"] and
                    document["scope"]["recording_manager_cache_genesis_inputs"] and
                    document["scope"]["small_temporary_disk_LevelDB"] and
                    document["scope"]["databases_closed_and_removed"] and
                    document["scope"]["controlled_clean_reopen_executed"] and
                    not document["scope"]["chain_Start_executed"] and
                    not document["scope"]["full_node_started"] and
                    not document["scope"]["signing"] and not document["scope"]["transactions"],
                    "wrong chain startup execution boundary")
        if args.fixture_kind == "disk-lifecycle":
            require(document["backend"] == "NodeTree" and document["scope"]["actual_NodeTree_disk_APIs_executed"] and
                    document["scope"]["small_owned_temporary_disk_LevelDB"] and
                    document["scope"]["controlled_process_exit_executed"] and
                    document["scope"]["child_defer_close_marker_checked"] and
                    document["scope"]["controlled_clean_close_control"] and
                    document["scope"]["controlled_clean_reopen_executed"] and
                    document["scope"]["logical_storage_records_measured"] and
                    document["scope"]["owned_databases_removed"] and
                    not document["scope"]["chain_component_Init_executed"] and
                    not document["scope"]["full_node_started"] and not document["scope"]["power_loss_qualified"] and
                    not document["scope"]["production_crash_recovery_qualified"], "wrong disk lifecycle execution boundary")
        seal(args.output, first)
    report = {"node_revision": NODE_REVISION, "node_tree": NODE_TREE, "matched_source_blobs": 394,
              "source_manifest_sha256": hashlib.sha256(manifest_raw).hexdigest(),
              "go_version": version, "deterministic_generations": 2, "corpus_sha256": hashlib.sha256(first).hexdigest(),
              "commands": commands, "signing": False, "node_lifecycle_execution": False,
              "network_execution": False, "runtime_state_proof_acceptance": False,
              "fixture_kind": args.fixture_kind, "l1_fold_filter_api_executed": args.fixture_kind == "fold-filter",
              "l1_staged_applier_executed": args.fixture_kind == "applier", "node_database_opened": args.fixture_kind in ("applier", "chain-startup", "disk-lifecycle"),
              "database_storage_in_memory_only": args.fixture_kind == "applier", "persisted_disk_lifecycle_executed": args.fixture_kind in ("chain-startup", "disk-lifecycle"),
              "persisted_disk_lifecycle_qualified": False,
              "StateProof_serializer_executed": args.fixture_kind in ("wire", "rpc-methods", "rpc-dispatcher"),
              "LedgerApi_method_executed": args.fixture_kind in ("rpc-methods", "rpc-dispatcher"),
              "recording_chain_store_stubs": args.fixture_kind in ("rpc-methods", "rpc-dispatcher"), "actual_chain_stateTree_executed": args.fixture_kind == "chain-startup",
              "actual_chain_component_Init_executed": args.fixture_kind == "chain-startup",
              "controlled_clean_disk_reopen_executed": args.fixture_kind in ("chain-startup", "disk-lifecycle"),
              "small_temporary_disk_LevelDB": args.fixture_kind in ("chain-startup", "disk-lifecycle"),
              "controlled_process_exit_executed": args.fixture_kind == "disk-lifecycle",
              "logical_NodeTree_storage_records_measured": args.fixture_kind == "disk-lifecycle",
              "power_loss_qualified": False, "torn_write_qualified": False,
              "full_node_startup": False, "chain_Start_executed": False, "crash_recovery_qualified": False,
              "rpc_dispatcher_executed": args.fixture_kind == "rpc-dispatcher",
              "rpc_http_handler_executed_in_memory": args.fixture_kind == "rpc-dispatcher", "http_listener_started": False,
              "rpc_transport_executed": False, "header_authentication_executed": False,
              "reference_cgo_enabled": args.fixture_kind in ("wire", "rpc-methods", "rpc-dispatcher", "chain-startup")}
    seal(args.evidence_directory / "completed.json", encoded(report))
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError):
        print("Candidate fixture generation failed. Preserve the existing private evidence and output.", file=sys.stderr)
        sys.exit(1)
