#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Stage the selected experimental raw NodeTree transport component, without execution.

The caller owns acquisition, dependency caches, bounded process supervision and
cleanup. No existing database, chain wrapper or authenticated snapshot is used.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import stat
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("raw_kv_selected_runtime", HERE / "prepare_offline_rebuild_successor.py")
R = importlib.util.module_from_spec(spec)
spec.loader.exec_module(R)
P = R.P
PROBE = "raw_kv_roundtrip_successor_probe_test.go"
TAG = "candidate_raw_kv_roundtrip_successor"
SELECTION_SHA256 = "5052b65d63205d8bbe3fc14a22e72fcead69cce83710d75d2bec2f3701ce3b68"


def require(condition):
    if not condition:
        raise ValueError("Raw KV roundtrip preparation refused")


def selection():
    manifest, modified, state, pins = R.runtime_selection("full-identifier")
    changed = dict(modified)
    changed[R.T.STATE] = state
    require(set(changed) == P.CHANGED and len(pins) == 467)
    require(P.UTIL.reconstruct_tree(pins) == R.MODIFIED_TREE)
    for name, raw in changed.items():
        require(P.sha(raw) == pins[name]["sha256"] and len(raw) == pins[name]["bytes"])
    return manifest, changed, pins


def probe_bytes():
    raw = P.read_regular(HERE / PROBE, 128 << 10)
    require(raw.startswith(("//go:build " + TAG + "\n").encode()))
    require(('const rawKvSelectionSHA = "' + SELECTION_SHA256 + '"').encode() in raw)
    return raw


def plan(workspace, go, pins, probe):
    require(type(go) is str and bool(go) and type(probe) is bytes)
    require(P.UTIL.reconstruct_tree(pins) == R.MODIFIED_TREE)
    manifest = P.source_manifest()
    require(set(pins) == set(manifest["files"]) and len(pins) == 467)
    staged = {name: dict(row) for name, row in pins.items()}
    staged["common/trie/" + PROBE] = {
        "mode": "100644", "sha256": P.sha(probe), "bytes": len(probe),
        "git_blob": P.UTIL.git_hash("blob", probe),
    }
    binary = workspace / "raw-kv-roundtrip-successor.test"
    return {
        "format_version": 1, "kind": "successor-raw-kv-roundtrip-prepared-source",
        "node_revision": P.REVISION, "original_node_tree": P.TREE, "source_blobs": 467,
        "runtime_tree_without_probe": R.MODIFIED_TREE,
        "staged_tree_with_probe": P.UTIL.reconstruct_tree(staged), "staged_blobs": 468,
        "source_manifest_sha256": P.SOURCE_SHA256, "hash_identity_patch_sha256": P.PATCH_SHA256,
        "terminal_patch_sha256": R.T.PATCH_SHA256, "caller_patch_sha256": R.PATCH_SHA256,
        "probe": PROBE, "probe_sha256": P.sha(probe), "selection_sha256": SELECTION_SHA256,
        "module_selection": "complete selected source own go.mod/go.sum; no research-lock substitution",
        "module_sha256": pins["go.mod"]["sha256"], "sum_sha256": pins["go.sum"]["sha256"],
        "working_directory": str(workspace / "node"), "binary": str(binary),
        "build_argv": [go, "test", "-c", "-p=1", "-mod=readonly", "-trimpath", "-buildvcs=false",
                       "-vet=off", "-tags", TAG, "-o", str(binary), "./common/trie"],
        "run_argv": [str(binary), "-test.v", "-test.timeout=180s",
                     "-test.run=^TestCandidateRawKVRoundtripSuccessor$"],
        "upstream_test_sources_unchanged": True, "upstream_tests_selected_for_execution": False,
        "compiler_overlays_added": False, "chain_wrappers_compiled_or_executed": False,
        "required_run_environment": {
            "ZENON_RAW_KV_SELECTION": "SEALED_INPUT_OPERATIONS_AND_IDENTIFIERS_ONLY",
            "ZENON_RAW_KV_SELECTION_SHA256": SELECTION_SHA256,
            "ZENON_RAW_KV_POLICY": "archive OR retain-5",
            "ZENON_RAW_KV_WORKSPACE": "FRESH_ABSENT_OWNED_DATABASE_DIRECTORY",
        },
        "expected_roots_or_proofs_passed_to_node": False, "reference_backend_executed": False,
        "source_acquisition_performed": False, "Go_race_detector_selected": False,
        "authenticated_snapshot_import": False, "accepted_header_binding": False,
        "balance_value_encoding_agreed": False, "representative_resources_qualified": False,
        "consumer_result": "REFUSED", "production_state_value_accepted": False,
    }


def inventory(node):
    require(node.is_dir() and not any(p.is_symlink() for p in (node, *node.parents)))
    files = set()
    root = node.lstat()
    for path in node.rglob("*"):
        info = path.lstat()
        require(not path.is_symlink() and info.st_dev == root.st_dev
                and (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)))
        if stat.S_ISREG(info.st_mode):
            require(info.st_nlink == 1)
            files.add(path.relative_to(node).as_posix())
    return files


def prepare(node_source, workspace, go):
    require(type(go) is str and bool(go))
    workspace = P.private_destination(workspace)
    node_source = Path(node_source).absolute()
    manifest, changed, pins = selection()
    require(inventory(node_source) == set(manifest["files"]))
    original = {name: P.read_regular(node_source / name, 16 << 20) for name in manifest["files"]}
    for name, raw in original.items():
        pin = manifest["files"][name]
        require(len(raw) == pin["bytes"] and P.sha(raw) == pin["sha256"]
                and P.UTIL.git_hash("blob", raw) == pin["git_blob"]
                and stat.S_IMODE((node_source / name).stat().st_mode) == int(pin["mode"], 8) & 0o777)
    selected, probe = dict(original), probe_bytes()
    selected.update(changed)
    selected["common/trie/" + PROBE] = probe
    workspace.mkdir(mode=0o700)
    for name, raw in selected.items():
        destination = workspace / "node" / name
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with destination.open("xb") as stream:
            stream.write(raw)
        destination.chmod(0o755 if name in manifest["files"]
                          and manifest["files"][name]["mode"] == "100755" else 0o644)
    result = plan(workspace, go, pins, probe)
    P.UTIL.seal(workspace / "raw-kv-roundtrip-prepared.json", P.UTIL.encoded(result))
    require(inventory(node_source) == set(original))
    for name, raw in original.items():
        require(P.read_regular(node_source / name, 16 << 20) == raw)
    P.exact(verify(workspace, go), result)
    return result


def verify(workspace, go):
    workspace = Path(workspace).absolute()
    require(workspace.is_dir() and not any(p.is_symlink() for p in (workspace, *workspace.parents)))
    manifest, changed, pins = selection()
    node = workspace / "node"
    require(inventory(node) == set(manifest["files"]) | {"common/trie/" + PROBE})
    for name, pin in pins.items():
        raw = P.read_regular(node / name, 16 << 20)
        require(len(raw) == pin["bytes"] and P.sha(raw) == pin["sha256"]
                and P.UTIL.git_hash("blob", raw) == pin["git_blob"]
                and stat.S_IMODE((node / name).stat().st_mode) == int(pin["mode"], 8) & 0o777)
    probe = probe_bytes()
    require(P.read_regular(node / "common/trie" / PROBE, 128 << 10) == probe)
    require(stat.S_IMODE((node / "common/trie" / PROBE).stat().st_mode) == 0o644)
    stored = json.loads(P.read_regular(workspace / "raw-kv-roundtrip-prepared.json", 128 << 10),
                        object_pairs_hook=P.pairs)
    P.exact(stored, plan(workspace, go, pins, probe))
    return stored


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node-source", type=Path, required=True)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--go", required=True)
    args = parser.parse_args(argv)
    print(json.dumps(prepare(args.node_source, args.workspace, args.go), sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError, IndexError, AssertionError):
        print("Raw KV roundtrip preparation refused; preserve owned inputs and partial workspace.", file=sys.stderr)
        sys.exit(1)
