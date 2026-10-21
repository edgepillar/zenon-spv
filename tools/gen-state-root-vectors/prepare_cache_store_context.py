#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Prepare a bounded local cache-context comparison; never execute a backend."""
import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import stat
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
def load(name, file):
    spec = importlib.util.spec_from_file_location(name, HERE / file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
N = load("cache_context_parent", "prepare_public_chain_startup_record.py")
R = load("cache_context_fixture", "prepare_public_chain_reorg_reopen.py")
P = N.P
VARIANTS = ("baseline", "candidate")
MODES = ("initialize-and-query", "reopen-and-query")
PATCH = "testdata/candidate-cache-store-context-patch.json"
PATCH_SHA256 = "f6f735ad1ccf606d510d3bccb9976663dc70b03160060affdd6cbbcd7e1ef0bb"
PROBE = "cache_store_identifier_probe.go"
PROBE_TARGET = "cmd/candidate-cache-store-identifier-context/main.go"
PROBE_BYTES = 11215
PROBE_SHA256 = "4923ccdcdb32f58486d699ed842793ad76862c66eed771f1bd717faadac0c709"
UNIT = "cache_store_context_guard_test.go.txt"
UNIT_TARGET = "chain/cache_store_context_guard_test.go"
UNIT_BYTES = 6896
UNIT_SHA256 = "0a7cb66cf90d64d2c470441fafdd90636f6cc84f8802026a4d8e10bc3777065a"
PARENT_TREE = "d56bf37a23ddf0ec0f8af2eca62be01bb6c54dbc"
CANDIDATE_TREE = "69b0844bccc68273b2b367cda7706d933d45358f"
BUILD_TREES = {"baseline": "c3843a58aff7f3520cc5a6582482907d7408593c",
               "candidate": "ca6bcf586b3f8ce6a68f1872c4407925c9aa1fa8"}
FIXTURE_FILE = "cache-store-context-fixture.json"
PREPARED_FILE = "prepared-cache-store-context.json"
TAGS = "candidate_cache_store_identifier_context,candidate_public_startup_record_identity,candidate_momentum_rollback_target"

def require(ok):
    if not ok:
        raise ValueError("Cache store context preparation refused")

def selected_fixture():
    raw = R.selected_fixture()
    require(len(raw) == R.FIXTURE_BYTES and hashlib.sha256(raw).hexdigest() == R.FIXTURE_SHA256)
    return raw

def pinned(name, size, digest):
    raw = P.read_regular(HERE / name, size)
    require(len(raw) == size and hashlib.sha256(raw).hexdigest() == digest)
    return raw

def selection(variant="candidate"):
    require(type(variant) is str and variant in VARIANTS)
    manifest, modified, pins = N.selection()
    require(len(pins) == 467 and P.UTIL.reconstruct_tree(pins) == PARENT_TREE)
    if variant == "baseline":
        return manifest, modified, pins
    raw = P.read_regular(HERE / PATCH, 32 << 10)
    require(hashlib.sha256(raw).hexdigest() == PATCH_SHA256)
    patch = json.loads(raw, object_pairs_hook=P.pairs)
    require(set(patch) == {"kind", "node_revision", "parent_tree", "candidate_tree", "file",
                           "before", "after", "before_sha256", "after_sha256",
                           "before_git_blob", "after_git_blob", "source_only_experimental"})
    P.exact({key: patch[key] for key in ("kind", "node_revision", "parent_tree", "candidate_tree", "file", "source_only_experimental")},
            {"kind": "experimental-public-chain-cache-context", "node_revision": P.REVISION,
             "parent_tree": PARENT_TREE, "candidate_tree": CANDIDATE_TREE,
             "file": "chain/chain.go", "source_only_experimental": True})
    before, after = patch["before"].encode(), patch["after"].encode()
    for label, payload in (("before", before), ("after", after)):
        require(hashlib.sha256(payload).hexdigest() == patch[label + "_sha256"])
        require(P.UTIL.git_hash("blob", payload) == patch[label + "_git_blob"])
    require(before == modified["chain/chain.go"])
    require(patch["before_sha256"] == "4175fbe331d953a76c0f2f0ef83909311cdc8e026f69d916c7009f828b70c7dc")
    require(patch["after_sha256"] == "48a3615f079c14a1b965b7f9f7c5213e80e6c11cdea11e6e3bd364adaea34d54")
    modified["chain/chain.go"] = after
    for name, payload in N.extras(True).items():
        if name.endswith("_test.go"):
            require(name not in pins)
            modified[name] = payload
    modified[UNIT_TARGET] = pinned(UNIT, UNIT_BYTES, UNIT_SHA256)
    for name, payload in modified.items():
        pins[name] = {"mode": "100644", "bytes": len(payload), "sha256": hashlib.sha256(payload).hexdigest(),
                      "git_blob": P.UTIL.git_hash("blob", payload)}
    require(len(pins) == 470 and P.UTIL.reconstruct_tree(pins) == CANDIDATE_TREE)
    return manifest, modified, pins

def roots():
    raw = pinned(UNIT, UNIT_BYTES, UNIT_SHA256)
    added = re.findall(rb"(?m)^func (TestCacheContext_[A-Za-z0-9_]+)\(t \*testing.T\)", raw)
    require(len(added) == 12 and len(set(added)) == 12 and len(N.ROOTS) == 11)
    result = sorted(set(name.decode() for name in added) | set(N.ROOTS))
    require(len(result) == 23)
    return result

def build_pins(variant="candidate"):
    _, _, pins = selection(variant)
    raw = pinned(PROBE, PROBE_BYTES, PROBE_SHA256)
    require(PROBE_TARGET not in pins)
    pins[PROBE_TARGET] = {"mode": "100644", "bytes": len(raw), "sha256": PROBE_SHA256,
                          "git_blob": P.UTIL.git_hash("blob", raw)}
    require(len(pins) == (468 if variant == "baseline" else 471))
    require(P.UTIL.reconstruct_tree(pins) == BUILD_TREES[variant])
    return pins

def plan(workspace, go, variant="candidate"):
    require(type(go) is str and bool(go) and "\x00" not in go)
    workspace = Path(workspace).absolute()
    pins = build_pins(variant)
    selected_fixture()
    return {"kind": "prepared-public-cache-store-context", "variant": variant, "node_revision": P.REVISION,
        "parent_runtime_tree": PARENT_TREE, "runtime_tree": PARENT_TREE if variant == "baseline" else CANDIDATE_TREE,
        "build_tree": BUILD_TREES[variant], "source_blobs": len(pins),
        "probe": {"bytes": PROBE_BYTES, "sha256": PROBE_SHA256},
        "fixture": {"bytes": R.FIXTURE_BYTES, "sha256": R.FIXTURE_SHA256},
        "minimum_free_floor_bytes": 10 << 30, "expected_allocation_bytes": 2 << 30, "suggested_task_quota_bytes": 3 << 30,
        "native_test_roots": roots() if variant == "candidate" else [],
        "expected_native_pass_results": 29 if variant == "candidate" else 0,
        "native_test_argv": [go, "test", "-mod=readonly", "-count=1", "-json", "-p=2", "-trimpath", "-buildvcs=false",
            "-tags", TAGS, "-run", "^(" + "|".join(roots()) + ")$", "./chain"] if variant == "candidate" else [],
        "build_argv": [go, "build", "-mod=readonly", "-p=2", "-trimpath", "-buildvcs=false",
            "-tags", "candidate_cache_store_identifier_context", "-o", str(workspace / "cache-context"),
            "./cmd/candidate-cache-store-identifier-context"],
        "native_working_directory": str(workspace / "node"),
        "run_argv_templates": [[str(workspace / "cache-context"), "--case", mode, "--root", "OWNED_CASE_ROOT",
            "--fixture", str(workspace / FIXTURE_FILE), "--fixture-sha256", R.FIXTURE_SHA256] for mode in MODES],
        "first_case_requires_empty_root": True, "second_case_reopens_same_closed_stores": True,
        "ordinary_builds": 1, "ordinary_processes": 2, "expected_queries": 8,
        "expected_context_mismatches": 4 if variant == "baseline" else 0,
        "parent_fixture_source_label_rebound": False, "reference_backend_executed": False,
        "new_dependency_transports_permitted": False, "new_account_blocks_added": False,
        "concurrent_history_changes_or_full_node_qualified": False, "cache_value_correctness_qualified": False,
        "accepted_header_binding": False, "runtime_state_value_acceptance": False, "consumer_result": "REFUSED"}

def prepare(node_source, workspace, go, variant="candidate"):
    expected = plan(workspace, go, variant)
    workspace = P.private_destination(workspace)
    node_source = Path(node_source).absolute()
    require(not any(path.is_symlink() for path in (node_source, *node_source.parents)))
    original_root, prepared_root = node_source.resolve(), workspace.resolve()
    require(original_root != prepared_root and original_root not in prepared_root.parents and prepared_root not in original_root.parents)
    manifest, modified, _ = selection(variant)
    original = P.UTIL.snapshot_source(node_source, manifest["files"])
    rows = {name: modified.get(name, raw) for name, raw in original.items()}
    rows.update(modified)
    rows[PROBE_TARGET] = pinned(PROBE, PROBE_BYTES, PROBE_SHA256)
    workspace.mkdir(mode=0o700)
    for name, pin in build_pins(variant).items():
        path = workspace / "node" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as stream:
            stream.write(rows[name])
        path.chmod(int(pin["mode"], 8) & 0o777)
    P.UTIL.seal(workspace / FIXTURE_FILE, selected_fixture())
    P.UTIL.seal(workspace / PREPARED_FILE, P.UTIL.encoded(expected))
    P.exact(verify(workspace, go, variant), expected)
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
    require(P.read_regular(workspace / FIXTURE_FILE, 64 << 10) == selected_fixture())
    recorded = json.loads(P.read_regular(workspace / PREPARED_FILE, 128 << 10), object_pairs_hook=P.pairs)
    P.exact(recorded, expected)
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
    main()
