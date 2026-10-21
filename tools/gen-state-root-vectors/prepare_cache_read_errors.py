#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Prepare a bounded real-cache read comparison; never execute a backend."""
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

def load(name, file):
    spec = importlib.util.spec_from_file_location(name, HERE / file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

C = load("cache_read_prior_context", "prepare_cache_store_context.py")
P = C.P
MODEL = "cache_read_error_model.py"
MODEL_BYTES = 9992
MODEL_SHA256 = "ebd70aaf2dcece65dc94cad8df4a379151b4fffacff0fd61cf42efdd7e14e921"
VARIANTS = ("baseline", "candidate")
MODES = ("initialize-extract-query-close", "reopen-query-close")
PATCH = "testdata/candidate-cache-read-errors-patch.json"
PATCH_SHA256 = "db68f648e7193d3e3d8c3b1c2c182bf6c2335d8101cc0ec7e5d63a0898f0bfb1"
PROBE = "cache_read_error_probe.go"
PROBE_TARGET = "cmd/candidate-cache-read-error/main.go"
PROBE_BYTES = 8801
PROBE_SHA256 = "b73ebf18b474b3f71bbda9e119ae98b5df3b4af6bd1499e66a8eb905ee4fe185"
UNIT = "cache_store_read_error_guard_test.go.txt"
UNIT_TARGET = "chain/cache/cache_store_read_error_guard_test.go"
UNIT_BYTES = 7236
UNIT_SHA256 = "578744e1bf7fcf657180becd23ca46ff0227a5944cda8fa7812bb96f3e74b383"
PARENT_TREE = "69b0844bccc68273b2b367cda7706d933d45358f"
CANDIDATE_TREE = "c5e413c43794b3ba32763484670db2b100295a15"
BUILD_TREES = {"baseline": "9a6312076a5e7e5abfb900635abe9bc3a62d7251",
               "candidate": "e849d5a5bf223a7c43fbb40030a817c2250ae89c"}
FIXTURE_FILE = "cache-read-errors-fixture.json"
FIXTURE_BYTES = 1588
FIXTURE_SHA256 = "96513b59a64bbd8b734238fc6c768fe49fd72dcb1437096a220346cc0a6371cc"
PREPARED_FILE = "prepared-cache-read-errors.json"
TAGS = C.TAGS + ",candidate_cache_read_error"
EXISTING_CACHE_ROOTS = (
    ("chain/cache", "TestExtractor"),
    ("chain/cache/storage", "TestAddWriteFailureIsAtomic"),
    ("chain/cache/storage", "TestPopWriteFailureIsAtomic"),
    ("chain/cache/storage", "TestPop"),
    ("chain/cache/storage", "TestCacheDBManagerStopIsIdempotent"),
    ("chain/cache/storage", "TestCacheDBManagerStopAfterFailedClose"),
)

def require(ok):
    if not ok:
        raise ValueError("Cache read error preparation refused")

def pinned(name, size, digest):
    raw = P.read_regular(HERE / name, size)
    require(len(raw) == size and hashlib.sha256(raw).hexdigest() == digest)
    return raw

pinned(MODEL, MODEL_BYTES, MODEL_SHA256)
M = load("cache_read_independent_model", MODEL)

def selected_fixture():
    pinned(MODEL, MODEL_BYTES, MODEL_SHA256)
    raw = P.UTIL.encoded(M.expected_fixture())
    require(len(raw) == FIXTURE_BYTES and hashlib.sha256(raw).hexdigest() == FIXTURE_SHA256)
    M.selected_fixture(raw)
    return raw

def new_roots():
    raw = pinned(UNIT, UNIT_BYTES, UNIT_SHA256)
    names = re.findall(rb"(?m)^func (TestCacheReadError_[A-Za-z0-9_]+)\(t \*testing.T\)", raw)
    require(len(names) == 12 and len(set(names)) == 12)
    return sorted(name.decode() for name in names)

def roots():
    result = sorted(set(C.roots()) | set(new_roots()) | {name for _, name in EXISTING_CACHE_ROOTS})
    require(len(C.roots()) == 23 and len(EXISTING_CACHE_ROOTS) == 6 and len(result) == 41)
    return result

def selection(variant="candidate"):
    require(type(variant) is str and variant in VARIANTS)
    manifest, modified, pins = C.selection("candidate")
    require(len(pins) == 470 and P.UTIL.reconstruct_tree(pins) == PARENT_TREE)
    if variant == "baseline":
        return manifest, modified, pins
    raw = P.read_regular(HERE / PATCH, 32 << 10)
    require(hashlib.sha256(raw).hexdigest() == PATCH_SHA256)
    patch = json.loads(raw, object_pairs_hook=P.pairs, parse_constant=M.constant)
    require(set(patch) == {"kind", "node_revision", "parent_tree", "candidate_tree", "file",
        "before", "after", "before_sha256", "after_sha256", "before_git_blob",
        "after_git_blob", "source_only_experimental"})
    P.exact({key: patch[key] for key in ("kind", "node_revision", "parent_tree", "candidate_tree",
        "file", "source_only_experimental")}, {
        "kind": "experimental-cache-initial-read-error-propagation", "node_revision": P.REVISION,
        "parent_tree": PARENT_TREE, "candidate_tree": CANDIDATE_TREE,
        "file": "chain/cache/store.go", "source_only_experimental": True})
    before, after = patch["before"].encode(), patch["after"].encode()
    for label, payload in (("before", before), ("after", after)):
        require(hashlib.sha256(payload).hexdigest() == patch[label + "_sha256"])
        require(P.UTIL.git_hash("blob", payload) == patch[label + "_git_blob"])
    require(patch["before_sha256"] == "4c194aec82f46ef95ed2349b9c4786c08375234166aaf1e2f2813e2e921d7445")
    require(patch["after_sha256"] == "0d3aab42ff433f324798e5c7ce89881f7584d8409cc3dd7a6117054f8e941818")
    require(pins[patch["file"]]["sha256"] == patch["before_sha256"])
    old = b"\tif !iterator.Last() {\n\t\treturn []byte{}, nil\n\t}"
    new = b"\tif !iterator.Last() {\n\t\tif err := iterator.Error(); err != nil {\n\t\t\treturn nil, err\n\t\t}\n\t\treturn []byte{}, nil\n\t}"
    require(before.count(old) == 1 and before.replace(old, new) == after)
    modified[patch["file"]] = after
    require(UNIT_TARGET not in pins)
    modified[UNIT_TARGET] = pinned(UNIT, UNIT_BYTES, UNIT_SHA256)
    for name, payload in modified.items():
        pins[name] = {"mode": "100644", "bytes": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(), "git_blob": P.UTIL.git_hash("blob", payload)}
    require(len(pins) == 471 and P.UTIL.reconstruct_tree(pins) == CANDIDATE_TREE)
    return manifest, modified, pins

def build_pins(variant="candidate"):
    _, _, pins = selection(variant)
    raw = pinned(PROBE, PROBE_BYTES, PROBE_SHA256)
    require(PROBE_TARGET not in pins)
    pins[PROBE_TARGET] = {"mode": "100644", "bytes": len(raw), "sha256": PROBE_SHA256,
                          "git_blob": P.UTIL.git_hash("blob", raw)}
    require(len(pins) == (471 if variant == "baseline" else 472))
    require(P.UTIL.reconstruct_tree(pins) == BUILD_TREES[variant])
    return pins

def plan(workspace, go, variant="candidate"):
    require(type(go) is str and bool(go) and "\x00" not in go)
    workspace = Path(workspace).absolute()
    pins = build_pins(variant)
    selected_fixture()
    return {"kind": "prepared-cache-read-error-comparison", "variant": variant,
        "node_revision": P.REVISION, "parent_runtime_tree": PARENT_TREE,
        "runtime_tree": PARENT_TREE if variant == "baseline" else CANDIDATE_TREE,
        "build_tree": BUILD_TREES[variant], "source_blobs": len(pins),
        "probe": {"bytes": PROBE_BYTES, "sha256": PROBE_SHA256},
        "fixture": {"bytes": FIXTURE_BYTES, "sha256": FIXTURE_SHA256},
        "minimum_free_floor_bytes": 10 << 30, "expected_allocation_bytes": 2 << 30,
        "suggested_task_quota_bytes": 3 << 30,
        "native_test_roots": roots() if variant == "candidate" else [],
        "expected_native_root_tests": 41 if variant == "candidate" else 0,
        "expected_native_pass_results": 50 if variant == "candidate" else 0,
        "native_test_argv": [go, "test", "-mod=readonly", "-count=1", "-json", "-p=2",
            "-trimpath", "-buildvcs=false", "-tags", TAGS, "-run", "^(" + "|".join(roots()) + ")$",
            "./chain", "./chain/cache", "./chain/cache/storage"] if variant == "candidate" else [],
        "build_argv": [go, "build", "-mod=readonly", "-p=2", "-trimpath", "-buildvcs=false",
            "-tags", "candidate_cache_read_error", "-o", str(workspace / "cache-read-error"),
            "./cmd/candidate-cache-read-error"],
        "native_working_directory": str(workspace / "node"),
        "run_argv_templates": [[str(workspace / "cache-read-error"), "--case", mode,
            "--root", "OWNED_CASE_ROOT", "--fixture", str(workspace / FIXTURE_FILE),
            "--fixture-sha256", FIXTURE_SHA256] for mode in MODES],
        "first_case_requires_empty_root": True, "second_case_reopens_same_closed_cache": True,
        "ordinary_builds": 1, "ordinary_processes": 2, "expected_events": 29,
        "expected_queries": 19, "expected_error_propagation_mismatches": 6 if variant == "baseline" else 0,
        "ordinary_probe_cache_manager_and_extractor_only": True,
        "separate_units_include_selected_public_chain_regressions": variant == "candidate",
        "reference_backend_executed": False, "new_dependency_transports_permitted": False,
        "nominal_identifier_is_verified_momentum": False, "account_block_execution_selected": False,
        "concurrent_lifecycle_or_full_node_qualified": False, "cache_value_authentication": False,
        "accepted_header_binding": False, "runtime_state_value_acceptance": False,
        "consumer_result": "REFUSED"}

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
    require(P.read_regular(workspace / FIXTURE_FILE, 16384) == selected_fixture())
    recorded = json.loads(P.read_regular(workspace / PREPARED_FILE, 128 << 10),
                          object_pairs_hook=P.pairs, parse_constant=M.constant)
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
