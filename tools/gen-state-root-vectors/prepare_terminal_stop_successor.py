#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Prepare a separate terminal-instance experiment on the selected successor.

Return exact build/run arguments without executing them. The caller owns source
acquisition, dependency verification, private scratch, supervision and cleanup.
Historical source selectors, patches and observations remain unchanged.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import stat
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("terminal_successor_parent", HERE / "prepare_recovery_successor.py")
P = importlib.util.module_from_spec(spec)
spec.loader.exec_module(P)
VARIANTS = ("hash-bound", "monotonic-stop")
PATCH = "node-terminal-stop-9c71-patch.json"
PATCH_SHA256 = "845be9c2a61dcac285d2f1d465cf2fe3b22d33bb96fc3ab58fb345f504889be5"
MODIFIED_TREE = "2ab95e67aa184e7faa3f080c6b08d8980a8e16f9"
AFTER = "83311a1a529a76351c7ca2137bae67395010b3ab883558f5702a3e31601c731f"
AFTER_BYTES = 31695
PROBE = "lifecycle_stop_successor_probe_test.go"
TAG = "candidate_state_tree_stop_successor"
STATE = "chain/state_tree.go"
HOOKS = (
    ('func (s *stateTree) startBuild(c *chain) {\n',
     'func (s *stateTree) startBuild(c *chain) {\n\tlifecycleCheckpoint("launch-entry", s, nil)\n'),
    ('\tprevious := s.buildExited\n\ts.changes.Unlock()\n',
     '\tprevious := s.buildExited\n\ts.changes.Unlock()\n\tlifecycleCheckpoint("launch-snapshot", s, previous)\n'),
    ('\t\tdefer close(exited)\n\t\ts.runBuild(c)\n',
     '\t\tdefer close(exited)\n\t\tlifecycleCheckpoint("worker-claimed", s, exited)\n\t\ts.runBuild(c)\n'),
)


def require(condition):
    if not condition:
        raise ValueError("Successor terminal preparation refused")


def parent_selection():
    manifest = P.source_manifest()
    descriptor = P.document(P.PATCH, P.PATCH_SHA256)
    original = {name: row["replacements"][0]["before"].encode()
                for name, row in descriptor["files"].items()}
    modified, _ = P.patch_files(original, manifest)
    pins = {name: dict(row) for name, row in manifest["files"].items()}
    for name, raw in modified.items():
        pins[name].update(sha256=P.sha(raw), git_blob=P.UTIL.git_hash("blob", raw), bytes=len(raw))
    require(P.UTIL.reconstruct_tree(pins) == P.MODIFIED_TREE)
    return manifest, modified, pins


def patch_state(raw):
    value = P.document(PATCH, PATCH_SHA256)
    _, modified, _ = parent_selection()
    require(raw == modified[STATE])
    expected = {
        "format_version": 1, "kind": "experimental-successor-monotonic-state-tree-stop",
        "base_revision": P.REVISION, "base_tree": P.TREE, "base_blob_count": 467,
        "hash_identity_parent_tree": P.MODIFIED_TREE, "hash_identity_patch_sha256": P.PATCH_SHA256,
        "modified_node_tree_without_probes": MODIFIED_TREE, "file": STATE, "mode": "100644",
        "before_sha256": P.sha(raw), "before_git_blob": P.UTIL.git_hash("blob", raw), "before_bytes": len(raw),
        "after_sha256": AFTER, "after_git_blob": value["after_git_blob"], "after_bytes": AFTER_BYTES,
        "replacements": value["replacements"], "experimental_only": True,
        "disk_format_changed": False, "SMT_profile_changed": False, "automatic_migration_added": False,
        "network_activation_authenticated": False, "state_value_acceptance_enabled": False,
        "historical_source_records_rebound": False, "production_qualified": False,
    }
    P.exact(value, expected)
    require(type(value["replacements"]) is list and len(value["replacements"]) == 1)
    row = value["replacements"][0]
    require(type(row) is dict and set(row) == {"before", "after"})
    require(all(type(v) is str and bool(v) for v in row.values()))
    require(row["before"].encode() == raw)
    after = row["after"].encode()
    require(len(after) == AFTER_BYTES and P.sha(after) == AFTER)
    require(P.UTIL.git_hash("blob", after) == value["after_git_blob"])
    require(after.decode().replace(row["after"], row["before"], 1).encode() == raw)
    return after


def instrument(raw):
    text = raw.decode()
    for before, after in HOOKS:
        require(text.count(before) == 1)
        text = text.replace(before, after)
    selected = text.encode()
    for before, after in reversed(HOOKS):
        require(text.count(after) == 1)
        text = text.replace(after, before)
    require(text.encode() == raw)
    return selected


def expected_plan(workspace, variant, go, parent, original, probe):
    require(variant in VARIANTS and type(go) is str and bool(go))
    chosen = patch_state(original) if variant == "monotonic-stop" else original
    binary = workspace / "terminal-successor.test"
    build = list(parent["build_argv"])
    require(build[0] == go and build.count("-c") == build.count("-tags") == build.count("-o") == 1)
    build.insert(build.index("-c") + 1, "-race")
    build[build.index("-tags") + 1] = P.TAG + "," + TAG
    build[build.index("-o") + 1] = str(binary)
    return {
        "format_version": 1, "kind": "successor-terminal-instance-prepared-source", "variant": variant,
        "base_revision": P.REVISION, "base_tree": P.TREE,
        "hash_identity_parent_tree": P.MODIFIED_TREE, "terminal_patch_sha256": PATCH_SHA256,
        "runtime_tree_without_probes_or_checkpoints": MODIFIED_TREE if variant == "monotonic-stop" else P.MODIFIED_TREE,
        "node_source_blobs": 467, "compiled_test_source_files_added": 2,
        "parent_probe_compiled_but_not_selected": P.PROBE,
        "selected_probe": PROBE, "selected_probe_sha256": P.sha(probe),
        "parent_prepared_sha256": P.sha(P.UTIL.encoded(parent)),
        "state_before_checkpoints_sha256": P.sha(chosen), "instrumented_state_sha256": P.sha(instrument(chosen)),
        "scheduler_checkpoints": ["launch-entry", "launch-snapshot", "worker-claimed"],
        "scheduler_checkpoints_are_injected_test_instrumentation": True, "Go_race_detector_selected": True,
        "original_upstream_tests_excluded_by_explicit_overlay": list(P.UPSTREAM_TESTS),
        "module_selection": parent["module_selection"], "module_sha256": parent["module_sha256"],
        "sum_sha256": parent["sum_sha256"],
        "working_directory": parent["working_directory"], "binary": str(binary), "build_argv": build,
        "run_argv": [str(binary), "-test.v", "-test.run=^TestCandidateStateTreeStop$"],
        "required_run_environment": {"ZENON_STOP_SUCCESSOR_VARIANT": variant},
        "network_acquisition_performed": False, "reference_execution_performed": False,
        "existing_database_adopted": False, "historical_source_records_rebound": False,
        "profile_agreed": False, "production_qualified": False,
    }


def prepare(node_source, workspace, variant, go):
    require(variant in VARIANTS and type(go) is str and bool(go))
    workspace = P.private_destination(workspace)
    # The parent checks every original file, the exact identity patch, the node's
    # own module files and all eight explicit compiler overlays before layering.
    parent = P.prepare(node_source, workspace, "hash-bound", go)
    P.exact(P.verify(workspace, "hash-bound", go), parent)
    _, modified, _ = parent_selection()
    original = P.read_regular(workspace / "node" / STATE, 128 << 10)
    require(original == modified[STATE])
    with (workspace / "parent-state-tree.go").open("xb") as stream:
        stream.write(original)
    (workspace / "parent-state-tree.go").chmod(0o400)
    probe = P.read_regular(HERE / PROBE, 128 << 10)
    require(probe.startswith(("//go:build " + TAG + "\n").encode()))
    plan = expected_plan(workspace, variant, go, parent, original, probe)
    chosen = patch_state(original) if variant == "monotonic-stop" else original
    (workspace / "node" / STATE).write_bytes(instrument(chosen))
    with (workspace / "node/chain" / PROBE).open("xb") as stream:
        stream.write(probe)
    P.UTIL.seal(workspace / "terminal-prepared.json", P.UTIL.encoded(plan))
    P.exact(verify(workspace, variant, go), plan)
    return plan


def verify(workspace, variant, go):
    require(variant in VARIANTS and type(go) is str and bool(go))
    workspace = Path(workspace).absolute()
    require(workspace.is_dir() and not any(p.is_symlink() for p in (workspace, *workspace.parents)))
    manifest, modified, parent_pins = parent_selection()
    parent = json.loads(P.read_regular(workspace / "prepared.json", 128 << 10), object_pairs_hook=P.pairs)
    original = P.read_regular(workspace / "parent-state-tree.go", 128 << 10)
    require(original == modified[STATE])
    probe = P.read_regular(HERE / PROBE, 128 << 10)
    require(probe.startswith(("//go:build " + TAG + "\n").encode()))
    plan = json.loads(P.read_regular(workspace / "terminal-prepared.json", 128 << 10), object_pairs_hook=P.pairs)
    expected = expected_plan(workspace, variant, go, parent, original, probe)
    P.exact(plan, expected)
    node = workspace / "node"
    require(node.is_dir() and not node.is_symlink())
    actual = set()
    for path in node.rglob("*"):
        require(not path.is_symlink())
        if path.is_file():
            info = path.lstat()
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1)
            actual.add(path.relative_to(node).as_posix())
    require(actual == set(manifest["files"]) | {"chain/" + P.PROBE, "chain/" + PROBE})
    chosen = patch_state(original) if variant == "monotonic-stop" else original
    pins = {}
    for name, pin in parent_pins.items():
        raw = P.read_regular(node / name, 16 << 20)
        expected_sha = P.sha(instrument(chosen)) if name == STATE else pin["sha256"]
        require(P.sha(raw) == expected_sha and len(raw) == (len(instrument(chosen)) if name == STATE else pin["bytes"]))
        pins[name] = dict(pin, git_blob=P.UTIL.git_hash("blob", chosen if name == STATE else raw))
    require(P.UTIL.reconstruct_tree(pins) == expected["runtime_tree_without_probes_or_checkpoints"])
    parent_probe = P.read_regular(HERE / P.PROBE, 128 << 10)
    require(P.read_regular(node / "chain" / P.PROBE, 128 << 10) == parent_probe)
    require(P.read_regular(node / "chain" / PROBE, 128 << 10) == probe)
    overlay = {"Replace": {str(node / "chain" / name): str(workspace / "test-overlays" / name)
                           for name in P.UPSTREAM_TESTS}}
    overlay_raw = P.read_regular(workspace / "test-overlay.json", 128 << 10)
    require(overlay_raw == P.UTIL.encoded(overlay))
    for name in P.UPSTREAM_TESTS:
        require(P.read_regular(workspace / "test-overlays" / name, 1 << 20) ==
                b"//go:build !" + P.TAG.encode() + b"\n\n" + P.read_regular(node / "chain" / name, 1 << 20))
    module = P.read_regular(node / "go.mod", 1 << 20)
    sums = P.read_regular(node / "go.sum", 1 << 20)
    P.exact(parent, P.plan(workspace, "hash-bound", go, parent_pins, parent_probe, overlay_raw, module, sums))
    return plan


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node-source", type=Path, required=True)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--variant", choices=VARIANTS, required=True)
    parser.add_argument("--go", required=True)
    args = parser.parse_args(argv)
    print(json.dumps(prepare(args.node_source, args.workspace, args.variant, args.go), sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, IndexError):
        print("Successor terminal preparation refused; preserve inputs and partial workspace.", file=sys.stderr)
        sys.exit(1)
