#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Prepare an isolated lifecycle comparison; execute no returned command.

Layer the exact stop proposal on the existing hash-bound current-node proposal.
Scheduler checkpoints are separate declared test instrumentation. The original
source selectors, source records and existing-database paths are never retargeted.
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
spec = importlib.util.spec_from_file_location("lifecycle_parent_hash_bound_preparer", HERE / "prepare_hash_bound_versions.py")
P = importlib.util.module_from_spec(spec)
spec.loader.exec_module(P)
VARIANTS = ("hash-bound", "monotonic-stop")
PATCH = "lifecycle-stop-patch.json"
PATCH_SHA256 = "2778017b5de86be222956a600dcb8bed49dd5fd543566f0230e6c2a042a8a165"
MODIFIED_TREE = "d3d9215bc9ea23b2e700aad53ebb23d4bdea3428"
AFTER = "cbe8e224386104220ec3d90e705cf1f35c3a8c5199df9794c3c27036b392097c"
PROBE = "lifecycle_stop_probe_test.go"
TAG = "candidate_state_tree_stop"
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
        raise ValueError("Lifecycle source preparation refused")


def patch_state(raw):
    descriptor_raw = P.read_regular(HERE / PATCH, 128 << 10)
    require(P.sha(descriptor_raw) == PATCH_SHA256)
    value = json.loads(descriptor_raw, object_pairs_hook=P.pairs)
    expected = {
        "format_version": 1, "kind": "experimental-monotonic-state-tree-stop",
        "base_revision": P.REVISION, "base_tree": P.TREE,
        "hash_identity_parent_tree": P.MODIFIED_TREE, "hash_identity_patch_sha256": P.PATCH_SHA256,
        "modified_node_tree_without_probes": MODIFIED_TREE, "file": STATE, "mode": "100644",
        "before_sha256": P.AFTER[STATE], "before_git_blob": P.UTIL.git_hash("blob", raw),
        "before_bytes": len(raw), "after_sha256": AFTER,
        "after_git_blob": value["after_git_blob"], "after_bytes": 32011,
        "replacements": value["replacements"], "experimental_only": True,
        "disk_format_changed": False, "SMT_profile_changed": False, "automatic_migration_added": False,
        "network_activation_authenticated": False, "state_value_acceptance_enabled": False,
        "production_qualified": False,
    }
    P.exact(value, expected)
    require(P.sha(raw) == value["before_sha256"])
    require(type(value["replacements"]) is list and 1 <= len(value["replacements"]) <= 32)
    text = raw.decode("utf-8")
    for row in value["replacements"]:
        require(type(row) is dict and set(row) == {"before", "after"})
        require(all(type(row[k]) is str and bool(row[k]) for k in row))
        require(text.count(row["before"]) == 1)
        text = text.replace(row["before"], row["after"])
    after = text.encode("utf-8")
    require(len(after) == value["after_bytes"] and P.sha(after) == AFTER)
    require(P.UTIL.git_hash("blob", after) == value["after_git_blob"])
    for row in reversed(value["replacements"]):
        require(text.count(row["after"]) == 1)
        text = text.replace(row["after"], row["before"])
    require(text.encode("utf-8") == raw)
    return after


def instrument(raw):
    text = raw.decode("utf-8")
    for before, after in HOOKS:
        require(text.count(before) == 1)
        text = text.replace(before, after)
    selected = text.encode("utf-8")
    for before, after in reversed(HOOKS):
        require(text.count(after) == 1)
        text = text.replace(after, before)
    require(text.encode("utf-8") == raw)
    return selected


def expected_plan(workspace, variant, go, parent, original, probe):
    chosen = patch_state(original) if variant == "monotonic-stop" else original
    runtime = instrument(chosen)
    binary = workspace / "generator" / "lifecycle-stop.test"
    build = list(parent["build_argv"])
    build.insert(build.index("-c") + 1, "-race")
    build[build.index("-tags") + 1] = P.TAG + "," + TAG
    build[build.index("-o") + 1] = str(binary)
    return {
        "format_version": 1, "kind": "state-tree-stop-lifecycle-prepared-source",
        "variant": variant, "base_revision": P.REVISION, "base_tree": P.TREE,
        "hash_identity_parent_tree": P.MODIFIED_TREE, "lifecycle_patch_sha256": PATCH_SHA256,
        "runtime_tree_without_probes_or_checkpoints": MODIFIED_TREE if variant == "monotonic-stop" else P.MODIFIED_TREE,
        "node_source_blobs": 439, "compiled_test_source_files_added": 2,
        "parent_probe_compiled_but_not_selected": P.PROBE,
        "selected_probe": PROBE, "selected_probe_sha256": P.sha(probe),
        "parent_prepared_sha256": P.sha(P.UTIL.encoded(parent)),
        "state_before_checkpoints_sha256": P.sha(chosen), "instrumented_state_sha256": P.sha(runtime),
        "scheduler_checkpoints": ["launch-entry", "launch-snapshot", "worker-claimed"],
        "scheduler_checkpoints_are_injected_test_instrumentation": True,
        "Go_race_detector_selected": True,
        "original_upstream_tests_excluded_by_explicit_overlay": list(P.UPSTREAM_TESTS),
        "working_directory": parent["working_directory"], "binary": str(binary),
        "build_argv": build, "run_argv": [str(binary), "-test.v", "-test.run=^TestCandidateStateTreeStop$"],
        "required_run_environment": {"ZENON_STOP_VARIANT": variant},
        "network_acquisition_performed": False, "reference_execution_performed": False,
        "existing_database_adopted": False, "profile_agreed": False, "production_qualified": False,
    }


def prepare(node_source, workspace, variant, go):
    require(variant in VARIANTS)
    workspace = P.private_destination(workspace)
    # Parent preparation first verifies all 439 original files and its exact
    # forward/inverse patch, then stages independent quota-accounted source bytes.
    parent = P.prepare(node_source, workspace, "hash-bound", go)
    P.exact(P.verify(workspace, "hash-bound"), parent)
    original = P.read_regular(workspace / "node" / STATE, 128 << 10)
    require(P.sha(original) == P.AFTER[STATE])
    backup = workspace / "parent-state-tree.go"
    with backup.open("xb") as stream:
        stream.write(original)
    backup.chmod(0o400)
    probe = P.read_regular(HERE / PROBE, 128 << 10)
    require(probe.startswith(("//go:build " + TAG + "\n").encode()))
    plan = expected_plan(workspace, variant, go, parent, original, probe)
    chosen = patch_state(original) if variant == "monotonic-stop" else original
    (workspace / "node" / STATE).write_bytes(instrument(chosen))
    with (workspace / "node/chain" / PROBE).open("xb") as stream:
        stream.write(probe)
    P.UTIL.seal(workspace / "lifecycle-prepared.json", P.UTIL.encoded(plan))
    P.exact(verify(workspace, variant), plan)
    return plan


def verify(workspace, variant):
    require(variant in VARIANTS)
    workspace = Path(workspace).absolute()
    require(workspace.is_dir() and not any(p.is_symlink() for p in (workspace, *workspace.parents)))
    _, manifest = P.source_manifest()
    parent = json.loads(P.read_regular(workspace / "prepared.json", 128 << 10), object_pairs_hook=P.pairs)
    original = P.read_regular(workspace / "parent-state-tree.go", 128 << 10)
    require(P.sha(original) == P.AFTER[STATE])
    probe = P.read_regular(HERE / PROBE, 128 << 10)
    plan = json.loads(P.read_regular(workspace / "lifecycle-prepared.json", 128 << 10), object_pairs_hook=P.pairs)
    require(type(plan["build_argv"]) is list and len(plan["build_argv"]) > 1)
    expected = expected_plan(workspace, variant, plan["build_argv"][0], parent, original, probe)
    P.exact(plan, expected)
    node = workspace / "node"
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
    for name, pin in manifest["files"].items():
        raw = P.read_regular(node / name, 16 << 20)
        required_sha = P.sha(instrument(chosen)) if name == STATE else P.AFTER.get(name, pin["sha256"])
        require(P.sha(raw) == required_sha)
        pins[name] = dict(pin, git_blob=P.UTIL.git_hash("blob", chosen if name == STATE else raw))
    require(P.UTIL.reconstruct_tree(pins) == expected["runtime_tree_without_probes_or_checkpoints"])
    require(P.read_regular(node / "chain" / P.PROBE, 128 << 10) == P.read_regular(HERE / P.PROBE, 128 << 10))
    require(P.read_regular(node / "chain" / PROBE, 128 << 10) == probe)
    modules = P.frozen_module()
    require(P.read_regular(workspace / "generator/go.mod", 1 << 20) ==
            modules["go.mod"] + b"\nreplace github.com/zenon-network/go-zenon => ../node\n")
    require(P.read_regular(workspace / "generator/go.sum", 1 << 20) == modules["go.sum"])
    overlay = {"Replace": {str(node / "chain" / name): str(workspace / "test-overlays" / name)
                           for name in P.UPSTREAM_TESTS}}
    require(P.read_regular(workspace / "test-overlay.json", 128 << 10) == P.UTIL.encoded(overlay))
    for name in P.UPSTREAM_TESTS:
        require(P.read_regular(workspace / "test-overlays" / name, 1 << 20) ==
                b"//go:build !" + P.TAG.encode() + b"\n\n" + P.read_regular(node / "chain" / name, 1 << 20))
    # Bind the inherited plan to the same selected files and paths, not merely
    # to a freely editable checksum inside the new plan.
    parent_pins = {name: dict(pin) for name, pin in manifest["files"].items()}
    for name, digest in P.AFTER.items():
        raw = original if name == STATE else P.read_regular(node / name, 128 << 10)
        require(P.sha(raw) == digest)
        parent_pins[name] = dict(parent_pins[name], sha256=digest, bytes=len(raw), git_blob=P.UTIL.git_hash("blob", raw))
    P.exact(parent, P.plan(workspace, "hash-bound", plan["build_argv"][0], parent_pins,
                          P.read_regular(HERE / P.PROBE, 128 << 10), overlay))
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
        print("Lifecycle preparation refused; retain inputs and incomplete owned workspace.", file=sys.stderr)
        sys.exit(1)

