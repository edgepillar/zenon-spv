#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Prepare one owned, exact-source component workspace without executing it.

Acquisition and process supervision are separate. No fetching, service, source
repository mutation, existing-directory adoption or existing-output replacement.
Use an explicitly quota-accounted disposable workspace and offline dependencies.
The supplied node snapshot remains pinned to its original historical revision.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import stat
import sys

HERE = Path(__file__).resolve().parent
BASE_FILE_SHA256 = "951abad916d989b20eb934c4c3f486311a8b10b86f94654f0775302631235135"
GUARDED_FILE_SHA256 = "5b629baefd0064543122d7fa653e86804ebbf07593a542dd0055dd5e39b6ddce"
GUARDED_NODE_TREE = "c39bda7a640821c0a88adb99ecac9cc912dbbbba"
PROBE = "startup_quarantine_probe_test.go"
PATCH = "startup-quarantine-patch.json"
VARIANTS = ("baseline", "startup-quarantine")
UPSTREAM_TESTS = ("account_pool_test.go", "momentum_pool_test.go",
                  "state_tree_ready_test.go", "state_tree_update_test.go")


def load_source():
    spec = importlib.util.spec_from_file_location("quarantine_frozen_source", HERE / "regenerate.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SOURCE = load_source()


def require(condition):
    if not condition:
        raise ValueError("Startup quarantine source preparation refused")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def patch_source(raw):
    require(type(raw) is bytes and sha(raw) == BASE_FILE_SHA256)
    path = HERE / PATCH
    require(path.stat().st_size <= 4096)
    document = json.loads(path.read_bytes())
    require(set(document) == {"format_version", "kind", "base_revision", "base_tree", "path",
            "before_sha256", "after_sha256", "replacements", "blocked_ahead_error", "experimental_only",
            "persisted_schema_changed", "low_level_height_only_API_repaired",
            "authenticated_retained_version_provenance_qualified", "production_qualified",
            "before_git_blob", "after_git_blob", "after_bytes", "guarded_node_tree"})
    require(type(document["format_version"]) is int and document["format_version"] == 1)
    require(document["kind"] == "experimental-startup-quarantine-patch")
    require(document["base_revision"] == SOURCE.NODE_REVISION and document["base_tree"] == SOURCE.NODE_TREE)
    require(document["path"] == "chain/state_tree.go")
    require(document["before_sha256"] == BASE_FILE_SHA256 and document["after_sha256"] == GUARDED_FILE_SHA256)
    require(document["experimental_only"] is True)
    require(all(document[k] is False for k in ("persisted_schema_changed", "low_level_height_only_API_repaired",
            "authenticated_retained_version_provenance_qualified", "production_qualified")))
    require(type(document["replacements"]) is list and len(document["replacements"]) == 2)
    text = raw.decode("utf-8")
    for row in document["replacements"]:
        require(type(row) is dict and set(row) == {"before", "after"})
        require(type(row["before"]) is str and type(row["after"]) is str and text.count(row["before"]) == 1)
        text = text.replace(row["before"], row["after"])
    guarded = text.encode("utf-8")
    require(sha(guarded) == GUARDED_FILE_SHA256)
    require(SOURCE.git_hash("blob", raw) == document["before_git_blob"] == "1a947fd64a6a5e922c256157d10d8ff412fc1471")
    require(SOURCE.git_hash("blob", guarded) == document["after_git_blob"] == "a8d8e15e69df299d9c952a3700b23bca8da0780d")
    require(type(document["after_bytes"]) is int and document["after_bytes"] == len(guarded) == 31200)
    require(document["guarded_node_tree"] == GUARDED_NODE_TREE)
    for row in reversed(document["replacements"]):
        require(text.count(row["after"]) == 1)
        text = text.replace(row["after"], row["before"])
    require(text.encode("utf-8") == raw)
    return guarded, document


def private_destination(path):
    path = Path(path).absolute()
    require(not path.exists() and not path.is_symlink() and path.parent.is_dir())
    require(not any(parent.is_symlink() for parent in (path, *path.parents)))
    return path


def prepare(node_source, workspace, variant, go):
    require(variant in VARIANTS and type(go) is str and bool(go))
    workspace = private_destination(workspace)
    manifest_raw, manifest = SOURCE.source_manifest()
    original = SOURCE.snapshot_source(node_source, manifest["files"])
    guarded, patch = patch_source(original["chain/state_tree.go"])
    probe = (HERE / PROBE).read_bytes()
    require(len(probe) <= 32768)
    selected = dict(original)
    if variant == "startup-quarantine":
        selected["chain/state_tree.go"] = guarded
    pins = {name: dict(pin, git_blob=SOURCE.git_hash("blob", selected[name]),
                         sha256=sha(selected[name]), bytes=len(selected[name]))
            for name, pin in manifest["files"].items()}
    tree = SOURCE.reconstruct_tree(pins)
    if variant == "baseline":
        require(tree == SOURCE.NODE_TREE)
    else:
        require(tree == GUARDED_NODE_TREE and
                [name for name in selected if selected[name] != original[name]] == ["chain/state_tree.go"])
    workspace.mkdir(mode=0o700)
    node, generator = workspace / "node", workspace / "generator"
    generator.mkdir(mode=0o700)
    for name, raw in selected.items():
        destination = node / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(raw)
        destination.chmod(0o755 if manifest["files"][name]["mode"] == "100755" else 0o644)
    inserted = node / "chain" / PROBE
    require(not inserted.exists())
    inserted.write_bytes(probe)
    # Compile only this probe. Preserve every upstream file and use explicit Go
    # compiler overlays to exclude unrelated test-package imports/initializers.
    # This is a probe build, not execution of the upstream test suite.
    overlay_directory = workspace / "test-overlays"
    overlay_directory.mkdir(mode=0o700)
    overlays = {}
    for name in UPSTREAM_TESTS:
        original_test = selected["chain/" + name]
        require(b"//go:build" not in original_test and b"// +build" not in original_test)
        replacement = overlay_directory / name
        replacement.write_bytes(b"//go:build !candidate_startup_quarantine\n\n" + original_test)
        overlays[str(node / "chain" / name)] = str(replacement)
    overlay_file = workspace / "test-overlay.json"
    overlay_file.write_bytes(SOURCE.encoded({"Replace": overlays}))
    module = (HERE / "go.mod").read_bytes() + b"\nreplace github.com/zenon-network/go-zenon => ../node\n"
    (generator / "go.mod").write_bytes(module)
    (generator / "go.sum").write_bytes((HERE / "go.sum").read_bytes())
    binary = generator / "startup-quarantine.test"
    result = {"format_version": 1, "kind": "startup-quarantine-prepared-source",
              "variant": variant, "base_revision": SOURCE.NODE_REVISION, "base_tree": SOURCE.NODE_TREE,
              "selected_node_tree_without_probe": tree, "node_blob_count": len(original),
              "source_manifest_sha256": sha(manifest_raw),
              "state_tree_sha256": sha(selected["chain/state_tree.go"]), "probe_sha256": sha(probe),
              "patch_sha256": sha((HERE / PATCH).read_bytes()),
              "upstream_tests_excluded_by_explicit_compiler_overlay": list(UPSTREAM_TESTS),
              "overlay_sha256": sha(overlay_file.read_bytes()),
              "upstream_source_files_changed_by_overlay": False,
              "module_sha256": sha(module), "sum_sha256": sha((HERE / "go.sum").read_bytes()),
              "working_directory": str(generator), "binary": str(binary),
              "build_argv": [go, "test", "-c", "-p=1", "-mod=readonly", "-trimpath", "-overlay=" + str(overlay_file),
                             "-tags", "candidate_startup_quarantine", "-o", str(binary),
                             "github.com/zenon-network/go-zenon/chain"],
              "run_argv": [str(binary), "-test.v", "-test.run=^TestCandidateStartupQuarantine$"],
              "required_run_environment": {"ZENON_STARTUP_VARIANT": variant},
              "network_acquisition_performed": False, "reference_execution_performed": False,
              "upstream_modified": False, "production_qualified": False}
    SOURCE.seal(workspace / "prepared.json", SOURCE.encoded(result))
    require(SOURCE.snapshot_source(node_source, manifest["files"]) == original)
    verify(workspace, variant)
    return result


def verify(workspace, variant):
    require(variant in VARIANTS)
    workspace = Path(workspace)
    _, manifest = SOURCE.source_manifest()
    selected = json.loads((workspace / "prepared.json").read_bytes())
    require(selected["variant"] == variant)
    node = workspace / "node"
    actual = set()
    for path in node.rglob("*"):
        require(not path.is_symlink())
        if path.is_file():
            require(stat.S_ISREG(path.stat().st_mode) and path.stat().st_nlink == 1)
            actual.add(path.relative_to(node).as_posix())
    require(actual == set(manifest["files"]) | {"chain/" + PROBE})
    for name, pin in manifest["files"].items():
        raw = (node / name).read_bytes()
        expected = GUARDED_FILE_SHA256 if name == "chain/state_tree.go" and variant != "baseline" else pin["sha256"]
        require(sha(raw) == expected)
    require((node / "chain" / PROBE).read_bytes() == (HERE / PROBE).read_bytes())
    for name, key in (("go.mod", "module_sha256"), ("go.sum", "sum_sha256")):
        require(sha((workspace / "generator" / name).read_bytes()) == selected[key])
    overlay_file = workspace / "test-overlay.json"
    require(sha(overlay_file.read_bytes()) == selected["overlay_sha256"])
    overlay = json.loads(overlay_file.read_bytes())["Replace"]
    require(set(overlay) == {str(node / "chain" / name) for name in UPSTREAM_TESTS})
    for original_test, backing_file in overlay.items():
        require(Path(backing_file).read_bytes() == b"//go:build !candidate_startup_quarantine\n\n" + Path(original_test).read_bytes())
    return selected


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
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
        print("Startup quarantine preparation failed; preserve the selected inputs and partial workspace.", file=sys.stderr)
        sys.exit(1)

