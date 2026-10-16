#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Prepare a new current-node component workspace; execute no returned commands.

The caller supplies the complete selected 33d7 source and an explicitly owned,
quota-accounted, nonexistent destination. Source acquisition, offline dependency
provisioning and process supervision remain separate. Existing databases and
historical 56ce source selections are never adopted, migrated or overwritten.
"""
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
REVISION = "33d7d1ee1b6a915c40aea196e2a10f1e893d171f"
TREE = "40d71efb7e462d5bbd0f27d83ed7588e121c3cb6"
MODIFIED_TREE = "28c9eec1156633836357028e16a3958edbc635c4"
SOURCE_MANIFEST = "node-recovery-source-pins.json"
SOURCE_MANIFEST_SHA256 = "12ec9f524b1a4c3ba45344fa619f433df2b11a63eaf523ea695d9ca4ba84f460"
PATCH = "hash-bound-versions-patch.json"
PATCH_SHA256 = "a1a00190d81fcd5eed0326570d95b29e8869d82edd2c5a0804bb3af440e506ef"
PROBE = "hash_bound_versions_probe_test.go"
TAG = "candidate_hash_bound_versions"
VARIANTS = ("baseline", "hash-bound")
AFTER = {
    "chain/state_tree.go": "c4fad60ce7e56739eea6f688209f8e7062a6b80b750498d58651cac7fc060fc8",
    "common/trie/nodestore.go": "5de460eca7bade1dee6bf4340e6518ea677052868c27ccb07c0688597b494d9d",
}
MODULE_PINS = {
    "go.mod": "a0de865eafa939dc4acb62364284736095eb38108643ac44767dc5ea72269e9d",
    "go.sum": "b8d715d77c7ca1ea1ac9548df868f57753d434dbefd52ad6d5f3c49685dd7da1",
}
UPSTREAM_TESTS = (
    "account_pool_rollback_regression_test.go", "account_pool_test.go",
    "momentum_pool_test.go", "state_tree_ready_test.go",
    "state_tree_update_test.go", "test_suffix_fix_test.go",
)


def require(condition):
    if not condition:
        raise ValueError("Hash-bound node preparation refused")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def pairs(items):
    result = {}
    for key, value in items:
        require(key not in result)
        result[key] = value
    return result


def exact(actual, expected):
    require(type(actual) is type(expected))
    if type(expected) is dict:
        require(set(actual) == set(expected))
        for key in expected:
            exact(actual[key], expected[key])
    elif type(expected) is list:
        require(len(actual) == len(expected))
        for left, right in zip(actual, expected):
            exact(left, right)
    else:
        require(actual == expected)


def read_regular(path, limit):
    path = Path(path)
    require(not any(p.is_symlink() for p in (path, *path.parents)))
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= limit)
    with path.open("rb") as stream:
        raw = stream.read(limit + 1)
    require(len(raw) == info.st_size and len(raw) <= limit)
    return raw


def document(name, digest):
    raw = read_regular(HERE / name, 256 << 10)
    require(sha(raw) == digest)
    return raw, json.loads(raw, object_pairs_hook=pairs)


def load_utilities():
    # Reuse only pure Git/blob/inventory utilities. Do not invoke the historical
    # source selector or its reference writer and do not replace their globals.
    spec = importlib.util.spec_from_file_location("hash_bound_git_utilities", HERE / "regenerate.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


UTIL = load_utilities()


def source_manifest():
    raw, value = document(SOURCE_MANIFEST, SOURCE_MANIFEST_SHA256)
    require(set(value) == {"format_version", "kind", "repository", "revision", "tree",
                          "blob_count", "logical_blob_bytes", "files",
                          "historical_56ce_source_and_records_rebound"})
    require(type(value["format_version"]) is int and value["format_version"] == 1)
    require(value["kind"] == "selected-current-node-recovery-source")
    require(value["repository"] == "https://github.com/digitalSloth/go-zenon")
    require(value["revision"] == REVISION and value["tree"] == TREE)
    require(type(value["blob_count"]) is int and value["blob_count"] == 439)
    require(type(value["logical_blob_bytes"]) is int and value["logical_blob_bytes"] == 7138317)
    require(value["historical_56ce_source_and_records_rebound"] is False)
    require(type(value["files"]) is dict and len(value["files"]) == 439)
    for pin in value["files"].values():
        require(type(pin) is dict and set(pin) == {"mode", "git_blob", "sha256", "bytes"})
        require(type(pin["bytes"]) is int and 0 <= pin["bytes"] <= 16 << 20)
        require(type(pin["sha256"]) is str and re.fullmatch("[0-9a-f]{64}", pin["sha256"]))
        require(type(pin["git_blob"]) is str and re.fullmatch("[0-9a-f]{40}", pin["git_blob"]))
    require(sum(v["bytes"] for v in value["files"].values()) == 7138317)
    require(UTIL.reconstruct_tree(value["files"]) == TREE)
    tests = sorted(name[6:] for name in value["files"] if name.startswith("chain/") and
                   "/" not in name[6:] and name.endswith("_test.go"))
    require(tests == list(UPSTREAM_TESTS))
    return raw, value


def snapshot_source(root, pins):
    root = Path(root).absolute()
    require(root.is_dir() and not any(p.is_symlink() for p in (root, *root.parents)))
    for name in pins:
        info = (root / name).lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1)
    return UTIL.snapshot_source(root, pins)


def patch_source(original):
    _, patch = document(PATCH, PATCH_SHA256)
    require(set(patch) == {"format_version", "kind", "repository", "base_revision", "base_tree",
                          "base_blob_count", "modified_node_tree_without_probe", "files",
                          "disk_format_before", "disk_format_after", "retained_hash_record",
                          "experimental_only", "automatic_existing_database_migration",
                          "automatic_incompatible_database_wipe", "SMT_root_and_proof_profile_changed",
                          "node_client_protocol_profile_agreed", "accepted_v3_header_binding_qualified",
                          "production_qualified"})
    require(type(patch["format_version"]) is int and patch["format_version"] == 1)
    require(patch["kind"] == "experimental-hash-bound-retained-node-versions")
    require(patch["repository"] == "https://github.com/digitalSloth/go-zenon")
    require(patch["base_revision"] == REVISION and patch["base_tree"] == TREE)
    require(type(patch["base_blob_count"]) is int and patch["base_blob_count"] == 439)
    require(patch["modified_node_tree_without_probe"] == MODIFIED_TREE)
    require(type(patch["disk_format_before"]) is int and patch["disk_format_before"] == 2)
    require(type(patch["disk_format_after"]) is int and patch["disk_format_after"] == 3)
    require(patch["retained_hash_record"] == "06 || uint64_be(height) -> Momentum_hash_32")
    require(patch["experimental_only"] is True)
    require(all(patch[k] is False for k in (
        "automatic_existing_database_migration", "automatic_incompatible_database_wipe",
        "SMT_root_and_proof_profile_changed", "node_client_protocol_profile_agreed",
        "accepted_v3_header_binding_qualified", "production_qualified")))
    require(type(patch["files"]) is dict and set(patch["files"]) == set(AFTER))
    modified = dict(original)
    for name, row in patch["files"].items():
        require(set(row) == {"before_sha256", "before_git_blob", "before_bytes", "after_sha256",
                             "after_git_blob", "after_bytes", "mode", "replacements"})
        raw = original[name]
        require(type(row["before_bytes"]) is int and len(raw) == row["before_bytes"])
        require(sha(raw) == row["before_sha256"] and UTIL.git_hash("blob", raw) == row["before_git_blob"])
        require(row["mode"] == "100644" and row["after_sha256"] == AFTER[name])
        require(type(row["replacements"]) is list and 1 <= len(row["replacements"]) <= 32)
        text = raw.decode("utf-8")
        for change in row["replacements"]:
            require(type(change) is dict and set(change) == {"before", "after"})
            require(all(type(change[k]) is str and bool(change[k]) for k in ("before", "after")))
            require(text.count(change["before"]) == 1)
            text = text.replace(change["before"], change["after"])
        modified[name] = text.encode("utf-8")
        require(type(row["after_bytes"]) is int and len(modified[name]) == row["after_bytes"])
        require(sha(modified[name]) == row["after_sha256"])
        require(UTIL.git_hash("blob", modified[name]) == row["after_git_blob"])
        for change in reversed(row["replacements"]):
            require(text.count(change["after"]) == 1)
            text = text.replace(change["after"], change["before"])
        require(text.encode("utf-8") == raw)
    require({name for name in original if original[name] != modified[name]} == set(AFTER))
    return modified, patch


def private_destination(path):
    path = Path(path).absolute()
    require(not path.exists() and not path.is_symlink() and path.parent.is_dir())
    require(not any(p.is_symlink() for p in (path, *path.parents)))
    return path


def frozen_module():
    values = {name: read_regular(HERE / name, 1 << 20) for name in MODULE_PINS}
    require(all(sha(raw) == MODULE_PINS[name] for name, raw in values.items()))
    return values


def plan(workspace, variant, go, pins, probe, overlay):
    generator = workspace / "generator"
    overlay_file = workspace / "test-overlay.json"
    modules = frozen_module()
    module = modules["go.mod"] + b"\nreplace github.com/zenon-network/go-zenon => ../node\n"
    binary = generator / "hash-bound-versions.test"
    return {
        "format_version": 1, "kind": "hash-bound-retained-versions-prepared-source",
        "variant": variant, "base_revision": REVISION, "base_tree": TREE,
        "selected_node_tree_without_probe": UTIL.reconstruct_tree(pins),
        "node_blob_count": 439, "source_manifest_sha256": SOURCE_MANIFEST_SHA256,
        "patch_sha256": PATCH_SHA256, "probe_sha256": sha(probe),
        "changed_runtime_files": sorted(AFTER) if variant == "hash-bound" else [],
        "disk_format": 3 if variant == "hash-bound" else 2,
        "upstream_tests_excluded_by_explicit_compiler_overlay": list(UPSTREAM_TESTS),
        "overlay_sha256": sha(UTIL.encoded(overlay)),
        "upstream_source_files_changed_by_overlay": False,
        "module_sha256": sha(module), "sum_sha256": sha(modules["go.sum"]),
        "working_directory": str(generator), "binary": str(binary),
        "build_argv": [go, "test", "-c", "-p=1", "-mod=readonly", "-trimpath",
                       "-buildvcs=false", "-overlay=" + str(overlay_file), "-tags", TAG,
                       "-o", str(binary), "github.com/zenon-network/go-zenon/chain"],
        "run_argv": [str(binary), "-test.v", "-test.run=^TestCandidateHashBoundVersions$"],
        "required_run_environment": {"ZENON_HASH_BOUND_VARIANT": variant},
        "source_copy_method": "explicit-independent-files-from-verified-bytes",
        "network_acquisition_performed": False, "reference_execution_performed": False,
        "historical_reference_writer_executed": False, "upstream_modified": False,
        "production_qualified": False,
    }


def prepare(node_source, workspace, variant, go):
    require(variant in VARIANTS and type(go) is str and bool(go))
    workspace = private_destination(workspace)
    _, manifest = source_manifest()
    original = snapshot_source(node_source, manifest["files"])
    guarded, _ = patch_source(original)
    selected = guarded if variant == "hash-bound" else original
    probe = read_regular(HERE / PROBE, 128 << 10)
    require(b"//go:build " + TAG.encode() in probe and b"package chain" in probe)
    pins = {name: dict(pin, git_blob=UTIL.git_hash("blob", selected[name]),
                      sha256=sha(selected[name]), bytes=len(selected[name]))
            for name, pin in manifest["files"].items()}
    require(UTIL.reconstruct_tree(pins) == (MODIFIED_TREE if variant == "hash-bound" else TREE))
    workspace.mkdir(mode=0o700)
    node, generator = workspace / "node", workspace / "generator"
    generator.mkdir(mode=0o700)
    for name, raw in selected.items():
        path = node / name
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as stream:
            stream.write(raw)
        path.chmod(0o755 if pins[name]["mode"] == "100755" else 0o644)
    with (node / "chain" / PROBE).open("xb") as stream:
        stream.write(probe)
    backing = workspace / "test-overlays"
    backing.mkdir(mode=0o700)
    overlay = {"Replace": {}}
    for name in UPSTREAM_TESTS:
        raw = selected["chain/" + name]
        require(b"//go:build" not in raw and b"// +build" not in raw)
        destination = backing / name
        destination.write_bytes(b"//go:build !" + TAG.encode() + b"\n\n" + raw)
        overlay["Replace"][str(node / "chain" / name)] = str(destination)
    (workspace / "test-overlay.json").write_bytes(UTIL.encoded(overlay))
    modules = frozen_module()
    (generator / "go.mod").write_bytes(modules["go.mod"] + b"\nreplace github.com/zenon-network/go-zenon => ../node\n")
    (generator / "go.sum").write_bytes(modules["go.sum"])
    selected_plan = plan(workspace, variant, go, pins, probe, overlay)
    UTIL.seal(workspace / "prepared.json", UTIL.encoded(selected_plan))
    require(snapshot_source(node_source, manifest["files"]) == original)
    verify(workspace, variant)
    return selected_plan


def verify(workspace, variant):
    require(variant in VARIANTS)
    workspace = Path(workspace).absolute()
    require(workspace.is_dir() and not any(p.is_symlink() for p in (workspace, *workspace.parents)))
    _, manifest = source_manifest()
    selected = json.loads(read_regular(workspace / "prepared.json", 128 << 10), object_pairs_hook=pairs)
    require(selected["variant"] == variant)
    node = workspace / "node"
    actual = set()
    for path in node.rglob("*"):
        require(not path.is_symlink())
        if path.is_file():
            require(stat.S_ISREG(path.stat().st_mode) and path.stat().st_nlink == 1)
            actual.add(path.relative_to(node).as_posix())
    require(actual == set(manifest["files"]) | {"chain/" + PROBE})
    pins = {}
    for name, pin in manifest["files"].items():
        raw = read_regular(node / name, 16 << 20)
        expected = AFTER[name] if variant == "hash-bound" and name in AFTER else pin["sha256"]
        require(sha(raw) == expected)
        pins[name] = dict(pin, sha256=sha(raw), bytes=len(raw), git_blob=UTIL.git_hash("blob", raw))
    probe = read_regular(HERE / PROBE, 128 << 10)
    require(read_regular(node / "chain" / PROBE, 128 << 10) == probe)
    modules = frozen_module()
    require(read_regular(workspace / "generator/go.mod", 1 << 20) ==
            modules["go.mod"] + b"\nreplace github.com/zenon-network/go-zenon => ../node\n")
    require(read_regular(workspace / "generator/go.sum", 1 << 20) == modules["go.sum"])
    overlay = {"Replace": {str(node / "chain" / name): str(workspace / "test-overlays" / name)
                           for name in UPSTREAM_TESTS}}
    require(read_regular(workspace / "test-overlay.json", 128 << 10) == UTIL.encoded(overlay))
    for name in UPSTREAM_TESTS:
        require(read_regular(workspace / "test-overlays" / name, 1 << 20) ==
                b"//go:build !" + TAG.encode() + b"\n\n" + read_regular(node / "chain" / name, 1 << 20))
    exact(selected, plan(workspace, variant, selected["build_argv"][0], pins, probe, overlay))
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
    except (OSError, ValueError, KeyError, TypeError, IndexError):
        print("Hash-bound node preparation refused; preserve inputs and partial workspace.", file=sys.stderr)
        sys.exit(1)
