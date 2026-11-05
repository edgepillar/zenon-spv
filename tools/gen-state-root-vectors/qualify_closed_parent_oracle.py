#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Build the offline source oracle in a fresh, owned hosted-CI workspace.

No chain/consensus service, wallet, transaction or live ledger is used. The
native H1 fixture is newly created by the selected Go test and is disposable.
Raw command streams are retained once, with actual exit and EOF information.
This does not measure peak disk/RSS or authenticate execution/distribution.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import threading
import time

NODE_REPOSITORY = "https://github.com/digitalSloth/go-zenon.git"
NODE_REVISION = "938fca3b7787da86827a5eb63371509b36e14761"
NODE_TREE = "f3b7947d2267ebdb806f18ff0c02bba5bffae9c4"
GENESIS_SHA256 = "0dd33b18b147f70b3d3d5f07199a2b45311f6e9b84a98b3f86d8f6c6b45f419a"
GIB = 1 << 30
FREE_FLOOR = 10 * GIB
EXPECTED_ALLOCATION = GIB
SAFETY_MARGIN = GIB
MAX_SOURCE_FILE = 4 << 20
MAX_SOURCE_TOTAL = 64 << 20
MAX_BINARY = 32 << 20
MAX_STREAM = 2 << 20
ROOT = Path(__file__).resolve().parents[2]
INPUTS = {
    "tools/gen-state-root-vectors/parent-schedule-adapter.go.txt": "consensus/spv_parent_schedule_adapter.go",
    "tools/gen-state-root-vectors/closed-devnet-parent-oracle.go.txt": "cmd/spv-closed-parent-oracle/main.go",
    "tools/gen-state-root-vectors/closed-devnet-parent-oracle_test.go.txt": "cmd/spv-closed-parent-oracle/main_test.go",
    "internal/testdata/conformance/selected-parent-slots.json": "cmd/spv-closed-parent-oracle/testdata/source-h1-slots.json",
}


class Refused(Exception):
    pass


def require(value, reason):
    if not value:
        raise Refused(reason)


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode("ascii")


def digest(raw):
    return {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}


def regular(path, limit):
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_size <= limit, "regular_input_bound")
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        require(os.path.samestat(before, opened), "input_identity")
        raw = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
    require(len(raw) == before.st_size == after.st_size and len(raw) <= limit
            and os.path.samestat(before, after) and os.path.samestat(after, path.lstat()), "input_changed")
    return raw


def seal(path, raw):
    with path.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    path.chmod(0o400)
    return digest(raw)


def space(root):
    free = shutil.disk_usage(root).free
    require(free >= FREE_FLOOR + EXPECTED_ALLOCATION + SAFETY_MARGIN, "free_space_floor")
    return {"free_bytes": free, "floor_bytes": FREE_FLOOR,
            "expected_allocation_bytes": EXPECTED_ALLOCATION, "safety_margin_bytes": SAFETY_MARGIN,
            "OS_disk_quota_or_peak_measurement": False}


def capture(argv, cwd, *, cap=MAX_STREAM, timeout=600, env=None):
    """Bound both anonymous pipes; stop/reap only the directly created child.

    On a timeout or unresolved descendant stream, output is incomplete even if
    an exit is observed. This is not a process-tree cleanup guarantee on Windows.
    """
    require(type(cap) is int and 0 < cap <= 4 << 20 and 0 < timeout <= 900, "command_limits")
    buffers = {name: bytearray() for name in ("stdout", "stderr")}
    rows = {name: {"eof": False, "observed_bytes": 0, "truncated": False, "read_error": False}
            for name in buffers}
    record = {"actual_exit": None, "launch_failed": False, "timed_out": False,
              "output_complete": False, "readers_joined": False, "streams": rows}
    stop = threading.Event()
    try:
        child = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError:
        record["launch_failed"] = True
        for row in rows.values():
            row.update(digest(b""), captured_bytes=0)
        return {name: b"" for name in buffers}, record

    def drain(name, pipe):
        row = rows[name]
        try:
            while True:
                chunk = pipe.read(min(8192, cap + 1 - row["observed_bytes"]))
                if not chunk:
                    row["eof"] = True
                    break
                row["observed_bytes"] += len(chunk)
                buffers[name].extend(chunk[:max(0, cap - len(buffers[name]))])
                if row["observed_bytes"] > cap:
                    row["truncated"] = True
                    stop.set()
                    break
        except OSError:
            row["read_error"] = True
            stop.set()
        finally:
            pipe.close()

    readers = [threading.Thread(target=drain, args=(name, getattr(child, name)), daemon=True)
               for name in buffers]
    started = []
    try:
        for reader in readers:
            reader.start()
            started.append(reader)
        deadline = time.monotonic() + timeout
        while child.poll() is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                record["timed_out"] = True
                break
            if stop.wait(min(0.05, remaining)):
                break
        if child.poll() is None:
            child.kill()
        try:
            record["actual_exit"] = child.wait(timeout=2)
        except subprocess.TimeoutExpired:
            pass
    finally:
        if child.poll() is None:
            child.kill()
            try:
                record["actual_exit"] = child.wait(timeout=2)
            except subprocess.TimeoutExpired:
                pass
        for reader in started:
            reader.join(timeout=2)
        for reader, name in zip(readers, buffers):
            if reader not in started:
                getattr(child, name).close()
    record["readers_joined"] = all(not reader.is_alive() for reader in readers)
    raw = {name: bytes(value) for name, value in buffers.items()}
    for name, row in rows.items():
        row.update(digest(raw[name]), captured_bytes=len(raw[name]))
    record["output_complete"] = (record["actual_exit"] is not None
        and not record["timed_out"] and record["readers_joined"]
        and all(row["eof"] and not row["truncated"] and not row["read_error"] for row in rows.values()))
    return raw, record


def command(output, label, argv, cwd, records, *, cap=MAX_STREAM, timeout=600, env=None):
    require(re.fullmatch(r"[a-z][a-z0-9-]{0,63}", label) is not None, "command_label")
    raw, receipt = capture(argv, cwd, cap=cap, timeout=timeout, env=env)
    receipt["label"] = label
    receipt["outputs"] = {name: {"file": label + "." + name,
                                  **seal(output / (label + "." + name), value)}
                          for name, value in raw.items()}
    receipt_ref = seal(output / (label + ".json"), encoded(receipt))
    records.append({"label": label, "receipt": receipt_ref, "file": label + ".json"})
    require(receipt["actual_exit"] == 0 and type(receipt["actual_exit"]) is int
            and receipt["output_complete"], "command_incomplete_or_failed")
    return raw["stdout"]


def git(output, label, args, cwd, records):
    env = dict(os.environ, GIT_NO_REPLACE_OBJECTS="1", GIT_OPTIONAL_LOCKS="0", GIT_TERMINAL_PROMPT="0")
    return command(output, label, ["git", "--no-optional-locks", "-c", "core.fsmonitor=false", *args],
                   cwd, records, cap=256 << 10, timeout=120, env=env)


def context(platform):
    require(os.environ.get("GITHUB_ACTIONS") == "true"
            and os.environ.get("GITHUB_REPOSITORY") == "edgepillar/zenon-spv", "owned_CI_context")
    checkout = os.environ.get("GITHUB_SHA", "")
    feature = os.environ.get("SPV_FEATURE_REVISION", "")
    event = os.environ.get("GITHUB_EVENT_NAME", "")
    require(event in ("push", "pull_request") and re.fullmatch("[a-f0-9]{40}", checkout) is not None
            and re.fullmatch("[a-f0-9]{40}", feature) is not None, "selected_source_context")
    values = [os.environ.get(name, "") for name in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")]
    require(all(re.fullmatch("[1-9][0-9]*", value) is not None for value in values), "run_context")
    require(platform == {"linux": "linux-amd64", "darwin": "darwin-amd64", "win32": "windows-amd64"}.get(sys.platform),
            "native_platform")
    return {"repository": "edgepillar/zenon-spv", "workflow": "closed-devnet-parent-oracle",
            "event": event, "source_revision": checkout, "feature_revision": feature,
            "run_id": int(values[0]), "run_attempt": int(values[1]), "platform": platform}


def source_inventory(node, index):
    require(index.endswith(b"\0") and 0 < len(index) <= 256 << 10, "source_index")
    result, total = {}, 0
    for record in index.split(b"\0")[:-1]:
        match = re.fullmatch(rb"(?:100644|100755) ([a-f0-9]{40}) 0\t([ -~]+)", record)
        require(match is not None, "original_source_mode_or_path")
        oid, raw_path = match.groups()
        name = raw_path.decode("ascii")
        parts = name.split("/")
        require(not name.startswith("/") and "\\" not in name
                and all(part not in ("", ".", "..", ".git") for part in parts) and name not in result,
                "source_path")
        raw = regular(node / name, MAX_SOURCE_FILE)
        require(hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest() == oid.decode(),
                "original_source_blob")
        result[name] = digest(raw)
        total += len(raw)
        require(total <= MAX_SOURCE_TOTAL and len(result) <= 2048, "source_total_bound")
    require(len(result) >= 400, "incomplete_original_source")
    return result


def installed_inputs(node):
    result = {}
    for source, target in INPUTS.items():
        raw = regular(ROOT / source, MAX_SOURCE_FILE)
        require(regular(node / target, MAX_SOURCE_FILE) == raw, "added_source_changed")
        result[source] = {"added_path": target, **digest(raw)}
    return result


def selected_sources(index, paths):
    """Bind working helper bytes to the selected Git index, never a path label.

    Only the workflow YAML may have a CRLF checkout spelling; its execution
    input is the canonical Git blob. Compiled and interpreted helper inputs
    must be byte-exact. The caller separately verifies index == HEAD.
    """
    require(index.endswith(b"\0") and len(index) <= 256 << 10, "SPV_source_index")
    result, working = {}, {}
    for record in index.split(b"\0")[:-1]:
        match = re.fullmatch(rb"100644 ([a-f0-9]{40}) 0\t([ -~]+)", record)
        require(match is not None, "SPV_source_mode")
        oid, raw_name = match.groups()
        name = raw_name.decode("ascii")
        require(name in paths and name not in result, "SPV_source_path")
        raw = regular(ROOT / name, MAX_SOURCE_FILE)
        canonical = raw
        def blob(value):
            return hashlib.sha1(b"blob " + str(len(value)).encode() + b"\0" + value).hexdigest().encode()
        relation = "exact"
        if blob(raw) != oid:
            require(name.endswith(".yml") and b"\r\n" in raw, "SPV_working_source")
            canonical = raw.replace(b"\r\n", b"\n")
            require(blob(canonical) == oid, "SPV_workflow_source")
            relation = "CRLF-only"
        result[name] = digest(canonical)
        working[name] = {**digest(raw), "relation": relation}
    require(set(result) == set(paths), "SPV_source_coverage")
    return result, working


def owned_scope(work, output, selected):
    if selected is None:
        return False
    try:
        scope = json.loads(regular(work / "scope.json", 4096))
        return (scope["format"] == "owned-closed-parent-oracle-scope/v1"
                and scope["context"] == selected
                and not work.is_symlink() and not output.is_symlink()
                and [work.stat().st_dev, work.stat().st_ino] == scope["work_identity"]
                and [output.stat().st_dev, output.stat().st_ino] == scope["output_identity"])
    except (Refused, OSError, ValueError, KeyError, TypeError):
        return False


def stage(work, output, selected, records):
    require(not work.exists() and not work.is_symlink() and not output.exists() and not output.is_symlink(),
            "fresh_workspace_required")
    require(work.parent.is_dir() and output.parent.is_dir() and work != output
            and work not in output.parents and output not in work.parents, "workspace_separation")
    allocation = space(work.parent)
    work.mkdir(mode=0o700)
    output.mkdir(mode=0o700)
    seal(work / "scope.json", encoded({"format": "owned-closed-parent-oracle-scope/v1", "context": selected,
         "work_identity": [work.stat().st_dev, work.stat().st_ino],
         "output_identity": [output.stat().st_dev, output.stat().st_ino]}))
    node = work / "node"
    git(output, "node-init", ["init", "--quiet", str(node)], work, records)
    git(output, "node-line-endings", ["config", "--local", "core.autocrlf", "false"], node, records)
    git(output, "node-fetch", ["fetch", "--quiet", "--depth=1", "--no-tags", NODE_REPOSITORY, NODE_REVISION], node, records)
    git(output, "node-checkout", ["checkout", "--quiet", "--detach", "FETCH_HEAD"], node, records)
    head = git(output, "node-head", ["rev-parse", "HEAD"], node, records).decode().strip()
    tree = git(output, "node-tree", ["rev-parse", "HEAD^{tree}"], node, records).decode().strip()
    require((head, tree) == (NODE_REVISION, NODE_TREE), "node_source_pin")
    require(git(output, "node-clean", ["status", "--porcelain=v1"], node, records) == b"", "original_source_dirty")
    index = git(output, "node-index", ["ls-files", "--stage", "-z"], node, records)
    original = source_inventory(node, index)
    require(original["docker/devnet/genesis.json"] == {"sha256": GENESIS_SHA256, "bytes": 8137}, "genesis_source_pin")
    for source, target in INPUTS.items():
        destination = node / target
        require(not destination.exists() and not destination.is_symlink(), "added_path_exists")
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("xb") as stream:
            stream.write(regular(ROOT / source, MAX_SOURCE_FILE))
    inputs = installed_inputs(node)
    marker = {"format": "owned-closed-parent-oracle-work/v1", "context": selected,
              "work_identity": [work.stat().st_dev, work.stat().st_ino],
              "output_identity": [output.stat().st_dev, output.stat().st_ino],
              "node_identity": [node.stat().st_dev, node.stat().st_ino],
              "original_sources": original, "inputs": inputs}
    marker_pin = seal(work / "ownership.json", encoded(marker))
    seal(output / "preparation.json", encoded({"format": "closed-parent-oracle-preparation/v1", "context": selected,
         "node_repository": NODE_REPOSITORY, "node_revision": head, "node_tree": tree,
         "original_sources": original, "added_inputs": inputs, "commands": records,
         "ownership_sha256": marker_pin["sha256"], "allocation_admission": allocation,
         "native_execution": False, "signing_or_transaction": False}))


def qualify(work, output, selected, records):
    require(owned_scope(work, output, selected), "owned_stage_scope")
    marker = json.loads(regular(work / "ownership.json", 256 << 10))
    node = work / "node"
    require(marker["format"] == "owned-closed-parent-oracle-work/v1" and marker["context"] == selected,
            "owned_stage_context")
    for path, key in ((work, "work_identity"), (output, "output_identity"), (node, "node_identity")):
        require(not path.is_symlink() and [path.stat().st_dev, path.stat().st_ino] == marker[key], "owned_stage_identity")
    require(installed_inputs(node) == marker["inputs"], "input_stage_changed")
    index = git(output, "qualified-node-index", ["ls-files", "--stage", "-z"], node, records)
    require(source_inventory(node, index) == marker["original_sources"], "original_source_changed")
    allocation = space(work)
    go_raw = command(output, "go-environment", ["go", "env", "-json", "GOOS", "GOARCH", "GOVERSION", "CGO_ENABLED"], node, records)
    go = json.loads(go_raw)
    require(go["GOOS"] + "-" + go["GOARCH"] == selected["platform"] and go["GOVERSION"] == "go1.25.14"
            and go["CGO_ENABLED"] == "0", "selected_toolchain")
    command(output, "native-test", ["go", "test", "-mod=readonly", "-p=2", "-tags", "devnet", "-json", "-count=1",
                                    "-timeout=90s", "./cmd/spv-closed-parent-oracle"], node, records)
    binary = output / "spv-closed-parent-oracle.exe"
    command(output, "native-build", ["go", "build", "-mod=readonly", "-p=2", "-tags", "devnet", "-trimpath", "-buildvcs=false",
                                     "-o", str(binary), "./cmd/spv-closed-parent-oracle"], node, records)
    module_raw = command(output, "binary-module-info", ["go", "version", "-m", binary.name], output, records, cap=128 << 10)
    # Use a relative binary name so the raw stream has no owned workspace path.
    module_rows = module_raw.decode().splitlines()[1:]
    require(module_rows and all(line.startswith("\t") for line in module_rows), "module_info")
    require(source_inventory(node, index) == marker["original_sources"] and installed_inputs(node) == marker["inputs"],
            "source_drift_after_execution")
    require(git(output, "node-head-after", ["rev-parse", "HEAD"], node, records).decode().strip() == NODE_REVISION
            and git(output, "node-tree-after", ["rev-parse", "HEAD^{tree}"], node, records).decode().strip() == NODE_TREE,
            "node_revision_after_execution")
    git(output, "node-index-after", ["diff", "--cached", "--exit-code", "HEAD"], node, records)
    status = git(output, "node-working-after", ["status", "--porcelain=v1", "-z", "--untracked-files=all"], node, records)
    require(sorted(status.split(b"\0")[:-1]) == sorted(b"?? " + path.encode() for path in INPUTS.values()),
            "unexpected_node_working_change")
    spv_revision = git(output, "spv-source-head", ["rev-parse", "HEAD"], ROOT, records).decode().strip()
    require(spv_revision == selected["source_revision"], "SPV_source_revision")
    source_tree = git(output, "spv-source-tree", ["rev-parse", "HEAD^{tree}"], ROOT, records).decode().strip()
    public_paths = (
        *INPUTS, "tools/gen-state-root-vectors/qualify_closed_parent_oracle.py",
        "tools/gen-state-root-vectors/qualify_closed_parent_oracle_test.py",
        ".github/workflows/closed-devnet-parent-oracle.yml")
    git(output, "spv-index-clean", ["diff", "--cached", "--exit-code", "HEAD"], ROOT, records)
    selected_index = git(output, "spv-selected-index", ["ls-files", "--stage", "-z", "--", *public_paths], ROOT, records)
    public_files, working_sources = selected_sources(selected_index, public_paths)
    for name in ("LICENSE",):
        seal(output / ("NODE_" + name), regular(node / name, 64 << 10))
    source_dir = output / "source-inputs"
    source_dir.mkdir()
    for number, name in enumerate(INPUTS):
        seal(source_dir / (str(number) + "-" + Path(name).name), regular(ROOT / name, MAX_SOURCE_FILE))
    source_note = ("This offline helper is linked with GPL-3.0 go-zenon.\n"
                   "Original node source: https://github.com/digitalSloth/go-zenon/tree/" + NODE_REVISION + "\n"
                   "SPV helper source: https://github.com/edgepillar/zenon-spv/tree/" + spv_revision + "\n"
                   "The exact added source inputs and node license accompany this artifact.\n"
                   "Build recipe: docs/closed-devnet-parent-oracle.md at the SPV source revision.\n"
                   "These CI controls are not a release or authenticated distribution.\n").encode("ascii")
    seal(output / "SOURCE.txt", source_note)
    manifest = {"format": "zenon-closed-parent-oracle-ci/v1", "status": "NATIVE_H1_CONTROLS_PASSED",
                **selected, "source_tree": source_tree, "node_repository": NODE_REPOSITORY,
                "node_revision": NODE_REVISION, "node_tree": NODE_TREE, "source_files": public_files,
                "working_sources": working_sources,
                "node_original_files": len(marker["original_sources"]), "node_original_sources_unchanged": True,
                "go": go, "binary": {"name": binary.name, **digest(regular(binary, MAX_BINARY))},
                "binary_module_info": module_rows, "commands": records, "allocation_admission": allocation,
                "scope": {"source_H1_fixture": True, "complete_positive_command_on_real_devnet": False,
                          "Chain_Init_in_reader": False, "Chain_Start_called": False, "consensus_Start_called": False,
                          "signing_or_transaction": False, "accepting_schedule_created": False,
                          "actual_devnet_capture": False, "header_or_value_accepted": False,
                          "independent_module_h1_replay": False, "peak_disk_or_RSS_measured": False,
                          "authenticated_distribution": False, "production_qualified": False}}
    seal(output / "manifest.json", encoded(manifest))
    return manifest


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("prepare", "qualify"), required=True)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--platform", choices=("linux-amd64", "darwin-amd64", "windows-amd64"), required=True)
    args = parser.parse_args(argv)
    records, selected = [], None
    try:
        selected = context(args.platform)
        if args.mode == "prepare":
            stage(args.workspace, args.evidence, selected, records)
            result = {"format": "closed-parent-oracle-stage-complete/v1", "context": selected, "native_execution": False}
        else:
            manifest = qualify(args.workspace, args.evidence, selected, records)
            result = {"format": "closed-parent-oracle-qualification-complete/v1", "context": selected,
                      "manifest_sha256": digest(encoded(manifest))["sha256"], "actual_devnet_capture": False}
        print(json.dumps(result, sort_keys=True))
        return 0
    except (Refused, OSError, ValueError, KeyError, UnicodeError) as error:
        # An existing refusal/failure packet is never replaced. A prior stage
        # remains available; failure does not authorize deleting the workspace.
        if owned_scope(args.workspace, args.evidence, selected):
            failure = {"format": "closed-parent-oracle-qualification-failure/v1", "mode": args.mode,
                       "error_type": type(error).__name__, "commands": records, "status": "FAILURE_OR_UNKNOWN"}
            path = args.evidence / ("failure-" + args.mode + ".json")
            if not path.exists():
                seal(path, encoded(failure))
        print("Closed parent oracle qualification refused; retain owned command evidence.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
