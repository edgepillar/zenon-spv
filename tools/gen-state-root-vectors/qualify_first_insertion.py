#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Observe original point catch-up on an isolated unsigned H2, without a node.

Only fresh hosted workspaces are written. Original node sources are verified
against Git blobs before and after execution. No wallet, signature, RPC, peer,
live transaction or accepted header is involved. Retain failed command streams.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import math
import os
from pathlib import Path
import shutil
import sys

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("first_insertion_common", HERE / "qualify_closed_parent_oracle.py")
C = importlib.util.module_from_spec(spec)
spec.loader.exec_module(C)
require, Refused = C.require, C.Refused
ROOT = HERE.parents[1]
INPUT = "tools/gen-state-root-vectors/first-insertion-catchup_test.go.txt"
INPUTS = {INPUT: "consensus/spv_first_insertion_catchup_test.go",
          "tools/gen-state-root-vectors/first-insertion-cpu_test.go.txt": "consensus/spv_first_insertion_cpu_test.go",
          "tools/gen-state-root-vectors/first-insertion-export_test.go.txt": "consensus/spv_first_insertion_export_test.go"}
WORKFLOW = ".github/workflows/first-insertion-catchup.yml"
PUBLIC_PATHS = (*INPUTS, WORKFLOW, ".gitattributes", "tools/gen-state-root-vectors/qualify_first_insertion.py",
                "tools/gen-state-root-vectors/qualify_first_insertion_test.py",
                "tools/gen-state-root-vectors/qualify_closed_parent_oracle.py",
                "docs/first-insertion-catchup.md")
CASES = {"one-period": 300, "one-day": 86400, "fixture-window": 54815400}
TEST = "TestSPVFirstInsertionCatchup"
PACKAGE = "github.com/zenon-network/go-zenon/consensus"
MARKER = "SPV_FIRST_INSERTION_CATCHUP "
CPU_MARKER = "SPV_FIRST_INSERTION_CPU "
VISIBILITY_MARKER = "SPV_FIRST_INSERTION_VISIBILITY "
CPU_LIMITS = {"reference": "max 100000", "half-core": "50000 100000"}
# Resources from the reference-gas contract used by the historical signed run.
FIXTURE_CONTRACT = "6f67a35cf6db1e2fd91a529880b9fa555461a4687ed0a76d9a27c900ca6b6f31"
FIXTURE_MEMORY_BYTES = 768 << 20
FIXTURE_READINESS_SECONDS = 90
FALSE_FIELDS = frozenset(("Chain_Start", "consensus_Start", "wallet_or_signing", "network_or_broadcast",
    "actual_fixture_cause_established", "accepted_header_authority", "new_devnet_acceptance_established",
    "peak_disk_or_RSS_measured"))
TRUE_FIELDS = frozenset(("original_points_listener_completed", "real_LevelDB_managers",
                        "owned_databases_closed", "unsigned_test_fixture_bypasses_authentication"))
INTEGER_FIELDS = frozenset(("source_genesis_unix", "unsigned_H2_unix", "gap_seconds", "period_seconds",
    "completed_periods", "completed_epochs", "consensus_get_calls", "consensus_put_calls",
    "consensus_put_value_bytes", "closed_consensus_files", "closed_consensus_logical_bytes"))


def decode(raw):
    def pairs(values):
        result = {}
        for key, value in values:
            require(key not in result, "duplicate_JSON_field")
            result[key] = value
        return result

    def constant(_):
        raise Refused("nonfinite_JSON_number")

    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    except (ValueError, UnicodeError) as error:
        raise Refused("invalid_JSON") from error


def selected_trace(text, marker):
    require(text.endswith("\n") and text.count(marker) == 1, "native_trace_count")
    line, = [line for line in text.splitlines() if marker in line]
    return decode(line.split(marker, 1)[1].strip())


def cpu_observation(text, profile):
    row = selected_trace(text, CPU_MARKER)
    require(type(row) is dict and set(row) == {"format", "profile", "cpu_max", "memory_max_bytes",
             "memory_swap_max_bytes", "gomaxprocs", "listener_cpu_delta"}, "cpu_trace_fields")
    require(row["format"] == "first-insertion-cpu-observation/v1" and row["profile"] == profile
            and row["cpu_max"] == CPU_LIMITS[profile], "cpu_trace_limit")
    for name, expected in (("memory_max_bytes", FIXTURE_MEMORY_BYTES), ("memory_swap_max_bytes", 0),
                           ("gomaxprocs", 1)):
        require(type(row[name]) is int and row[name] == expected, "cpu_trace_environment")
    delta = row["listener_cpu_delta"]
    require(type(delta) is dict and set(delta) == {"usage_usec", "nr_periods", "nr_throttled", "throttled_usec"}
            and all(type(v) is int and 0 <= v < 1 << 40 for v in delta.values())
            and delta["usage_usec"] > 0, "cpu_trace_delta")
    return row


def insertion_visibility(text):
    row = selected_trace(text, VISIBILITY_MARKER)
    require(type(row) is dict and set(row) == {
        "format", "before_height", "during_height", "callback_held_during_read",
        "insert_returned_after_release", "accepted_header_authority",
    }, "frontier_visibility_fields")
    require(row["format"] == "first-insertion-frontier-visibility/v1"
            and type(row["before_height"]) is int and row["before_height"] == 1
            and type(row["during_height"]) is int and row["during_height"] == 2
            and row["callback_held_during_read"] is True and row["insert_returned_after_release"] is True
            and row["accepted_header_authority"] is False, "frontier_visibility_observation")
    return row


def native_controls(raw, cpu_profile=None):
    require(cpu_profile is None or cpu_profile in CPU_LIMITS, "cpu_profile_selection")
    cases = {"fixture-window": CASES["fixture-window"]} if cpu_profile == "half-core" else CASES
    require(type(raw) is bytes and 0 < len(raw) <= C.MAX_STREAM and raw.endswith(b"\n"), "native_stream")
    lines = raw.splitlines()
    require(len(lines) <= 4096, "native_event_bound")
    expected = {TEST, *(TEST + "/" + name for name in cases)}
    started, passed, outputs = set(), set(), {}
    package_started = package_passed = False
    for line in lines:
        require(not package_passed, "native_after_package_pass")
        event = decode(line)
        require(type(event) is dict and event.get("Package") == PACKAGE, "native_package")
        action, name = event.get("Action"), event.get("Test")
        require(action in ("start", "run", "output", "pass"), "native_outcome")
        if name is not None:
            require(type(name) is str and name in expected and package_started, "native_selection")
            if action == "run":
                require(name not in started and (name == TEST or TEST in started), "native_run_order")
                started.add(name)
            else:
                require(name in started and name not in passed, "native_test_order")
            if action == "pass":
                passed.add(name)
        elif action == "start":
            require(not package_started and not started, "native_package_start")
            package_started = True
        elif action == "pass":
            require(package_started and started == passed == expected, "native_package_completion")
            package_passed = True
        else:
            require(action == "output" and package_started, "native_package_event")
        output = event.get("Output", "")
        require(type(output) is str and (not output or action == "output"), "native_output_action")
        outputs[name] = outputs.get(name, "") + output
        require(len(outputs[name].encode("utf-8")) <= 128 << 10, "native_output_bound")
    require(package_passed and started == passed == expected, "native_completion")
    require(all(MARKER not in text for name, text in outputs.items()
                if name not in {TEST + "/" + case for case in cases}), "foreign_trace")
    visibility_test = TEST + "/one-period" if "one-period" in cases else None
    require(all(VISIBILITY_MARKER not in text for name, text in outputs.items()
                if visibility_test is None or name != visibility_test), "foreign_visibility_trace")
    cpu_test = TEST + "/fixture-window" if cpu_profile else None
    require(all(CPU_MARKER not in text for name, text in outputs.items()
                if cpu_test is None or name != cpu_test), "foreign_cpu_trace")
    observations = {}
    for case, gap in cases.items():
        text = outputs.get(TEST + "/" + case, "")
        trace = selected_trace(text, MARKER)
        fields = (FALSE_FIELDS | TRUE_FIELDS | INTEGER_FIELDS |
                  {"format", "case", "node_revision", "source_genesis_sha256",
                   "unsigned_insert_seconds", "points_listener_seconds"})
        require(type(trace) is dict and set(trace) == fields, "native_trace_fields")
        require(trace["format"] == "selected-first-insertion-catchup/v1" and trace["case"] == case
                and trace["node_revision"] == C.NODE_REVISION
                and trace["source_genesis_sha256"] == C.GENESIS_SHA256, "native_trace_source")
        require(all(trace[k] is False for k in FALSE_FIELDS) and all(trace[k] is True for k in TRUE_FIELDS),
                "native_trace_scope")
        require(all(type(trace[k]) is int and 0 <= trace[k] < 1 << 40 for k in INTEGER_FIELDS), "native_trace_integers")
        require(trace["source_genesis_unix"] == 1739923200 and trace["unsigned_H2_unix"] == 1739923200 + gap
                and trace["gap_seconds"] == gap and trace["period_seconds"] == 300
                and trace["completed_periods"] == gap // 300 and trace["completed_epochs"] == gap // 86400,
                "native_trace_history")
        require(0 < trace["closed_consensus_files"] <= 4096
                and trace["closed_consensus_logical_bytes"] <= 256 << 20
                and trace["consensus_put_calls"] >= trace["completed_periods"] + trace["completed_epochs"],
                "native_trace_measurement")
        for key in ("unsigned_insert_seconds", "points_listener_seconds"):
            require(type(trace[key]) in (float, int) and math.isfinite(trace[key]) and 0 <= trace[key] <= 180,
                    "native_trace_duration")
        observations[case] = trace
    result = {"root_tests": 1, "subtests": len(cases), "failed": 0, "skipped": 0,
            "observations": observations, "actual_fixture_cause_established": False,
            "new_devnet_acceptance_established": False}
    if visibility_test:
        result["frontier_visibility"] = insertion_visibility(outputs.get(visibility_test, ""))
    if cpu_profile:
        result["cpu"] = cpu_observation(outputs.get(cpu_test, ""), cpu_profile)
    return result


def compare_cpu_controls(reference, constrained, binary_pin):
    a = reference["observations"]["fixture-window"]
    b = constrained["observations"]["fixture-window"]
    workload = ("completed_periods", "completed_epochs", "consensus_get_calls",
                "consensus_put_calls", "consensus_put_value_bytes")
    require(all(a[key] == b[key] for key in workload), "cpu_comparison_workload")
    return {"format": "first-insertion-cpu-comparison/v1", "test_binary": binary_pin,
            "historical_fixture_contract_sha256": FIXTURE_CONTRACT,
            "historical_readiness_seconds": FIXTURE_READINESS_SECONDS,
            "reference_listener_seconds": a["points_listener_seconds"],
            "half_core_listener_seconds": b["points_listener_seconds"],
            "half_core_listener_reached_readiness_duration": b["points_listener_seconds"] >= FIXTURE_READINESS_SECONDS,
            "same_measured_workload": {key: a[key] for key in workload},
            "half_core_controls": constrained, "actual_fixture_cause_established": False}


def linux_cpu_controls(work, node, output, selected, records):
    require(sys.platform == "linux" and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
            and os.getuid() != 0 and os.getgid() != 0, "hosted_linux_cpu_scope")
    binary = work / "consensus-catchup.test"
    require(not binary.exists() and not binary.is_symlink(), "fresh_test_binary")
    C.command(output, "compile-native-test", ["go", "test", *C.NATIVE_FLAGS, "-c", "-o", str(binary),
              "./consensus"], node, records, timeout=480)
    initial = C.digest(C.regular(binary, C.MAX_BINARY))
    require(initial["bytes"] > 0, "compiled_test_binary")
    binary.chmod(0o500)

    def run(profile, label, pattern):
        scratch = work / (profile + "-db")
        scratch.mkdir(mode=0o700)
        unit = f"spv-catchup-{selected['run_id']}-{selected['run_attempt']}-{profile}.service"
        args = ["go", "tool", "test2json", "-t", "-p", PACKAGE, "sudo", "-n", "--", "/usr/bin/systemd-run",
                "--quiet", "--wait", "--pipe", "--collect", "--service-type=exec", "--expand-environment=no",
                "--unit=" + unit, "--slice=system.slice", f"--uid={os.getuid()}", f"--gid={os.getgid()}",
                "--working-directory=" + str(node / "consensus"), "--setenv=GOMAXPROCS=1",
                "--setenv=SPV_CATCHUP_CPU_PROFILE=" + profile, "--setenv=SPV_CATCHUP_CPU_UNIT=" + unit,
                "--setenv=TMPDIR=" + str(scratch),
                "--property=PrivateNetwork=yes", "--property=NoNewPrivileges=yes",
                "--property=ProtectSystem=strict", "--property=ReadWritePaths=" + str(scratch),
                "--property=RuntimeMaxSec=190s", "--property=TimeoutStopSec=5s",
                "--property=CPUWeight=100", "--property=CPUQuotaPeriodSec=100ms",
                f"--property=MemoryMax={FIXTURE_MEMORY_BYTES}", "--property=MemorySwapMax=0"]
        if profile == "half-core":
            args.append("--property=CPUQuota=50%")
        args.extend(("--", str(binary), "-test.v=test2json", "-test.count=1", "-test.timeout=180s",
                     "-test.run", pattern))
        raw = C.command(output, label, args, work, records, timeout=215)
        require(C.digest(C.regular(binary, C.MAX_BINARY)) == initial and not any(scratch.iterdir()),
                "cpu_sample_binary_or_scratch")
        return native_controls(raw, profile)

    reference = run("reference", "native-test", "^" + TEST + "$")
    constrained = run("half-core", "half-core-test", "^" + TEST + "$/^fixture-window$")
    return reference, compare_cpu_controls(reference, constrained, initial)


def context(platform):
    selected = C.context(platform)
    selected["workflow"] = "first-insertion-catchup"
    return selected


def space(path):
    free = shutil.disk_usage(path).free
    require(free >= 14 * C.GIB, "free_space_floor")
    return {"free_bytes": free, "floor_bytes": 10 * C.GIB,
            "expected_allocation_bytes": 3 * C.GIB, "safety_margin_bytes": C.GIB,
            "OS_disk_quota_or_peak_measurement": False}


def owned_scope(work, output, selected):
    if selected is None:
        return False
    try:
        marker = decode(C.regular(work / "scope.json", 4096))
        return (marker["format"] == "owned-first-insertion-scope/v1" and marker["context"] == selected
                and not work.is_symlink() and not output.is_symlink()
                and marker["work_identity"] == [work.stat().st_dev, work.stat().st_ino]
                and marker["output_identity"] == [output.stat().st_dev, output.stat().st_ino])
    except (Refused, OSError, KeyError, TypeError):
        return False


def stage(work, output, selected, records):
    require(not work.exists() and not work.is_symlink() and not output.exists() and not output.is_symlink(),
            "fresh_workspace_required")
    require(work.parent.is_dir() and output.parent.is_dir() and work != output
            and work not in output.parents and output not in work.parents, "workspace_separation")
    inputs = {name: C.regular(ROOT / name, C.MAX_SOURCE_FILE) for name in INPUTS}
    allocation = space(work.parent)
    work.mkdir(mode=0o700)
    output.mkdir(mode=0o700)
    C.seal(work / "scope.json", C.encoded({"format": "owned-first-insertion-scope/v1", "context": selected,
        "work_identity": [work.stat().st_dev, work.stat().st_ino],
        "output_identity": [output.stat().st_dev, output.stat().st_ino]}))
    node = work / "node"
    C.git(output, "node-init", ["init", "--quiet", str(node)], work, records)
    C.git(output, "node-line-endings", ["config", "--local", "core.autocrlf", "false"], node, records)
    C.git(output, "node-fetch", ["fetch", "--quiet", "--depth=1", "--no-tags", C.NODE_REPOSITORY, C.NODE_REVISION], node, records)
    C.git(output, "node-checkout", ["checkout", "--quiet", "--detach", "FETCH_HEAD"], node, records)
    head = C.git(output, "node-head", ["rev-parse", "HEAD"], node, records).decode().strip()
    tree = C.git(output, "node-tree", ["rev-parse", "HEAD^{tree}"], node, records).decode().strip()
    require((head, tree) == (C.NODE_REVISION, C.NODE_TREE), "node_source_pin")
    require(C.git(output, "node-clean", ["status", "--porcelain=v1"], node, records) == b"", "original_source_dirty")
    index = C.git(output, "node-index", ["ls-files", "--stage", "-z"], node, records)
    original = C.source_inventory(node, index)
    require(original["docker/devnet/genesis.json"] == {"bytes": 8137, "sha256": C.GENESIS_SHA256}, "source_genesis")
    for name, target in INPUTS.items():
        require(not (node / target).exists() and not (node / target).is_symlink(), "added_path_exists")
        C.seal(node / target, inputs[name])
    C.seal(work / "ownership.json", C.encoded({"format": "owned-first-insertion-work/v1", "context": selected,
        "node_identity": [node.stat().st_dev, node.stat().st_ino], "original_sources": original,
        "added_inputs": {name: C.digest(raw) for name, raw in inputs.items()}}))
    C.seal(output / "preparation.json", C.encoded({"format": "first-insertion-preparation/v1", "context": selected,
        "node_revision": head, "node_tree": tree, "original_sources": original,
        "added_inputs": {name: C.digest(raw) for name, raw in inputs.items()},
        "allocation_admission": allocation, "commands": records, "native_execution": False}))


def qualify(work, output, selected, records):
    require(owned_scope(work, output, selected), "owned_stage_scope")
    marker = decode(C.regular(work / "ownership.json", 256 << 10))
    node = work / "node"
    require(marker["format"] == "owned-first-insertion-work/v1" and marker["context"] == selected
            and not node.is_symlink() and marker["node_identity"] == [node.stat().st_dev, node.stat().st_ino],
            "owned_node_identity")
    index = C.git(output, "qualified-node-index", ["ls-files", "--stage", "-z"], node, records)

    def unchanged():
        require(C.source_inventory(node, index) == marker["original_sources"]
                and set(marker["added_inputs"]) == set(INPUTS), "source_drift")
        for name, target in INPUTS.items():
            raw = C.regular(node / target, C.MAX_SOURCE_FILE)
            require(raw == C.regular(ROOT / name, C.MAX_SOURCE_FILE)
                    and C.digest(raw) == marker["added_inputs"][name], "added_source_drift")

    unchanged()
    allocation = space(work)
    go = decode(C.command(output, "go-environment", ["go", "env", "-json", "GOOS", "GOARCH", "GOVERSION", "CGO_ENABLED", "CC"], node, records))
    C.require_toolchain(go, selected["platform"])
    comparison = None
    if selected["platform"] == "linux-amd64":
        controls, comparison = linux_cpu_controls(work, node, output, selected, records)
    else:
        raw = C.command(output, "native-test", ["go", "test", *C.NATIVE_FLAGS, "-json", "-count=1", "-timeout=180s",
                        "-run", "^" + TEST + "$", "./consensus"], node, records, timeout=600)
        controls = native_controls(raw)
    unchanged()
    require(C.git(output, "node-head-after", ["rev-parse", "HEAD"], node, records).decode().strip() == C.NODE_REVISION
            and C.git(output, "node-tree-after", ["rev-parse", "HEAD^{tree}"], node, records).decode().strip() == C.NODE_TREE,
            "node_revision_after")
    C.git(output, "node-index-after", ["diff", "--cached", "--exit-code", "HEAD"], node, records)
    status = C.git(output, "node-working-after", ["status", "--porcelain=v1", "-z", "--untracked-files=all"], node, records)
    require(status.endswith(b"\0") and sorted(status.split(b"\0")[:-1])
            == sorted(b"?? " + target.encode() for target in INPUTS.values()), "unexpected_working_change")
    require(C.git(output, "spv-source-head", ["rev-parse", "HEAD"], ROOT, records).decode().strip()
            == selected["source_revision"], "SPV_source_revision")
    tree = C.git(output, "spv-source-tree", ["rev-parse", "HEAD^{tree}"], ROOT, records).decode().strip()
    C.git(output, "spv-index-clean", ["diff", "--cached", "--exit-code", "HEAD"], ROOT, records)
    selected_index = C.git(output, "spv-selected-index", ["ls-files", "--stage", "-z", "--", *PUBLIC_PATHS], ROOT, records)
    sources, working = C.selected_sources(selected_index, PUBLIC_PATHS)
    for name in INPUTS:
        C.seal(output / Path(name).name, C.regular(ROOT / name, C.MAX_SOURCE_FILE))
    C.seal(output / "NODE_LICENSE", C.regular(node / "LICENSE", 64 << 10))
    result = {"format": "first-insertion-catchup-ci/v1", "status": "UNSIGNED_BOOKKEEPING_CONTROLS_PASSED",
        **selected, "source_tree": tree, "node_revision": C.NODE_REVISION, "node_tree": C.NODE_TREE,
        "source_files": sources, "working_sources": working, "original_node_sources_unchanged": True,
        "node_original_files": len(marker["original_sources"]), "go": go, "native_controls": controls,
        "linux_cpu_comparison": comparison,
        "allocation_admission": allocation, "commands": records,
        "scope": {"unsigned_test_fixture_bypasses_authentication": True, "actual_fixture_cause_established": False,
                  "new_devnet_acceptance_established": False, "authenticated_distribution": False,
                  "production_qualified": False}}
    C.seal(output / "manifest.json", C.encoded(result))
    return result


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
        else:
            qualify(args.workspace, args.evidence, selected, records)
        print(json.dumps({"format": "first-insertion-stage-complete/v1", "mode": args.mode,
                          "context": selected, "new_devnet_acceptance_established": False}, sort_keys=True))
        return 0
    except (Refused, OSError, ValueError, KeyError, TypeError, UnicodeError) as error:
        if owned_scope(args.workspace, args.evidence, selected):
            failure = args.evidence / ("failure-" + args.mode + ".json")
            if not failure.exists():
                C.seal(failure, C.encoded({"format": "first-insertion-failure/v1", "mode": args.mode,
                    "error_type": type(error).__name__, "reason": str(error) if isinstance(error, Refused) else None,
                    "status": "FAILURE_OR_UNKNOWN", "commands": records}))
        print("First insertion control refused; retain owned command evidence.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
