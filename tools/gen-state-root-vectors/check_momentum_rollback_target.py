#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Check recorded ledger rollback targets without compiling or executing a node.

Hashes bind published source and observations. They do not authenticate private
execution, network history, consensus, a state root or production resource use.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location("rollback_recorded_" + name, HERE / (name + ".py"))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


H = load("prepare_momentum_rollback_target")
R = load("check_cache_forward_replay")
B = load("check_patch_snapshot_lifetime")
P = H.P
CORPUS = "native-momentum-rollback-target.json"
CORPUS_SHA256 = "ac5c269ca488152fc492727c477ef26c3cf6d9c13097aeac9330a3b17b3c97fc"
CORPUS_BYTES = 29518
EXECUTION_SHA256 = "9f3ffe15a623ae70d339cd85a2eab989a663e6753dcf7add9c840d4a37d20ba7"
MAX_BYTES = 128 << 10
CASES = ("nil-locker", "missing-height-zero", "missing-above-frontier", "missing-maximum-height",
         "wrong-hash-at-frontier", "matching-frontier-noop")
SCOPE = {
    "real_disk_MomentumPool_and_manager_executed": True,
    "source_embedded_unsigned_genesis_and_local_second_momentum": True,
    "recovered_API_panics_reported_separately_from_process_exit": True,
    "logical_images_omit_nil_tombstones_and_retain_present_empty": True,
    "independent_small_logical_frame_and_v1_momentum_hash": True,
    "selected_native_unit_tests_recorded": True,
    "hosted_checks_replay_recorded_bytes": True,
    "Chain_Init_or_Start_executed": False,
    "cache_or_state_tree_executed": False,
    "full_node_service_or_network_executed": False,
    "signature_or_consensus_validated_second_momentum": False,
    "whole_window_atomicity_or_power_loss_qualified": False,
    "representative_resource_budget_qualified": False,
    "private_execution_receipts_authenticated": False,
    "complete_genesis_KV_image_independently_rederived_by_checker": False,
    "whole_module_archive_graph_qualified": False,
    "node_client_profile_agreed": False,
    "accepted_header_binding": False,
    "runtime_state_value_acceptance": False,
    "production_qualified": False,
    "checker_executes_reference_backend": False,
}
INPUTS = tuple(dict.fromkeys((
    "check_momentum_rollback_target.py", "prepare_momentum_rollback_target.py", H.PATCH, H.PROBE, H.UNIT,
    "check_cache_forward_replay.py", *R.INPUTS, *B.INPUTS,
)))


def document(raw):
    P.require(type(raw) is bytes and 0 < len(raw) <= MAX_BYTES)
    def constant(_):
        raise ValueError("Non-finite JSON refused")
    return json.loads(raw, object_pairs_hook=P.pairs, parse_constant=constant)


def expected_source():
    manifest, _, pins = H.selection()
    P.require(len(manifest["files"]) == len(pins) == 467)
    for variant, unit in (("parent", False), ("candidate", False), ("candidate", True)):
        H.build_pins(variant, unit)
    return {
        "repository": "https://github.com/digitalSloth/go-zenon", "revision": P.REVISION,
        "original_tree": P.TREE, "original_source_blobs": 467, "source_manifest_sha256": P.SOURCE_SHA256,
        "parent_runtime_tree": H.H.MODIFIED_TREE, "candidate_runtime_tree": H.MODIFIED_TREE,
        "parent_probe_build_tree": H.PARENT_BUILD_TREE, "candidate_probe_build_tree": H.BUILD_TREE,
        "candidate_unit_build_tree": H.UNIT_BUILD_TREE, "source_blobs_per_build": 468,
        "patch_sha256": H.PATCH_SHA256,
        "probe": {"bytes": H.PROBE_BYTES, "sha256": H.PROBE_SHA256},
        "unit_source": {"bytes": H.UNIT_BYTES, "sha256": H.UNIT_SHA256},
        "module_sha256": pins["go.mod"]["sha256"], "sum_sha256": pins["go.sum"]["sha256"],
    }


def ref(value):
    P.require(type(value) is dict and set(value) == {"bytes", "sha256"})
    P.require(type(value["bytes"]) is int and 0 <= value["bytes"] <= 64 << 20)
    P.require(type(value["sha256"]) is str and re.fullmatch("[0-9a-f]{64}", value["sha256"]) is not None)
    if value["bytes"] == 0:
        P.require(value["sha256"] == P.sha(b""))


def command(value, raw=None, exit_code=0):
    P.require(type(value) is dict and set(value) == {"state", "actual_exit", "output_complete", "reason", "stdout", "stderr"})
    P.exact([value[k] for k in ("state", "actual_exit", "output_complete", "reason")],
            ["COMPLETE", exit_code, True, None])
    ref(value["stdout"])
    ref(value["stderr"])
    if raw is not None:
        P.exact(value["stdout"], {"bytes": len(raw), "sha256": P.sha(raw)})


def presence_image():
    # An independent one-row model: key 0x11 has a present, zero-length value.
    # The deleted 0x22 key contributes no row or length frame.
    frame = struct.pack(">Q", 1) + b"\x11" + struct.pack(">Q", 0)
    return {"identifier": R.identifiers()["EMPTY"], "records": 1, "key_bytes": 1,
            "value_bytes": 0, "sha256": hashlib.sha256(frame).hexdigest()}


def ledger_image(second=False):
    # Recorded complete-image pins; the 10 MiB genesis KV payload is not copied
    # into this small corpus and is not independently re-derived by this reader.
    ids = R.identifiers()
    return {
        "identifier": ids["A2" if second else "A1"], "records": 103826 if second else 103824,
        "key_bytes": 3449911 if second else 3449869, "value_bytes": 8004591 if second else 8004463,
        "sha256": "647c402cf28644ce2d39767b3fa3826ce011107d19196671fc1c34c5d38211ab" if second else
                  "1c1168a46cb671751f1bc38ed79354e43cf3a7df30127a12851a9b66f05de815",
    }


def observation(error_class):
    panic = error_class == "panic"
    return {"error_class": error_class, "panic": panic, "canonical_state_uncertain": False,
            "panic_type": "runtime.errorString" if panic else "",
            "panic_text": "runtime error: invalid memory address or nil pointer dereference" if panic else ""}


def expected_events(variant):
    P.require(variant in ("parent", "candidate"))
    ids = R.identifiers()
    initial, second = ledger_image(), ledger_image(True)
    missing = "panic" if variant == "parent" else "missing-target"
    targets = [ids["A2"], ids["EMPTY"], {"hash": R.ZERO, "height": 3},
               {"hash": R.ZERO, "height": (1 << 64) - 1},
               dict(ids["A2"], hash="fa" + ids["A2"]["hash"][2:]), ids["A2"]]
    classes = ["nil-locker", missing, missing, missing, "target-identifier-mismatch", "none"]
    rows = [
        {"stage": "logical-presence-control", "image": presence_image(),
         "present_empty_retained": True, "nil_deletion_marker_omitted": True},
        {"stage": "source-selection", "genesis_identifier": ids["A1"], "genesis_patch_bytes": 10849399,
         "genesis_patch_sha256": "a222aac55304b1a489d395235c61af4182ac08b887d24d0c3f654aa402f35e75",
         "unsigned_second_momentum": R.second_momentum(), "chain_init_or_start_selected": False,
         "cache_or_state_tree_selected": False, "network_started": False,
         "wallet_signing_or_broadcast": False, "consumer_result": "REFUSED"},
        {"stage": "source-genesis-committed", "image": initial},
        {"stage": "unsigned-second-momentum-committed", "image": second},
    ]
    for case, target, error_class in zip(CASES, targets, classes):
        rows.append({"stage": "rollback-target-observation", "case": case, "target": target,
                     "before": second, "after": second, "result": observation(error_class),
                     "insert_callbacks": 0, "delete_callbacks": 0})
    rows.extend([
        {"stage": "valid-one-step-rollback", "target": ids["A1"], "before": second, "after": initial,
         "result": observation("none"), "insert_callbacks": 0, "deleted_identifiers": [ids["A2"]]},
        {"stage": "removed-height-target-observation", "target": ids["A2"], "after": initial,
         "result": observation(missing), "insert_callbacks": 0, "delete_callbacks": 1},
        {"stage": "closed-manager-reopen", "image": initial, "removed_height_absent": True},
    ])
    return rows


def check_case(row, variant):
    P.require(type(row) is dict and set(row) == {"variant", "command", "stdout_utf8"})
    P.exact(row["variant"], variant)
    text = row["stdout_utf8"]
    P.require(type(text) is str and 0 < len(text) < 16 << 10 and text.endswith("\n"))
    command(row["command"], text.encode())
    marker = b"MOMENTUM_ROLLBACK_TARGET_PROCESS_COMPLETE\n"
    P.exact(row["command"]["stderr"], {"bytes": len(marker), "sha256": P.sha(marker)})
    events = [document(line.encode()) for line in text.splitlines()]
    P.exact(events, expected_events(variant))
    return {"events": len(events), "recovered_API_panics": sum(event.get("result", {}).get("panic", False)
                                                              for event in events)}


def check_units(value):
    P.require(type(value) is dict and set(value) == {"build_tree", "command", "race_detector", "root_tests", "test_pass_names",
                                                  "package_pass_names", "explicit_skips", "failed_tests"})
    P.exact(value["build_tree"], H.UNIT_BUILD_TREE)
    command(value["command"])
    names = {*H.ROOTS, *(H.ROOTS[0] + "/" + name for name in
                         ("zero", "above", "maximum", "wrong-hash", "nil-locker", "matching-frontier"))}
    P.exact(value["race_detector"], False)
    P.exact(value["root_tests"], sorted(H.ROOTS))
    P.exact(value["test_pass_names"], sorted(names))
    P.exact(value["package_pass_names"], ["github.com/zenon-network/go-zenon/chain"])
    P.exact(value["explicit_skips"], [])
    P.exact(value["failed_tests"], [])


def check_corpus(value):
    P.require(type(value) is dict and set(value) == {"format_version", "kind", "source", "scope", "execution", "cases",
                                                  "unit_run", "consumer_result"})
    P.exact([value["format_version"], value["kind"], value["consumer_result"]],
            [1, "recorded-native-momentum-rollback-target", "REFUSED"])
    P.exact(value["source"], expected_source())
    P.exact(value["scope"], SCOPE)
    execution = value["execution"]
    P.require(type(execution) is dict and P.sha(P.UTIL.encoded(execution)) == EXECUTION_SHA256)
    P.exact([execution[k] for k in ("compiler", "reference_platform", "ordinary_builds", "native_ledger_processes",
                                  "new_external_transports", "new_archive_downloads", "linked_modules_per_binary",
                                  "whole_module_archive_graph_verification")],
            ["go1.25.14", "darwin/arm64", 2, 2, 0, 0, 25, "NOT_QUALIFIED"])
    P.require(type(value["cases"]) is list and len(value["cases"]) == 2)
    results = [check_case(row, phase) for row, phase in zip(value["cases"], ("parent", "candidate"))]
    for row in value["cases"]:
        P.exact(row["command"], execution["commands"][row["variant"] + "_run"])
    check_units(value["unit_run"])
    P.exact(value["unit_run"]["command"], execution["unit_command"])
    return {
        "kind": "recorded-native-momentum-rollback-target-check", "recorded_ledger_processes": 2,
        "recorded_events": sum(row["events"] for row in results),
        "recorded_parent_API_panics": results[0]["recovered_API_panics"],
        "recorded_candidate_API_panics": results[1]["recovered_API_panics"],
        "recorded_missing_target_cases_per_generation": 4, "recorded_native_unit_roots": 5,
        "recorded_native_unit_pass_results": 11, "recorded_native_skips": 0,
        "independent_present_empty_logical_frames": 1, "independent_v1_hash_preimage_bytes": 160,
        "recorded_valid_rollback_and_manager_reopen": True, "initial_observer_attempt_outcome": "FAILURE",
        "reference_processes_executed_by_this_check": 0, "source": expected_source(), "scope": dict(SCOPE),
        "consumer_result": "REFUSED", "reader_inputs_sha256": {
            name: P.sha(P.read_regular(HERE / name, 1 << 20)) for name in INPUTS},
    }


def check_file(path):
    raw = P.read_regular(path, MAX_BYTES)
    P.require(len(raw) == CORPUS_BYTES and P.sha(raw) == CORPUS_SHA256)
    result = check_corpus(document(raw))
    result["corpus_sha256"] = P.sha(raw)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, default=HERE / "testdata" / CORPUS)
    parser.add_argument("--source-revision")
    args = parser.parse_args(argv)
    if args.source_revision is not None:
        P.require(type(args.source_revision) is str and re.fullmatch("[0-9a-f]{40}", args.source_revision) is not None)
    result = check_file(args.corpus)
    if args.source_revision is not None:
        result["source_revision"] = args.source_revision
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, IndexError, RecursionError):
        print("Recorded rollback targets refused; preserve failures and disabled acceptance.", file=sys.stderr)
        raise SystemExit(1)
