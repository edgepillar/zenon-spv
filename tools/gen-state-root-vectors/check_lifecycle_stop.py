#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Independent selected stop schedules, read bytes and logical-record oracle.

This reads bounded recorded component evidence. It executes no node, process,
scheduler, database or network. Controlled checkpoints do not qualify a live
background build, a complete node, production concurrency or a state-value proof.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("stop_independent_retained_bytes", HERE / "check_hash_bound_versions.py")
H = importlib.util.module_from_spec(spec)
spec.loader.exec_module(H)
VARIANTS = ("hash-bound", "monotonic-stop")
PATCH_SHA256 = "2778017b5de86be222956a600dcb8bed49dd5fd543566f0230e6c2a042a8a165"
MODIFIED_TREE = "d3d9215bc9ea23b2e700aad53ebb23d4bdea3428"
MAX_FILE_BYTES = 1 << 20
INPUTS = (
    "lifecycle-stop-patch.json", "prepare_lifecycle_stop.py", "lifecycle_stop_probe_test.go",
    "check_lifecycle_stop.py", *H.INPUTS,
)
SCOPE = {
    "synthetic": True, "unsigned": True, "actual_state_tree_component_Init_Stop_executed": True,
    "actual_disk_NodeTree_read_APIs_executed": True, "inflight_patch_callbacks_executed": True,
    "controlled_channel_schedules": True, "test_only_source_checkpoints_injected": True,
    "race_detector_selected_in_local_component_builds": True,
    "selected_logical_records_and_clean_reopen_compared": True,
    "baseline_orphan_launches_controlled_before_loop": True,
    **{name: False for name in (
        "scheduler_or_backend_executed_by_checker", "background_build_batches_executed",
        "chain_Start_executed", "full_node_started", "upstream_tests_executed",
        "complete_current_node_revision_qualified", "production_concurrency_qualified",
        "physical_crash_or_power_loss_qualified", "automatic_migration_performed",
        "network_execution", "RPC_executed", "signing", "transactions",
        "header_authentication_executed", "profile_agreed", "network_activation_authenticated",
        "authenticated_retained_provenance", "runtime_state_value_acceptance",
        "production_state_value_accepted",
    )},
}
NAMES = ("stop-before-init", "init-before-stop", "pending-stop-lock",
         "pending-init-stop", "pending-compute-stop", "held-launches-stop")


def read_corpus(path):
    with Path(path).open("rb") as stream:
        raw = stream.read(MAX_FILE_BYTES + 1)
    H.require(len(raw) <= MAX_FILE_BYTES, "Lifecycle corpus size exceeds limit")
    return raw, json.loads(raw, object_pairs_hook=H.BYTE.object_pairs)


def reads(ready, compute):
    model = H.Model("hash-bound", "A", 2)
    selected = H.identifier("A", 2)
    root = H.root(H.patch("A", 2))
    value, proof = H.proof(H.patch("A", 2), H.PRIMARY)
    rows = [
        {"method": "StateRoot", "identifier": selected, "root": root.hex() if ready else H.ZERO.hex(),
         "value": None, "proof": None, "error": None if ready else "not-ready",
         "patch_callbacks": {"dump": 0, "replay": 0}},
        {"method": "GetProof", "identifier": selected, "root": None,
         "value": value if ready else None, "proof": proof if ready else None,
         "error": None if ready else "not-ready", "patch_callbacks": {"dump": 0, "replay": 0}},
    ]
    if compute:
        computed, error, callbacks = model.compute(selected)
        H.require(error is None and callbacks == 1)
        rows.append({
            "method": "ComputeStateRoot", "identifier": selected,
            "root": computed.hex() if ready else H.ZERO.hex(), "value": None, "proof": None,
            "error": None if ready else "not-ready", "patch_callbacks": {"dump": 1 if ready else 0, "replay": 1 if ready else 0},
        })
    return rows


def selected_records(kind):
    if kind == "unopened":
        return []
    if kind == "format-only":
        return [{"key": "05", "value": "03"}]
    H.require(kind == "A2")
    return H.Model("hash-bound", "A", 2).snapshot()


def phase(name, ready, quit_closed, kind, compute=False):
    opened = kind != "unopened"
    return {
        "name": name, "ready": ready, "quit_closed": quit_closed,
        "handle_assigned": opened,
        "retained_frontier": None if not opened else dict(H.ORIGIN) if kind == "format-only" else H.identifier("A", 2),
        "root_cache_present": ready and compute,
        "records": selected_records(kind), "reads": reads(ready, compute),
    }


def expected_variant(variant):
    H.require(variant in VARIANTS)
    guarded = variant == "monotonic-stop"
    rows = []
    trace = [{"method": "Frontier"}, {"method": "Frontier"}]
    trace += [{"method": "GetPatch", "identifier": H.identifier("A", h)} for h in (1, 2)]
    for name in NAMES:
        phases, inits, stops = [], [None], [None]
        count, checkpoint, admission, inflight, extra = 0, {"launch_entry": 0, "launch_snapshot": 0, "worker_claimed": 0}, None, None, False
        kind, manager = "A2", list(trace)
        backend = {"root": H.ZERO.hex(), "error": "database-closed"}
        if name == "stop-before-init":
            count = 1
            checkpoint = {"launch_entry": 1, "launch_snapshot": 0 if guarded else 1, "worker_claimed": 0 if guarded else 1}
            kind = "unopened" if guarded else "A2"
            inits, stops = ["stopped" if guarded else None], [None, None]
            phases = [phase("stopped-empty", False, True, "unopened"),
                      phase("init-after-stop", not guarded, True, kind),
                      phase("after-final-stop", not guarded, True, kind, True)]
            manager = [] if guarded else list(trace)
            backend = None if guarded else {"root": H.root(H.patch("A", 2)).hex(), "error": None}
            extra = not guarded
        elif name == "init-before-stop":
            inits = [None, "stopped" if guarded else "database-closed"]
            phases = [phase("initialized", True, False, "A2"),
                      phase("after-stop", False, True, "A2", True),
                      phase("reinit-after-stop", False, True, "A2", True)]
        elif name == "pending-stop-lock":
            phases = [phase("initialized", True, False, "A2"),
                      phase("stop-intent", not guarded, True, "A2"),
                      phase("after-stop", False, True, "A2", True)]
        elif name == "pending-init-stop":
            kind = "format-only" if guarded else "A2"
            inits = ["stopped" if guarded else None]
            manager = [{"method": "Frontier"}] if guarded else list(trace)
            phases = [phase("stop-intent", False, True, "format-only"),
                      phase("after-stop", False, True, kind, True)]
        elif name == "pending-compute-stop":
            phases = [phase("initialized", True, False, "A2"),
                      phase("stop-intent", not guarded, True, "A2"),
                      phase("after-stop", False, True, "A2", True)]
            inflight = {"root": H.root(H.patch("A", 99)).hex(), "error": None,
                        "patch_callbacks": {"dump": 1, "replay": 1}}
        elif name == "held-launches-stop":
            count = 2
            checkpoint = {"launch_entry": 2, "launch_snapshot": 1 if guarded else 2, "worker_claimed": 0 if guarded else 2}
            admission = {"stop_returned_while_snapshots_held": not guarded,
                         "published_after_stop_returned": not guarded,
                         "workers_awaited_by_harness": 0 if guarded else 2}
            phases = [phase("initialized", True, False, "A2"),
                      phase("stop-intent", False, True, "A2"),
                      phase("after-stop", False, True, "A2", True)]
        rows.append({
            "name": name, "init_errors": inits, "stop_errors": stops, "start_calls": count,
            "phases": phases, "inflight_compute": inflight, "launch_admission": admission,
            "checkpoints": checkpoint, "backend_after_final_stop": backend,
            "harness_extra_close_required": extra, "records_after_close_reopen": selected_records(kind),
            "manager_trace": manager, "consumer_result": "REFUSED",
        })
    return {
        "format_version": 1, "kind": "current-node-stop-lifecycle-observations",
        "variant": variant, "cases": rows, "node_revision": H.REVISION,
        "consumer_result": "REFUSED", "production_state_value_accepted": False,
        "background_build_batches_executed": False,
    }


def source_pins():
    pins = {name: hashlib.sha256((HERE / name).read_bytes()).hexdigest() for name in INPUTS}
    H.require(pins["lifecycle-stop-patch.json"] == PATCH_SHA256)
    H.require(pins["hash-bound-versions-patch.json"] == H.PATCH_SHA256)
    return {
        "node_revision": H.REVISION, "node_original_tree": H.TREE, "node_blobs": 439,
        "hash_identity_parent_tree": H.MODIFIED_TREE, "monotonic_stop_tree": MODIFIED_TREE,
        "producer_and_oracle_inputs": pins,
        "historical_source_records_rebound": False,
        "checkpoint_source_is_separate_from_uninstrumented_proposal": True,
    }


def expected_corpus():
    return {"format_version": 1, "kind": "current-node-stop-lifecycle-comparison",
            "source": source_pins(), "scope": dict(SCOPE),
            "variants": {v: expected_variant(v) for v in VARIANTS}, "consumer_result": "REFUSED"}


def check_corpus(document):
    H.exact(document, expected_corpus())
    phases = [p for v in document["variants"].values() for c in v["cases"] for p in c["phases"]]
    return {
        "kind": "recorded-state-tree-stop-lifecycle-check", "variants": list(VARIANTS),
        "cases_per_variant": 6, "phase_observations": len(phases),
        "component_initializations": 14, "stop_calls": 14, "build_launch_calls": 6,
        "selected_read_observations": sum(len(p["reads"]) for p in phases),
        "logical_record_snapshots": len(phases) + 12,
        "local_node_revision": H.REVISION, "controlled_scheduler_instrumentation": True,
        "reference_execution_in_checker": False, "background_build_batches_executed": False,
        "production_concurrency_qualified": False, "complete_current_node_revision_qualified": False,
        "accepted_header_binding_qualified": False, "production_state_value_accepted": False,
        "consumer_result": "REFUSED",
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, default=HERE / "testdata/candidate-lifecycle-stop.json")
    parser.add_argument("--source-revision")
    args = parser.parse_args(argv)
    if args.source_revision is not None:
        H.require(type(args.source_revision) is str and len(args.source_revision) == 40 and
                  all(c in "0123456789abcdef" for c in args.source_revision), "Invalid source label")
    raw, document = read_corpus(args.corpus)
    result = check_corpus(document)
    result["corpus_sha256"] = hashlib.sha256(raw).hexdigest()
    if args.source_revision is not None:
        result["source_revision"] = args.source_revision
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, IndexError):
        print("Lifecycle fixture refused; preserve failures and disabled production acceptance.", file=sys.stderr)
        sys.exit(1)

