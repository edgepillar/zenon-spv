#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Check finite real-manager startup recordings without executing a backend.

The raw-store digests and private command references are recorded observations,
not independently authenticated database images or accepted-header proofs.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("recorded_foreign_preparation", HERE / "prepare_public_chain_foreign_startup.py")
F = importlib.util.module_from_spec(spec)
spec.loader.exec_module(F)
spec = importlib.util.spec_from_file_location("recorded_foreign_byte_witness", HERE / "check_public_chain_lifecycle_successor.py")
W = importlib.util.module_from_spec(spec)
spec.loader.exec_module(W)
P = F.P
CORPUS = "successor-public-chain-foreign-startup.json"
CORPUS_SHA256 = "5eecc65899e49a0744225b767fdb80a26e46bef9f9db2c92a1da2d99bda7551d"
CORPUS_BYTES = 32759
MAX_BYTES = 128 << 10
ZERO = "00" * 32
FRAMING = "ordered u64be key length, key bytes, u64be value length, value bytes"
SINGLE_ROOT = "29e6754c2098f405b067f62f92bc48a22ea23b45c1a7b9cc05556ed03dc385c7"
CHANGED_ROOT = "7f5f225685590ad9dfc37c8caaa9f32bfd27b0a77a6d5fbb3fea2b749a47686a"
DEPENDENCIES_SHA256 = "78fd4849b456bb5fca9f80619dd747871794d251e7652ca2d06378c004d29033"
CANONICAL_IMAGE = (77030, 2541878, 4254290, "4fce74d75dc9a096f83c06eb0dbf9d8ef569358a48092d8a5309d6eb0d4ec47f")
IMAGE_PINS = (
    CANONICAL_IMAGE,
    (6, 86, 178, "4e3e4737e0ebb7b084fd58af33e7a188d3843abd4c571f781a56ab7c1be10e94"),
    (8, 104, 242, "574bd21297e10db4966ba3d4aea124b1b65d63fcf091492285db1799bdcd2146"),
    (77062, 2542886, 4256373, "94bf3c97dab64a5ebf24c7c2530beb8eb1ccdc6a5f32d2dd30ac822cd8eb9b0d"),
)
SCOPE = {name: True for name in (
    "real_public_Chain_Init_and_Stop", "real_disk_ledger_cache_and_NodeTree_managers",
    "source_embedded_unsigned_genesis_VM", "separate_native_format_foreign_tree_fixtures",
    "before_after_raw_store_digest_recorded", "canonical_clean_reopen_recorded",
)}
SCOPE.update({name: False for name in (
    "runtime_source_changed", "Chain_Start_called", "full_node_service_executed",
    "network_or_consensus_executed", "live_reorg_qualified", "concurrent_lifecycle_qualified",
    "power_loss_qualified", "test_overlay_or_scheduler_hooks", "race_detector_selected",
    "node_client_profile_agreed", "network_activation_authenticated", "accepted_header_binding",
    "runtime_state_value_acceptance", "production_qualified", "checker_executes_reference_backend",
    "public_record_authenticates_private_receipts", "raw_database_bytes_reconstructed_by_reader",
)})
INPUTS = tuple(dict.fromkeys((F.PROBE, "prepare_public_chain_foreign_startup.py",
    "check_public_chain_lifecycle_successor.py", "testdata/" + W.CORPUS, *W.INPUTS)))


def document(raw):
    return W.document(raw)


def selection():
    # The earlier byte-pinned canonical witness was selected before this run.
    raw = P.read_regular(HERE / "testdata" / W.CORPUS, W.MAX_BYTES)
    P.require(len(raw) == W.CORPUS_BYTES and P.sha(raw) == W.CORPUS_SHA256)
    proof = document(raw)["selection"]["witness"]["proof"]
    P.require(W.witness_root(W.KEY, W.VALUE, proof) == W.ROOT)
    value = (100001).to_bytes(32, "big")
    path = hashlib.sha3_256(bytes.fromhex(W.KEY)).digest()
    leaf = hashlib.sha3_256(path + value).digest()
    single = b"\1" + path + leaf + bytes(32) + bytes(2) + (32).to_bytes(4, "big") + value
    changed = bytearray.fromhex(proof)
    changed[33:65], changed[-32:] = leaf, value
    # Three independent 256-level folds; no full genesis projection or node run.
    P.require(W.witness_root(W.KEY, value.hex(), single.hex()) == SINGLE_ROOT)
    P.require(W.witness_root(W.KEY, value.hex(), changed.hex()) == CHANGED_ROOT)
    return {"cases": list(F.CASES), "genesis_identifier": W.GENESIS, "genesis_dump": W.DUMP,
            "canonical_root": W.ROOT, "key": W.KEY, "canonical_value": W.VALUE,
            "canonical_proof": proof, "foreign_value": value.hex(),
            "foreign_single_leaf_root": SINGLE_ROOT, "foreign_full_projection_root": CHANGED_ROOT}


def identifiers():
    a = dict(W.GENESIS)
    b = dict(a, hash=("%02x" % (int(a["hash"][:2], 16) ^ 1)) + a["hash"][2:])
    b2 = dict(b, hash=("%02x" % (int(b["hash"][:2], 16) ^ 2)) + b["hash"][2:], height=2)
    return a, b, b2


def snapshot(case, stage, index, after=False):
    a, b, b2 = identifiers()
    canonical = index == 0 or (index == 3 and after)
    mismatch, missing = "version-hash-mismatch", "no-version"
    if canonical:
        frontier, roots = a, [(W.ROOT, "none"), (ZERO, mismatch), (ZERO, missing)]
    elif index == 1:
        frontier, roots = b, [(ZERO, mismatch), (SINGLE_ROOT, "none"), (ZERO, missing)]
    elif index == 2:
        frontier, roots = b2, [(ZERO, mismatch), (SINGLE_ROOT, "none"), (SINGLE_ROOT, "none")]
    else:
        frontier, roots = b2, [(W.ROOT, "none"), (ZERO, mismatch), (CHANGED_ROOT, "none")]
    records, keys, values, digest = CANONICAL_IMAGE if canonical else IMAGE_PINS[index]
    return {"case": case, "stage": stage, "framing": FRAMING, "frontier": frontier,
            "records": records, "key_bytes": keys, "value_bytes": values, "raw_store_sha256": digest,
            "roots": [{"identifier": id_, "root": root, "error": error}
                      for id_, (root, error) in zip((a, b, b2), roots)]}


def expected_events(index, proof):
    case = F.CASES[index]
    good = index in (0, 3)
    def event(stage, **fields):
        return dict(fields, case=case, stage=stage)
    rows = [event("source-genesis", identifier=W.GENESIS, raw_patch_sha256=W.DUMP["sha256"],
                  raw_patch_bytes=W.DUMP["bytes"], network_started=False, wallet_signing_or_broadcast=False),
            event("canonical-ledger-primed", root=W.ROOT, ready_after_stop=False),
            snapshot(case, "fixture-before-public-init", index),
            event("public-init-returned", ready=good, error=("none" if good else
                  "chain-frontier-identity-mismatch" if index == 1 else "version-hash-mismatch"))]
    for i, id_ in enumerate(identifiers()):
        available = good and i == 0
        error = "none" if available else ("not-ready" if not good else
                "version-hash-mismatch" if i == 1 else "no-version")
        rows.append(event("public-query", identifier=id_, root=W.ROOT if available else ZERO,
                    root_error=error, proof_error=error, value=W.VALUE if available else "",
                    proof=proof if available else ""))
    rows += [event("public-stop", ready=False), snapshot(case, "fixture-after-public-stop", index, after=True)]
    if good:
        rows.append(event("public-clean-reopen", ready=True, root=W.ROOT))
    return rows


def expected_source():
    # Reconstruct all 467 selected runtime blobs and the separate tagged command.
    p = F.plan("NEW_OWNED_WORKSPACE", "PINNED_GO")
    P.require(p["build_tree"] == "6b5c452bd643d1b11e4b640cb398adfdf59ec12b")
    return {"repository": "https://github.com/digitalSloth/go-zenon", "revision": p["node_revision"],
            "original_tree": p["original_tree"], "runtime_tree": p["runtime_tree"], "build_tree": p["build_tree"],
            "source_blobs": 467, "source_manifest_sha256": p["source_manifest_sha256"], "probe": p["probe"],
            "module_sha256": p["module_sha256"], "sum_sha256": p["sum_sha256"], "runtime_changed": False}


def command(stdout_sha, stdout_bytes, stderr_sha, stderr_bytes):
    return {"state": "COMPLETE", "actual_exit": 0, "output_complete": True, "reason": None,
            "stdout": {"sha256": stdout_sha, "bytes": stdout_bytes},
            "stderr": {"sha256": stderr_sha, "bytes": stderr_bytes}}


def check_corpus(value):
    P.require(type(value) is dict and set(value) == {
        "format_version", "kind", "source", "selection", "execution", "scope", "cases", "consumer_result"})
    P.exact([value["format_version"], value["kind"], value["consumer_result"]],
            [1, "recorded-public-chain-foreign-startup", "REFUSED"])
    P.exact(value["source"], expected_source())
    selected = selection()
    P.exact(value["selection"], selected)
    P.exact(value["scope"], SCOPE)
    dependencies = value["execution"]["selected_linked_dependencies"]
    P.require(type(dependencies) is list and len(dependencies) == 25)
    P.require(P.sha(P.UTIL.encoded(dependencies)) == DEPENDENCIES_SHA256)
    empty = hashlib.sha256(b"").hexdigest()
    P.exact(value["execution"], {
        "platform": "darwin/arm64", "Go_version": "go1.25.14",
        "Go_binary_sha256": "55770db639faa42f3ebc998ac583b008f7ff2b4bbb9dbb8a76511a9a6ffa4a19",
        "ordinary_binary": {"sha256": "bb0058427f7fd676d3424a79891991b1206982704c88aa536e6f598345a72dce", "bytes": 19854162},
        "commands": {
            "compiler_version": command("701f70956d50072291a29dc76dfb6e8b79cccfc141fc7e9a98aac8fc9ddae245", 34, empty, 0),
            "build": command(empty, 0, "6d59d2bf3d7c4398e505ef04b613b9e2bdbd04aa634670e6319934491d8c1280", 1422),
            "binary_info": command("f8cb36f09e6dc1dd07a5cdac79c44c5d22e4e2645bd50a54c146d4d2ba6ba050", 3075, empty, 0)},
        "actual_builds": 1, "actual_case_processes": 4, "new_source_or_dependency_transports": 0,
        "verified_dependency_inputs": 75, "selected_linked_dependencies": dependencies,
        "original_task_outcome": "SUCCESS",
        "whole_module_graph_verification": "NOT_QUALIFIED_PRIOR_MISSING_UNUSED_PROXY_INPUT_NOT_RETRIED",
        "post_run_owned_workspace_logical_bytes": 359728029, "physical_reclaim_or_peak_disk_claim": False,
        "presealed_plan": {"sha256": "0ba1ffd9377de4621a42a918c95ee5547baa3772e9c2bf6d72767f2fd5239963", "bytes": 9233},
        "private_execution": {"sha256": "7c2753744b6caeb90964a3ada6452d58a1cf9599b55fd7e539f7e32e8c9f490f", "bytes": 63430},
    })
    P.require(type(value["cases"]) is list and len(value["cases"]) == 4)
    count = 0
    for index, row in enumerate(value["cases"]):
        P.require(type(row) is dict and set(row) == {"case", "command", "stdout_utf8", "stderr_diagnostics"})
        P.exact(row["case"], F.CASES[index])
        raw = row["stdout_utf8"]
        P.require(type(raw) is str and 0 < len(raw) < 8 << 10 and raw.endswith("\n"))
        good = index in (0, 3)
        stderr = ("52740efeda38ce97bb54697d07ad57edcd28dd28a95884ef008959a974323fd3", 343) if good else (
                  "cf4e8b1c9793bdc1d64aa91cd201b6c21de2e2b937202b8acdb3763bb1066b25", 145)
        P.exact(row["command"], command(P.sha(raw.encode()), len(raw.encode()), *stderr))
        P.exact(row["stderr_diagnostics"], {"normal_process_complete": True, "runtime_panic_observed": False})
        events = [document(line.encode()) for line in raw.splitlines()]
        P.exact(events, expected_events(index, selected["canonical_proof"]))
        count += len(events)
    return {"kind": "recorded-public-chain-foreign-startup-check", "recorded_cases": 4,
            "recorded_raw_exits": [0, 0, 0, 0], "recorded_event_observations": count,
            "recorded_refused_starts": 2, "recorded_unchanged_refused_raw_stores": 2,
            "recorded_canonical_rollback_and_reopen": 1, "recorded_clean_reopens": 2,
            "recorded_public_queries": 12, "recorded_available_canonical_queries": 2,
            "independent_witness_folds": 3, "witness_levels_per_fold": 256,
            "selected_linked_modules": 25, "whole_module_graph_verification": "NOT_QUALIFIED",
            "recorded_reference_platform": "darwin/arm64", "reference_processes_executed_by_this_check": 0,
            "source": expected_source(), "scope": dict(SCOPE),
            "reader_inputs_sha256": {name: P.sha(P.read_regular(HERE / name, 1 << 20)) for name in INPUTS},
            "raw_stderr_or_private_receipts_rehashed_by_this_check": False, "consumer_result": "REFUSED"}


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
        print("Recorded public Chain foreign startup refused; preserve failures and disabled acceptance.", file=sys.stderr)
        sys.exit(1)
