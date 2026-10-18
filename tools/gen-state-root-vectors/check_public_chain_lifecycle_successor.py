#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Check bounded recorded public Chain calls and a preselected byte witness.

This reader performs no Go build, node/database execution, download or network
request. Hashes of private stderr/receipts are references, not authentication.
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
spec = importlib.util.spec_from_file_location("recorded_public_chain_preparation", HERE / "prepare_public_chain_lifecycle_successor.py")
C = importlib.util.module_from_spec(spec)
spec.loader.exec_module(C)
P = C.P
CORPUS = "successor-public-chain-lifecycle.json"
CORPUS_SHA256 = "50cd1a5960562735f27708959bf8d2420a8e0f4e3e2d6d9e4e3c8a997154efb6"
CORPUS_BYTES = 48471
MAX_BYTES = 128 << 10
ROOT = "864dbad1c3ef38e2c867950390364878c58238183d01b8bf97ef73e2efa4383d"
KEY = "0300000000000000000000000000000000000000000304066318c6318c6318c6"
VALUE = "00000000000000000000000000000000000000000000000000000000000186a0"
GENESIS = {"hash": "9e204601d1b7b1427fe12bc82622e610d8a6ad43c40abf020eb66e538bb8eeb0", "height": 1}
DUMP = {"sha256": "a222aac55304b1a489d395235c61af4182ac08b887d24d0c3f654aa402f35e75", "bytes": 10849399}
DEPENDENCIES_SHA256 = "f64df33469b27762747325f3adf73ea86e5c85ee800d659ea7e534cde34c2283"
STDERR_PINS = {
    C.VARIANTS[0]: (
        ("e23c6d213f17c3e30119d8d070efb03f539ed1c56b0a36d23707adb72314e66f", 1195),
        ("cbe589ed5f29ad50815de0be3e9e310e2a3b30fc0060f0613f73c40dca97e2c4", 832),
        ("4c8e4bd041ba7e1879aa4c897d18cd3251f40e0c103cc50877332420dc1c925e", 403)),
    C.VARIANTS[1]: (
        ("4622c470ca8a7ef00bb32210f791f4ef78b85cd98c9dde6b4a46163e0d037519", 535),
        ("cbe589ed5f29ad50815de0be3e9e310e2a3b30fc0060f0613f73c40dca97e2c4", 832),
        ("67c3d5f845c051efb7938c006ca130f38e507476c56fdaa7c999136204b796de", 40)),
}
SCOPE = {name: True for name in (
    "real_public_Chain_Init_Start_Stop", "real_disk_ledger_cache_and_NodeTree_managers",
    "source_embedded_unsigned_genesis_VM", "normal_init_start_query_and_clean_reopen",
)}
SCOPE.update({name: False for name in (
    "full_node_service_executed", "network_or_consensus_executed", "upstream_test_suite_executed",
    "test_overlay_or_scheduler_hooks", "race_detector_selected", "concurrent_lifecycle_qualified",
    "power_loss_or_reorg_qualified", "node_client_profile_agreed", "network_activation_authenticated",
    "accepted_header_binding", "runtime_state_value_acceptance", "production_qualified",
    "checker_executes_reference_backend", "private_process_receipts_authenticated_by_public_record",
)})
INPUTS = (
    C.PATCH, C.PROBE, "prepare_public_chain_lifecycle_successor.py",
    "prepare_offline_rebuild_successor.py", "prepare_terminal_stop_successor.py",
    "prepare_recovery_successor.py", "regenerate.py", P.SOURCE_MANIFEST,
    C.R.PATCH, C.R.T.PATCH, P.PATCH,
)


def document(raw):
    P.require(type(raw) is bytes and 0 < len(raw) <= MAX_BYTES)
    # This finite corpus has shallow maps and bounded JSONL strings. Reject
    # non-finite constants and duplicate names at every level, including events.
    def constant(_):
        raise ValueError("Non-finite JSON refused")
    return json.loads(raw, object_pairs_hook=P.pairs, parse_constant=constant)


def hex_bytes(text, size=None):
    P.require(type(text) is str and len(text) <= 8192 and re.fullmatch("[0-9a-f]*", text) is not None)
    raw = bytes.fromhex(text)
    P.require(size is None or len(raw) == size)
    return raw


def witness_root(key, value, proof):
    key, value, proof = hex_bytes(key, 32), hex_bytes(value, 32), hex_bytes(proof)
    P.require(len(proof) >= 103 and proof[0] == 1)
    path = hashlib.sha3_256(key).digest()
    leaf = hashlib.sha3_256(path + value).digest()
    P.require(proof[1:33] == path and proof[33:65] == leaf)
    bitmap, count = proof[65:97], int.from_bytes(proof[97:99], "big")
    P.require(count <= 256 and count == sum(bin(x).count("1") for x in bitmap))
    offset = 99 + 32 * count
    P.require(len(proof) == offset + 4 + len(value))
    P.require(int.from_bytes(proof[offset:offset + 4], "big") == len(value) and proof[offset + 4:] == value)
    cursor, root, zero = 0, leaf, bytes(32)
    for index in range(256):
        sibling = zero
        if bitmap[index // 8] & (1 << (7 - index % 8)):
            sibling = proof[99 + cursor * 32:131 + cursor * 32]
            cursor += 1
            P.require(sibling != zero)  # Zero siblings must be implicit.
        depth = 255 - index
        right_path = (path[depth // 8] >> (7 - depth % 8)) & 1
        left, right = (sibling, root) if right_path else (root, sibling)
        root = zero if left == right == zero else hashlib.sha3_256(left + right).digest()
    P.require(cursor == count)
    return root.hex()


def expected_events(case, variant, proof):
    def event(stage, **fields):
        return dict(fields, stage=stage, case=case)
    rows = [event("source-genesis", identifier=GENESIS, raw_patch_bytes=DUMP["bytes"],
                  raw_patch_sha256=DUMP["sha256"], genesis_VM_derivation=True,
                  network_started=False, wallet_signing_or_broadcast=False)]
    if case == "stop-before-init":
        rows.append(event("stopped-before-init", error=None, ready=False))
    else:
        rows += [event("initialized", ready=True), event("started", ready=True),
                 event("query", root=ROOT, root_error=None, value=VALUE, proof=proof, proof_error=None,
                       wrong_hash_error="trie: retained version Momentum hash mismatch"),
                 event("stopped", ready=False), event("clean-reopen", ready=True, root=ROOT, error=None)]
    rows.append(event("terminal-call-selected", call=case))
    if variant == C.VARIANTS[1] or case == "start-after-stop":
        rows += [event("terminal-call-returned", ready=False,
                       error="chain instance is stopped" if variant == C.VARIANTS[1] else None),
                 event("repeat-stop", error=None, ready=False)]
    return rows


def expected_source():
    # Reconstruct both complete runtime Git trees independently of the corpus.
    for variant in C.VARIANTS:
        C.selection(variant)
    return {
        "repository": "https://github.com/digitalSloth/go-zenon", "revision": P.REVISION,
        "original_tree": P.TREE, "parent_runtime_tree": C.R.MODIFIED_TREE,
        "candidate_runtime_tree": C.MODIFIED_TREE, "source_blobs": 467,
        "source_manifest_sha256": P.SOURCE_SHA256,
        "patch": {"sha256": C.PATCH_SHA256, "bytes": 12654},
        "probe": {"sha256": C.PROBE_SHA256, "bytes": len(C.probe_bytes())},
        "module_sha256": "ac08476abe3df0bc67f1c5c6868f04889b864310f16a37b0d51a6598b9017a45",
        "sum_sha256": "e536610c08abc9f4b979ce39cd5ae7323c3df14a189d186d911ee1d1184b8537",
    }


def check_corpus(value):
    P.require(type(value) is dict and set(value) == {"format_version", "kind", "source", "selection", "execution", "scope", "variants", "consumer_result"})
    P.exact([value["format_version"], value["kind"], value["consumer_result"]],
            [1, "recorded-public-chain-terminal-lifecycle", "REFUSED"])
    P.exact(value["source"], expected_source())
    P.exact(value["scope"], SCOPE)
    selected = value["selection"]
    P.require(type(selected) is dict and set(selected) == {"cases", "genesis_identifier", "genesis_dump", "root", "witness"})
    P.exact([selected["cases"], selected["genesis_identifier"], selected["genesis_dump"], selected["root"]],
            [list(C.CASES), GENESIS, DUMP, ROOT])
    w = selected["witness"]
    proof = w["proof"]
    P.exact(w, {"consumer_result": "REFUSED", "ledger_raw_input_has_key": True,
                "path": hashlib.sha3_256(bytes.fromhex(KEY)).hexdigest(), "present_in_projection": True,
                "proof": proof, "raw_key": KEY, "selection": "balance", "typed_domain_refused": False, "value": VALUE})
    P.require(witness_root(KEY, VALUE, proof) == ROOT)
    ex = value["execution"]
    dependencies = ex["selected_linked_dependencies"]
    P.require(type(dependencies) is list and len(dependencies) == 25)
    P.require(P.sha(P.UTIL.encoded(dependencies)) == DEPENDENCIES_SHA256)
    for row in dependencies:
        P.require(row["go_sum"] == row["extracted_cache_h1"])
        P.require([p["extension"] for p in row["payloads"]] == ["zip", "mod", "info"])
        P.require(row["payloads"][0]["independent_h1"] == row["go_sum"])
    P.exact(ex, {
        "platform": "darwin/arm64", "Go_version": "go1.25.14",
        "Go_binary_sha256": "55770db639faa42f3ebc998ac583b008f7ff2b4bbb9dbb8a76511a9a6ffa4a19",
        "ordinary_binaries": {
            C.VARIANTS[0]: {"sha256": "f5be16ee5ae802be21290347c1c8bd36d504d930f4243c9490decd1c949d0e66", "bytes": 19802578},
            C.VARIANTS[1]: {"sha256": "bc182ea44ae428da95e00ef2b1cc345633dddc9637031929fa0d8b178cb7fa7a", "bytes": 19802818}},
        "actual_builds": 2, "actual_case_processes": 6, "new_dependency_transports": 0,
        "original_task_outcome": "FAILURE", "original_final_comparison_emitted": False,
        "whole_module_graph_verification": {"actual_exit": 1, "output_complete": True,
            "classification": "NOT_QUALIFIED_OFFLINE_PROXY_OMITS_UNUSED_REQUIREMENT",
            "missing_module": "github.com/BurntSushi/toml@v1.2.1", "checksum_mismatch_observed": False},
        "selected_linked_dependencies": dependencies, "post_run_owned_workspace_logical_bytes": 408707196,
        "physical_reclaim_or_peak_disk_claim": False,
        "presealed_plan": {"sha256": "610566abc43021fd3edc9cedf28a9f26bc8f55d2f6410dec41dc98d2e4fdbbcb", "bytes": 4826},
        "private_read_only_reconciliation": {"sha256": "28d2393e2c1a90371a33c7d05181bf67c5dfab4b98a771eeee0f2259e00cac77", "bytes": 60968},
    })
    P.require(type(value["variants"]) is dict and set(value["variants"]) == set(C.VARIANTS))
    observations = 0
    for variant in C.VARIANTS:
        cases = value["variants"][variant]
        P.require(type(cases) is list and len(cases) == len(C.CASES))
        for case, row, (stderr_sha, stderr_bytes) in zip(C.CASES, cases, STDERR_PINS[variant]):
            P.require(type(row) is dict and set(row) == {"case", "command", "stdout_utf8", "stderr_diagnostics"})
            P.exact(row["case"], case)
            panic = variant == C.VARIANTS[0] and case != "start-after-stop"
            raw = row["stdout_utf8"]
            P.require(type(raw) is str and len(raw) < 8 << 10 and raw.endswith("\n"))
            cmd = row["command"]
            P.require(type(cmd) is dict and set(cmd) == {"state", "actual_exit", "output_complete", "reason", "stdout", "stderr"})
            P.exact([cmd[k] for k in ("state", "actual_exit", "output_complete", "reason")], ["COMPLETE", 2 if panic else 0, True, None])
            P.exact(cmd["stdout"], {"sha256": P.sha(raw.encode()), "bytes": len(raw.encode())})
            P.exact(cmd["stderr"], {"sha256": stderr_sha, "bytes": stderr_bytes})
            P.exact(row["stderr_diagnostics"], {"runtime_nil_pointer_panic": panic,
                    "public_Chain_Init_frame": panic, "normal_process_complete": not panic})
            events = [document(line.encode()) for line in raw.splitlines()]
            P.exact(events, expected_events(case, variant, proof))
            observations += len(events)
    return {
        "kind": "recorded-public-chain-terminal-lifecycle-check", "recorded_cases": 6,
        "recorded_parent_raw_exits": [2, 0, 2], "recorded_candidate_raw_exits": [0, 0, 0],
        "recorded_event_observations": observations, "positive_queries_and_clean_reopens": 4,
        "independently_reconstructed_witness_levels": 256, "selected_linked_modules": 25,
        "whole_module_graph_verification": "NOT_QUALIFIED", "original_task_outcome": "FAILURE",
        "recorded_reference_platform": "darwin/arm64", "reference_processes_executed_by_this_check": 0,
        "source": expected_source(), "scope": dict(SCOPE),
        "reader_inputs_sha256": {name: P.sha(P.read_regular(HERE / name, 1 << 20)) for name in INPUTS},
        "raw_stderr_or_private_receipts_rehashed_by_this_check": False,
        "consumer_result": "REFUSED",
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
        print("Recorded public Chain lifecycle refused; preserve failures and disabled acceptance.", file=sys.stderr)
        sys.exit(1)
