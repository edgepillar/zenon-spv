#!/usr/bin/env python3
"""Independently check selected PoW bytes and finite memory-store method calls.

No node, protobuf/database backend, nonce search or signature process runs here.
A nonce match and a method match are different objects from authenticated block
history, full protocol validation or an enabled SPV PoW guarantee.
"""
import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("pow_basic_bytes", HERE / "check.py")
BASIC = importlib.util.module_from_spec(spec)
spec.loader.exec_module(BASIC)
ACCOUNT = BASIC.ACCOUNT
CORPUS_SHA256 = "560ff77f5fe092e99222399309da164c0539dec749e95b0e1788cd52fe30716f"
DIFFICULTIES = (0, 1, 2, 1000, (1 << 63) - 1, 1 << 63, (1 << 64) - 2, (1 << 64) - 1)
NONCES = ("0000000000000000", "0100000000000000", "0123456789abcdef", "ffffffffffffffff")
NODE = {k: v for k, v in ACCOUNT.NODE.items() if k != "function"}
NODE["functions"] = ["pow.GetAccountBlockHash", "pow.CheckPoWNonce", "pow.GetThresholdByDifficulty",
                     "common/crypto.Hash", "verifier.AccountBlockVerifier.AccountBlock",
                     "verifier.AccountBlockVerifier.AccountBlockTransaction"]
SCOPE = {"actual_node_entry_point_execution": True, "actual_memory_account_and_momentum_stores": True,
         "actual_pow_helpers": True, "synthetic_context_handle_selection": True,
         "synthetic_unsigned_momentum_metadata": True, "original_claimed_hashes_and_signatures_preserved": True,
         "unsigned_difficulty_selection": True, "zero_difficulty_producer_helper_called": False,
         "nonce_generation": False, "wallet_api_calls": False, "new_signatures_generated": False,
         "disk_database_opened": False, "network_transport": False, "full_node_validation": False,
         "authenticated_context": False, "canonicality": False, "consensus_finality": False,
         "state_value_acceptance": False}


def expected():
    source = ACCOUNT.read_selected(BASIC.FIXTURES / "account-segments.json", BASIC.INPUTS["account-segments.json"])
    originals = {v["name"]: v["rpc"] for segment in source["segments"] for v in segment["vectors"]}
    ACCOUNT.need(len(originals) == 4, "pow_input_inventory")
    original = originals["user-type-2"]
    ACCOUNT.need(original["height"] == 1 and original["difficulty"] == 0 and original["nonce"] == "00" * 8,
                 "pow_original_first_send")
    byte_oracle = ACCOUNT.byte_oracle
    data_preimage = byte_oracle.address_bytes(original["address"]) + bytes.fromhex(original["previousHash"])
    data_hash = hashlib.sha3_256(data_preimage).digest()
    ack = original["momentumAcknowledged"]
    records = BASIC.seed_records(ack, BASIC.momentum_proto(ack))
    probes, rows = [], []
    for difficulty in DIFFICULTIES:
        threshold = 0 if difficulty == 0 else (1 << 64) - ((1 << 64) // difficulty)
        for nonce_hex in NONCES:
            nonce_preimage = bytes.fromhex(nonce_hex) + data_hash
            calculated_hash = hashlib.sha3_256(nonce_preimage).digest()
            calculated = int.from_bytes(calculated_hash[:8], "little")
            matched = calculated >= threshold
            profile = "difficulty-" + str(difficulty) + "/nonce-" + nonce_hex
            probes.append({"name": "user-type-2/" + profile, "difficulty_decimal": str(difficulty),
                           "nonce_hex": nonce_hex, "data_preimage_hex": data_preimage.hex(),
                           "node_data_hash": data_hash.hex(), "nonce_preimage_hex": nonce_preimage.hex(),
                           "node_calculated_hash": calculated_hash.hex(), "calculated_uint64_decimal": str(calculated),
                           "producer_threshold_status": "RETURNED" if difficulty else "SKIPPED_ZERO_DIFFICULTY",
                           "node_producer_threshold_decimal": str(threshold) if difficulty else "",
                           "node_producer_threshold_le_hex": threshold.to_bytes(8, "little").hex() if difficulty else "",
                           "node_nonce_matches": matched})
            wire = copy.deepcopy(original)
            wire.update(difficulty=difficulty, nonce=nonce_hex)
            _, computed_hash = ACCOUNT.projection(wire)
            for method in BASIC.METHODS:
                calls = [{"method": "Chain.GetAccountStore", "address": wire["address"],
                          "identifier": {"hash": wire["previousHash"], "height": 0}},
                         {"method": "Chain.GetFrontierMomentumStore"}]
                reads = []
                if method == "AccountBlock":
                    calls.append({"method": "Momentum.ChainIdentifier"})
                    error = "" if difficulty == 0 or matched else "pow_invalid"
                    if not error:
                        calls.append({"method": "Momentum.GetMomentumByHeight", "height": ack["height"]})
                        key = "02" + ack["height"].to_bytes(8, "big").hex()
                        reads.append({"store": "momentum", "key": key, "value": records[key].hex(), "error": ""})
                else:
                    # The independently selected original hash/signature are
                    # preserved; matching work cannot authorize a changed hash.
                    error = "" if computed_hash.hex() == original["hash"] else "hash_mismatch"
                rows.append({"name": "user-type-2/" + profile + "/" + method, "profile": profile, "method": method,
                             "store_plan": {"chain_id": 99, "account_seed": "empty", "momentum_seed": "exact"},
                             "account_block": copy.deepcopy(wire), "computed_hash": computed_hash.hex(),
                             "node_method_result": "REJECT" if error else "MATCH", "node_error": error,
                             "store_calls": calls, "database_reads": reads, "account_entries": [],
                             "momentum_entries": [{"key": k, "value": v.hex()} for k, v in sorted(records.items())]})
    return probes, rows


def check(document):
    probes, rows = expected()
    wanted = {"format_version": 1, "source": NODE, "input_files_sha256": BASIC.INPUTS,
              "scope": SCOPE, "pow_probes": probes, "observations": rows}
    ACCOUNT.need(ACCOUNT.exact(document, wanted), "pow_exact_inventory_bytes_stores_reads_outcomes")
    ACCOUNT.need(len(probes) == 32 and sum(p["node_nonce_matches"] for p in probes) == 10 and len(rows) == 64 and
                 sum(r["node_method_result"] == "MATCH" for r in rows) == 11 and
                 sum(r["node_method_result"] == "REJECT" for r in rows) == 53, "pow_complete_selection")
    return {"status": "recorded_node_pow_and_method_bytes_checked", "source_node_commit": NODE["commit"],
            "corpus_sha256": CORPUS_SHA256, "recorded_pow_probes": 32, "pow_preimages_checked": 32,
            "recorded_nonce_MATCH": 10, "recorded_nonce_REJECT": 22, "producer_threshold_calls_checked": 28,
            "zero_difficulty_producer_calls": 0, "recorded_account_method_calls": 64,
            "complete_account_preimages_checked": 64, "recorded_MATCH": 11, "recorded_REJECT": 53,
            "recorded_PANIC": 0, "complete_seeded_store_maps_checked": 128,
            "recorded_database_reads_checked": 10, "actual_node_calls_in_checker": 0,
            "actual_signature_processes": 0, "nonce_generation": False, "context_authenticated": False,
            "runtime_acceptance_changed": False, "network_or_production_qualified": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-revision")
    args = parser.parse_args()
    if args.source_revision is not None:
        ACCOUNT.need(re.fullmatch(r"[0-9a-f]{40}", args.source_revision) is not None, "pow_source_revision")
    document = ACCOUNT.read_selected(BASIC.FIXTURES / "node-account-pow.json", CORPUS_SHA256)
    report = check(document)
    report["source_revision"] = args.source_revision
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (ACCOUNT.signatures.Refused, ValueError, KeyError, TypeError, OSError):
        print(json.dumps({"status": "REFUSED", "stage": "node_account_pow_corpus"}), file=sys.stderr)
        sys.exit(1)
