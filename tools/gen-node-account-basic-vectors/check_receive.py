#!/usr/bin/env python3
"""Independently reconstruct recorded receive bytes, memory stores and reads.

The selected ledger records are synthetic, including deliberately incoherent
indexes and unsigned frontier identifiers. No node, database or signature
backend runs in this checker. A method MATCH is not execution eligibility.
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
spec = importlib.util.spec_from_file_location("receive_basic_bytes", HERE / "check.py")
BASIC = importlib.util.module_from_spec(spec)
spec.loader.exec_module(BASIC)
ACCOUNT = BASIC.ACCOUNT
CORPUS_SHA256 = "153c7563d863ccfb1563a1bdaca310215a415236ef0bf9e85c2e44228a1fe21c"
ENFORCEMENT_HEIGHT = 10109240
PROFILES = ("exact", "source-header-missing", "source-body-missing", "source-header-corrupt", "source-body-corrupt",
            "source-index-other-original", "confirmation-missing", "confirmation-before", "confirmation-after",
            "receiver-before-enforcement", "receiver-at-enforcement", "receiver-after-enforcement", "received", "received-empty",
            "ack-missing", "ack-wrong", "ack-corrupt", "previous-ack-after", "receive-amount-nonzero",
            "receive-token-nonzero", "receive-to-nonzero", "receive-source-zero")
SOURCE = dict(BASIC.NODE, receiver_mismatch_enforcement_height=ENFORCEMENT_HEIGHT)
SCOPE = {"actual_node_entry_point_execution": True, "actual_memory_account_and_momentum_stores": True,
         "synthetic_context_handle_selection": True, "synthetic_unsigned_ledger_records": True,
         "receive_field_checks_reached": True, "source_confirmation_and_received_checks_reached": True,
         "new_signatures_generated": False, "disk_database_opened": False, "mailbox_or_contract_execution": False,
         "network_transport": False, "full_node_validation": False, "authenticated_context": False,
         "canonicality": False, "consensus_finality": False, "state_value_acceptance": False}


def identifier(wire):
    return {"hash": wire["hash"], "height": wire["height"]}


def header_proto(wire):
    b = ACCOUNT.byte_oracle
    hh = BASIC.data(1, BASIC.nested_hash(wire["hash"])) + BASIC.integer(2, wire["height"])
    return BASIC.data(1, BASIC.data(1, b.address_bytes(wire["address"]))) + BASIC.data(2, hh)


def selection(originals, profile):
    receive = copy.deepcopy(originals["user-type-3"])
    previous = copy.deepcopy(originals["user-type-2"])
    source = copy.deepcopy(originals["embedded-type-4"])
    plan = {"source_seed": "exact", "confirmation_seed": "exact", "received_seed": "none",
            "acknowledgement_seed": "exact", "previous_seed": "exact", "ledger_frontier_height": 3000}
    if profile.startswith("source-"): plan["source_seed"] = profile
    if profile.startswith("confirmation-"): plan["confirmation_seed"] = profile
    if profile.startswith("receiver-"):
        plan.update(source_seed="receiver-mismatch", ledger_frontier_height={"receiver-before-enforcement": ENFORCEMENT_HEIGHT - 1,
                    "receiver-at-enforcement": ENFORCEMENT_HEIGHT, "receiver-after-enforcement": ENFORCEMENT_HEIGHT + 1}[profile])
        source["toAddress"] = source["address"]
    if profile.startswith("received"): plan["received_seed"] = profile
    if profile.startswith("ack-"): plan["acknowledgement_seed"] = profile
    if profile == "source-index-other-original": source = copy.deepcopy(originals["user-type-2"])
    if profile == "previous-ack-after":
        plan["previous_seed"] = profile; previous["momentumAcknowledged"]["height"] += 1
    if profile == "receive-amount-nonzero": receive["amount"] = "1"
    if profile == "receive-token-nonzero": receive["tokenStandard"] = previous["tokenStandard"]
    if profile == "receive-to-nonzero": receive["toAddress"] = receive["address"]
    if profile == "receive-source-zero": receive["fromBlockHash"] = "00" * 32
    return receive, previous, source, plan


def seed_maps(original, previous, source, plan):
    account = BASIC.seed_records(identifier(previous), BASIC.account_proto(previous))
    if plan["received_seed"] != "none":
        account["06" + original["fromBlockHash"]] = b"" if plan["received_seed"] == "received-empty" else (1).to_bytes(8, "big")
    momentum = {}
    ack = copy.deepcopy(original["momentumAcknowledged"])
    if plan["acknowledgement_seed"] == "ack-wrong": ack["hash"] = ACCOUNT.flipped(bytes.fromhex(ack["hash"])).hex()
    if plan["acknowledgement_seed"] != "ack-missing":
        momentum.update(BASIC.seed_records(ack, b"\xff" if plan["acknowledgement_seed"] == "ack-corrupt" else BASIC.momentum_proto(ack)))
    if plan["ledger_frontier_height"] != original["momentumAcknowledged"]["height"]:
        frontier = {"hash": "fe" + "00" * 31, "height": plan["ledger_frontier_height"]}
        momentum.update(BASIC.seed_records(frontier, BASIC.momentum_proto(frontier)))
    prefix = "03" + ACCOUNT.byte_oracle.address_bytes(source["address"]).hex()
    source_records = BASIC.seed_records(identifier(source), b"\xff" if plan["source_seed"] == "source-body-corrupt" else BASIC.account_proto(source))
    if plan["source_seed"] == "source-body-missing": source_records["02" + source["height"].to_bytes(8, "big").hex()] = b""
    momentum.update({prefix + key: value for key, value in source_records.items()})
    if plan["source_seed"] != "source-header-missing":
        momentum["09" + original["fromBlockHash"]] = b"\xff" if plan["source_seed"] == "source-header-corrupt" else header_proto(source)
    if plan["confirmation_seed"] != "confirmation-missing":
        adjustment = {"exact": 0, "confirmation-before": -1, "confirmation-after": 1}[plan["confirmation_seed"]]
        momentum["05" + original["fromBlockHash"]] = (original["momentumAcknowledged"]["height"] + adjustment).to_bytes(8, "big")
    return account, momentum


def expected_rows():
    fixture = ACCOUNT.read_selected(BASIC.FIXTURES / "account-segments.json", BASIC.INPUTS["account-segments.json"])
    originals = {v["name"]: v["rpc"] for segment in fixture["segments"] for v in segment["vectors"]}
    original = originals["user-type-3"]
    ACCOUNT.need(len(originals) == 4 and original["height"] == 2 and original["blockType"] == 3 and
                 original["difficulty"] == 0 and original["momentumAcknowledged"]["height"] == 3000 and
                 original["fromBlockHash"] == originals["embedded-type-4"]["hash"], "receive_selected_originals")
    basic_errors = {"source-header-missing": "source_block_missing", "source-body-missing": "source_block_missing",
                    "source-header-corrupt": "internal_store_error", "source-body-corrupt": "internal_store_error",
                    "confirmation-after": "source_block_missing", "receiver-at-enforcement": "source_receiver_mismatch",
                    "receiver-after-enforcement": "source_receiver_mismatch", "received": "source_already_received",
                    "received-empty": "source_already_received", "ack-missing": "ack_missing", "ack-wrong": "ack_missing",
                    "ack-corrupt": "internal_store_error", "previous-ack-after": "ack_gap",
                    "receive-amount-nonzero": "receive_amount_must_be_zero", "receive-token-nonzero": "receive_token_must_be_zero",
                    "receive-to-nonzero": "receive_to_must_be_zero", "receive-source-zero": "receive_from_hash_missing"}
    rows = []
    for profile in PROFILES:
        wire, previous, source, plan = selection(originals, profile)
        account, momentum = seed_maps(original, previous, source, plan)
        # The selected Delete operation leaves an iterator-visible tombstone.
        # A present empty received marker has no read error and is not deleted.
        deleted = {"03" + ACCOUNT.byte_oracle.address_bytes(source["address"]).hex() + "02" + source["height"].to_bytes(8, "big").hex()} if profile == "source-body-missing" else set()
        _, computed_hash = ACCOUNT.projection(wire)
        for method in BASIC.METHODS:
            calls = [{"method": "Chain.GetAccountStore", "address": wire["address"],
                      "identifier": {"hash": wire["previousHash"], "height": 1}}, {"method": "Chain.GetFrontierMomentumStore"}]
            reads = []
            def read(store, key):
                records = account if store == "account" else momentum
                reads.append({"store": store, "key": key, "value": records.get(key, b"").hex(),
                              "error": "not_found" if key not in records or (store == "momentum" and key in deleted) else ""})
            if method == "AccountBlock":
                error = basic_errors.get(profile, "")
                calls.append({"method": "Momentum.ChainIdentifier"})
                if not profile.startswith("receive-"):
                    calls.append({"method": "Account.Frontier"}); read("account", "00"); read("account", "020000000000000001")
                    calls.append({"method": "Momentum.GetMomentumByHeight", "height": 3000}); read("momentum", "020000000000000bb8")
                    if not profile.startswith("ack-"):
                        calls.append({"method": "Account.ByHeight", "height": 1}); read("account", "020000000000000001")
                        if profile != "previous-ack-after":
                            calls.append({"method": "Momentum.GetAccountBlockByHash", "hash": original["fromBlockHash"]})
                            read("momentum", "09" + original["fromBlockHash"])
                            if profile not in ("source-header-missing", "source-header-corrupt"):
                                read("momentum", "03" + ACCOUNT.byte_oracle.address_bytes(source["address"]).hex() + "02" + source["height"].to_bytes(8, "big").hex())
                                if profile not in ("source-body-missing", "source-body-corrupt"):
                                    calls.append({"method": "Momentum.GetBlockConfirmationHeight", "hash": original["fromBlockHash"]})
                                    read("momentum", "05" + original["fromBlockHash"])
                                    if profile != "confirmation-after":
                                        if source["toAddress"] != wire["address"]:
                                            calls.append({"method": "Momentum.Identifier"}); read("momentum", "00")
                                            read("momentum", "02" + plan["ledger_frontier_height"].to_bytes(8, "big").hex())
                                        if profile not in ("receiver-at-enforcement", "receiver-after-enforcement"):
                                            calls.append({"method": "Account.IsReceived", "hash": original["fromBlockHash"]})
                                            read("account", "06" + original["fromBlockHash"])
            else:
                error = "hash_mismatch" if profile.startswith("receive-") else ""
            rows.append({"name": "user-type-3/" + profile + "/" + method, "profile": profile, "method": method,
                         "store_plan": copy.deepcopy(plan), "account_block": copy.deepcopy(wire), "computed_hash": computed_hash.hex(),
                         "node_method_result": "REJECT" if error else "MATCH", "node_error": error, "store_calls": calls,
                         "database_reads": reads, "account_entries": [{"key": k, "value": v.hex(), "read_error": ""} for k, v in sorted(account.items())],
                         "momentum_entries": [{"key": k, "value": v.hex(), "read_error": "not_found" if k in deleted else ""}
                                              for k, v in sorted(momentum.items())]})
    return rows


def check(document):
    expected = {"format_version": 1, "source": SOURCE, "scope": SCOPE, "input_files_sha256": BASIC.INPUTS, "observations": expected_rows()}
    ACCOUNT.need(ACCOUNT.exact(document, expected), "receive_exact_document_seed_bytes_reads_and_outcomes")
    rows = document["observations"]
    ACCOUNT.need(len(rows) == 44 and sum(r["node_method_result"] == "MATCH" for r in rows) == 23 and
                 sum(r["node_method_result"] == "REJECT" for r in rows) == 21, "receive_complete_inventory")
    return {"status": "recorded_node_receive_store_methods_checked", "source_node_commit": SOURCE["commit"],
            "corpus_sha256": CORPUS_SHA256, "recorded_entry_point_calls": 44, "complete_byte_preimages_checked": 44,
            "recorded_MATCH": 23, "recorded_REJECT": 21, "recorded_PANIC": 0, "complete_seeded_store_maps_checked": 88,
            "recorded_database_reads_checked": sum(len(r["database_reads"]) for r in rows),
            "actual_node_calls_in_checker": 0, "actual_signature_processes": 0, "context_authenticated": False,
            "runtime_acceptance_changed": False, "execution_eligibility_proven": False, "network_or_production_qualified": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-revision")
    args = parser.parse_args()
    if args.source_revision is not None:
        ACCOUNT.need(re.fullmatch(r"[0-9a-f]{40}", args.source_revision) is not None, "receive_source_revision")
    document = ACCOUNT.read_selected(BASIC.FIXTURES / "node-account-receive.json", CORPUS_SHA256)
    report = check(document); report["source_revision"] = args.source_revision
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (ACCOUNT.signatures.Refused, ValueError, KeyError, TypeError, OSError):
        print(json.dumps({"status": "REFUSED", "stage": "node_account_receive_store_corpus"}), file=sys.stderr)
        sys.exit(1)
