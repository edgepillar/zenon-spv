#!/usr/bin/env python3
"""Check finite node method observations, raw DB reads and complete seed bytes.

No node or database backend runs here. MATCH is scoped to one recorded method
with caller-selected context and unsigned synthetic acknowledgement metadata.
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
FIXTURES = HERE.parents[1] / "internal/testdata/conformance"
spec = importlib.util.spec_from_file_location("basic_account_bytes", HERE.parent / "gen-node-account-vectors/check.py")
ACCOUNT = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ACCOUNT)
CORPUS_SHA256 = "133735fd68c2631bfd58071053333bd4a99786b4b83dd065005f41228fcdb204"
INPUTS = {"account-segments.json": ACCOUNT.INPUTS["account-segments.json"]}
NODE = {k: v for k, v in ACCOUNT.NODE.items() if k != "function"}
NODE["methods"] = ["verifier.AccountBlockVerifier.AccountBlock", "verifier.AccountBlockVerifier.AccountBlockTransaction"]
SCOPE = {"actual_node_entry_point_execution": True, "actual_memory_account_and_momentum_stores": True,
         "synthetic_context_handle_selection": True, "synthetic_unsigned_momentum_metadata": True,
         "basic_account_checks_reached": True, "hash_signature_checks_reached": True,
         "new_signatures_generated": False, "disk_database_opened": False, "network_transport": False,
         "full_node_validation": False, "authenticated_context": False, "canonicality": False,
         "consensus_finality": False, "state_value_acceptance": False}
PROFILES = ("first-exact-ack", "version-zero", "version-two", "chain-zero", "chain-mismatch", "stored-chain-mismatch",
            "type-zero", "type-genesis", "type-unsupported", "type-contract-receive", "amount-negative", "amount-large",
            "token-zero", "send-from-hash-nonzero", "ack-missing", "ack-wrong-hash", "ack-corrupt-entry", "height-two-exact",
            "height-two-empty", "height-two-wrong-frontier", "height-two-corrupt-frontier", "height-two-previous-ack-ahead",
            "hash-zero", "hash-mutated", "signature-empty")
METHODS = ("AccountBlock", "AccountBlockTransaction")


def varint(number):
    ACCOUNT.need(type(number) is int and 0 <= number < (1 << 64), "basic_proto_uint64")
    out = bytearray()
    while number >= 128:
        out.append((number & 127) | 128); number >>= 7
    out.append(number)
    return bytes(out)


def integer(field, number):
    return b"" if number == 0 else varint(field << 3) + varint(number)


def data(field, value):
    return b"" if not value else varint((field << 3) | 2) + varint(len(value)) + value


def nested_hash(value):
    return data(1, bytes.fromhex(value))


def account_proto(wire):
    """Independent proto3 encoding of the complete selected no-child block.

    Field tags come from the pinned nom/types schemas; no protobuf package or
    generated node code is imported. Zero hashes remain present nested messages.
    """
    ACCOUNT.need(wire["descendantBlocks"] == [], "basic_proto_no_descendants")
    b = ACCOUNT.byte_oracle
    amount = abs(int(wire["amount"]))
    ack = wire["momentumAcknowledged"]
    return b"".join((integer(1, wire["version"]), integer(2, wire["chainIdentifier"]), integer(3, wire["blockType"]),
                     data(4, nested_hash(wire["hash"])), data(5, nested_hash(wire["previousHash"])), integer(6, wire["height"]),
                     data(7, data(1, nested_hash(ack["hash"])) + integer(2, ack["height"])),
                     data(8, data(1, b.address_bytes(wire["address"]))), data(9, data(1, b.address_bytes(wire["toAddress"]))),
                     data(10, amount.to_bytes(max(32, (amount.bit_length() + 7) // 8), "big")),
                     data(11, b.bech32_bytes(wire["tokenStandard"], "zts", 10)), data(12, nested_hash(wire["fromBlockHash"])),
                     data(14, b.base64_bytes(wire["data"]) if wire["data"] else b""), integer(15, wire["fusedPlasma"]),
                     integer(17, wire["difficulty"]), data(18, bytes.fromhex(wire["nonce"])), integer(19, wire["basePlasma"]),
                     integer(20, wire["usedPlasma"]), data(21, nested_hash(wire["changesHash"])),
                     data(22, b.base64_bytes(wire["publicKey"]) if wire["publicKey"] else b""),
                     data(23, b.base64_bytes(wire["signature"]) if wire["signature"] else b"")))


def momentum_proto(identifier):
    return b"".join((integer(1, 1), integer(2, 99), data(3, nested_hash(identifier["hash"])),
                     data(4, nested_hash("00" * 32)), integer(5, identifier["height"]), data(9, nested_hash("00" * 32))))


def seed_records(identifier, payload):
    height = identifier["height"].to_bytes(8, "big")
    return {"00": data(1, nested_hash(identifier["hash"])) + integer(2, identifier["height"]),
            "01" + identifier["hash"]: height, "02" + height.hex(): payload}


def expected_rows():
    source = ACCOUNT.read_selected(FIXTURES / "account-segments.json", INPUTS["account-segments.json"])
    originals = {v["name"]: v["rpc"] for segment in source["segments"] for v in segment["vectors"]}
    ACCOUNT.need(len(originals) == 4, "basic_input_inventory")
    original = originals["user-type-2"]
    ACCOUNT.need(original["height"] == 1 and original["blockType"] == 2 and original["difficulty"] == 0,
                 "basic_selected_first_send")
    rows = []
    basic_errors = {"version-zero": "version_missing", "version-two": "version_invalid", "chain-zero": "chain_missing",
                    "chain-mismatch": "chain_mismatch", "stored-chain-mismatch": "chain_mismatch", "type-zero": "type_missing",
                    "type-genesis": "type_genesis", "type-unsupported": "type_unsupported", "type-contract-receive": "type_must_be_user",
                    "amount-negative": "amount_negative", "amount-large": "amount_too_big", "token-zero": "zts_missing",
                    "send-from-hash-nonzero": "from_hash_must_be_zero", "ack-missing": "ack_missing", "ack-wrong-hash": "ack_missing",
                    "ack-corrupt-entry": "internal_store_error", "height-two-empty": "internal_store_error",
                    "height-two-wrong-frontier": "previous_missing", "height-two-corrupt-frontier": "internal_store_error",
                    "height-two-previous-ack-ahead": "ack_gap"}
    tx_matches = {"first-exact-ack", "stored-chain-mismatch", "amount-negative", "ack-missing", "ack-wrong-hash", "ack-corrupt-entry"}
    for profile in PROFILES:
        wire, previous = copy.deepcopy(original), copy.deepcopy(original)
        plan = {"chain_id": 99, "account_seed": "empty", "momentum_seed": "exact"}
        fields = {"version-zero": ("version", 0), "version-two": ("version", 2), "chain-zero": ("chainIdentifier", 0),
                  "chain-mismatch": ("chainIdentifier", 100), "type-zero": ("blockType", 0), "type-genesis": ("blockType", 1),
                  "type-unsupported": ("blockType", 6), "type-contract-receive": ("blockType", 5),
                  "amount-negative": ("amount", "-1000"), "amount-large": ("amount", str(1 << 255)),
                  "token-zero": ("tokenStandard", ACCOUNT.encoded_payload(bytes(10), "zts")),
                  "send-from-hash-nonzero": ("fromBlockHash", "01" + "00" * 31), "hash-zero": ("hash", "00" * 32),
                  "hash-mutated": ("hash", ACCOUNT.flipped(bytes.fromhex(original["hash"])).hex()), "signature-empty": ("signature", None)}
        if profile in fields:
            field, value = fields[profile]; wire[field] = value
        if profile == "stored-chain-mismatch": plan["chain_id"] = 100
        if profile.startswith("ack-"):
            plan["momentum_seed"] = {"ack-missing": "empty", "ack-wrong-hash": "wrong_hash", "ack-corrupt-entry": "corrupt"}[profile]
        if profile.startswith("height-two-"):
            wire.update(height=2, previousHash=original["hash"])
            plan["account_seed"] = {"height-two-exact": "exact", "height-two-empty": "empty", "height-two-wrong-frontier": "wrong_hash",
                                    "height-two-corrupt-frontier": "corrupt", "height-two-previous-ack-ahead": "ack_ahead"}[profile]
        if plan["account_seed"] == "wrong_hash": previous["hash"] = ACCOUNT.flipped(bytes.fromhex(previous["hash"])).hex()
        if plan["account_seed"] == "ack_ahead": previous["momentumAcknowledged"]["height"] += 1
        account_records = {} if plan["account_seed"] == "empty" else seed_records(
            {"hash": previous["hash"], "height": previous["height"]},
            b"\xff" if plan["account_seed"] == "corrupt" else account_proto(previous))
        ack = copy.deepcopy(original["momentumAcknowledged"])
        if plan["momentum_seed"] == "wrong_hash": ack["hash"] = ACCOUNT.flipped(bytes.fromhex(ack["hash"])).hex()
        momentum_records = {} if plan["momentum_seed"] == "empty" else seed_records(
            ack, b"\xff" if plan["momentum_seed"] == "corrupt" else momentum_proto(ack))
        _, computed_hash = ACCOUNT.projection(wire)
        for method in METHODS:
            calls = [{"method": "Chain.GetAccountStore", "address": wire["address"],
                      "identifier": {"hash": wire["previousHash"], "height": wire["height"] - 1}},
                     {"method": "Chain.GetFrontierMomentumStore"}]
            reads = []
            def read(store, key):
                records = account_records if store == "account" else momentum_records
                reads.append({"store": store, "key": key, "value": records.get(key, b"").hex(),
                              "error": "" if key in records else "not_found"})
            if method == "AccountBlock":
                error = basic_errors.get(profile, "")
                if profile not in ("version-zero", "version-two", "chain-zero"):
                    calls.append({"method": "Momentum.ChainIdentifier"})
                    if profile in ("chain-mismatch", "stored-chain-mismatch"): calls.append({"method": "Momentum.ChainIdentifier"})
                if profile.startswith("height-two-"):
                    calls.append({"method": "Account.Frontier"}); read("account", "00")
                    read("account", "02" + (0 if plan["account_seed"] == "empty" else 1).to_bytes(8, "big").hex())
                if profile in ("first-exact-ack", "ack-missing", "ack-wrong-hash", "ack-corrupt-entry", "height-two-exact",
                               "height-two-previous-ack-ahead", "hash-zero", "hash-mutated", "signature-empty"):
                    calls.append({"method": "Momentum.GetMomentumByHeight", "height": ack["height"]})
                    read("momentum", "02" + ack["height"].to_bytes(8, "big").hex())
                    if profile in ("height-two-exact", "height-two-previous-ack-ahead"):
                        calls.append({"method": "Account.ByHeight", "height": 1}); read("account", "02" + (1).to_bytes(8, "big").hex())
            else:
                error = "" if profile in tx_matches else {"hash-zero": "hash_missing", "signature-empty": "signature_missing"}.get(profile, "hash_mismatch")
            rows.append({"name": "user-type-2/" + profile + "/" + method, "profile": profile, "method": method,
                         "store_plan": copy.deepcopy(plan), "account_block": copy.deepcopy(wire), "computed_hash": computed_hash.hex(),
                         "node_method_result": "REJECT" if error else "MATCH", "node_error": error, "store_calls": calls, "database_reads": reads,
                         "account_entries": [{"key": k, "value": v.hex()} for k, v in sorted(account_records.items())],
                         "momentum_entries": [{"key": k, "value": v.hex()} for k, v in sorted(momentum_records.items())]})
    return rows


def check(document):
    expected = {"format_version": 1, "source": NODE, "scope": SCOPE, "input_files_sha256": INPUTS, "observations": expected_rows()}
    ACCOUNT.need(ACCOUNT.exact(document, expected), "basic_exact_document_seed_bytes_reads_and_outcomes")
    rows = document["observations"]
    ACCOUNT.need(len(rows) == 50 and sum(r["node_method_result"] == "MATCH" for r in rows) == 11 and
                 sum(r["node_method_result"] == "REJECT" for r in rows) == 39, "basic_complete_selection")
    return {"status": "recorded_node_basic_store_methods_checked", "source_node_commit": NODE["commit"],
            "corpus_sha256": CORPUS_SHA256, "recorded_entry_point_calls": 50, "methods": 2,
            "complete_byte_preimages_checked": 50, "recorded_MATCH": 11, "recorded_REJECT": 39, "recorded_PANIC": 0,
            "complete_seeded_store_maps_checked": 100, "recorded_database_reads_checked": sum(len(r["database_reads"]) for r in rows),
            "actual_node_calls_in_checker": 0, "actual_signature_processes": 0, "context_authenticated": False,
            "runtime_acceptance_changed": False, "network_or_production_qualified": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-revision")
    args = parser.parse_args()
    if args.source_revision is not None:
        ACCOUNT.need(re.fullmatch(r"[0-9a-f]{40}", args.source_revision) is not None, "basic_source_revision")
    document = ACCOUNT.read_selected(FIXTURES / "node-account-basic.json", CORPUS_SHA256)
    report = check(document); report["source_revision"] = args.source_revision
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (ACCOUNT.signatures.Refused, ValueError, KeyError, TypeError, OSError):
        print(json.dumps({"status": "REFUSED", "stage": "node_account_basic_store_corpus"}), file=sys.stderr)
        sys.exit(1)
