#!/usr/bin/env python3
"""Independently check selected node transaction observations and signatures.

MATCH refers only to the exported method with opaque synthetic context stubs.
No node, chain, key creation, signing, or network request runs in this checker.
"""

import base64
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
import tempfile

HERE = Path(__file__).resolve().parent
FIXTURES = HERE.parents[1] / "internal/testdata/conformance"
NODE = {"repository": "https://github.com/zenon-network/go-zenon",
        "commit": "c64ed6279ff1d07335dab0ac36156dec8b5b71e9",
        "module_version": "v0.0.8-alphanet.0.20261009223306-c64ed6279ff1",
        "module_sum": "h1:3Vyk+6hw2dcWJLg15JEq7ITFOkaYvrVyI+W8Qb3Jlr4=",
        "function": "verifier.AccountBlockVerifier.AccountBlockTransaction"}
INPUTS = {"account-segments.json": "1faca6715c3865bae726a7a07f56ef2c43bd8a5a5c9816f618373312de43b048",
          "account-amounts.json": "55e6d89f2ad3a25f7f7a6232fe99a5a572e2937d844fc9a3828d9e4cdad4a6aa"}
CORPUS_SHA256 = "8f3858bf3cb0d77ded8ae4d12b500a3d21c54492f1f5f4dc5014da531f23df32"
SCOPE = {"actual_node_transaction_execution": True, "synthetic_opaque_context": True,
         "programmatic_nil_inputs": True, "new_signatures_generated": False,
         "basic_account_block_execution": False, "full_node_validation": False,
         "network_transport": False, "network_activation": False, "authenticated_context": False,
         "canonicality": False, "consensus_finality": False, "state_value_acceptance": False}
USER_MUTATIONS = ("hash-zero", "hash-bit", "data-bit", "chain", "height-zero", "height-two-with-zero-parent",
                  "previous-nonzero-at-one", "ack-zero", "signature-empty", "public-key-empty", "both-empty",
                  "public-key-short31", "public-key-long33", "signature-short63", "signature-long65",
                  "signature-bit", "public-key-bit", "changes-hash-bit", "base-plasma-one", "used-plasma-one",
                  "amount-negative", "amount-nil", "token-bit", "nonce-bit", "difficulty-one", "fused-plasma-one",
                  "to-address-bit", "from-hash-bit", "ack-height")
EMBEDDED_MUTATIONS = ("version-zero", "version-two", "type-zero", "type-six", "chain-zero", "chain-different",
                      "receive-amount-one", "receive-token-nonzero", "receive-to-nonzero", "receive-from-zero",
                      "difficulty-one", "fused-plasma-one")


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


byte_oracle = load("account_node_byte_primitives", HERE.parent / "gen-node-momentum-vectors/check.py")
signatures = load("account_node_signature_backend", HERE.parent / "gen-node-momentum-vectors/check-signatures.py")


def need(condition, stage):
    if not condition:
        raise signatures.Refused(stage)


def exact(a, b):
    return json.dumps(a, sort_keys=True, separators=(",", ":")) == json.dumps(b, sort_keys=True, separators=(",", ":"))


def read_selected(path, digest):
    with signatures.regular_file(path, 512 << 10, "account_corpus_file") as (stream, before):
        raw = stream.read((512 << 10) + 1)
        after = os.fstat(stream.fileno())
        need(len(raw) <= 512 << 10 and (before.st_size, before.st_mtime_ns) ==
             (after.st_size, after.st_mtime_ns), "account_corpus_changed_or_bound")
    need(hashlib.sha256(raw).hexdigest() == digest, "account_input_pin")
    return json.loads(raw.decode("utf-8"), object_pairs_hook=signatures.json_pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(signatures.Refused("account_corpus_json")))


def encoded_payload(raw, hrp):
    # Independently reconstruct the two selected Bech32 bit mutations, including
    # their new checksums; no node encoder or SPV implementation is imported.
    alphabet = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    acc, bits, values = 0, 0, []
    for value in raw:
        acc = (acc << 8) | value; bits += 8
        while bits >= 5:
            bits -= 5; values.append((acc >> bits) & 31)
    if bits: values.append((acc << (5 - bits)) & 31)
    check = 1
    expanded = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    for value in expanded + values + [0] * 6:
        top = check >> 25; check = ((check & 0x1ffffff) << 5) ^ value
        for bit, generator in enumerate((0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3)):
            if (top >> bit) & 1: check ^= generator
    check ^= 1
    return hrp + "1" + "".join(alphabet[v] for v in values + [(check >> (5 * i)) & 31 for i in range(5, -1, -1)])


def flipped(raw):
    data = bytearray(raw); data[0] ^= 1
    return bytes(data)


def projection(wire, amount_nil=False):
    block = {k: copy.deepcopy(wire[k]) for k in
             ("version", "chainIdentifier", "blockType", "hash", "previousHash", "height", "momentumAcknowledged",
              "fromBlockHash", "fusedPlasma", "difficulty", "nonce", "publicKey", "signature")}
    address = byte_oracle.address_bytes(wire["address"])
    to = byte_oracle.address_bytes(wire["toAddress"])
    token = byte_oracle.bech32_bytes(wire["tokenStandard"], "zts", 10)
    amount = 0 if amount_nil else int(wire["amount"])
    magnitude = abs(amount)
    amount_bytes = magnitude.to_bytes(max(32, (magnitude.bit_length() + 7) // 8), "big")
    data = b"" if wire["data"] is None else byte_oracle.base64_bytes(wire["data"])
    descendants_hash = byte_oracle.digest(b"".join(byte_oracle.hash_bytes(child["hash"]) for child in wire["descendantBlocks"]))
    data_hash = byte_oracle.digest(data)
    block.update(address=address.hex(), toAddress=to.hex(), tokenStandard=token.hex(),
                 amount=None if amount_nil else amount, descendantBlocksHash=descendants_hash.hex(), dataHash=data_hash.hex())
    u64, h32 = byte_oracle.uint64, byte_oracle.hash_bytes
    ack = wire["momentumAcknowledged"]
    nonce = bytes.fromhex(wire["nonce"])
    need(len(nonce) == 8, "account_nonce_width")
    preimage = b"".join((u64(wire["version"]), u64(wire["chainIdentifier"]), u64(wire["blockType"]),
                         h32(wire["previousHash"]), u64(wire["height"]), h32(ack["hash"]), u64(ack["height"]),
                         address, to, amount_bytes, token, h32(wire["fromBlockHash"]), descendants_hash, data_hash,
                         u64(wire["fusedPlasma"]), u64(wire["difficulty"]), nonce))
    need(len(preimage) == 274 + len(amount_bytes), "account_preimage_width")
    return block, byte_oracle.digest(preimage)


def expected_cases():
    segments = read_selected(FIXTURES / "account-segments.json", INPUTS["account-segments.json"])
    amounts = read_selected(FIXTURES / "account-amounts.json", INPUTS["account-amounts.json"])
    vectors = [v for s in segments["segments"] for v in s["vectors"]] + amounts["vectors"]
    base = {v["name"]: v["rpc"] for v in vectors}
    cases = [("baseline/" + v["name"], v["name"], v["rpc"], False, False,
              "external_batched_type" if v["name"] == "embedded-type-4" else
              "descendants_must_be_zero" if v in amounts["vectors"] else "") for v in vectors]
    for mutation in USER_MUTATIONS:
        wire = copy.deepcopy(base["user-type-2"])
        error, amount_nil = "hash_mismatch", False
        if mutation == "hash-zero": wire["hash"] = "00" * 32; error = "hash_missing"
        elif mutation in ("hash-bit", "previous-nonzero-at-one", "changes-hash-bit", "from-hash-bit", "nonce-bit"):
            field = {"hash-bit": "hash", "previous-nonzero-at-one": "previousHash", "changes-hash-bit": "changesHash",
                     "from-hash-bit": "fromBlockHash", "nonce-bit": "nonce"}[mutation]
            wire[field] = flipped(bytes.fromhex(wire[field])).hex()
            if mutation == "previous-nonzero-at-one": error = "previous_must_be_zero"
            elif mutation == "changes-hash-bit": error = ""
        elif mutation == "data-bit": wire["data"] = base64.b64encode(byte_oracle.base64_bytes(wire["data"]) + b"\xff").decode()
        elif mutation == "chain": wire["chainIdentifier"] += 1
        elif mutation == "height-zero": wire["height"] = 0; error = "height_missing"
        elif mutation == "height-two-with-zero-parent": wire["height"] = 2; error = "previous_missing"
        elif mutation == "ack-zero": wire["momentumAcknowledged"] = {"hash": "00" * 32, "height": 0}; error = "ack_missing"
        elif mutation == "ack-height": wire["momentumAcknowledged"]["height"] += 1
        elif mutation in ("signature-empty", "public-key-empty", "both-empty"):
            if mutation != "signature-empty": wire["publicKey"] = ""
            if mutation != "public-key-empty": wire["signature"] = ""
            error = "public_key_missing" if mutation == "public-key-empty" else "signature_missing"
        elif mutation.startswith(("public-key-", "signature-")):
            field = "publicKey" if mutation.startswith("public-key-") else "signature"
            raw = byte_oracle.base64_bytes(wire[field])
            if "short" in mutation: raw = raw[:-1]
            elif "long" in mutation: raw += b"\0"
            else: raw = flipped(raw)
            wire[field] = base64.b64encode(raw).decode(); error = "signature_invalid"
        elif mutation in ("base-plasma-one", "used-plasma-one"):
            wire["basePlasma" if mutation == "base-plasma-one" else "usedPlasma"] = 1; error = ""
        elif mutation == "amount-negative": wire["amount"] = "-1000"; error = ""
        elif mutation == "amount-nil": wire["amount"] = "<nil>"; amount_nil = True
        elif mutation in ("difficulty-one", "fused-plasma-one"):
            wire["difficulty" if mutation == "difficulty-one" else "fusedPlasma"] = 1
        elif mutation in ("token-bit", "to-address-bit"):
            field, hrp, size = ("tokenStandard", "zts", 10) if mutation == "token-bit" else ("toAddress", "z", 20)
            wire[field] = encoded_payload(flipped(byte_oracle.bech32_bytes(wire[field], hrp, size)), hrp)
        else: raise signatures.Refused("account_mutation_selection")
        cases.append(("user-type-2/" + mutation, "user-type-2", wire, amount_nil, False, error))
    wire = copy.deepcopy(base["user-type-3"]); wire["amount"] = "<nil>"
    cases.append(("user-type-3/amount-nil", "user-type-3", wire, True, False, ""))
    for mutation in EMBEDDED_MUTATIONS:
        wire = copy.deepcopy(base["embedded-type-5"])
        if mutation in ("version-zero", "version-two", "type-zero", "type-six", "chain-zero", "chain-different"):
            field, value = {"version-zero": ("version", 0), "version-two": ("version", 2), "type-zero": ("blockType", 0),
                            "type-six": ("blockType", 6), "chain-zero": ("chainIdentifier", 0),
                            "chain-different": ("chainIdentifier", 100)}[mutation]
            wire[field] = value
        elif mutation == "receive-amount-one": wire["amount"] = "1"
        elif mutation == "receive-token-nonzero": wire["tokenStandard"] = base["user-type-2"]["tokenStandard"]
        elif mutation == "receive-to-nonzero": wire["toAddress"] = base["user-type-2"]["address"]
        elif mutation == "receive-from-zero": wire["fromBlockHash"] = "00" * 32
        else: wire["difficulty" if mutation == "difficulty-one" else "fusedPlasma"] = 1
        wire["hash"] = projection(wire)[1].hex()
        cases.append(("embedded-type-5/" + mutation, "embedded-type-5", wire, False, True, ""))
    for mutation in ("public-key-present", "signature-present", "both-present"):
        wire = copy.deepcopy(base["embedded-type-5"])
        if mutation != "signature-present": wire["publicKey"] = base["user-type-2"]["publicKey"]
        if mutation != "public-key-present": wire["signature"] = base["user-type-2"]["signature"]
        error = "signature_must_be_zero" if mutation == "signature-present" else "public_key_must_be_zero"
        cases.append(("embedded-type-5/" + mutation, "embedded-type-5", wire, False, False, error))
    cases.extend((name, "", None, False, False, "nil_pointer") for name in ("nil-transaction", "nil-block"))
    need(len(cases) == len({r[0] for r in cases}) == 58, "account_selection_inventory")
    return cases


def context_calls(wire, error):
    if wire is None or error in ("external_batched_type", "height_missing", "previous_must_be_zero", "previous_missing", "ack_missing"):
        return []
    calls = []
    if byte_oracle.address_bytes(wire["address"])[0] == 1:
        calls.append({"method": "GetMomentumStore", "identifier": wire["momentumAcknowledged"]})
    previous = wire["descendantBlocks"][0] if wire["descendantBlocks"] else wire
    calls.extend(({"method": "GetAccountStore", "address": wire["address"],
                   "identifier": {"hash": previous["previousHash"], "height": (previous["height"] - 1) % (1 << 64)}},
                  {"method": "GetFrontierMomentumStore"}))
    return calls


def validate(data):
    need(type(data) is dict and set(data) == {"format_version", "source", "input_files_sha256", "observations", "scope"}, "account_corpus_shape")
    need(type(data["format_version"]) is int and data["format_version"] == 1, "account_format")
    need(exact(data["source"], NODE) and exact(data["input_files_sha256"], INPUTS), "account_source")
    need(exact(data["scope"], SCOPE), "account_scope")
    cases, jobs = expected_cases(), []
    need(type(data["observations"]) is list and len(data["observations"]) == len(cases), "account_inventory")
    for row, (name, baseline, wire, nil_amount, recomputed, error) in zip(data["observations"], cases):
        need(type(row) is dict and set(row) == {"name", "baseline", "account_block", "block", "computed_hash", "amount_is_nil",
                                              "recomputed_claimed_hash", "node_transaction_result", "node_error", "context_calls"}, "account_row_shape")
        need(exact([row["name"], row["baseline"], row["account_block"], row["amount_is_nil"], row["recomputed_claimed_hash"]],
                   [name, baseline, wire, nil_amount, recomputed]), "account_selected_input")
        result = "PANIC" if wire is None else "REJECT" if error else "MATCH"
        need(exact(row["node_error"], error) and exact(row["node_transaction_result"], result), "account_node_outcome")
        need(exact(row["context_calls"], context_calls(wire, error)), "account_context_calls")
        if wire is None:
            need(row["block"] is None and row["computed_hash"] is None, "account_nil_projection")
            continue
        block, computed = projection(wire, nil_amount)
        need(exact(row["block"], block) and exact(row["computed_hash"], computed.hex()), "account_byte_projection")
        if computed.hex() == wire["hash"] and byte_oracle.address_bytes(wire["address"])[0] == 0:
            key = b"" if wire["publicKey"] is None else byte_oracle.base64_bytes(wire["publicKey"])
            signature = b"" if wire["signature"] is None else byte_oracle.base64_bytes(wire["signature"])
            if len(key) == 32 and len(signature) == 64:
                jobs.append((name, key, computed, signature, error != "signature_invalid"))
    need(len(jobs) == 16 and sum(j[-1] for j in jobs) == 14, "account_signature_inventory")
    return jobs


def run(path, selected, revision):
    need(revision is None or re.fullmatch("[0-9a-f]{40}", revision) is not None, "source_revision")
    data = read_selected(path, CORPUS_SHA256)
    jobs = validate(data)  # Entire selection, input, trace and byte preflight precedes OpenSSL.
    outcomes = []
    try:
        with tempfile.TemporaryDirectory(prefix="node-account-signatures-") as temporary:
            backend = signatures.Backend(selected, Path(temporary))
            for name, key, message, signature, expected in jobs:
                actual, details = backend.verify(key, message, signature)
                details.update(name=name, expected=expected, actual=actual)
                outcomes.append(details)
                need(actual == expected, "account_signature_outcome")
            identity = backend.identity()
    except signatures.Refused as failure:
        if failure.details is not None: outcomes.append(failure.details)
        failure.outcomes = outcomes
        raise
    return {"schema_version": 1, "status": "verified", "source_revision": revision,
            "source_revision_is_caller_asserted": True, "node_source": NODE, "corpus_sha256": CORPUS_SHA256,
            "input_files_sha256": INPUTS, "node_transaction_observations": 58, "node_transaction_matches": 20,
            "node_transaction_rejections": 36, "node_transaction_programmatic_panics": 2,
            "independent_byte_projections": 56, "independent_signature_processes": 16,
            "independent_signature_matches": 14, "independent_signature_rejections": 2,
            "backend": identity, "outcomes": outcomes, "new_node_execution": False,
            "new_signatures_generated": False, "authenticated_context": False, "full_node_validation": False,
            "network_or_production_qualified": False, "production_state_value_accepted": False}


def main(argv=None):
    try:
        parser = signatures.QuietParser(description=__doc__, allow_abbrev=False)
        parser.add_argument("--openssl", required=True)
        parser.add_argument("--corpus", type=Path, default=FIXTURES / "node-account-transactions.json")
        parser.add_argument("--source-revision")
        args = parser.parse_args(argv)
        report = run(args.corpus, args.openssl, args.source_revision)
    except signatures.Refused as failure:
        return signatures.emit_report({"schema_version": 1, "status": "refused", "error_stage": failure.stage,
                                       "outcomes": failure.outcomes, "network_or_production_qualified": False}, 2)
    except (OSError, ValueError, KeyError, TypeError, RecursionError, OverflowError):
        return signatures.emit_report({"schema_version": 1, "status": "refused", "error_stage": "account_corpus_or_backend_input",
                                       "network_or_production_qualified": False}, 2)
    return signatures.emit_report(report, 0, pretty=True)


if __name__ == "__main__":
    code = main()
    if code == 70: signatures.discard_failed_output_at_shutdown()
    sys.exit(code)
