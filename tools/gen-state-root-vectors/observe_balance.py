#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Read-only, offline candidate balance observation; never a production proof.

The selection is an unsigned consumer input, not VerifiedState. There is no
accepting profile, trust-flag override, network transport or database writer.
"""

import argparse
import base64
import binascii
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

PROFILE = "research-balance-storage-smt-sha3-32-v1"
SELECTION_KIND = "unsigned-candidate-balance-selection-v1"
MAX_SELECTION = 8192
MAX_RESPONSE = 16384
MAX_PROOF = 103 + 256 * 32 + 32
ZERO = bytes(32)
ALPHABET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
NOT_PROVEN = ["STATE_VALUE_INCLUSION", "CANONICALITY", "CONSENSUS_FINALITY",
              "STATE_TRANSITION", "NETWORK_ACTIVATION", "FRESHNESS"]


class Refusal(ValueError):
    """A stable error code without private input or filesystem details."""


def need(condition, code):
    if not condition:
        raise Refusal(code)


def closed(value, fields, code):
    need(type(value) is dict and set(value) == set(fields), code)


def hash32(value):
    need(type(value) is str and len(value) == 64 and
         all(c in "0123456789abcdef" for c in value), "hash_encoding")
    return bytes.fromhex(value)


def u64(value, nonzero=False):
    need(type(value) is int and int(nonzero) <= value < 1 << 64, "uint64_selection")


def polymod(words):
    check = 1
    generators = (0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3)
    for word in words:
        top = check >> 25
        check = ((check & 0x1ffffff) << 5) ^ word
        for bit, generator in enumerate(generators):
            if top & (1 << bit):
                check ^= generator
    return check


def identifier(text, prefix, width):
    # These exact widths have no Bech32 padding. Both all-lower and all-upper
    # strings denote the same bytes; mixed case and Bech32m are refused.
    need(type(text) is str and len(text) == len(prefix) + 1 + width * 8 // 5 + 6,
         "identifier_width")
    need(text == text.lower() or text == text.upper(), "identifier_case")
    text = text.lower()
    need(text.startswith(prefix + "1"), "identifier_prefix")
    tail = text[len(prefix) + 1:]
    need(all(c in ALPHABET for c in tail), "identifier_alphabet")
    words = [ALPHABET.index(c) for c in tail]
    expanded = [ord(c) >> 5 for c in prefix] + [0] + [ord(c) & 31 for c in prefix]
    need(polymod(expanded + words) == 1, "identifier_checksum")
    number = 0
    for word in words[:-6]:
        number = (number << 5) | word
    return number.to_bytes(width, "big")


def request_id(value):
    need((type(value) is int and 0 <= value <= (1 << 53) - 1) or
         (type(value) is str and 0 < len(value) <= 64 and
          all(32 <= ord(c) < 127 for c in value)), "request_id_selection")


def selection(value):
    closed(value, ("kind", "profile", "genesis_hash", "context_pin", "header",
                   "address", "token_standard", "request_id", "claim"), "selection_shape")
    need(value["kind"] == SELECTION_KIND and value["profile"] == PROFILE, "research_profile")
    hash32(value["genesis_hash"])
    hash32(value["context_pin"])
    header = value["header"]
    closed(header, ("version", "chain_identifier", "height", "hash", "state_root"), "header_shape")
    need(type(header["version"]) is int and header["version"] == 3, "research_version")
    u64(header["chain_identifier"])
    u64(header["height"], nonzero=True)
    hash32(header["hash"])
    hash32(header["state_root"])
    address = identifier(value["address"], "z", 20)
    token = identifier(value["token_standard"], "zts", 10)
    request_id(value["request_id"])
    claim = value["claim"]
    closed(claim, ("present", "amount"), "claim_shape")
    need(type(claim["present"]) is bool, "claim_presence")
    amount = claim["amount"]
    need(type(amount) is str and 0 < len(amount) <= 78 and
         all("0" <= c <= "9" for c in amount) and
         (amount == "0" or amount[0] != "0"), "claim_amount_encoding")
    need(int(amount) < 1 << 256, "research_balance_bound")
    need(claim["present"] or amount == "0", "absent_claim_amount")
    return b"\x03" + address + b"\x03" + token


def prepare_request(value):
    key = selection(value)
    return {"jsonrpc": "2.0", "id": value["request_id"], "method": "ledger.getProof",
            "params": [value["header"]["height"], base64.b64encode(key).decode("ascii")]}


def b64(value, limit):
    need(type(value) is str and len(value) <= 4 * ((limit + 2) // 3), "base64_bound")
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        raise Refusal("base64_encoding") from None
    need(len(raw) <= limit, "base64_bound")
    need(base64.b64encode(raw).decode("ascii") == value, "base64_canonical")
    return raw


def proof_observation(raw, path, selected_root):
    need(99 <= len(raw) <= MAX_PROOF and raw[0] in (0, 1), "proof_shape")
    need(raw[1:33] == path, "proof_path")
    present, leaf, bitmap = raw[0] == 1, raw[33:65], raw[65:97]
    count = int.from_bytes(raw[97:99], "big")
    need(count <= 256 and count == sum(bin(b).count("1") for b in bitmap), "proof_siblings")
    offset = 99 + 32 * count
    need(len(raw) >= offset, "proof_length")
    value = b""
    if present:
        need(len(raw) == offset + 4 + 32 and
             int.from_bytes(raw[offset:offset + 4], "big") == 32, "research_balance_width")
        value = raw[offset + 4:]
        need(hashlib.sha3_256(path + value).digest() == leaf, "proof_leaf")
    else:
        need(len(raw) == offset and leaf == ZERO, "proof_absence")
    current, cursor, index = leaf, 99, int.from_bytes(path, "big")
    for level in range(256):
        sibling = ZERO
        if bitmap[level // 8] & (1 << (7 - level % 8)):
            sibling = raw[cursor:cursor + 32]
            cursor += 32
            need(sibling != ZERO, "research_noncanonical_sibling")
        left, right = (sibling, current) if (index >> level) & 1 else (current, sibling)
        current = ZERO if left == ZERO and right == ZERO else hashlib.sha3_256(left + right).digest()
    need(current == selected_root, "proof_selected_root")
    return present, value


def observe(selected, response):
    key = selection(selected)
    closed(response, ("jsonrpc", "id", "result"), "rpc_envelope")
    need(response["jsonrpc"] == "2.0" and
         type(response["id"]) is type(selected["request_id"]) and
         response["id"] == selected["request_id"], "rpc_identity")
    result = response["result"]
    closed(result, ("value", "proof", "root"), "rpc_result")
    root = hash32(result["root"])
    need(root == hash32(selected["header"]["state_root"]), "rpc_selected_root")
    raw = b64(result["proof"], MAX_PROOF)
    path = hashlib.sha3_256(key).digest()
    present, value = proof_observation(raw, path, root)
    if present:
        need(result["value"] is not None and b64(result["value"], 32) == value, "rpc_proof_value")
    else:
        # The candidate []byte wire can encode absent bytes as null or "".
        # Presence is decided by the proof flag, never by this JSON choice.
        need(result["value"] is None or b64(result["value"], 32) == b"", "rpc_proof_absence")
    amount = str(int.from_bytes(value, "big"))
    need(selected["claim"] == {"present": present, "amount": amount}, "selected_claim")
    return {"kind": "unsigned-candidate-balance-observation-v1",
            "candidate_observation": "MATCH", "present": present, "amount": amount,
            "profile": PROFILE, "proof_bytes": len(raw),
            "selected_header_hash": selected["header"]["hash"],
            "selected_height": selected["header"]["height"],
            "selected_chain_identifier": selected["header"]["chain_identifier"],
            "selected_genesis_hash": selected["genesis_hash"],
            "selected_context_pin": selected["context_pin"],
            "selected_state_root": result["root"], "locally_derived_path": path.hex(),
            "header_authentication_executed": False, "consumer_result": "REFUSED",
            "production_state_value_accepted": False, "proven": [], "not_proven": NOT_PROVEN.copy()}


def pairs(values):
    result = {}
    for key, value in values:
        need(key not in result, "json_duplicate_field")
        result[key] = value
    return result


def read_document(path, limit):
    flags = (os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) |
             getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0))
    # Windows has no portable O_NOFOLLOW. Refuse visible symlinks before open;
    # this is not an atomic reparse-point or concurrent-source guarantee.
    need(not Path(path).is_symlink(), "file_symlink")
    fd = os.open(path, flags)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_size <= limit, "file_bound_or_type")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(limit + 1)
        after = os.fstat(fd)
        need(len(raw) <= limit and (before.st_size, before.st_mtime_ns) ==
             (after.st_size, after.st_mtime_ns), "file_changed_or_bound")
    finally:
        os.close(fd)
    # Bound nesting before json.loads; braces inside strings do not count.
    depth, quoted, escaped = 0, False, False
    for byte in raw:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):
            depth += 1
            need(depth <= 8, "json_depth")
        elif byte in (93, 125):
            depth -= 1
    try:
        document = json.loads(raw, object_pairs_hook=pairs,
                              parse_constant=lambda _: (_ for _ in ()).throw(Refusal("json_constant")))
    except (UnicodeError, json.JSONDecodeError, ValueError, RecursionError) as error:
        if isinstance(error, Refusal):
            raise
        raise Refusal("json_encoding") from None
    return raw, document


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("request", "observe"))
    parser.add_argument("--selection", required=True)
    parser.add_argument("--response")
    args = parser.parse_args(argv)
    try:
        need((args.mode == "observe") == bool(args.response), "cli_mode_inputs")
        selected_raw, selected = read_document(args.selection, MAX_SELECTION)
        if args.mode == "request":
            report = {"kind": "unsigned-candidate-balance-request-v1", "request": prepare_request(selected),
                      "consumer_result": "REFUSED", "production_state_value_accepted": False}
        else:
            response_raw, response = read_document(args.response, MAX_RESPONSE)
            report = observe(selected, response)
            report["response_sha256"] = hashlib.sha256(response_raw).hexdigest()
        report["selection_sha256"] = hashlib.sha256(selected_raw).hexdigest()
        print(json.dumps(report, sort_keys=True, separators=(",", ":")))
        return 0  # Only the selected offline observation/request succeeded.
    except (Refusal, OSError) as error:
        print(json.dumps({"consumer_result": "REFUSED", "candidate_observation": "REFUSED",
                          "error": str(error) if isinstance(error, Refusal) else "file_io",
                          "production_state_value_accepted": False, "proven": [], "not_proven": NOT_PROVEN}))
        return 1


if __name__ == "__main__":
    sys.exit(main())
