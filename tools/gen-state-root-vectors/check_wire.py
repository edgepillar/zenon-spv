#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Independent bounded StateProof wire bytes and synthetic header/key binding.

The selected roots, keys, unsigned header identifiers and context pins are built
locally. They are research inputs, never authenticated headers or live profiles.
This module cannot produce production state-value acceptance.
"""

import argparse
import base64
import binascii
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("candidate_wire_byte_oracle", HERE / "check.py")
BYTE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(BYTE)
MAX_WIRE_BYTES = 32768
MAX_VALUE_BYTES = 4096
MAX_KEY_BYTES = 1024
MAX_CASES = 64
SCOPE = {"synthetic": True, "unsigned": True, "StateProof_serializer_executed": True,
         "primitive_proof_api_executed": True, "LedgerApi_method_executed": False,
         "rpc_transport_executed": False, "node_database_opened": False,
         "l1_staged_applier_executed": False, "node_lifecycle_executed": False,
         "node_tests_executed": False, "profile_agreed": False,
         "network_activation_authenticated": False, "header_authentication_executed": False,
         "runtime_state_proof_acceptance": False}
ROW_FIELDS = {"name", "value_hex", "proof_hex", "root", "wire"}


def serialization_inputs():
    return {"nil-nil": (None, None, BYTE.ZERO),
            "empty-empty": (b"", b"", bytes(range(32))),
            "nil-empty": (None, b"", (17).to_bytes(32, "big")),
            "empty-nil": (b"", None, bytes([255]) * 32),
            "base64-padding": (bytes([251]), bytes([255, 0]), bytes([170]) * 32),
            "binary-range": (bytes(range(256)), bytes(reversed(range(256))), BYTE.digest(b"synthetic-state-proof-wire-v1")),
            "stored-zero-bytes": (bytes(32), bytes([0, 255, 128, 1]), bytes([34]) * 32)}


def binding_inputs():
    key = BYTE.balance_key("11" * 20, "22" * 10)
    return {"stored-zero": (key, key, bytes(32), "balance"),
            "positive-one": (key, key, (1).to_bytes(32, "big"), "balance"),
            "missing-token": (BYTE.balance_key("11" * 20, "44" * 10), key, bytes(32), "balance"),
            "missing-address": (BYTE.balance_key("33" * 20, "22" * 10), key, bytes(32), "balance"),
            "excluded-mailbox": (bytes([4, 1, 2]), key, bytes(32), "unsupported"),
            "storage-is-not-a-balance": (bytes([3]) + bytes([17]) * 20 + bytes([4, 0, 255, 128]), key, bytes(32), "unsupported"),
            "present-empty-core-only": (key, key, b"", "balance")}


def expected_binding(name):
    BYTE.require(type(name) is str and name in binding_inputs(), "unknown selected binding case")
    key, leaf_key, value, domain = binding_inputs()[name]
    position = BYTE.digest(key)
    levels, values = BYTE.tree_levels([{"path": BYTE.digest(leaf_key).hex(), "value": value.hex()}])
    root = levels[0].get(0, BYTE.ZERO)
    index = int.from_bytes(position, "big")
    present = index in values
    return key, domain, root, values[index] if present else None, BYTE.canonical_proof(levels, values, position)


def selected_context(name):
    key, domain, root, _, _ = expected_binding(name)
    # Independently construct the known v3 research preimage. No candidate
    # serializer/header fields or provider root select this unsigned identifier.
    preimage = (BYTE.uint64(3) + BYTE.uint64(2) + bytes([85]) * 32 + BYTE.uint64(42) +
                BYTE.uint64(1700000000) + BYTE.digest(b"") + BYTE.digest(b"") + bytes([102]) * 32 +
                BYTE.uint64(7) + BYTE.uint64(11) + root)
    BYTE.require(len(preimage) == 208, "unexpected research header preimage")
    selection = {"name": name, "domain": domain, "raw_key": key.hex(), "root": root.hex(),
                 "header_version": 3, "header_height": 42, "header_hash": BYTE.digest(preimage).hex(),
                 "profile": "synthetic-candidate-wire-v1", "synthetic": True,
                 "header_authenticated": False, "network_profile_agreed": False}
    selection["context_pin"] = hashlib.sha256(json.dumps(selection, sort_keys=True, separators=(",", ":")).encode("ascii")).hexdigest()
    return selection


def encode_wire(value, proof, root):
    def field(raw):
        return None if raw is None else base64.b64encode(raw).decode("ascii")
    return json.dumps({"value": field(value), "proof": field(proof), "root": root.hex()}, separators=(",", ":"))


def decode_base64(value, limit):
    if value is None:
        return None
    BYTE.require(type(value) is str and len(value) <= ((limit + 2) // 3) * 4, "wire byte field exceeds bound or type")
    BYTE.require(value.isascii(), "non-ASCII Base64")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as error:
        raise ValueError("invalid bounded Base64") from error
    BYTE.require(len(decoded) <= limit and base64.b64encode(decoded).decode("ascii") == value,
                 "noncanonical Base64 or decoded byte bound")
    return decoded


def decode_wire(text):
    BYTE.require(type(text) is str and len(text) <= MAX_WIRE_BYTES, "wire type or character bound")
    raw = text.encode("utf-8")
    BYTE.require(len(raw) <= MAX_WIRE_BYTES, "wire byte bound")
    fields = json.loads(raw, object_pairs_hook=BYTE.object_pairs)
    BYTE.require(type(fields) is dict and set(fields) == {"value", "proof", "root"}, "closed StateProof wire shape required")
    root = BYTE.hex_bytes(fields["root"], 32)
    return decode_base64(fields["value"], MAX_VALUE_BYTES), decode_base64(fields["proof"], BYTE.MAX_PROOF_BYTES), root


def research_binding(text, name, selection):
    expected = selected_context(name)
    BYTE.require(type(selection) is dict and set(selection) == set(expected), "closed locally selected context required")
    BYTE.require(all(type(selection[key]) is type(value) for key, value in expected.items()), "selected context scalar types differ")
    BYTE.require(selection == expected, "selected header, key or context pin differs")
    value, proof, root = decode_wire(text)
    BYTE.require(root.hex() == selection["root"], "provider root differs from independently selected research header")
    BYTE.require(proof is not None and len(proof) > 0, "missing wire proof")
    key = BYTE.hex_bytes(selection["raw_key"])
    BYTE.require(len(key) <= MAX_KEY_BYTES, "selected key exceeds bound")
    present = value is not None
    BYTE.require(BYTE.proof_result(root, BYTE.digest(key), value if present else b"", proof, present) == "match",
                 "proof does not bind selected root/key/value/presence")
    if selection["domain"] != "balance":
        return {"name": name, "decision": "unsupported_typed_query", "typed_balance": None}
    BYTE.require(len(key) == 32 and key[0] == 3 and key[21] == 3, "invalid selected typed balance key")
    if present and len(value) != 32:
        return {"name": name, "decision": "unsupported_balance_value", "typed_balance": None}
    return {"name": name, "decision": "research_balance_match",
            "typed_balance": {"present": present, "amount": str(int.from_bytes(value or b"", "big"))}}


def optional_hex(text, limit):
    if text is None:
        return None
    BYTE.require(type(text) is str and len(text) <= limit * 2, "fixture byte field exceeds bound")
    return BYTE.hex_bytes(text)


def check_row(row, name, value, proof, root, extra=frozenset()):
    BYTE.require(type(row) is dict and set(row) == ROW_FIELDS | set(extra) and row["name"] == name, "wire case shape or selected name differs")
    BYTE.require(optional_hex(row["value_hex"], MAX_VALUE_BYTES) == value and
                 optional_hex(row["proof_hex"], BYTE.MAX_PROOF_BYTES) == proof, "selected wire bytes differ")
    BYTE.require(BYTE.hex_bytes(row["root"], 32) == root, "selected wire root differs")
    BYTE.require(row["wire"] == encode_wire(value, proof, root), "actual StateProof serializer bytes differ")
    BYTE.require(decode_wire(row["wire"]) == (value, proof, root), "independent wire decode differs")


def check_corpus(document):
    BYTE.require(type(document) is dict and set(document) == {"format_version", "kind", "source", "scope", "serialization_cases", "binding_cases"},
                 "closed wire corpus shape required")
    BYTE.require(type(document["format_version"]) is int and document["format_version"] == 1 and
                 document["kind"] == "candidate-state-proof-wire-research", "unsupported wire corpus format")
    BYTE.require(document["source"] == {"repository": "https://github.com/digitalSloth/go-zenon",
                                        "revision": BYTE.NODE_REVISION, "tree": BYTE.NODE_TREE}, "wrong selected node source")
    BYTE.require(type(document["scope"]) is dict and document["scope"] == SCOPE and
                 all(type(value) is bool for value in document["scope"].values()), "unsupported wire scope claim")
    rows, bindings = document["serialization_cases"], document["binding_cases"]
    for actual, expected in ((rows, serialization_inputs()), (bindings, binding_inputs())):
        BYTE.require(type(actual) is list and len(actual) <= MAX_CASES and len(actual) == len(expected), "wire case bound or inventory differs")
    for row, (name, (value, proof, root)) in zip(rows, serialization_inputs().items()):
        check_row(row, name, value, proof, root)
    decisions, context_pins = [], {}
    for row, name in zip(bindings, binding_inputs()):
        key, _, root, value, proof = expected_binding(name)
        check_row(row, name, value, proof, root, {"raw_key", "path", "present", "node_result"})
        BYTE.require(optional_hex(row["raw_key"], MAX_KEY_BYTES) == key and BYTE.hex_bytes(row["path"], 32) == BYTE.digest(key),
                     "selected raw key or single-hash path differs")
        BYTE.require(type(row["present"]) is bool and row["present"] == (value is not None), "selected null/presence differs")
        BYTE.require(row["node_result"] == BYTE.proof_result(root, BYTE.digest(key), value or b"", proof, value is not None) == "match",
                     "independent primitive proof verdict differs")
        selection = selected_context(name)
        decisions.append(research_binding(row["wire"], name, selection))
        context_pins[name] = selection["context_pin"]
    all_rows = rows + bindings
    return {"serialization_cases": len(rows), "binding_cases": len(bindings), "serializer_comparisons": len(all_rows),
            "node_proof_comparisons": len(bindings), "nil_value_observations": sum(row["value_hex"] is None for row in all_rows),
            "empty_value_observations": sum(row["value_hex"] == "" for row in all_rows),
            "research_balance_matches": sum(row["decision"] == "research_balance_match" for row in decisions),
            "unsupported_typed_query_refusals": sum(row["decision"] == "unsupported_typed_query" for row in decisions),
            "unsupported_balance_value_refusals": sum(row["decision"] == "unsupported_balance_value" for row in decisions),
            "binding_decisions": decisions, "synthetic_context_pins": context_pins,
            "reference_StateProof_serializer_executed": True, "reference_LedgerApi_method_executed": False,
            "reference_rpc_transport_executed": False, "reference_database_opened": False,
            "header_authentication_qualified": False, "production_acceptance_enabled": False,
            "profile_agreed": False, "network_activation_authenticated": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, default=HERE / "testdata/candidate-state-proof-wire.json")
    parser.add_argument("--source-revision")
    args = parser.parse_args(argv)
    if args.source_revision is not None:
        BYTE.require(len(args.source_revision) == 40 and all(char in "0123456789abcdef" for char in args.source_revision), "invalid source revision")
    raw, document = BYTE.read_corpus(args.corpus)
    report = check_corpus(document)
    report.update({"source_revision": args.source_revision, "corpus_sha256": hashlib.sha256(raw).hexdigest(),
                   "node_revision": BYTE.NODE_REVISION, "node_tree": BYTE.NODE_TREE})
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError, RecursionError, UnicodeError):
        print("Candidate StateProof wire check failed; retain the original fixture and inspect locally.", file=sys.stderr)
        sys.exit(1)
