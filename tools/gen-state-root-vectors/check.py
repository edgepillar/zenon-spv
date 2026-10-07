#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Independent stdlib byte oracle for synthetic candidate state-root fixtures.

The bottom-up tree calculation deliberately differs from the node's recursive
path partitioning. This is a research checker, not a network proof API or an
enabled SPV profile. Its file/value limits are local fixture-work limits only.
"""

import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

HERE = Path(__file__).resolve().parent
ZERO = bytes(32)
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_VALUE_BYTES = 4096
MAX_PROOF_BYTES = 103 + 256 * 32 + MAX_VALUE_BYTES
NODE_REVISION = "56ce2c384966f2f1940967257a0788d3998a5eef"
NODE_TREE = "d5abff528566a561e1a53a46103cb4b15ff63c6c"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha3_256(data).digest()


def hex_bytes(text, width=None):
    require(type(text) is str and len(text) % 2 == 0, "expected hex bytes")
    require(all(char in "0123456789abcdefABCDEF" for char in text), "invalid hex alphabet")
    if width is not None:
        require(len(text) == width * 2, "invalid hex width")
    else:
        require(len(text) <= MAX_PROOF_BYTES * 2, "fixture byte field exceeds limit")
    return bytes.fromhex(text)


def uint64(value):
    require(type(value) is int and 0 <= value < 1 << 64, "expected uint64 integer")
    return struct.pack(">Q", value)


def object_pairs(pairs):
    document = {}
    for key, value in pairs:
        require(key not in document, "duplicate JSON field")
        document[key] = value
    return document


def read_corpus(path):
    with Path(path).open("rb") as stream:
        raw = stream.read(MAX_FILE_BYTES + 1)
    require(len(raw) <= MAX_FILE_BYTES, "fixture file exceeds limit")
    return raw, json.loads(raw, object_pairs_hook=object_pairs)


def parent(left, right):
    return ZERO if left == ZERO and right == ZERO else digest(left + right)


def balance_key(address, token):
    return b"\x03" + hex_bytes(address, 20) + b"\x03" + hex_bytes(token, 10)


def balance_magnitude(amount):
    require(type(amount) is str and 0 < len(amount) <= 1235, "invalid fixture amount")
    require(all("0" <= char <= "9" for char in amount), "invalid amount alphabet")
    number = int(amount)
    width = max(32, (number.bit_length() + 7) // 8)
    require(width <= MAX_VALUE_BYTES, "fixture value exceeds limit")
    return number.to_bytes(width, "big")


def tree_levels(leaves):
    require(type(leaves) is list and len(leaves) <= 1024, "fixture leaf count exceeds limit")
    values, nodes = {}, {}
    for leaf in leaves:
        position, value = hex_bytes(leaf["path"], 32), hex_bytes(leaf["value"])
        require(len(value) <= MAX_VALUE_BYTES, "fixture value exceeds limit")
        index = int.from_bytes(position, "big")
        require(index not in values, "duplicate leaf path")
        values[index] = value
        nodes[index] = digest(position + value)
    levels = {256: nodes}
    for depth in range(255, -1, -1):
        parents = {}
        for index in {index >> 1 for index in nodes}:
            result = parent(nodes.get(index * 2, ZERO), nodes.get(index * 2 + 1, ZERO))
            if result != ZERO:
                parents[index] = result
        nodes = parents
        levels[depth] = nodes
    return levels, values


def canonical_proof(levels, values, position):
    require(type(position) is bytes and len(position) == 32, "expected path bytes")
    index = int.from_bytes(position, "big")
    present = index in values
    value = values.get(index, b"")
    bitmap, siblings = bytearray(32), []
    for proof_index in range(256):
        depth = 255 - proof_index
        sibling = levels[depth + 1].get((index >> proof_index) ^ 1, ZERO)
        if sibling != ZERO:
            bitmap[proof_index // 8] |= 1 << (7 - proof_index % 8)
            siblings.append(sibling)
    leaf = digest(position + value) if present else ZERO
    proof = bytes([int(present)]) + position + leaf + bytes(bitmap) + struct.pack(">H", len(siblings))
    proof += b"".join(siblings)
    if present:
        proof += struct.pack(">I", len(value)) + value
    return proof


class ProofError(ValueError):
    pass


def decode_proof(proof):
    def malformed(ok):
        if not ok:
            raise ProofError("malformed")

    malformed(type(proof) is bytes and 99 <= len(proof) <= MAX_PROOF_BYTES)
    malformed(proof[0] in (0, 1))
    present, position, leaf, bitmap = proof[0] == 1, proof[1:33], proof[33:65], proof[65:97]
    count = int.from_bytes(proof[97:99], "big")
    malformed(count <= 256 and count == sum(bin(byte).count("1") for byte in bitmap))
    offset = 99 + count * 32
    malformed(len(proof) >= offset)
    value = b""
    if present:
        malformed(len(proof) >= offset + 4)
        length = int.from_bytes(proof[offset:offset + 4], "big")
        malformed(length <= MAX_VALUE_BYTES and len(proof) == offset + 4 + length)
        value = proof[offset + 4:]
        malformed(digest(position + value) == leaf)
    else:
        malformed(len(proof) == offset and leaf == ZERO)
    siblings, offset, canonical = {}, 99, True
    for index in range(256):
        if bitmap[index // 8] & (1 << (7 - index % 8)):
            sibling = proof[offset:offset + 32]
            siblings[255 - index] = sibling
            offset += 32
            canonical = canonical and sibling != ZERO
    return {"present": present, "path": position, "leaf": leaf, "value": value,
            "siblings": siblings, "canonical": canonical}


def proof_result(root, position, value, proof, present):
    require(type(root) is bytes and len(root) == 32, "invalid root width")
    require(type(position) is bytes and len(position) == 32, "invalid selected path width")
    require(type(value) is bytes and type(present) is bool, "invalid selected proof claim")
    try:
        decoded = decode_proof(proof)
        if decoded["present"] != present:
            return "malformed"
        if decoded["path"] != position:
            return "path_mismatch"
        if present and digest(position + value) != decoded["leaf"]:
            return "mismatch"
        current, index = decoded["leaf"], int.from_bytes(position, "big")
        for depth in range(255, -1, -1):
            sibling = decoded["siblings"].get(depth, ZERO)
            current = parent(sibling, current) if (index >> (255 - depth)) & 1 else parent(current, sibling)
        return "match" if current == root else "mismatch"
    except ProofError:
        return "malformed"


def check_balance_claim(case, state):
    require(case["domain"] == "balance", "unsupported typed balance domain")
    key = balance_key(case["address"], case["token"])
    require(hex_bytes(case["raw_key"]) == key, "substituted raw balance key")
    require(hex_bytes(case["path"], 32) == digest(key), "wrong locally derived balance path")
    require(hex_bytes(case["root"], 32) == hex_bytes(state["root"], 32), "wrong selected root")
    require(proof_result(hex_bytes(case["root"], 32), digest(key), hex_bytes(case["value"]),
                         hex_bytes(case["proof"]), case["present"]) == "match", "invalid selected balance proof")
    selected = [leaf for leaf in state["leaves"] if hex_bytes(leaf["path"], 32) == digest(key)]
    require(case["present"] == bool(selected), "presence differs from selected synthetic state")
    expected = hex_bytes(selected[0]["value"]) if selected else b""
    require(hex_bytes(case["value"]) == expected, "wrong balance claim bytes")
    return {"present": case["present"], "amount": str(int.from_bytes(expected, "big"))}


def check_header(header):
    fields = header["fields"]
    version = fields["version"]
    require(type(version) is int and version in (1, 2, 3), "unsupported research header version")
    integers = {name: uint64(fields[name]) for name in ("version", "chain_identifier", "height", "timestamp",
                                                        "next_fusion_price", "next_work_price")}
    previous, changes, root = (hex_bytes(fields[name], 32) for name in ("previous_hash", "changes_hash", "state_root"))
    data_hash = digest(hex_bytes(fields["data"]))
    require(type(fields["content"]) is list and len(fields["content"]) <= 1024, "invalid content count")
    content = [hex_bytes(row["address"], 20) + uint64(row["height"]) + hex_bytes(row["hash"], 32)
               for row in fields["content"]]
    require(content == sorted(content), "noncanonical synthetic content order")
    content_hash = digest(b"".join(content))
    preimage = (integers["version"] + integers["chain_identifier"] + previous + integers["height"] +
                integers["timestamp"] + data_hash + content_hash + changes)
    if version >= 2:
        preimage += integers["next_fusion_price"] + integers["next_work_price"]
    if version == 3:
        preimage += root
    require(len(preimage) == {1: 160, 2: 176, 3: 208}[version], "wrong header preimage length")
    require(data_hash == hex_bytes(header["data_hash"], 32), "wrong data hash")
    require(content_hash == hex_bytes(header["content_hash"], 32), "wrong content hash")
    require(preimage == hex_bytes(header["preimage"]), "wrong node preimage bytes")
    require(digest(preimage) == hex_bytes(header["hash"], 32), "wrong node header hash")
    return preimage


def check_corpus(document):
    require(type(document["format_version"]) is int and document["format_version"] == 1, "unsupported corpus format")
    require(document["kind"] == "candidate-state-root-byte-research", "wrong corpus kind")
    require(document["source"] == {"repository": "https://github.com/digitalSloth/go-zenon", "revision": NODE_REVISION,
                                    "tree": NODE_TREE, "selection": "complete-source-snapshot-local-replacement"}, "wrong node source pin")
    require(document["scope"] == {"synthetic": True, "unsigned": True, "candidate_primitive_execution": True,
                                  "network_activation_authenticated": False, "profile_agreed": False,
                                  "balance_maximum_pinned": False, "node_lifecycle_qualified": False,
                                  "runtime_state_proof_acceptance": False}, "unsupported corpus trust claim")
    require(all(type(value) is bool for value in document["scope"].values()), "invalid scope flag type")
    require(len(document["headers"]) == 10 and len(document["states"]) == 6 and len(document["proofs"]) == 41,
            "incomplete research corpus")
    headers, states, trees, decisions = {}, {}, {}, []
    for h in document["headers"]:
        require(h["name"] not in headers, "duplicate header name")
        check_header(h)
        headers[h["name"]] = h
    require(hex_bytes(headers["v1-zero-root"]["hash"], 32) == hex_bytes(headers["v1-populated-root-ignored"]["hash"], 32), "v1 hashed state root")
    require(hex_bytes(headers["v2-zero-root"]["hash"], 32) == hex_bytes(headers["v2-populated-root-ignored"]["hash"], 32), "v2 hashed state root")
    require(len({hex_bytes(headers[name]["hash"], 32) for name in ("v3-zero-root", "v3-balance-root", "v3-alternate-root")}) == 3,
            "v3 root binding mutation is vacuous")
    for s in document["states"]:
        require(s["name"] not in states and s["kind"] in ("balance", "path_native"), "invalid state identity")
        if s["kind"] == "balance":
            for leaf in s["leaves"]:
                key = balance_key(leaf["address"], leaf["token"])
                require(hex_bytes(leaf["raw_key"]) == key and hex_bytes(leaf["path"], 32) == digest(key), "wrong typed leaf key")
                require(hex_bytes(leaf["value"]) == balance_magnitude(leaf["amount"]), "wrong node balance magnitude")
        levels, values = tree_levels(s["leaves"])
        require(hex_bytes(s["root"], 32) == levels[0].get(0, ZERO), "wrong node sparse root")
        states[s["name"]], trees[s["name"]] = s, (levels, values)
    require(hex_bytes(headers["v3-balance-root"]["fields"]["state_root"], 32) == hex_bytes(states["synthetic-balance-magnitudes"]["root"], 32),
            "fixture header root differs from selected balance state")
    names, noncanonical = set(), []
    for p in document["proofs"]:
        require(p["name"] not in names and p["domain"] in ("balance", "excluded", "path_native"), "invalid proof identity")
        names.add(p["name"])
        state = states[p["state"]]
        proof = hex_bytes(p["proof"])
        result = proof_result(hex_bytes(p["root"], 32), hex_bytes(p["path"], 32), hex_bytes(p["value"]), proof, p["present"])
        require(result == p["node_result"], "independent proof verdict differs from node")
        if result == "match":
            decoded = decode_proof(proof)
            if decoded["canonical"]:
                levels, values = trees[p["state"]]
                require(proof == canonical_proof(levels, values, hex_bytes(p["path"], 32)), "node canonical proof bytes differ")
            else:
                noncanonical.append(p["name"])
        balance = check_balance_claim(p, state) if p["domain"] == "balance" else None
        if p["domain"] == "excluded":
            require(not p["present"] and result == "match", "excluded-domain absence control did not verify mathematically")
            require(digest(hex_bytes(p["raw_key"])) == hex_bytes(p["path"], 32), "wrong excluded raw key")
        decisions.append({"name": p["name"], "result": result, "proof_bytes": len(proof),
                          "typed_balance": balance, "typed_domain_refused": p["domain"] == "excluded"})
    require(noncanonical == ["stored-zero-sibling-equivalent", "absent-stored-zero-sibling-equivalent"],
            "changed candidate canonical-encoding diagnostic")
    return {"header_preimages": len(headers), "state_roots": len(states), "node_proof_comparisons": len(decisions),
            "matched_proofs": sum(d["result"] == "match" for d in decisions),
            "nonmatching_or_malformed_proofs": sum(d["result"] != "match" for d in decisions),
            "node_accepted_noncanonical_proofs": noncanonical, "decisions": decisions,
            "production_acceptance_enabled": False, "profile_agreed": False, "network_activation_authenticated": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, default=HERE / "testdata/candidate-v3-balances.json")
    parser.add_argument("--source-revision")
    args = parser.parse_args(argv)
    if args.source_revision is not None:
        require(len(args.source_revision) == 40 and all(c in "0123456789abcdef" for c in args.source_revision), "invalid source revision")
    raw, document = read_corpus(args.corpus)
    report = check_corpus(document)
    report.update({"source_revision": args.source_revision, "corpus_sha256": hashlib.sha256(raw).hexdigest(),
                   "node_revision": NODE_REVISION, "node_tree": NODE_TREE})
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError, RecursionError):
        print("Candidate state-root byte check failed; retain the original fixture and inspect locally.", file=sys.stderr)
        sys.exit(1)
