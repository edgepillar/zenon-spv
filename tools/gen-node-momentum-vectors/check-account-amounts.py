#!/usr/bin/env python3
"""Check the account-amount corpus with Python's standard library only."""

import base64
import hashlib
import json
from pathlib import Path
import struct
import sys


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha3_256(data).digest()


def check(path):
    corpus = json.loads(Path(path).read_text())
    require(corpus["format_version"] == 1, "unsupported corpus format")
    require(corpus["source"]["commit"] == "3a4131e63881058b6ce2ee81d3a41d0033fafc99", "wrong source pin")
    require(len(corpus["vectors"]) == 7, "incomplete corpus")
    for vector in corpus["vectors"]:
        block, rpc = vector["block"], vector["rpc"]
        amount = block["amount"]
        require(amount == int(rpc["amount"]), "amount differs across wire forms")
        magnitude = abs(amount)
        encoded = magnitude.to_bytes(max(32, (magnitude.bit_length() + 7) // 8), "big")
        require(encoded.hex() == vector["amount_bytes"], "amount encoding lost magnitude bytes")
        require(vector["scalar_valid"] == (0 <= amount < 2**255), "wrong scalar classification")
        u64 = lambda value: struct.pack(">Q", value)
        h = lambda field: bytes.fromhex(block[field])
        ack = block["momentumAcknowledged"]
        data_hash = digest(base64.b64decode(rpc["data"], validate=True))
        descendant_hash = digest(b"".join(bytes.fromhex(child["hash"]) for child in rpc["descendantBlocks"]))
        require(data_hash == h("dataHash"), "wrong data digest")
        require(descendant_hash == h("descendantBlocksHash"), "wrong descendant digest")
        preimage = b"".join([
            u64(block["version"]), u64(block["chainIdentifier"]), u64(block["blockType"]),
            h("previousHash"), u64(block["height"]), bytes.fromhex(ack["hash"]), u64(ack["height"]),
            h("address"), h("toAddress"), encoded, h("tokenStandard"), h("fromBlockHash"),
            descendant_hash, data_hash, u64(block["fusedPlasma"]), u64(block["difficulty"]), h("nonce"),
        ])
        require(digest(preimage).hex() == block["hash"] == rpc["hash"], "account-block preimage mismatch")
    print("Verified 7 node-derived account amount vectors.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: check-account-amounts.py CORPUS.json")
    check(sys.argv[1])
