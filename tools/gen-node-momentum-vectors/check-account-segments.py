#!/usr/bin/env python3
"""Check linked account and momentum vectors without node or SPV dependencies.

Ed25519 verification is performed separately by the Go conformance tests.
"""

import json
from pathlib import Path
import sys

from check import address_bytes, check_anchor, check_vector, digest, require
from check_account import check_account, optional_base64


def check(path):
    corpus = json.loads(Path(path).read_text())
    require(corpus["format_version"] == 1, "unsupported corpus format")
    require(corpus["source"]["commit"] == "3a4131e63881058b6ce2ee81d3a41d0033fafc99", "wrong source pin")
    series = corpus["chain"]
    require(len(series["vectors"]) == 9 and len(corpus["segments"]) == 2, "incomplete corpus")
    anchor = series["anchor"]
    check_anchor(anchor)
    previous, height = anchor["header_hash"], anchor["height"]
    for vector in series["vectors"]:
        check_vector(vector)
        header = vector["header"]
        require(header["version"] == 1 and header["chainIdentifier"] == anchor["chain_id"], "wrong momentum domain")
        require(header["previousHash"] == previous and header["height"] == height + 1, "broken momentum chain")
        previous, height = header["hash"], header["height"]
    members = []
    for segment, types in zip(corpus["segments"], [(2, 3), (5, 4)]):
        require(len(segment["vectors"]) == 2, "incomplete account segment")
        require(address_bytes(segment["rpc_address"]).hex() == segment["address"], "wrong segment address")
        previous = "00" * 32
        for index, (vector, kind) in enumerate(zip(segment["vectors"], types)):
            block, rpc = vector["block"], vector["rpc"]
            check_account(block, rpc)
            require(block["version"] == 1 and block["chainIdentifier"] == anchor["chain_id"], "wrong account domain")
            require(block["blockType"] == kind and block["address"] == segment["address"], "wrong account type/address")
            require(block["height"] == index + 1 and block["previousHash"] == previous, "broken account chain")
            require(block["momentumAcknowledged"] == {"hash": anchor["header_hash"], "height": anchor["height"]}, "wrong acknowledgement")
            key = optional_base64(block["publicKey"])
            signature = optional_base64(block["signature"])
            if kind in (2, 3):
                require(len(key) == 32 and len(signature) == 64, "wrong user signature shape")
                require((b"\x00" + digest(key)[:19]).hex() == block["address"], "wrong user key/address binding")
            else:
                require(not key and not signature and block["address"].startswith("01"), "embedded account unexpectedly signed")
            previous = block["hash"]
            members.append({field: block[field] for field in ("address", "height", "hash")})
    committing = series["vectors"][2]
    require(committing["content"] == sorted(members, key=lambda b: (b["address"], b["height"], b["hash"])), "incomplete account inclusion content")
    require(height - committing["header"]["height"] == 6, "wrong strict-past depth")
    print("Verified 4 node-derived account blocks and 9 linked momentum preimages.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: check-account-segments.py CORPUS.json")
    check(sys.argv[1])
