#!/usr/bin/env python3
"""Independently check the mixed-height corpus using standard-library bytes.

No node or SPV implementation is imported. Go checks Ed25519 separately.
This checks envelope consistency, not execution, election or network finality.
"""

import base64
import json
from pathlib import Path
import sys

from check import address_bytes, check_vector, digest, require
from check_account import check_account


def check(path):
    corpus = json.loads(Path(path).read_text(encoding="utf-8"))
    require(corpus["format_version"] == 1, "unsupported corpus format")
    require(corpus["source"]["commit"] == "3a4131e63881058b6ce2ee81d3a41d0033fafc99", "wrong node pin")
    series, segments = corpus["chain"], corpus["segments"]
    require(len(series["vectors"]) == 19 and len(segments) == 2, "incomplete corpus")
    anchor = series["anchor"]
    require(anchor["height"] == 5000 and anchor["chain_id"] == 99 and series["v2_from_height"] == 5009, "wrong domain or activation")
    by_height = {}
    previous, height = anchor["header_hash"], anchor["height"]
    for vector in series["vectors"]:
        check_vector(vector)
        h = vector["header"]
        require(h["height"] == height + 1 and h["previousHash"] == previous, "broken momentum chain")
        require(h["chainIdentifier"] == 99 and h["version"] == (2 if h["height"] >= 5009 else 1), "wrong activation/domain")
        if h["version"] == 2:
            require(h["nextFusionPrice"] >= 1000 and h["nextWorkPrice"] >= 1000, "invalid synthetic resource price")
        by_height[h["height"]] = vector
        previous, height = h["hash"], h["height"]
    members = {h: [] for h in (5003, 5007, 5011)}
    sends = []
    for segment, kind in zip(segments, (2, 5)):
        require(len(segment["vectors"]) == 3, "incomplete account segment")
        require(address_bytes(segment["rpc_address"]).hex() == segment["address"], "wrong account address")
        previous = "00" * 32
        for index, confirming in enumerate(members):
            vector = segment["vectors"][index]
            block, rpc = vector["block"], vector["rpc"]
            check_account(block, rpc)
            require(block["version"] == 1 and block["chainIdentifier"] == 99 and block["blockType"] == kind, "wrong account domain")
            require(block["address"] == segment["address"] and block["height"] == index + 1 and block["previousHash"] == previous, "broken account chain")
            ack = by_height[confirming - 1]["header"]
            require(block["momentumAcknowledged"] == {"hash": ack["hash"], "height": ack["height"]}, "wrong acknowledgement")
            key = base64.b64decode(block["publicKey"] or "", validate=True)
            signature = base64.b64decode(block["signature"] or "", validate=True)
            if kind == 2:
                require(len(key) == 32 and len(signature) == 64 and (b"\x00" + digest(key)[:19]).hex() == block["address"], "wrong signing identity")
                sends.append(block["hash"])
            else:
                require(not key and not signature and block["address"].startswith("01"), "unexpected embedded signature")
                require(block["fromBlockHash"] == sends[index], "wrong receive source")
            members[confirming].append({name: block[name] for name in ("address", "height", "hash")})
            previous = block["hash"]
    for height, vector in by_height.items():
        expected = sorted(members.get(height, []), key=lambda h: (h["address"], h["height"], h["hash"]))
        require(vector["content"] == expected, "wrong inclusion height/content")
    require(5016 - 5011 < 6 <= 5017 - 5011, "wrong depth boundary")
    require(5018 - 16 + 1 == 5003 < 5019 - 16 + 1, "wrong eviction boundary")
    print("Verified 6 account and 19 momentum preimages, 3 confirming heights, and the v1/v2 transition.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: check-delayed-inclusion.py CORPUS.json")
    check(sys.argv[1])
