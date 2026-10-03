#!/usr/bin/env python3
"""Check contract batch ordering and direct inclusion without node/SPV imports.

This verifies serialization, not VM execution or full-node transaction validity.
Ed25519 verification is performed separately by the Go conformance tests.
"""

import base64
import json
from pathlib import Path
import sys

from check import address_bytes, check_anchor, check_vector, hash_bytes, require, uint64
from check_account import check_account


def check(path):
    corpus = json.loads(Path(path).read_text())
    require(corpus["format_version"] == 1, "unsupported corpus format")
    require(corpus["source"]["commit"] == "3a4131e63881058b6ce2ee81d3a41d0033fafc99", "wrong source pin")
    series = corpus["chain"]
    require(len(series["vectors"]) == 9 and len(corpus["segments"]) == 1, "incomplete corpus")
    anchor = series["anchor"]
    check_anchor(anchor)
    previous, height = anchor["header_hash"], anchor["height"]
    for vector in series["vectors"]:
        check_vector(vector)
        header = vector["header"]
        require(header["version"] == 1 and header["chainIdentifier"] == anchor["chain_id"], "wrong momentum domain")
        require(header["previousHash"] == previous and header["height"] == height + 1, "broken momentum chain")
        previous, height = header["hash"], header["height"]
    segment = corpus["segments"][0]
    vectors = segment["vectors"]
    require(len(vectors) == 5 and len(corpus["batches"]) == 2, "incomplete contract batches")
    require(address_bytes(segment["rpc_address"]).hex() == segment["address"], "wrong segment address")
    previous = "00" * 32
    members = []
    for index, (vector, kind) in enumerate(zip(vectors, (4, 4, 5, 4, 5))):
        block, rpc = vector["block"], vector["rpc"]
        check_account(block, rpc)
        require(block["version"] == 1 and block["chainIdentifier"] == anchor["chain_id"], "wrong account domain")
        require(block["blockType"] == kind and block["address"] == segment["address"], "wrong account type/address")
        require(block["height"] == index + 1 and block["previousHash"] == previous, "broken account chain")
        require(block["momentumAcknowledged"] == {"hash": anchor["header_hash"], "height": anchor["height"]}, "wrong acknowledgement")
        key = base64.b64decode(block["publicKey"] or "", validate=True)
        signature = base64.b64decode(block["signature"] or "", validate=True)
        require(not key and not signature and block["address"].startswith("01"), "embedded account unexpectedly signed")
        if kind == 4:
            require(not rpc["descendantBlocks"], "child unexpectedly has descendants")
        previous = block["hash"]
        members.append({field: block[field] for field in ("address", "height", "hash")})
    before = {"hash": "00" * 32, "height": 0}
    for batch, heights in zip(corpus["batches"], ([1, 2, 3], [4, 5])):
        for commit_height in batch["commit_heights"]:
            uint64(commit_height)
        uint64(batch["receive_height"])
        uint64(batch["previous"]["height"])
        hash_bytes(batch["previous"]["hash"])
        receive = vectors[heights[-1] - 1]
        require(batch["commit_heights"] == heights and batch["receive_height"] == heights[-1], "wrong transaction commit order")
        require(batch["previous"] == before, "wrong transaction previous frontier")
        children = receive["rpc"]["descendantBlocks"]
        require(children == [vectors[h - 1]["rpc"] for h in heights[:-1]], "wrong receive descendants or order")
        require(receive["block"]["previousHash"] == children[-1]["hash"], "receive does not follow final child")
        require(receive["block"]["previousHash"] != before["hash"], "batch frontier confused with raw previousHash")
        before = {"hash": receive["block"]["hash"], "height": receive["block"]["height"]}
    committing = series["vectors"][2]
    require(committing["content"] == members, "child or receive missing from direct momentum content")
    require(height - committing["header"]["height"] == 6, "wrong strict-past depth")
    print("Verified 5 node-derived contract blocks, 2 batches, and 9 linked momentum preimages.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: check-contract-batches.py CORPUS.json")
    check(sys.argv[1])
