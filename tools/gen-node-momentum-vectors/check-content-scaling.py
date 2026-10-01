#!/usr/bin/env python3
"""Expand compact node vectors with independent Python SHA3-256 byte checks.

This checks serialization, not ledger execution. Go tests check signatures.
"""

import json
from pathlib import Path
import sys

from check import digest, require, uint64


def check(corpus):
    require(corpus["format_version"] == 1, "unsupported format")
    require(corpus["source"] == {
        "repository": "https://github.com/zenon-network/go-zenon",
        "commit": "3a4131e63881058b6ce2ee81d3a41d0033fafc99",
        "module_version": "v0.0.8-alphanet.0.20260924192459-3a4131e63881",
        "module_sum": "h1:7Yf9IL6y7T0gHnRrUs4oulsEcV6YXDRDiIKpUCurCHk=",
    }, "unexpected node pin")
    require(corpus["member_prefix"] == "synthetic flat content member:", "unexpected recipe")
    address = bytes.fromhex(corpus["member_address"])
    require(len(address) == 20 and address[0] == 0, "expected synthetic user address")
    anchor = corpus["anchor"]
    require(anchor == {"chain_id": 99, "height": 6000,
                       "header_hash": digest(b"synthetic flat content checkpoint").hex()}, "unexpected anchor")
    require([s["members"] for s in corpus["samples"]] == [1, 1000, 100000], "incomplete workloads")
    for sample in corpus["samples"]:
        count = sample["members"]
        hashes = [digest(corpus["member_prefix"].encode("ascii") + uint64(i)) for i in range(1, count + 1)]
        rows = [address + uint64(i + 1) + h for i, h in enumerate(hashes)]
        require(rows == sorted(rows), "recipe is not canonically ordered")
        require(sample["targets"] == [{"address": address.hex(), "height": i + 1, "hash": hashes[i].hex()}
                                      for i in (0, count // 2, count - 1)], "target mismatch")
        require(len(sample["headers"]) == 7, "incomplete header series")
        previous = anchor["header_hash"]
        for i, header in enumerate(sample["headers"]):
            require(header["version"] == 2 and header["chainIdentifier"] == 99 and
                    header["height"] == 6001 + i and header["previousHash"] == previous and
                    header["timestamp"] == 1700000000 + 10 * i and
                    header["nextFusionPrice"] == header["nextWorkPrice"] == 1000, "unexpected header")
            require(header["dataHash"] == digest(b"").hex(), "data mismatch")
            require(header["contentHash"] == digest(b"".join(rows) if i == 0 else b"").hex(), "content mismatch")
            require(header["changesHash"] == digest(b"synthetic changes").hex(), "changes mismatch")
            preimage = b"".join((uint64(2), uint64(99), bytes.fromhex(previous), uint64(6001 + i),
                                 uint64(header["timestamp"]), bytes.fromhex(header["dataHash"]),
                                 bytes.fromhex(header["contentHash"]), bytes.fromhex(header["changesHash"]),
                                 uint64(1000), uint64(1000)))
            require(digest(preimage).hex() == header["hash"], "header hash mismatch")
            previous = header["hash"]


if __name__ == "__main__":
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parents[2] / "internal/testdata/conformance/content-scaling.json"
    check(json.loads(path.read_text(encoding="utf-8")))
    print("Verified 101001 node-derived content members and 21 momentum preimages with Python SHA3-256")
