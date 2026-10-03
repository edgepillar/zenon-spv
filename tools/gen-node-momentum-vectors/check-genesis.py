#!/usr/bin/env python3
"""Check a pinned historical testnet genesis with standard-library bytes.

The node generator constructs the genesis ledger. This checker independently
checks its momentum preimage, content bytes and RPC projections; it does not
re-execute genesis contracts or authenticate any running network or trust root.
"""

import base64
import binascii
import json
from pathlib import Path
import struct
import sys

from check import address_bytes, digest, require


NODE_SOURCE = {
    "repository": "https://github.com/zenon-network/go-zenon",
    "commit": "3a4131e63881058b6ce2ee81d3a41d0033fafc99",
    "module_version": "v0.0.8-alphanet.0.20260924192459-3a4131e63881",
    "module_sum": "h1:7Yf9IL6y7T0gHnRrUs4oulsEcV6YXDRDiIKpUCurCHk=",
}
GENESIS_CONFIG = {
    "repository": "https://github.com/HyperCore-Team/dockerized-testnet",
    "commit": "a8db3e7e42718fc025e604dcb45e4690fd2f3d7a",
    "path": "data/configs/genesis.json",
    "sha256": "a293ee85c4273e5119f18e23f5929f8382981be904109b53070f0fe6a89e1240",
}
HEADER_FIELDS = {
    "version", "chainIdentifier", "hash", "previousHash", "height", "timestamp",
    "dataHash", "contentHash", "changesHash", "publicKey", "signature",
    "nextFusionPrice", "nextWorkPrice",
}
WIRE_FIELDS = HEADER_FIELDS - {"dataHash", "contentHash"} | {"data", "content"}
CONTENT_FIELDS = {"address", "height", "hash"}
DEFAULT_CORPUS = Path(__file__).resolve().parents[2] / "internal/testdata/conformance/historical-testnet-genesis.json"


def object_fields(value, fields, label):
    require(type(value) is dict and set(value) == fields, f"wrong {label} fields")


def uint64(value, label):
    require(type(value) is int and 0 <= value < 2**64, f"wrong {label} uint64")
    return struct.pack(">Q", value)


def hex_bytes(value, size, label):
    require(type(value) is str and len(value) == size * 2 and
            all(character in "0123456789abcdef" for character in value),
            f"wrong {label} hex width or encoding")
    return bytes.fromhex(value)


def base64_bytes(value, label, nullable=False):
    if value is None and nullable:
        return b""
    require(type(value) is str, f"wrong {label} base64 type")
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as error:
        raise ValueError(f"wrong {label} base64 encoding") from error


def check_corpus(corpus):
    object_fields(corpus, {"format_version", "source", "genesis_config", "anchor", "vector"}, "corpus")
    require(type(corpus["format_version"]) is int and corpus["format_version"] == 1,
            "unsupported corpus format")
    require(corpus["source"] == NODE_SOURCE, "wrong node source pin")
    require(corpus["genesis_config"] == GENESIS_CONFIG, "wrong historical genesis config pin")
    anchor = corpus["anchor"]
    object_fields(anchor, {"chain_id", "height", "header_hash"}, "anchor")
    uint64(anchor["chain_id"], "anchor chain ID")
    uint64(anchor["height"], "anchor height")
    require(anchor["chain_id"] == 3 and anchor["height"] == 1, "wrong genesis anchor domain")
    anchor_hash = hex_bytes(anchor["header_hash"], 32, "anchor hash")
    require(any(anchor_hash), "zero genesis anchor hash")

    vector = corpus["vector"]
    object_fields(vector, {"name", "momentum", "header", "content"}, "vector")
    require(vector["name"] == "historical-testnet-genesis", "wrong genesis vector name")
    wire, header = vector["momentum"], vector["header"]
    object_fields(wire, WIRE_FIELDS, "momentum RPC")
    object_fields(header, HEADER_FIELDS, "header projection")
    for field in ("version", "chainIdentifier", "height", "timestamp", "nextFusionPrice", "nextWorkPrice"):
        uint64(wire[field], field)
        uint64(header[field], f"projected {field}")
        require(wire[field] == header[field], f"header projection mismatch: {field}")
    require(wire["version"] == 1 and wire["chainIdentifier"] == 3 and wire["height"] == 1,
            "wrong genesis envelope domain or version")
    require(wire["timestamp"] == 1666083600, "wrong historical genesis timestamp")
    for field in ("previousHash", "changesHash", "hash"):
        hex_bytes(wire[field], 32, field)
        require(wire[field] == header[field], f"header projection mismatch: {field}")
    require(wire["previousHash"] == "00" * 32, "nonzero genesis previous hash")
    require(any(hex_bytes(wire["changesHash"], 32, "changes hash")), "zero genesis changes hash")
    for field in ("publicKey", "signature"):
        require(base64_bytes(wire[field], f"RPC {field}", nullable=True) == b"" and
                base64_bytes(header[field], f"projected {field}", nullable=True) == b"",
                "genesis must remain unsigned")

    data = base64_bytes(wire["data"], "genesis data", nullable=True)
    require(data == b"", "wrong historical genesis data")
    members, projected = wire["content"], vector["content"]
    require(type(members) is list and type(projected) is list and
            len(members) == 47 and len(members) == len(projected), "wrong genesis content length")
    rows = []
    for member, expected in zip(members, projected):
        object_fields(member, CONTENT_FIELDS, "RPC content")
        object_fields(expected, CONTENT_FIELDS, "projected content")
        require(type(member["address"]) is str, "wrong RPC content address type")
        address = address_bytes(member["address"])
        require(address == hex_bytes(expected["address"], 20, "projected address"),
                "content address projection mismatch")
        encoded_height = uint64(member["height"], "content height")
        uint64(expected["height"], "projected content height")
        require(member["height"] == expected["height"] == 1, "wrong genesis content height")
        block_hash = hex_bytes(member["hash"], 32, "content hash")
        require(any(block_hash) and member["hash"] == expected["hash"], "content hash projection mismatch")
        rows.append(address + encoded_height + block_hash)
    require(rows == sorted(rows) and len(set(rows)) == len(rows),
            "genesis content must be unique and canonically ordered")

    data_hash, content_hash = digest(data), digest(b"".join(rows))
    require(data_hash == hex_bytes(header["dataHash"], 32, "data digest"), "data hash mismatch")
    require(content_hash == hex_bytes(header["contentHash"], 32, "content digest"), "content hash mismatch")
    # Version 1 excludes both price fields from the preimage, even if their
    # wire values are nonzero. Their types and projections are still checked.
    preimage = b"".join([
        uint64(wire["version"], "version"), uint64(wire["chainIdentifier"], "chain ID"),
        hex_bytes(wire["previousHash"], 32, "previous hash"), uint64(wire["height"], "height"),
        uint64(wire["timestamp"], "timestamp"), data_hash, content_hash,
        hex_bytes(wire["changesHash"], 32, "changes hash"),
    ])
    require(digest(preimage) == anchor_hash == hex_bytes(wire["hash"], 32, "momentum hash"),
            "genesis momentum preimage or anchor mismatch")
    return len(rows)


def check(path):
    corpus = json.loads(Path(path).read_text(encoding="utf-8"))
    count = check_corpus(corpus)
    print(f"Verified historical testnet genesis preimage and {count} content projections with Python SHA3-256.")


if __name__ == "__main__":
    if len(sys.argv) > 2:
        raise SystemExit("usage: check-genesis.py [CORPUS.json]")
    check(Path(sys.argv[1]) if len(sys.argv) == 2 else DEFAULT_CORPUS)
