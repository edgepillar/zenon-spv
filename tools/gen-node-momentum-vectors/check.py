#!/usr/bin/env python3
"""Cross-check node vectors using only Python's standard library.

This checks SHA3-256 preimages, integer encoding, Bech32 addresses, and
canonical content ordering. Ed25519 signatures are checked by the Go tests.
No node, SPV, wallet, or RPC dependency is used here.
"""

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


def uint64(value):
    return struct.pack(">Q", value)


def address_bytes(text):
    require(text == text.lower(), "expected a lowercase Bech32 address")
    hrp, separator, encoded = text.rpartition("1")
    require(separator and hrp == "z" and len(encoded) >= 6, "invalid address envelope")
    alphabet = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    values = [alphabet.index(char) for char in encoded]
    checksum = 1
    expanded = [ord(char) >> 5 for char in hrp] + [0] + [ord(char) & 31 for char in hrp]
    generators = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    for value in expanded + values:
        top = checksum >> 25
        checksum = ((checksum & 0x1FFFFFF) << 5) ^ value
        for bit, generator in enumerate(generators):
            if (top >> bit) & 1:
                checksum ^= generator
    require(checksum == 1, "invalid Bech32 checksum")
    accumulator, bits = 0, 0
    decoded = bytearray()
    for value in values[:-6]:
        accumulator = ((accumulator << 5) | value) & 0xFFF
        bits += 5
        if bits >= 8:
            bits -= 8
            decoded.append((accumulator >> bits) & 255)
    require(bits < 5 and ((accumulator << (8 - bits)) & 255) == 0, "invalid Bech32 padding")
    require(len(decoded) == 20, "invalid address length")
    return bytes(decoded)


def check_vector(vector):
    wire, expected = vector["momentum"], vector["header"]
    rows = []
    require(len(wire["content"]) == len(vector["content"]), "content length mismatch")
    for member, header in zip(wire["content"], vector["content"]):
        address = address_bytes(member["address"])
        require(address.hex() == header["address"], "address representation mismatch")
        require(member["height"] == header["height"] and member["hash"] == header["hash"], "content mismatch")
        rows.append(address + uint64(member["height"]) + bytes.fromhex(member["hash"]))
    require(rows == sorted(rows), "fixture content is not in canonical order")
    data_hash = digest(base64.b64decode(wire["data"], validate=True))
    content_hash = digest(b"".join(rows))
    require(data_hash.hex() == expected["dataHash"], "data hash mismatch")
    require(content_hash.hex() == expected["contentHash"], "content hash mismatch")
    preimage = b"".join([
        uint64(wire["version"]), uint64(wire["chainIdentifier"]),
        bytes.fromhex(wire["previousHash"]), uint64(wire["height"]),
        uint64(wire["timestamp"]), data_hash, content_hash,
        bytes.fromhex(wire["changesHash"]),
    ])
    require(wire["version"] in (1, 2), "unsupported checker profile")
    if wire["version"] == 2:
        preimage += uint64(wire["nextFusionPrice"]) + uint64(wire["nextWorkPrice"])
    require(digest(preimage).hex() == wire["hash"] == expected["hash"], "momentum hash mismatch")
    for field in ("version", "chainIdentifier", "previousHash", "height", "timestamp", "changesHash",
                  "publicKey", "signature", "nextFusionPrice", "nextWorkPrice"):
        require(wire[field] == expected[field], f"header projection mismatch: {field}")


def main():
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else (
        Path(__file__).resolve().parents[2] / "internal/testdata/conformance/momentum-v1-v2.json"
    )
    corpus = json.loads(path.read_text(encoding="utf-8"))
    require(corpus["format_version"] == 1, "unsupported corpus format")
    vectors = corpus["vectors"] + corpus["chain"]["vectors"]
    require(len(corpus["vectors"]) == 9 and len(corpus["chain"]["vectors"]) == 6, "incomplete corpus")
    for vector in vectors:
        try:
            check_vector(vector)
        except (KeyError, ValueError, struct.error) as error:
            raise ValueError(f"{vector['name']}: {error}") from error
    previous = corpus["chain"]["anchor"]["header_hash"]
    height = corpus["chain"]["anchor"]["height"]
    for vector in corpus["chain"]["vectors"]:
        header = vector["header"]
        require(header["previousHash"] == previous and header["height"] == height + 1, "broken fixture chain")
        require(header["chainIdentifier"] == corpus["chain"]["anchor"]["chain_id"], "chain identity mismatch")
        previous, height = header["hash"], header["height"]
    print(f"Verified {len(vectors)} node-derived momentum preimages with Python SHA3-256")


if __name__ == "__main__":
    main()
