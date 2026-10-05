"""Check independently packed address bytes from the seven pinned node corpora."""
from collections import Counter
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CORPORA = (
    "account-amounts.json", "account-segments.json", "content-scaling.json",
    "contract-batches.json", "delayed-inclusion.json",
    "historical-testnet-genesis.json", "momentum-v1-v2.json",
)
CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
GENERATORS = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
DERIVATION = "Python checksum arithmetic and direct 160-bit base32 packing; no Go decoder used."


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON member")
        result[key] = value
    return result


def read_json(path):
    raw = path.read_bytes()
    if len(raw) > 32 << 20:
        raise ValueError("source byte limit exceeded")
    return raw, json.loads(raw, object_pairs_hook=unique_object)


def address_strings(value):
    if isinstance(value, str):
        if value.startswith("z1"):
            yield value
    elif isinstance(value, list):
        for child in value:
            yield from address_strings(child)
    elif isinstance(value, dict):
        for child in value.values():
            yield from address_strings(child)


def address_bytes(encoded):
    if len(encoded) != 40 or encoded[:2] != "z1" or encoded != encoded.lower():
        raise ValueError("invalid fixture address shape")
    values = [CHARSET.index(char) for char in encoded[2:]]
    checksum = 1
    for value in [ord("z") >> 5, 0, ord("z") & 31] + values:
        top = checksum >> 25
        checksum = ((checksum & 0x1FFFFFF) << 5) ^ value
        for bit, generator in enumerate(GENERATORS):
            if top >> bit & 1:
                checksum ^= generator
    if checksum != 1:
        raise ValueError("invalid fixture address checksum")
    packed = 0
    for value in values[:-6]:
        packed = packed << 5 | value
    return packed.to_bytes(20, "big").hex()


def build_vectors(directory):
    counts = Counter()
    sources = []
    for name in CORPORA:
        raw, document = read_json(directory / name)
        sources.append({"name": name, "sha256": hashlib.sha256(raw).hexdigest()})
        counts.update(address_strings(document))
    if not counts or sum(counts.values()) > 4096:
        raise ValueError("address occurrence limit exceeded")
    return {
        "format_version": 1,
        "derivation": DERIVATION,
        "sources": sources,
        "total_occurrences": sum(counts.values()),
        "vectors": [
            {"encoded": address, "decoded_hex": address_bytes(address), "occurrences": count}
            for address, count in sorted(counts.items())
        ],
    }


def validate_document(actual, expected):
    # Canonical JSON text distinguishes booleans and floats from integer fields.
    options = {"sort_keys": True, "separators": (",", ":"), "allow_nan": False}
    return json.dumps(actual, **options) == json.dumps(expected, **options)


def main():
    try:
        expected = build_vectors(ROOT / "internal/testdata/conformance")
        _, actual = read_json(ROOT / "internal/fetch/testdata/bech32-address-vectors.json")
        if not validate_document(actual, expected):
            raise ValueError("address vectors differ")
    except (OSError, ValueError, TypeError):
        raise SystemExit("Address checksum vectors do not match the selected node corpora.")
    print(f"Verified {len(expected['vectors'])} address byte vectors and "
          f"{expected['total_occurrences']} fixture occurrences with independent Python checksum and base32 packing.")


if __name__ == "__main__":
    main()
