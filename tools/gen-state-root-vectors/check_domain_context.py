# SPDX-License-Identifier: MIT
"""Replay selected original-node ABI bytes with independent Python encodings."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
FIXTURE_SHA256 = "eb062c1377bdb9a07605ada1269480fc563508083f011bfdce05c322cd7d8955"
HARNESS_SHA256 = "050c4ab29737fc9e4a6acf2981712be433e88176ae7eecc9bd875c1c039ffbfc"
NODE = "938fca3b7787da86827a5eb63371509b36e14761"
SCHEMA = (("domainClass", 8), ("runtimeKind", 8), ("stfSpecHash", "hash"),
          ("inputSource", 8), ("execProfile", 8), ("foreignProfile", 8),
          ("profileConfigHex", "dynamic"), ("chainBindingHex", "dynamic"),
          ("minExecutors", 8), ("proposerPolicy", 8), ("finalityModel", 8), ("status", 8))


def require(condition):
    if not condition:
        raise ValueError("recorded domain-context mismatch")


def pinned(path, length, sha):
    with path.open("rb") as stream:
        raw = stream.read(length + 1)
    require(len(raw) == length and hashlib.sha256(raw).hexdigest() == sha)
    return raw


def uint(value, bits):
    require(type(value) is int and 0 <= value < 1 << bits)
    return value.to_bytes(32, "big")


def check(facts):
    require(facts["format"] == "zenon-candidate-domain-context-facts/v1")
    require(facts["source"]["revision"] == NODE)
    require(len(facts["records"]) == 8 and len(facts["configs"]) == 4
            and len(facts["subkeys"]) == len(facts["independent_full_keys"]) == 4)
    for row in facts["records"]:
        fields = row["fields"]
        require(set(fields) == {key for key, _ in SCHEMA})
        head, tails = [], b""
        for key, kind in SCHEMA:
            value = fields[key]
            if type(kind) is int:
                head.append(uint(value, kind))
            elif kind == "hash":
                raw = bytes.fromhex(value)
                require(len(raw) == 32)
                head.append(raw)
            else:
                raw = bytes.fromhex(value)
                head.append(uint(384 + len(tails), 64))
                tails += uint(len(raw), 64) + raw + b"\0" * (-len(raw) % 32)
        require((b"".join(head) + tails).hex() == row["packed_hex"])
    for row in facts["configs"]:
        packed = uint(row["withdrawalDelay"], 64) + uint(row["runtimeUpgradeDelay"], 64)
        require(packed.hex() == row["packed_hex"])
    address = bytes.fromhex(facts["settlement_address_hex"])
    require(len(address) == 20)
    for original, independent in zip(facts["subkeys"], facts["independent_full_keys"]):
        require(original["domain_id"] == independent["domain_id"] and original["name"] == independent["name"])
        domain = original["domain_id"]
        uint(domain, 32)
        for kind, prefix in (("record", b"\x01"), ("config", b"\x15")):
            subkey = prefix + domain.to_bytes(4, "big")
            require(subkey.hex() == original[kind + "_subkey_hex"])
            key = b"\x03" + address + b"\x04" + subkey
            require(len(key) == 27 and key.hex() == independent[kind + "_ledger_key_hex"])
            require(hashlib.sha3_256(key).hexdigest() == independent[kind + "_path_hex"])
    return {"format": "zenon-independent-domain-context/v1", "status": "MATH_ONLY",
            "source_revision": NODE, "original_node_reexecuted": False,
            "recorded_ABI_rows_matched": 12, "original_subkeys_matched": 8,
            "source_mapped_full_keys_and_paths": 8, "state_value_accepted": False,
            "submission_time_config_established": False, "network_execution": False}


def main():
    try:
        raw = pinned(ROOT / "internal/testdata/conformance/domain-context-abi.json", 20285, FIXTURE_SHA256)
        pinned(ROOT / "tools/gen-state-root-vectors/domain-context-abi_test.go.txt", 5453, HARNESS_SHA256)
        report = check(json.loads(raw))
        print(json.dumps(report, sort_keys=True, separators=(",", ":"), allow_nan=False))
        return 0
    except (OSError, ValueError, KeyError, TypeError, OverflowError):
        sys.stderr.write("domain-context: recorded encoding check failed\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
