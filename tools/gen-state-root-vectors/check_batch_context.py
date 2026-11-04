# SPDX-License-Identifier: MIT
"""Independent replay of pooled node proofs and synthetic consumer byte pins."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import struct

ROOT = Path(__file__).resolve().parents[2]
NODE = "938fca3b7787da86827a5eb63371509b36e14761"
TRACE_SHA = "773cda402e08709ffd73adfea355f73269b1470b7336c5a027ddd5b331ab9d96"
UNIT_SHA = "e4bfbdb7bff55f9719782c7e609240b2ba9aeefd0d0f42b7ee1948286e890366"
H = lambda value: hashlib.sha3_256(value).digest()
WORD = lambda value: struct.pack(">Q", value)
HEX = bytes.fromhex
ZERO = bytes(32)


def producer_bech32(address):
    require(len(address) == 20)
    value = int.from_bytes(address, "big")
    data = [(value >> (5 * (31 - i))) & 31 for i in range(32)]
    checksum = 1
    for item in [ord("z") >> 5, 0, ord("z") & 31] + data + [0] * 6:
        top = checksum >> 25
        checksum = ((checksum & 0x1ffffff) << 5) ^ item
        for i, generator in enumerate((0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3)):
            if (top >> i) & 1:
                checksum ^= generator
    checksum ^= 1
    charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    return "z1" + "".join(charset[n] for n in data + [(checksum >> (5 * (5 - i))) & 31 for i in range(6)])


def require(condition):
    if not condition:
        raise ValueError("three-witness byte replay differs")


def read_fixture(name, digest):
    with (ROOT / "internal/testdata/conformance" / name).open("rb") as stream:
        raw = stream.read(32769)
    require(len(raw) <= 32768 and hashlib.sha256(raw).hexdigest() == digest)
    return json.loads(raw)


def proof_root(row):
    raw, value, path = HEX(row["proof_hex"]), HEX(row["value_hex"]), HEX(row["path_hex"])
    require(len(raw) >= 99 and len(path) == 32 and raw[0] in (0, 1) and raw[1:33] == path)
    present = raw[0] == 1
    require(present == row["present"])
    count = int.from_bytes(raw[97:99], "big")
    require(count <= 256 and count == sum(bin(byte).count("1") for byte in raw[65:97]))
    cursor = 99 + count * 32
    leaf = H(path + value) if present else ZERO
    require(raw[33:65] == leaf)
    if present:
        require(len(raw) == cursor + 4 + len(value)
                and int.from_bytes(raw[cursor:cursor + 4], "big") == len(value)
                and raw[cursor + 4:] == value)
    else:
        require(not value and len(raw) == cursor)
    current, cursor = leaf, 99
    for level in range(256):
        sibling = ZERO
        if raw[65 + level // 8] & (1 << (7 - level % 8)):
            sibling = raw[cursor:cursor + 32]
            cursor += 32
            require(sibling != ZERO)  # This typed contract requires canonicality.
        if current == sibling == ZERO:
            continue
        current = H(sibling + current if path[31 - level // 8] & (1 << (level % 8)) else current + sibling)
    return current


def check(unit, trace):
    require(unit["format"] == "synthetic-owned-three-witness-workflow/v1" and unit["node_revision"] == NODE)
    require(unit["original_trace_sha256"] == TRACE_SHA and trace["source_fixture_values_are_one_original_snapshot"] is False)
    require(trace["scope"] == "SYNTHETIC_THREE_LEAF_TREE_NO_HEADER_OR_NETWORK_ACCEPTANCE"
            and trace["node_chain_wallet_RPC_or_transactions_started"] is False)
    require(len(trace["rows"]) == 4 and trace["domain_id"] == 1 and trace["batch_id"] == 0)
    config = unit["config"]
    selected, policy = config["header_profile"], config["header_policy"]
    p = config["query_profile"]
    entry = p["entry"]
    address = HEX(entry["settlement"])
    require(len(address) == 20 and address.hex() == trace["settlement_address_hex"])
    names = ("batch_entry", "domain_record", "domain_config", "absent_batch")
    for row, name, prefix, batch in zip(trace["rows"], names, (2, 1, 21, 2), (0, None, None, 1)):
        key = b"\x03" + address + b"\x04" + bytes([prefix]) + struct.pack(">I", entry["domain_id"])
        if batch is not None:
            key += WORD(batch)
        require(row["name"] == name and row["ledger_key_hex"] == key.hex() and row["path_hex"] == H(key).hex())
        require(proof_root(row).hex() == trace["root_hex"])
    require(sum(len(HEX(row["proof_hex"])) for row in trace["rows"][:3]) == 1781
            and sum(len(HEX(row["value_hex"])) for row in trace["rows"][:3]) == 1312)
    batch = HEX(trace["rows"][0]["value_hex"])
    domain_config = HEX(trace["rows"][2]["value_hex"])
    require(len(domain_config) == 64 and int.from_bytes(domain_config[:32], "big") == 30
            and int.from_bytes(domain_config[32:], "big") == 64)
    require(int.from_bytes(batch[12*32:13*32], "big") == 77
            and int.from_bytes(batch[13*32:14*32], "big") == 87)
    headers, wires = unit["headers"], unit["momentums"]
    require(len(headers) == len(wires) == 4)
    previous = selected["anchor"]["header_hash"]
    for index, (row, wire) in enumerate(zip(headers, wires)):
        require(row["height"] == 87 + index and row["version"] == 3 and row["chainIdentifier"] == 9001
                and row["previousHash"] == previous and row["stateRoot"] == trace["root_hex"])
        require(row["dataHash"] == row["contentHash"] == H(b"").hex()
                and wire["data"] == "" and wire["content"] == [])
        preimage = WORD(3) + WORD(9001) + HEX(previous) + WORD(row["height"]) + WORD(row["timestamp"])
        preimage += b"".join(HEX(row[name]) for name in ("dataHash", "contentHash", "changesHash"))
        preimage += WORD(row["nextFusionPrice"]) + WORD(row["nextWorkPrice"]) + HEX(row["stateRoot"])
        require(len(preimage) == 208 and H(preimage).hex() == row["hash"] == wire["hash"])
        pub = base64.b64decode(row["publicKey"], validate=True)
        require(len(pub) == 32 and len(base64.b64decode(row["signature"], validate=True)) == 64)
        require(wire["producer"] == producer_bech32(b"\0" + H(pub)[:19]))
        # Signature verification is executed by the Go owned-state controls,
        # separately from this Python encoding oracle.
        previous = row["hash"]
    schedule = config["producer_schedule"]
    s = WORD(schedule["chain_id"]) + WORD(len(schedule["coverage"]))
    for coverage in schedule["coverage"]:
        s += WORD(coverage["from_height"]) + WORD(coverage["through_height"])
    s += WORD(len(schedule["entries"]))
    for row in schedule["entries"]:
        s += WORD(row["height"]) + WORD(row["timestamp_unix"]) + HEX(row["producing_addr"])
    expected = unit["expected"]
    require(H(s).hex() == schedule["schedule_hash"] == expected["schedule_hash"])
    v3 = b"ZENON-EXPERIMENTAL-V3-CONTEXT\0\1"
    for anchor in (selected["genesis"], selected["anchor"]):
        v3 += WORD(anchor["chain_id"]) + WORD(anchor["height"]) + HEX(anchor["header_hash"])
    v3 += b"".join(WORD(n) for n in (selected["version"], selected["first_v3_height"], selected["valid_through"],
                                   policy["w"], policy["retain_headers"], policy["max_batch_headers"], 8192, 8 << 20))
    v3 += HEX(NODE) + H(s)
    abi = entry["limits"]
    schema = b"zenon-settlement-batch-entry-17/v1"
    legacy = b"ZENON-EXPERIMENTAL-BATCH-ENTRY\0\1" + WORD(entry["version"]) + H(v3)
    legacy += HEX(NODE) + HEX("caeaf764270b1489a53c860c6006026af208f924") + HEX("bc1548d75473797f24bb3eb79f5594969c596e39")
    legacy += WORD(len(schema)) + schema + address + struct.pack(">I", entry["domain_id"]) + HEX(entry["runtime_identity"])
    legacy += b"".join(WORD(n) for n in (entry["max_proof_bytes"], entry["max_siblings"], 1, abi["max_value_bytes"],
                        abi["max_executor_pillar_bytes"], abi["max_asset_flow_summary_bytes"],
                        abi["max_proof_data_bytes"], abi["max_dynamic_bytes"], abi["string_rule"]))
    record, cfg, totals = p["domain_record"], p["domain_config"], p["limits"]
    context = b"ZENON-EXPERIMENTAL-BATCH-CONTEXT\0\1" + H(legacy) + WORD(p["version"])
    for text in ("zenon-settlement-domain-record-12/v1", "zenon-settlement-domain-config-2/v1", p["domain_rule"]):
        encoded = text.encode("utf-8")
        context += WORD(len(encoded)) + encoded
    context += b"".join(WORD(n) for n in (record["max_proof_bytes"], record["max_siblings"], record["max_value_bytes"],
        record["max_profile_config_bytes"], record["max_chain_binding_bytes"], record["max_dynamic_bytes"],
        cfg["max_proof_bytes"], cfg["max_siblings"], 64, totals["max_total_proof_bytes"], totals["max_total_value_bytes"],
        totals["max_total_siblings"], 1, 1))
    request = unit["request"]
    require(request["height"] == 89 and request["header_hash"] == headers[2]["hash"]
            and request["tip_height"] == 90 and request["tip_hash"] == headers[3]["hash"] and request["batch_id"] == 0)
    old_query = b"ZENON-EXPERIMENTAL-BATCH-ENTRY-QUERY\0\1" + H(legacy) + WORD(request["height"]) + HEX(request["header_hash"])
    old_query += WORD(request["tip_height"]) + HEX(request["tip_hash"]) + WORD(request["batch_id"])
    query = b"ZENON-EXPERIMENTAL-BATCH-CONTEXT-QUERY\0\1" + H(context) + H(old_query)
    for name, preimage in (("header_context", v3), ("entry_context", legacy), ("context", context), ("query", query)):
        require(H(preimage).hex() == expected[name])
    require(request["context"] == H(context).hex() and expected["root"] == trace["root_hex"])
    return {"format": "synthetic-three-witness-byte-replay/v1", "node_revision": NODE,
            "root_checks": 4, "full_key_checks": 4, "header_hash_checks": 4, "fingerprint_checks": 5,
            "original_node_reexecuted": False, "pooled_values_are_one_snapshot": False,
            "selected_network_or_production_state_value_accepted": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-revision", default=None)
    args = parser.parse_args()
    if args.source_revision is not None and re.fullmatch("[0-9a-f]{40}", args.source_revision) is None:
        parser.error("source revision must be 40 lowercase hex characters")
    report = check(read_fixture("batch-context-unit.json", UNIT_SHA), read_fixture("batch-context-node-witness.json", TRACE_SHA))
    report["source_revision"] = args.source_revision
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
