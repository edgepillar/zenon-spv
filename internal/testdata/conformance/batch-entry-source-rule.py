#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Independent byte vectors for an opt-in experimental BatchEntry source rule.

Uses Python stdlib only; imports no SPV or node code. This is a source-derived
reference and mathematical fixture, not original-node or network execution.
Run from this directory and compare stdout byte-for-byte with the JSON corpus.
"""
import hashlib
import json
import re
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
NODE = "938fca3b7787da86827a5eb63371509b36e14761"
RULE = "zenon-phase1-batch-fields/v1"
SCHEMA = "zenon-settlement-batch-entry-17/v1"
EXECUTOR = "caeaf764270b1489a53c860c6006026af208f924"
SDK = "bc1548d75473797f24bb3eb79f5594969c596e39"


def fixture(name, digest):
    raw = (HERE / name).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == digest
    return json.loads(raw)


def u64(n):
    return struct.pack(">Q", n)


def frame(text):
    raw = text.encode("ascii")
    return u64(len(raw)) + raw


def entry_context(p, header, version):
    b = b"ZENON-EXPERIMENTAL-BATCH-ENTRY\0" + bytes([version]) + u64(version)
    b += bytes.fromhex(header) + bytes.fromhex(NODE + EXECUTOR + SDK)
    b += frame(SCHEMA) + bytes.fromhex(p["settlement"]) + struct.pack(">I", p["domain_id"])
    b += bytes.fromhex(p["runtime_identity"])
    limits = p["limits"]
    b += b"".join(u64(v) for v in (
        p["max_proof_bytes"], p["max_siblings"], 1, limits["max_value_bytes"],
        limits["max_executor_pillar_bytes"], limits["max_asset_flow_summary_bytes"],
        limits["max_proof_data_bytes"], limits["max_dynamic_bytes"], limits["string_rule"]))
    if version == 2:
        b += frame(RULE)
    return hashlib.sha3_256(b).hexdigest()


def context(p, entry, version):
    b = b"ZENON-EXPERIMENTAL-BATCH-CONTEXT\0" + bytes([version]) + bytes.fromhex(entry) + u64(version)
    b += frame("zenon-settlement-domain-record-12/v1") + frame("zenon-settlement-domain-config-2/v1")
    b += frame(p["domain_rule"])
    r, c, limits = p["domain_record"], p["domain_config"], p["limits"]
    b += b"".join(u64(v) for v in (
        r["max_proof_bytes"], r["max_siblings"], r["max_value_bytes"],
        r["max_profile_config_bytes"], r["max_chain_binding_bytes"], r["max_dynamic_bytes"],
        c["max_proof_bytes"], c["max_siblings"], 64,
        limits["max_total_proof_bytes"], limits["max_total_value_bytes"], limits["max_total_siblings"], 1, 1))
    return hashlib.sha3_256(b).hexdigest()


def query(entry, request):
    b = b"ZENON-EXPERIMENTAL-BATCH-ENTRY-QUERY\0\1" + bytes.fromhex(entry)
    b += u64(request["height"]) + bytes.fromhex(request["header_hash"])
    b += u64(request["tip_height"]) + bytes.fromhex(request["tip_hash"]) + u64(request["batch_id"])
    return hashlib.sha3_256(b).hexdigest()


def summary(rows):
    return struct.pack(">I", len(rows)) + b"".join(
        asset.to_bytes(32, "big") + deposit.to_bytes(32, "big") + withdrawal.to_bytes(32, "big")
        for asset, deposit, withdrawal in rows)


def source_accepts(pillar, flow, data):
    if not 1 <= len(pillar) <= 40 or re.fullmatch(rb"([a-zA-Z0-9]+[-._]?)*[a-zA-Z0-9]", pillar) is None or data:
        return False
    if len(flow) < 4:
        return False
    count, = struct.unpack(">I", flow[:4])
    if count > 16 or len(flow) != 4 + 96 * count:
        return False
    previous = -1
    for asset, deposit, withdrawal in struct.iter_unpack(">32s32s32s", flow[4:]):
        value = int.from_bytes(asset, "big")
        if value >= 1 << 80 or value <= previous or not (int.from_bytes(deposit, "big") or int.from_bytes(withdrawal, "big")):
            return False
        previous = value
    return True


def pack(head, pillar, flow, data):
    head = bytearray(head)
    tail = b""
    for index, value in zip((11, 14, 15), (pillar, flow, data)):
        head[index * 32:(index + 1) * 32] = (544 + len(tail)).to_bytes(32, "big")
        tail += len(value).to_bytes(32, "big") + value + b"\0" * (-len(value) % 32)
    return bytes(head) + tail


def proof_set(rows, replacement=None):
    # Independent sparse-tree reconstruction. Empty subtrees remain zero;
    # nonempty children are SHA3(left || right), from leaves up to the root.
    zero = b"\0" * 32
    values = [bytes.fromhex(row["value_hex"]) for row in rows]
    if replacement is not None:
        values[0] = replacement
    paths = [bytes.fromhex(row["path_hex"]) for row in rows]
    indexes = [int.from_bytes(path, "big") for path in paths]
    levels = [{i: hashlib.sha3_256(path + value).digest() for i, path, value in zip(indexes, paths, values)}]
    for _ in range(256):
        child = levels[-1]
        levels.append({p: hashlib.sha3_256(child.get(2 * p, zero) + child.get(2 * p + 1, zero)).digest()
                       for p in {i >> 1 for i in child}})
    root = levels[-1][0].hex()
    output = []
    for row, index, path, value in zip(rows, indexes, paths, values):
        bitmap, siblings = bytearray(32), []
        for depth in range(256):
            sibling = levels[depth].get((index >> depth) ^ 1, zero)
            if sibling != zero:
                bitmap[depth // 8] |= 1 << (7 - depth % 8)
                siblings.append(sibling)
        proof = b"\1" + path + levels[0][index] + bitmap + struct.pack(">H", len(siblings))
        proof += b"".join(siblings) + struct.pack(">I", len(value)) + value
        output.append({"name": row["name"], "value_hex": value.hex(), "proof_hex": proof.hex()})
    return {"root_hex": root, "rows": output}


def main():
    single = fixture("batch-entry-node-header-witness.json", "cf784dae5b502d79de832d73e5da91055762249e2252811195fc41960a662d97")
    unit = fixture("batch-context-unit.json", "e4bfbdb7bff55f9719782c7e609240b2ba9aeefd0d0f42b7ee1948286e890366")
    rows = fixture("batch-context-node-witness.json", "773cda402e08709ffd73adfea355f73269b1470b7336c5a027ddd5b331ab9d96")
    base = bytes.fromhex(rows["rows"][0]["value_hex"])[:544]
    normal = summary([(1, 7, 0)])
    vectors = []
    def add(name, expected, pillar=b"A", flow=normal, data=b""):
        assert source_accepts(pillar, flow, data) == expected, name
        value = pack(base, pillar, flow, data)
        assert 640 <= len(value) <= 4096
        vectors.append({"name": name, "accepted": expected, "value_hex": value.hex()})

    for name, pillar in (
        ("one-byte", b"A"), ("name-boundary-40", b"A" * 40),
        ("source-separators", b"a-B.c_9"), ("numeric-name", b"1")):
        add(name, True, pillar)
    for name, pillar in (
        ("empty-name", b""), ("name-over-40", b"A" * 41),
        ("leading-separator", b"-a"), ("trailing-separator", b"a."),
        ("consecutive-separators", b"a-_b"), ("space-in-name", b"a b"),
        ("non-ascii-name", b"a\xc3\xa9"), ("opaque-name", b"\xff"),
        ("newline-name", b"a\n")):
        add(name, False, pillar)
    add("zero-assets", True, flow=summary([]))
    add("zero-asset-id-is-encoding-valid", True, flow=summary([(0, 1, 0)]))
    add("withdrawal-only", True, flow=summary([(1, 0, 1)]))
    add("both-amounts", True, flow=summary([(1, 1, 1)]))
    add("maximum-u256-amounts", True, flow=summary([(1, (1 << 256) - 1, (1 << 256) - 1)]))
    add("maximum-asset-id", True, flow=summary([((1 << 80) - 1, 1, 0)]))
    add("maximum-16-assets-and-name", True, b"A" * 40, summary([(n, 1, 0) for n in range(16)]))
    add("empty-summary", False, flow=b"")
    add("short-summary", False, flow=b"\0" * 3)
    add("summary-over-16", False, flow=summary([(n, 1, 0) for n in range(17)]))
    add("count-u32-max", False, flow=b"\xff" * 4)
    add("count-length-mismatch", False, flow=struct.pack(">I", 2) + normal[4:])
    add("trailing-summary-byte", False, flow=normal + b"\0")
    add("truncated-summary-byte", False, flow=normal[:-1])
    add("invalid-asset-prefix", False, flow=summary([(1 << 80, 1, 0)]))
    add("high-asset-prefix", False, flow=summary([(1 << 255, 1, 0)]))
    add("duplicate-assets", False, flow=summary([(1, 1, 0), (1, 0, 1)]))
    add("descending-assets", False, flow=summary([(2, 1, 0), (1, 1, 0)]))
    add("zero-amounts", False, flow=summary([(1, 0, 0)]))
    add("nonempty-proof-data", False, data=b"\0")
    add("nonzero-proof-data", False, data=b"\1")

    s = single["test_selection"]
    sp = s["config"]["query_profile"]
    up = unit["config"]["query_profile"]
    entry_v1 = entry_context(sp, s["header_context"], 1)
    three_entry_v1 = entry_context(up["entry"], unit["expected"]["header_context"], 1)
    assert entry_v1 == s["query_context"]
    assert context(up, three_entry_v1, 1) == unit["expected"]["context"]
    entry_v2 = entry_context(sp, s["header_context"], 2)
    three_entry_v2 = entry_context(up["entry"], unit["expected"]["header_context"], 2)
    three_v2 = context(up, three_entry_v2, 2)
    q = query(three_entry_v2, unit["request"])
    original = proof_set(rows["rows"][:3])
    assert original["root_hex"] == rows["root_hex"]
    assert all(a["proof_hex"] == b["proof_hex"] for a, b in zip(original["rows"], rows["rows"]))
    negative = proof_set(rows["rows"][:3], pack(base, b"a-_b", normal, b""))
    output = {
        "format": "zenon-batch-source-rule-independent-vectors/v1",
        "source_revision": NODE, "rule": RULE,
        "scope": "SOURCE_FIELD_SUBSET_AND_PYTHON_BYTES_NO_NODE_OR_NETWORK_EXECUTION",
        "node_functions": [
            "vm/embedded/implementation/pillars.go:checkPillarName",
            "vm/embedded/implementation/settlement.go:decodeAssetFlowSummary",
            "vm/embedded/definition/settlement.go:ZTSFromAssetId"],
        "single": {"entry_v1": entry_v1, "entry_v2": entry_v2,
                   "query_v2": query(entry_v2, s["request"])},
        "three": {"entry_v1": three_entry_v1, "entry_v2": three_entry_v2,
                  "context_v1": unit["expected"]["context"], "context_v2": three_v2,
                  "query_v2": hashlib.sha3_256(b"ZENON-EXPERIMENTAL-BATCH-CONTEXT-QUERY\0\1" +
                      bytes.fromhex(three_v2 + q)).hexdigest()},
        "vectors": vectors, "negative_three": negative}
    print(json.dumps(output, sort_keys=True, indent=2) + "\n", end="")


if __name__ == "__main__":
    main()

