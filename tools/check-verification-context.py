#!/usr/bin/env python3
"""Independently check the diagnostic context vector using Python SHA3-256."""

import hashlib
import json
import pathlib
import re
import struct


def fingerprint(context):
    version = context["schema_version"]
    if type(version) is not int or version not in (1, 2):
        raise ValueError("Unsupported verification context schema")
    data = bytearray(f"zenon-spv/verification-context/v{version}\0".encode("ascii"))

    def u64(value, maximum=(1 << 64) - 1):
        if type(value) is not int or not 0 <= value <= maximum:
            raise ValueError("Integer outside the nonnegative source field range")
        data.extend(struct.pack(">Q", value))

    def hash32(value):
        if type(value) is not str or re.fullmatch(r"[0-9a-fA-F]{64}", value) is None:
            raise ValueError("Hash must contain exactly 64 hexadecimal characters")
        data.extend(bytes.fromhex(value))

    def text(value):
        encoded = value.encode("utf-8")
        u64(len(encoded))
        data.extend(encoded)

    u64(context["schema_version"], (1 << 32) - 1)
    anchor = context["anchor"]
    u64(anchor["chain_id"])
    u64(anchor["height"])
    hash32(anchor["header_hash"])
    policy = context["policy"]
    u64(policy["w"])
    if version == 2:
        u64(policy["retain_headers"], (1 << 63) - 1)
    for name in (
        "max_bundle_bytes", "max_headers", "max_commitments",
        "max_flat_evidence_members", "max_total_flat_evidence_members",
        "max_segments", "max_segment_blocks", "max_total_segment_blocks",
        "max_state_value_proofs", "max_state_proof_nodes", "max_state_proof_bytes",
    ):
        u64(policy[name], (1 << 63) - 1)
    profile = context["protocol_profile"]
    u64(int(profile is not None))
    if profile is not None:
        u64(profile["version"], (1 << 32) - 1)
        for name in ("valid_through", "v2_from_height"):
            u64(profile[name])
    producer = context["producer"]
    for name in ("mode", "source", "kind"):
        text(producer[name])
    u64(int(producer["schedule_hash"] is not None))
    if producer["schedule_hash"] is not None:
        hash32(producer["schedule_hash"])
    u64(len(context["checkpoints"]))
    for checkpoint in context["checkpoints"]:
        u64(checkpoint["height"])
        hash32(checkpoint["header_hash"])
    return hashlib.sha3_256(data).hexdigest()


if __name__ == "__main__":
    root = pathlib.Path(__file__).resolve().parents[1] / "internal/testdata/verification-context"
    vectors = sorted(root.glob("*.json"))
    if not vectors:
        raise SystemExit("No verification context vectors found")
    for vector in vectors:
        context = json.loads(vector.read_text())
        actual = fingerprint(context)
        if actual != context["fingerprint"]:
            raise SystemExit(f"Verification context fingerprint mismatch: {vector.name}")
        print(f"{vector.name}: {actual}")
