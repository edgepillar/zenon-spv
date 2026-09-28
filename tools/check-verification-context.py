#!/usr/bin/env python3
"""Independently check the diagnostic context vector using Python SHA3-256."""

import hashlib
import json
import pathlib
import struct


def fingerprint(context):
    data = bytearray(b"zenon-spv/verification-context/v1\0")

    def u64(value):
        data.extend(struct.pack(">Q", value))

    def text(value):
        encoded = value.encode("utf-8")
        u64(len(encoded))
        data.extend(encoded)

    u64(context["schema_version"])
    anchor = context["anchor"]
    u64(anchor["chain_id"])
    u64(anchor["height"])
    data.extend(bytes.fromhex(anchor["header_hash"]))
    policy = context["policy"]
    for name in (
        "w", "max_bundle_bytes", "max_headers", "max_commitments",
        "max_flat_evidence_members", "max_total_flat_evidence_members",
        "max_segments", "max_segment_blocks", "max_total_segment_blocks",
        "max_state_value_proofs", "max_state_proof_nodes", "max_state_proof_bytes",
    ):
        u64(policy[name])
    profile = context["protocol_profile"]
    u64(int(profile is not None))
    if profile is not None:
        for name in ("version", "valid_through", "v2_from_height"):
            u64(profile[name])
    producer = context["producer"]
    for name in ("mode", "source", "kind"):
        text(producer[name])
    u64(int(producer["schedule_hash"] is not None))
    if producer["schedule_hash"] is not None:
        data.extend(bytes.fromhex(producer["schedule_hash"]))
    u64(len(context["checkpoints"]))
    for checkpoint in context["checkpoints"]:
        u64(checkpoint["height"])
        data.extend(bytes.fromhex(checkpoint["header_hash"]))
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
