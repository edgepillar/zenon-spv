#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Independently verify signatures on the retained chain-100 v3 transition."""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
import tempfile


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
FIXTURES = {
    "internal/testdata/conformance/first-v3-node-headers.json":
        (21634, "78222ac4bba092fc9f4b6775d158a8e5d013c22b7e7a85948dce6453f26cff12"),
    "internal/testdata/conformance/candidate-v3-node-rpc.json":
        (15475, "4ac2da237eead98f146d931a27679a7251a5a9ef5e109920b9f7fd1f3a383e57"),
}
BACKEND_INPUTS = {
    "tools/gen-node-momentum-vectors/check-signatures.py":
        "692e0cd528823440ca9a0b0f74cc38d2b84dc239f8b5191d1bc0b657a522f3f5",
    "tools/gen-node-momentum-vectors/check.py":
        "97ad75294f10aeb877f2e1758eb4361801f458b142e7e4c208bc3e972f562e61",
    "tools/gen-node-momentum-vectors/check_account.py":
        "c104dd96039dfa9be14f79d104739f64d39c86961053523f0f71598b90fb1dde",
}
VERSIONS = (1,) * 10 + (2,) + (3,) * 3
CHAIN_ID = 100
FIRST_V3 = 12


def load_backend():
    if any(hashlib.sha256((ROOT / path).read_bytes()).hexdigest() != pin
           for path, pin in BACKEND_INPUTS.items()):
        raise ValueError("signature backend source pin")
    spec = importlib.util.spec_from_file_location("node_signature_backend", HERE / "check-signatures.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SIG = load_backend()
BYTES = SIG.BYTES
require = SIG.require


def preimage(header):
    version = header["version"]
    root = BYTES.hash_bytes(header["stateRoot"])
    require(type(version) is int and version in (1, 2, 3) and (root != bytes(32)) == (version == 3),
            "state_root_version")
    raw = (BYTES.uint64(version) + BYTES.uint64(header["chainIdentifier"])
           + BYTES.hash_bytes(header["previousHash"]) + BYTES.uint64(header["height"])
           + BYTES.uint64(header["timestamp"]) + BYTES.hash_bytes(header["dataHash"])
           + BYTES.hash_bytes(header["contentHash"]) + BYTES.hash_bytes(header["changesHash"]))
    if version >= 2:
        raw += BYTES.uint64(header["nextFusionPrice"]) + BYTES.uint64(header["nextWorkPrice"])
    return raw + root if version == 3 else raw


def load_fixtures():
    documents = []
    for relative, (size, digest) in FIXTURES.items():
        with SIG.regular_file(ROOT / relative, size, "fixture_scope") as (source, _):
            raw = source.read(size + 1)
        require(len(raw) == size and SIG.sha(raw) == digest, "fixture_pin")
        documents.append(json.loads(raw, object_pairs_hook=SIG.json_pairs))
    return documents


def select_headers(boundary, rpc):
    trace = boundary["trace"]
    rows = trace["rows"]
    require(trace["chain_id"] == CHAIN_ID and trace["first_incoming_v3"] == FIRST_V3
            and boundary["scope"]["isolated_node_fixture"] is True
            and all(rpc["source"][key] == value for key, value in boundary["source"].items())
            and len(rows) == len(VERSIONS), "fixture_scope")
    previous, previous_time = "0" * 64, 0
    records, headers = [], []
    for height, (row, version) in enumerate(zip(rows, VERSIONS), 1):
        header = row["header"]
        require(header["chainIdentifier"] == CHAIN_ID and header["version"] == version
                and header["height"] == height and header["previousHash"] == previous
                and header["timestamp"] > previous_time and header["hash"] == row["hash"]
                and header["stateRoot"] == row["state_root"],
                "fixture_header_selection")
        raw = preimage(header)
        require(len(raw) == {1: 160, 2: 176, 3: 208}[version], "preimage_size")
        record = SIG.record(f"height-{height}", "momentum", header, raw, unsigned=height == 1)
        records.append({**record, "height": height, "version": version})
        headers.append(header)
        previous, previous_time = header["hash"], header["timestamp"]
    require(headers[0]["hash"] == trace["genesis_hash"], "fixture_genesis")

    selected = [row for row in rpc["rows"] if row["existing_signature_valid"] is True]
    v3_headers = headers[FIRST_V3 - 1:]
    require(len(selected) == len(v3_headers) and rpc["scope"]["historical_fixture_chain_id"] == CHAIN_ID,
            "fixture_rpc_roster")
    for row, header in zip(selected, v3_headers):
        require(row["name"] == f"retained-signed-height-{header['height']}", "fixture_rpc_roster")
        wire = json.loads(row["wire_json"], object_pairs_hook=SIG.json_pairs)
        content = b"".join(BYTES.address_bytes(member["address"]) + BYTES.uint64(member["height"])
                           + BYTES.hash_bytes(member["hash"]) for member in wire["content"])
        projection = {key: wire[key] for key in header if key not in ("dataHash", "contentHash")}
        projection.update(dataHash=BYTES.digest(BYTES.base64_bytes(wire["data"])).hex(),
                          contentHash=BYTES.digest(content).hex())
        require(projection == header and row["preimage"] == preimage(projection).hex(), "fixture_rpc_projection")
        producer = b"\x00" + BYTES.digest(BYTES.base64_bytes(wire["publicKey"]))[:19]
        require(producer == BYTES.address_bytes(wire["producer"]), "fixture_rpc_producer")
    return records


def checks(record):
    yield "original", record["message"], True
    if record["version"] == 3:
        prefix, root = record["preimage"][:-32], record["preimage"][-32:]
        yield "without-state-root", BYTES.digest(prefix), False
        yield "different-state-root", BYTES.digest(prefix + bytes((root[0] ^ 1,)) + root[1:]), False


def run(openssl, source_revision):
    require(re.fullmatch(r"[a-f0-9]{40}", source_revision) is not None, "source_revision")
    checker = Path(__file__)
    checker_sha256 = SIG.sha(checker.read_bytes())
    boundary, rpc = load_fixtures()
    records = select_headers(boundary, rpc)
    outcomes = []
    with tempfile.TemporaryDirectory(prefix="first-v3-signatures-") as temporary:
        backend = SIG.Backend(openssl, Path(temporary))
        for record in records[1:]:
            for control, message, expected in checks(record):
                observation = {"height": record["height"], "version": record["version"],
                               "header_hash": record["message"].hex(), "control": control, "expected": expected}
                try:
                    actual, details = backend.verify(record["key"], message, record["signature"])
                except SIG.Refused as error:
                    outcomes.append({**observation, "actual": None, "error_stage": error.stage,
                                     **(error.details or {})})
                    error.outcomes = outcomes
                    raise
                outcomes.append({**observation, "actual": actual, **details})
                if actual is not expected:
                    error = SIG.Refused("signature_outcome")
                    error.outcomes = outcomes
                    raise error
        identity = backend.identity()
    require(SIG.sha(checker.read_bytes()) == checker_sha256, "checker_source_changed")
    return {"format": "independent-first-v3-signatures/v1", "status": "verified",
            "source_revision": source_revision, "source_revision_is_caller_asserted": True,
            "checker_sha256": checker_sha256, "backend_inputs": BACKEND_INPUTS,
            "fixtures": {p: {"bytes": size, "sha256": digest} for p, (size, digest) in FIXTURES.items()},
            "node_source": boundary["source"], "scope": boundary["scope"],
            "fixture_chain_id": CHAIN_ID, "first_v3_height": FIRST_V3, "unsigned_genesis": 1,
            "signed_headers": len(records) - 1, "raw_rpc_v3_headers": len(records) - FIRST_V3 + 1,
            "backend": identity, "outcomes": outcomes}


if __name__ == "__main__":
    parser = SIG.QuietParser(description=__doc__)
    parser.add_argument("--openssl", required=True)
    parser.add_argument("--source-revision", required=True)
    try:
        args = parser.parse_args()
        print(json.dumps(run(args.openssl, args.source_revision), sort_keys=True, separators=(",", ":")))
    except (SIG.Refused, ValueError, TypeError, KeyError, OSError) as error:
        refusal = {"format": "independent-first-v3-signatures/v1", "status": "refused",
                   "reason": getattr(error, "stage", "input_or_backend_error"),
                   "outcomes": getattr(error, "outcomes", [])}
        print(json.dumps(refusal, sort_keys=True, separators=(",", ":")))
        sys.exit(1)
