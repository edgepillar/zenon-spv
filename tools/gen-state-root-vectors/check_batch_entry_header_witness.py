#!/usr/bin/env python3
"""Replay recorded fixture bytes without a node, native verifier or RPC read.

This is a mathematical and encoding check. Go separately verifies signatures,
owned-header acceptance and the compiled consumer. No live trust is selected.
"""

import argparse
import base64
import hashlib
import importlib.util
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CORPUS = ROOT / "internal/testdata/conformance/batch-entry-node-header-witness.json"
HARNESS = ROOT / "tools/gen-state-root-vectors/batch-entry-header-witness_test.go.txt"
NODE = "938fca3b7787da86827a5eb63371509b36e14761"
EXECUTOR = "caeaf764270b1489a53c860c6006026af208f924"
SDK = "bc1548d75473797f24bb3eb79f5594969c596e39"
SETTLEMENT = bytes.fromhex("01b3b6e5adcb4d0cad7fcef33598c6318c6318c0")
SCOPE = {
    "isolated_chain_100_fixture": True,
    "fixture_public_keys_only": True,
    "original_node_contract_RPC_and_proof_executed": True,
    "selected_chain_69_executed": False,
    "network_activation_authenticated": False,
    "independent_network_trust_selected": False,
    "authenticated_election_or_fork_choice": False,
    "STF_execution_proven": False,
    "consensus_finality_proven": False,
    "production_state_value_accepted": False,
    "release_qualified": False,
}
spec = importlib.util.spec_from_file_location(
    "batch_header_byte_helpers", ROOT / "tools/gen-node-momentum-vectors/check.py")
byte_helpers = importlib.util.module_from_spec(spec)
spec.loader.exec_module(byte_helpers)


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(data):
    return hashlib.sha3_256(data).digest()


def word(value):
    require(type(value) is int and 0 <= value < 1 << 64, "invalid uint64")
    return value.to_bytes(8, "big")


def hx(value, size=32):
    require(type(value) is str and len(value) == 2 * size and
            all(c in "0123456789abcdef" for c in value), "invalid canonical hex")
    return bytes.fromhex(value)


def b64(value):
    require(type(value) is str and len(value) <= 20000, "invalid bounded base64")
    raw = base64.b64decode(value, validate=True)
    require(base64.b64encode(raw).decode() == value, "noncanonical base64")
    return raw


def check_witness(witness, key, root, present):
    raw = b64(witness["proof"])
    require(99 <= len(raw) <= 12391 and raw[0] == int(present), "invalid proof bounds or kind")
    path = sha(key)
    require(raw[1:33] == path and hx(witness["root"]) == root, "proof identity differs")
    positions = [i for i in range(256) if raw[65 + i // 8] & (128 >> (i % 8))]
    require(int.from_bytes(raw[97:99], "big") == len(positions), "sibling count differs")
    end = 99 + 32 * len(positions)
    require(end <= len(raw), "truncated siblings")
    siblings = {index: raw[99 + n * 32:131 + n * 32] for n, index in enumerate(positions)}
    require(all(len(s) == 32 and any(s) for s in siblings.values()), "noncanonical zero sibling")
    if present:
        require(len(raw) >= end + 4, "missing value length")
        size = int.from_bytes(raw[end:end + 4], "big")
        value = raw[end + 4:]
        require(640 <= size == len(value) <= 4096 and value == b64(witness["value"]), "value differs")
        leaf = sha(path + value)
        require(leaf == raw[33:65], "leaf digest differs")
    else:
        require(len(raw) == end and witness["value"] is None and raw[33:65] == bytes(32),
                "absence carries a value")
        value, leaf = None, bytes(32)

    # Recurse from the root; this does not call the native bottom-up verifier.
    def subtree(depth):
        if depth == 256:
            return leaf
        child, sibling = subtree(depth + 1), siblings.get(255 - depth, bytes(32))
        if not any(child + sibling):
            return bytes(32)
        right = path[depth // 8] & (128 >> (depth % 8))
        return sha(sibling + child if right else child + sibling)

    require(subtree(0) == root, "reconstructed root differs")
    return value


def check_abi(value, gateway):
    require(640 <= len(value) <= 4096, "invalid ABI size")
    integers = {
        0: ("protocolVersion", 2), 1: ("firstInputSeq", 8), 2: ("lastInputSeq", 8),
        10: ("daMode", 1), 12: ("submittedAtHeight", 8),
        13: ("finalizeAtHeight", 8), 16: ("state", 1),
    }
    for index, (name, width) in integers.items():
        packed = value[index * 32:(index + 1) * 32]
        word(gateway[name])
        require(not any(packed[:-width]) and int.from_bytes(packed, "big") == gateway[name],
                "stored integer differs")
    hashes = ["preStateRoot", "postStateRoot", "inputRoot", "receiptRoot",
              "eventRoot", "outboxRoot", "daHash"]
    for index, name in enumerate(hashes, 3):
        require(value[index * 32:(index + 1) * 32] == hx(gateway[name]), "stored hash differs")
    cursor, total = 544, 0
    for index, name, cap in [(11, "executorPillar", 256), (14, "assetFlowSummary", 1024),
                             (15, "proofData", 1024)]:
        require(int.from_bytes(value[index * 32:(index + 1) * 32], "big") == cursor and
                cursor + 32 <= len(value), "noncontiguous ABI offset")
        size = int.from_bytes(value[cursor:cursor + 32], "big")
        total += size
        require(size <= cap and total <= 2048, "ABI dynamic bound")
        start, end = cursor + 32, cursor + 32 + size
        cursor = end + (-size % 32)
        require(cursor <= len(value) and not any(value[end:cursor]), "ABI truncation or padding")
        expected = gateway[name].encode("utf-8") if index == 11 else b64(gateway[name])
        require(value[start:end] == expected, "stored dynamic field differs")
    require(cursor == len(value), "trailing ABI bytes")
    require(type(gateway["isFinalized"]) is bool, "invalid frontier hint")


def check_corpus(corpus, harness):
    require(corpus["format"] == "zenon-recorded-batch-entry-header-witness/v1", "wrong format")
    require(corpus["source"] == {
        "repository": "https://github.com/digitalSloth/go-zenon", "revision": NODE,
        "tree": "f3b7947d2267ebdb806f18ff0c02bba5bffae9c4",
        "archive_sha256": "8ca1512eff8c04ee8b6ed0ff9a5da9e3eeba518660b07833f99a6b74e1dcc3a3",
    }, "wrong source cohort")
    require(corpus["harness"] == {
        "path": "tools/gen-state-root-vectors/batch-entry-header-witness_test.go.txt",
        "bytes": 7741, "sha256": "230ae18c289f5adcf9e195a2405bbefec56851ec7742956a00eb66348060a45a",
    }, "wrong harness pin")
    require(len(harness) == 7741 and hashlib.sha256(harness).hexdigest() == corpus["harness"]["sha256"],
            "harness bytes differ")
    require(set(corpus["scope"]) == set(SCOPE) and
            all(corpus["scope"][name] is expected for name, expected in SCOPE.items()), "upgraded scope")
    execution = corpus["execution"]
    require(type(execution["actual_exit"]) is int and execution["actual_exit"] == 0 and
            execution["output_complete"] is True and
            execution["native_test"] == "TestSPVBatchEntryHeaderWitnessCapture" and
            execution["prior_failed_capture"]["outcome_preserved"] == "FAILURE",
            "unqualified original execution")
    require(execution["record_sha256"] == "9803750517e87d55c8a14c5b5eb06d6653bbf77d82d72c07cb61239d51f6adf5" and
            execution["output_sha256"] == "d914355c15f183587139a1b8d43f39a095ae09639881195b53988bcfb35a3c3f" and
            execution["output_bytes"] == 42933 and execution["go"] == "go1.25.14" and
            execution["platform"] == "darwin/arm64" and execution["cgo_enabled"] is True and
            execution["used_modules_verified"] == 34 and execution["original_regular_source_files_unchanged"] == 484,
            "original execution binding differs")
    trace, selection = corpus["trace"], corpus["test_selection"]
    require(trace["chain_id"] == 100 and trace["domain_id"] == 1 and trace["batch_id"] == 0 and
            trace["scope"] == "ISOLATED_ATTESTATION_FIXTURE_NOT_SELECTED_NETWORK_OR_STF_EXECUTION",
            "wrong fixture domain")
    require(all(trace[n] is False for n in ["RPC_P2P_service_started", "network_execution",
                                          "selected_network_profile_or_anchor",
                                          "STF_execution_or_finality_established"]), "upgraded trace")
    require(selection["scope"] == "EXPLICIT_SYNTHETIC_TEST_SETTINGS_NOT_INDEPENDENT_NETWORK_TRUST",
            "fixture selection promoted")
    rows = trace["bundle"]["momentums"]
    require(len(rows) == 3, "incomplete linked capture")
    previous, entries = trace["anchor"]["hash"], []
    for i, row in enumerate(rows):
        require(row["version"] == 3 and row["chainIdentifier"] == 100 and
                row["previousHash"] == previous and row["height"] == trace["anchor"]["height"] + i + 1,
                "header domain or linkage differs")
        members = b"".join(byte_helpers.address_bytes(m["address"]) + word(m["height"]) +
                           hx(m["hash"]) for m in row["content"])
        preimage = (word(3) + word(100) + hx(previous) + word(row["height"]) + word(row["timestamp"]) +
                    sha(b64(row["data"])) + sha(members) + hx(row["changesHash"]) +
                    word(row["nextFusionPrice"]) + word(row["nextWorkPrice"]) + hx(row["stateRoot"]))
        require(len(preimage) == 208 and sha(preimage) == hx(row["hash"]), "header preimage differs")
        public, signature = b64(row["publicKey"]), b64(row["signature"])
        require(len(public) == 32 and len(signature) == 64, "wrong signature widths")
        address = b"\0" + sha(public)[:19]
        require(byte_helpers.address_bytes(row["producer"]) == address, "producer projection differs")
        entries.append({"height": row["height"], "timestamp_unix": row["timestamp"], "producing_addr": address.hex()})
        previous = row["hash"]
    require(rows[1]["height"] == trace["height"] and rows[1]["hash"] == trace["header_hash"] and
            rows[2]["height"] == trace["tip_height"] and rows[2]["hash"] == trace["tip_hash"],
            "query or tip binding differs")
    key = b"\x03" + SETTLEMENT + b"\x04\x02" + (1).to_bytes(4, "big") + word(0)
    require(key == hx(trace["ledger_key"], 35) and sha(key) == hx(trace["path"]), "key/path differs")
    value = check_witness(trace["bundle"]["witness"], key, hx(rows[1]["stateRoot"]), True)
    require(trace["absent_batch_id"] == 1, "absent query identity differs")
    check_witness(trace["absent_witness"], key[:-8] + word(1), hx(rows[1]["stateRoot"]), False)
    gateway = trace["bundle"]["gateway"]
    require(gateway["domainId"] == 1 and gateway["batchId"] == 0, "gateway identity differs")
    check_abi(value, gateway)
    config = selection["config"]
    for number in [trace["chain_id"], trace["domain_id"], trace["batch_id"], trace["absent_batch_id"], config["version"]]:
        word(number)
    profile, policy, schedule, query = (config[n] for n in
        ["header_profile", "header_policy", "producer_schedule", "query_profile"])
    for number in [*policy.values(), profile["version"], query["version"]]:
        word(number)
    require(policy == {"w": 1, "retain_headers": 2, "max_batch_headers": 3}, "fixture policy differs")
    require(profile["genesis"] == {"chain_id": 100, "height": 1, "header_hash": trace["genesis_hash"]} and
            profile["anchor"] == {"chain_id": 100, "height": trace["anchor"]["height"], "header_hash": trace["anchor"]["hash"]} and
            profile["first_v3_height"] == trace["first_incoming_v3"] <= trace["anchor"]["height"] and
            profile["valid_through"] == trace["tip_height"] and profile["node_revision"] == NODE,
            "fixture header profile differs")
    require(schedule["entries"] == entries and schedule["chain_id"] == 100 and
            schedule["coverage"] == [{"from_height": rows[0]["height"], "through_height": rows[2]["height"]}],
            "fixture finite schedule differs")
    schedule_bytes = (word(100) + word(1) + word(rows[0]["height"]) + word(rows[2]["height"]) + word(3) +
                      b"".join(word(e["height"]) + word(e["timestamp_unix"]) + hx(e["producing_addr"], 20) for e in entries))
    require(sha(schedule_bytes) == hx(schedule["schedule_hash"]), "schedule hash differs")
    header_bytes = (b"ZENON-EXPERIMENTAL-V3-CONTEXT\0\1" +
                    b"".join(word(a["chain_id"]) + word(a["height"]) + hx(a["header_hash"])
                             for a in [profile["genesis"], profile["anchor"]]) +
                    b"".join(word(v) for v in [1, profile["first_v3_height"], profile["valid_through"], 1, 2, 3, 8192, 8 << 20]) +
                    hx(NODE, 20) + sha(schedule_bytes))
    header_pin = sha(header_bytes)
    limits = {"max_value_bytes": 4096, "max_executor_pillar_bytes": 256,
              "max_asset_flow_summary_bytes": 1024, "max_proof_data_bytes": 1024,
              "max_dynamic_bytes": 2048, "string_rule": 2}
    require(query["version"] == profile["version"] == config["version"] == 1 and
            query["settlement"] == SETTLEMENT.hex() and query["domain_id"] == 1 and
            query["max_proof_bytes"] == 12391 and query["max_siblings"] == 256 and query["limits"] == limits,
            "fixture typed policy differs")
    schema = b"zenon-settlement-batch-entry-17/v1"
    typed_bytes = (b"ZENON-EXPERIMENTAL-BATCH-ENTRY\0\1" + word(1) + header_pin +
                   hx(NODE, 20) + hx(EXECUTOR, 20) + hx(SDK, 20) + word(len(schema)) + schema +
                   SETTLEMENT + (1).to_bytes(4, "big") + hx(query["runtime_identity"]) +
                   b"".join(word(v) for v in [12391, 256, 1, 4096, 256, 1024, 1024, 2048, 2]))
    query_pin = sha(typed_bytes)
    request = selection["request"]
    require(request == {"context": query_pin.hex(), "height": trace["height"], "header_hash": trace["header_hash"],
                        "tip_height": trace["tip_height"], "tip_hash": trace["tip_hash"], "batch_id": 0},
            "local request differs")
    fingerprint = sha(b"ZENON-EXPERIMENTAL-BATCH-ENTRY-QUERY\0\1" + query_pin +
                      word(request["height"]) + hx(request["header_hash"]) +
                      word(request["tip_height"]) + hx(request["tip_hash"]) + word(0))
    require(header_pin == hx(selection["header_context"]) and query_pin == hx(selection["query_context"]) and
            fingerprint == hx(selection["query_fingerprint"]), "context or query fingerprint differs")
    return {"headers": 3, "proofs": 2, "ABI_fields": 17, "value_bytes": len(value),
            "scope": "RECORDED_FIXTURE_BYTES_NOT_NETWORK_ACCEPTANCE",
            "Ed25519_checked_by_Python": False, "production_qualified": False}


def pairs(rows):
    result = {}
    for name, value in rows:
        require(name not in result, "duplicate JSON field")
        result[name] = value
    return result


def read_corpus():
    raw = CORPUS.read_bytes()
    require(len(raw) <= 64 << 10, "oversized corpus")
    return json.loads(raw, object_pairs_hook=pairs)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-revision", default=None)
    args = parser.parse_args()
    if args.source_revision is not None:
        hx(args.source_revision, 20)
    report = check_corpus(read_corpus(), HARNESS.read_bytes())
    print(json.dumps({"format": "spv-recorded-batch-entry-byte-replay/v1",
                      "source_revision": args.source_revision, **report}, sort_keys=True))

