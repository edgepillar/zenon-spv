#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Independent actual LedgerApi method observations under recording synthetic stubs.

Only source-pinned method forwarding is compared. Actual chain readiness, node
lifecycle, JSON-RPC dispatch, authenticated headers and production proofs remain
outside this fixture. Reference errors and synthetic counterexamples never
become state-value acceptance.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("candidate_rpc_wire_oracle", HERE / "check_wire.py")
WIRE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(WIRE)
BYTE = WIRE.BYTE
SCOPE = {"synthetic": True, "unsigned": True, "LedgerApi_constructor_executed": True,
         "LedgerApi_methods_executed": True, "recording_chain_store_stubs": True,
         "primitive_proof_api_executed": True, "StateProof_serializer_executed": True,
         "actual_chain_stateTree_executed": False, "rpc_dispatcher_executed": False,
         "rpc_transport_executed": False, "node_database_opened": False,
         "node_lifecycle_executed": False, "node_tests_executed": False,
         "profile_agreed": False, "network_activation_authenticated": False,
         "header_authentication_executed": False, "runtime_state_proof_acceptance": False}
MAX_CASES = 64
METHODS = ("GetProof", "GetStateRoot")


def selected_inputs():
    result = []
    gates = {"zero-height": {"height": 0}, "lookup-error": {"lookup_error": "lookup"},
             "missing-momentum": {"missing_momentum": True}, "version-zero": {"version": 0},
             "version-one": {"version": 1}, "version-two": {"version": 2}, "active-three": {},
             "version-four": {"version": 4}, "version-max": {"version": 2**64 - 1},
             "store-height-diff": {"store_height": 43}, "store-hash-diff": {"hash_override": True},
             "not-ready": {}, "not-retained": {}, "root-error": {"root_error": "root"},
             "coherent-root-substitution": {"response_kind": "coherent-substitution"}}
    def base(method, name):
        return {"name": method + "/" + name, "method": method, "height": 42, "version": 3,
                "store_height": 42, "missing_momentum": False, "hash_override": False,
                "key_kind": "balance", "binding_name": "stored-zero", "lookup_error": "",
                "proof_error": "", "root_error": "", "response_kind": "selected"}
    for method in METHODS:
        for name, changes in gates.items():
            item = base(method, name) | changes
            if name in ("not-ready", "not-retained"):
                item["proof_error" if method == "GetProof" else "root_error"] = name
            result.append(item)
    proof_cases = {"present-one": {"binding_name": "positive-one"},
                   "missing-token": {"binding_name": "missing-token", "key_kind": "missing-token"},
                   "present-empty": {"binding_name": "present-empty-core-only"},
                   "nil-key": {"key_kind": "nil"}, "empty-key": {"key_kind": "empty"},
                   "oversized-key": {"key_kind": "oversized"},
                   "nil-value-present-proof": {"response_kind": "nil-value"},
                   "oversized-value": {"response_kind": "oversized-value"},
                   "proof-error-before-root-error": {"proof_error": "proof", "root_error": "root"},
                   "root-substitution": {"response_kind": "root-substitution"}}
    for name, changes in proof_cases.items():
        result.append(base("GetProof", name) | changes)
    return result


def selected_key(kind):
    return {"balance": BYTE.balance_key("11" * 20, "22" * 10),
            "missing-token": BYTE.balance_key("11" * 20, "44" * 10),
            "nil": None, "empty": b"", "oversized": bytes([119]) * 1025}[kind]


def primitive(key, value):
    leaf = BYTE.balance_key("11" * 20, "22" * 10)
    # The fixed oversized-value API observation is one byte beyond the prior
    # proof policy. Construct its expected bytes under a separate +1 bound;
    # consumer decoding and all four earlier oracle limits remain unchanged.
    BYTE.require(type(value) is bytes and len(value) <= WIRE.MAX_VALUE_BYTES + 1, "RPC expected leaf exceeds fixed work bound")
    leaf_index = int.from_bytes(BYTE.digest(leaf), "big")
    values = {leaf_index: value}
    nodes = {leaf_index: BYTE.digest(BYTE.digest(leaf) + value)}
    levels = {256: nodes}
    for depth in range(255, -1, -1):
        parents = {}
        for index in {index >> 1 for index in nodes}:
            parents[index] = BYTE.parent(nodes.get(index * 2, BYTE.ZERO), nodes.get(index * 2 + 1, BYTE.ZERO))
        nodes = parents
        levels[depth] = nodes
    root = levels[0].get(0, BYTE.ZERO)
    position = BYTE.digest(key or b"")
    index = int.from_bytes(position, "big")
    return root, values.get(index), BYTE.canonical_proof(levels, values, position)


def header_identifier(version, height, root):
    preimage = (BYTE.uint64(version) + BYTE.uint64(2) + bytes([85]) * 32 + BYTE.uint64(height) +
                BYTE.uint64(1700000000) + BYTE.digest(b"") + BYTE.digest(b"") + bytes([102]) * 32)
    if version >= 2:
        preimage += BYTE.uint64(7) + BYTE.uint64(11)
    if version >= 3:
        preimage += root
    return BYTE.digest(preimage)


def stub_error(kind, phase):
    if not kind:
        return None
    message = {"not-ready": "state tree: not yet built to the chain frontier",
               "not-retained": "synthetic: no such version"}.get(kind, "synthetic " + kind + " failure")
    return {"message": message, "code": None if kind in ("not-ready", "not-retained") else
            {"lookup": -32101, "proof": -32102, "root": -32103}[phase], "stub_error_identity": phase}


def expected_observation(item):
    key = selected_key(item["key_kind"])
    leaf_value = WIRE.binding_inputs()[item["binding_name"]][2]
    selected_root, value, proof = primitive(key, leaf_value)
    momentum = None if item["missing_momentum"] else {
        "version": item["version"], "height": item["store_height"],
        "hash": (bytes([170]) * 32 if item["hash_override"] else
                 header_identifier(item["version"], item["store_height"], selected_root)).hex(),
        "state_root": selected_root.hex()}
    identifier = None if momentum is None else {"hash": momentum["hash"], "height": momentum["height"]}
    root = selected_root
    kind = item["response_kind"]
    if kind == "coherent-substitution":
        root, value, proof = primitive(key, (2).to_bytes(32, "big"))
    elif kind == "oversized-value":
        root, value, proof = primitive(key, bytes([119]) * 4097)
    elif kind == "nil-value":
        value = None
    elif kind == "root-substitution":
        root = bytes([68]) * 32
    trace = [{"method": "Zenon.Chain"}]
    error, result = None, "null" if item["method"] == "GetProof" else json.dumps(BYTE.ZERO.hex())
    if item["height"] == 0:
        error = {"message": "height parameter must be strictly greater than zero", "code": -32000,
                 "stub_error_identity": None}
    else:
        trace += [{"method": "Chain.GetFrontierMomentumStore"},
                  {"method": "MomentumStore.GetMomentumByHeight", "height": item["height"]}]
        if item["lookup_error"]:
            error = stub_error(item["lookup_error"], "lookup")
        elif momentum is None:
            error = {"message": "no momentum at height " + str(item["height"]), "code": None,
                     "stub_error_identity": None}
        elif item["version"] < 3:
            error = {"message": "state root not available before its activation height", "code": -32000,
                     "stub_error_identity": None}
        else:
            if item["method"] == "GetProof":
                trace.append({"method": "Chain.GetProof", "identifier": identifier,
                              "key_hex": None if key is None else key.hex()})
                error = stub_error(item["proof_error"], "proof")
            if error is None:
                trace.append({"method": "Chain.StateRoot", "identifier": identifier})
                error = stub_error(item["root_error"], "root")
                if item["method"] == "GetStateRoot":
                    returned = BYTE.ZERO if item["root_error"] in ("not-ready", "not-retained") else root
                    result = json.dumps(returned.hex())
                elif error is None:
                    result = WIRE.encode_wire(value, proof, root)
    return {"input": item, "momentum": momentum, "request_key_hex": None if key is None else key.hex(),
            "trace": trace, "result_json": result, "error": error}


def strict_equal(actual, expected):
    BYTE.require(type(actual) is type(expected), "RPC fixture scalar/container type differs")
    if type(expected) is dict:
        BYTE.require(set(actual) == set(expected), "closed RPC fixture shape required")
        for key, value in expected.items():
            strict_equal(actual[key], value)
    elif type(expected) is list:
        BYTE.require(len(actual) == len(expected), "RPC fixture inventory/trace count differs")
        for item, value in zip(actual, expected):
            strict_equal(item, value)
    else:
        BYTE.require(actual == expected, "independent RPC observation differs")


def consumer_decision(row, selection):
    item = row["input"]
    expected = WIRE.selected_context(item["binding_name"])
    strict_equal(selection, expected)
    if row["error"] is not None:
        return "reference_error"
    momentum = row["momentum"]
    if momentum["version"] != 3:
        return "unsupported_reference_version"
    if item["height"] != selection["header_height"] or momentum["height"] != item["height"]:
        return "selected_height_mismatch"
    if momentum["hash"] != selection["header_hash"] or momentum["state_root"] != selection["root"]:
        return "selected_header_identifier_mismatch"
    if item["method"] == "GetStateRoot":
        root = json.loads(row["result_json"])
        return "research_root_match" if BYTE.hex_bytes(root, 32).hex() == selection["root"] else "selected_root_mismatch"
    key = row["request_key_hex"]
    if key is None or len(key) > WIRE.MAX_KEY_BYTES * 2:
        return "selected_key_bound_or_type_refusal"
    if key != selection["raw_key"]:
        return "selected_key_mismatch"
    try:
        return WIRE.research_binding(row["result_json"], item["binding_name"], selection)["decision"]
    except (ValueError, TypeError, UnicodeError):
        return "wire_binding_refusal"


def check_corpus(document):
    BYTE.require(type(document) is dict and set(document) == {"format_version", "kind", "source", "scope", "cases"},
                 "closed RPC method corpus required")
    strict_equal(document["format_version"], 1)
    strict_equal(document["kind"], "candidate-rpc-method-research")
    strict_equal(document["source"], {"repository": "https://github.com/digitalSloth/go-zenon",
                                     "revision": BYTE.NODE_REVISION, "tree": BYTE.NODE_TREE})
    strict_equal(document["scope"], SCOPE)
    rows = document["cases"]
    BYTE.require(type(rows) is list and len(rows) <= MAX_CASES and len(rows) == len(selected_inputs()),
                 "RPC method inventory differs")
    decisions, methods = [], {method: 0 for method in METHODS}
    trace_counts = {method: 0 for method in ("Zenon.Chain", "Chain.GetFrontierMomentumStore", "MomentumStore.GetMomentumByHeight", "Chain.GetProof", "Chain.StateRoot")}
    for row, selected in zip(rows, selected_inputs()):
        strict_equal(row, expected_observation(selected))
        for event in row["trace"]:
            trace_counts[event["method"]] += 1
        methods[selected["method"]] += 1
        decisions.append({"name": selected["name"], "decision": consumer_decision(row, WIRE.selected_context(selected["binding_name"]))})
    counts = {}
    for decision in decisions:
        name = decision["decision"]
        counts[name] = counts.get(name, 0) + 1
    return {"method_cases": len(rows), "actual_method_observations": methods, "recorded_call_events": sum(trace_counts.values()),
            "call_counts": trace_counts, "consumer_decision_counts": counts, "consumer_decisions": decisions,
            "nonzero_root_error_results": sum(row["input"]["method"] == "GetStateRoot" and row["error"] is not None and
                json.loads(row["result_json"]) != BYTE.ZERO.hex() for row in rows),
            "reference_LedgerApi_methods_executed": True, "recording_chain_store_stubs": True,
            "reference_CGO_native_CI_qualified": False, "actual_chain_stateTree_qualified": False,
            "reference_rpc_dispatcher_executed": False, "reference_rpc_transport_executed": False,
            "reference_database_opened": False, "header_authentication_qualified": False,
            "production_acceptance_enabled": False, "profile_agreed": False, "network_activation_authenticated": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, default=HERE / "testdata/candidate-rpc-methods.json")
    parser.add_argument("--source-revision")
    args = parser.parse_args(argv)
    if args.source_revision is not None:
        BYTE.require(len(args.source_revision) == 40 and all(char in "0123456789abcdef" for char in args.source_revision), "invalid source revision")
    raw, document = BYTE.read_corpus(args.corpus)
    report = check_corpus(document)
    report.update({"source_revision": args.source_revision, "corpus_sha256": hashlib.sha256(raw).hexdigest(),
                   "node_revision": BYTE.NODE_REVISION, "node_tree": BYTE.NODE_TREE})
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError, RecursionError, UnicodeError):
        print("Candidate RPC method check failed; preserve the original fixture and inspect locally.", file=sys.stderr)
        sys.exit(1)
