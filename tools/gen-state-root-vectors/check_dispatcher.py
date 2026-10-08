#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Independent offline HTTP/JSON-RPC observations and synthetic consumer refusals.

The finite inventory selects request bytes and expected method/error/trace bytes
independently. Actual ServeHTTP execution uses in-memory recorders and synthetic
chain/store stubs; this is not a network, lifecycle or accepted-header fixture.
The strict consumer policy below is research policy, not an agreed RPC profile.
"""
import argparse
import base64
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("candidate_dispatcher_method_oracle", HERE / "check_rpc_methods.py")
RPC = importlib.util.module_from_spec(spec)
spec.loader.exec_module(RPC)
WIRE, BYTE = RPC.WIRE, RPC.BYTE
MAX_CASES = 128
MAX_MESSAGE_BYTES = 32768
SCOPE = {"synthetic": True, "unsigned": True, "LedgerApi_constructor_executed": True,
         "LedgerApi_methods_executed": True, "recording_chain_store_stubs": True,
         "primitive_proof_api_executed": True, "StateProof_serializer_executed": True,
         "rpc_dispatcher_executed": True, "rpc_parameter_decoder_executed": True,
         "rpc_http_handler_executed_in_memory": True, "read_only_delegates_only": True,
         "server_stopped_after_each_case": True, "request_body_closed_after_each_case": True,
         "http_listener_started": False, "live_transport_executed": False,
         "actual_chain_stateTree_executed": False, "node_database_opened": False,
         "node_lifecycle_executed": False, "node_tests_executed": False,
         "profile_agreed": False, "network_activation_authenticated": False,
         "header_authentication_executed": False, "runtime_state_proof_acceptance": False}
CODEC_NAMES = (
    "string-id", "null-id", "boolean-id", "fraction-id", "exponent-id", "wide-id", "object-id", "array-id",
    "notification", "unknown-method", "unknown-namespace", "missing-version", "wrong-version", "unknown-field", "duplicate-id", "duplicate-params",
    "trailing-object", "trailing-garbage", "malformed-json", "null-request", "empty-batch", "single-call-batch", "empty-body",
    "missing-params", "null-params", "named-params", "missing-key", "excess-params", "null-height", "negative-height", "fraction-height",
    "exponent-height", "text-height", "boolean-height", "max-height", "overflow-height", "null-key", "array-key", "bad-base64", "unpadded-base64",
    "invalid-byte-array", "wrong-content-type", "put-method", "health-get", "declared-oversize", "options-method")
ID_TOKENS = {"string-id": '"selected-7"', "null-id": "null", "boolean-id": "true", "fraction-id": "7.0",
             "exponent-id": "7e0", "wide-id": "9007199254740993", "object-id": "{}", "array-id": "[]"}
HEIGHT_TOKENS = {"null-height": "null", "negative-height": "-1", "fraction-height": "42.0", "exponent-height": "4.2e1",
                 "text-height": '"42"', "boolean-height": "true", "max-height": "18446744073709551615",
                 "overflow-height": "18446744073709551616"}


def compact(value):
    return json.dumps(value, separators=(",", ":"), ensure_ascii=True)


def byte_argument(raw):
    return "null" if raw is None else compact(base64.b64encode(raw).decode("ascii"))


def request(id_token, method, params):
    return '{"jsonrpc":"2.0","id":' + id_token + ',"method":' + compact(method) + ',"params":' + params + '}'


def wire_method(item):
    return "ledger.getProof" if item["method"] == "GetProof" else "ledger.getStateRoot"


def selected_inputs():
    rows = []
    for item in RPC.selected_inputs():
        params = "[" + str(item["height"])
        if item["method"] == "GetProof":
            params += "," + byte_argument(RPC.selected_key(item["key_kind"]))
        rows.append({"name": "method/" + item["name"], "method_case": item, "http_method": "POST",
                     "content_type": "application/json", "declared_content_length": -1,
                     "request_json": request("7", wire_method(item), params + "]")})
    base = RPC.selected_inputs()[6]
    raw_key = RPC.selected_key("balance")
    key = byte_argument(raw_key)
    params = "[42," + key + "]"
    chosen = request("7", "ledger.getProof", params)
    for name in CODEC_NAMES:
        row = {"name": "codec/" + name, "method_case": copy.deepcopy(base), "http_method": "POST",
               "content_type": "application/json", "declared_content_length": -1, "request_json": chosen}
        if name in ID_TOKENS:
            row["request_json"] = request(ID_TOKENS[name], "ledger.getProof", params)
        elif name == "notification":
            row["request_json"] = chosen.replace('"id":7,', "", 1)
        elif name in ("unknown-method", "unknown-namespace"):
            row["request_json"] = request("7", "ledger.unknown" if name == "unknown-method" else "other.getProof", params)
        elif name == "missing-version":
            row["request_json"] = chosen.replace('"jsonrpc":"2.0",', "", 1)
        elif name == "wrong-version":
            row["request_json"] = chosen.replace('"jsonrpc":"2.0"', '"jsonrpc":"1.0"', 1)
        elif name == "unknown-field":
            row["request_json"] = chosen.replace('"jsonrpc":', '"unselected":true,"jsonrpc":', 1)
        elif name == "duplicate-id":
            row["request_json"] = chosen.replace('"id":7', '"id":8,"id":7', 1)
        elif name == "duplicate-params":
            row["request_json"] = chosen.replace('"params":', '"params":[0,null],"params":', 1)
        elif name in ("trailing-object", "trailing-garbage"):
            row["request_json"] += " {}" if name == "trailing-object" else " trailing"
        elif name in ("malformed-json", "null-request", "empty-batch", "single-call-batch", "empty-body"):
            row["request_json"] = {"malformed-json": '{"jsonrpc":', "null-request": "null", "empty-batch": "[]",
                                   "single-call-batch": "[" + chosen + "]", "empty-body": ""}[name]
        elif name == "missing-params":
            row["request_json"] = '{"jsonrpc":"2.0","id":7,"method":"ledger.getProof"}'
        elif name in ("null-params", "named-params", "missing-key", "excess-params"):
            argument = {"null-params": "null", "named-params": '{"height":42,"key":' + key + '}',
                        "missing-key": "[42]", "excess-params": "[42," + key + ",0]"}[name]
            row["request_json"] = request("7", "ledger.getProof", argument)
        elif name in HEIGHT_TOKENS:
            row["request_json"] = request("7", "ledger.getProof", "[" + HEIGHT_TOKENS[name] + "," + key + "]")
        elif name in ("null-key", "array-key", "bad-base64", "unpadded-base64", "invalid-byte-array"):
            argument = {"null-key": "null", "array-key": compact(list(raw_key)), "bad-base64": '"!"',
                        "unpadded-base64": '"AA"', "invalid-byte-array": "[300]"}[name]
            row["request_json"] = request("7", "ledger.getProof", "[42," + argument + "]")
        elif name == "wrong-content-type":
            row["content_type"] = "text/plain"
        elif name == "put-method":
            row["http_method"] = "PUT"
        elif name == "health-get":
            row.update(http_method="GET", content_type="", request_json="")
        elif name == "declared-oversize":
            row["declared_content_length"] = 5 * 1024 * 1024 + 1
        elif name == "options-method":
            row.update(http_method="OPTIONS", content_type="")
        rows.append(row)
    return rows


def envelope(id_token, result=None, error=None):
    payload = '"error":' + compact(error) if error is not None else '"result":' + result
    return '{"jsonrpc":"2.0","id":' + id_token + ',' + payload + '}\n'


def parameter_error(name):
    messages = {"missing-params": "missing value for required argument 0", "null-params": "missing value for required argument 0",
                "named-params": "non-array args", "missing-key": "missing value for required argument 1",
                "excess-params": "too many arguments, want at most 2",
                "bad-base64": "invalid argument 1: illegal base64 data at input byte 0",
                "unpadded-base64": "invalid argument 1: illegal base64 data at input byte 0",
                "invalid-byte-array": "invalid argument 1: json: cannot unmarshal number 300 into Go value of type uint8"}
    if name in HEIGHT_TOKENS and name not in ("null-height", "max-height"):
        token = HEIGHT_TOKENS[name]
        text = "string" if name == "text-height" else "bool" if name == "boolean-height" else "number " + token
        return "invalid argument 0: json: cannot unmarshal " + text + " into Go value of type uint64"
    return messages.get(name)


def expected_observation(item):
    original = RPC.expected_observation(item["method_case"])
    row = {"input": item, "momentum": original["momentum"], "delegated_calls": [], "trace": [{"method": "Zenon.Chain"}],
           "http_status": 200, "response_content_type": "application/json", "response_body": ""}
    name = item["name"].removeprefix("codec/")
    if name in ("wrong-content-type", "put-method", "declared-oversize"):
        status, message = {"wrong-content-type": (415, "invalid content type, only application/json is supported"),
                           "put-method": (405, "method not allowed"),
                           "declared-oversize": (413, "content length too large (5242881>5242880)")}[name]
        row.update(http_status=status, response_content_type="text/plain; charset=utf-8", response_body=message + "\n")
        return row
    if name == "health-get":
        row["response_content_type"] = ""
        return row
    if name == "empty-body":
        return row
    id_token = ID_TOKENS.get(name, "7")
    code, message = None, None
    if name in ("object-id", "array-id", "null-request"):
        code, message, id_token = -32600, "invalid request", "null"
    elif name == "empty-batch":
        code, message, id_token = -32600, "empty batch", "null"
    elif name == "malformed-json":
        code, message, id_token = -32700, "parse error", "null"
    elif name in ("unknown-method", "unknown-namespace"):
        method = "ledger.unknown" if name == "unknown-method" else "other.getProof"
        code, message = -32601, "the method " + method + " does not exist/is not available"
    elif parameter_error(name) is not None:
        code, message = -32602, parameter_error(name)
    if code is not None:
        row["response_body"] = envelope(id_token, error={"code": code, "message": message})
        return row
    actual_item = copy.deepcopy(item["method_case"])
    if name == "null-height":
        actual_item["height"] = 0
    elif name == "max-height":
        actual_item["height"] = 2**64 - 1
    observed = RPC.expected_observation(actual_item)
    key = None if name == "null-key" else RPC.selected_key(actual_item["key_kind"])
    call = {"method": actual_item["method"], "height": actual_item["height"]}
    if actual_item["method"] == "GetProof":
        call["key_hex"] = None if key is None else key.hex()
    row["delegated_calls"] = [call]
    row["trace"] = observed["trace"]
    if name == "null-key":
        # The recording provider's fixed response is independent of the decoded
        # call key. Only the actual forwarded key changes in this counterexample.
        for event in row["trace"]:
            if event["method"] == "Chain.GetProof":
                event["key_hex"] = None
    error = observed["error"]
    row["response_body"] = envelope(id_token, result=observed["result_json"], error=None if error is None else
                                    {"code": -32000 if error["code"] is None else error["code"], "message": error["message"]})
    if name == "notification":
        row["response_body"] = ""
    elif name == "single-call-batch":
        row["response_body"] = "[" + row["response_body"].strip() + "]\n"
    return row


def bounded_json(text):
    BYTE.require(type(text) is str and len(text) <= MAX_MESSAGE_BYTES, "message type or character bound")
    raw = text.encode("utf-8")
    BYTE.require(len(raw) <= MAX_MESSAGE_BYTES, "message byte bound")
    return json.loads(raw, object_pairs_hook=BYTE.object_pairs)


def selected_consumer(item):
    return {"context": WIRE.selected_context(item["method_case"]["binding_name"]),
            "method": wire_method(item["method_case"]),
            "request_id": "selected-7" if item["name"] == "codec/string-id" else 7,
            "profile": "synthetic-dispatcher-policy-v1", "accepted_VerifiedState_binding": False}


def consumer_decision(row, selection):
    RPC.strict_equal(selection, selected_consumer(row["input"]))
    context, item = selection["context"], row["input"]
    try:
        BYTE.require(item["http_method"] == "POST" and item["content_type"] == "application/json" and
                     item["declared_content_length"] == -1, "unselected HTTP request")
        chosen = bounded_json(item["request_json"])
        BYTE.require(type(chosen) is dict and set(chosen) == {"jsonrpc", "id", "method", "params"}, "closed single request required")
        BYTE.require(chosen["jsonrpc"] == "2.0" and type(chosen["jsonrpc"]) is str and chosen["method"] == selection["method"],
                     "unselected version or method")
        RPC.strict_equal(chosen["id"], selection["request_id"])
        params = chosen["params"]
        BYTE.require(type(params) is list and len(params) == (2 if selection["method"] == "ledger.getProof" else 1), "exact positional arguments required")
        BYTE.require(type(params[0]) is int and params[0] == context["header_height"], "unselected uint64 height")
        if len(params) == 2:
            BYTE.require(type(params[1]) is str, "bounded canonical Base64 key required")
            key = WIRE.decode_base64(params[1], WIRE.MAX_KEY_BYTES)
            BYTE.require(key is not None and key.hex() == context["raw_key"], "unselected raw key")
    except (ValueError, TypeError, KeyError, RecursionError, UnicodeError):
        return "request_policy_refusal"
    try:
        BYTE.require(type(row["http_status"]) is int and row["http_status"] == 200 and row["response_content_type"] == "application/json",
                     "unsuccessful or unselected HTTP response")
        reply = bounded_json(row["response_body"])
        BYTE.require(type(reply) is dict and set(reply) in ({"jsonrpc", "id", "result"}, {"jsonrpc", "id", "error"}),
                     "exactly one closed success/error envelope required")
        BYTE.require(type(reply["jsonrpc"]) is str and reply["jsonrpc"] == "2.0", "unselected response version")
        RPC.strict_equal(reply["id"], selection["request_id"])
        if "error" in reply:
            error = reply["error"]
            BYTE.require(type(error) is dict and set(error) == {"code", "message"} and type(error["code"]) is int and
                         type(error["message"]) is str, "closed typed error required")
            return "reference_error"
        method_item = item["method_case"]
        momentum = row["momentum"]
        BYTE.require(type(momentum) is dict and set(momentum) == {"version", "height", "hash", "state_root"},
                     "closed synthetic momentum metadata required")
        for field in ("version", "height"):
            BYTE.require(type(momentum[field]) is int and 0 <= momentum[field] < 1 << 64, "exact momentum uint64 required")
        for field in ("hash", "state_root"):
            BYTE.hex_bytes(momentum[field], 32)
        observed = {"input": method_item, "momentum": row["momentum"], "request_key_hex": context["raw_key"],
                    "result_json": compact(reply["result"]), "error": None}
        return RPC.consumer_decision(observed, context)
    except (ValueError, TypeError, KeyError, RecursionError, UnicodeError):
        return "response_envelope_refusal"


def check_corpus(document):
    BYTE.require(type(document) is dict and set(document) == {"format_version", "kind", "source", "scope", "cases"}, "closed dispatcher corpus required")
    RPC.strict_equal(document["format_version"], 1)
    RPC.strict_equal(document["kind"], "candidate-rpc-dispatcher-research")
    RPC.strict_equal(document["source"], {"repository": "https://github.com/digitalSloth/go-zenon",
                                       "revision": BYTE.NODE_REVISION, "tree": BYTE.NODE_TREE})
    RPC.strict_equal(document["scope"], SCOPE)
    rows = document["cases"]
    BYTE.require(type(rows) is list and len(rows) <= MAX_CASES and len(rows) == len(selected_inputs()), "finite dispatcher inventory required")
    decisions, statuses = [], {}
    calls, events, success, error = 0, 0, 0, 0
    for row, selected in zip(rows, selected_inputs()):
        RPC.strict_equal(row, expected_observation(selected))
        calls += len(row["delegated_calls"])
        events += len(row["trace"])
        statuses[str(row["http_status"])] = statuses.get(str(row["http_status"]), 0) + 1
        if row["response_body"] and row["response_content_type"] == "application/json":
            response = bounded_json(row["response_body"])
            if type(response) is list:
                response = response[0]
            success += "result" in response
            error += "error" in response
        decisions.append({"name": selected["name"], "decision": consumer_decision(row, selected_consumer(selected))})
    counts = {}
    for result in decisions:
        name = result["decision"]
        counts[name] = counts.get(name, 0) + 1
    return {"dispatcher_cases": len(rows), "actual_delegated_calls": calls, "recorded_call_events": events,
            "http_status_counts": statuses, "success_envelopes": success, "error_envelopes": error,
            "empty_responses": sum(row["response_body"] == "" for row in rows),
            "consumer_decision_counts": counts, "consumer_decisions": decisions,
            "reference_rpc_dispatcher_executed": True, "reference_http_handler_executed_in_memory": True,
            "reference_parameter_decoder_executed": True, "reference_LedgerApi_methods_executed": True,
            "recording_chain_store_stubs": True, "http_listener_started": False,
            "native_reference_rpc_dispatcher_execution": False, "native_reference_CGO_qualified": False,
            "live_transport_qualified": False, "actual_chain_stateTree_qualified": False, "reference_database_opened": False,
            "accepted_VerifiedState_binding_qualified": False, "header_authentication_qualified": False,
            "production_acceptance_enabled": False, "profile_agreed": False, "network_activation_authenticated": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, default=HERE / "testdata/candidate-rpc-dispatcher.json")
    parser.add_argument("--source-revision")
    args = parser.parse_args(argv)
    if args.source_revision is not None:
        BYTE.require(len(args.source_revision) == 40 and all(char in "0123456789abcdef" for char in args.source_revision), "invalid source revision")
    raw, document = BYTE.read_corpus(args.corpus)
    report = check_corpus(document)
    report.update(source_revision=args.source_revision, corpus_sha256=hashlib.sha256(raw).hexdigest(),
                  node_revision=BYTE.NODE_REVISION, node_tree=BYTE.NODE_TREE)
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError, RecursionError, UnicodeError):
        print("Candidate dispatcher check failed; preserve the original fixture and inspect locally.", file=sys.stderr)
        sys.exit(1)
