#!/usr/bin/env python3
"""Compare a trusted compiled consumer with a bounded independent Python oracle.

This is an offline conformance checker, not a replacement consumer, SDK, report
authenticator or network pilot. It neither imports Go output to select expected
targets nor invokes the verifier, RPC, state persistence or a wallet.
"""

import argparse
import contextlib
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import tempfile


REPORT_BYTES = 4 << 20
EXPECTATION_BYTES = 256 << 10
U64_MAX = (1 << 64) - 1
I64_MAX = (1 << 63) - 1
GUARANTEES = {
    "HEADER_CHAIN_INTEGRITY", "SIGNATURE_AUTHENTICITY", "CONTENT_INCLUSION",
    "PRODUCER_AUTHORIZATION",
}
ALL_GUARANTEES = GUARANTEES | {"CANONICALITY", "STATE_TRANSITION", "STATE_VALUE_INCLUSION"}
TRUST = {
    "TRUST_CONFIGURED_ANCHOR", "TRUST_PERSISTED_STATE", "TRUST_EXTERNAL_PROTOCOL_PROFILE",
    "TRUST_CHECKPOINT_ANCHOR", "TRUST_RPC_QUORUM", "TRUST_EXTERNAL_PRODUCER_SCHEDULE",
    "TRUST_RETAINED_WINDOW_DEPTH",
}
REQUIRED_TRUST = {"TRUST_CONFIGURED_ANCHOR", "TRUST_PERSISTED_STATE"}
LIMITS = (
    "max_bundle_bytes", "max_headers", "max_commitments", "max_flat_evidence_members",
    "max_total_flat_evidence_members", "max_segments", "max_segment_blocks",
    "max_total_segment_blocks", "max_state_value_proofs", "max_state_proof_nodes",
    "max_state_proof_bytes",
)


class Invalid(ValueError):
    """A bounded input does not satisfy the selected diagnostic contract."""


class JSONInteger(str):
    """Preserve lexical integers until their signed field range is checked."""


def normalized(text):
    # Go encoding/json replaces unpaired escaped UTF-16 surrogates with U+FFFD.
    # Python combines paired escapes but preserves unpaired code units.
    return "".join("\ufffd" if 0xD800 <= ord(c) <= 0xDFFF else c for c in text)


def object_pairs(pairs):
    result = {}
    for key, value in pairs:
        key = normalized(key)
        if key in result:
            raise Invalid("duplicate key")
        result[key] = value
    return result


def noninteger(_):
    raise Invalid("noninteger token")


def bounded_json(raw):
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=object_pairs,
                       parse_int=JSONInteger, parse_float=noninteger,
                       parse_constant=noninteger)
    nodes = 0

    def visit(item, depth=0):
        nonlocal nodes
        nodes += 1
        if depth > 16 or nodes > 16384:
            raise Invalid("traversal bound")
        if type(item) is JSONInteger:
            if len(item) > 21 or item == "-0":
                raise Invalid("integer spelling")
        elif type(item) is str:
            item = normalized(item)
            if len(item.encode("utf-8")) > 4096:
                raise Invalid("string bound")
        elif type(item) is list:
            if len(item) > 256:
                raise Invalid("array bound")
            item = [visit(child, depth + 1) for child in item]
        elif type(item) is dict:
            if len(item) > 256 or any(len(k.encode("utf-8")) > 128 for k in item):
                raise Invalid("object bound")
            item = {key: visit(child, depth + 1) for key, child in item.items()}
        return item

    return visit(value)


TIP = {"hash": "text", "height": "u64"}
ACCOUNT = {"address": "text", "height": "u64", "hash": "text"}
REFERENCE = {
    "scope": "text", "index": "u64", "block_index": ("optional", "u64"),
    "momentum_height": ("optional", "u64"), "account_header": ACCOUNT,
}
POLICY = {"w": "u64", "retain_headers": ("optional", "i64"), **{k: "i64" for k in LIMITS}}
CONTEXT = {
    "schema_version": "u32", "fingerprint": "text", "fingerprint_status": "text",
    "anchor": {"chain_id": "u64", "height": "u64", "header_hash": "text"},
    "policy": POLICY,
    "protocol_profile": ("nullable", {"version": "u32", "valid_through": "u64", "v2_from_height": "u64"}),
    "producer": {"mode": "text", "source": "text", "kind": "text", "schedule_hash": ("nullable", "text")},
    "checkpoints": ("array", {"height": "u64", "header_hash": "text"}),
}
EXPECTATIONS = {
    "schema_version": "u32", "command": "text", "context_fingerprint": "text",
    "verification_tip": TIP, "targets": ("array", REFERENCE),
    "required_guarantees": ("array", "text"), "allowed_trust_assumptions": ("array", "text"),
}
ROW = {
    "reference": REFERENCE, "outcome": "text", "reason": "text", "failed_at": "i64",
    "proven": ("array", "text"), "not_proven": ("array", "text"),
    "trust_assumptions": ("array", "text"),
}
REPORT = {
    "schema_version": "u32", "command": "text", "mode": "text", "exit_code": "i64",
    "outcome": "text", "error": ("nullable", {"stage": "text", "category": "text"}),
    "persistence": "text", "verification_context": CONTEXT, "verification_tip": TIP,
    "state_trust": ("array", "text"), "results": ("array", ROW), "caveats": ("array", "text"),
}


def typed(value, schema):
    if type(schema) is dict:
        if type(value) is not dict or set(value) - set(schema):
            raise Invalid("object shape")
        result = {}
        for key, field in schema.items():
            optional = type(field) is tuple and field[0] == "optional"
            if key not in value:
                if not optional:
                    raise Invalid("missing key")
            else:
                result[key] = typed(value[key], field[1] if optional else field)
        return result
    if type(schema) is tuple:
        kind, child = schema
        if kind == "nullable":
            return None if value is None else typed(value, child)
        if kind == "array" and type(value) is list:
            return [typed(item, child) for item in value]
        raise Invalid("array shape")
    if schema == "text" and type(value) is str:
        return value
    if schema in ("u32", "u64", "i64") and type(value) is JSONInteger:
        integer = int(value)
        lower, upper = {"u32": (0, (1 << 32) - 1), "u64": (0, U64_MAX),
                        "i64": (-(1 << 63), I64_MAX)}[schema]
        if lower <= integer <= upper:
            return integer
    raise Invalid("scalar type or range")


def decode(raw, schema):
    return typed(bounded_json(raw), schema)


def hex_value(value, length, nonzero=False):
    return re.fullmatch(r"[0-9a-f]{%d}" % length, value) is not None and (not nonzero or set(value) != {"0"})


def valid_tip(tip):
    return tip["height"] > 0 and hex_value(tip["hash"], 64, True)


def known_set(items, known):
    return len(items) == len(set(items)) and set(items) <= known


def position(ref):
    return ref["scope"], ref["index"], ref.get("block_index", 0)


def valid_references(refs, command):
    if not 1 <= len(refs) <= 256 or len({position(r) for r in refs}) != len(refs):
        return False
    for ref in refs:
        account = ref["account_header"]
        if not hex_value(account["address"], 40) or not hex_value(account["hash"], 64):
            return False
        if command == "verify-commitment":
            if ref["scope"] != "commitment" or "momentum_height" not in ref or "block_index" in ref:
                return False
        elif command == "verify-segment":
            if ref["scope"] != "segment" or "block_index" not in ref or ref["block_index"] > I64_MAX or "momentum_height" in ref:
                return False
        else:
            return False
    return True


def context_fingerprint(context):
    # Written from docs/verification-context.md. No Go encoder or its output
    # selects these bytes, field order, settings or target identities.
    version = context["schema_version"]
    raw = bytearray(("zenon-spv/verification-context/v%d\0" % version).encode("ascii"))

    def number(value):
        raw.extend(struct.pack(">Q", value))

    def digest(value):
        raw.extend(bytes.fromhex(value))

    def text(value):
        encoded = value.encode("utf-8")
        number(len(encoded))
        raw.extend(encoded)

    number(version)
    anchor = context["anchor"]
    number(anchor["chain_id"])
    number(anchor["height"])
    digest(anchor["header_hash"])
    policy = context["policy"]
    number(policy["w"])
    if version == 2:
        number(policy["retain_headers"])
    for key in LIMITS:
        number(policy[key])
    profile = context["protocol_profile"]
    number(int(profile is not None))
    if profile is not None:
        for key in ("version", "valid_through", "v2_from_height"):
            number(profile[key])
    producer = context["producer"]
    for key in ("mode", "source", "kind"):
        text(producer[key])
    number(int(producer["schedule_hash"] is not None))
    if producer["schedule_hash"] is not None:
        digest(producer["schedule_hash"])
    number(len(context["checkpoints"]))
    for checkpoint in context["checkpoints"]:
        number(checkpoint["height"])
        digest(checkpoint["header_hash"])
    return hashlib.sha3_256(raw).hexdigest()


def valid_context(context):
    version = context["schema_version"]
    anchor, policy, producer = (context[key] for key in ("anchor", "policy", "producer"))
    if version not in (1, 2) or context["fingerprint_status"] != "available" or not hex_value(context["fingerprint"], 64):
        return False
    if not anchor["height"] or not hex_value(anchor["header_hash"], 64, True) or not policy["w"]:
        return False
    if version == 1 and "retain_headers" in policy or version == 2 and policy.get("retain_headers", 0) <= 0:
        return False
    if any(policy[key] < 0 for key in LIMITS):
        return False
    profile = context["protocol_profile"]
    if profile is not None and (profile["version"] != 1 or profile["valid_through"] < anchor["height"]):
        return False
    if producer["mode"] == "Disabled":
        if producer != {"mode": "Disabled", "source": "None", "kind": "disabled", "schedule_hash": None}:
            return False
    elif (producer["mode"] != "Required" or producer["kind"] != "schedule" or
          producer["source"] not in ("OperatorAttested", "LocallyDerivedFromChain") or
          producer["schedule_hash"] is None or not hex_value(producer["schedule_hash"], 64, True)):
        return False
    previous = 0
    for checkpoint in context["checkpoints"]:
        if checkpoint["height"] <= previous or not hex_value(checkpoint["header_hash"], 64, True):
            return False
        previous = checkpoint["height"]
    return context_fingerprint(context) == context["fingerprint"]


def valid_expectations(expected):
    return (expected["schema_version"] == 1 and hex_value(expected["context_fingerprint"], 64) and
            valid_tip(expected["verification_tip"]) and valid_references(expected["targets"], expected["command"]) and
            known_set(expected["required_guarantees"], GUARANTEES) and
            "CONTENT_INCLUSION" in expected["required_guarantees"] and
            known_set(expected["allowed_trust_assumptions"], TRUST))


def valid_report(report):
    if (report["schema_version"] != 1 or not valid_context(report["verification_context"]) or
            not valid_tip(report["verification_tip"]) or not known_set(report["state_trust"], TRUST) or
            not valid_references([r["reference"] for r in report["results"]], report["command"])):
        return False
    return all(known_set(row["proven"], GUARANTEES) and known_set(row["not_proven"], ALL_GUARANTEES) and
               known_set(row["trust_assumptions"], TRUST) and not set(row["proven"]) & set(row["not_proven"])
               for row in report["results"])


def trust_allowed(actual, allowed):
    return REQUIRED_TRUST <= set(actual) <= set(allowed)


def match(report, expected):
    if (report["command"] != expected["command"] or report["mode"] != "retained_only" or
            report["persistence"] != "read_only" or report["exit_code"] != 0 or report["error"] is not None or
            report["outcome"] != "ACCEPT" or
            report["verification_context"]["fingerprint"] != expected["context_fingerprint"] or
            report["verification_tip"] != expected["verification_tip"]):
        return "report_mismatch"
    if not trust_allowed(report["state_trust"], expected["allowed_trust_assumptions"]):
        return "trust_mismatch"
    targets = {position(ref): ref for ref in expected["targets"]}
    if len(report["results"]) != len(targets):
        return "target_mismatch"
    for row in report["results"]:
        ref = row["reference"]
        if targets.get(position(ref)) != ref:
            return "target_mismatch"
        if row["outcome"] != "ACCEPT" or row["reason"] != "ReasonOK" or row["failed_at"] != ref.get("block_index", -1):
            return "report_mismatch"
        if not set(expected["required_guarantees"]) <= set(row["proven"]):
            return "guarantee_mismatch"
        if not trust_allowed(row["trust_assumptions"], expected["allowed_trust_assumptions"]):
            return "trust_mismatch"
    return None


def summary(category=None, count=0, code=2):
    result = {"schema_version": 1, "status": "not_matched" if category else "matched",
              "category": category, "checked_targets": count}
    return code, (json.dumps(result, separators=(",", ":")) + "\n").encode("ascii")


def consume(report_raw, expected_raw, process_exit):
    if type(process_exit) is not int or not -(1 << 63) <= process_exit <= I64_MAX:
        raise Invalid("caller status range")
    if process_exit:
        return summary("process_failure")
    for raw, schema, cap, category, validate in (
            (expected_raw, EXPECTATIONS, EXPECTATION_BYTES, "invalid_expectations", valid_expectations),
            (report_raw, REPORT, REPORT_BYTES, "invalid_report", valid_report)):
        if len(raw) > cap:
            return summary("input_unavailable", code=70)
        try:
            value = decode(raw, schema)
            if not validate(value):
                return summary(category)
        except (ValueError, UnicodeError, RecursionError):
            return summary(category)
        if schema is EXPECTATIONS:
            expected = value
        else:
            report = value
    category = match(report, expected)
    return summary(category, count=0 if category else len(expected["targets"]), code=2 if category else 0)


def encoded(value):
    return json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode("ascii")


def selected_inputs(command="verify-commitment", version=2, count=1):
    context = {
        "schema_version": version, "fingerprint": "", "fingerprint_status": "available",
        "anchor": {"chain_id": U64_MAX, "height": 7, "header_hash": "1" * 64},
        "policy": {"w": 5, **{key: 64 for key in LIMITS}},
        "protocol_profile": {"version": 1, "valid_through": U64_MAX, "v2_from_height": 100},
        "producer": {"mode": "Required", "source": "OperatorAttested", "kind": "schedule", "schedule_hash": "2" * 64},
        "checkpoints": [{"height": 9, "header_hash": "3" * 64}],
    }
    if version == 2:
        context["policy"]["retain_headers"] = 256
    context["fingerprint"] = context_fingerprint(context)
    targets = []
    for index in range(count):
        ref = {"scope": "commitment" if command == "verify-commitment" else "segment", "index": index,
               "account_header": {"address": "4" * 40, "height": U64_MAX - index, "hash": "%064x" % (index + 5)}}
        ref["momentum_height" if command == "verify-commitment" else "block_index"] = U64_MAX if command == "verify-commitment" else index
        targets.append(ref)
    tip = {"height": U64_MAX, "hash": "6" * 64}
    expected = {"schema_version": 1, "command": command, "context_fingerprint": context["fingerprint"],
                "verification_tip": copy.deepcopy(tip), "targets": copy.deepcopy(targets),
                "required_guarantees": ["CONTENT_INCLUSION"], "allowed_trust_assumptions": sorted(TRUST)}
    report = {"schema_version": 1, "command": command, "mode": "retained_only", "exit_code": 0,
              "outcome": "ACCEPT", "error": None, "persistence": "read_only", "verification_context": context,
              "verification_tip": tip, "state_trust": sorted(REQUIRED_TRUST), "caveats": [],
              "results": [{"reference": copy.deepcopy(ref), "outcome": "ACCEPT", "reason": "ReasonOK",
                           "failed_at": ref.get("block_index", -1), "proven": ["CONTENT_INCLUSION"],
                           "not_proven": sorted(ALL_GUARANTEES - {"CONTENT_INCLUSION"}),
                           "trust_assumptions": sorted(REQUIRED_TRUST)} for ref in targets]}
    return report, expected


def pinned_cases():
    """Expected decisions are pinned independently of both oracle and executable."""
    rows = []

    def add(name, report, expected, category=None, count=0, process_exit=0, code=None):
        rows.append({"id": name, "report": report if type(report) is bytes else encoded(report),
                     "expectations": expected if type(expected) is bytes else encoded(expected),
                     "process_exit": process_exit,
                     "wanted": summary(category, count, (2 if category else 0) if code is None else code)})

    for command in ("verify-commitment", "verify-segment"):
        for version in (1, 2):
            for count in (1, 2, 256):
                report, expected = selected_inputs(command, version, count)
                report["results"].reverse()
                add("%s_v%d_%d" % (command, version, count), report, expected, count=count)
    for name in ("disabled_producer", "locally_derived_schedule", "no_profile", "no_checkpoints"):
        r, e = selected_inputs()
        context = r["verification_context"]
        if name == "disabled_producer":
            context["producer"] = {"mode": "Disabled", "source": "None", "kind": "disabled", "schedule_hash": None}
        elif name == "locally_derived_schedule":
            context["producer"]["source"] = "LocallyDerivedFromChain"
        elif name == "no_profile":
            context["protocol_profile"] = None
        else:
            context["checkpoints"] = []
        context["fingerprint"] = context_fingerprint(context)
        e["context_fingerprint"] = context["fingerprint"]
        add(name, r, e, count=1)
    report, expected = selected_inputs(count=2)

    def mutation(name, side, path, value, category):
        r, e = copy.deepcopy(report), copy.deepcopy(expected)
        target = r if side == "report" else e
        for key in path[:-1]:
            target = target[key]
        if value is DELETE:
            del target[path[-1]]
        else:
            target[path[-1]] = value
        add(name, r, e, category)

    for name, path, value in (
            ("wrong_address", ("results", 0, "reference", "account_header", "address"), "a" * 40),
            ("wrong_height", ("results", 0, "reference", "account_header", "height"), U64_MAX - 2),
            ("wrong_hash", ("results", 0, "reference", "account_header", "hash"), "b" * 64),
            ("wrong_momentum", ("results", 0, "reference", "momentum_height"), U64_MAX - 1),
            ("wrong_position", ("results", 0, "reference", "index"), 8),
            ("missing_target", ("results",), report["results"][:1]),
            ("extra_target", ("results",), selected_inputs(count=3)[0]["results"]),
    ):
        mutation(name, "report", path, value, "target_mismatch")
    for name, path, value in (
            ("wrong_tip", ("verification_tip", "hash"), "a" * 64),
            ("wrong_tip_height", ("verification_tip", "height"), U64_MAX - 1),
            ("wrong_mode", ("mode",), "collect"), ("wrong_persistence", ("persistence",), "written"),
            ("internal_failure", ("exit_code",), 2), ("top_refusal", ("outcome",), "REJECT"),
            ("reported_error", ("error",), {"stage": "query", "category": "bounded"}),
            ("row_refusal", ("results", 0, "outcome"), "REJECT"),
            ("wrong_reason", ("results", 0, "reason"), "ReasonOther"),
            ("wrong_result_index", ("results", 0, "failed_at"), 0),
    ):
        mutation(name, "report", path, value, "report_mismatch")
    mutation("wrong_expected_pin", "expectations", ("context_fingerprint",), "a" * 64, "report_mismatch")
    for level, path in (("state", ("state_trust",)), ("row", ("results", 0, "trust_assumptions"))):
        mutation(level + "_missing_anchor", "report", path, ["TRUST_PERSISTED_STATE"], "trust_mismatch")
        mutation(level + "_missing_state", "report", path, ["TRUST_CONFIGURED_ANCHOR"], "trust_mismatch")
        r, e = copy.deepcopy(report), copy.deepcopy(expected)
        target = r if level == "state" else r["results"][0]
        target["state_trust" if level == "state" else "trust_assumptions"].append("TRUST_RPC_QUORUM")
        e["allowed_trust_assumptions"].remove("TRUST_RPC_QUORUM")
        add(level + "_unallowed_trust", r, e, "trust_mismatch")
    for name, path, value in (
            ("unknown_trust", ("state_trust",), ["UNKNOWN"]),
            ("duplicate_trust", ("state_trust",), ["TRUST_CONFIGURED_ANCHOR"] * 2),
            ("unknown_guarantee", ("results", 0, "proven"), ["UNKNOWN"]),
            ("conflicting_guarantee", ("results", 0, "not_proven"), ["CONTENT_INCLUSION"]),
            ("duplicate_reference", ("results", 1, "reference"), report["results"][0]["reference"]),
            ("modified_context", ("verification_context", "policy", "w"), 6),
            ("negative_limit", ("verification_context", "policy", LIMITS[0]), -1),
            ("invalid_profile", ("verification_context", "protocol_profile", "version"), 2),
            ("zero_anchor", ("verification_context", "anchor", "header_hash"), "0" * 64),
            ("unknown_producer", ("verification_context", "producer", "source"), "UNKNOWN"),
            ("null_optional", ("results", 0, "reference", "momentum_height"), None),
            ("null_array", ("results",), None),
            ("null_scalar", ("exit_code",), None),
            ("boolean_integer", ("exit_code",), True),
            ("unsigned_overflow", ("verification_tip", "height"), U64_MAX + 1),
            ("signed_overflow", ("exit_code",), I64_MAX + 1),
            ("negative_unsigned", ("verification_tip", "height"), -1),
            ("missing_field", ("results", 0, "reference", "index"), DELETE),
            ("uppercase_hash", ("results", 0, "reference", "account_header", "hash"), "A" * 64),
    ):
        mutation(name, "report", path, value, "invalid_report")
    r = copy.deepcopy(report)
    r["results"][0]["proven"] = []
    add("missing_required_guarantee", r, expected, "guarantee_mismatch")
    r, e = copy.deepcopy(report), copy.deepcopy(expected)
    e["required_guarantees"].append("SIGNATURE_AUTHENTICITY")
    r["results"][0]["proven"].append("SIGNATURE_AUTHENTICITY")
    r["results"][0]["not_proven"].remove("SIGNATURE_AUTHENTICITY")
    add("guarantees_are_per_row", r, e, "guarantee_mismatch")
    for guarantee in ("CANONICALITY", "STATE_TRANSITION", "STATE_VALUE_INCLUSION"):
        mutation("unsupported_" + guarantee.lower(), "expectations", ("required_guarantees",), [guarantee], "invalid_expectations")
    mutation("duplicate_expected_position", "expectations", ("targets", 1), expected["targets"][0], "invalid_expectations")
    mutation("missing_inclusion_request", "expectations", ("required_guarantees",), ["SIGNATURE_AUTHENTICITY"], "invalid_expectations")
    mutation("expected_integer_overflow", "expectations", ("targets", 0, "account_header", "height"), U64_MAX + 1, "invalid_expectations")
    mutation("missing_expected_field", "expectations", ("targets", 0, "index"), DELETE, "invalid_expectations")
    raw = encoded(report)
    for name, changed in (
            ("duplicate_key", raw.replace(b'"schema_version":1', b'"schema_version":1,"schema_version":1', 1)),
            ("escaped_duplicate", raw.replace(b'"schema_version":1', b'"schema_version":1,"schema_vers\\u0069on":1', 1)),
            ("unknown_key", raw[:-1] + b',"unknown":false}'),
            ("aliased_key", raw.replace(b'"schema_version"', b'"Schema_version"', 1)),
            ("fraction", raw.replace(b'"exit_code":0', b'"exit_code":0.0', 1)),
            ("exponent", raw.replace(b'"exit_code":0', b'"exit_code":0e0', 1)),
            ("negative_zero", raw.replace(b'"exit_code":0', b'"exit_code":-0', 1)),
            ("extra_document", raw + b' {}'), ("truncated", raw[:-1]),
            ("invalid_utf8", raw[:-1] + b',"unknown":"\xff"}'), ("bom", b'\xef\xbb\xbf' + raw),
            ("excessive_depth", b'[' * 17 + raw + b']' * 17),
    ):
        add(name, changed, expected, "invalid_report")
    add("escaped_known_key", raw.replace(b'"schema_version"', b'"schema_vers\\u0069on"', 1), expected, count=2)
    add("reordered_keys", dict(reversed(list(report.items()))), expected, count=2)
    for name, caveats, category in (
            ("string_at_bound", ["x" * 4096], None), ("string_over_bound", ["x" * 4097], "invalid_report"),
            ("array_at_bound", ["x"] * 256, None), ("array_over_bound", ["x"] * 257, "invalid_report"),
            ("quoted_delimiters", ['[]{}:,"\\'], None),
            ("unicode_strings", ["\U0001f680", "\ud800", "\udfff"], None),
    ):
        r = copy.deepcopy(report)
        r["caveats"] = caveats
        add(name, r, expected, category, count=0 if category else 2)
    for status in (2, -9, 3221225477, -(1 << 63), I64_MAX):
        add("process_status_%d" % status, b"not JSON", b"not JSON", "process_failure", process_exit=status)
    add("report_over_byte_cap", b" " * (REPORT_BYTES + 1), expected, "input_unavailable", code=70)
    add("expectations_over_byte_cap", b"not JSON", b" " * (EXPECTATION_BYTES + 1), "input_unavailable", code=70)
    expected_raw = encoded(expected)
    add("report_at_byte_cap", raw + b" " * (REPORT_BYTES - len(raw)), expected, count=2)
    add("expectations_at_byte_cap", report, expected_raw + b" " * (EXPECTATION_BYTES - len(expected_raw)), count=2)
    add("expectations_before_report", b"not JSON", b"not JSON", "invalid_expectations")
    return rows


DELETE = object()


GENERATED_SEEDS = (0, 1, 17, 255, 65535, 2147483647, 2147483648, 4294967295)
GENERATED_VARIANTS = (
    "valid", "wire_equivalent", "account_address", "account_hash", "account_height",
    "reference_index", "reference_position", "target_count", "duplicate_report_position",
    "duplicate_expected_position", "tip", "context_unpinned", "context_tampered",
    "required_guarantee", "row_trust", "state_trust", "integer_range",
    "escaped_duplicate_report", "escaped_duplicate_expected", "process_failure",
)


def generated_inputs(command, version, seed_index):
    """Select synthetic identities/settings before either implementation runs."""
    seed = GENERATED_SEEDS[seed_index]
    domain = "zenon-spv/consumer-cases/v1/%s/%d/%d/" % (command, version, seed)

    def digest(label):
        return hashlib.sha256((domain + label).encode("ascii")).hexdigest()

    count = (1, 3, 17, 64)[seed_index % 4]
    report, expected = selected_inputs(command, version, count)
    context = report["verification_context"]
    capacity = (16, 256, 4096)[seed_index % 3]
    context["anchor"] = {"chain_id": (0, 1, U64_MAX)[seed_index % 3],
                         "height": 7, "header_hash": digest("anchor")}
    context["policy"]["w"] = (1, 6, capacity - 1)[seed_index % 3]
    if version == 2:
        context["policy"]["retain_headers"] = capacity
    for index, key in enumerate(LIMITS):
        context["policy"][key] = (0, 1, 64, I64_MAX)[(seed_index + index) % 4]
    if seed_index % 2:
        context["protocol_profile"] = None
    else:
        context["protocol_profile"]["v2_from_height"] = (0, 100, U64_MAX)[seed_index % 3]
    if seed_index % 3 == 0:
        context["producer"] = {"mode": "Disabled", "source": "None", "kind": "disabled", "schedule_hash": None}
    else:
        context["producer"]["source"] = "OperatorAttested" if seed_index % 3 == 1 else "LocallyDerivedFromChain"
        context["producer"]["schedule_hash"] = digest("schedule")
    context["checkpoints"] = [{"height": 9 + i * 2, "header_hash": digest("checkpoint-%d" % i)}
                              for i in range(seed_index % 3)]
    context["fingerprint"] = context_fingerprint(context)
    expected["context_fingerprint"] = context["fingerprint"]
    tip = {"height": (1, (1 << 53) + 1, I64_MAX, U64_MAX)[seed_index % 4], "hash": digest("tip")}
    report["verification_tip"], expected["verification_tip"] = tip, copy.deepcopy(tip)
    required = {"CONTENT_INCLUSION"} | {g for i, g in enumerate(sorted(GUARANTEES - {"CONTENT_INCLUSION"}))
                                         if (seed_index + i) % 2 == 0}
    extras = sorted(TRUST - REQUIRED_TRUST)
    state_trust = REQUIRED_TRUST | {t for i, t in enumerate(extras) if (seed_index + i) % 3 == 0}
    row_trust = REQUIRED_TRUST | {t for i, t in enumerate(extras) if (seed_index + i) % 3 == 1}
    expected["required_guarantees"] = sorted(required)
    expected["allowed_trust_assumptions"] = sorted(state_trust | row_trust)
    report["state_trust"] = sorted(state_trust)
    numbers = (0, 1, (1 << 53) - 1, (1 << 53) + 1, I64_MAX, 1 << 63, U64_MAX)
    for index, (ref, row) in enumerate(zip(expected["targets"], report["results"])):
        # Segment positions deliberately share an index while their block
        # indices differ. Spacing by two makes the XOR-one mutations distinct.
        ref["index"] = (U64_MAX - 2 * index if seed_index % 2 else 2 * index) if command == "verify-commitment" else numbers[seed_index % len(numbers)]
        ref["account_header"] = {"address": digest("address-%d" % index)[:40],
                                 "height": numbers[(seed_index + index) % len(numbers)],
                                 "hash": digest("account-%d" % index)}
        ref["momentum_height" if command == "verify-commitment" else "block_index"] = (
            numbers[(seed_index + index + 1) % len(numbers)] if command == "verify-commitment" else
            I64_MAX - 2 * index if seed_index % 2 else 2 * index)
        row["reference"] = copy.deepcopy(ref)
        row["failed_at"] = ref.get("block_index", -1)
        proven = required | ({"PRODUCER_AUTHORIZATION"} if index % 2 else set())
        row["proven"], row["not_proven"] = sorted(proven), sorted(ALL_GUARANTEES - proven)
        row["trust_assumptions"] = sorted(row_trust)
    expected["targets"].sort(key=lambda ref: digest("expected-order-%d" % ref["account_header"]["height"]) + ref["account_header"]["hash"])
    report["results"].sort(key=lambda row: digest("report-order-" + row["reference"]["account_header"]["hash"]))
    report["caveats"] = ["synthetic", '\\[]{}:,"', "\ufffd\U0001f680", "x" * (seed_index + 1)]
    return report, expected


def wire_equivalent(value):
    """Change key order, whitespace, escaped keys and Unicode spelling only."""
    def reverse_keys(item):
        if type(item) is dict:
            return {key: reverse_keys(child) for key, child in reversed(list(item.items()))}
        if type(item) is list:
            return [reverse_keys(child) for child in item]
        return item

    raw = json.dumps(reverse_keys(value), ensure_ascii=False, indent=2).encode("utf-8")
    return re.sub(rb'"([a-z_])([^"\n]*)":',
                  lambda match: b'"\\u%04x' % match[1][0] + match[2] + b'":', raw)


def generated_cases():
    """Finite seeded programs with declarative decisions, never oracle votes."""
    corpus = []
    for command in ("verify-commitment", "verify-segment"):
        for version in (1, 2):
            for seed_index, seed in enumerate(GENERATED_SEEDS):
                report, expected = generated_inputs(command, version, seed_index)
                prefix = "generated_%s_v%d_seed%08x_" % (command.removeprefix("verify-"), version, seed)
                for variant in GENERATED_VARIANTS:
                    r, e = copy.deepcopy(report), copy.deepcopy(expected)
                    category, status = None, 0
                    # The last selected row ensures mutations are not confined
                    # to the first target of a batch.
                    row = r["results"][-1]
                    ref, context = row["reference"], r["verification_context"]
                    if variant == "wire_equivalent":
                        r, e = wire_equivalent(r), wire_equivalent(e)
                    elif variant in ("account_address", "account_hash"):
                        key = variant.removeprefix("account_")
                        ref["account_header"][key] = ("0" if ref["account_header"][key][0] != "0" else "1") + ref["account_header"][key][1:]
                        category = "target_mismatch"
                    elif variant == "account_height":
                        ref["account_header"]["height"] ^= 1
                        category = "target_mismatch"
                    elif variant in ("reference_index", "reference_position"):
                        key = "index" if variant == "reference_index" else "momentum_height" if command == "verify-commitment" else "block_index"
                        ref[key] ^= 1
                        category = "target_mismatch"
                    elif variant == "target_count":
                        if len(r["results"]) > 1:
                            r["results"].pop()
                        else:
                            extra = copy.deepcopy(row)
                            extra["reference"]["index"] ^= 1
                            r["results"].append(extra)
                        category = "target_mismatch"
                    elif variant == "duplicate_report_position":
                        r["results"].append(copy.deepcopy(row))
                        category = "invalid_report"
                    elif variant == "duplicate_expected_position":
                        e["targets"].append(copy.deepcopy(e["targets"][-1]))
                        category = "invalid_expectations"
                    elif variant == "tip":
                        r["verification_tip"]["height"] = 2 if r["verification_tip"]["height"] == 1 else 1
                        category = "report_mismatch"
                    elif variant == "context_unpinned":
                        context["anchor"]["chain_id"] ^= 1
                        context["fingerprint"] = context_fingerprint(context)
                        category = "report_mismatch"
                    elif variant == "context_tampered":
                        context["policy"][LIMITS[seed_index % len(LIMITS)]] ^= 1
                        category = "invalid_report"
                    elif variant == "required_guarantee":
                        row["proven"].remove("CONTENT_INCLUSION")
                        row["not_proven"].append("CONTENT_INCLUSION")
                        category = "guarantee_mismatch"
                    elif variant == "row_trust":
                        row["trust_assumptions"].remove("TRUST_CONFIGURED_ANCHOR")
                        category = "trust_mismatch"
                    elif variant == "state_trust":
                        r["state_trust"].remove("TRUST_PERSISTED_STATE")
                        category = "trust_mismatch"
                    elif variant == "integer_range":
                        ref["account_header"]["height"] = -1 if seed_index % 2 else U64_MAX + 1
                        category = "invalid_report"
                    elif variant in ("escaped_duplicate_report", "escaped_duplicate_expected"):
                        raw = encoded(r if variant == "escaped_duplicate_report" else e)
                        raw = raw.replace(b'"schema_version":1', b'"schema_version":1,"schema_vers\\u0069on":1', 1)
                        if variant == "escaped_duplicate_report":
                            r, category = raw, "invalid_report"
                        else:
                            e, category = raw, "invalid_expectations"
                    elif variant == "process_failure":
                        r, e = b"not JSON", b"not JSON"
                        status = (2, -9, 3221225477, -(1 << 63), I64_MAX)[seed_index % 5]
                        category = "process_failure"
                    elif variant != "valid":
                        raise Invalid("unknown generated variant")
                    corpus.append({"id": prefix + variant, "report": r if type(r) is bytes else encoded(r),
                                   "expectations": e if type(e) is bytes else encoded(e), "process_exit": status,
                                   "wanted": summary(category, 0 if category else len(expected["targets"]), 2 if category else 0)})
    return corpus


def cases():
    return pinned_cases() + generated_cases()


class ComparisonFailure(Invalid):
    """Keep fixed case identifiers, counters and hashes; omit private bytes."""

    def __init__(self, case_id, stage, counts, outcomes=()):
        self.details = {"schema_version": 1, "status": "comparison_failed", "case_id": case_id,
                        "stage": stage, "comparison_counts": dict(counts),
                        "process_outcomes": copy.deepcopy(list(outcomes)), "cleanup_failures": []}
        super().__init__("synthetic consumer comparison failed")


class ComparisonRunner:
    def __init__(self, consumer, selected, available):
        self.consumer = consumer
        self.counts = {"selected": selected, "reference_checked": 0, "consumer_attempted": 0,
                       "consumer_compared": 0, "skipped": 0, "not_selected": available - selected}
        self.rows, self.process_outcomes = [], []

    def require(self, case_id, stage, condition):
        if not condition:
            raise ComparisonFailure(case_id, stage, self.counts, self.process_outcomes)

    @contextlib.contextmanager
    def boundary(self, case_id):
        try:
            yield
        except ComparisonFailure:
            raise
        except (OSError, ValueError, KeyError, TypeError, RecursionError):
            raise ComparisonFailure(case_id, "input_or_shape", self.counts, self.process_outcomes) from None

    @contextlib.contextmanager
    def directory(self):
        with self.boundary("setup"):
            temporary = tempfile.TemporaryDirectory(prefix="consumer-conformance-")
        failure, interrupted = None, False
        try:
            with self.boundary("complete"):
                yield Path(temporary.name)
        except ComparisonFailure as error:
            failure = error
            raise
        except BaseException:
            interrupted = True
            raise
        finally:
            try:
                temporary.cleanup()
            except (OSError, ValueError, KeyError, TypeError, RecursionError):
                if failure is not None:
                    failure.details["cleanup_failures"].append("temporary_cleanup")
                elif not interrupted:
                    raise ComparisonFailure("complete", "temporary_cleanup", self.counts, self.process_outcomes) from None

    def child(self, case_id, arguments):
        self.counts["consumer_attempted"] += 1
        try:
            result = subprocess.run([str(self.consumer), *arguments], capture_output=True, timeout=10, check=False)
        except (OSError, subprocess.SubprocessError):
            self.process_outcomes.append({"case_id": case_id, "role": "consumer", "completed": False, "actual_exit": None})
            raise ComparisonFailure(case_id, "child_run", self.counts, self.process_outcomes) from None
        self.counts["consumer_compared"] += 1
        # Preserve real completion before a mismatch, input reread or cleanup can fail.
        self.process_outcomes.append({"case_id": case_id, "role": "consumer", "completed": True,
                                      "actual_exit": result.returncode,
                                      "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(),
                                      "stderr_sha256": hashlib.sha256(result.stderr).hexdigest(),
                                      "stdout_bytes": len(result.stdout), "stderr_bytes": len(result.stderr)})
        return result

    def compare_case(self, case, paths):
        with self.boundary(case["id"]):
            wanted = case["wanted"]
            self.counts["reference_checked"] += 1
            self.require(case["id"], "reference_decision", consume(case["report"], case["expectations"], case["process_exit"]) == wanted)
            for path, key in zip(paths, ("report", "expectations")):
                path.write_bytes(case[key])
                path.chmod(0o600)
            completed = self.child(case["id"], ["--report", str(paths[0]), "--expectations", str(paths[1]),
                                                "--verifier-exit-code", str(case["process_exit"])])
            self.require(case["id"], "compiled_decision", (completed.returncode, completed.stdout) == wanted and not completed.stderr)
            self.require(case["id"], "input_changed", all(path.read_bytes() == case[key] for path, key in zip(paths, ("report", "expectations"))))
            self.rows.append({"id": case["id"], "exit_code": wanted[0],
                              "report_sha256": hashlib.sha256(case["report"]).hexdigest(),
                              "expectations_sha256": hashlib.sha256(case["expectations"]).hexdigest(),
                              "process_exit": case["process_exit"], "summary_sha256": hashlib.sha256(wanted[1]).hexdigest()})


def compare(consumer, source_revision, case_id=None):
    available = cases()
    corpus = available if case_id is None else [case for case in available if case["id"] == case_id]
    if not corpus or len({case["id"] for case in available}) != len(available):
        raise Invalid("case selection")
    executable = consumer.read_bytes()
    executable_digest = hashlib.sha256(executable).hexdigest()
    runner = ComparisonRunner(consumer, len(corpus), len(available))
    with runner.boundary("complete"):
        return compare_selected(runner, corpus, executable, executable_digest, source_revision, case_id)


def compare_selected(runner, corpus, executable, executable_digest, source_revision, case_id):
    with runner.directory() as directory:
        directory.chmod(0o700)
        paths = [directory / "report.json", directory / "expectations.json"]
        for case in corpus:
            runner.compare_case(case, paths)
    runner.require("complete", "executable_changed", hashlib.sha256(runner.consumer.read_bytes()).hexdigest() == executable_digest)
    counts = runner.counts
    runner.require("complete", "comparison_coverage", counts["reference_checked"] == counts["consumer_attempted"] ==
                   counts["consumer_compared"] == counts["selected"] == len(runner.rows) == len(runner.process_outcomes) and
                   counts["skipped"] == 0 and all(row["completed"] for row in runner.process_outcomes))
    return {"schema_version": 1, "source_revision": source_revision,
            "source_revision_is_caller_asserted": True,
            "consumer_sha256": executable_digest, "consumer_bytes": len(executable),
            "consumer_bytes_unchanged": True,
            "oracle_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), "cases": runner.rows,
            "case_selection": case_id, "comparison_counts": counts, "process_outcomes": runner.process_outcomes,
            "available_pinned_cases": len(pinned_cases()),
            "generated_corpus": {"version": 1, "identity_derivation": "sha256-v1", "seeds": list(GENERATED_SEEDS),
                                 "programs": 4 * len(GENERATED_SEEDS), "cases_per_program": len(GENERATED_VARIANTS),
                                 "available_cases": 4 * len(GENERATED_SEEDS) * len(GENERATED_VARIANTS)},
            "matched": sum(case["wanted"][0] == 0 for case in corpus),
            "refused": sum(case["wanted"][0] != 0 for case in corpus),
            "input_bytes_unchanged": True, "stderr_empty": True,
            "external_rpc_calls": 0, "verifier_state_loaded": False,
            "independent_human_review": False, "network_pilot": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--consumer", required=True, type=Path)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--case", help="Replay one named synthetic case; otherwise compare the complete corpus")
    args = parser.parse_args()
    if re.fullmatch(r"[0-9a-f]{40}", args.source_revision) is None:
        parser.error("source revision must be a full lowercase commit identifier")
    try:
        result = compare(args.consumer.resolve(strict=True), args.source_revision, args.case)
    except ComparisonFailure as failure:
        parser.exit(1, json.dumps(failure.details, sort_keys=True, separators=(",", ":")) + "\n")
    except (OSError, subprocess.SubprocessError, Invalid):
        raise SystemExit("Independent consumer comparison failed; private inputs and diagnostics omitted")
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    os.umask(0o077)
    main()
