# SPDX-License-Identifier: GPL-3.0-only
"""Independent byte checks for the selected runner, not an accepting SPV API.

The ordinary native CLI must authenticate headers and produce its owned-state
result separately. Matching these calculations does not establish signatures,
canonicality, election authority, runtime execution or production acceptance.
"""
from __future__ import annotations

import base64
import hashlib
import re
import struct

import model
from model import require, same

H = lambda raw: hashlib.sha3_256(raw).digest()
CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
WIRE_FIELDS = frozenset(("version", "chainIdentifier", "hash", "previousHash", "height", "timestamp",
    "data", "content", "changesHash", "publicKey", "signature", "nextFusionPrice", "nextWorkPrice", "stateRoot", "producer"))
ENTRY_SCHEMA = (("ProtocolVersion", 16), ("FirstInputSeq", 64), ("LastInputSeq", 64),
    ("PreStateRoot", "hash"), ("PostStateRoot", "hash"), ("InputRoot", "hash"),
    ("ReceiptRoot", "hash"), ("EventRoot", "hash"), ("OutboxRoot", "hash"), ("DaHash", "hash"),
    ("DaMode", 8), ("ExecutorPillar", "text"), ("SubmittedAtHeight", 64), ("FinalizeAtHeight", 64),
    ("AssetFlowSummary", "bytes"), ("ProofData", "bytes"), ("State", 8))
RECORD_SCHEMA = (("DomainClass", 8), ("RuntimeKind", 8), ("StfSpecHash", "hash"),
    ("InputSource", 8), ("ExecProfile", 8), ("ForeignProfile", 8), ("ProfileConfig", "bytes"),
    ("ChainBinding", "bytes"), ("MinExecutors", 8), ("ProposerPolicy", 8), ("FinalityModel", 8), ("Status", 8))


def uint(value, bits=64):
    require(type(value) is int and 0 <= value < 1 << bits, "independent_unsigned_integer")
    return value


def word(value):
    return struct.pack(">Q", uint(value))


def hex_bytes(text, count):
    require(type(text) is str and len(text) == count * 2
            and re.fullmatch(r"[0-9a-f]*", text) is not None, "independent_hex_encoding")
    return bytes.fromhex(text)


def binary(text, maximum, *, nullable=False):
    if text is None and nullable:
        return b""
    require(type(text) is str and len(text) <= 4 * ((maximum + 2) // 3), "independent_base64_bound")
    try:
        raw = base64.b64decode(text, validate=True)
    except ValueError as error:
        raise model.Refused("independent_base64_encoding") from error
    require(len(raw) <= maximum and base64.b64encode(raw).decode("ascii") == text,
            "independent_base64_encoding")
    return raw


def address_text(raw):
    require(type(raw) is bytes and len(raw) == 20, "independent_address_width")
    value = int.from_bytes(raw, "big")
    data = [(value >> (5 * (31 - i))) & 31 for i in range(32)]
    checksum = 1
    for item in [ord("z") >> 5, 0, ord("z") & 31] + data + [0] * 6:
        top = checksum >> 25
        checksum = ((checksum & 0x1ffffff) << 5) ^ item
        for i, generator in enumerate((0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3)):
            if (top >> i) & 1:
                checksum ^= generator
    checksum ^= 1
    return "z1" + "".join(CHARSET[n] for n in data + [(checksum >> (5 * (5 - i))) & 31 for i in range(6)])


def address_bytes(text):
    require(type(text) is str and len(text) == 40 and text.startswith("z1")
            and all(c in CHARSET for c in text[2:]), "independent_address_encoding")
    value = 0
    for char in text[2:34]:
        value = (value << 5) | CHARSET.index(char)
    raw = value.to_bytes(20, "big")
    require(address_text(raw) == text, "independent_address_checksum")
    return raw


def header_facts(row):
    require(type(row) is dict and set(row) == WIRE_FIELDS, "independent_header_fields")
    version, height = uint(row["version"]), uint(row["height"])
    require(version in (1, 2, 3) and height > 0, "independent_header_version_or_height")
    previous, root = hex_bytes(row["previousHash"], 32), hex_bytes(row["stateRoot"], 32)
    require((root != bytes(32)) == (version == 3), "independent_header_root_version")
    content = row["content"]
    require(type(content) is list and len(content) <= 1024, "independent_header_content_bound")
    members = bytearray()
    for member in content:
        require(type(member) is dict and set(member) == {"address", "height", "hash"},
                "independent_header_content_fields")
        members += address_bytes(member["address"]) + word(member["height"]) + hex_bytes(member["hash"], 32)
    preimage = word(version) + word(row["chainIdentifier"]) + previous + word(height) + word(row["timestamp"])
    preimage += H(binary(row["data"], 16 << 10)) + H(members) + hex_bytes(row["changesHash"], 32)
    for name in ("nextFusionPrice", "nextWorkPrice"):
        uint(row[name])
    if version >= 2:
        preimage += word(row["nextFusionPrice"]) + word(row["nextWorkPrice"])
    if version == 3:
        preimage += root
    require(H(preimage) == hex_bytes(row["hash"], 32), "independent_header_hash")
    unsigned_genesis = version == 1 and height == 1
    public = binary(row["publicKey"], 32, nullable=unsigned_genesis)
    signature = binary(row["signature"], 64, nullable=unsigned_genesis)
    require((len(public), len(signature)) == (32, 64) or height == 1 and not public and not signature,
            "independent_header_key_width")
    producer = b"\0" + H(public)[:19] if public else None
    if producer is not None:
        require(address_bytes(row["producer"]) == producer, "independent_header_producer_encoding")
    return {"hash": row["hash"], "height": height, "version": version, "timestamp": row["timestamp"],
            "parent_hash": row["previousHash"], "root": row["stateRoot"],
            "producing_addr": producer.hex() if producer is not None else None,
            "signature_verified_by_this_calculation": False}


def schedule_hash(schedule):
    chain, coverage, entries = schedule["chain_id"], schedule["coverage"], schedule["entries"]
    require(type(coverage) is list and 0 < len(coverage) <= 512
            and type(entries) is list and 0 < len(entries) <= 512, "independent_schedule_bound")
    raw = word(chain) + word(len(coverage))
    expected_heights = []
    previous = 0
    for interval in coverage:
        start, end = uint(interval["from_height"]), uint(interval["through_height"])
        require(start > previous and start <= end and end - start < 512, "independent_schedule_coverage")
        expected_heights.extend(range(start, end + 1))
        require(len(expected_heights) <= 512, "independent_schedule_bound")
        raw += word(start) + word(end)
        previous = end
    require([row["height"] for row in entries] == expected_heights, "independent_schedule_density")
    raw += word(len(entries))
    for row in entries:
        raw += word(row["height"]) + word(row["timestamp_unix"]) + hex_bytes(row["producing_addr"], 20)
    return H(raw)


def fingerprints(config, request=None):
    selected, policy, schedule, p = (config[k] for k in
        ("header_profile", "header_policy", "producer_schedule", "query_profile"))
    s = schedule_hash(schedule)
    require(s.hex() == schedule["schedule_hash"]
            and schedule["chain_id"] == selected["genesis"]["chain_id"] == selected["anchor"]["chain_id"],
            "independent_schedule_or_chain_pin")
    header = b"ZENON-EXPERIMENTAL-V3-CONTEXT\0\1"
    for anchor in (selected["genesis"], selected["anchor"]):
        header += word(anchor["chain_id"]) + word(anchor["height"]) + hex_bytes(anchor["header_hash"], 32)
    header += b"".join(word(n) for n in (selected["version"], selected["first_v3_height"], selected["valid_through"],
        policy["w"], policy["retain_headers"], policy["max_batch_headers"], 8192, 8 << 20))
    header += hex_bytes(selected["node_revision"], 20) + s
    entry = p["entry"]
    version = uint(p["version"], 8)
    require(version in (1, 2) and entry["version"] == version, "independent_query_profile_version")
    require((version == 1 and "source_rule" not in entry) or
            (version == 2 and entry.get("source_rule") == "zenon-phase1-batch-fields/v1"),
            "independent_query_source_rule")
    schema = b"zenon-settlement-batch-entry-17/v1"
    legacy = b"ZENON-EXPERIMENTAL-BATCH-ENTRY\0" + bytes([version]) + word(version) + H(header)
    legacy += hex_bytes(selected["node_revision"], 20)
    legacy += hex_bytes(model.SOURCE_PINS["executor"][1], 20) + hex_bytes(model.SOURCE_PINS["contract_sdk"][1], 20)
    legacy += word(len(schema)) + schema + hex_bytes(entry["settlement"], 20)
    legacy += struct.pack(">I", uint(entry["domain_id"], 32)) + hex_bytes(entry["runtime_identity"], 32)
    abi = entry["limits"]
    legacy += b"".join(word(n) for n in (entry["max_proof_bytes"], entry["max_siblings"], 1,
        abi["max_value_bytes"], abi["max_executor_pillar_bytes"], abi["max_asset_flow_summary_bytes"],
        abi["max_proof_data_bytes"], abi["max_dynamic_bytes"], abi["string_rule"]))
    if version == 2:
        rule = entry["source_rule"].encode("ascii")
        legacy += word(len(rule)) + rule
    context = b"ZENON-EXPERIMENTAL-BATCH-CONTEXT\0" + bytes([version]) + H(legacy) + word(version)
    for text in ("zenon-settlement-domain-record-12/v1", "zenon-settlement-domain-config-2/v1", p["domain_rule"]):
        encoded = text.encode("ascii")
        context += word(len(encoded)) + encoded
    record, cfg, limits = p["domain_record"], p["domain_config"], p["limits"]
    context += b"".join(word(n) for n in (record["max_proof_bytes"], record["max_siblings"], record["max_value_bytes"],
        record["max_profile_config_bytes"], record["max_chain_binding_bytes"], record["max_dynamic_bytes"],
        cfg["max_proof_bytes"], cfg["max_siblings"], 64, limits["max_total_proof_bytes"],
        limits["max_total_value_bytes"], limits["max_total_siblings"], 1, 1))
    result = {"schedule_hash": s.hex(), "header_context": H(header).hex(),
              "entry_context": H(legacy).hex(), "context": H(context).hex()}
    if request is not None:
        require(request["context"] == result["context"], "independent_request_context")
        old_query = b"ZENON-EXPERIMENTAL-BATCH-ENTRY-QUERY\0\1" + H(legacy)
        old_query += word(request["height"]) + hex_bytes(request["header_hash"], 32)
        old_query += word(request["tip_height"]) + hex_bytes(request["tip_hash"], 32) + word(request["batch_id"])
        result["query"] = H(b"ZENON-EXPERIMENTAL-BATCH-CONTEXT-QUERY\0\1" + H(context) + H(old_query)).hex()
    return result


def ledger_keys(profile, batch):
    entry = profile["entry"]
    base = b"\x03" + hex_bytes(entry["settlement"], 20) + b"\x04"
    domain = struct.pack(">I", uint(entry["domain_id"], 32))
    return {"batch_entry": base + b"\x02" + domain + word(batch),
            "domain_record": base + b"\x01" + domain, "domain_config": base + b"\x15" + domain}


def membership(root, path, proof, value, max_proof, max_value, max_siblings):
    require(type(proof) is bytes and type(value) is bytes and 103 <= len(proof) <= max_proof
            and len(value) <= max_value and proof[0] == 1 and len(path) == len(root) == 32,
            "independent_membership_bounds_or_presence")
    require(proof[1:33] == path and proof[33:65] == H(path + value), "independent_membership_leaf")
    count = int.from_bytes(proof[97:99], "big")
    require(count <= max_siblings <= 256 and count == sum(bin(byte).count("1") for byte in proof[65:97]),
            "independent_membership_siblings")
    cursor = 99 + 32 * count
    require(len(proof) == cursor + 4 + len(value) and int.from_bytes(proof[cursor:cursor+4], "big") == len(value)
            and proof[cursor+4:] == value, "independent_membership_value_encoding")
    current, cursor = proof[33:65], 99
    for level in range(256):
        sibling = bytes(32)
        if proof[65 + level // 8] & (1 << (7 - level % 8)):
            sibling = proof[cursor:cursor+32]
            cursor += 32
            require(sibling != bytes(32), "independent_membership_noncanonical_zero")
        if current == sibling == bytes(32):
            continue
        current = H(sibling + current if path[31 - level // 8] & (1 << (level % 8)) else current + sibling)
    require(current == root, "independent_membership_root")
    return count


def decode_abi(raw, schema, dynamic_caps, max_value, max_dynamic):
    require(type(raw) is bytes and 32 * (len(schema) + len(dynamic_caps)) <= len(raw) <= max_value,
            "independent_ABI_size")
    result, cursor, total = {}, 32 * len(schema), 0
    for index, (name, kind) in enumerate(schema):
        encoded = raw[index*32:(index+1)*32]
        number = int.from_bytes(encoded, "big")
        if type(kind) is int:
            result[name] = uint(number, kind)
        elif kind == "hash":
            result[name] = encoded.hex()
        else:
            require(number == cursor and cursor + 32 <= len(raw), "independent_ABI_offset")
            size = uint(int.from_bytes(raw[cursor:cursor+32], "big"))
            total += size
            require(size <= dynamic_caps[name] and total <= max_dynamic, "independent_ABI_dynamic_bound")
            start, end = cursor + 32, cursor + 32 + size
            cursor = end + (-size % 32)
            require(cursor <= len(raw) and raw[end:cursor] == bytes(cursor - end), "independent_ABI_padding")
            result[name] = raw[start:end].decode("utf-8") if kind == "text" else raw[start:end]
    require(cursor == len(raw), "independent_ABI_trailing_bytes")
    return result


def decode_rows(profile, values):
    limits, record = profile["entry"]["limits"], profile["domain_record"]
    entry = decode_abi(values["batch_entry"], ENTRY_SCHEMA,
        {"ExecutorPillar": limits["max_executor_pillar_bytes"], "AssetFlowSummary": limits["max_asset_flow_summary_bytes"],
         "ProofData": limits["max_proof_data_bytes"]}, limits["max_value_bytes"], limits["max_dynamic_bytes"])
    domain = decode_abi(values["domain_record"], RECORD_SCHEMA,
        {"ProfileConfig": record["max_profile_config_bytes"], "ChainBinding": record["max_chain_binding_bytes"]},
        record["max_value_bytes"], record["max_dynamic_bytes"])
    config = values["domain_config"]
    require(len(config) == 64, "independent_domain_config_size")
    cfg = {"WithdrawalDelay": uint(int.from_bytes(config[:32], "big")),
           "RuntimeUpgradeDelay": uint(int.from_bytes(config[32:], "big"))}
    return {"entry": entry, "domain_record": domain, "domain_config": cfg}


def selected_semantics(descriptor, decoded):
    expected, record, config = descriptor["source_profile"], decoded["domain_record"], decoded["domain_config"]
    for name, value in expected.items():
        if name in ("withdrawal_delay", "runtime_upgrade_delay"):
            target = "WithdrawalDelay" if name == "withdrawal_delay" else "RuntimeUpgradeDelay"
            require(config[target] == value, "selected_domain_config_value")
        elif name.endswith("_hex"):
            target = "ProfileConfig" if name == "profile_config_hex" else "ChainBinding"
            require(record[target].hex() == value, "selected_domain_record_value")
        else:
            target = {"stf_spec_hash": "StfSpecHash"}.get(name, "".join(part.capitalize() for part in name.split("_")))
            require(record[target] == value, "selected_domain_record_value")
    require(record["Status"] == 0, "selected_domain_status")
    entry = decoded["entry"]
    require(not entry["ProofData"] and re.fullmatch(r"[A-Za-z0-9]+(?:[-._]?[A-Za-z0-9]+)*", entry["ExecutorPillar"])
            is not None and 0 < len(entry["ExecutorPillar"].encode()) <= 40, "selected_batch_source_rule")
    flow = entry["AssetFlowSummary"]
    require(len(flow) >= 4, "selected_batch_asset_flow")
    count = int.from_bytes(flow[:4], "big")
    require(count <= 16 and len(flow) == 4 + count * 96, "selected_batch_asset_flow")
    previous = None
    for offset in range(4, len(flow), 96):
        row = flow[offset:offset+96]
        require(row[:22] == bytes(22) and (previous is None or previous < row[:32])
                and row[32:] != bytes(64), "selected_batch_asset_flow")
        previous = row[:32]


def compare_decoded(actual, expected):
    require(type(actual) is dict and set(actual) == set(expected), "consumer_typed_fields")
    for name, value in expected.items():
        got = binary(actual[name], 4096, nullable=True) if type(value) is bytes else actual[name]
        require(type(got) is type(value) and got == value, "consumer_typed_value")


def witness_rows(profile, batch, header_root, witnesses):
    keys = ledger_keys(profile, batch)
    require(type(witnesses) is dict and set(witnesses) == set(keys), "independent_witness_set")
    root = hex_bytes(header_root, 32)
    require(root != bytes(32), "independent_header_root_missing")
    totals = {"proof": 0, "value": 0, "siblings": 0}
    values, members = {}, {}
    for name, key in keys.items():
        row = witnesses[name]
        require(type(row) is dict and set(row) == {"root", "value", "proof"}
                and row["root"] == header_root, "independent_witness_root_hint")
        limits = profile["entry"] if name == "batch_entry" else profile[name]
        max_value = limits["limits"]["max_value_bytes"] if name == "batch_entry" else limits.get("max_value_bytes", 64)
        value = binary(row["value"], max_value, nullable=True)
        proof = binary(row["proof"], limits["max_proof_bytes"])
        siblings = membership(root, H(key), proof, value, limits["max_proof_bytes"], max_value, limits["max_siblings"])
        for field, size in (("proof", len(proof)), ("value", len(value)), ("siblings", siblings)):
            totals[field] += size
            require(totals[field] <= profile["limits"]["max_total_" + (field + "_bytes" if field != "siblings" else field)],
                    "independent_witness_aggregate_bound")
        values[name] = value
        members[name] = {"ledger_key": key.hex(), "path": H(key).hex(), "value": value,
                        "value_sha3_256": H(value).hex(), "proof_sha3_256": H(proof).hex()}
    return {"decoded": decode_rows(profile, values), "memberships": members, "totals": totals}


def consumer_result(report, config, request, provider, header_root, descriptor=None):
    """Compare actual CLI output bytes; its successful receipt is checked outside."""
    pins = fingerprints(config, request)
    require(type(report) is dict and report.get("command") == "query-experimental-batch-context"
            and report.get("status") == "matched" and type(report.get("exit_code")) is int
            and report["exit_code"] == 0 and report.get("error") is None
            and report.get("production_state_value_guarantee") is False
            and report.get("persistence") == "read_only",
            "consumer_report_status_or_scope")
    same(report.get("schema_version"), 1, "consumer_schema_version")
    same(report.get("rpc_requests"), 0, "consumer_rpc_requests")
    scope = "EXPERIMENTAL_CONFIGURED_HEADER_THREE_ROW_MEMBERSHIP"
    require(report.get("scope") == scope and report.get("headers", {}).get("outcome") == "ACCEPT",
            "consumer_headers_not_accepted")
    require(report.get("header_context", {}).get("fingerprint") == pins["header_context"]
            and report.get("query_context", {}).get("fingerprint") == pins["context"],
            "consumer_context_pins")
    actual = report.get("result")
    require(type(actual) is dict and actual.get("scope") == scope
            and actual.get("query_fingerprint") == pins["query"] and actual.get("root") == header_root
            and actual.get("context", {}).get("fingerprint") == pins["context"], "consumer_result_binding")
    same(actual.get("request"), request, "consumer_request_identity")
    checked = witness_rows(config["query_profile"], request["batch_id"], header_root, provider["witnesses"])
    if descriptor is not None:
        selected_semantics(descriptor, checked["decoded"])
    for name, expected in checked["decoded"].items():
        compare_decoded(actual.get(name), expected)
    for row, name in (("batch_entry", "batch_membership"), ("domain_record", "record_membership"), ("domain_config", "config_membership")):
        compare_decoded(actual.get(name), checked["memberships"][row])
    gateway = provider.get("gateway")
    require(type(gateway) is dict and type(gateway.get("isFinalized")) is bool,
            "consumer_gateway_identity")
    same(gateway.get("domainId"), config["query_profile"]["entry"]["domain_id"], "consumer_gateway_identity")
    same(gateway.get("batchId"), request["batch_id"], "consumer_gateway_identity")
    gateway_match = True
    for name, expected in checked["decoded"]["entry"].items():
        field = name[0].lower() + name[1:]
        got = binary(gateway.get(field), 4096, nullable=True) if type(expected) is bytes else gateway.get(field)
        gateway_match = gateway_match and type(got) is type(expected) and got == expected
    comparison = report.get("gateway_comparison")
    require(type(comparison) is dict and comparison.get("stored_fields_match") is gateway_match
            and comparison.get("frontier_is_finalized_hint") is gateway["isFinalized"]
            and comparison.get("frontier_identity_authenticated") is False
            and report.get("gateway_comparison_requested") is True, "consumer_gateway_comparison")
    return {"format": "owned-devnet-independent-consumer-check/v1", "pins": pins,
        "three_membership_proofs_checked": 3, "typed_rows_checked": 3,
        "gateway_stored_fields_compared": 17, "gateway_stored_fields_match": gateway_match,
        "request": request, "root": header_root, "totals": checked["totals"],
        "selected_source_semantics_checked": descriptor is not None,
        "signature_verification_independently_reimplemented": False,
        "canonicality_finality_STF_or_funds_release_established": False,
        "production_qualified": False}
