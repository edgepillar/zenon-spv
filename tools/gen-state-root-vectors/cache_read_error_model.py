#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Check finite cache-component records; never execute a backend or accept state."""
import argparse
import hashlib
import json
import os
import stat
import sys
from pathlib import Path
import re

FIXTURE_SHA256 = "96513b59a64bbd8b734238fc6c768fe49fd72dcb1437096a220346cc0a6371cc"
MAX_STREAM = 131072
MODES = ("initialize-extract-query-close", "reopen-query-close")

def require(ok):
    if not ok:
        raise ValueError("Cache read error evidence refused")

def pairs(values):
    result = {}
    for key, value in values:
        require(key not in result)
        result[key] = value
    return result

def constant(_):
    raise ValueError("Non-finite number refused")

def exact(actual, expected):
    require(type(actual) is type(expected))
    if type(expected) is dict:
        require(set(actual) == set(expected))
        for key in expected:
            exact(actual[key], expected[key])
    elif type(expected) is list:
        require(len(actual) == len(expected))
        for a, b in zip(actual, expected):
            exact(a, b)
    else:
        require(actual == expected)

def vint(value):
    result = bytearray()
    while value >= 128:
        result.append((value & 127) | 128)
        value >>= 7
    result.append(value)
    return bytes(result)

def put(key, value):
    return b"\x01" + vint(len(key)) + key + vint(len(value)) + value

def delete(key):
    return b"\x00" + vint(len(key)) + key

def expected_fixture():
    alphabet = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    text = "z1qxemdeddedxplasmaxxxxxxxxxxxxxxxxsctrp"
    accumulator = bits = 0
    address = bytearray()
    for character in text.split("1", 1)[1][:-6]:
        accumulator = (accumulator << 5) | alphabet.index(character)
        bits += 5
        while bits >= 8:
            bits -= 8
            address.append((accumulator >> bits) & 255)
    require(len(address) == 20 and bits == 0)
    subject, absent = bytes.fromhex("00" + "11" * 19), bytes.fromhex("00" + "22" * 19)
    height = (2).to_bytes(8, "big")
    plasma_key = b"\x03" + subject + b"\x05"
    fused_key = b"\x03" + bytes(address) + b"\x04\x02" + subject
    cached_fused, cached_plasma = b"\x03\x00" + subject + height, b"\x03\x01" + subject + height
    plasma_value, fused_value = (17).to_bytes(32, "big"), (35).to_bytes(32, "big")
    return {"schema": "cache-read-errors-component-fixture-v1",
        "original_revision": "9c71ae82fc983e16f914ae085d4034030c8ebe3b",
        "parent_runtime_tree": "69b0844bccc68273b2b367cda7706d933d45358f",
        "subject": subject.hex(), "absent": absent.hex(), "plasma_contract": address.hex(),
        "momentum_hash": "44" * 32, "momentum_height": 2, "unconfigured_spork_id": "33" * 32,
        "plasma_input_key": plasma_key.hex(), "fused_input_key": fused_key.hex(),
        "plasma_input_value": plasma_value.hex(), "fused_input_value": fused_value.hex(),
        "input_patch_dump": (put(plasma_key, plasma_value) + put(fused_key, fused_value)).hex(),
        "cache_patch_dump": (put(cached_fused, fused_value) + put(cached_plasma, plasma_value)).hex(),
        "consumer_result": "REFUSED", "state_value_accepted": False}

def selected_fixture(raw):
    require(type(raw) is bytes and 0 < len(raw) <= 16384)
    require(hashlib.sha256(raw).hexdigest() == FIXTURE_SHA256)
    result = json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    exact(result, expected_fixture())
    return result

def expected_image(fixture):
    subject, height = bytes.fromhex(fixture["subject"]), (2).to_bytes(8, "big")
    fused, plasma = b"\x03\x00" + subject + height, b"\x03\x01" + subject + height
    frontier = b"\x0a\x22\x0a\x20" + bytes.fromhex(fixture["momentum_hash"]) + b"\x10\x02"
    rollback = delete(fused) + delete(plasma) + delete(b"\x00")
    rows = sorted([(b"\x55\x00", b"\x00" + frontier),
        (b"\x55" + fused, b"\x00" + bytes.fromhex(fixture["fused_input_value"])),
        (b"\x55" + plasma, b"\x00" + bytes.fromhex(fixture["plasma_input_value"])),
        (b"\x77" + height, rollback)])
    raw = b"".join(len(key).to_bytes(8, "big") + key + len(value).to_bytes(8, "big") + value
                   for key, value in rows)
    return {"rows": [{"key": key.hex(), "value": value.hex()} for key, value in rows],
            "records": 4, "sha256": hashlib.sha256(raw).hexdigest()}

def query(checkpoint, method, selection, variant):
    integer, boolean, error = None, None, "none"
    if method == "spork":
        boolean = False
    else:
        integer = str(17 if method == "plasma" else 35)
        if checkpoint == "empty" or selection == "absent" or checkpoint == "closed":
            integer = "0"
    if checkpoint == "closed" and variant == "candidate":
        error = "leveldb-closed"
        if method != "spork":
            integer = None
    return {"checkpoint": checkpoint, "method": method, "selection": selection,
            "integer": integer, "boolean": boolean, "error": error}

def expected_events(fixture, mode, variant):
    require(mode in MODES and variant in ("baseline", "candidate"))
    result = []
    def emit(stage, values):
        result.append(dict(values, stage=stage, case=mode))
    emit("selection", {"fixture_sha256": FIXTURE_SHA256, "cache_manager_selected": True,
        "account_patch_extractor_selected": True, "public_Chain_selected": False,
        "ledger_or_state_tree_selected": False, "full_node_or_consensus_executed": False,
        "wallet_signing_or_network": False, "consumer_result": "REFUSED"})
    if mode == MODES[0]:
        for method in ("plasma", "stake", "spork"):
            emit("query", query("empty", method, "subject", variant))
        emit("extracted", {"input_patch_dump": fixture["input_patch_dump"],
            "cache_patch_dump": fixture["cache_patch_dump"], "nonempty_account_block_rows": 1,
            "nominal_momentum_hash": fixture["momentum_hash"], "nominal_momentum_height": 2,
            "network_valid_momentum_or_account_execution": False})
    else:
        emit("closed-store-before-reopen", expected_image(fixture))
    for method, selection in (("plasma", "subject"), ("stake", "subject"), ("spork", "subject"),
                              ("plasma", "absent"), ("stake", "absent")):
        emit("query", query("populated", method, selection, variant))
    emit("manager-stopped", {"first_stop": "none", "second_stop": "none",
                            "manager_DB_nil": True, "borrowed_views_retained": True})
    emit("closed-iterator", {"last": False, "error": "leveldb-closed", "released": True})
    for method in ("plasma", "stake", "spork"):
        emit("query", query("closed", method, "subject", variant))
    emit("closed-store", expected_image(fixture))
    return result

def stream(raw):
    require(type(raw) is bytes and 0 < len(raw) <= MAX_STREAM and raw.endswith(b"\n"))
    lines = raw.splitlines()
    require(0 < len(lines) <= 32 and all(0 < len(line) <= 16384 for line in lines))
    return [json.loads(line, object_pairs_hook=pairs, parse_constant=constant) for line in lines]

def check(first_raw, reopen_raw, fixture_raw, variant):
    fixture = selected_fixture(fixture_raw)
    require(type(variant) is str and variant in ("baseline", "candidate"))
    first, reopen = stream(first_raw), stream(reopen_raw)
    exact(first, expected_events(fixture, MODES[0], variant))
    exact(reopen, expected_events(fixture, MODES[1], variant))
    queries = [event for event in first + reopen if event["stage"] == "query"]
    require(len(first) == 16 and len(reopen) == 13 and len(queries) == 19)
    closed = [event for event in queries if event["checkpoint"] == "closed"]
    require(len(closed) == 6)
    mismatches = sum(event["error"] != "leveldb-closed" for event in closed)
    require(mismatches == (6 if variant == "baseline" else 0))
    return {"kind": "recorded-cache-read-error-comparison", "variant": variant,
        "event_count": 29, "query_count": 19, "healthy_or_empty_queries": 13,
        "closed_view_queries": 6, "direct_iterator_error_observations": 2,
        "observed_error_propagation_mismatches": mismatches,
        "complete_raw_rows_bound": 4, "closed_raw_images_unchanged": True,
        "backend_executed": False, "private_capture_authenticated": False,
        "public_Chain_or_full_node_qualified": False, "cache_values_authenticated": False,
        "state_value_accepted": False, "consumer_result": "REFUSED"}

def read_bounded(path, limit):
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and not path.is_symlink() and 0 <= before.st_size <= limit)
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    try:
        opened = os.fstat(descriptor)
        require(stat.S_ISREG(opened.st_mode) and (opened.st_dev, opened.st_ino) == (before.st_dev, before.st_ino))
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            raw = stream.read(limit + 1)
        require(len(raw) == before.st_size and len(raw) <= limit)
        return raw
    finally:
        os.close(descriptor)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--first", type=Path, required=True)
    parser.add_argument("--reopen", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--variant", choices=("baseline", "candidate"), required=True)
    args = parser.parse_args()
    result = check(read_bounded(args.first, MAX_STREAM), read_bounded(args.reopen, MAX_STREAM),
                   read_bounded(args.fixture, 16384), args.variant)
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))

if __name__ == "__main__":
    try:
        main()
    except (ValueError, TypeError, KeyError, OSError):
        print("Recorded cache read error evidence refused; state values remain disabled.", file=sys.stderr)
        raise SystemExit(1)
