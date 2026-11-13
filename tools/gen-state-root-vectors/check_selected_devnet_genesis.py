#!/usr/bin/env python3
"""Replay selected source-genesis H1 recordings with independent SHA3 bytes.

This reader does not execute the genesis VM or managers, observe a network,
authenticate a trust input, or select an accepting SPV profile.
"""

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import sys


ROOT = Path(__file__).resolve().parents[2]
CORPUS = ROOT / "internal/testdata/conformance/selected-devnet-genesis.json"
REFERENCE_GAS_CORPUS = ROOT / "internal/testdata/conformance/reference-gas-devnet-genesis.json"
CONFIG_PATH = "internal/testdata/conformance/selected-devnet-genesis-config.json"
HARNESS_PATH = "tools/gen-state-root-vectors/selected-devnet-genesis-lifecycle_test.go.txt"
GENESIS_HASH = "fab7609bae7fd78eb7d2b0d4a5023832f1a6730921b862f2415da25524698dc9"
CONFIG_SHA256 = "0dd33b18b147f70b3d3d5f07199a2b45311f6e9b84a98b3f86d8f6c6b45f419a"
SOURCE = {
    "repository": "https://github.com/digitalSloth/go-zenon",
    "revision": "938fca3b7787da86827a5eb63371509b36e14761",
    "tree": "f3b7947d2267ebdb806f18ff0c02bba5bffae9c4",
    "archive_sha256": "8ca1512eff8c04ee8b6ed0ff9a5da9e3eeba518660b07833f99a6b74e1dcc3a3",
}
CONFIG = {
    "path": CONFIG_PATH, "source_path": "docker/devnet/genesis.json",
    "bytes": 8137, "sha256": CONFIG_SHA256,
    "git_blob": "0f158f4414d165075c85a5ba3bde48a9eff792e4",
}
HARNESS = {
    "path": HARNESS_PATH, "bytes": 4458,
    "sha256": "1f2eb54d60b777ed73e6cebd1d1bcdff28a8a7536aa0f1617bad7fb36a3ee542",
}
EXECUTION = {
    "native_test": "TestSPVSelectedDevnetGenesisLifecycle", "go": "go1.25.14",
    "platform": "darwin/arm64", "cgo_enabled": True,
    "actual_exit": 0, "output_complete": True,
    "record_sha256": "38b3b33c74ea7226febf9d5759726c923ab449363a4530f0c3f013a5da454b9f",
    "gate_sha256": "923313f8091162021e390ffbabb2410e551ec3f52b7fbf5c3fd9d082ec2937c5",
    "output_sha256": "5bdc702a455942718b82297e2bfa56d6b76523bb0ae32bdbd104d3a173d26a5e",
    "output_bytes": 23745, "used_modules_verified": 25,
    "full_module_graph_go_mod_verify": "NOT_ESTABLISHED",
    "native_execution_repeated_for_publication": False,
}
REFERENCE_GAS_SOURCE = {
    "repository": "https://github.com/digitalSloth/go-zenon",
    "revision": "2835c436b197fece5c76adf4ba8dc1decca2e3ea",
    "tree": "f89d645c7f5be85dfe10dc7a510d80df7965d22f",
    "archive_sha256": "76d974ab3588518dddf9ea5eb4032b43228f9a732d14006330477037a905884a",
}
REFERENCE_GAS_EXECUTION = {
    "native_test": "TestSPVSelectedDevnetGenesisLifecycle", "go": "go1.25.14",
    "platform": "darwin/arm64", "cgo_enabled": True,
    "actual_exit": 0, "output_complete": True,
    "record_sha256": "19d6164025ef9489f3d638f7f1fbe507793fb9ef5f71e5236a304a821478c7fa",
    "gate_sha256": "59550d5f45f770525aecbfd4b02d3399e5902e175f755a9aaef6dca12251a647",
    "output_sha256": "8f552843b9647cf43b405de5ca95d674e08fbe01c344d9a8d02b6128da88b6cc",
    "output_bytes": 23716,
    "used_modules_verified": 25,
    "full_module_graph_go_mod_verify": "NOT_ESTABLISHED",
    "native_execution_repeated_for_publication": False,
    "capture_controller_outcome": "FAILURE",
    "native_result_reconciled_without_rerun": True,
}
SCOPE = {
    "source_genesis_H1_only": True, "real_manager_Init_Stop_reopen_cycles": 2,
    "Chain_Start_called": False, "network_execution": False,
    "first_incoming_v3_captured": False, "network_identity_authenticated": False,
    "anchor_selected": False, "profile_agreed": False,
    "producer_schedule_authenticated": False, "accepted_SPV_header": False,
    "state_value_accepted": False, "consensus_finality": False,
    "production_qualified": False,
}
UINT_FIELDS = ("version", "chainIdentifier", "height", "timestamp",
               "nextFusionPrice", "nextWorkPrice")
HASH_FIELDS = ("hash", "previousHash", "dataHash", "contentHash", "changesHash", "stateRoot")


def require(condition):
    if not condition:
        raise ValueError("selected source-genesis evidence mismatch")


def exact(actual, expected):
    require(type(actual) is type(expected))
    if type(expected) is dict:
        require(actual.keys() == expected.keys())
        for key, value in expected.items():
            exact(actual[key], value)
    elif type(expected) is list:
        require(len(actual) == len(expected))
        for value, selected in zip(actual, expected):
            exact(value, selected)
    else:
        require(actual == expected)


def pairs(items):
    result = {}
    for key, value in items:
        require(key not in result)
        result[key] = value
    return result


def parse(raw, limit):
    require(type(raw) is bytes and 0 < len(raw) <= limit)
    return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                      parse_constant=lambda _: require(False))


def read_regular(path, limit):
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= limit)
        raw = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns))
        require(len(raw) == before.st_size)
        return raw


def selected_recording(cohort):
    if cohort == "original":
        return CORPUS, SOURCE, EXECUTION
    if cohort == "reference-gas":
        return REFERENCE_GAS_CORPUS, REFERENCE_GAS_SOURCE, REFERENCE_GAS_EXECUTION
    raise ValueError("unsupported source-genesis recording")


def check_corpus(value, config_raw, harness_raw, *, cohort="original"):
    _, source, execution = selected_recording(cohort)
    require(type(value) is dict and set(value) == {
        "format", "source", "genesis_config", "harness", "execution", "scope", "trace"})
    exact(value["format"], "zenon-recorded-selected-devnet-genesis/v1")
    for key, expected in (("source", source), ("genesis_config", CONFIG),
                          ("harness", HARNESS), ("execution", execution), ("scope", SCOPE)):
        exact(value[key], expected)
    require(type(config_raw) is bytes and len(config_raw) == CONFIG["bytes"] and
            hashlib.sha256(config_raw).hexdigest() == CONFIG_SHA256)
    require(type(harness_raw) is bytes and len(harness_raw) == HARNESS["bytes"] and
            hashlib.sha256(harness_raw).hexdigest() == HARNESS["sha256"])
    config = parse(config_raw, 16 << 10)
    exact(config["ChainIdentifier"], 69)
    exact(config["GenesisTimestampSec"], 1739923200)

    trace = value["trace"]
    require(type(trace) is dict and set(trace) == {
        "format", "scope", "source_genesis_sha256", "sporks", "cycles",
        "Chain_Start_called", "first_incoming_v3_executed", "header"})
    exact(trace["format"], "selected-node-source-genesis-lifecycle/v1")
    exact(trace["scope"], "LOCAL_GENESIS_H1_RESTART_NOT_NETWORK_IDENTITY")
    exact(trace["source_genesis_sha256"], CONFIG_SHA256)
    exact(trace["Chain_Start_called"], False)
    exact(trace["first_incoming_v3_executed"], False)
    exact(trace["cycles"], [{"cycle": cycle, "height": 1, "version": 1, "hash": GENESIS_HASH}
                            for cycle in (1, 2)])
    expected_sporks = []
    for index, name in ((2, "dynamic-plasma"), (3, "merkle-state-root"), (4, "offchain-execution")):
        selected = {"id": f"{index:064x}", "name": name, "activated": True, "enforcement_height": 0}
        matches = [row for row in config["SporkConfig"]["Sporks"] if row["id"] == selected["id"]]
        require(len(matches) == 1)
        for key in ("id", "name", "activated"):
            exact(matches[0][key], selected[key])
        exact(matches[0]["enforcementHeight"], 0)
        expected_sporks.append(selected)
    exact(trace["sporks"], expected_sporks)

    header = trace["header"]
    require(type(header) is dict and set(header) == set(UINT_FIELDS + HASH_FIELDS + ("publicKey", "signature")))
    for field in UINT_FIELDS:
        require(type(header[field]) is int and 0 <= header[field] < 2**64)
    for field in HASH_FIELDS:
        require(type(header[field]) is str and re.fullmatch("[0-9a-f]{64}", header[field]) is not None)
    exact([header[k] for k in ("version", "chainIdentifier", "height", "timestamp")],
          [1, config["ChainIdentifier"], 1, config["GenesisTimestampSec"]])
    exact([header[k] for k in ("previousHash", "stateRoot", "publicKey", "signature",
                              "nextFusionPrice", "nextWorkPrice")], ["00" * 32, "00" * 32, None, None, 0, 0])
    exact(header["dataHash"], hashlib.sha3_256(config["ExtraData"].encode("utf-8")).hexdigest())
    # The v1 frame excludes both prices and StateRoot. ContentHash and
    # ChangesHash are recorded node outputs; this reader does not rebuild them.
    preimage = b"".join(struct.pack(">Q", header[field]) if field in UINT_FIELDS
                        else bytes.fromhex(header[field]) for field in (
                            "version", "chainIdentifier", "previousHash", "height", "timestamp",
                            "dataHash", "contentHash", "changesHash"))
    require(len(preimage) == 160)
    exact(hashlib.sha3_256(preimage).hexdigest(), GENESIS_HASH)
    exact(header["hash"], GENESIS_HASH)
    report = {"format": "zenon-selected-devnet-genesis-byte-check/v1", "chain_id": 69,
            "height": 1, "version": 1, "genesis_hash": GENESIS_HASH,
            "preimage_bytes": len(preimage), "preimage_sha256": hashlib.sha256(preimage).hexdigest(),
            "recorded_manager_cycles": 2, "genesis_VM_or_managers_executed_by_reader": False,
            "network_identity_authenticated": False, "first_incoming_v3_captured": False,
            "anchor_or_accepting_profile_selected": False, "state_value_accepted": False}
    if cohort == "reference-gas":
        report.update(format="zenon-reference-gas-devnet-genesis-byte-check/v1",
                      node_revision=source["revision"])
    return report


def check(cohort="original"):
    corpus, _, _ = selected_recording(cohort)
    raw = read_regular(corpus, 16 << 10)
    report = check_corpus(parse(raw, 16 << 10), read_regular(ROOT / CONFIG_PATH, 16 << 10),
                          read_regular(ROOT / HARNESS_PATH, 8 << 10), cohort=cohort)
    report["corpus_sha256"] = hashlib.sha256(raw).hexdigest()
    return report


def main(argv):
    revision = None
    cohort = "original"
    options = {}
    if len(argv) > 4 or len(argv) % 2:
        print("selected-devnet-genesis: invalid command syntax", file=sys.stderr)
        return 64
    for key, value in zip(argv[::2], argv[1::2]):
        if key not in ("--source-revision", "--cohort") or key in options:
            print("selected-devnet-genesis: invalid command syntax", file=sys.stderr)
            return 64
        options[key] = value
    revision = options.get("--source-revision")
    cohort = options.get("--cohort", "original")
    if ((revision is not None and re.fullmatch("[0-9a-f]{40}", revision) is None)
            or cohort not in ("original", "reference-gas")):
        print("selected-devnet-genesis: invalid command syntax", file=sys.stderr)
        return 64
    try:
        report = check() if cohort == "original" else check(cohort)
        report["source_revision"] = revision
        print(json.dumps(report, sort_keys=True, allow_nan=False))
    except (ValueError, OSError, KeyError, TypeError, OverflowError, RecursionError):
        print("selected-devnet-genesis: evidence check failed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
