#!/usr/bin/env python3
"""Replay a finite source-node parent-snapshot record without node execution.

Slot and proof-time arithmetic are independent Python checks. Producer ordering
is a digest-bound node output, not independently recomputed or authenticated.
"""

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys


ROOT = Path(__file__).resolve().parents[2]
CORPUS = ROOT / "internal/testdata/conformance/selected-parent-slots.json"
SOURCE = {
    "repository": "https://github.com/digitalSloth/go-zenon",
    "revision": "938fca3b7787da86827a5eb63371509b36e14761",
    "tree": "f3b7947d2267ebdb806f18ff0c02bba5bffae9c4",
    "archive_sha256": "8ca1512eff8c04ee8b6ed0ff9a5da9e3eeba518660b07833f99a6b74e1dcc3a3"
}
SOURCE_FILES = {
    "consensus/election.go": {
        "bytes": 7115,
        "git_blob": "ba530f44a8b1fbf4497f4ebff3b56fe4c15e91e0",
        "sha256": "a45497b3df349e4b0a9cc3d7680d8e88c148663df81fc8673f322605c7b3e017"
    },
    "consensus/consensus.go": {
        "bytes": 5249,
        "git_blob": "4ca364631a16b94b845fe997ee2ea1eb2a8edc96",
        "sha256": "bfc388fc8115d0b648015eef73dbe11d392ba647e5a0039671bfc15d0a61550b"
    },
    "consensus/context.go": {
        "bytes": 536,
        "git_blob": "5845e15286b603a0fdeebf789b6cd1cf68b15bf8",
        "sha256": "b38b279d160e6d38c25b7ef6c65b623e25ec131bc1bb8e5c0a034a71c5e49ebe"
    },
    "consensus/election_algorithm.go": {
        "bytes": 3449,
        "git_blob": "f4a3cc9a6dcc8ad0b13f52f069289b9bb2eaf9be",
        "sha256": "f4dc4b54b5806832559c6b209dd1824858c677b705c9d583e61d93a46a8ff95b"
    },
    "vm/constants/consensus.go": {
        "bytes": 581,
        "git_blob": "5b7bec0ff69e6596bab8c8161b9de9a72731836c",
        "sha256": "ac4089b8401b9a1ab8959202666448c9d5894c18885de9a96c6697b0dbb16c66"
    }
}
CONFIG = {
    "path": "internal/testdata/conformance/selected-devnet-genesis-config.json",
    "source_path": "docker/devnet/genesis.json",
    "bytes": 8137,
    "sha256": "0dd33b18b147f70b3d3d5f07199a2b45311f6e9b84a98b3f86d8f6c6b45f419a",
    "git_blob": "0f158f4414d165075c85a5ba3bde48a9eff792e4"
}
HELPERS = {
    "adapter": {
        "path": "tools/gen-state-root-vectors/parent-schedule-adapter.go.txt",
        "injected_path": "consensus/spv_parent_schedule_adapter.go",
        "bytes": 4062,
        "sha256": "7c2976c0feb437dd7689a01709e146559014b4e4f9aa93c1828f9cebc2388c79"
    },
    "harness": {
        "path": "tools/gen-state-root-vectors/parent-schedule-capture_test.go.txt",
        "injected_path": "consensus/spv_parent_schedule_capture_test.go",
        "bytes": 6329,
        "sha256": "53d1a65e87e0a5a74045f85078a242b3d5b827611f6ebe844671318e5815504c"
    }
}
EXECUTION = {
    "native_test": "TestSPVParentSnapshotProducerCapture",
    "go": "go1.25.14",
    "platform": "darwin/arm64",
    "cgo_enabled": True,
    "node_test_actual_exit": 0,
    "node_test_output_complete": True,
    "node_test_output": {
        "bytes": 14654,
        "sha256": "a584da4b0d248fdc0d6ccad631dd3be7b386a2af31df7134a7da05d7f30895de"
    },
    "readback_record": {
        "sha256": "4fd4ea84994b73031ee6cd3f485b116ba7229c937bc96126f78424cc610262d4",
        "bytes": 2901
    },
    "trace_object": {
        "sha256": "1a62a4f51d30f79fc962714f8b293743b6aadb988289ba405ce098841bb47f74",
        "bytes": 4274
    },
    "module_integrity_record": {
        "sha256": "164c86ea90851ca2ba4658b609e0abd1b448b75391e92422548861cddcef1432",
        "bytes": 19263
    },
    "used_modules_verified": 25,
    "passed_test_events": 11,
    "full_module_graph_go_mod_verify": "NOT_ESTABLISHED",
    "original_controller_outcome": "FAILURE",
    "original_controller_exit": 1,
    "cleanup_failed_after_completed_node_test": True,
    "native_execution_repeated_for_publication": False
}
SCOPE = {
    "source_H1_snapshot_only": True,
    "explicit_parent_and_timestamp_inputs": True,
    "original_consensus_parameters_unchanged": True,
    "original_node_implementation_files_unchanged": True,
    "independent_replay_recomputes_election_order": False,
    "network_execution": False,
    "network_height_assignment": False,
    "accepting_ProducerSchedule_created": False,
    "network_identity_or_activation_authenticated": False,
    "first_incoming_v3_captured": False,
    "authenticated_election_or_fork_choice": False,
    "accepted_SPV_header": False,
    "state_value_accepted": False,
    "consensus_finality": False,
    "production_qualified": False
}
GENESIS_HASH = "fab7609bae7fd78eb7d2b0d4a5023832f1a6730921b862f2415da25524698dc9"
REFUSALS = [
    "foreign-parent-hash", "foreign-parent-height", "before-genesis", "off-slot",
    "unordered", "duplicate", "too-many", "empty", "time-work-limit",
    "valid-prefix-invalid-tail",
]
NO_AUTHORITY = [
    "Chain_Start_called", "consensus_Start_called", "signing_selected",
    "network_execution", "network_height_assignment",
    "accepting_ProducerSchedule_created", "authenticated_election_or_fork_choice",
    "divergent_network_branches_executed", "network_activation_or_state_values_accepted",
]


def require(condition):
    if not condition:
        raise ValueError("source parent-slot evidence mismatch")


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


def uint(value):
    require(type(value) is int and 0 <= value < 2**64)
    return value


def check_trace(trace, config):
    require(type(trace) is dict and set(trace) == {
        "format", "scope", "source_genesis_sha256", "genesis", "genesis_timestamp",
        "parameters", "limits", "snapshot", "source_pillars", "refused_controls",
        "frontier_unchanged", "Stop_returned_nil", *NO_AUTHORITY,
    })
    exact(trace["format"], "selected-node-parent-snapshot-slots/v1")
    exact(trace["scope"], "SOURCE_H1_SLOT_LOOKUP_NOT_NETWORK_SCHEDULE")
    exact(trace["source_genesis_sha256"], CONFIG["sha256"])
    exact(trace["parameters"], {
        "block_time": 10, "node_count": 30, "rand_count": 15,
        "counting_zts": "zts1znnxxxxxxxxxxxxx9z4ulx",
    })
    exact(trace["limits"], {"query_count": 64, "max_genesis_delta_seconds": 315360000})
    exact(trace["frontier_unchanged"], True)
    exact(trace["Stop_returned_nil"], True)
    exact(trace["refused_controls"], REFUSALS)
    for field in NO_AUTHORITY:
        exact(trace[field], False)
    exact(config["ChainIdentifier"], 69)
    genesis_time = uint(config["GenesisTimestampSec"])
    exact(genesis_time, 1739923200)
    exact(trace["genesis_timestamp"], genesis_time)
    parent = {"hash": GENESIS_HASH, "height": 1}
    exact(trace["genesis"], parent)
    pillars = {row["Name"]: row["BlockProducingAddress"]
               for row in config["PillarConfig"]["Pillars"]}
    require(len(pillars) == len(config["PillarConfig"]["Pillars"]) == 3)
    exact(trace["source_pillars"], pillars)
    snapshot = trace["snapshot"]
    require(type(snapshot) is dict and set(snapshot) == {"parent", "rows"})
    exact(snapshot["parent"], parent)
    rows = snapshot["rows"]
    require(type(rows) is list and len(rows) == 6)
    timestamps = [genesis_time + delta for delta in (10, 20, 290, 300, 590, 600)]
    for row, timestamp in zip(rows, timestamps):
        require(type(row) is dict and set(row) == {
            "timestamp", "tick", "slot_start", "slot_end", "producer", "name",
            "proof_time", "proof_block", "proof_block_timestamp",
        })
        for field in ("timestamp", "tick", "slot_start", "slot_end", "proof_time",
                      "proof_block_timestamp"):
            uint(row[field])
        exact(row["timestamp"], timestamp)
        tick = (timestamp - genesis_time) // 300
        exact(row["tick"], tick)
        exact(row["slot_start"], timestamp)
        exact(row["slot_end"], timestamp + 10)
        proof_time = genesis_time + (1 if tick < 2 else (tick - 1) * 300)
        exact(row["proof_time"], proof_time)
        exact(row["proof_block"], parent)
        exact(row["proof_block_timestamp"], genesis_time)
        require(type(row["name"]) is str and row["name"] in pillars)
        exact(row["producer"], pillars[row["name"]])
    # This checks timing and context, not the node's election ordering.
    return rows


def check_corpus(value, config_raw, helper_raw):
    require(type(value) is dict and set(value) == {
        "format", "source", "source_files", "genesis_config", "helpers",
        "execution", "scope", "trace",
    })
    exact(value["format"], "zenon-recorded-source-parent-snapshot-slots/v1")
    for key, expected in (
            ("source", SOURCE), ("source_files", SOURCE_FILES), ("genesis_config", CONFIG),
            ("helpers", HELPERS), ("execution", EXECUTION), ("scope", SCOPE)):
        exact(value[key], expected)
    require(type(config_raw) is bytes and len(config_raw) == CONFIG["bytes"] and
            hashlib.sha256(config_raw).hexdigest() == CONFIG["sha256"])
    require(type(helper_raw) is dict and helper_raw.keys() == HELPERS.keys())
    for key, pin in HELPERS.items():
        raw = helper_raw[key]
        require(type(raw) is bytes and len(raw) == pin["bytes"] and
                hashlib.sha256(raw).hexdigest() == pin["sha256"])
    config = parse(config_raw, 16 << 10)
    rows = check_trace(value["trace"], config)
    raw_trace = (json.dumps(value["trace"], sort_keys=True, indent=2, allow_nan=False) + "\n").encode()
    pin = EXECUTION["trace_object"]
    require(len(raw_trace) == pin["bytes"] and hashlib.sha256(raw_trace).hexdigest() == pin["sha256"])
    return {
        "format": "zenon-source-parent-slots-replay/v1",
        "chain_id": 69, "source_parent": {"height": 1, "hash": GENESIS_HASH},
        "recorded_slot_queries": len(rows), "recorded_node_pass_events": 11,
        "recorded_negative_controls": len(REFUSALS), "independent_tick_and_proof_time_checks": True,
        "independent_election_order_recomputed": False,
        "node_or_managers_executed_by_reader": False,
        "original_controller_outcome": "FAILURE",
        "node_test_actual_exit": 0, "node_test_output_complete": True,
        "network_identity_or_activation_authenticated": False,
        "accepting_ProducerSchedule_created": False, "state_value_accepted": False,
    }


def check():
    raw = read_regular(CORPUS, 32 << 10)
    report = check_corpus(
        parse(raw, 32 << 10), read_regular(ROOT / CONFIG["path"], 16 << 10),
        {key: read_regular(ROOT / pin["path"], 16 << 10) for key, pin in HELPERS.items()},
    )
    report["corpus_sha256"] = hashlib.sha256(raw).hexdigest()
    return report


def main(argv):
    revision = None
    if argv:
        if len(argv) != 2 or argv[0] != "--source-revision" or re.fullmatch("[0-9a-f]{40}", argv[1]) is None:
            print("source-parent-slots: invalid command syntax", file=sys.stderr)
            return 64
        revision = argv[1]
    try:
        report = check()
        report["source_revision"] = revision
        print(json.dumps(report, sort_keys=True, allow_nan=False))
    except (ValueError, OSError, KeyError, TypeError, OverflowError, RecursionError):
        print("source-parent-slots: evidence check failed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
