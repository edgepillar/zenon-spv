#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Read recorded public Chain startup observations; execute no node or network.

The full KV-image digests are recorded pins, not an independent reconstruction
of the large source-genesis database. Header hashes and a small raw KV frame
are computed separately using Python's standard library.
"""
import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location("startup_record_" + name, HERE / (name + ".py"))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


H = load("prepare_public_chain_startup_record")
R = load("check_momentum_rollback_target")
P = H.P
CORPUS = "native-public-chain-startup-record.json"
CORPUS_SHA256 = "1314679e7359f24b687327d2efb8b5997a27adbb0e3aa7ecdc3f3b9f2371f860"
CORPUS_BYTES = 122389
EXECUTION_SHA256 = "9ebe7980979a560393faba8494adae79687893c05ab165e51dac2e65ac87085d"
MAX_BYTES = 256 << 10
ZERO = "0" * 64
ROOT = "864dbad1c3ef38e2c867950390364878c58238183d01b8bf97ef73e2efa4383d"
GENESIS_PATCH = {"bytes": 10849399, "sha256": "a222aac55304b1a489d395235c61af4182ac08b887d24d0c3f654aa402f35e75"}
SCOPE = {
    "actual_public_Chain_Init_and_Stop_recorded": True,
    "actual_real_ledger_cache_and_tree_recorded": True,
    "controlled_local_unsigned_fixtures": True,
    "recovered_API_panics_separate_from_process_success": True,
    "independent_v1_header_hashes_and_small_raw_KV_frame": True,
    "raw_zero_length_values_retained": True,
    "hosted_checks_replay_recorded_bytes": True,
    "complete_large_KV_images_independently_rederived": False,
    "all_malformed_metadata_or_records_qualified": False,
    "concurrent_lifecycle_or_full_node_recovery_qualified": False,
    "representative_resource_budget_qualified": False,
    "private_execution_or_distribution_authenticated": False,
    "Chain_Start_or_network_executed": False,
    "signature_consensus_or_canonicality_qualified": False,
    "node_client_profile_agreed": False,
    "accepted_header_binding": False,
    "runtime_state_value_acceptance": False,
    "production_qualified": False,
    "checker_executes_reference_backend": False,
}
INPUTS = tuple(dict.fromkeys((
    "check_public_chain_startup_record.py", "prepare_public_chain_startup_record.py",
    H.PATCH, H.PROBE, H.UNIT, *R.INPUTS,
)))
HEADERS = {'genesis': {'chain_identifier': 1,
             'changes_hash': 'fe37ddbea9fc05b16cd91e8b50d6aa74c1754f00f3339c3512717fe92fdb3d78',
             'content_hash': '1bfc9e7035ceba7e45f6ab0fa40c448fc060b17ec31201fa51fa67a11b1ca577',
             'data_hex': '303030303030303030303030303030303030303034646430343035393535343064343363653866663539343665656161343033666231336430653538326438662357652061726520616c6c205361746f73686923446f6e27742074727573742e20566572696679',
             'hash': '9e204601d1b7b1427fe12bc82622e610d8a6ad43c40abf020eb66e538bb8eeb0',
             'height': 1,
             'next_fusion_price': 0,
             'next_work_price': 0,
             'previous_hash': '0000000000000000000000000000000000000000000000000000000000000000',
             'public_key_bytes': 0,
             'serialized_bytes': 930429,
             'serialized_sha256': 'bb2ea592e3b386954568687becbf9fb47471bba57806602a750a7c0781aa241e',
             'signature_bytes': 0,
             'state_root': '0000000000000000000000000000000000000000000000000000000000000000',
             'timestamp': 1637755200,
             'version': 1},
 'second': {'chain_identifier': 1,
            'changes_hash': 'a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a',
            'content_hash': 'a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a',
            'data_hex': '',
            'hash': 'fbe4d2002715d5993894e36fe23eefab052ffe697861465b1be8c07d786beed0',
            'height': 2,
            'next_fusion_price': 0,
            'next_work_price': 0,
            'previous_hash': '9e204601d1b7b1427fe12bc82622e610d8a6ad43c40abf020eb66e538bb8eeb0',
            'public_key_bytes': 0,
            'serialized_bytes': 120,
            'serialized_sha256': 'a87eec953ef7de5e55ac6a902c01bca762d7f7d22b2921bd457c9389535f6203',
            'signature_bytes': 0,
            'state_root': '0000000000000000000000000000000000000000000000000000000000000000',
            'timestamp': 1637755210,
            'version': 1}}
BASE_IMAGES = {'cache': {'key_bytes': 20,
           'records': 3,
           'sha256': '93c4e32515f9c52804fbacf3553af7c658bfa3ab9a5c44b5d4f8fa83b42b38d7',
           'value_bytes': 84},
 'ledger': {'key_bytes': 3553773,
            'records': 103830,
            'sha256': '760a378e0d48e958cfea755722737179f2aabb11cef5dad4f491cdddc63d0a58',
            'value_bytes': 23546168},
 'tree': {'key_bytes': 2541896,
          'records': 77032,
          'sha256': '776e55c60cdee4cefc3eddeefa9387ef1f970bee2228b288e2353f09a8058711',
          'value_bytes': 4254354}}
ROW_HASHES = {'genesis': 'fb872998751aa5a4fa1350539912d63d838a86ec1ce36cb860a29806089ef5db',
 'second': 'f238db35d88f03a900b94e079675dca7a73a21b2fd42101a89b7c62d8b911186'}
ROW_PINS = {'healthy-clean-reopen': {'ledger_sha256': '760a378e0d48e958cfea755722737179f2aabb11cef5dad4f491cdddc63d0a58'},
 'missing-genesis': {'ledger_sha256': 'afb262fbc843cb066fd0b4a5d3cc02bd9ce3f1dc9f6aa3c5974745d4a1b08a33',
                     'after_value_sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
                     'byte_changes': []},
 'genesis-wrong-height': {'ledger_sha256': 'e9648d7887742bb82f8e00f7514b5131cd8956df08b51ff57194ae98c6d75742',
                          'after_value_sha256': '19ccf5187d4a85fc5d332899a746518a0af24bbc903d6d20118d25e4e2f6c0ad',
                          'byte_changes': [{'after': 2, 'before': 1, 'offset': 78}],
                          'after_serialized_sha256': '386ba6542a3111988e76ec942afdb0f586c6fde61531f5876eec02ec53a43ddc'},
 'genesis-body-hash-mismatch': {'ledger_sha256': 'acfd9a957842ac3bc8e2d7619e4577874f8675030b5628456b2670c1efda47f0',
                                'after_value_sha256': 'b24349e1eb3654fb3041930216a84ed4349547984bf6a3e6acc17b2ce29c9a9e',
                                'byte_changes': [{'after': 193, 'before': 192, 'offset': 80}],
                                'after_serialized_sha256': 'e95a5bfb344959ca6c69d184b50243f49a90cec422a11cae23407378d11b36ea'},
 'missing-frontier': {'ledger_sha256': 'b6aa94e33a8872d4df19da798e73b4013a615a75a28652c1437c0c3b1d4c7eb5',
                      'after_value_sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
                      'byte_changes': []},
 'frontier-wrong-height': {'ledger_sha256': '159b3a77dd93de1541ad80abd68d70b2315ce4a3cc4f67ba27becb824babffb3',
                           'after_value_sha256': 'e88e8061093db949d0eaeeb55e87378b3e3eae9332af986692587e0fa96c302e',
                           'byte_changes': [{'after': 3, 'before': 2, 'offset': 78}],
                           'after_serialized_sha256': 'f107f026cd4daa20c5fa0532c941e70517d2f8a1ac5a14bf52b96cd35ed3bd98'},
 'frontier-wrong-hash': {'ledger_sha256': 'a17beada25b45fc2930fca78756eea2ecb248a99e8593f71d5b6cd2c04aa04e0',
                         'after_value_sha256': '1e95ed583d0e4771211265af43004e96d4c50f2f9d8edfbf90cc102273f4adfc',
                         'byte_changes': [{'after': 250, 'before': 251, 'offset': 9}],
                         'after_serialized_sha256': '0861354887f337f4ddd0683c903a53b99aebee08440d563f7860891747db9aa8'},
 'frontier-body-hash-mismatch': {'ledger_sha256': '1b308438563cfa5a5974354aad89f46884e7877f28a3d9b3e05d994e1e6c1b31',
                                 'after_value_sha256': 'ad9af5d7a276c5301aafd094562e1f544d738a7e4265577608778c2941fa1f64',
                                 'byte_changes': [{'after': 203, 'before': 202, 'offset': 80}],
                                 'after_serialized_sha256': '27ef09748a4e3a6d975a5df46cbdea6a5d3e5a5a32af2d3c0c859072180dad3d'},
 'corrupt-genesis': {'ledger_sha256': '6afdd250205ef6f68483138d97de574c915ef71d636500a4d15326e58daf5158',
                     'after_value_sha256': '06eb7d6a69ee19e5fbdf749018d3d2abfa04bcbd1365db312eb86dc7169389b8',
                     'byte_changes': []},
 'corrupt-frontier': {'ledger_sha256': 'e773e4d42b58e6121e248a821b18985f5b2ea5624be2626fa68c30f9f353001b',
                      'after_value_sha256': '06eb7d6a69ee19e5fbdf749018d3d2abfa04bcbd1365db312eb86dc7169389b8',
                      'byte_changes': []},
 'ledger-manager-stopped': {'ledger_sha256': '760a378e0d48e958cfea755722737179f2aabb11cef5dad4f491cdddc63d0a58'},
 'cache-manager-stopped': {'ledger_sha256': '760a378e0d48e958cfea755722737179f2aabb11cef5dad4f491cdddc63d0a58'}}

def fixture(case, row):
    images = copy.deepcopy(BASE_IMAGES)
    images["ledger"]["sha256"] = row["ledger_sha256"]
    if case == "healthy-clean-reopen" or case.endswith("manager-stopped"):
        mutation = {"kind": "none"}
    else:
        selected = HEADERS["genesis" if "genesis" in case else "second"]
        before_bytes = selected["serialized_bytes"] + 1
        present = not case.startswith("missing-")
        corrupt = case.startswith("corrupt-")
        after_bytes = 0 if not present else 2 if corrupt else before_bytes
        after = None
        if present and not corrupt:
            after = copy.deepcopy(selected)
            if case.endswith("wrong-height"):
                after["height"] += 1
            elif case.endswith("wrong-hash"):
                raw = bytearray.fromhex(after["hash"])
                raw[0] ^= 1
                after["hash"] = raw.hex()
            else:
                after["timestamp"] += 1
            after["serialized_sha256"] = row["after_serialized_sha256"]
        mutation = {
            "kind": case, "key_hex": (b"\x55\x02" + struct.pack(">Q", selected["height"])).hex(),
            "selected_identifier": {"hash": selected["hash"], "height": selected["height"]},
            "before_header": copy.deepcopy(selected), "before_value_bytes": before_bytes,
            "before_value_sha256": ROW_HASHES["genesis" if "genesis" in case else "second"],
            "before_presence_prefix": 0, "after_present": present,
            "after_value_sha256": row["after_value_sha256"], "after_value_bytes": after_bytes,
            "after_header": after, "same_length_byte_changes": copy.deepcopy(row["byte_changes"]),
            "corrupt_after_hex": "00ff" if corrupt else "",
        }
        images["ledger"]["records"] -= int(not present)
        images["ledger"]["key_bytes"] -= 10 * int(not present)
        images["ledger"]["value_bytes"] += after_bytes - before_bytes
    return {"case": case, "stage": "fixture-before-public-init", "images": images,
            "ledger_frontier_metadata": {"hash": HEADERS["second"]["hash"], "height": 2},
            "mutation": mutation}


FIXTURES = {case: fixture(case, row) for case, row in ROW_PINS.items()}
CASES = tuple(FIXTURES)

PARENT_CLASSES = (
    "none", "panic", "none", "none", "other", "none", "none", "none",
    "other", "panic", "panic", "panic",
)
CANDIDATE_CLASSES = (
    "none", "missing-genesis", "other", "genesis-body-hash-mismatch", "missing-frontier",
    "frontier-identifier-mismatch", "frontier-identifier-mismatch", "frontier-body-hash-mismatch",
    "other", "other", "ledger-unavailable", "cache-unavailable",
)


def document(raw):
    P.require(type(raw) is bytes and 0 < len(raw) <= MAX_BYTES)
    def constant(_):
        raise ValueError("Non-finite JSON refused")
    return json.loads(raw, object_pairs_hook=P.pairs, parse_constant=constant)


def expected_source():
    manifest, _, pins = H.selection()
    for variant, unit in (("parent", False), ("candidate", False), ("candidate", True)):
        H.build_pins(variant, unit)
    return {
        "repository": "https://github.com/digitalSloth/go-zenon", "revision": P.REVISION,
        "original_tree": P.TREE, "original_source_blobs": len(manifest["files"]),
        "source_manifest_sha256": P.SOURCE_SHA256, "parent_runtime_tree": H.H.MODIFIED_TREE,
        "candidate_runtime_tree": H.MODIFIED_TREE, "parent_probe_build_tree": H.PARENT_BUILD_TREE,
        "candidate_probe_build_tree": H.BUILD_TREE, "candidate_unit_build_tree": H.UNIT_BUILD_TREE,
        "ordinary_source_blobs": 468, "unit_source_blobs": 470,
        "patch_sha256": H.PATCH_SHA256,
        "probe": {"bytes": H.PROBE_BYTES, "sha256": H.PROBE_SHA256},
        "unit_source": {"bytes": H.UNIT_BYTES, "sha256": H.UNIT_SHA256},
        "module_sha256": pins["go.mod"]["sha256"], "sum_sha256": pins["go.sum"]["sha256"],
    }


def hexbytes(value, count=None):
    P.require(type(value) is str and len(value) % 2 == 0 and re.fullmatch("[0-9a-f]*", value) is not None)
    raw = bytes.fromhex(value)
    P.require(count is None or len(raw) == count)
    return raw


def header_hash(value):
    P.require(type(value) is dict and set(value) == set(HEADERS["genesis"]))
    for key in ("version", "chain_identifier", "height", "timestamp", "next_fusion_price", "next_work_price",
                "public_key_bytes", "signature_bytes", "serialized_bytes"):
        P.require(type(value[key]) is int and 0 <= value[key] < (1 << 64))
    P.require(value["version"] == 1 and value["chain_identifier"] == 1)
    P.require(value["public_key_bytes"] == value["signature_bytes"] == 0)
    P.require(0 < value["serialized_bytes"] <= 1 << 20)
    for key in ("hash", "previous_hash", "content_hash", "changes_hash", "state_root", "serialized_sha256"):
        hexbytes(value[key], 32)
    P.require(value["next_fusion_price"] == value["next_work_price"] == 0 and value["state_root"] == ZERO)
    data = hexbytes(value["data_hex"])
    P.require(len(data) <= 1024)
    raw = (struct.pack(">QQ", value["version"], value["chain_identifier"]) +
           hexbytes(value["previous_hash"], 32) + struct.pack(">QQ", value["height"], value["timestamp"]) +
           hashlib.sha3_256(data).digest() + hexbytes(value["content_hash"], 32) +
           hexbytes(value["changes_hash"], 32))
    P.require(len(raw) == 160)
    return hashlib.sha3_256(raw).hexdigest()


def check_result(value, error_class):
    P.require(type(value) is dict and set(value) == {
        "error_class", "error_sha256", "panic", "panic_type", "panic_sha256"})
    panic = error_class == "panic"
    P.exact(value["error_class"], error_class)
    P.exact(value["panic"], panic)
    if panic:
        P.require(type(value["panic_type"]) is str and bool(value["panic_type"]))
        hexbytes(value["panic_sha256"], 32)
        P.exact(value["error_sha256"], "")
    else:
        P.exact([value["panic_type"], value["panic_sha256"]], ["", ""])
        if error_class == "none":
            P.exact(value["error_sha256"], "")
        else:
            hexbytes(value["error_sha256"], 32)


def check_trace(row, variant):
    P.require(type(row) is dict and set(row) == {"variant", "command", "completion_marker_observed", "stdout_utf8"})
    P.exact(row["variant"], variant)
    P.exact(row["completion_marker_observed"], True)
    text = row["stdout_utf8"]
    P.require(type(text) is str and 0 < len(text.encode()) < 96 << 10 and text.endswith("\n"))
    R.command(row["command"], text.encode())
    events = [document(line.encode()) for line in text.splitlines()]
    P.require(len(events) == 75)
    frame = struct.pack(">Q", 1) + b"\x11" + struct.pack(">Q", 0)
    P.exact(events[0], {
        "case": "", "stage": "raw-presence-control", "raw_zero_length_values_retained": True,
        "image": {"records": 1, "key_bytes": 1, "value_bytes": 0, "sha256": P.sha(frame)},
    })
    P.exact(events[1], {
        "case": "", "stage": "source-selection", **HEADERS,
        "cases": list(CASES), "genesis_patch_bytes": GENESIS_PATCH["bytes"],
        "genesis_patch_sha256": GENESIS_PATCH["sha256"], "chain_start_called": False,
        "full_node_or_network_started": False, "wallet_signing_or_broadcast": False, "consumer_result": "REFUSED",
    })
    for name, header in HEADERS.items():
        P.require(header_hash(header) == header["hash"])
    cursor, panics, invalid_ready = 2, 0, 0
    classes = PARENT_CLASSES if variant == "parent" else CANDIDATE_CLASSES
    base = FIXTURES["healthy-clean-reopen"]["images"]
    for case, error_class in zip(CASES, classes):
        expected = FIXTURES[case]
        P.exact(events[cursor], {
            "case": case, "stage": "fixture-seeded", "images": base,
            "frontier": {"hash": HEADERS["second"]["hash"], "height": 2}, "source_projection_root": ROOT,
        })
        P.exact(events[cursor + 1], expected)
        mutation = expected["mutation"]
        if mutation["kind"] != "none":
            selected = HEADERS["genesis" if "genesis" in case else "second"]
            P.exact(mutation["key_hex"], (b"\x55\x02" + struct.pack(">Q", selected["height"])).hex())
            P.exact(mutation["before_header"], selected)
            P.exact(mutation["before_value_bytes"], 1 + selected["serialized_bytes"])
            P.exact(mutation["before_presence_prefix"], 0)
            after = mutation["after_header"]
            if after is not None:
                P.require(header_hash(after) != after["hash"])
                P.require(len(mutation["same_length_byte_changes"]) == 1)
            if case.startswith("corrupt-"):
                P.exact(mutation["corrupt_after_hex"], "00ff")
                P.exact(mutation["after_value_sha256"], P.sha(b"\x00\xff"))
            if case.startswith("missing-"):
                P.exact([mutation["after_present"], mutation["after_value_bytes"],
                         mutation["after_value_sha256"]], [False, 0, P.sha(b"")])
        init = events[cursor + 2]
        P.require(set(init) == {"case", "stage", "result", "state_tree_ready", "root", "root_query_result"})
        P.exact([init["case"], init["stage"]], [case, "public-init-observation"])
        check_result(init["result"], error_class)
        ready = error_class == "none"
        P.exact([init["state_tree_ready"], init["root"]], [ready, ROOT if ready else ZERO])
        check_result(init["root_query_result"], "none" if ready else "not-ready")
        panics += int(error_class == "panic")
        invalid_ready += int(ready and case != "healthy-clean-reopen")
        stop = events[cursor + 3]
        P.require(set(stop) == {"case", "stage", "result", "state_tree_ready"})
        P.exact([stop["case"], stop["stage"], stop["state_tree_ready"]], [case, "public-stop-observation", False])
        check_result(stop["result"], "none")
        P.exact(events[cursor + 4], {
            "case": case, "stage": "fixture-after-public-stop", "images": expected["images"],
            "raw_images_unchanged": True,
        })
        cursor += 5
        if case == "healthy-clean-reopen":
            P.exact(events[cursor], {
                "case": case, "stage": "public-clean-reopen", "images": base, "root": ROOT,
                "state_tree_ready_after_stop": False,
            })
            cursor += 1
        consumed = variant == "parent" and case == "missing-frontier"
        P.exact(events[cursor], {
            "case": case, "stage": "configured-genesis-transaction-after-stop",
            "changes_present": not consumed, "bytes": 0 if consumed else GENESIS_PATCH["bytes"],
            "sha256": P.sha(b"") if consumed else GENESIS_PATCH["sha256"],
        })
        cursor += 1
    P.require(cursor == len(events))
    return {"events": len(events), "API_panics": panics, "invalid_ready": invalid_ready}


def check_units(value):
    P.require(type(value) is dict and set(value) == {
        "build_tree", "command", "race_detector", "root_tests", "test_pass_names",
        "package_pass_names", "explicit_skips", "failed_tests"})
    P.exact(value["build_tree"], H.UNIT_BUILD_TREE)
    R.command(value["command"])
    old = H.H.ROOTS
    names = {*H.ROOTS, *(old[0] + "/" + name for name in
                        ("zero", "above", "maximum", "wrong-hash", "nil-locker", "matching-frontier"))}
    P.exact(value["root_tests"], list(H.ROOTS))
    P.exact(value["test_pass_names"], sorted(names))
    P.exact(value["package_pass_names"], ["github.com/zenon-network/go-zenon/chain"])
    P.exact([value["race_detector"], value["explicit_skips"], value["failed_tests"]], [False, [], []])
    P.require(len(names) == 17)


def check_corpus(value):
    P.require(type(value) is dict and set(value) == {
        "format_version", "kind", "source", "scope", "execution", "cases", "unit_run", "consumer_result"})
    P.exact([value["format_version"], value["kind"], value["consumer_result"]],
            [1, "recorded-public-chain-startup-record", "REFUSED"])
    P.exact(value["source"], expected_source())
    P.exact(value["scope"], SCOPE)
    execution = value["execution"]
    P.require(type(execution) is dict and P.sha(P.UTIL.encoded(execution)) == EXECUTION_SHA256)
    P.exact([execution[key] for key in ("compiler", "reference_platform", "ordinary_builds", "ordinary_processes",
                                      "linked_modules_per_binary", "new_external_transports",
                                      "whole_module_archive_graph_verification")],
            ["go1.25.14", "darwin/arm64", 2, 2, 25, 0, "NOT_QUALIFIED"])
    P.require(type(value["cases"]) is list and len(value["cases"]) == 2)
    results = [check_trace(row, variant) for row, variant in zip(value["cases"], ("parent", "candidate"))]
    for row in value["cases"]:
        P.exact(row["command"], execution["commands"][row["variant"] + "_run"])
    P.exact([results[0]["API_panics"], results[1]["API_panics"],
             results[0]["invalid_ready"], results[1]["invalid_ready"]], [4, 0, 5, 0])
    check_units(value["unit_run"])
    P.exact(value["unit_run"]["command"], execution["unit_command"])
    return {
        "kind": "recorded-public-chain-startup-record-check", "recorded_reference_processes": 2,
        "recorded_cases_per_generation": 12, "recorded_events": sum(row["events"] for row in results),
        "recorded_parent_API_panics": 4, "recorded_candidate_API_panics": 0,
        "recorded_parent_inconsistent_ready_results": 5, "recorded_candidate_inconsistent_ready_results": 0,
        "recorded_native_unit_roots": 11, "recorded_native_unit_pass_results": 17, "recorded_native_skips": 0,
        "independent_raw_presence_frames": 1, "independent_v1_header_hash_preimage_bytes": 160,
        "reference_processes_executed_by_this_check": 0, "source": expected_source(), "scope": dict(SCOPE),
        "initial_observer_attempts": "TWO_INCOMPLETE_FAILURES_RETAINED",
        "initial_unit_attempts": "IMPORT_CYCLE_AND_INCOMPLETE_CAPTURE_RETAINED",
        "consumer_result": "REFUSED",
        "reader_inputs_sha256": {name: P.sha(P.read_regular(HERE / name, 1 << 20)) for name in INPUTS},
    }


def check_file(path):
    raw = P.read_regular(Path(path), MAX_BYTES)
    P.require(len(raw) == CORPUS_BYTES and P.sha(raw) == CORPUS_SHA256)
    result = check_corpus(document(raw))
    result["corpus_sha256"] = P.sha(raw)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", default=str(HERE / "testdata" / CORPUS))
    parser.add_argument("--source-revision")
    parser.add_argument("--output")
    args = parser.parse_args(argv)
    try:
        if args.source_revision is not None:
            P.require(re.fullmatch("[0-9a-f]{40}", args.source_revision) is not None)
        result = check_file(args.corpus)
        if args.source_revision is not None:
            result["source_revision"] = args.source_revision
        if args.output:
            P.UTIL.seal(Path(args.output), P.UTIL.encoded(result))
    except (OSError, ValueError, KeyError, TypeError, OverflowError):
        print(json.dumps({"kind": "recorded-public-chain-startup-record-check", "consumer_result": "REFUSED", "result": "REFUSED"}))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
