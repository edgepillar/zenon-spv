#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Check the complete preselected public-Chain reorg/reopen event sequence.

This is recorded-output checking, not fresh backend execution or authentication
of the producer, process boundary, source, binary, network or consensus.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re

import importlib.util
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent

def load(name):
    spec = importlib.util.spec_from_file_location("reorg_" + name, HERE / (name + ".py"))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value

H = load("prepare_public_chain_reorg_reopen")
S = load("check_public_chain_startup_record")
P = H.P
generate = H.generate

FIXTURE_SHA256 = "220bb05cd50a6e3b174022950f66530c28c0c8f93529ac1194bfa5c15b323b3f"

def require(ok, reason="recorded event mismatch"):
    if not ok:
        raise ValueError(reason)

def pairs(items):
    out = {}
    for key, value in items:
        require(key not in out, "duplicate JSON key")
        out[key] = value
    return out

def load_json(raw):
    require(type(raw) is bytes and len(raw) <= 2 << 20, "recorded input cap")
    def constant(_):
        raise ValueError("non-finite JSON")
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)

def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()

def validate_images(images):
    require(type(images) is dict and set(images) == {"ledger", "cache", "tree"}, "three raw store images")
    for row in images.values():
        require(type(row) is dict and set(row) == {"records", "key_bytes", "value_bytes", "zero_length_values", "sha256"}, "complete raw image counters")
        require(all(type(row[k]) is int for k in ["records", "key_bytes", "value_bytes", "zero_length_values"]), "integer image counters")
        require(0 < row["records"] <= 1000000 and
                row["records"] <= row["key_bytes"] <= 256 * row["records"] and
                0 <= row["zero_length_values"] <= row["records"] and
                row["records"] - row["zero_length_values"] <= row["value_bytes"] <=
                (row["records"] - row["zero_length_values"]) * (16 << 20), "raw image bounds")
        require(type(row["sha256"]) is str and re.fullmatch("[0-9a-f]{64}", row["sha256"]) is not None, "raw image digest")

def expected_events(fixture, images, fixture_digest=FIXTURE_SHA256):
    validate_images(images)
    states = fixture["states"]
    zero = "00" * 32
    result = {}
    for mode in ["advance-reorg", "reopen"]:
        rows = []
        def emit(stage, **fields):
            rows.append(dict(fields, stage=stage, case=mode))
        def frontiers(tip):
            return {"ledger":states[tip]["identifier"], "cache":states[tip]["identifier"], "ready":True}
        def query(checkpoint, name, identifier, error="none"):
            row = states[name] if error == "none" else {"root":zero, "present":False, "value":"", "proof":""}
            emit("query", checkpoint=checkpoint, selection=name, identifier=identifier, root=row["root"],
                 value=row["value"], present=row["present"], proof=row["proof"], root_error=error, proof_error=error)
        def checkpoint(stage, tip, accepted, refused=()):
            emit("frontiers", checkpoint=stage, tip=tip, frontiers=frontiers(tip))
            for name in accepted:
                query(stage, name, states[name]["identifier"])
            for name, error in refused:
                query(stage, name, states[name]["identifier"], error)
            wrong = dict(states[tip]["identifier"])
            raw = bytearray.fromhex(wrong["hash"]); raw[0] ^= 1; wrong["hash"] = raw.hex()
            query(stage, "same-height-foreign-" + tip, wrong, "identity-mismatch")
        def append(name, previous):
            row = states[name]
            emit("projection", selection=name, previous=previous, root=row["root"], repeated_root=row["root"],
                 new_version_error="missing-version", frontiers=frontiers(previous), previous_root_unchanged=True,
                 patch_dump=row["patch_dump"])
            emit("appended", selection=name, identifier=row["identifier"], frontiers=frontiers(name),
                 maintenance_order=["UpdateCache","UpdateStateTree","AddMomentumTransaction"], patch_consumed=True)
        def old_projection(stage, error):
            emit("old-projection-refused", checkpoint=stage, previous="A2", changes="A3", error=error, root=zero)
        emit("selection", fixture_sha256=fixture_digest, raw_key=fixture["raw_key"], unsigned_local_component_fixture=True,
             public_Chain_Init_and_Start_selected=True, full_node_or_network_started=False, consensus_validation_executed=False,
             wallet_signing_or_broadcast=False, cache_account_block_extraction_selected=False, consumer_result="REFUSED")
        if mode == "reopen":
            emit("closed-stores-before-reopen", images=images)
        emit("fresh-source-genesis", identifier=states["A1"]["identifier"],
             patch_sha256=fixture["source"]["genesis_patch"]["sha256"], patch_bytes=fixture["source"]["genesis_patch"]["bytes"])
        if mode == "advance-reorg":
            checkpoint("initialized","A1",["A1"],[("A2","missing-version")])
            append("A2","A1"); checkpoint("after-A2","A2",["A1","A2"])
            append("A3","A2"); checkpoint("after-A3","A3",["A1","A2","A3"])
            emit("rolled-back", target=states["A1"]["identifier"], frontiers=frontiers("A1"),
                 maintenance_order=["RollbackTo","RollbackCacheTo","TruncateStateTreeTo"])
            checkpoint("after-rollback","A1",["A1"],[("A2","missing-version"),("A3","missing-version")])
            old_projection("after-rollback","missing-version")
            append("B2","A1"); checkpoint("after-B2","B2",["A1","B2"],[("A2","identity-mismatch"),("A3","missing-version")])
            append("B3","B2"); checkpoint("after-B3","B3",["A1","B2","B3"],[("A2","identity-mismatch"),("A3","identity-mismatch")])
            old_projection("after-B3","identity-mismatch")
        else:
            checkpoint("fresh-process-reopen","B3",["A1","B2","B3"],[("A2","identity-mismatch"),("A3","identity-mismatch")])
            old_projection("fresh-process-reopen","identity-mismatch")
        emit("closed-stores", images=images, ready=False, repeat_stop_error=None, raw_zero_length_values_retained=True,
             fresh_process_reopen_images_unchanged=mode=="reopen", consumer_result="REFUSED")
        result[mode] = rows
    return result

def validate(events, fixture):
    require(type(fixture) is dict and hashlib.sha256(encoded(fixture)).hexdigest()==FIXTURE_SHA256, "independent fixture digest")
    require(type(events) is dict and set(events)=={"advance-reorg","reopen"}, "both selected process records")
    for mode in events:
        require(type(events[mode]) is list and 0 < len(events[mode]) <= 128, "bounded event list")
    try:
        images=events["advance-reorg"][-1]["images"]
    except (KeyError, TypeError):
        raise ValueError("closed raw store images missing")
    validate_images(images)
    expected=expected_events(fixture, images)
    require(encoded(events)==encoded(expected), "complete preselected event sequence")
    queries=[r for rows in events.values() for r in rows if r["stage"]=="query"]
    require(len(events["advance-reorg"])==45 and len(events["reopen"])==12 and len(queries)==31, "selected case accounting")
    exact=sum(r["root_error"]=="none" for r in queries)
    require(exact==15, "exact and refused result accounting")
    return {"kind":"independent-recorded-public-Chain-reorg-reopen-events", "event_count":57, "query_count":31,
            "exact_matches":15, "version_refusals":16, "fixture_sha256":FIXTURE_SHA256,
            "raw_images_equal_in_record":True, "backend_reexecuted":False, "process_freshness_authenticated":False,
            "source_and_binary_authenticated":False, "consumer_result":"REFUSED", "production_state_value_accepted":False}

CORPUS = "native-public-chain-reorg-reopen.json"
CORPUS_SHA256 = "158544b09978156c1a343826ea6524d3b79d154c87862c25b2c88a66f36a164b"
CORPUS_BYTES = 56499
EXECUTION_SHA256 = "ac2375758f029f92aee8eb62caaeb69af3c7bcdee0fdd432f4357b206e8d97d0"
MAX_BYTES = 128 << 10
SCOPE = {
    "actual_public_Chain_Init_Start_Stop_recorded": True,
    "actual_real_disk_ledger_cache_and_tree_recorded": True,
    "one_ordinary_binary_and_two_sequential_processes": True,
    "new_local_momentums_unsigned_and_empty_content": True,
    "exact_maintenance_order_from_selected_callers": True,
    "independent_patch_v1_header_and_partial_SMT_bytes": True,
    "stored_zero_and_absence_distinguished": True,
    "full_hash_and_height_version_queries_checked": True,
    "fresh_process_reopen_and_equal_logical_KV_images_recorded": True,
    "raw_zero_length_values_retained": True,
    "hosted_checks_replay_recorded_bytes": True,
    "complete_large_genesis_or_KV_images_independently_rederived": False,
    "cache_account_block_extraction_qualified": False,
    "network_valid_history_or_full_node_recovery_qualified": False,
    "concurrent_lifecycle_interruption_or_retention_workload_qualified": False,
    "representative_resource_budget_qualified": False,
    "private_execution_or_distribution_authenticated": False,
    "signature_consensus_or_canonicality_qualified": False,
    "node_client_profile_agreed": False,
    "accepted_header_binding": False,
    "runtime_state_value_acceptance": False,
    "production_qualified": False,
    "checker_executes_reference_backend": False,
}
INPUTS = tuple(dict.fromkeys((
    "check_public_chain_reorg_reopen.py", "prepare_public_chain_reorg_reopen.py", H.PROBE,
    "testdata/successor-public-chain-lifecycle.json", *S.INPUTS,
)))


def expected_source():
    manifest, _, pins = H.H.selection()
    build = H.build_pins()
    require(P.UTIL.reconstruct_tree(pins) == H.H.MODIFIED_TREE, "selected runtime")
    return {
        "repository": "https://github.com/digitalSloth/go-zenon", "revision": P.REVISION,
        "original_tree": P.TREE, "source_manifest_sha256": P.SOURCE_SHA256,
        "original_source_blobs": len(manifest["files"]), "runtime_tree": H.H.MODIFIED_TREE,
        "ordinary_build_tree": P.UTIL.reconstruct_tree(build), "ordinary_source_blobs": len(build),
        "probe": {"bytes": H.PROBE_BYTES, "sha256": H.PROBE_SHA256},
        "fixture": {"bytes": H.FIXTURE_BYTES, "sha256": H.FIXTURE_SHA256},
        "seed_file_sha256": H.SEED_SHA256,
        "module_sha256": pins["go.mod"]["sha256"], "sum_sha256": pins["go.sum"]["sha256"],
        "runtime_patch_added": False,
    }


def check_command(value):
    require(type(value) is dict and set(value) == {"state","actual_exit","output_complete","reason","stdout","stderr"}, "complete command fields")
    P.exact([value[k] for k in ("state","actual_exit","output_complete","reason")], ["COMPLETE",0,True,None])
    for key in ("stdout","stderr"):
        row = value[key]
        require(type(row) is dict and set(row) == {"bytes","sha256"}, "stream reference fields")
        require(type(row["bytes"]) is int and 0 <= row["bytes"] <= 2 << 20, "stream bound")
        require(type(row["sha256"]) is str and re.fullmatch("[0-9a-f]{64}",row["sha256"]) is not None, "stream digest")


def check_corpus(value):
    require(type(value) is dict and set(value) == {"format_version","kind","source","scope","execution","cases","consumer_result"}, "recorded corpus fields")
    P.exact([value["format_version"],value["kind"],value["consumer_result"]], [1,"recorded-public-chain-reorg-reopen","REFUSED"])
    P.exact(value["source"], expected_source())
    P.exact(value["scope"], SCOPE)
    execution = value["execution"]
    require(type(execution) is dict and hashlib.sha256(encoded(execution)).hexdigest() == EXECUTION_SHA256, "recorded execution pin")
    P.exact([execution[k] for k in ("compiler","reference_platform","ordinary_builds","ordinary_processes",
                                    "linked_modules_per_binary","new_external_transports","whole_module_archive_graph_verification")],
            ["go1.25.14","darwin/arm64",1,2,25,0,"NOT_QUALIFIED"])
    require(type(execution["commands"]) is dict and set(execution["commands"]) == {"build","buildinfo",*H.MODES}, "selected command inventory")
    for command in execution["commands"].values():
        check_command(command)
    for label in ("build","buildinfo"):
        for stream in ("stdout","stderr"):
            text = execution[label+"_"+stream+"_utf8"]
            require(type(text) is str, "complete build text stream")
            raw = text.encode()
            pin = execution["commands"][label][stream]
            require(len(raw) == pin["bytes"] and hashlib.sha256(raw).hexdigest() == pin["sha256"], "exact build stream")
    info = load_json(execution["buildinfo_stdout_utf8"].encode())
    P.exact([info["GoVersion"],info["Path"],info["Main"]],
            ["go1.25.14","github.com/zenon-network/go-zenon/cmd/candidate-public-chain-reorg-reopen",
             {"Path":"github.com/zenon-network/go-zenon","Version":"(devel)"}])
    require(len(info["Deps"]) == 25 and all("Replace" not in dep for dep in info["Deps"]), "recorded linked module inventory")
    fixture_raw = H.selected_fixture()
    fixture = load_json(fixture_raw)
    cases = value["cases"]
    require(type(cases) is list and len(cases) == 2, "two ordinary process records")
    events = {}
    for mode, row in zip(H.MODES, cases):
        require(type(row) is dict and set(row) == {"case","command","stdout_utf8","stderr_utf8"}, "complete process record")
        require(row["case"] == mode, "process order")
        P.exact(row["command"],execution["commands"][mode])
        for stream in ("stdout","stderr"):
            text = row[stream+"_utf8"]
            require(type(text) is str, "text stream")
            raw = text.encode()
            require(len(raw) == row["command"][stream]["bytes"] and hashlib.sha256(raw).hexdigest() == row["command"][stream]["sha256"], "exact captured stream")
        lines = row["stdout_utf8"].encode().splitlines()
        require(0 < len(lines) <= 128 and all(lines), "bounded complete event list")
        events[mode] = [load_json(line) for line in lines]
        tip = fixture["states"]["A1" if mode=="advance-reorg" else "B3"]["identifier"]
        expected_stderr = "Initialized NoM. Height: "+str(tip["height"])+", Hash: "+tip["hash"]+"\nPUBLIC_CHAIN_REORG_REOPEN_PROCESS_COMPLETE\n"
        require(row["stderr_utf8"] == expected_stderr, "complete ordinary-process marker")
    result = validate(events,fixture)
    result.update(
        kind="recorded-public-chain-reorg-reopen-check", source=expected_source(), scope=dict(SCOPE),
        recorded_reference_processes=2, recorded_reference_builds=1,
        reference_processes_executed_by_this_check=0,
        independent_preselected_roots=5, independent_v1_header_preimage_bytes=160,
        consumer_result="REFUSED",
        reader_inputs_sha256={name:hashlib.sha256(P.read_regular(HERE/name,1<<20)).hexdigest() for name in INPUTS})
    return result


def check_file(path):
    raw = P.read_regular(Path(path),MAX_BYTES)
    require(len(raw)==CORPUS_BYTES and hashlib.sha256(raw).hexdigest()==CORPUS_SHA256, "recorded corpus pin")
    result = check_corpus(load_json(raw))
    result["corpus_sha256"] = CORPUS_SHA256
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    inputs = parser.add_mutually_exclusive_group()
    inputs.add_argument("--corpus", type=Path)
    inputs.add_argument("--events", type=Path)
    inputs.add_argument("--advance-stdout", type=Path)
    parser.add_argument("--reopen-stdout", type=Path)
    parser.add_argument("--source-revision")
    parser.add_argument("--output")
    args = parser.parse_args(argv)
    try:
        if args.events is not None or args.advance_stdout is not None:
            fixture = load_json(H.selected_fixture())
            if args.events is not None:
                require(args.reopen_stdout is None, "one selected input mode")
                events = load_json(P.read_regular(args.events,2<<20))
            else:
                require(args.reopen_stdout is not None, "both stdout objects required")
                events = {}
                for mode,path in zip(H.MODES,(args.advance_stdout,args.reopen_stdout)):
                    lines = P.read_regular(path,2<<20).splitlines()
                    require(0<len(lines)<=128 and all(lines), "bounded JSON lines")
                    events[mode] = [load_json(line) for line in lines]
            result = validate(events,fixture)
        else:
            require(args.reopen_stdout is None, "one selected input mode")
            result = check_file(HERE/"testdata"/CORPUS if args.corpus is None else args.corpus)
        if args.source_revision is not None:
            require(re.fullmatch("[0-9a-f]{40}",args.source_revision) is not None, "source revision")
            result["source_revision"] = args.source_revision
        if args.output:
            P.UTIL.seal(Path(args.output),encoded(result))
    except (OSError,ValueError,KeyError,TypeError,OverflowError,RecursionError):
        print(json.dumps({"kind":"recorded-public-chain-reorg-reopen-check","consumer_result":"REFUSED","result":"REFUSED"}))
        return 1
    print(json.dumps(result,sort_keys=True))
    return 0


if __name__=="__main__":
    raise SystemExit(main())
