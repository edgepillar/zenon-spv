#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Independent finite bulk seed/tail, SMT, retained graph and sample shape.

The checker never opens LevelDB, starts a node, measures resources or executes
children. Variable local samples are optional, separate from conformance, and
cannot qualify production resource budgets or authenticated retained versions.
"""
import argparse
import functools
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct
import sys

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("bulk_retention_oracle", HERE / "check_retention.py")
RET = importlib.util.module_from_spec(spec)
spec.loader.exec_module(RET)
BYTE = RET.BYTE
ZERO = BYTE.ZERO
def key(index):
    address = b'\x11' * 16 + index.to_bytes(4, 'big')
    return b'\x03' + address + b'\x03' + b'\x22' * 10

def identifier(item, height):
    keys, versions, churn = item['keys'], item['versions'], item['churn']
    return {'height':height,'hash':('00'*32 if height==0 else BYTE.digest(('synthetic-bulk-tail-v1/%d/%d/%d/A/%d' % (keys,versions,churn,height)).encode('ascii')).hex())}

@functools.lru_cache(maxsize=3)
def states(keys, versions, churn):
    state, history = {}, {0:{}}
    for height in range(1,versions+1):
        start,count=(0,keys) if height==1 else ((height-2)*churn%keys,churn)
        for offset in range(count):
            index=(start+offset)%keys
            path=BYTE.digest(key(index))
            if height>1 and height%3==0 and offset%3==0:
                state.pop(path,None)
            else:
                amount=0 if height>1 and height%4==0 and offset==1 else height*keys+index+1
                state[path]=amount.to_bytes(32,'big')
        history[height]=dict(state)
    return history

def seed_manifest(item, history):
    height=item['versions']-item['retain']+1
    rows={key(index):history[height][BYTE.digest(key(index))] for index in range(item['keys']) if BYTE.digest(key(index)) in history[height]}
    digest=hashlib.sha256()
    for raw,value in sorted(rows.items()):
        digest.update(struct.pack('>Q',len(raw))+raw+struct.pack('>Q',len(value))+value)
    return {'height':height,'present_keys':len(rows),'raw_map_sha256':digest.hexdigest()}

graph = RET.graph

def expected_storage(history, item):
    retained = list(range(max(1, item['versions'] - item['retain'] + 1), item['versions'] + 1))
    nodes, edges, root_ids = {}, {}, {}
    for height in retained:
        node, _, current, links = graph(history[height])
        root_ids[height] = node
        for node_id, encoded in current.items():
            BYTE.require(node_id not in nodes or nodes[node_id] == encoded, 'retained graph collision')
            nodes[node_id] = encoded
        edges.update(links)
    refs = {node: 0 for node in nodes}
    for node in root_ids.values():
        if node != ZERO:
            refs[node] += 1
    for left, right in edges.values():
        refs[left] += 1
        refs[right] += 1
    BYTE.require(all(count > 0 for count in refs.values()), 'unreachable independent graph node')
    selected = identifier(item, item['versions'])
    records = {b'\x00': bytes.fromhex(selected['hash']) + selected['height'].to_bytes(8, 'big'), b'\x05': b'\x02'}
    records.update({b'\x01' + node: encoded for node, encoded in nodes.items()})
    records.update({b'\x02' + node: count.to_bytes(8, 'big') for node, count in refs.items()})
    records.update({b'\x03' + height.to_bytes(8, 'big'): node for height, node in root_ids.items()})
    digest = hashlib.sha256()
    for k, v in sorted(records.items()):
        digest.update(struct.pack('>Q', len(k)) + k + struct.pack('>Q', len(v)) + v)
    return {'records': len(records), 'key_bytes': sum(map(len, records)), 'value_bytes': sum(map(len, records.values())),
            'family_counts': {'frontier': 1, 'format': 1, 'node': len(nodes), 'refcount': len(refs), 'version': len(retained)},
            'retained_heights': retained, 'records_sha256': digest.hexdigest()}

SCOPE = {**RET.SCOPE, 'actual_NodeTree_CommitBulk_executed':True, 'fixture_seed_not_authenticated_snapshot':True,'node_snapshot_import_executed':False,'historical_archive_replay_qualified':False}
NO_VERSION = "trie: no such version"
MAX_CASES = 6

def exact(actual, expected):
    BYTE.require(type(actual) is type(expected), "retention fixture scalar/container type differs")
    if type(expected) is dict:
        BYTE.require(set(actual) == set(expected), "retention fixture fields differ")
        for k, v in expected.items():
            exact(actual[k], v)
    elif type(expected) is list:
        BYTE.require(len(actual) == len(expected), "retention fixture inventory differs")
        for a, b in zip(actual, expected):
            exact(a, b)
    else:
        BYTE.require(actual == expected, "retention fixture bytes or selected policy differ")


WORKLOADS=((64,16,8),(256,32,32),(1024,64,128))
def selections():
    return tuple(("%s-%d-%d-%d" % (policy,keys,versions,churn),keys,versions,4,churn,policy)
                 for keys,versions,churn in WORKLOADS for policy in ('replay-pruned','bulk-tail'))

def query_indices(keys,versions,churn):
    return (-1,0,keys-1,keys,((versions-2)*churn%keys+1)%keys,(versions//3*3-2)*churn%keys)

@functools.lru_cache(maxsize=1)
def expected_cases():
    cases = []
    for name, keys, versions, retain, churn, policy in selections():
        item = {"name": name, "keys": keys, "versions": versions, "retain": retain, "churn":churn, "policy":policy}
        history = states(keys, versions, churn)
        stored = expected_storage(history, item)
        rows = []
        for height in (0, versions-4, versions-3, versions-2, versions-1, versions, versions+1):
            retained = height == 0 or height in stored["retained_heights"]
            if retained:
                state = history[height]
                levels, values = BYTE.tree_levels([{"path": p.hex(), "value": v.hex()} for p, v in state.items()])
                root = levels[0].get(0, ZERO)
                _, commitment, _, _ = graph(state)
                BYTE.require(root == commitment, "compressed DAG differs from full independent SMT")
            for index in query_indices(keys, versions, churn):
                row = {"identifier": identifier(item, height), "key": None, "root": None,
                       "value": None, "proof": None, "error": None if retained else NO_VERSION}
                if index == -1:
                    row["root"] = (root if retained else ZERO).hex()
                else:
                    raw = key(index)
                    row["key"] = raw.hex()
                    if retained:
                        path = BYTE.digest(raw)
                        value = state.get(path)
                        proof = BYTE.canonical_proof(levels, values, path)
                        row["value"] = None if value is None else value.hex()
                        row["proof"] = proof.hex()
                        BYTE.require(BYTE.proof_result(root, path, value or b"", proof, value is not None) == "match",
                                     "independent selected proof does not match")
                rows.append(row)
        seed=seed_manifest(item,history) if policy=='bulk-tail' else None
        patches=retain if policy=='bulk-tail' else versions
        operations=seed['present_keys']+(retain-1)*churn if seed else keys+(versions-1)*churn
        cases.append({"input": item, "patch_calls": patches, "input_operations": operations,
                      "commit_calls": patches-(1 if seed else 0), "bulk_commit_calls":1 if seed else 0, "regular_seed_commit_error":"trie: commit height must be exactly one above the frontier" if seed else None, "bulk_seed_manifest":seed, "prune_calls": 0 if seed else versions-retain, "manual_compaction_calls": 1,
                      "rounds": [{"round": i, "frontier": identifier(item, versions), "storage": stored, "reads": rows}
                                 for i in (0, 1, 2)]})
    return cases


def check_corpus(document):
    BYTE.require(type(document) is dict and set(document) == {"format_version", "kind", "backend", "source", "scope", "cases"},
                 "invalid retention corpus shape")
    exact(document["format_version"], 1)
    exact(document["kind"], "candidate-bulk-tail-research")
    exact(document["backend"], "NodeTree")
    exact(document["source"], {"repository": "https://github.com/digitalSloth/go-zenon",
                              "revision": BYTE.NODE_REVISION, "tree": BYTE.NODE_TREE})
    exact(document["scope"], SCOPE)
    BYTE.require(type(document["cases"]) is list and len(document["cases"]) <= MAX_CASES, "retention case bound exceeded")
    exact(document["cases"], expected_cases())
    reads = present = absent = unavailable = zeros = 0
    storage = []
    for case in document["cases"]:
        storage.append({"case": case["input"]["name"], **case["rounds"][0]["storage"]})
        for observed in case["rounds"]:
            for row in observed["reads"]:
                reads += 1
                if row["error"] is not None:
                    unavailable += 1
                elif row["key"] is not None:
                    present += int(row["value"] is not None)
                    absent += int(row["value"] is None)
                    zeros += int(row["value"] == "00" * 32)
    return {"bulk_tail_cases": len(document["cases"]), "conformance_rounds": MAX_CASES*3, "read_api_observations": reads,
            "unretained_version_errors": unavailable, "inclusion_proof_matches": present, "absence_proof_matches": absent,
            "stored_zero_inclusion_proof_matches": zeros, "independent_logical_records_one_round_per_case": storage,
            "fixture_seed_not_authenticated_snapshot":True, "node_snapshot_import_executed":False, "historical_archive_replay_qualified":False,
            "reference_backend_execution_in_checker": False, "native_reference_node_execution": False,
            "resource_measurements_executed_in_checker": False, "production_retention_resource_budgets_qualified": False,
            "authenticated_retained_version_provenance_qualified": False, "power_loss_qualified": False,
            "production_crash_recovery_qualified": False, "accepted_VerifiedState_binding_qualified": False,
            "profile_agreed": False, "network_activation_authenticated": False, "production_acceptance_enabled": False}


TIMINGS = ("initial_open_elapsed_ns", "fixture_input_preparation_elapsed_ns", "prepared_patch_update_commit_prune_elapsed_ns", "update_elapsed_ns",
           "commit_elapsed_ns", "prune_elapsed_ns", "initial_close_elapsed_ns", "reopen_elapsed_ns",
           "manual_compaction_elapsed_ns", "compacted_reopen_elapsed_ns")
PHYSICAL = ("closed_before_compaction", "closed_after_compaction", "closed_after_final_reopen")
RSS_METHOD = "getrusage(RUSAGE_SELF), child-process high-water mark; includes fixture, NodeTree and LevelDB"


def integer(value, minimum=0):
    BYTE.require(type(value) is int and minimum <= value < (1 << 63), "invalid resource integer/unit")


def digest_field(value):
    BYTE.require(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None, "invalid resource digest")


def check_resource_samples(document, corpus_sha256):
    fields = {"format_version", "kind", "source", "corpus_sha256", "conformance_runs", "measurement_runs_expected_to_vary",
              "production_resource_budgets_qualified", "source_execution_platform", "go_version", "reference_binary_sha256", "samples", "commands"}
    BYTE.require(type(document) is dict and set(document) == fields, "invalid separate resource sample shape")
    for k, v in (("format_version", 1), ("kind", "candidate-bulk-tail-samples"), ("conformance_runs", 2),
                 ("measurement_runs_expected_to_vary", True), ("production_resource_budgets_qualified", False),
                 ("source", {"repository": "https://github.com/digitalSloth/go-zenon", "revision": BYTE.NODE_REVISION, "tree": BYTE.NODE_TREE}),
                 ("corpus_sha256", corpus_sha256)):
        exact(document[k], v)
    BYTE.require(type(document["source_execution_platform"]) is str and document["source_execution_platform"] in ("darwin", "linux"), "unsupported resource platform")
    BYTE.require(type(document["go_version"]) is str and re.fullmatch(r"go version go1\.25\.[0-9]+ (darwin|linux)/[a-z0-9]+", document["go_version"]) is not None, "invalid reference toolchain")
    digest_field(document["reference_binary_sha256"])
    platform = document["go_version"].rsplit(" ", 1)[1]
    BYTE.require(platform.split("/")[0] == document["source_execution_platform"], "resource/toolchain platform differs")
    BYTE.require(type(document["commands"]) is list and len(document["commands"]) == 2, "resource command inventory differs")
    for label, command in zip(("generate-first", "generate-second"), document["commands"]):
        BYTE.require(type(command) is dict and set(command) == {"label", "completed", "actual_exit", "stdout_sha256", "stderr_sha256"}, "invalid resource command")
        for k, v in (("label", label), ("completed", True), ("actual_exit", 0), ("stderr_sha256", hashlib.sha256(b"").hexdigest())):
            exact(command[k], v)
        digest_field(command["stdout_sha256"])
    BYTE.require(type(document["samples"]) is list and len(document["samples"]) == 2, "resource sample run inventory differs")
    for run in document["samples"]:
        BYTE.require(type(run) is list and len(run) == MAX_CASES, "resource sample case inventory differs")
        for sample, (name, _, versions, retain, _, policy) in zip(run, selections()):
            fields = {"case", "platform", "peak_rss_bytes", "peak_rss_method", "query_timings", *TIMINGS, *PHYSICAL}
            BYTE.require(type(sample) is dict and set(sample) == fields, "resource sample fields differ")
            exact(sample["case"], name)
            exact(sample["platform"], platform)
            exact(sample["peak_rss_method"], RSS_METHOD)
            integer(sample["peak_rss_bytes"], 1)
            for field in TIMINGS:
                integer(sample[field])
            if policy == "bulk-tail":
                exact(sample["prune_elapsed_ns"], 0)
            BYTE.require(sum(sample[k] for k in ("update_elapsed_ns", "commit_elapsed_ns", "prune_elapsed_ns")) <=
                         sample["prepared_patch_update_commit_prune_elapsed_ns"], "resource aggregate time differs")
            BYTE.require(type(sample["query_timings"]) is list and len(sample["query_timings"]) == 3, "resource query rounds differ")
            for query in sample["query_timings"]:
                BYTE.require(type(query) is dict and set(query) == {"root_calls", "root_elapsed_ns", "proof_calls", "proof_elapsed_ns"}, "invalid query time fields")
                exact(query["root_calls"], 7)
                exact(query["proof_calls"], 35)
                integer(query["root_elapsed_ns"])
                integer(query["proof_elapsed_ns"])
            for field in PHYSICAL:
                physical = sample[field]
                BYTE.require(type(physical) is dict and set(physical) == {"regular_files", "file_bytes", "largest_file_bytes"}, "invalid closed file observations")
                for k in physical:
                    integer(physical[k], 1)
                BYTE.require(physical["largest_file_bytes"] <= physical["file_bytes"] <= physical["regular_files"] * physical["largest_file_bytes"], "inconsistent file lengths")
    return {"resource_sample_runs": 2, "separate_variable_local_samples": True,
            "sample_shape_and_corpus_binding_checked": True, "sample_execution_independently_reproduced": False,
            "resource_budget_acceptance": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, default=HERE / "testdata/candidate-bulk-tail.json")
    parser.add_argument("--resource-samples", type=Path)
    parser.add_argument("--source-revision")
    args = parser.parse_args(argv)
    raw, document = BYTE.read_corpus(args.corpus)
    report = check_corpus(document)
    report.update({"source_revision": args.source_revision, "corpus_sha256": hashlib.sha256(raw).hexdigest(),
                   "node_revision": BYTE.NODE_REVISION, "node_tree": BYTE.NODE_TREE})
    if args.resource_samples is not None:
        _, samples = BYTE.read_corpus(args.resource_samples)
        report.update(check_resource_samples(samples, report["corpus_sha256"]))
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError):
        print("Candidate bulk tail conformance failed; production acceptance remains disabled.", file=sys.stderr)
        sys.exit(1)
