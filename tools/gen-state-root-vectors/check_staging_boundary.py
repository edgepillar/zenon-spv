#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Independently check serial staging, replacement and injected replay failures.

The default LevelDB batch replay returns nil. Custom interface faults are research
inputs, while full SMT/proof and compressed physical-store math are independent.
Every synthetic consumer refuses, including the healthy replay control.
"""
import argparse
import functools
import hashlib
import importlib.util
from pathlib import Path
import struct
import sys
import json

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("staging_retention_oracle", HERE / "check_retention.py")
RET = importlib.util.module_from_spec(spec)
spec.loader.exec_module(RET)
BYTE, ZERO = RET.BYTE, RET.ZERO
NO_VERSION = "trie: no such version"
NOT_STAGED = "trie: commit called without a staged write-set"
REGULAR_ORDER = "trie: commit height must be exactly one above the frontier"
BULK_ORDER = "trie: bulk commit height must be above the frontier"
SCOPE = {"synthetic": True, "unsigned": True, "actual_NodeTree_disk_APIs_executed": True,
         "actual_NodeTree_CommitBulk_executed": True, "actual_NodeTree_AccumulateFrom_executed": True, "custom_Patch_Replay_errors_injected": True, "default_Batch_Replay_executed": True, "default_Batch_Replay_failure_observed": False, "production_replay_failure_qualified": False,
         "single_serial_caller_for_staged_sequence": True, "small_owned_temporary_disk_LevelDB": True,
         "controlled_clean_reopen_executed": True, "manual_compaction_executed": True,
         "logical_storage_records_measured": True, "owned_databases_removed": True,
         "selected_fixture_not_authenticated_snapshot": True,
         **{name: False for name in ("resource_measurements_executed", "chain_component_Init_executed",
            "chain_Start_executed", "background_build_executed", "full_node_started", "node_tests_executed",
            "network_execution", "RPC_executed", "signing", "transactions", "power_loss_qualified",
            "production_crash_recovery_qualified", "authenticated_retained_version_provenance_qualified",
            "realistic_retention_resource_budgets_qualified", "profile_agreed", "network_activation_authenticated",
            "runtime_state_proof_acceptance")}}
def key(index):
    return b'\x03' + b'\x11' * 16 + index.to_bytes(4, 'big') + b'\x03' + b'\x22' * 10


def identifier(name, height):
    return {"height": height, "hash": (ZERO if height == 0 else BYTE.digest(
        ("synthetic-staging-boundary-v1/%s/A/%d" % (name, height)).encode('ascii'))).hex()}


def complete():
    return {i: (0 if i == 0 else i + 1).to_bytes(32, 'big') for i in range(8)}


REPLAY_FAILURE = "synthetic Patch.Replay failure"
NAMES = ("update-error-keeps-prior-stage", "accumulate-error-keeps-prefix",
         "update-initial-error-not-staged", "accumulate-initial-error-is-staged",
         "update-replaces-accumulation", "clean-reopen-clears-staging", "default-accumulation-control")


def patches():
    return {"complete": list(complete().items()), "changes": [(1, (91).to_bytes(32, 'big')), (2, None), (8, (9).to_bytes(32, 'big'))]}


def actions(name):
    a = [("fresh", "observe", None, None, None)]
    if name == NAMES[0]:
        a += [("complete-stage", "Update", "complete", None, None),
              ("update-prefix-error", "Update", "changes", None, 2),
              ("commit-after-error", "Commit", None, 1, None)]
    elif name == NAMES[1]:
        a += [("complete-accumulation", "AccumulateFrom", "complete", None, None),
              ("accumulate-prefix-error", "AccumulateFrom", "changes", None, 2),
              ("bulk-after-error", "CommitBulk", None, 10, None)]
    elif name == NAMES[2]:
        a += [("update-empty-error", "Update", "changes", None, 0),
              ("commit-empty-error-refused", "Commit", None, 1, None),
              ("update-first-put-error", "Update", "changes", None, 1),
              ("commit-first-put-error-refused", "Commit", None, 1, None),
              ("complete-retry", "Update", "changes", None, None),
              ("commit-after-retry", "Commit", None, 1, None)]
    elif name == NAMES[3]:
        a += [("accumulate-empty-error", "AccumulateFrom", "changes", None, 0),
              ("commit-empty-error", "Commit", None, 1, None),
              ("accumulate-first-put-error", "AccumulateFrom", "changes", None, 1),
              ("commit-first-put-error", "Commit", None, 2, None)]
    elif name == NAMES[4]:
        a += [("complete-accumulation", "AccumulateFrom", "complete", None, None),
              ("update-replaces-stage", "Update", "changes", None, None),
              ("bulk-after-replacement", "CommitBulk", None, 10, None)]
    elif name == NAMES[5]:
        a += [("complete-stage", "Update", "complete", None, None),
              ("seed-commit", "Commit", None, 1, None),
              ("accumulate-prefix-error", "AccumulateFrom", "changes", None, 2),
              ("interrupted-stage-clean-reopen", "reopen", None, None, None),
              ("commit-after-reopen-refused", "Commit", None, 2, None),
              ("full-patch-retry", "AccumulateFrom", "changes", None, None),
              ("commit-after-retry", "Commit", None, 2, None)]
    elif name == NAMES[6]:
        a += [("complete-accumulation", "AccumulateFrom", "complete", None, None),
              ("changes-accumulation", "AccumulateFrom", "changes", None, None),
              ("bulk-after-default-replay", "CommitBulk", None, 10, None)]
    else:
        raise ValueError("unselected staging-boundary case")
    return a + [("clean-reopen", "reopen", None, None, None), ("compacted-clean-reopen", "compact-reopen", None, None, None)]


def selected_state(name):
    state = {} if name in (NAMES[2], NAMES[3]) else complete()
    state[1] = (91).to_bytes(32, 'big'); state.pop(2, None); state[8] = (9).to_bytes(32, 'big')
    return state


@functools.lru_cache(maxsize=16)
def tree(state_items):
    state = {BYTE.digest(key(i)): value for i, value in state_items}
    levels, values = BYTE.tree_levels([{"path": p.hex(), "value": v.hex()} for p, v in state.items()])
    root = levels[0].get(0, ZERO)
    BYTE.require(RET.graph(state)[1] == root, "compressed DAG differs from full independent SMT")
    return state, levels, values, root


def manifest(state):
    digest = hashlib.sha256()
    for i, value in sorted(state.items()):
        raw = key(i)
        digest.update(struct.pack('>Q', len(raw)) + raw + struct.pack('>Q', len(value)) + value)
    return {"present_keys": len(state), "raw_map_sha256": digest.hexdigest()}


def storage(name, frontier, versions):
    nodes, links, roots = {}, {}, {}
    for height, raw_state in sorted(versions.items()):
        state = {BYTE.digest(key(i)): v for i, v in raw_state.items()}
        node, _, graph, edges = RET.graph(state)
        roots[height] = node
        for node_id, encoded in graph.items():
            BYTE.require(node_id not in nodes or nodes[node_id] == encoded, "retained graph collision")
            nodes[node_id] = encoded
        links.update(edges)
    refs = {node: 0 for node in nodes}
    for node in roots.values():
        if node != ZERO:
            refs[node] += 1
    for left, right in links.values():
        refs[left] += 1
        refs[right] += 1
    BYTE.require(all(n > 0 for n in refs.values()), "unreachable independent height-boundary node")
    records = {b'\x05': b'\x02'}
    if versions:
        records[b'\x00'] = bytes.fromhex(identifier(name, frontier)['hash']) + frontier.to_bytes(8, 'big')
    records.update({b'\x01' + node: encoded for node, encoded in nodes.items()})
    records.update({b'\x02' + node: count.to_bytes(8, 'big') for node, count in refs.items()})
    records.update({b'\x03' + height.to_bytes(8, 'big'): node for height, node in roots.items()})
    digest = hashlib.sha256()
    for raw, value in sorted(records.items()):
        digest.update(struct.pack('>Q', len(raw)) + raw + struct.pack('>Q', len(value)) + value)
    return {"records": len(records), "key_bytes": sum(map(len, records)), "value_bytes": sum(map(len, records.values())),
            "family_counts": {"frontier": int(bool(versions)), "format": 1, "node": len(nodes), "refcount": len(refs), "version": len(roots)},
            "retained_heights": sorted(roots), "records_sha256": digest.hexdigest()}


def reads(name, versions):
    rows = []
    for height in (0, 1, 2, 10):
        retained = height == 0 or height in versions
        if retained:
            state, levels, values, root = tree(tuple(sorted((versions.get(height, {}) if height != 0 else {}).items())))
        for index in (-1, 0, 1, 2, 8):
            row = {"identifier": identifier(name, height), "key": None, "root": None, "value": None,
                   "proof": None, "error": None if retained else NO_VERSION}
            if index == -1:
                row['root'] = (root if retained else ZERO).hex()
            else:
                raw = key(index)
                row['key'] = raw.hex()
                if retained:
                    path = BYTE.digest(raw)
                    value = state.get(path)
                    proof = BYTE.canonical_proof(levels, values, path)
                    row['value'], row['proof'] = None if value is None else value.hex(), proof.hex()
                    BYTE.require(BYTE.proof_result(root, path, value or b'', proof, value is not None) == 'match',
                                 "independent height proof does not match its selected version")
            rows.append(row)
    return rows


@functools.lru_cache(maxsize=1)
def expected_cases():
    cases, plans = [], patches()
    for name in NAMES:
        frontier, versions, staged, steps = 0, {}, None, []
        for label, operation, patch, height, cut in actions(name):
            error, callbacks = None, None
            if operation in ('Update', 'AccumulateFrom'):
                delivered = plans[patch] if cut is None else plans[patch][:cut]
                callbacks = [{"operation": "Delete" if value is None else "Put", "key": key(i).hex(),
                              "value": None if value is None else value.hex()} for i, value in delivered]
                if cut is not None:
                    error = REPLAY_FAILURE
                if operation == 'Update':
                    # Replay targets a private replacement; an error never swaps it in.
                    if cut is None:
                        staged = dict(delivered)
                else:
                    # Accumulation initializes its shared map before replay, even
                    # when no callback runs. Prefix callbacks remain on error.
                    if staged is None:
                        staged = {}
                    staged.update(delivered)
            elif operation in ('Commit', 'CommitBulk'):
                if staged is None:
                    error = NOT_STAGED
                elif operation == 'Commit' and height != frontier + 1:
                    error = REGULAR_ORDER
                elif operation == 'CommitBulk' and height <= frontier:
                    error = BULK_ORDER
                else:
                    state = dict(versions.get(frontier, {}))
                    for i, value in staged.items():
                        if value is None:
                            state.pop(i, None)
                        else:
                            state[i] = value
                    versions[height], frontier, staged = state, height, None
            elif operation in ('reopen', 'compact-reopen'):
                staged = None
            elif operation != 'observe':
                raise ValueError('unselected staging operation')
            steps.append({"label": label, "operation": operation, "patch": patch, "target_height": height,
                          "fault_after_callbacks": cut, "replay_callbacks": callbacks, "operation_error": error,
                          "frontier": identifier(name, frontier), "storage": storage(name, frontier, versions),
                          "reads": reads(name, versions)})
        selected = selected_state(name)
        selected_root = tree(tuple(sorted(selected.items())))[3]
        state, levels, values, root = tree(tuple(sorted(versions[frontier].items())))
        checks = []
        for index in (0, 1, 2, 8):
            raw, path = key(index), BYTE.digest(key(index))
            value = state.get(path)
            proof = BYTE.canonical_proof(levels, values, path)
            checks.append({"key": raw.hex(), "value": None if value is None else value.hex(), "proof": proof.hex(),
                           "own_root_result": BYTE.proof_result(root, path, value or b'', proof, value is not None),
                           "selected_fixture_result": BYTE.proof_result(selected_root, path, value or b'', proof, value is not None)})
        cases.append({"name": name, "steps": steps, "boundary": {"identifier": identifier(name, frontier),
                      "selected_fixture_root": selected_root.hex(), "selected_fixture_manifest": manifest(selected),
                      "observed_root": root.hex(), "root_matches_selected_fixture": root == selected_root,
                      "production_replay_failure_qualified": False, "consumer_result": "REFUSED", "proof_checks": checks}})
    return cases


def check_corpus(document):
    RET.exact(document, {"format_version": 1, "kind": "candidate-staging-boundary-research", "backend": "NodeTree",
        "source": {"repository": "https://github.com/digitalSloth/go-zenon", "revision": BYTE.NODE_REVISION, "tree": BYTE.NODE_TREE},
        "scope": SCOPE, "cases": expected_cases()})
    snapshots = [step for case in document['cases'] for step in case['steps']]
    rows = [row for step in snapshots for row in step['reads']]
    boundary = [row for case in document['cases'] for row in case['boundary']['proof_checks']]
    replay = [step for step in snapshots if step['replay_callbacks'] is not None]
    commits_after_error = [right for case in document['cases'] for left, right in zip(case['steps'], case['steps'][1:])
                           if left['operation_error'] == REPLAY_FAILURE and right['operation'] in ('Commit', 'CommitBulk')]
    return {"staging_boundary_cases": len(NAMES), "logical_store_snapshots": len(snapshots), "read_api_observations": len(rows),
            "custom_Replay_error_returns": sum(step['operation_error'] == REPLAY_FAILURE for step in replay),
            "default_Batch_Replay_success_returns": sum(step['fault_after_callbacks'] is None for step in replay),
            "recorded_replay_callbacks": sum(len(step['replay_callbacks']) for step in replay),
            "successful_commits_immediately_after_Replay_error": sum(step['operation_error'] is None for step in commits_after_error),
            "not_staged_commit_refusals": sum(step['operation_error'] == NOT_STAGED for step in snapshots),
            "unretained_version_errors": sum(row['error'] is not None for row in rows),
            "inclusion_proof_matches": sum(row['key'] is not None and row['value'] is not None for row in rows),
            "absence_proof_matches": sum(row['key'] is not None and row['value'] is None and row['error'] is None for row in rows),
            "stored_zero_inclusion_proof_matches": sum(row['value'] == '00' * 32 for row in rows),
            "own_root_boundary_proof_matches": sum(row['own_root_result'] == 'match' for row in boundary),
            "selected_fixture_boundary_proof_matches": sum(row['selected_fixture_result'] == 'match' for row in boundary),
            "selected_fixture_boundary_proof_mismatches": sum(row['selected_fixture_result'] == 'mismatch' for row in boundary),
            "root_matches_selected_fixture_cases": sum(case['boundary']['root_matches_selected_fixture'] for case in document['cases']),
            "consumer_refusals": sum(case['boundary']['consumer_result'] == 'REFUSED' for case in document['cases']),
            "reference_backend_execution_in_checker": False, "native_reference_node_execution": False,
            "resource_measurements_executed_in_checker": False, "production_retention_resource_budgets_qualified": False,
            "default_Batch_Replay_failure_observed": False, "production_replay_failure_qualified": False,
            "authenticated_retained_version_provenance_qualified": False, "power_loss_qualified": False,
            "production_crash_recovery_qualified": False, "accepted_VerifiedState_binding_qualified": False,
            "profile_agreed": False, "network_activation_authenticated": False, "production_acceptance_enabled": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--corpus', type=Path, default=HERE / 'testdata/candidate-staging-boundary.json')
    parser.add_argument('--source-revision')
    args = parser.parse_args(argv)
    raw, document = BYTE.read_corpus(args.corpus)
    report = check_corpus(document)
    report.update({"source_revision": args.source_revision, "corpus_sha256": hashlib.sha256(raw).hexdigest(),
                   "node_revision": BYTE.NODE_REVISION, "node_tree": BYTE.NODE_TREE})
    print(json.dumps(report, sort_keys=True, separators=(',', ':')))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError):
        print('Candidate staging-boundary conformance failed; production acceptance remains disabled.', file=sys.stderr)
        sys.exit(1)
