#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Independent finite bulk guards, staged retry, fold and shared-root records.

This checker reconstructs full sparse proofs and compressed persistent graphs.
It never opens LevelDB or executes the reference backend. A coherent proof from
an incomplete fixture is checked against the separately selected complete root;
synthetic selection does not authenticate a network snapshot or retained hash.
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
spec = importlib.util.spec_from_file_location("guard_retention_oracle", HERE / "check_retention.py")
RET = importlib.util.module_from_spec(spec)
spec.loader.exec_module(RET)
BYTE, ZERO = RET.BYTE, RET.ZERO
NO_VERSION = "trie: no such version"
NOT_STAGED = "trie: commit called without a staged write-set"
REGULAR_ORDER = "trie: commit height must be exactly one above the frontier"
BULK_ORDER = "trie: bulk commit height must be above the frontier"
NAMES = ("guards-and-shared-root", "accumulated-zero-delete-reinsert", "omitted-seed-zero", "omitted-accumulated-delete")
SCOPE = {"synthetic": True, "unsigned": True, "actual_NodeTree_disk_APIs_executed": True,
         "actual_NodeTree_CommitBulk_executed": True, "actual_NodeTree_AccumulateFrom_executed": True,
         "single_serial_caller_for_staged_sequence": True, "small_owned_temporary_disk_LevelDB": True,
         "controlled_clean_reopen_executed": True, "manual_compaction_executed": True,
         "logical_storage_records_measured": True, "owned_databases_removed": True,
         "selected_complete_fixture_not_authenticated_snapshot": True,
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
        ("synthetic-bulk-guards-v1/%s/A/%d" % (name, height)).encode('ascii'))).hex()}


def complete():
    return {i: (0 if i == 0 else i + 1).to_bytes(32, 'big') for i in range(8)}


def patches():
    return {"complete": complete(), "empty": {},
            "without-zero": {i: v for i, v in complete().items() if i != 0},
            "fold-two": {1: (17).to_bytes(32, 'big'), 2: None, 3: bytes(32), 7: None},
            "fold-three": {1: None, 2: (22).to_bytes(32, 'big'), 7: bytes(32)},
            "tail-four": {0: None, 1: bytes(32), 7: (47).to_bytes(32, 'big')},
            "without-delete": {1: bytes(32)}}


def actions(name):
    a = [("fresh", "observe", None, None)]
    if name == NAMES[0]:
        a += [("unstaged-bulk", "CommitBulk", None, 3),
              ("empty-stage", "Update", "empty", None), ("origin-bulk-refused", "CommitBulk", None, 0),
              ("replace-with-complete-seed", "Update", "complete", None),
              ("regular-gap-refused", "Commit", None, 3), ("retry-seed-as-bulk", "CommitBulk", None, 3),
              ("consumed-bulk-stage", "CommitBulk", None, 4), ("empty-reuse-stage", "Update", "empty", None),
              ("same-height-refused", "CommitBulk", None, 3), ("backward-height-refused", "CommitBulk", None, 2),
              ("retry-empty-bulk", "CommitBulk", None, 5), ("consumed-regular-stage", "Commit", None, 6),
              ("empty-tail-stage", "Update", "empty", None), ("regular-no-op-tail", "Commit", None, 6),
              ("prune-shared-roots", "Prune", None, 6)]
    elif name == NAMES[1]:
        a += [("accumulate-complete", "AccumulateFrom", "complete", None),
              ("accumulate-delete-zero", "AccumulateFrom", "fold-two", None),
              ("accumulate-reinsert", "AccumulateFrom", "fold-three", None),
              ("commit-folded-seed", "CommitBulk", None, 3), ("tail-delete-zero", "Update", "tail-four", None),
              ("commit-tail", "Commit", None, 4), ("empty-fold-stage", "Update", "empty", None),
              ("shared-folded-root", "CommitBulk", None, 6), ("prune-old-seed", "Prune", None, 4),
              ("prune-shared-tail", "Prune", None, 6)]
    elif name == NAMES[2]:
        a += [("incomplete-zero-stage", "Update", "without-zero", None),
              ("commit-incomplete-zero", "CommitBulk", None, 3), ("incomplete-no-op-stage", "Update", "empty", None),
              ("reuse-incomplete-root", "CommitBulk", None, 5), ("prune-incomplete-seed", "Prune", None, 5)]
    elif name == NAMES[3]:
        a += [("complete-base-stage", "Update", "complete", None), ("complete-base", "CommitBulk", None, 3),
              ("incomplete-delete-stage", "AccumulateFrom", "without-delete", None),
              ("commit-incomplete-delete", "CommitBulk", None, 5), ("prune-complete-base", "Prune", None, 5)]
    else:
        raise ValueError("unselected bulk guard case")
    return a + [("clean-reopen", "reopen", None, None), ("compacted-clean-reopen", "compact-reopen", None, None)]


def selected_state(name):
    selected = complete()
    if name == NAMES[1]:
        del selected[0]
        selected.update({1: bytes(32), 2: (22).to_bytes(32, 'big'), 3: bytes(32), 7: (47).to_bytes(32, 'big')})
    elif name == NAMES[3]:
        selected[1] = bytes(32)
        del selected[2]
    return selected


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
    BYTE.require(all(n > 0 for n in refs.values()), "unreachable independent guard node")
    records = {b'\x05': b'\x02'}
    if frontier:
        records[b'\x00'] = bytes.fromhex(identifier(name, frontier)['hash']) + frontier.to_bytes(8, 'big')
    records.update({b'\x01' + node: encoded for node, encoded in nodes.items()})
    records.update({b'\x02' + node: count.to_bytes(8, 'big') for node, count in refs.items()})
    records.update({b'\x03' + height.to_bytes(8, 'big'): node for height, node in roots.items()})
    digest = hashlib.sha256()
    for raw, value in sorted(records.items()):
        digest.update(struct.pack('>Q', len(raw)) + raw + struct.pack('>Q', len(value)) + value)
    return {"records": len(records), "key_bytes": sum(map(len, records)), "value_bytes": sum(map(len, records.values())),
            "family_counts": {"frontier": int(frontier != 0), "format": 1, "node": len(nodes), "refcount": len(refs), "version": len(roots)},
            "retained_heights": sorted(roots), "records_sha256": digest.hexdigest()}


def reads(name, versions):
    rows = []
    for height in range(8):
        retained = height == 0 or height in versions
        if retained:
            state, levels, values, root = tree(tuple(sorted(versions.get(height, {}).items())))
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
                                 "independent guard proof does not match its selected version")
            rows.append(row)
    return rows


@functools.lru_cache(maxsize=1)
def expected_cases():
    cases = []
    plans = patches()
    for name in NAMES:
        frontier, versions, staged, steps = 0, {}, None, []
        for label, operation, patch, height in actions(name):
            error = None
            if operation == 'Update':
                staged = dict(plans[patch])
            elif operation == 'AccumulateFrom':
                if staged is None:
                    staged = {}
                staged.update(plans[patch])
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
            elif operation == 'Prune':
                versions = {h: s for h, s in versions.items() if h >= height}
            steps.append({"label": label, "operation": operation, "patch": patch, "target_height": height,
                          "operation_error": error, "frontier": identifier(name, frontier),
                          "storage": storage(name, frontier, versions), "reads": reads(name, versions)})
        selected = selected_state(name)
        selected_root = tree(tuple(sorted(selected.items())))[3]
        state, levels, values, root = tree(tuple(sorted(versions[frontier].items())))
        checks = []
        for index in (0, 1, 2, 8):
            raw = key(index)
            path = BYTE.digest(raw)
            value = state.get(path)
            proof = BYTE.canonical_proof(levels, values, path)
            checks.append({"key": raw.hex(), "value": None if value is None else value.hex(), "proof": proof.hex(),
                           "own_root_result": BYTE.proof_result(root, path, value or b'', proof, value is not None),
                           "selected_complete_fixture_result": BYTE.proof_result(selected_root, path, value or b'', proof, value is not None)})
        cases.append({"name": name, "steps": steps, "boundary": {"identifier": identifier(name, frontier),
                      "selected_complete_fixture_root": selected_root.hex(), "selected_complete_fixture_manifest": manifest(selected),
                      "observed_root": root.hex(), "root_matches_selected_complete_fixture": root == selected_root, "proof_checks": checks}})
    return cases


def check_corpus(document):
    RET.exact(document, {"format_version": 1, "kind": "candidate-bulk-guards-research", "backend": "NodeTree",
        "source": {"repository": "https://github.com/digitalSloth/go-zenon", "revision": BYTE.NODE_REVISION, "tree": BYTE.NODE_TREE},
        "scope": SCOPE, "cases": expected_cases()})
    snapshots = [step for case in document['cases'] for step in case['steps']]
    rows = [row for step in snapshots for row in step['reads']]
    boundary = [row for case in document['cases'] for row in case['boundary']['proof_checks']]
    return {"bulk_guard_cases": 4, "logical_store_snapshots": len(snapshots), "read_api_observations": len(rows),
            "operation_guard_refusals": sum(step['operation_error'] is not None for step in snapshots),
            "unretained_version_errors": sum(row['error'] is not None for row in rows),
            "inclusion_proof_matches": sum(row['key'] is not None and row['value'] is not None for row in rows),
            "absence_proof_matches": sum(row['key'] is not None and row['value'] is None and row['error'] is None for row in rows),
            "stored_zero_inclusion_proof_matches": sum(row['value'] == '00' * 32 for row in rows),
            "own_root_boundary_proof_matches": sum(row['own_root_result'] == 'match' for row in boundary),
            "selected_complete_fixture_proof_refusals": sum(row['selected_complete_fixture_result'] == 'mismatch' for row in boundary),
            "incomplete_fixture_root_refusals": sum(not case['boundary']['root_matches_selected_complete_fixture'] for case in document['cases']),
            "reference_backend_execution_in_checker": False, "native_reference_node_execution": False,
            "resource_measurements_executed_in_checker": False, "production_retention_resource_budgets_qualified": False,
            "authenticated_retained_version_provenance_qualified": False, "power_loss_qualified": False,
            "production_crash_recovery_qualified": False, "accepted_VerifiedState_binding_qualified": False,
            "profile_agreed": False, "network_activation_authenticated": False, "production_acceptance_enabled": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--corpus', type=Path, default=HERE / 'testdata/candidate-bulk-guards.json')
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
        print('Candidate bulk guard conformance failed; production acceptance remains disabled.', file=sys.stderr)
        sys.exit(1)
