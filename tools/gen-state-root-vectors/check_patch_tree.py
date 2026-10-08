#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Independently bind a finite opened-file to low-level NodeTree seed handoff.

Reconstruct literal inputs, complete maps, full sparse proofs and compressed
physical records/refcounts without executing Go or opening LevelDB. Recorded
local phase allocation, elapsed time, closed files and lifetime RSS are separate
unsigned observations. No authenticated snapshot, retained hash or budget follows.
"""
import argparse
import functools
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys

HERE = Path(__file__).resolve().parent


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, HERE / file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


FILE = load('tree_file_oracle', 'check_patch_file.py')
RESOURCE = load('tree_resource_bindings', 'check_patch_resources.py')
GUARD = load('tree_graph_oracle', 'check_bulk_guards.py')
BYTE, DEC, ZERO = FILE.BYTE, FILE.DEC, GUARD.ZERO
NAMES = ('empty-complete', 'complete-stored-zero', 'complete-256', 'delete-reinsert',
    'file-selection-refusal', 'transient-cap-refusal', 'unsupported-key-refusal',
    'empty-value-refusal', 'wrong-selected-root-refusal', 'omitted-zero-refusal', 'omitted-delete-refusal')
BUILD_NAMES = ('main.go', 'go.mod', 'go.sum', 'patch_decode.go', 'patch_import.go', 'patch_targets.go',
               'patch_resources.go', 'patch_file.go', 'bulk_guards.go', 'patch_tree_test.go')
INPUT_NAMES = BUILD_NAMES + ('source-pins.json', 'regenerate.py', 'reproduce_patch_tree.py', 'check_patch_tree.py',
    'check_patch_tree_test.py', 'check_patch_file.py', 'check_patch_resources.py', 'check_patch_targets.py',
    'check_patch_import.py', 'check_patch_decode.py', 'check_bulk_guards.py', 'check_retention.py', 'check.py')
PHASES = ('opened-file-to-owned-map', 'complete-balance-map-and-root-selection', 'open-fresh-NodeTree',
    'complete-sorted-seed-patch-and-Update', 'CommitBulk', 'clean-close', 'clean-reopen-NodeTree', 'final-clean-close')
PEAK_METHOD = ('getrusage(RUSAGE_SELF) after final phase and closed-file inventory, before final result binding/serialization; '
    'lifetime high water includes startup, fixture/selection/pre-operation GC, interim conformance queries and inventory')
SCOPE = {name: True for name in ('synthetic', 'unsigned', 'opened_stable_regular_file_required', 'single_exclusive_caller',
    'owned_complete_finite_balance_maps', 'root_selection_precedes_storage_creation', 'actual_NewPatchFromDump_executed',
    'actual_NodeTree_Update_CommitBulk_executed', 'fresh_owned_temporary_LevelDB', 'controlled_clean_reopen_executed',
    'complete_original_alias_and_callback_bindings', 'full_sparse_and_compressed_graph_oracles',
    'named_phases_separately_measured', 'phase_timing_excludes_interim_queries_and_report', 'fresh_child_per_sample')}
SCOPE.update({name: False for name in ('cold_disk_behavior_qualified', 'atomic_filesystem_snapshot', 'shared_writer_atomicity',
    'crash_durability', 'authenticated_snapshot_import', 'excluded_state_authenticated', 'retained_Momentum_hash_provenance',
    'actual_chain_component_executed', 'realistic_archive_or_retention_workload', 'production_resource_budgets_qualified',
    'latency_speedup_qualified', 'network_execution', 'full_node_started', 'signing', 'transactions', 'profile_agreed',
    'network_activation_authenticated', 'accepted_VerifiedState_binding', 'execution_provenance_authenticated', 'runtime_state_proof_acceptance')})


def require(condition):
    if not condition:
        raise ValueError('Tree handoff evidence differs from its selected boundary')


def complete(count=8):
    return {i: (0 if i == 0 else i + 1).to_bytes(32, 'big') for i in range(count)}


def selected(name):
    state = complete(0 if name == 'empty-complete' else 256 if name == 'complete-256' else 8)
    if name == 'delete-reinsert':
        del state[2]
        state.update({1: bytes(32), 6: bytes(32), 8: (10).to_bytes(32, 'big')})
    if name == 'omitted-delete-refusal':
        del state[2]
        state[1] = bytes(32)
    return state


def inputs():
    rows = []
    for name in NAMES:
        initial, events, caps = {}, [], FILE.TARGET.CEILINGS.copy()
        if name in ('delete-reinsert', 'transient-cap-refusal', 'unsupported-key-refusal', 'empty-value-refusal', 'omitted-delete-refusal'):
            initial = {GUARD.key(i).hex(): v.hex() for i, v in complete().items()}
            if name == 'delete-reinsert':
                events = [(GUARD.key(2), None), (GUARD.key(1), bytes(32)), (GUARD.key(8), (9).to_bytes(32, 'big')),
                          (GUARD.key(8), (10).to_bytes(32, 'big')), (GUARD.key(6), None), (GUARD.key(6), bytes(32))]
            if name == 'transient-cap-refusal':
                caps = {'entries': 8, 'hex_bytes': 1024}
                events = [(GUARD.key(8), (10).to_bytes(32, 'big')), (GUARD.key(2), None)]
            if name == 'unsupported-key-refusal':
                key = GUARD.key(8)
                events = [(key[:21] + b'\x05' + key[22:], (9).to_bytes(32, 'big'))]
            if name == 'empty-value-refusal': events = [(GUARD.key(8), b'')]
            if name == 'omitted-delete-refusal': events = [(GUARD.key(1), bytes(32))]
        else:
            state = complete(0 if name == 'empty-complete' else 256 if name == 'complete-256' else 8)
            events = [(GUARD.key(i), value) for i, value in sorted(state.items()) if name != 'omitted-zero-refusal' or i != 0]
        raw = b''.join(DEC.record(int(value is not None), key, value or b'') for key, value in events)
        choice = {'name': name, 'bytes': len(raw), 'records': len(events), 'changes_hash': BYTE.digest(raw).hex()}
        if name == 'file-selection-refusal': choice['changes_hash'] = ZERO.hex()
        rows.append({'name': name, 'raw': raw, 'limits': FILE.IMP.CEILINGS.copy(), 'selection': choice,
                     'fault': 'none', 'source_fault': 'none', 'target': initial, 'target_limits': caps, '_events': events})
    return rows


def reads(name, versions):
    rows = []
    for height in (0, 1, 3, 4):
        retained = height == 0 or height in versions
        if retained:
            state, levels, values, root = GUARD.tree(tuple(sorted(versions.get(height, {}).items())))
        identifier = GUARD.identifier(name, height)
        rows.append({'identifier': identifier, 'key': None, 'root': (root if retained else ZERO).hex(),
                     'value': None, 'proof': None, 'error': None if retained else GUARD.NO_VERSION})
        for index in (0, 1, 2, 6, 8, 255, 256):
            key, value, proof = GUARD.key(index), None, None
            if retained:
                path = BYTE.digest(key)
                value = state.get(path)
                proof = BYTE.canonical_proof(levels, values, path)
                require(BYTE.proof_result(root, path, value or b'', proof, value is not None) == 'match')
            rows.append({'identifier': identifier, 'key': key.hex(), 'root': None,
                         'value': None if value is None else value.hex(), 'proof': None if proof is None else proof.hex(),
                         'error': None if retained else GUARD.NO_VERSION})
    return rows


@functools.lru_cache(maxsize=1)
def expected_document():
    cases = []
    for row in inputs():
        name = row['name']
        imported = FILE.expected_case(row)
        callbacks = imported['staging_callbacks']
        imported['staging_callbacks'] = {'count': len(callbacks), 'manifest_sha256': RESOURCE.binding(callbacks)}
        wanted = selected(name)
        selected_root = GUARD.tree(tuple(sorted(wanted.items())))[3]
        if name == 'wrong-selected-root-refusal': selected_root = ZERO
        refusal, preflight = '', None
        actual = {bytes.fromhex(k): bytes.fromhex(v) for k, v in row['target'].items()}
        for key, value in row['_events']:
            if value is None: actual.pop(key, None)
            else: actual[key] = value
        if imported['refusal']:
            refusal = 'import_' + imported['refusal']
        elif any(len(key) != 32 or key[0] != 3 or key[21] != 3 for key in actual):
            refusal = 'unsupported_balance_key'
        elif any(len(value) != 32 for value in actual.values()):
            refusal = 'unsupported_balance_value'
        else:
            actual = {int.from_bytes(key[17:21], 'big'): value for key, value in actual.items()}
            require(all(GUARD.key(i) in dict(row['_events']) or GUARD.key(i).hex() in row['target'] for i in actual))
            preflight = GUARD.tree(tuple(sorted(actual.items())))[3].hex()
            if preflight != selected_root.hex(): refusal = 'selected_root_mismatch'
        snapshots, tree_events = [], []
        if not refusal:
            tree_events = [{'operation': 'Put', 'key': GUARD.key(i).hex(), 'value': v.hex()} for i, v in sorted(actual.items())]
            for label in ('fresh', 'staged', 'seed-committed', 'clean-reopened'):
                frontier, versions = (0, {}) if label in ('fresh', 'staged') else (3, {3: actual})
                snapshots.append({'label': label, 'frontier': GUARD.identifier(name, frontier),
                                  'storage': GUARD.storage(name, frontier, versions), 'reads': reads(name, versions)})
        cases.append({'name': name, 'import': imported, 'selected_complete_map': GUARD.manifest(wanted),
            'selected_root': selected_root.hex(), 'preflight_root': preflight, 'handoff_refusal': refusal,
            'database_open_calls': 0 if refusal else 2, 'tree_update_calls': int(not refusal),
            'tree_bulk_commit_calls': int(not refusal), 'clean_reopen_calls': int(not refusal),
            'tree_staging_callbacks': {'count': len(tree_events), 'manifest_sha256': RESOURCE.binding(tree_events)},
            'snapshots': snapshots, 'research_handoff_result': 'REJECTED' if refusal else 'COMMITTED_RESEARCH', 'consumer_result': 'REFUSED'})
    return {'format_version': 1, 'kind': 'candidate-patch-tree-handoff-research',
        'source': {'repository': 'https://github.com/digitalSloth/go-zenon', 'revision': BYTE.NODE_REVISION, 'tree': BYTE.NODE_TREE},
        'scope': SCOPE, 'research_source_inputs': {name: hashlib.sha256((HERE / name).read_bytes()).hexdigest() for name in INPUT_NAMES}, 'cases': cases}


def check_corpus(document):
    DEC.RET.exact(document, expected_document())
    cases = document['cases']
    return {'patch_tree_cases': len(cases), 'research_seed_commits': sum(not c['handoff_refusal'] for c in cases),
        'refusals_before_database_creation': sum(bool(c['handoff_refusal']) for c in cases),
        'logical_snapshots': sum(len(c['snapshots']) for c in cases),
        'root_and_proof_cells': sum(len(s['reads']) for c in cases for s in c['snapshots']),
        'consumer_refusals': len(cases), 'research_source_inputs_bound': len(INPUT_NAMES),
        'NodeTree_execution_in_checker': False, 'resource_measurements_executed_in_checker': False,
        'production_resource_budgets_qualified': False, 'production_acceptance_enabled': False}


def inventory(document):
    return [(case, repetition, mode) for case in document['cases'] for repetition in range(3) for mode in ('plain', 'allocation')]


def phase_inventory(case):
    return PHASES[:1] if case['import']['refusal'] else PHASES[:2] if case['handoff_refusal'] else PHASES


def check_samples(report, corpus_raw, document):
    check_corpus(document)
    fixed = {'format_version': 1, 'kind': 'candidate-patch-tree-handoff-samples', 'source': document['source'],
        'corpus_sha256': hashlib.sha256(corpus_raw).hexdigest(), 'conformance_runs': 2,
        'measurement_runs_expected_to_vary': True, 'production_resource_budgets_qualified': False}
    variable = {'source_execution_platform', 'go_version', 'reference_binary_sha256', 'samples', 'commands'}
    require(type(report) is dict and set(report) == set(fixed) | variable)
    DEC.RET.exact({key: report[key] for key in fixed}, fixed)
    match = re.fullmatch(r'go version (go1\.25\.[0-9]+) (darwin|linux)/(amd64|arm64)', report['go_version'])
    require(match is not None and report['source_execution_platform'] == match[2])
    require(RESOURCE.hash_string(report['reference_binary_sha256']))
    for field in ('samples', 'commands'): require(type(report[field]) is list and len(report[field]) == 2)
    wanted = inventory(document)
    fields = {'case', 'mode', 'repetition', 'phase_resources', 'closed_database_files', 'process_peak_rss_bytes',
              'process_peak_rss_method', 'conformance_sha256', 'platform', 'go_version'}
    for generation, (run, commands) in enumerate(zip(report['samples'], report['commands'])):
        require(type(run) is list and type(commands) is list and len(run) == len(commands) == len(wanted))
        for sample, command, (case, repetition, mode) in zip(run, commands, wanted):
            require(type(sample) is dict and set(sample) == fields)
            selected_fields = {'case': case['name'], 'mode': mode, 'repetition': repetition, 'conformance_sha256': RESOURCE.binding(case),
                'platform': match[2] + '/' + match[3], 'go_version': match[1], 'process_peak_rss_method': PEAK_METHOD}
            DEC.RET.exact({key: sample[key] for key in selected_fields}, selected_fields)
            require(RESOURCE.unsigned(sample['process_peak_rss_bytes']) and sample['process_peak_rss_bytes'] > 0)
            phases = sample['phase_resources']
            require(type(phases) is list and len(phases) == len(phase_inventory(case)))
            for row, name in zip(phases, phase_inventory(case)):
                require(type(row) is dict and set(row) == {'phase', 'elapsed_ns', 'go_total_alloc_delta_bytes', 'go_mallocs_delta', 'go_gc_cycles'})
                require(row['phase'] == name and RESOURCE.unsigned(row['elapsed_ns']) and row['elapsed_ns'] > 0)
                for field in ('go_total_alloc_delta_bytes', 'go_mallocs_delta', 'go_gc_cycles'):
                    require(row[field] is None if mode == 'plain' else RESOURCE.unsigned(row[field]))
            files = sample['closed_database_files']
            if case['handoff_refusal']: require(files is None)
            else:
                require(type(files) is dict and set(files) == {'regular_files', 'bytes'})
                require(all(RESOURCE.unsigned(value) and value > 0 for value in files.values()))
            require(type(command) is dict and set(command) == {'label', 'completed', 'actual_exit', 'stdout_sha256', 'stderr_sha256', 'result_sha256'})
            DEC.RET.exact({key: command[key] for key in ('label', 'completed', 'actual_exit', 'result_sha256')},
                {'label': '%d-%s-%d-%s' % (generation, case['name'], repetition, mode), 'completed': True, 'actual_exit': 0,
                 'result_sha256': RESOURCE.binding({'conformance': case, 'measurement': sample})})
            require(RESOURCE.hash_string(command['stdout_sha256']) and command['stderr_sha256'] == hashlib.sha256(b'').hexdigest())
    return {'recorded_fresh_child_samples': 2 * len(wanted), 'samples_per_generation': len(wanted),
        'all_phase_and_actual_child_outcomes_bound': True, 'allocation_metric_is_cumulative_not_peak': True,
        'RSS_includes_interim_queries_and_is_not_phase_allocation': True, 'recorded_reference_platform': match[2] + '/' + match[3],
        'execution_provenance_authenticated': False, 'resource_measurements_executed_in_checker': False, 'production_acceptance_enabled': False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--corpus', type=Path, default=HERE / 'testdata/candidate-patch-tree.json')
    parser.add_argument('--samples', type=Path, default=HERE / 'testdata/candidate-patch-tree-samples.json')
    parser.add_argument('--source-revision')
    args = parser.parse_args(argv)
    require(args.source_revision is None or re.fullmatch('[0-9a-f]{40}', args.source_revision) is not None)
    raw, document = BYTE.read_corpus(args.corpus)
    sample_raw, samples = BYTE.read_corpus(args.samples)
    report = check_corpus(document) | check_samples(samples, raw, document)
    report.update(source_revision=args.source_revision, corpus_sha256=hashlib.sha256(raw).hexdigest(),
        samples_sha256=hashlib.sha256(sample_raw).hexdigest(), node_revision=BYTE.NODE_REVISION, node_tree=BYTE.NODE_TREE)
    print(json.dumps(report, sort_keys=True, separators=(',', ':')))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError):
        print('Candidate tree handoff evidence failed; production acceptance remains disabled.', file=sys.stderr)
        sys.exit(1)
