#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Bind finite file-backed deltas, retained versions and clean NodeTree reopen.

Derive complete maps, sparse proofs and compressed version/refcount records from
literal rules without Go, LevelDB or a network. Recorded phase allocation and
lifetime RSS are unsigned local observations, not production resource budgets.
"""
import argparse
import functools
import hashlib
import json
from pathlib import Path
import re
import sys

HERE = Path(__file__).resolve().parent
import importlib.util
spec = importlib.util.spec_from_file_location('tail_seed_oracle', HERE / 'check_patch_tree.py')
TREE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(TREE)
FILE, RESOURCE, GUARD, BYTE, DEC, ZERO = TREE.FILE, TREE.RESOURCE, TREE.GUARD, TREE.BYTE, TREE.DEC, TREE.ZERO
NAMES = ('retained-8', 'retained-32', 'empty-transitions', 'tail-selection-refusal', 'tail-cap-refusal',
         'tail-key-refusal', 'tail-value-refusal', 'tail-root-refusal')
BUILD_NAMES = TREE.BUILD_NAMES + ('patch_tree_tail_test.go',)
INPUT_NAMES = TREE.INPUT_NAMES + ('patch_tree_tail_test.go', 'check_patch_tree_tail.py',
                                'check_patch_tree_tail_test.py', 'reproduce_patch_tree_tail.py')
SCOPE = TREE.SCOPE.copy()
SCOPE.pop('root_selection_precedes_storage_creation')
SCOPE.update(explicit_existing_complete_map_to_delta=True, actual_NodeTree_tail_Commits_and_Prune=True,
             retained_empty_and_shared_roots=True, refusal_preserves_existing_storage=True,
             all_previous_original_map_aliases_bound=True, initial_seed_preflight_precedes_storage_creation=True,
             each_tail_preflight_precedes_existing_storage_mutation=True)


def require(condition):
    if not condition:
        raise ValueError('Tree tail evidence differs from its selected boundary')


def size(name):
    return 0 if name == 'empty-transitions' else 32 if name == 'retained-32' else 8


def selected(name, height):
    state = TREE.complete(size(name))
    if height == 3:
        return state
    if name == 'empty-transitions':
        return {0: bytes(32), 1: (3).to_bytes(32, 'big')} if height == 4 else {} if height == 5 else {0: bytes(32), 3: (7).to_bytes(32, 'big')}
    del state[2]
    state.update({1: bytes(32), 6: bytes(32), size(name): (10).to_bytes(32, 'big')})
    if height >= 5:
        del state[0]
        state[9 if name == 'tail-cap-refusal' else 2] = (12).to_bytes(32, 'big')
    return state


def events(name, height):
    def put(i, n): return GUARD.key(i), n.to_bytes(32, 'big')
    def delete(i): return GUARD.key(i), None
    if height == 3:
        return [(GUARD.key(i), value) for i, value in sorted(TREE.complete(size(name)).items())]
    if name == 'empty-transitions':
        return [put(0, 0), put(1, 2), put(1, 3)] if height == 4 else [delete(0), delete(1)] if height == 5 else [put(0, 0), put(3, 7)]
    if height == 4:
        return [delete(2), put(1, 0), put(size(name), 9), put(size(name), 10), delete(6), put(6, 0)]
    if height == 6:
        return []
    if name == 'tail-cap-refusal': return [put(9, 12), delete(0)]
    if name == 'tail-key-refusal':
        key, value = put(9, 12)
        return [(key[:21] + b'\x05' + key[22:], value)]
    if name == 'tail-value-refusal': return [(GUARD.key(9), b'')]
    return [delete(0), put(2, 12)]


def input_row(name, height, target):
    changes = events(name, height)
    raw = b''.join(DEC.record(int(value is not None), key, value or b'') for key, value in changes)
    label = '%s/%d' % (name, height)
    choice = {'name': label, 'bytes': len(raw), 'records': len(changes), 'changes_hash': BYTE.digest(raw).hex()}
    caps = FILE.TARGET.CEILINGS.copy()
    if name == 'tail-selection-refusal' and height == 5: choice['records'] += 1
    if name == 'tail-cap-refusal' and height == 5: caps = {'entries': 8, 'hex_bytes': 1024}
    return {'name': label, 'raw': raw, 'limits': FILE.IMP.CEILINGS.copy(), 'selection': choice, 'fault': 'none',
            'source_fault': 'none', 'target': target.copy(), 'target_limits': caps}


def reads(name, versions):
    rows = []
    for height in (0, 1, 3, 4, 5, 6, 7):
        retained = height == 0 or height in versions
        if retained:
            state, levels, values, root = GUARD.tree(tuple(sorted(versions.get(height, {}).items())))
        identifier = GUARD.identifier(name, height)
        rows.append({'identifier': identifier, 'key': None, 'root': (root if retained else ZERO).hex(),
                     'value': None, 'proof': None, 'error': None if retained else GUARD.NO_VERSION})
        for index in (0, 1, 2, 6, 8, 31, 32):
            key, value, proof = GUARD.key(index), None, None
            if retained:
                path = BYTE.digest(key)
                value, proof = state.get(path), BYTE.canonical_proof(levels, values, path)
                require(BYTE.proof_result(root, path, value or b'', proof, value is not None) == 'match')
            rows.append({'identifier': identifier, 'key': key.hex(), 'root': None,
                         'value': None if value is None else value.hex(), 'proof': None if proof is None else proof.hex(),
                         'error': None if retained else GUARD.NO_VERSION})
    return rows


def snapshot(name, label, frontier, versions):
    return {'label': label, 'frontier': GUARD.identifier(name, frontier),
            'storage': GUARD.storage(name, frontier, versions), 'reads': reads(name, versions)}


def delta(before, after):
    return [{'operation': 'Delete' if key not in after else 'Put', 'key': key,
             'value': after.get(key)} for key in sorted(set(before) | set(after))
            if key not in after or key not in before or before[key] != after[key]]


@functools.lru_cache(maxsize=1)
def expected_document():
    cases = []
    for name in NAMES:
        target, versions, frontier = {}, {}, 0
        rows, snapshots, aliases = [], [], []
        for height in (3, 4, 5, 6):
            wanted = selected(name, height)
            selected_root = GUARD.tree(tuple(sorted(wanted.items())))[3]
            if name == 'tail-root-refusal' and height == 5: selected_root = ZERO
            row = input_row(name, height, target)
            aliases.append(FILE.TARGET.summary(target))
            imported = FILE.expected_case(row)
            callbacks = imported['staging_callbacks']
            imported['staging_callbacks'] = {'count': len(callbacks), 'manifest_sha256': RESOURCE.binding(callbacks)}
            actual = {bytes.fromhex(k): bytes.fromhex(v) for k, v in target.items()}
            for key, value in events(name, height):
                if value is None: actual.pop(key, None)
                else: actual[key] = value
            refusal, preflight = '', None
            if imported['refusal']: refusal = 'import_' + imported['refusal']
            elif any(len(k) != 32 or k[0] != 3 or k[21] != 3 for k in actual): refusal = 'unsupported_balance_key'
            elif any(len(v) != 32 for v in actual.values()): refusal = 'unsupported_balance_value'
            else:
                actual_state = {int.from_bytes(k[17:21], 'big'): v for k, v in actual.items()}
                require(all(GUARD.key(i) in actual for i in actual_state))
                preflight = GUARD.tree(tuple(sorted(actual_state.items())))[3].hex()
                if preflight != selected_root.hex(): refusal = 'selected_root_mismatch'
            tree_events = []
            if not refusal:
                following = {k.hex(): v.hex() for k, v in actual.items()}
                tree_events = delta(target, following)
                if height == 3: snapshots.append(snapshot(name, 'fresh', 0, {}))
                snapshots.append(snapshot(name, 'staged-%d' % height, frontier, versions))
                versions[height], frontier, target = actual_state, height, following
                snapshots.append(snapshot(name, 'committed-%d' % height, frontier, versions))
            else:
                require(height == 5 and frontier == 4)
                snapshots.append(snapshot(name, 'refused-5', frontier, versions))
            rows.append({'height': height, 'import': imported, 'selected_complete_map': GUARD.manifest(wanted),
                'selected_root': selected_root.hex(), 'preflight_root': preflight, 'handoff_refusal': refusal,
                'tree_staging_callbacks': {'count': len(tree_events), 'manifest_sha256': RESOURCE.binding(tree_events)},
                'research_handoff_result': 'REJECTED' if refusal else 'COMMITTED_RESEARCH', 'consumer_result': 'REFUSED'})
            if refusal: break
        if len(rows) == 4:
            versions = {height: values for height, values in versions.items() if height >= 5}
            snapshots.append(snapshot(name, 'pruned-5', frontier, versions))
        snapshots.append(snapshot(name, 'clean-reopened', frontier, versions))
        accepted = sum(not row['handoff_refusal'] for row in rows)
        cases.append({'name': name, 'steps': rows, 'snapshots': snapshots, 'original_aliases_before': aliases,
            'original_aliases_after': aliases, 'database_open_calls': 2, 'tree_update_calls': accepted,
            'tree_bulk_commit_calls': 1, 'tree_tail_commit_calls': accepted-1, 'tree_prune_calls': int(len(rows) == 4),
            'clean_reopen_calls': 1, 'consumer_result': 'REFUSED'})
    return {'format_version': 1, 'kind': 'candidate-patch-tree-tail-research', 'source': TREE.expected_document()['source'],
            'scope': SCOPE, 'research_source_inputs': {name: hashlib.sha256((HERE / name).read_bytes()).hexdigest() for name in INPUT_NAMES}, 'cases': cases}


def check_corpus(document):
    DEC.RET.exact(document, expected_document())
    cases = document['cases']
    return {'patch_tree_tail_cases': len(cases), 'research_seed_commits': len(cases),
        'research_tail_commits': sum(c['tree_tail_commit_calls'] for c in cases), 'research_prunes': sum(c['tree_prune_calls'] for c in cases),
        'refused_tail_handoffs': sum(bool(s['handoff_refusal']) for c in cases for s in c['steps']),
        'logical_snapshots': sum(len(c['snapshots']) for c in cases), 'root_and_proof_cells': sum(len(s['reads']) for c in cases for s in c['snapshots']),
        'consumer_refusals': len(cases), 'research_source_inputs_bound': len(INPUT_NAMES), 'NodeTree_execution_in_checker': False,
        'resource_measurements_executed_in_checker': False, 'production_resource_budgets_qualified': False, 'production_acceptance_enabled': False}


def inventory(document):
    return [(case, repetition, mode) for case in document['cases'] for repetition in range(3) for mode in ('plain', 'allocation')]


def phase_inventory(case):
    phases = []
    for row in case['steps']:
        height, prefix = row['height'], str(row['height']) + '/'
        phases.append(prefix + 'opened-file-to-owned-map')
        if not row['import']['refusal']: phases.append(prefix + 'complete-balance-map-and-root-selection')
        if not row['handoff_refusal']:
            if height == 3: phases.append('open-fresh-NodeTree')
            phases.append(prefix + 'complete-map-delta-and-Update')
            phases.append('CommitBulk' if height == 3 else prefix + 'Commit')
    if case['tree_prune_calls']: phases.append('Prune/5')
    return phases + ['clean-close', 'clean-reopen-NodeTree', 'final-clean-close']


def check_samples(report, corpus_raw, document):
    check_corpus(document)
    fixed = {'format_version': 1, 'kind': 'candidate-patch-tree-tail-samples', 'source': document['source'],
        'corpus_sha256': hashlib.sha256(corpus_raw).hexdigest(), 'conformance_runs': 2,
        'measurement_runs_expected_to_vary': True, 'production_resource_budgets_qualified': False}
    variable = {'source_execution_platform', 'go_version', 'reference_binary_sha256', 'samples', 'commands'}
    require(type(report) is dict and set(report) == set(fixed) | variable)
    DEC.RET.exact({k: report[k] for k in fixed}, fixed)
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
            chosen = {'case': case['name'], 'mode': mode, 'repetition': repetition, 'conformance_sha256': RESOURCE.binding(case),
                'platform': match[2]+'/'+match[3], 'go_version': match[1], 'process_peak_rss_method': TREE.PEAK_METHOD}
            DEC.RET.exact({k: sample[k] for k in chosen}, chosen)
            require(RESOURCE.unsigned(sample['process_peak_rss_bytes']) and sample['process_peak_rss_bytes'] > 0)
            phases = sample['phase_resources']
            require(type(phases) is list and len(phases) == len(phase_inventory(case)))
            for row, name in zip(phases, phase_inventory(case)):
                require(type(row) is dict and set(row) == {'phase', 'elapsed_ns', 'go_total_alloc_delta_bytes', 'go_mallocs_delta', 'go_gc_cycles'})
                require(row['phase'] == name and RESOURCE.unsigned(row['elapsed_ns']) and row['elapsed_ns'] > 0)
                for field in ('go_total_alloc_delta_bytes', 'go_mallocs_delta', 'go_gc_cycles'):
                    require(row[field] is None if mode == 'plain' else RESOURCE.unsigned(row[field]))
            files = sample['closed_database_files']
            require(type(files) is dict and set(files) == {'regular_files', 'bytes'})
            require(all(RESOURCE.unsigned(v) and v > 0 for v in files.values()))
            require(type(command) is dict and set(command) == {'label', 'completed', 'actual_exit', 'stdout_sha256', 'stderr_sha256', 'result_sha256'})
            DEC.RET.exact({k: command[k] for k in ('label', 'completed', 'actual_exit', 'result_sha256')},
                {'label': '%d-%s-%d-%s' % (generation, case['name'], repetition, mode), 'completed': True, 'actual_exit': 0,
                 'result_sha256': RESOURCE.binding({'conformance': case, 'measurement': sample})})
            require(RESOURCE.hash_string(command['stdout_sha256']) and command['stderr_sha256'] == hashlib.sha256(b'').hexdigest())
    return {'recorded_fresh_child_samples': 2*len(wanted), 'samples_per_generation': len(wanted),
        'all_phase_and_actual_child_outcomes_bound': True, 'allocation_metric_is_cumulative_not_peak': True,
        'RSS_includes_interim_queries_and_is_not_phase_allocation': True, 'recorded_reference_platform': match[2]+'/'+match[3],
        'execution_provenance_authenticated': False, 'resource_measurements_executed_in_checker': False, 'production_acceptance_enabled': False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--corpus', type=Path, default=HERE/'testdata/candidate-patch-tree-tail.json')
    parser.add_argument('--samples', type=Path, default=HERE/'testdata/candidate-patch-tree-tail-samples.json')
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
        print('Candidate tree tail evidence failed; production acceptance remains disabled.', file=sys.stderr)
        sys.exit(1)
