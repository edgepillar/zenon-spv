#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Check complete bounded file imports, NodeTree deltas and retained DAG bytes.

Reconstruct 512/4096-key literal histories independently of Go and LevelDB.
The unchanged file importer admits at most 1024 records per file: four ordered
seed files form the 4096-key complete map before a single CommitBulk. Digest
selection is unsigned; neither a chunk digest nor this root is a trust anchor.
Recorded phase allocation, post-GC heap, RSS and closed allocated-file sizes
are separate observations. No whole pipeline, peak disk or production budget
is qualified. The checker never executes the node or resource workloads.
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


TAIL = load('import_scale_file_oracle', 'check_patch_tree_tail.py')
SCALE = load('import_scale_sparse_oracle', 'check_tree_scale.py')
FILE, BYTE, RET = TAIL.FILE, SCALE.BYTE, SCALE.RET
BUILD_NAMES = TAIL.BUILD_NAMES + ('retention_resources.go', 'tree_import_scale_test.go')
INPUT_NAMES = tuple(dict.fromkeys(TAIL.INPUT_NAMES + SCALE.INPUT_NAMES + BUILD_NAMES + (
    'check_tree_import_scale.py', 'check_tree_import_scale_test.py', 'reproduce_tree_import_scale.py')))
SELECTIONS = (('import-512-16-retain8', 512, 16, 8), ('import-4096-16-retain8', 4096, 16, 8))
RSS_METHOD = 'getrusage(RUSAGE_SELF) after closed storage inventory and controlled final GC, before final conformance binding/output; includes setup, selected-map construction, conformance checks and GC'
HEAP_METHOD = 'runtime.GC then ReadMemStats HeapAlloc; selected maps, final map, conformance, input metadata and closed tree explicitly live; before final result binding/output'
SCOPE = SCALE.SCOPE | {'unmodified_retentionChild_reused': False, 'fresh_plain_children': False,
    'unchanged_file_importer_and_explicit_delta_reused': True, 'seed_files_maximum_records': 1024,
    'initial_complete_map_selected_before_NodeTree_update': True,
    'file_digest_is_authenticated_snapshot': False, 'full_node_snapshot_imported': False,
    'live_heap_or_allocation_measurements_executed': True,
    'post_GC_heap_includes_explicitly_live_fixture_and_conformance': True,
    'closed_allocated_regular_file_bytes_observed': True, 'peak_disk_measured': False,
    'whole_pipeline_time_measured': False, 'whole_pipeline_memory_measured': False,
    'single_serial_caller': True, 'consumer_result_is_REFUSED': True}


def require(condition):
    if not condition:
        raise ValueError('Larger file/tree evidence differs from the selected finite contract')


encoded, binding = SCALE.encoded, SCALE.binding


def chunks(keys, height):
    start, count = (0, keys) if height == 1 else ((height - 2) * 8 % keys, 8)
    events = []
    for offset in range(count):
        index = (start + offset) % keys
        value = None if height > 1 and height % 3 == 0 and offset % 3 == 0 else (
            0 if height > 1 and height % 4 == 0 and offset == 1 else height * keys + index + 1).to_bytes(32, 'big')
        events.append((RET.key(index), value))
    return [events[first:first + 1024] for first in range(0, count, 1024)]


def expected_import(label, events, target):
    raw = b''.join(TAIL.DEC.record(int(value is not None), key, value or b'') for key, value in events)
    choice = {'name': label, 'bytes': len(raw), 'records': len(events), 'changes_hash': BYTE.digest(raw).hex()}
    row = {'name': label, 'raw': raw, 'limits': FILE.IMP.CEILINGS.copy(), 'selection': choice,
           'fault': 'none', 'source_fault': 'none', 'target': target.copy(), 'target_limits': FILE.TARGET.CEILINGS.copy()}
    imported = FILE.expected_case(row)
    require(not imported['refusal'])
    following = target.copy()
    for key, value in events:
        if value is None:
            following.pop(key.hex(), None)
        else:
            following[key.hex()] = value.hex()
    return {'selection': choice, 'raw_sha256': hashlib.sha256(raw).hexdigest(),
        'before': imported['target_before'], 'after': imported['target_after'],
        'callbacks': {'count': len(imported['staging_callbacks']), 'manifest_sha256': binding(imported['staging_callbacks'])},
        'source_cursor_preserved': True, 'original_alias_preserved': True,
        'stat_calls': imported['file_stat_calls'], 'read_calls': imported['file_read_calls'],
        'buffer_bytes': imported['file_buffer_bytes'], 'read_bytes': imported['file_read_bytes'],
        'preflight_records': imported['preflight_records'], 'raw_copies': imported['raw_copies'],
        'constructor_calls': imported['constructor_calls'], 'replay_calls': imported['default_replay_calls'],
        'clone_calls': imported['target_clone_calls'], 'cloned_entries': imported['target_cloned_entries'],
        'replacements': imported['target_replacements']}, following


def expected_case(selection):
    name, keys, versions, retain = selection
    history, target, steps = RET.states(keys, versions), {}, []
    for height in range(1, versions + 1):
        before, imports = target.copy(), []
        for number, events in enumerate(chunks(keys, height)):
            row, target = expected_import('%s/%d/%d' % (name, height, number), events, target)
            imports.append(row)
        actual = {BYTE.digest(bytes.fromhex(key)): bytes.fromhex(value) for key, value in target.items()}
        RET.exact(actual, history[height])
        root = RET.graph(history[height])[1].hex()
        callbacks = TAIL.delta(before, target)
        steps.append({'height': height, 'imports': imports, 'complete_map': FILE.TARGET.summary(target),
            'selected_root': root, 'preflight_root': root,
            'delta_callbacks': {'count': len(callbacks), 'manifest_sha256': binding(callbacks)}})
    return {'input': {'name': name, 'keys': keys, 'versions': versions, 'retain': retain},
            'steps': steps, 'rounds': SCALE.expected_case(selection)['rounds'], 'bulk_commits': 1,
            'tail_commits': versions - 1, 'prune_calls': versions - retain, 'consumer_result': 'REFUSED'}


@functools.lru_cache(maxsize=1)
def expected_document():
    return {'format_version': 1, 'kind': 'candidate-tree-import-scale-research', 'source': SCALE.SOURCE,
        'scope': SCOPE, 'research_source_inputs': {name: hashlib.sha256((HERE / name).read_bytes()).hexdigest() for name in INPUT_NAMES},
        'cases': [expected_case(selection) for selection in SELECTIONS], 'consumer_result': 'REFUSED'}


def check_corpus(document):
    RET.exact(document, expected_document())
    require(len(encoded(document)) <= BYTE.MAX_FILE_BYTES)
    return {'tree_import_scale_cases': 2, 'selected_initial_keys': [512, 4096], 'versions_per_case': 16,
        'retained_versions_per_case': 8, 'root_and_proof_cells': 252, 'logical_storage_and_refcount_checks': 6,
        'selected_file_imports_per_pair': 35, 'file_record_ceiling_preserved': 1024,
        'research_source_inputs_bound': len(INPUT_NAMES), 'consumer_result': 'REFUSED',
        'new_NodeTree_execution': False, 'new_resource_measurements': False,
        'authenticated_snapshot_or_retained_version_provenance_qualified': False,
        'production_resource_budgets_qualified': False, 'production_acceptance_enabled': False}


def phases(case):
    labels = ['open']
    for step in case['steps']:
        labels.extend(row['selection']['name'] + '/file-import' for row in step['imports'])
        labels.extend('%d/%s' % (step['height'], suffix) for suffix in ('complete-map-root-preflight', 'delta-and-Update', 'Commit'))
        if step['height'] > case['input']['retain']:
            labels.append('%d/Prune' % step['height'])
    return labels + ['clean-close', 'clean-reopen', 'compact', 'compact-close', 'compact-reopen', 'final-close']


def inventory(corpus):
    return [(case, repetition, mode) for case in corpus['cases'] for repetition in range(3) for mode in ('plain', 'allocation')]


def measurement_contract(row, case, platform, version, repetition, mode):
    fields = {'case', 'mode', 'repetition', 'go_version', 'platform', 'conformance_sha256', 'phase_resources',
        'query_timings', 'closed_storage', 'process_peak_rss_bytes', 'process_peak_rss_method', 'post_gc_heap_alloc_bytes',
        'post_gc_heap_method', 'whole_pipeline_time_measured', 'whole_pipeline_memory_measured', 'peak_disk_measured'}
    require(type(row) is dict and set(row) == fields)
    for key, value in (('case', case['input']['name']), ('mode', mode), ('repetition', repetition), ('go_version', version),
                       ('platform', platform), ('conformance_sha256', binding(case)), ('process_peak_rss_method', RSS_METHOD),
                       ('post_gc_heap_method', HEAP_METHOD), ('whole_pipeline_time_measured', False),
                       ('whole_pipeline_memory_measured', False), ('peak_disk_measured', False)):
        RET.exact(row[key], value)
    for key in ('process_peak_rss_bytes', 'post_gc_heap_alloc_bytes'):
        RET.integer(row[key], 1)
    require(type(row['phase_resources']) is list and len(row['phase_resources']) == len(phases(case)))
    for phase, name in zip(row['phase_resources'], phases(case)):
        require(type(phase) is dict and set(phase) == {'phase', 'elapsed_ns', 'go_total_alloc_delta_bytes', 'go_mallocs_delta', 'go_gc_cycles'})
        RET.exact(phase['phase'], name)
        RET.integer(phase['elapsed_ns'])
        for field in ('go_total_alloc_delta_bytes', 'go_mallocs_delta', 'go_gc_cycles'):
            if mode == 'allocation':
                RET.integer(phase[field])
            else:
                require(phase[field] is None)
    require(type(row['query_timings']) is list and len(row['query_timings']) == 3)
    for query in row['query_timings']:
        require(type(query) is dict and set(query) == {'root_calls', 'proof_calls', 'root_elapsed_ns', 'proof_elapsed_ns'})
        RET.exact(query['root_calls'], 7)
        RET.exact(query['proof_calls'], 35)
        RET.integer(query['root_elapsed_ns'])
        RET.integer(query['proof_elapsed_ns'])
    require(type(row['closed_storage']) is list and len(row['closed_storage']) == 3)
    for physical in row['closed_storage']:
        require(type(physical) is dict and set(physical) == {'regular_files', 'file_bytes', 'largest_file_bytes', 'allocated_file_bytes'})
        for value in physical.values():
            RET.integer(value, 1)
        require(physical['largest_file_bytes'] <= physical['file_bytes'] <= physical['regular_files'] * physical['largest_file_bytes'])
        require(physical['allocated_file_bytes'] % 512 == 0)


def check_samples(document, corpus_raw, corpus):
    RET.exact(json.loads(corpus_raw, object_pairs_hook=BYTE.object_pairs), corpus)
    check_corpus(corpus)
    fields = {'format_version', 'kind', 'source', 'corpus_sha256', 'research_source_inputs', 'conformance_runs',
        'measurement_runs_expected_to_vary', 'production_resource_budgets_qualified', 'source_execution_platform',
        'go_version', 'reference_binary_sha256', 'samples', 'commands'}
    require(type(document) is dict and set(document) == fields)
    for key, value in (('format_version', 1), ('kind', 'candidate-tree-import-scale-samples'), ('source', SCALE.SOURCE),
        ('corpus_sha256', hashlib.sha256(corpus_raw).hexdigest()), ('research_source_inputs', corpus['research_source_inputs']),
        ('conformance_runs', 2), ('measurement_runs_expected_to_vary', True), ('production_resource_budgets_qualified', False)):
        RET.exact(document[key], value)
    require(type(document['source_execution_platform']) is str and document['source_execution_platform'] in ('darwin', 'linux'))
    require(type(document['go_version']) is str and re.fullmatch(r'go version go1\.25\.[0-9]+ (darwin|linux)/[a-z0-9]+', document['go_version']) is not None)
    RET.digest_field(document['reference_binary_sha256'])
    platform, version = document['go_version'].rsplit(' ', 1)[1], document['go_version'].split()[2]
    require(platform.split('/')[0] == document['source_execution_platform'])
    require(type(document['samples']) is list and len(document['samples']) == 2)
    require(type(document['commands']) is list and len(document['commands']) == 2)
    for generation, (samples, commands) in enumerate(zip(document['samples'], document['commands'])):
        require(type(samples) is list and len(samples) == 12 and type(commands) is list and len(commands) == 12)
        for measurement, command, (case, repetition, mode) in zip(samples, commands, inventory(corpus)):
            measurement_contract(measurement, case, platform, version, repetition, mode)
            require(type(command) is dict and set(command) == {'label', 'completed', 'actual_exit', 'stdout_sha256', 'stderr_sha256', 'result_sha256'})
            for key, value in (('label', '%d-%s-%d-%s' % (generation, case['input']['name'], repetition, mode)),
                ('completed', True), ('actual_exit', 0), ('stderr_sha256', hashlib.sha256(b'').hexdigest()),
                ('result_sha256', binding({'conformance': case, 'measurement': measurement}))):
                RET.exact(command[key], value)
            RET.digest_field(command['stdout_sha256'])
    require(len(encoded(document)) <= BYTE.MAX_FILE_BYTES)
    return {'actual_recorded_fresh_children': 24, 'recorded_file_import_calls': 420, 'recorded_query_API_calls': 3024,
        'all_generations_modes_and_repetitions_bound': True, 'new_NodeTree_execution': False, 'new_resource_measurements': False,
        'execution_provenance_authenticated': False, 'whole_pipeline_or_peak_disk_measured': False,
        'production_resource_budgets_qualified': False, 'consumer_result': 'REFUSED'}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--corpus', type=Path, default=HERE / 'testdata/candidate-tree-import-scale.json')
    parser.add_argument('--samples', type=Path, default=HERE / 'testdata/candidate-tree-import-scale-samples.json')
    parser.add_argument('--source-revision')
    args = parser.parse_args(argv)
    require(args.source_revision is None or re.fullmatch(r'[0-9a-f]{40}', args.source_revision) is not None)
    raw, corpus = BYTE.read_corpus(args.corpus)
    _, samples = BYTE.read_corpus(args.samples)
    report = check_corpus(corpus) | check_samples(samples, raw, corpus)
    report.update(corpus_sha256=hashlib.sha256(raw).hexdigest(), source_revision=args.source_revision,
                  node_revision=BYTE.NODE_REVISION, node_tree=BYTE.NODE_TREE)
    print(json.dumps(report, sort_keys=True, separators=(',', ':')))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError, OverflowError, RecursionError):
        print('Larger file/tree evidence refused; production acceptance remains disabled.', file=sys.stderr)
        sys.exit(1)
