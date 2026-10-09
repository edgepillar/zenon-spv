#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Check larger finite NodeTree retention with independent bytes and DAG records.

Two preselected synthetic histories have 512/4096 keys, 64 versions and a
16-version retained window. No node, database, child or network runs here.
Recorded query/phase timings, RSS and closed file lengths are separate unsigned
observations, never production budgets or authenticated snapshot/proof inputs.
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
spec = importlib.util.spec_from_file_location('scale_retention_bytes', HERE / 'check_retention.py')
RET = importlib.util.module_from_spec(spec)
spec.loader.exec_module(RET)
BYTE, ZERO = RET.BYTE, RET.ZERO
BUILD_NAMES = ('go.mod', 'go.sum', 'main.go', 'retention_resources.go', 'tree_scale_test.go')
INPUT_NAMES = BUILD_NAMES + ('check.py', 'check_retention.py', 'check_tree_scale.py',
                            'check_tree_scale_test.py', 'reproduce_tree_scale.py')
SELECTIONS = (('scale-512-64-retain16', 512, 64, 16),
              ('scale-4096-64-retain16', 4096, 64, 16))
SOURCE = {'repository': 'https://github.com/digitalSloth/go-zenon',
          'revision': BYTE.NODE_REVISION, 'tree': BYTE.NODE_TREE}
SCOPE = RET.SCOPE | {'larger_finite_preselected_workload': True,
    'unmodified_retentionChild_reused': True, 'fresh_plain_children': True,
    'single_serial_caller': True, 'query_timings_recorded_separately': True,
    'phase_timings_are_not_whole_pipeline_time': True,
    'RSS_excludes_final_binding_and_output_serialization': True,
    'closed_file_lengths_are_not_allocated_disk_or_peak_disk': True,
    'live_heap_or_allocation_measurements_executed': False,
    'real_chain_archive_replayed': False, 'consumer_result_is_REFUSED': True}


def require(condition):
    if not condition:
        raise ValueError('Larger finite tree evidence differs from its selected contract')


def encoded(document):
    return (json.dumps(document, sort_keys=True, separators=(',', ':')) + '\n').encode('ascii')


def binding(document):
    return hashlib.sha256(encoded(document).rstrip(b'\n')).hexdigest()


def scale_levels(state):
    """Bottom-up sparse tree with an explicit new 4096-leaf local ceiling.

    The original 1024-leaf byte checker remains unchanged. Compressed storage
    is derived separately by RET.graph and must agree with this calculation.
    """
    require(type(state) is dict and len(state) <= 4096)
    values, nodes = {}, {}
    for path, value in state.items():
        require(type(path) is bytes and len(path) == 32 and type(value) is bytes and len(value) == 32)
        index = int.from_bytes(path, 'big')
        values[index] = value
        nodes[index] = BYTE.digest(path + value)
    levels = {256: nodes}
    for depth in range(255, -1, -1):
        parents = {}
        for index in {index >> 1 for index in nodes}:
            result = BYTE.parent(nodes.get(index * 2, ZERO), nodes.get(index * 2 + 1, ZERO))
            if result != ZERO:
                parents[index] = result
        nodes = parents
        levels[depth] = nodes
    return levels, values


def expected_case(selection):
    name, keys, versions, retain = selection
    item = {'name': name, 'keys': keys, 'versions': versions, 'retain': retain}
    history = RET.states(keys, versions)
    stored = RET.expected_storage(history, item)
    rows = []
    for height in (0, 1, versions // 4, versions // 2, versions - 3, versions, versions + 1):
        retained = height == 0 or height in stored['retained_heights']
        if retained:
            state = history[height]
            levels, values = scale_levels(state)
            root = levels[0].get(0, ZERO)
            require(root == RET.graph(state)[1])
        for index in RET.query_indices(keys, versions):
            row = {'identifier': RET.identifier(keys, height), 'key': None, 'root': None,
                   'value': None, 'proof': None, 'error': None if retained else RET.NO_VERSION}
            if index == -1:
                row['root'] = (root if retained else ZERO).hex()
            else:
                raw = RET.key(index)
                row['key'] = raw.hex()
                if retained:
                    path = BYTE.digest(raw)
                    value = state.get(path)
                    proof = BYTE.canonical_proof(levels, values, path)
                    require(BYTE.proof_result(root, path, value or b'', proof, value is not None) == 'match')
                    row['value'] = None if value is None else value.hex()
                    row['proof'] = proof.hex()
            rows.append(row)
    return {'input': item, 'patch_calls': versions, 'input_operations': keys + (versions - 1) * 8,
            'commit_calls': versions, 'prune_calls': versions - retain, 'manual_compaction_calls': 1,
            'rounds': [{'round': round_number, 'frontier': RET.identifier(keys, versions),
                       'storage': stored, 'reads': rows} for round_number in range(3)]}


@functools.lru_cache(maxsize=1)
def expected_document():
    return {'format_version': 1, 'kind': 'candidate-tree-scale-research', 'source': SOURCE,
            'scope': SCOPE, 'research_source_inputs': {name: hashlib.sha256((HERE / name).read_bytes()).hexdigest()
                                                    for name in INPUT_NAMES},
            'cases': [expected_case(selection) for selection in SELECTIONS], 'consumer_result': 'REFUSED'}


def check_corpus(document):
    RET.exact(document, expected_document())
    require(len(encoded(document)) <= BYTE.MAX_FILE_BYTES)
    return {'tree_scale_cases': 2, 'selected_versions_per_case': 64, 'retained_versions_per_case': 16,
            'selected_initial_keys': [512, 4096], 'root_and_proof_cells': 252,
            'logical_storage_and_refcount_checks': 6, 'conformance_rounds': 6,
            'research_source_inputs_bound': len(INPUT_NAMES), 'consumer_result': 'REFUSED',
            'NodeTree_execution_in_checker': False, 'resource_measurements_in_checker': False,
            'authenticated_retained_version_provenance_qualified': False,
            'production_resource_budgets_qualified': False, 'production_acceptance_enabled': False}


def measurement_contract(sample, case, platform, version, repetition):
    require(type(sample) is dict and set(sample) == {'case', 'repetition', 'go_version', 'conformance_sha256', 'measurement'})
    RET.exact(sample['case'], case['input']['name'])
    RET.exact(sample['repetition'], repetition)
    RET.exact(sample['go_version'], version)
    RET.exact(sample['conformance_sha256'], binding(case))
    m = sample['measurement']
    require(type(m) is dict and set(m) == {'case', 'platform', 'peak_rss_bytes', 'peak_rss_method',
                                        'query_timings', *RET.TIMINGS, *RET.PHYSICAL})
    RET.exact(m['case'], case['input']['name'])
    RET.exact(m['platform'], platform)
    RET.exact(m['peak_rss_method'], RET.RSS_METHOD)
    RET.integer(m['peak_rss_bytes'], 1)
    for field in RET.TIMINGS:
        RET.integer(m[field])
    require(sum(m[field] for field in ('update_elapsed_ns', 'commit_elapsed_ns', 'prune_elapsed_ns')) <=
            m['patch_build_update_commit_prune_elapsed_ns'])
    require(type(m['query_timings']) is list and len(m['query_timings']) == 3)
    for query in m['query_timings']:
        require(type(query) is dict and set(query) == {'root_calls', 'root_elapsed_ns', 'proof_calls', 'proof_elapsed_ns'})
        RET.exact(query['root_calls'], 7)
        RET.exact(query['proof_calls'], 35)
        RET.integer(query['root_elapsed_ns'])
        RET.integer(query['proof_elapsed_ns'])
    for field in RET.PHYSICAL:
        physical = m[field]
        require(type(physical) is dict and set(physical) == {'regular_files', 'file_bytes', 'largest_file_bytes'})
        for value in physical.values():
            RET.integer(value, 1)
        require(physical['largest_file_bytes'] <= physical['file_bytes'] <=
                physical['regular_files'] * physical['largest_file_bytes'])


def check_samples(document, corpus_raw, corpus):
    require(type(corpus_raw) is bytes and len(corpus_raw) <= BYTE.MAX_FILE_BYTES)
    RET.exact(json.loads(corpus_raw, object_pairs_hook=BYTE.object_pairs), corpus)
    check_corpus(corpus)
    fields = {'format_version', 'kind', 'source', 'corpus_sha256', 'research_source_inputs', 'conformance_runs',
              'measurement_runs_expected_to_vary', 'production_resource_budgets_qualified',
              'source_execution_platform', 'go_version', 'reference_binary_sha256', 'samples', 'commands'}
    require(type(document) is dict and set(document) == fields)
    for key, value in (('format_version', 1), ('kind', 'candidate-tree-scale-samples'), ('source', SOURCE),
                       ('corpus_sha256', hashlib.sha256(corpus_raw).hexdigest()),
                       ('research_source_inputs', corpus['research_source_inputs']), ('conformance_runs', 2),
                       ('measurement_runs_expected_to_vary', True), ('production_resource_budgets_qualified', False)):
        RET.exact(document[key], value)
    require(type(document['source_execution_platform']) is str and document['source_execution_platform'] in ('darwin', 'linux'))
    require(type(document['go_version']) is str and re.fullmatch(r'go version go1\.25\.[0-9]+ (darwin|linux)/[a-z0-9]+', document['go_version']) is not None)
    RET.digest_field(document['reference_binary_sha256'])
    platform = document['go_version'].rsplit(' ', 1)[1]
    require(platform.split('/')[0] == document['source_execution_platform'])
    version = document['go_version'].split()[2]
    require(type(document['samples']) is list and len(document['samples']) == 2)
    require(type(document['commands']) is list and len(document['commands']) == 2)
    inventory = [(case, repetition) for case in corpus['cases'] for repetition in range(3)]
    for generation, (samples, commands) in enumerate(zip(document['samples'], document['commands'])):
        require(type(samples) is list and len(samples) == len(inventory))
        require(type(commands) is list and len(commands) == len(inventory))
        for sample, command, (case, repetition) in zip(samples, commands, inventory):
            measurement_contract(sample, case, platform, version, repetition)
            require(type(command) is dict and set(command) == {'label', 'completed', 'actual_exit', 'stdout_sha256', 'stderr_sha256', 'result_sha256'})
            for field, value in (('label', '%d-%s-%d' % (generation, case['input']['name'], repetition)),
                                 ('completed', True), ('actual_exit', 0), ('stderr_sha256', hashlib.sha256(b'').hexdigest()),
                                 ('result_sha256', binding({'conformance': case, 'sample': sample}))):
                RET.exact(command[field], value)
            RET.digest_field(command['stdout_sha256'])
    require(len(encoded(document)) <= BYTE.MAX_FILE_BYTES)
    return {'actual_recorded_fresh_children': 12, 'recorded_query_API_calls': 1512,
            'all_generations_and_repetitions_bound': True, 'recorded_phase_timing_file_and_RSS_rows_bound': True,
            'execution_provenance_authenticated': False, 'new_NodeTree_execution': False,
            'new_resource_measurements': False, 'consumer_result': 'REFUSED',
            'production_resource_budgets_qualified': False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--corpus', type=Path, default=HERE / 'testdata/candidate-tree-scale.json')
    parser.add_argument('--samples', type=Path, default=HERE / 'testdata/candidate-tree-scale-samples.json')
    args = parser.parse_args(argv)
    raw, corpus = BYTE.read_corpus(args.corpus)
    report = check_corpus(corpus)
    _, samples = BYTE.read_corpus(args.samples)
    report.update(check_samples(samples, raw, corpus))
    report.update(corpus_sha256=hashlib.sha256(raw).hexdigest(), node_revision=BYTE.NODE_REVISION, node_tree=BYTE.NODE_TREE)
    print(json.dumps(report, sort_keys=True, separators=(',', ':')))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError, OverflowError, RecursionError):
        print('Larger finite tree evidence refused; production acceptance remains disabled.', file=sys.stderr)
        sys.exit(1)
