#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Bind separate fresh Python oracle workers to complete independent bytes.

Recorded resource counters are unsigned, scoped SELF observations. They do not
authenticate execution, hardware, snapshots, accepted headers or state values.
The portable checker executes no workers, builds, nodes or resource observers.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import statistics
import sys

HERE = Path(__file__).resolve().parent


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, HERE / file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PROJECT = load('recorded_projected_oracle', 'project_sparse_oracle.py')
DRIVER = load('oracle_counter_contract', 'check_tree_driver_resources.py')
IMPORT, BYTE, RET, OBS = PROJECT.IMPORT, PROJECT.BYTE, PROJECT.RET, DRIVER.OBS
encoded = IMPORT.encoded
INPUT_NAMES = DRIVER.INPUT_NAMES + ('project_sparse_oracle.py', 'check_oracle_projection.py',
                                   'check_oracle_projection_test.py', 'measure_oracle_projection.py')
REFERENCE = {'repository': 'https://github.com/edgepillar/zenon-spv',
    'revision': '9ec07b648d1bd7f47b4e5e4d64a37e894c011790',
    'tree': '06fd7542d68aafd46fd4c087b258bd3528761da4',
    'level_source_sha256': '558787e3c10a3cff6ea31a1062d2bb7c27c12cc55fc5d390c177783848c278e5'}
MODES = ('reference', 'projected')
MAX_WORKER_WALL_NS = 600_000_000_000
SCOPE = {'fresh_serial_Python_workers': True, 'generations': 2, 'repetitions': 3,
    'modes': list(MODES), 'workers': 24, 'within_batch_retries': 0, 'filtered_samples': 0,
    'mode_order_per_generation': [list(MODES), list(reversed(MODES))],
    'complete_import_map_delta_DAG_refcount_root_and_proof_bytes_required': True,
    'every_leaf_and_parent_hashed': True, 'only_selected_siblings_retained_in_projected_mode': True,
    'result_canonical_encoding_and_file_persistence_in_observed_call': True,
    'SELF_CPU_interval_and_lifetime_RSS_through_call_observed': True,
    'SELF_RSS_includes_imports_and_preflight': True,
    'final_resource_report_encoding_and_exit_measured': False,
    'resource_counter_precision_is_nanoseconds': False,
    'whole_driver_or_pipeline_memory_measured': False, 'peak_disk_measured': False,
    'target_hardware_identity_authenticated': False, 'execution_provenance_authenticated': False,
    'real_archive_snapshot_or_NodeTree_executed': False, 'accepted_header_profile_activation_qualified': False,
    'canonicality_finality_freshness_qualified': False, 'production_resource_budgets_qualified': False,
    'network_wallet_signing_or_transactions_executed': False,
    'consumer_result': 'REFUSED', 'production_acceptance_enabled': False}


def require(condition):
    if not condition:
        raise ValueError('Recorded sparse oracle comparison refused')


def input_pins():
    return {name: hashlib.sha256((HERE / name).read_bytes()).hexdigest() for name in INPUT_NAMES}


def inventory():
    return [(g, s, r, m) for g in range(2) for s in IMPORT.SELECTIONS for r in range(3)
            for m in (MODES if g == 0 else tuple(reversed(MODES)))]


def label(generation, selection, repetition, mode):
    return 'oracle-%d-%s-%d-%s' % (generation, selection[0], repetition, mode)


def worker_document(sample, runtime, pins, executable_hash):
    return {k: v for k, v in sample.items() if k != 'command'} | {
        'runtime': runtime, 'research_source_inputs': pins, 'python_executable_sha256': executable_hash}


def check_contract(document, corpus_raw, corpus):
    require(type(corpus_raw) is bytes and len(corpus_raw) <= BYTE.MAX_FILE_BYTES)
    fields = {'format_version', 'kind', 'source', 'reference', 'scope', 'corpus_sha256',
              'research_source_inputs', 'runtime', 'python_executable_sha256', 'samples',
              'consumer_result', 'production_acceptance_enabled'}
    require(type(document) is dict and set(document) == fields)
    for key, value in {'format_version': 1, 'kind': 'selected-sparse-oracle-comparison',
        'source': IMPORT.SCALE.SOURCE, 'reference': REFERENCE, 'scope': SCOPE,
        'corpus_sha256': hashlib.sha256(corpus_raw).hexdigest(), 'research_source_inputs': input_pins(),
        'consumer_result': 'REFUSED', 'production_acceptance_enabled': False}.items():
        RET.exact(document[key], value)
    require(type(corpus_raw) is bytes and len(corpus_raw) <= BYTE.MAX_FILE_BYTES)
    RET.exact(json.loads(corpus_raw, object_pairs_hook=BYTE.object_pairs), corpus)
    RET.digest_field(document['python_executable_sha256'])
    runtime = document['runtime']
    require(type(runtime) is dict and set(runtime) == {'os', 'architecture', 'python', 'implementation'})
    require(type(runtime['os']) is str and runtime['os'] in ('darwin', 'linux'))
    require(type(runtime['architecture']) is str and runtime['architecture'] in ('arm64', 'aarch64', 'x86_64', 'amd64'))
    RET.exact(runtime['implementation'], 'CPython')
    require(type(runtime['python']) is str and re.fullmatch(r'3\.[0-9]+\.[0-9]+', runtime['python']) is not None)
    require(type(document['samples']) is list and len(document['samples']) == 24)
    require(len(corpus['cases']) == len(IMPORT.SELECTIONS) == 2)
    cases = {}
    for case, selection in zip(corpus['cases'], IMPORT.SELECTIONS):
        RET.exact(case['input'], dict(zip(('name', 'keys', 'versions', 'retain'), selection)))
        cases[selection[0]] = encoded(case)
    for sample, (g, s, r, mode) in zip(document['samples'], inventory()):
        require(type(sample) is dict and set(sample) == {'generation', 'case', 'repetition', 'mode',
            'result_bytes', 'result_sha256', 'resource', 'command'})
        wanted = label(g, s, r, mode)
        for key, value in {'generation': g, 'case': s[0], 'repetition': r, 'mode': mode,
            'result_bytes': len(cases[s[0]]), 'result_sha256': hashlib.sha256(cases[s[0]]).hexdigest()}.items():
            RET.exact(sample[key], value)
        DRIVER.check_observation(sample['resource'], wanted, runtime['os'])
        require(sample['resource']['elapsed_ns'] <= MAX_WORKER_WALL_NS)
        for point in ('before', 'after'):
            RET.exact(sample['resource'][point]['waited_children_cpu'], {'user_cpu_ns': 0, 'system_cpu_ns': 0})
        command = sample['command']
        require(type(command) is dict and set(command) == {'label', 'completed', 'actual_exit', 'stdout_sha256', 'stderr_sha256'})
        for key, value in {'label': wanted, 'completed': True, 'actual_exit': 0,
                           'stderr_sha256': hashlib.sha256(b'').hexdigest()}.items():
            RET.exact(command[key], value)
        RET.digest_field(command['stdout_sha256'])
        expected_stdout = encoded(worker_document(sample, runtime, document['research_source_inputs'],
                                                   document['python_executable_sha256']))
        RET.exact(command['stdout_sha256'], hashlib.sha256(expected_stdout).hexdigest())
    require(len(encoded(document)) <= BYTE.MAX_FILE_BYTES)


def observations(document):
    output = {}
    for selection in IMPORT.SELECTIONS:
        modes = {}
        for mode in MODES:
            rows = [s['resource'] for s in document['samples'] if s['case'] == selection[0] and s['mode'] == mode]
            require(len(rows) == 6)
            rss = [r['after']['self']['process_peak_rss_bytes'] for r in rows]
            wall = [r['elapsed_ns'] for r in rows]
            modes[mode] = {'samples': 6, 'SELF_lifetime_RSS_min_bytes': min(rss),
                'SELF_lifetime_RSS_median_bytes': statistics.median(rss), 'SELF_lifetime_RSS_max_bytes': max(rss),
                'call_wall_median_ns': statistics.median(wall),
                'SELF_CPU_median_ns': statistics.median(r['self_user_cpu_delta_ns'] + r['self_system_cpu_delta_ns'] for r in rows)}
        output[selection[0]] = modes
    return output


def check_samples(document, corpus_raw, corpus):
    # Full legacy reconstruction is mandatory; a corpus answer is never enough.
    IMPORT.check_corpus(corpus)
    check_contract(document, corpus_raw, corpus)
    return {'fresh_recorded_Python_workers': 24, 'generations': 2, 'repetitions': 3,
        'complete_case_byte_bindings': 24, 'selected_initial_keys': [512, 4096],
        'research_source_inputs_bound': len(INPUT_NAMES), 'independent_complete_import_oracle_required': True,
        'new_NodeTree_execution': False, 'new_resource_measurements': False,
        'SELF_lifetime_high_water_is_not_an_interval_RSS_delta': True,
        'whole_pipeline_memory_measured': False, 'execution_provenance_authenticated': False,
        'target_hardware_identity_authenticated': False, 'production_resource_budgets_qualified': False,
        'observations': observations(document), 'consumer_result': 'REFUSED',
        'production_acceptance_enabled': False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--corpus', type=Path, default=HERE / 'testdata/candidate-tree-import-scale.json')
    parser.add_argument('--samples', type=Path, default=HERE / 'testdata/candidate-oracle-projection-samples.json')
    parser.add_argument('--source-revision')
    args = parser.parse_args(argv)
    require(args.source_revision is None or re.fullmatch(r'[0-9a-f]{40}', args.source_revision) is not None)
    raw, corpus = BYTE.read_corpus(args.corpus)
    _, document = BYTE.read_corpus(args.samples)
    report = check_samples(document, raw, corpus)
    report.update(source_revision=args.source_revision, corpus_sha256=hashlib.sha256(raw).hexdigest(),
                  samples_sha256=hashlib.sha256(encoded(document)).hexdigest(), node_revision=BYTE.NODE_REVISION, node_tree=BYTE.NODE_TREE)
    print(json.dumps(report, sort_keys=True, separators=(',', ':')))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError, OverflowError, RecursionError):
        print('Sparse oracle comparison refused; production acceptance remains disabled.', file=sys.stderr)
        raise SystemExit(1)
