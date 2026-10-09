#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Bind fresh complete driver comparisons to independent complete tree bytes.

Portable recorded-data checks run no worker, build, node or resource observer.
Unsigned observations establish no hardware, cache, snapshot, accepted header,
activation, finality or production resource/state-value qualification.
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


PREVIOUS = load('driver_previous_projection_contract', 'check_oracle_projection.py')
PROJECTOR = load('driver_complete_level_projection', 'project_driver_oracles.py')
LEGACY = PREVIOUS.DRIVER
BYTE, RET, OBS, encoded = LEGACY.BYTE, LEGACY.RET, LEGACY.OBS, LEGACY.encoded
INPUT_NAMES = PREVIOUS.INPUT_NAMES + ('project_driver_oracles.py', 'check_projected_driver.py',
                                     'check_projected_driver_test.py', 'measure_projected_driver.py')
MODES = PROJECTOR.MODES
REFERENCE = {'repository': 'https://github.com/edgepillar/zenon-spv',
    'revision': '1e78923d2d38a09697b338cef90517ec727925cd',
    'tree': '7f8e01132e0ceed9010059ca4581eba0b79f2ad8',
    'level_source_sha256': PROJECTOR.LEVEL_SOURCE_SHA256}
SCOPE = {'fresh_serial_Python_driver_workers': True, 'generations': 2,
    'modes': list(MODES), 'workers': 4, 'builds': 4, 'reference_children': 96,
    'driver_samples_per_mode': 2, 'mode_order_per_generation': [list(MODES), list(reversed(MODES))],
    'within_batch_retries': 0, 'filtered_samples': 0,
    'unchanged_Go_workload_build_flags_and_per_child_capture': True,
    'complete_import_map_delta_DAG_refcount_root_and_proof_bytes_required': True,
    'every_leaf_and_parent_hashed': True, 'all_three_level_seams_selected_in_each_driver': True,
    'projected_mode_changes_all_three_level_seams': True,
    'expected_corpus_preparation_delegation_final_checks_encoding_and_inner_persistence_in_observed_call': True,
    'SELF_CPU_interval_and_lifetime_RSS_through_call_observed': True,
    'SELF_RSS_includes_imports_and_source_preselection': True,
    'Go_build_wall_and_waited_descendant_CPU_observed_separately': True,
    'reference_child_wall_and_RSS_through_exit_observed_separately': True,
    'hard_whole_worker_deadline_enforced': False,
    'final_resource_report_encoding_persistence_and_exit_measured': False,
    'controller_stock_oracle_check_or_memory_measured': False,
    'compiler_peak_memory_measured': False, 'whole_pipeline_memory_measured': False,
    'peak_disk_measured': False, 'cold_or_warm_cache_state_qualified': False,
    'CPU_counter_storage_implies_nanosecond_precision': False,
    'execution_provenance_authenticated': False, 'target_hardware_identity_authenticated': False,
    'real_chain_archive_or_snapshot_executed': False,
    'accepted_header_profile_activation_or_state_value_qualified': False,
    'canonicality_finality_freshness_qualified': False, 'production_resource_budgets_qualified': False,
    'network_wallet_signing_or_transactions_executed': False,
    'consumer_result': 'REFUSED', 'production_acceptance_enabled': False}
DELEGATE_STDOUT = (json.dumps({'actual_fresh_child_samples': 24, 'selected_cases': 2,
    'deterministic_generations': 2, 'node_blobs': 394, 'production_acceptance_enabled': False}, sort_keys=True) + '\n' +
    json.dumps({'actual_reference_children': 24, 'full_selected_child_wall_and_exit_RSS_observed': True,
    'whole_pipeline_memory_measured': False, 'production_acceptance_enabled': False}, sort_keys=True) + '\n').encode('ascii')


def require(condition):
    if not condition:
        raise ValueError('Recorded complete driver projection comparison refused')


def input_pins():
    return {n: hashlib.sha256((HERE / n).read_bytes()).hexdigest() for n in INPUT_NAMES}


def inventory():
    return [(g, m) for g in range(2) for m in (MODES if g == 0 else tuple(reversed(MODES)))]


def label(generation, mode):
    return 'driver-%d-%s' % (generation, mode)


def bindings():
    return {'level_source_sha256': PROJECTOR.LEVEL_SOURCE_SHA256,
        'level_seams': list(PROJECTOR.SEAM_PATHS),
        'selected_paths': [p.hex() for p in PROJECTOR.selected_paths()],
        'every_leaf_and_parent_hashed': True, 'complete_oracle_checks_preserved': True,
        'unknown_query_or_seam_refused': True, 'serial_caller_required': True}


def worker_document(sample, document):
    return {k: v for k, v in sample.items() if k != 'command'} | {k: document[k] for k in
        ('runtime', 'research_source_inputs', 'python_executable_sha256', 'go_executable_sha256')}


def check_contract(document, corpus_raw, corpus):
    require(type(document) is dict and set(document) == {'format_version', 'kind', 'source', 'reference',
        'scope', 'corpus_sha256', 'research_source_inputs', 'runtime', 'python_executable_sha256',
        'go_executable_sha256', 'cache_policy', 'samples', 'consumer_result', 'production_acceptance_enabled'})
    for k, v in {'format_version': 1, 'kind': 'selected-complete-driver-projection-comparison',
        'source': LEGACY.LIFE.SCALE.SCALE.SOURCE, 'reference': REFERENCE, 'scope': SCOPE,
        'corpus_sha256': hashlib.sha256(corpus_raw).hexdigest(), 'research_source_inputs': input_pins(),
        'cache_policy': LEGACY.CACHE_POLICY, 'consumer_result': 'REFUSED', 'production_acceptance_enabled': False}.items():
        RET.exact(document[k], v)
    require(type(corpus_raw) is bytes and len(corpus_raw) <= BYTE.MAX_FILE_BYTES)
    RET.exact(json.loads(corpus_raw, object_pairs_hook=BYTE.object_pairs), corpus)
    for k in ('python_executable_sha256', 'go_executable_sha256'):
        RET.digest_field(document[k])
    runtime = document['runtime']
    require(type(runtime) is dict and set(runtime) == {'os', 'architecture', 'python', 'implementation'})
    require(type(runtime['os']) is str and runtime['os'] in ('darwin', 'linux'))
    require(type(runtime['architecture']) is str and runtime['architecture'] in ('arm64', 'aarch64', 'x86_64', 'amd64'))
    RET.exact(runtime['implementation'], 'CPython')
    require(type(runtime['python']) is str and re.fullmatch(r'3\.[0-9]+\.[0-9]+', runtime['python']) is not None)
    require(type(document['samples']) is list and len(document['samples']) == 4)
    binaries, versions = set(), set()
    empty_hash = hashlib.sha256(b'').hexdigest()
    for sample, (generation, mode) in zip(document['samples'], inventory()):
        require(type(sample) is dict and set(sample) == {'generation', 'mode', 'oracle_bindings',
            'result_bytes', 'result_sha256', 'delegate_stdout_sha256', 'lifecycle_samples',
            'driver', 'build', 'build_command', 'command'})
        name = label(generation, mode)
        for k, v in {'generation': generation, 'mode': mode, 'oracle_bindings': bindings(),
            'result_bytes': len(corpus_raw), 'result_sha256': hashlib.sha256(corpus_raw).hexdigest(),
            'delegate_stdout_sha256': hashlib.sha256(DELEGATE_STDOUT).hexdigest()}.items():
            RET.exact(sample[k], v)
        lifecycle = sample['lifecycle_samples']
        RET.exact(lifecycle['corpus_sha256'], document['corpus_sha256'])
        phase = lifecycle['phase_samples']
        RET.exact(phase['source_execution_platform'], runtime['os'])
        binaries.add(phase['reference_binary_sha256'])
        versions.add(phase['go_version'])
        driver, build = sample['driver'], sample['build']
        LEGACY.check_observation(driver, name, runtime['os'])
        LEGACY.check_observation(build, 'selected-go-build', runtime['os'])
        RET.exact(sample['build_command'], {'label': 'go-build-tests', 'completed': True, 'actual_exit': 0,
            'stdout_sha256': empty_hash, 'stderr_sha256': empty_hash})
        require(driver['elapsed_ns'] >= build['elapsed_ns'] + sum(r['elapsed_ns'] for g in lifecycle['lifecycle'] for r in g))
        for group in ('self', 'waited_children_cpu'):
            for k in ('user_cpu_ns', 'system_cpu_ns'):
                require(driver['before'][group][k] <= build['before'][group][k] <=
                        build['after'][group][k] <= driver['after'][group][k])
        require(driver['before']['self']['native_peak_rss'] <= build['before']['self']['native_peak_rss'] <=
                build['after']['self']['native_peak_rss'] <= driver['after']['self']['native_peak_rss'])
        expected_stdout = encoded(worker_document(sample, document))
        RET.exact(sample['command'], {'label': name, 'completed': True, 'actual_exit': 0,
            'stdout_sha256': hashlib.sha256(expected_stdout).hexdigest(), 'stderr_sha256': empty_hash})
    require(len(binaries) == len(versions) == 1)
    architecture = {'x86_64': 'amd64', 'aarch64': 'arm64'}.get(runtime['architecture'], runtime['architecture'])
    require(next(iter(versions)).endswith(' ' + runtime['os'] + '/' + architecture))
    require(len(encoded(document)) <= BYTE.MAX_FILE_BYTES)


def observations(document):
    report = {}
    for mode in MODES:
        rows = [s for s in document['samples'] if s['mode'] == mode]
        require(len(rows) == 2)
        report[mode] = {'samples': 2,
            'SELF_lifetime_RSS_bytes': [s['driver']['after']['self']['process_peak_rss_bytes'] for s in rows],
            'SELF_lifetime_RSS_median_bytes': statistics.median(s['driver']['after']['self']['process_peak_rss_bytes'] for s in rows),
            'selected_call_wall_ns': [s['driver']['elapsed_ns'] for s in rows],
            'selected_call_wall_median_ns': statistics.median(s['driver']['elapsed_ns'] for s in rows),
            'build_wall_ns': [s['build']['elapsed_ns'] for s in rows],
            'reference_child_wall_sum_ns': [sum(r['elapsed_ns'] for g in s['lifecycle_samples']['lifecycle'] for r in g) for s in rows]}
    return report


def check_samples(document, corpus_raw, corpus):
    # Unchanged stock reconstruction is mandatory in this portable checker.
    LEGACY.LIFE.SCALE.check_corpus(corpus)
    check_contract(document, corpus_raw, corpus)
    for sample in document['samples']:
        LEGACY.LIFE.check_samples(sample['lifecycle_samples'], corpus_raw, corpus)
    return {'fresh_recorded_driver_workers': 4, 'recorded_build_commands': 4, 'recorded_reference_children': 96,
        'complete_corpus_byte_bindings': 4, 'research_source_inputs_bound': len(INPUT_NAMES),
        'independent_stock_complete_byte_oracle_required': True, 'new_resource_measurements': False,
        'NodeTree_execution_in_checker': False, 'SELF_RSS_is_not_an_interval_delta_or_through_exit_peak': True,
        'compiler_peak_memory_measured': False, 'whole_pipeline_memory_measured': False,
        'production_resource_budgets_qualified': False, 'execution_provenance_authenticated': False,
        'target_hardware_identity_authenticated': False, 'observations': observations(document),
        'consumer_result': 'REFUSED', 'production_acceptance_enabled': False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--corpus', type=Path, default=HERE / 'testdata/candidate-tree-import-scale.json')
    parser.add_argument('--samples', type=Path, default=HERE / 'testdata/candidate-projected-driver-samples.json')
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
        print('Complete driver comparison refused; production acceptance remains disabled.', file=sys.stderr)
        raise SystemExit(1)
