#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Bind driver self usage and Go build wall/CPU to complete offline tree bytes.

Unsigned recordings cannot authenticate execution, caches, hardware, snapshots,
accepted headers, activation, canonicality/finality or production state values.
This portable checker performs no build, node execution or resource observation.
"""
import argparse
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


LIFE = load('driver_unchanged_lifecycle_checker', 'check_tree_import_lifecycle.py')
OBS = load('driver_resource_observation_contract', 'observe_driver_resources.py')
BYTE, RET, encoded = LIFE.BYTE, LIFE.RET, LIFE.encoded
INPUT_NAMES = LIFE.INPUT_NAMES + ('observe_driver_resources.py', 'observe_driver_resources_test.py',
    'check_tree_driver_resources.py', 'check_tree_driver_resources_test.py', 'reproduce_tree_driver_resources.py')
CACHE_POLICY = 'existing local default Go build/module caches reused without flushing; offline GOPROXY/GOSUMDB; initial contents, cache hits and cold/warm state unmeasured'
MAX_DRIVER_WALL_NS = 18_000_000_000_000
SCOPE = {'unchanged_lifecycle_driver_and_24_ordered_reference_children': True,
    'driver_call_wall_including_source_build_children_parent_checks_and_inner_persistence': True,
    'driver_SELF_CPU_interval_and_lifetime_RSS_through_return_observed': True,
    'Go_build_command_wall_and_waited_descendant_CPU_observed': True,
    'one_driver_call_and_one_build_selected_before_execution': True,
    'driver_repetitions': 1, 'build_repetitions': 1, 'reference_children': 24,
    'within_batch_retries': 0, 'filtered_samples': 0,
    'SELF_RSS_includes_pre_interval_imports_and_preflight': True,
    'SELF_RSS_through_interpreter_exit_measured': False,
    'final_outer_report_encoding_or_persistence_measured': False,
    'compiler_or_build_process_tree_peak_memory_measured': False,
    'whole_pipeline_simultaneous_peak_memory_measured': False,
    'CPU_counter_storage_implies_nanosecond_precision': False,
    'cold_or_warm_cache_state_qualified': False,
    'input_temp_workspace_or_peak_disk_measured': False,
    'execution_provenance_authenticated': False, 'target_hardware_identity_authenticated': False,
    'real_chain_archive_or_snapshot_executed': False,
    'accepted_header_profile_activation_or_state_value_qualified': False,
    'canonicality_finality_or_freshness_qualified': False,
    'production_resource_budgets_qualified': False, 'consumer_result': 'REFUSED',
    'production_acceptance_enabled': False}


def require(condition):
    if not condition:
        raise ValueError('Driver resource evidence differs from the selected finite contract')


def input_pins():
    return {name: hashlib.sha256((HERE / name).read_bytes()).hexdigest() for name in INPUT_NAMES}


def check_snapshot(row, platform):
    require(type(row) is dict and set(row) == {'self', 'waited_children_cpu'})
    own, children = row['self'], row['waited_children_cpu']
    require(type(own) is dict and set(own) == {'native_peak_rss', 'native_rss_unit',
        'process_peak_rss_bytes', 'user_cpu_ns', 'system_cpu_ns'})
    require(type(children) is dict and set(children) == {'user_cpu_ns', 'system_cpu_ns'})
    unit, factor = OBS.native_rss_unit(platform)
    RET.exact(own['native_rss_unit'], unit)
    for key in ('native_peak_rss', 'process_peak_rss_bytes'):
        RET.integer(own[key], 1)
    require(own['process_peak_rss_bytes'] == own['native_peak_rss'] * factor)
    for group in (own, children):
        for key in ('user_cpu_ns', 'system_cpu_ns'):
            RET.integer(group[key], 0)


def check_observation(row, label, platform):
    require(type(row) is dict and set(row) == {'label', 'call_returned', 'exception_type',
        'capture_platform', 'elapsed_ns', 'wall_method', 'self_method', 'child_cpu_method',
        'cpu_storage_method', 'before', 'after', 'self_user_cpu_delta_ns',
        'self_system_cpu_delta_ns', 'waited_children_user_cpu_delta_ns', 'waited_children_system_cpu_delta_ns'})
    for key, value in {'label': label, 'call_returned': True, 'exception_type': None,
        'capture_platform': platform, 'wall_method': OBS.WALL_METHOD, 'self_method': OBS.SELF_METHOD,
        'child_cpu_method': OBS.CHILD_CPU_METHOD, 'cpu_storage_method': OBS.CPU_METHOD}.items():
        RET.exact(row[key], value)
    RET.integer(row['elapsed_ns'], 1)
    require(row['elapsed_ns'] <= MAX_DRIVER_WALL_NS)
    for point in ('before', 'after'):
        check_snapshot(row[point], platform)
    require(row['after']['self']['native_peak_rss'] >= row['before']['self']['native_peak_rss'])
    for group, prefix in (('self', 'self'), ('waited_children_cpu', 'waited_children')):
        for mode in ('user', 'system'):
            key = mode + '_cpu_ns'
            difference = row['after'][group][key] - row['before'][group][key]
            require(difference >= 0)
            RET.integer(row[prefix + '_' + mode + '_cpu_delta_ns'], 0)
            RET.exact(row[prefix + '_' + mode + '_cpu_delta_ns'], difference)
    # Parallel compiler CPU may exceed elapsed wall; never impose CPU <= wall.


def check_driver_contract(document, lifecycle):
    """Check the added envelope; the caller must also validate lifecycle bytes."""
    require(type(document) is dict and set(document) == {'format_version', 'kind', 'source', 'scope',
        'corpus_sha256', 'research_source_inputs', 'cache_policy', 'lifecycle_samples',
        'driver', 'build', 'build_command', 'consumer_result', 'production_acceptance_enabled'})
    for key, value in {'format_version': 1, 'kind': 'candidate-tree-driver-resource-samples',
        'source': LIFE.SCALE.SCALE.SOURCE, 'scope': SCOPE, 'research_source_inputs': input_pins(),
        'cache_policy': CACHE_POLICY, 'consumer_result': 'REFUSED', 'production_acceptance_enabled': False}.items():
        RET.exact(document[key], value)
    RET.exact(document['corpus_sha256'], lifecycle['corpus_sha256'])
    platform = lifecycle['phase_samples']['source_execution_platform']
    driver, build = document['driver'], document['build']
    check_observation(driver, 'lifecycle-driver', platform)
    check_observation(build, 'go-build-tests', platform)
    command = document['build_command']
    require(type(command) is dict and set(command) == {'label', 'completed', 'actual_exit',
                                                      'stdout_sha256', 'stderr_sha256'})
    empty_hash = hashlib.sha256(b'').hexdigest()
    RET.exact(command, {'label': 'go-build-tests', 'completed': True, 'actual_exit': 0,
                       'stdout_sha256': empty_hash, 'stderr_sha256': empty_hash})
    require(driver['elapsed_ns'] >= build['elapsed_ns'] + sum(
        row['elapsed_ns'] for group in lifecycle['lifecycle'] for row in group))
    for group in ('self', 'waited_children_cpu'):
        for key in ('user_cpu_ns', 'system_cpu_ns'):
            require(driver['before'][group][key] <= build['before'][group][key] <=
                    build['after'][group][key] <= driver['after'][group][key])
    require(driver['before']['self']['native_peak_rss'] <= build['before']['self']['native_peak_rss'] <=
            build['after']['self']['native_peak_rss'] <= driver['after']['self']['native_peak_rss'])


def check_samples(document, corpus_raw, corpus):
    lifecycle = document['lifecycle_samples']
    summary = LIFE.check_samples(lifecycle, corpus_raw, corpus)
    check_driver_contract(document, lifecycle)
    require(len(encoded(document)) <= BYTE.MAX_FILE_BYTES)
    return summary | {'recorded_driver_calls': 1, 'recorded_build_commands': 1,
        'driver_SELF_usage_separate_from_waited_children': True,
        'parent_or_compiler_memory_measured': True,
        'parent_SELF_lifetime_RSS_through_driver_return_observed': True,
        'build_wall_and_waited_CPU_bound': True, 'compiler_peak_memory_measured': False,
        'cold_or_warm_cache_state_qualified': False, 'parent_RSS_through_exit_measured': False,
        'whole_pipeline_memory_measured': False, 'production_acceptance_enabled': False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--corpus', type=Path, default=HERE / 'testdata/candidate-tree-import-scale.json')
    parser.add_argument('--samples', type=Path, default=HERE / 'testdata/candidate-tree-driver-resource-samples.json')
    parser.add_argument('--source-revision')
    args = parser.parse_args(argv)
    require(args.source_revision is None or re.fullmatch(r'[0-9a-f]{40}', args.source_revision) is not None)
    raw, corpus = BYTE.read_corpus(args.corpus)
    _, samples = BYTE.read_corpus(args.samples)
    report = check_samples(samples, raw, corpus)
    report.update(corpus_sha256=hashlib.sha256(raw).hexdigest(), samples_sha256=hashlib.sha256(encoded(samples)).hexdigest(),
                  source_revision=args.source_revision, node_revision=BYTE.NODE_REVISION, node_tree=BYTE.NODE_TREE)
    print(json.dumps(report, sort_keys=True, separators=(',', ':')))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError, OverflowError, RecursionError):
        print('Driver resource evidence refused; production acceptance remains disabled.', file=sys.stderr)
        sys.exit(1)
