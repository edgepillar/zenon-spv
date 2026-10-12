#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Bind non-atomic workspace rows to complete unchanged reference-child bytes.

Unsigned records do not authenticate execution or qualify peak disk, compiler
memory, real snapshots, retained Momentum hashes or production state proofs.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, HERE / file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


LEGACY = load('workspace_complete_byte_contract', 'check_projected_driver.py')
OBS = load('workspace_stat_contract', 'observe_temp_workspace.py')
LIFE, BYTE, RET = LEGACY.LEGACY.LIFE, LEGACY.BYTE, LEGACY.RET
NAMES = ('observe_temp_workspace.py', 'observe_temp_workspace_test.py',
         'check_temp_workspace.py', 'check_temp_workspace_test.py',
         'reproduce_temp_workspace.py')
SCOPE = {'unchanged_512_4096_keys_16_versions_8_retained': True,
         'complete_file_map_delta_DAG_refcount_root_and_proof_bytes_checked': True,
         'one_driver_one_build_24_ordered_children': True,
         'only_child_TMPDIR_and_wait_observation_seams_added': True,
         'literal_inputs_and_database_observed_separately': True,
         'source_compiler_caches_and_evidence_outside_selected_TMPDIR': True,
         'non_atomic_stat_traversals_with_vanished_entries_retained': True,
         'observer_IO_and_scheduling_included_in_new_child_wall': True,
         'earlier_child_timings_are_not_this_observation_scope': True,
         'periodic_acceptance_caps_are_not_hard_disk_limits': True,
         'peak_disk_measured': False, 'instantaneous_footprint_measured': False,
         'compiler_peak_memory_measured': False, 'whole_pipeline_memory_measured': False,
         'real_chain_archive_or_snapshot_executed': False,
         'production_resource_budgets_qualified': False,
         'execution_provenance_authenticated': False,
         'accepted_header_profile_activation_or_retained_hash_qualified': False,
         'within_batch_retries': 0, 'filtered_samples': 0,
         'consumer_result': 'REFUSED', 'production_acceptance_enabled': False}


def require(condition):
    if not condition:
        raise ValueError('Temporary workspace evidence differs from the selected finite contract')


encoded = LIFE.encoded


def input_pins():
    return LEGACY.input_pins() | {n: hashlib.sha256((HERE / n).read_bytes()).hexdigest() for n in NAMES}


def check_row(row, sequence, previous_finished):
    require(type(row) is dict and set(row) == set(OBS.FIELDS) | {
        'sequence', 'boundary', 'started_elapsed_ns', 'finished_elapsed_ns', 'observation_elapsed_ns'})
    RET.exact(row['sequence'], sequence)
    require(row['boundary'] in ('before-spawn', 'while-waiting', 'after-reap'))
    for key in OBS.FIELDS + ('started_elapsed_ns', 'finished_elapsed_ns', 'observation_elapsed_ns'):
        RET.integer(row[key], 0)
    require(row['started_elapsed_ns'] >= previous_finished
            and row['finished_elapsed_ns'] >= row['started_elapsed_ns']
            and row['observation_elapsed_ns'] == row['finished_elapsed_ns'] - row['started_elapsed_ns'])
    require(row['entries'] <= OBS.MAX_ENTRIES and row['file_bytes'] <= OBS.MAX_FILE_BYTES)
    require(row['regular_files'] == row['input_files'] + row['database_files'] + row['other_files'])
    require(row['file_bytes'] == row['input_file_bytes'] + row['database_file_bytes'] + row['other_file_bytes'])
    require(row['directories'] + row['regular_files'] <= row['entries'])
    require(row['vanished_entries'] <= row['entries'] + row['directories'])
    require(row['allocated_file_bytes'] % 512 == row['database_allocated_file_bytes'] % 512 == 0)
    require(row['database_allocated_file_bytes'] <= row['allocated_file_bytes'])
    require(row['largest_file_bytes'] <= row['file_bytes'])
    if row['regular_files'] == 0:
        require(row['file_bytes'] == row['allocated_file_bytes'] == row['largest_file_bytes'] == 0)
    else:
        require(row['file_bytes'] <= row['regular_files'] * row['largest_file_bytes'])
    # This selected child owns only literal input files and its database.
    require(row['other_files'] == row['other_file_bytes'] == 0)


def check_samples(document, corpus_raw, corpus):
    require(type(document) is dict and set(document) == {'format_version', 'kind', 'source', 'scope',
        'research_source_inputs', 'corpus_sha256', 'lifecycle_samples', 'observations',
        'consumer_result', 'production_acceptance_enabled'})
    fixed = {'format_version': 1, 'kind': 'candidate-input-database-workspace-samples',
        'source': LIFE.SCALE.SCALE.SOURCE, 'scope': SCOPE, 'research_source_inputs': input_pins(),
        'corpus_sha256': hashlib.sha256(corpus_raw).hexdigest(),
        'consumer_result': 'REFUSED', 'production_acceptance_enabled': False}
    for key, value in fixed.items():
        RET.exact(document[key], value)
    report = LIFE.check_samples(document['lifecycle_samples'], corpus_raw, corpus)
    observations = document['observations']
    require(type(observations) is list and len(observations) == 24)
    children = [r for generation in document['lifecycle_samples']['lifecycle'] for r in generation]
    choices = [(case, repetition, mode) for _ in range(2) for case, repetition, mode in LIFE.SCALE.inventory(corpus)]
    total = 0
    for observation, child, choice in zip(observations, children, choices):
        require(type(observation) is dict and set(observation) == {'label', 'method', 'capture_platform',
            'interval_ns', 'maximum_samples', 'maximum_entries', 'maximum_depth', 'maximum_file_bytes',
            'capture_exception_type', 'capture_actual_exit', 'capture_reaped', 'capture_refusal',
            'points', 'summary'})
        for key, value in {'label': child['label'], 'method': OBS.METHOD,
            'capture_platform': document['lifecycle_samples']['phase_samples']['source_execution_platform'],
            'interval_ns': OBS.INTERVAL_NS, 'maximum_samples': OBS.MAX_SAMPLES,
            'maximum_entries': OBS.MAX_ENTRIES, 'maximum_depth': OBS.MAX_DEPTH,
            'maximum_file_bytes': OBS.MAX_FILE_BYTES, 'capture_exception_type': None,
            'capture_actual_exit': 0, 'capture_reaped': True, 'capture_refusal': ''}.items():
            RET.exact(observation[key], value)
        points = observation['points']
        require(type(points) is list and 2 <= len(points) <= OBS.MAX_SAMPLES)
        previous = 0
        for sequence, row in enumerate(points):
            check_row(row, sequence, previous)
            previous = row['finished_elapsed_ns']
            boundary = 'before-spawn' if sequence == 0 else 'after-reap' if sequence == len(points) - 1 else 'while-waiting'
            RET.exact(row['boundary'], boundary)
        require(points[0]['entries'] == points[-1]['entries'] == 0)
        RET.exact(observation['summary'], OBS.summary(points))
        require(observation['summary']['maximum_observed_input_file_bytes'] > 0
                and observation['summary']['maximum_observed_database_file_bytes'] > 0)
        case, _, _ = choice
        selected_input_bytes = sum(r['selection']['bytes'] for s in case['steps'] for r in s['imports'])
        require(observation['summary']['maximum_observed_input_file_bytes'] <= selected_input_bytes)
        total += len(points)
    require(len(encoded(document)) <= BYTE.MAX_FILE_BYTES)
    return report | {'workspace_children_bound': 24, 'workspace_stat_observations': total,
                     'non_atomic_observed_values_only': True, 'peak_disk_measured': False,
                     'instantaneous_footprint_measured': False, 'compiler_peak_memory_measured': False,
                     'production_acceptance_enabled': False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--corpus', type=Path, default=HERE / 'testdata/candidate-tree-import-scale.json')
    parser.add_argument('--samples', type=Path, default=HERE / 'testdata/candidate-temp-workspace-samples.json')
    args = parser.parse_args(argv)
    raw, corpus = BYTE.read_corpus(args.corpus)
    _, document = BYTE.read_corpus(args.samples)
    roots = {'lifecycle': LEGACY.load('workspace_check_lifecycle', 'reproduce_tree_import_lifecycle.py'), 'checks': LEGACY.LEGACY}
    with LEGACY.PROJECTOR.selected_oracles(roots, 'projected'):
        print(json.dumps(check_samples(document, raw, corpus), sort_keys=True, separators=(',', ':')))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError, OverflowError, RecursionError):
        print('Temporary workspace evidence refused; production acceptance remains disabled.', file=sys.stderr)
        sys.exit(1)
