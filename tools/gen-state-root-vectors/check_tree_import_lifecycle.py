#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Bind complete reference-child wall/RSS observations to unchanged tree bytes.

All old import, map-delta, DAG/refcount and proof checks remain required. These
unsigned records cannot authenticate execution, target hardware, a snapshot,
accepted headers, complete/excluded state or a production consumer budget.
The checker never executes the reference node or measurement children.
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


SCALE = load('lifecycle_complete_import_oracle', 'check_tree_import_scale.py')
CAPTURE = load('lifecycle_capture_contract', 'capture_child_lifecycle.py')
BYTE, RET = SCALE.BYTE, SCALE.RET
INPUT_NAMES = SCALE.INPUT_NAMES + ('capture_child_lifecycle.py',
    'capture_child_lifecycle_test.py', 'check_tree_import_lifecycle.py',
    'check_tree_import_lifecycle_test.py', 'reproduce_tree_import_lifecycle.py')
SCOPE = {'unchanged_Go_child_and_literal_workload': True,
    'same_selected_512_4096_keys_16_versions_8_retained': True,
    'whole_selected_reference_child_wall_observed': True,
    'per_child_RSS_through_exit_observed': True,
    'child_fixture_conformance_final_output_and_cleanup_included': True,
    'spawn_and_wait_polling_overhead_included': True,
    'copied_source_build_regular_file_footprint_observed': True,
    'captured_output_regular_file_footprint_observed': True,
    'parent_parsing_hashing_or_memory_measured': False,
    'source_build_time_or_compiler_memory_measured': False,
    'input_temp_workspace_peak_measured': False,
    'peak_disk_measured': False, 'minimum_consumer_memory_qualified': False,
    'whole_pipeline_memory_measured': False,
    'existing_named_phase_allocation_live_heap_RSS_and_closed_tree_metrics_separate': True,
    'within_batch_retries': 0, 'filtered_samples': 0,
    'execution_provenance_authenticated': False,
    'target_hardware_identity_authenticated': False,
    'real_chain_archive_or_snapshot_executed': False,
    'accepted_header_profile_activation_or_state_value_qualified': False,
    'production_resource_budgets_qualified': False,
    'consumer_result': 'REFUSED', 'production_acceptance_enabled': False}


def require(condition):
    if not condition:
        raise ValueError('Tree import lifecycle evidence differs from the selected finite contract')


encoded, binding = SCALE.encoded, SCALE.binding


def input_pins():
    return {name: hashlib.sha256((HERE / name).read_bytes()).hexdigest() for name in INPUT_NAMES}


def workspace_contract(row):
    require(type(row) is dict and set(row) == {'method', 'regular_files', 'file_bytes',
                                             'largest_file_bytes', 'allocated_file_bytes'})
    RET.exact(row['method'], CAPTURE.WORKSPACE_METHOD)
    for key in ('regular_files', 'file_bytes', 'largest_file_bytes', 'allocated_file_bytes'):
        RET.integer(row[key], 1)
    require(row['regular_files'] == 394 + len(SCALE.BUILD_NAMES) + 1)
    require(row['largest_file_bytes'] <= row['file_bytes'] <= row['regular_files'] * row['largest_file_bytes'])
    require(row['allocated_file_bytes'] % 512 == 0)


def lifecycle_contract(row, command, measurement, platform):
    fields = {'label', 'completed', 'process_reaped', 'actual_exit', 'wait_status', 'refusal',
        'elapsed_ns', 'wall_method', 'poll_ns', 'timeout_ns', 'rss_method',
        'native_rss_unit', 'native_peak_rss', 'process_peak_rss_bytes', 'capture_platform',
        'output_method', 'stdout_bytes', 'stderr_bytes', 'stdout_ceiling_bytes',
        'stderr_ceiling_bytes', 'captured_regular_files', 'captured_allocated_file_bytes',
        'stdout_sha256', 'stderr_sha256', 'parent_memory_measured', 'source_build_cost_measured',
        'input_temp_workspace_peak_measured', 'peak_disk_measured', 'workspace_before', 'workspace_after'}
    require(type(row) is dict and set(row) == fields)
    unit, factor = CAPTURE.native_rss_unit(platform)
    fixed = {'label': command['label'], 'completed': True, 'process_reaped': True,
        'actual_exit': 0, 'wait_status': 0, 'refusal': '', 'wall_method': CAPTURE.WALL_METHOD,
        'poll_ns': CAPTURE.POLL_NS, 'timeout_ns': CAPTURE.TIMEOUT_NS,
        'rss_method': CAPTURE.RSS_METHOD, 'native_rss_unit': unit, 'capture_platform': platform,
        'output_method': CAPTURE.OUTPUT_METHOD, 'stderr_bytes': 0,
        'stdout_ceiling_bytes': CAPTURE.OUTPUT_CEILING, 'stderr_ceiling_bytes': CAPTURE.OUTPUT_CEILING,
        'captured_regular_files': 2, 'stdout_sha256': command['stdout_sha256'],
        'stderr_sha256': command['stderr_sha256'], 'parent_memory_measured': False,
        'source_build_cost_measured': False, 'input_temp_workspace_peak_measured': False,
        'peak_disk_measured': False}
    for key, value in fixed.items():
        RET.exact(row[key], value)
    for key in ('elapsed_ns', 'native_peak_rss', 'process_peak_rss_bytes', 'stdout_bytes',
                'captured_allocated_file_bytes'):
        RET.integer(row[key], 1)
    require(row['elapsed_ns'] <= CAPTURE.TIMEOUT_NS + CAPTURE.POLL_NS * 1000)
    require(row['stdout_bytes'] <= CAPTURE.OUTPUT_CEILING)
    require(row['captured_allocated_file_bytes'] % 512 == 0)
    require(row['process_peak_rss_bytes'] == row['native_peak_rss'] * factor)
    require(row['process_peak_rss_bytes'] >= measurement['process_peak_rss_bytes'])
    # The old named timers are sequential. Query timers can overlap those
    # observations, so require both lower bounds separately, without addition.
    require(row['elapsed_ns'] >= sum(x['elapsed_ns'] for x in measurement['phase_resources']))
    require(row['elapsed_ns'] >= sum(x['root_elapsed_ns'] + x['proof_elapsed_ns'] for x in measurement['query_timings']))
    workspace_contract(row['workspace_before'])
    workspace_contract(row['workspace_after'])
    for key in ('regular_files', 'file_bytes', 'largest_file_bytes'):
        RET.exact(row['workspace_after'][key], row['workspace_before'][key])


def check_samples(document, corpus_raw, corpus):
    require(type(document) is dict and set(document) == {'format_version', 'kind', 'source',
        'scope', 'corpus_sha256', 'research_source_inputs', 'phase_samples', 'lifecycle',
        'consumer_result', 'production_acceptance_enabled'})
    for key, value in (('format_version', 1), ('kind', 'candidate-tree-import-lifecycle-samples'),
        ('source', SCALE.SCALE.SOURCE), ('scope', SCOPE),
        ('corpus_sha256', hashlib.sha256(corpus_raw).hexdigest()),
        ('research_source_inputs', input_pins()), ('consumer_result', 'REFUSED'),
        ('production_acceptance_enabled', False)):
        RET.exact(document[key], value)
    summary = SCALE.check_samples(document['phase_samples'], corpus_raw, corpus)
    rows = document['lifecycle']
    require(type(rows) is list and len(rows) == 2)
    for generation in range(2):
        require(type(rows[generation]) is list and len(rows[generation]) == 12)
        for row, command, measurement in zip(rows[generation],
                document['phase_samples']['commands'][generation], document['phase_samples']['samples'][generation]):
            lifecycle_contract(row, command, measurement, document['phase_samples']['source_execution_platform'])
    require(len(encoded(document)) <= BYTE.MAX_FILE_BYTES)
    return summary | {'recorded_lifecycle_children': 24, 'child_wall_and_RSS_through_exit_bound': True,
        'old_phase_source_and_conformance_preserved': True, 'workspace_and_output_file_scopes_separate': True,
        'parent_or_compiler_memory_measured': False, 'minimum_consumer_memory_qualified': False,
        'whole_pipeline_memory_measured': False, 'peak_disk_measured': False,
        'production_acceptance_enabled': False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--corpus', type=Path, default=HERE / 'testdata/candidate-tree-import-scale.json')
    parser.add_argument('--samples', type=Path, default=HERE / 'testdata/candidate-tree-import-lifecycle-samples.json')
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
        print('Tree import lifecycle evidence refused; production acceptance remains disabled.', file=sys.stderr)
        sys.exit(1)
