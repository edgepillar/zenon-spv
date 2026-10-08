#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Check output encoding comparisons without executing either encoder.

Historical encoder/shared helper pins and complete independent plan bytes are
bound separately from variable observations, production budgets and trust.
"""
import ast
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('selected_encoding_resource_oracle', HERE / 'check_patch_plan_resources.py')
CHECK = importlib.util.module_from_spec(spec)
spec.loader.exec_module(CHECK)
REFERENCE = {'encode_function_sha256': '58b4250bd41b1a36e003f87147ae8b9a1ddc489c4624e8e38aff6738548a8757', 'plan_sha256': '80f4437a71ab056bf62a17c3df997ec550305e35a8578ffb2a16580b2c615499', 'revision': 'f4bf2d2953825fa96f9e52be2d41f003fed4ab65', 'shared_functions_sha256': {'make_plan': 'aa2f866a786671d8c42b5f919e8b551f8ac56fe3402cadb68bfc0bafc4a41b0e', 'parse_events': '7e754d7142fb03f538c5c11151366ea7e7a9f896ffbbdb507de0bdd4ff3975f6', 'read_raw': '94d21179e3cac6b2917ea234caddb85e3c52e0f3958e0387e8819e58e21585ac', 'validate': '853cb4375d2590b617e7acd8e2e74542970ded46767c364e004b921c4a59674b'}}
FILES = ('plan_patch.py', 'measure_patch_plan.py', 'check_patch_plan_resources.py',
         'testdata/patch-plan-resource-inputs.json', 'measure_patch_plan_encodings.py', 'check_patch_plan_encodings.py')
MODES = ('reference', 'candidate')
SCOPE = CHECK.SCOPE | {'reference_Python_encode_function_executed': True,
    'candidate_bounded_binary_encoder_executed': True,
    'shared_reader_and_parser_preserved': True, 'production_default_encoder_measured': True,
    'latency_speedup_qualified': False}



def selected_function_hashes(path):
    with path.open('rb') as stream:
        raw = stream.read((64 << 10) + 1)
    CHECK.require(len(raw) <= 64 << 10)
    text = raw.decode('utf-8')
    return {node.name: hashlib.sha256(ast.get_source_segment(text, node).encode('utf-8')).hexdigest()
            for node in ast.parse(text).body if isinstance(node, ast.FunctionDef)}


def reference_pins():
    # Read source bytes only; never import or execute either planner/producer.
    historical = selected_function_hashes(HERE / 'measure_patch_plan_encodings.py')
    CHECK.exact(historical['encode_plan'], REFERENCE['encode_function_sha256'])
    current = selected_function_hashes(HERE / 'plan_patch.py')
    shared = REFERENCE['shared_functions_sha256']
    CHECK.exact({name: current[name] for name in shared}, shared)
    return REFERENCE


def validate_report(document, selected_revision=None):
    CHECK.revision(selected_revision)
    required = {'format_version', 'kind', 'source_revision', 'source_files_sha256', 'reference_source',
                'runtime', 'repetitions', 'limits', 'scope', 'measurement_result', 'consumer_result', 'cases'}
    CHECK.require(type(document) is dict and set(document) == required)
    CHECK.exact({key: document[key] for key in ('format_version', 'kind', 'source_revision', 'reference_source',
                                             'limits', 'scope', 'measurement_result', 'consumer_result')},
        {'format_version': 1, 'kind': 'read-only-patch-plan-output-encoding-comparison',
         'source_revision': selected_revision, 'reference_source': reference_pins(), 'limits': CHECK.LIMITS,
         'scope': SCOPE, 'measurement_result': 'OBSERVED', 'consumer_result': 'REFUSED'})
    CHECK.exact(document['source_files_sha256'], {name: hashlib.sha256((HERE / name).read_bytes()).hexdigest() for name in FILES})
    repetitions = document['repetitions']
    CHECK.require(type(repetitions) is int and 1 <= repetitions <= 3)
    CHECK.require(type(document['cases']) is list and len(document['cases']) == 6)
    expected_order = [(n, traced, mode) for n in range(1, repetitions + 1) for traced in (False, True) for mode in MODES]
    for case in document['cases']:
        CHECK.require(type(case) is dict and type(case.get('samples')) is list and len(case['samples']) == repetitions * 4)
        for sample, (number, traced, mode) in zip(case['samples'], expected_order):
            CHECK.require(type(sample) is dict)
            CHECK.exact({k: sample[k] for k in ('repetition', 'traced', 'encoder_mode')},
                        {'repetition': number, 'traced': traced, 'encoder_mode': mode})
    for mode in MODES:
        # Project each mode into the existing independent byte/resource schema.
        # It binds the literal six inputs, entire JSON spelling, positive units,
        # unavailable nulls and exact plain/traced sample order for both encoders.
        projected = {key: document[key] for key in ('format_version', 'source_revision', 'runtime', 'repetitions',
                                                  'limits', 'measurement_result', 'consumer_result')}
        projected.update(kind='read-only-patch-plan-resource-observations', scope=CHECK.SCOPE,
            source_files_sha256={name: document['source_files_sha256'][name] for name in FILES[:4]},
            cases=[{**{key: value for key, value in case.items() if key != 'samples'},
                    'samples': [{key: value for key, value in sample.items() if key != 'encoder_mode'}
                                for sample in case['samples'] if sample['encoder_mode'] == mode]}
                   for case in document['cases']])
        CHECK.validate_report(projected, selected_revision)
    peaks = {}
    for case in document['cases']:
        observed = {mode: [sample['python_traced_peak_bytes'] for sample in case['samples']
                          if sample['encoder_mode'] == mode and sample['traced']] for mode in MODES}
        peaks[case['name']] = {'reference_peak_min_bytes': min(observed['reference']),
            'reference_peak_max_bytes': max(observed['reference']), 'candidate_peak_min_bytes': min(observed['candidate']),
            'candidate_peak_max_bytes': max(observed['candidate']),
            'candidate_peaks_below_all_reference_peaks': max(observed['candidate']) < min(observed['reference'])}
    return {'profiles': 6, 'fresh_worker_samples': 24 * repetitions, 'all_complete_plan_bytes_bound': True,
        'historical_encoder_source_pinned': True, 'shared_reader_and_parser_pinned': True,
        'production_default_encoder_measured': True, 'python_peak_observations': peaks,
        'large_profile_python_peaks_reduced': all(peaks[name]['candidate_peaks_below_all_reference_peaks']
                                                      for name in ('records-256', 'records-1024', 'maximum-raw-values', 'maximum-keys')),
        'latency_speedup_qualified': False, 'whole_pipeline_memory_measured': False,
        'production_budget_qualified': False, 'NodeTree_or_retention_measured': False, 'consumer_result': 'REFUSED'}


def main():
    parser = CHECK.PrivateParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--report', required=True, type=Path)
    parser.add_argument('--source-revision')
    args = parser.parse_args()
    with args.report.open('rb') as stream:
        raw = stream.read((64 << 10) + 1)
    CHECK.require(len(raw) <= 64 << 10)
    document = json.loads(raw, object_pairs_hook=CHECK.ORACLE.BYTE.object_pairs)
    report = validate_report(document, args.source_revision)
    report['report_sha256'] = hashlib.sha256(raw).hexdigest()
    print(json.dumps(report, sort_keys=True, separators=(',', ':')))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, TypeError, KeyError, OSError, StopIteration, SyntaxError):
        print('Patch encoding comparison refused; production acceptance remains disabled.', file=sys.stderr)
        sys.exit(1)
