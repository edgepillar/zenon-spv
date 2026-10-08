#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Compare pinned bytearray encoding and current bounded binary encoding.

The historical function below is byte-identical to the selected source function.
Both modes share byte-pinned reading/parsing and independent output checks;
only synthetic Python planning runs, never a node, storage importer or proof.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import types

HERE = Path(__file__).resolve().parent


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


METER = module('selected_encoding_shared_meter', 'measure_patch_plan.py')
COMPARE = module('selected_encoding_independent_comparison', 'check_patch_plan_encodings.py')
CANDIDATE = METER.PLAN
# The historical function's original names resolve to the unchanged helpers.
validate, require = CANDIDATE.validate, CANDIDATE.require
CEILINGS = CANDIDATE.CEILINGS


def encode_plan(document, maximum):
    require(type(maximum) is int and 0 < maximum <= CEILINGS['plan_bytes'])
    result = bytearray()
    encoder = json.JSONEncoder(sort_keys=True, separators=(',', ':'), ensure_ascii=True)
    for chunk in encoder.iterencode(document):
        part = chunk.encode('ascii')
        require(len(part) <= maximum - len(result))
        result.extend(part)
    require(len(result) < maximum)
    result.extend(b'\n')
    return bytes(result)


def worker(profile, path, number, traced, revision, mode):
    COMPARE.reference_pins()
    # Each child handles one mode only. Shared instrumentation and independent
    # output checks remain unchanged; only output encoding differs.
    METER.PLAN = types.SimpleNamespace(validate=CANDIDATE.validate,
        read_raw=CANDIDATE.read_raw, make_plan=CANDIDATE.make_plan,
        encode_plan=encode_plan if mode == 'reference' else CANDIDATE.encode_plan)
    return METER.worker(profile, path, number, traced, revision) | {'encoder_mode': mode}


def main(argv=None):
    parser = CANDIDATE.PrivateParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--source-revision')
    parser.add_argument('--repetitions', default=3, type=CANDIDATE.number)
    parser.add_argument('--worker', choices=[name for name, family, count in COMPARE.CHECK.FAMILIES])
    parser.add_argument('--raw', type=Path)
    parser.add_argument('--sample', type=CANDIDATE.number)
    parser.add_argument('--traced', choices=('0', '1'))
    parser.add_argument('--encoder-mode', choices=COMPARE.MODES)
    args = parser.parse_args(argv)
    COMPARE.CHECK.revision(args.source_revision)
    COMPARE.CHECK.require(1 <= args.repetitions <= 3)
    COMPARE.reference_pins()
    if args.worker:
        with (HERE / 'testdata/patch-plan-resource-inputs.json').open('rb') as stream:
            raw_manifest = stream.read((16 << 10) + 1)
        COMPARE.CHECK.require(len(raw_manifest) <= 16 << 10)
        manifest = json.loads(raw_manifest, object_pairs_hook=COMPARE.CHECK.ORACLE.BYTE.object_pairs)
        COMPARE.CHECK.require(type(manifest) is dict and set(manifest) == {'format_version', 'kind', 'cases'})
        COMPARE.CHECK.exact(manifest['format_version'], 1)
        COMPARE.CHECK.exact(manifest['kind'], 'patch-plan-resource-input-selection')
        COMPARE.CHECK.require(type(manifest['cases']) is list and len(manifest['cases']) == 6)
        COMPARE.CHECK.require(args.raw is not None and args.sample in (1, 2, 3) and args.traced in ('0', '1')
                              and args.encoder_mode in COMPARE.MODES)
        profile = next(row for row in manifest['cases'] if row['name'] == args.worker)
        result = worker(profile, args.raw, args.sample, args.traced == '1', args.source_revision, args.encoder_mode)
    else:
        COMPARE.CHECK.require(args.raw is None and args.sample is None and args.traced is None and args.encoder_mode is None)
        rows = COMPARE.CHECK.profiles()
        cases = []
        os.umask(0o077)
        with tempfile.TemporaryDirectory(prefix='patch-encoding-comparison-') as directory:
            for profile in rows:
                raw = METER.fixture(profile)
                COMPARE.CHECK.require(len(raw) == profile['raw_bytes'] and hashlib.sha256(raw).hexdigest() == profile['input_sha256'])
                events, refusal = COMPARE.CHECK.ORACLE.preflight(raw, COMPARE.CHECK.LIMITS)
                COMPARE.CHECK.require(not refusal)
                COMPARE.CHECK.exact(events, COMPARE.CHECK.events(profile['name']))
                path = Path(directory) / (profile['name'] + '.dump')
                path.write_bytes(raw)
                case = profile | COMPARE.CHECK.output_selection(profile, args.source_revision) | {'samples': []}
                for repetition in range(1, args.repetitions + 1):
                    for traced in (False, True):
                        for mode in COMPARE.MODES:
                            command = [sys.executable, '-I', '-B', str(HERE / 'measure_patch_plan_encodings.py'),
                                '--worker', profile['name'], '--raw', str(path), '--sample', str(repetition),
                                '--traced', str(int(traced)), '--encoder-mode', mode]
                            if args.source_revision is not None:
                                command.extend(['--source-revision', args.source_revision])
                            run = subprocess.run(command, capture_output=True, timeout=45)
                            COMPARE.CHECK.require(run.returncode == 0 and not run.stderr and len(run.stdout) <= 8192)
                            case['samples'].append(json.loads(run.stdout, object_pairs_hook=COMPARE.CHECK.ORACLE.BYTE.object_pairs))
                cases.append(case)
        result = {'format_version': 1, 'kind': 'read-only-patch-plan-output-encoding-comparison',
            'source_revision': args.source_revision, 'reference_source': COMPARE.REFERENCE,
            'source_files_sha256': {name: hashlib.sha256((HERE / name).read_bytes()).hexdigest() for name in COMPARE.FILES},
            'runtime': METER.runtime(), 'repetitions': args.repetitions, 'limits': COMPARE.CHECK.LIMITS,
            'scope': COMPARE.SCOPE, 'measurement_result': 'OBSERVED', 'consumer_result': 'REFUSED', 'cases': cases}
        COMPARE.validate_report(result, args.source_revision)
    output = (json.dumps(result, sort_keys=True, separators=(',', ':')) + '\n').encode('ascii')
    COMPARE.CHECK.require(len(output) <= 64 << 10)
    sys.stdout.buffer.write(output)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, TypeError, KeyError, OSError, StopIteration, SyntaxError, subprocess.TimeoutExpired):
        print('Patch encoding comparison refused; no complete report emitted. Production acceptance remains disabled.', file=sys.stderr)
        sys.exit(1)
