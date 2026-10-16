#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Report the recorded hash-bound comparison for an explicitly labelled SPV source."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("hash_bound_recorded_byte_checker", HERE / "check_hash_bound_versions.py")
CHECK = importlib.util.module_from_spec(spec)
spec.loader.exec_module(CHECK)


def report(path, source_revision=None):
    if source_revision is not None:
        CHECK.require(type(source_revision) is str and len(source_revision) == 40 and
                      all(c in "0123456789abcdef" for c in source_revision), "invalid SPV source label")
    raw, document = CHECK.read_corpus(path)
    result = CHECK.check_corpus(document)
    result.update(
        corpus_sha256=hashlib.sha256(raw).hexdigest(),
        reference_execution_in_checker=False,
        authenticated_retained_version_provenance_qualified=False,
        accepted_VerifiedState_binding_qualified=False,
    )
    if source_revision is not None:
        result["source_revision"] = source_revision
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, default=HERE / "testdata/candidate-hash-bound-versions.json")
    parser.add_argument("--source-revision")
    args = parser.parse_args(argv)
    try:
        result = report(args.corpus, args.source_revision)
    except (ValueError, OSError, TypeError, KeyError, IndexError):
        print("Hash-bound retained-version fixture refused; production acceptance remains disabled.", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())

