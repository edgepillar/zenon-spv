#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Run the unchanged retention controls and recorded comparison in one process.

Only the original exact-byte, single-entry cache is reused. Historical source,
corpus and evidence identities stay fixed. This is recorded-data qualification,
not node execution or consumer/state-value acceptance.
"""

import argparse
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import stat
import sys
import unittest


HERE = Path(__file__).resolve().parent
TEST_COUNT = 27
PINS = {
    "check_default_retention_corpus.py": (
        64 << 10, "c658a5ddb5b0f7aeec0a13be05fb433d5fd04b77469ef16feb0c33f4f66c2c40"),
    "check_default_retention_corpus_test.py": (
        64 << 10, "0d1eee52babe7e4156703559f2317e84356cdfa83048cf1b431514b8c56ec2e5"),
    "testdata/candidate-default-retention.json": (
        8 << 20, "e18cf0c0ba4669233cf42d67381da50c0ae15c1229a1f3a18f52e0c8d53f59b3"),
}
REFUSAL = "Recorded retention joint qualification refused; preserve original evidence."
FALSE_FIELDS = (
    "native_reference_node_or_CGO_execution", "new_resource_measurements",
    "network_executed", "full_node_qualified", "production_resources_qualified",
    "profile_agreed", "accepted_header_root_binding",
)


def require(value):
    if not value:
        raise ValueError(REFUSAL)


def pinned_sources():
    result = {}
    for relative, (limit, digest) in PINS.items():
        path = HERE / relative
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= limit)
            raw = stream.read(limit + 1)
            after = os.fstat(stream.fileno())
        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns))
        require(len(raw) == before.st_size and hashlib.sha256(raw).hexdigest() == digest)
        result[relative] = raw
    return result


def load_controls():
    raw = pinned_sources()["check_default_retention_corpus_test.py"]
    path = HERE / "check_default_retention_corpus_test.py"
    spec = importlib.util.spec_from_file_location("retention_joint_original_controls", path)
    module = importlib.util.module_from_spec(spec)
    exec(compile(raw, str(path), "exec"), module.__dict__)
    return module


def cache_info(cache):
    value = cache.cache_info()
    require(all(type(getattr(value, field)) is int and getattr(value, field) >= 0
                for field in ("hits", "misses", "maxsize", "currsize")))
    require(value.maxsize == 1 and value.currsize <= 1)
    return value


def execute(module, revision=None, runner=None):
    reader = module.C
    cache = reader.expected_from_presealed_witnesses
    initial = cache_info(cache)
    require((initial.hits, initial.misses, initial.currsize) == (0, 0, 0))
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(module)
    require(not loader.errors and suite.countTestCases() == TEST_COUNT)
    runner = runner or unittest.TextTestRunner(verbosity=2)
    test_output = io.StringIO()
    with contextlib.redirect_stdout(test_output):
        result = runner.run(suite)
    require(type(result.testsRun) is int and result.testsRun == TEST_COUNT)
    require(result.wasSuccessful() is True and result.shouldStop is False)
    for field in ("failures", "errors", "skipped", "expectedFailures", "unexpectedSuccesses"):
        require(type(getattr(result, field)) is list and not getattr(result, field))
    require(test_output.getvalue() == "" and reader.expected_from_presealed_witnesses is cache)

    # Reread the pinned corpus and seal the entire cached graph after all tests.
    raw, document = reader.read_corpus(HERE / "testdata/candidate-default-retention.json")
    require(hashlib.sha256(raw).hexdigest() == PINS["testdata/candidate-default-retention.json"][1])
    base = reader.M.encoded(document["presealed_expectations_without_history"])
    require(hashlib.sha256(base).hexdigest() == reader.BASE_SHA256)
    warm = cache_info(cache)
    require(warm.currsize == 1)
    expected = cache(base)
    admitted = cache_info(cache)
    require(admitted.misses == warm.misses and admitted.hits == warm.hits + 1)
    require(hashlib.sha256(reader.M.encoded(expected)).hexdigest() == reader.EXPECTED_SHA256)

    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        returned = reader.main([] if revision is None else ["--source-revision", revision])
    require(returned is None and reader.expected_from_presealed_witnesses is cache)
    final = cache_info(cache)
    require(final.currsize == 1 and final.misses == admitted.misses and final.hits == admitted.hits + 1)
    require(hashlib.sha256(reader.M.encoded(expected)).hexdigest() == reader.EXPECTED_SHA256)
    text = output.getvalue()
    require(0 < len(text.encode()) <= 64 << 10)
    report = json.loads(text)
    require(type(report) is dict and report.get("kind") ==
            "recorded-source-default-retention-background-check")
    require(report.get("consumer_result") == "REFUSED" and
            report.get("corpus_sha256") == PINS["testdata/candidate-default-retention.json"][1])
    require(all(report.get(field) is False for field in FALSE_FIELDS))
    if revision is None:
        require("source_revision" not in report)
    else:
        require(report.get("source_revision") == revision)
    return text, {
        "format": "recorded-retention-joint-controls/v1", "original_tests_run": TEST_COUNT,
        "failures": 0, "errors": 0, "skipped": 0, "fresh_single_entry_cache_required": True,
        "cached_graph_sha256": reader.EXPECTED_SHA256,
        "comparison_cache_hits": final.hits - admitted.hits,
        "comparison_cache_misses": final.misses - admitted.misses,
        "comparison_added_history_derivation": False,
        "recorded_history_heights": 32768, "consumer_result": "REFUSED",
        "node_or_network_execution": False, "source_revision": revision,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-revision")
    args = parser.parse_args(argv)
    if args.source_revision is not None and re.fullmatch("[0-9a-f]{40}", args.source_revision) is None:
        parser.error("source revision must be a lowercase 40-character Git identity")
    try:
        module = load_controls()
        text, receipt = execute(module, args.source_revision)
        pinned_sources()  # Detect source/corpus replacement during the controls.
        print("recorded-retention-joint " + json.dumps(receipt, sort_keys=True), file=sys.stderr)
        print(text, end="")
    except (OSError, ValueError, TypeError, KeyError, IndexError, AssertionError, RecursionError):
        print(REFUSAL, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
