#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Check the source-pinned recorded raw-store corpus, without a reference process."""
import argparse
import importlib.util
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("recorded_raw_kv_shared_corpus", HERE / "raw_kv_roundtrip_successor_corpus.py")
K = importlib.util.module_from_spec(spec)
spec.loader.exec_module(K)
C = K.C
CORPUS = "successor-raw-kv-roundtrip-corpus.json"
CORPUS_SHA256 = "dc176eaf518f13d9d90f467f98319bbda8269096e0e44b4ca3db49188db62814"
CORPUS_BYTES = 1833034
EXECUTION = "successor-raw-kv-roundtrip-execution.json"
EXECUTION_SHA256 = "c21fa1ac628fcaaaa0ab9066b0c2c086e70ae5cd684cbeb3cb015075ffd617f1"
EXECUTION_BYTES = 5906
TOOLS = {
    "raw_kv_roundtrip_successor_probe_test.go", "prepare_raw_kv_roundtrip_successor.py",
    "check_raw_kv_roundtrip_successor.py", "raw_kv_roundtrip_successor_model.py",
    "raw_kv_roundtrip_codec.py", "raw_kv_roundtrip_successor_corpus.py",
}


def check_files(raw, manifest_raw):
    K.require(type(raw) is bytes and len(raw) == CORPUS_BYTES and C.P.sha(raw) == CORPUS_SHA256)
    K.require(type(manifest_raw) is bytes and len(manifest_raw) == EXECUTION_BYTES
              and C.P.sha(manifest_raw) == EXECUTION_SHA256)
    manifest = C.document(manifest_raw, 128 << 10)
    expected = C.M.derive()
    C.P.exact(manifest["source"], expected["source"])
    C.P.exact(manifest["source_inputs"], C.M.source_inputs())
    K.require(set(manifest["selected_tool_sources"]) == TOOLS)
    for name, pin in manifest["selected_tool_sources"].items():
        source = C.P.read_regular(HERE / name, 1 << 20)
        K.require(len(source) == pin["bytes"] and C.P.sha(source) == pin["sha256"])
    C.P.exact(manifest["corpus"], {"file": CORPUS, "sha256": CORPUS_SHA256, "bytes": CORPUS_BYTES})
    corpus = C.document(raw, K.MAX_BYTES)
    for row in corpus["observations"]:
        C.P.exact(row["original_transport"], manifest["original_transports"][row["policy"]])
    result = K.check(raw, expected)
    K.require(sum(row["canonical_proof_positions"] for row in result["policies"]) == 3015)
    K.require(sum(len(row["stages"]) * 130 for row in result["policies"]) == 1300)
    for row in result["policies"]:
        C.P.exact([row["source"]["GOOS"], row["source"]["GOARCH"], row["source"]["Go_version"]],
                  ["darwin", "arm64", "go1.25.14"])
    result.update(
        kind="recorded-successor-raw-kv-roundtrip-corpus-check",
        execution_manifest_sha256=EXECUTION_SHA256,
        original_transport_digest_metadata_bound_to_selected_manifest=True,
        original_transport_bytes_reconstructed_or_rehashed=False,
        recorded_reference_platform="darwin/arm64",
        recorded_ordinary_builds=1, recorded_successful_component_processes=2,
        recorded_early_input_refusals=2, recorded_capture_failure_independently_recovered=True,
        reference_processes_executed_by_this_check=0,
        accepted_header_binding=False, authenticated_snapshot_import=False,
        production_resources_qualified=False, runtime_state_value_acceptance=False,
    )
    return result


def check():
    return check_files(C.P.read_regular(HERE / "testdata" / CORPUS, K.MAX_BYTES),
                       C.P.read_regular(HERE / "testdata" / EXECUTION, 128 << 10))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-revision")
    args = parser.parse_args(argv)
    if args.source_revision is not None:
        K.require(type(args.source_revision) is str and len(args.source_revision) == 40
                  and all(char in "0123456789abcdef" for char in args.source_revision))
    result = check()
    if args.source_revision is not None:
        result["source_revision"] = args.source_revision
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, IndexError, AssertionError):
        print("Recorded raw KV corpus check refused; preserve selected files.", file=sys.stderr)
        sys.exit(1)
