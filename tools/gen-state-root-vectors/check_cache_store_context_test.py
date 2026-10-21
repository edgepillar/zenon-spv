#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Check complete retained observations, source bindings and refusal order."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("cache_context_recorded_controls", HERE / "check_cache_store_context.py")
C = importlib.util.module_from_spec(spec)
spec.loader.exec_module(C)

class CacheContextObservationControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.document = C.decode(C.read(HERE / "testdata" / C.CORPUS, 128 << 10))
        cls.fixture = C.decode(C.PREP.selected_fixture())
        cls.decoded = {variant: [[C.decode(line) for line in stream["jsonl"].encode().splitlines()]
                                for stream in cls.document["variants"][variant]["streams"]]
                       for variant in C.PREP.VARIANTS}

    def test_both_complete_observations_and_corpus(self):
        result = C.check_corpus(copy.deepcopy(self.document))
        self.assertEqual((result["event_count"], result["query_count"]), (34, 16))
        self.assertEqual((result["baseline_context_mismatches"], result["candidate_context_mismatches"]), (4, 0))
        self.assertEqual((result["recorded_unit_root_count"], result["recorded_unit_pass_results"]), (23, 29))

    def test_21_semantic_mutations_are_refused(self):
        mutations = [
          ("omitted-query", lambda a,b:a.pop(3)),
          ("duplicate-query", lambda a,b:a.insert(3,copy.deepcopy(a[3]))),
          ("reordered-query", lambda a,b:a.__setitem__(slice(3,5),list(reversed(a[3:5])))),
          ("different-requested-hash", lambda a,b:a[4]["requested_identifier"].update(hash="0"*64)),
          ("different-reported-hash", lambda a,b:a[4]["reported_identifier"].update(hash="0"*64)),
          ("claimed-refusal-after-return", lambda a,b:a[4].update(contract_mismatch=False)),
          ("claimed-expected-foreign-availability", lambda a,b:a[4].update(expected_available=True)),
          ("boolean-as-height", lambda a,b:a[3]["requested_identifier"].update(height=True)),
          ("false-state-root-acceptance", lambda a,b:a[4].update(state_root_error="none")),
          ("wrong-origin-root", lambda a,b:a[3].update(state_root="0"*64)),
          ("cache-as-proof", lambda a,b:a[4].update(cache_values_used_as_state_proof=True)),
          ("numeric-plasma", lambda a,b:a[3].update(chain_plasma=0)),
          ("nonascii-decimal", lambda a,b:a[3].update(chain_plasma="\u0660")),
          ("changed-alias-value", lambda a,b:a[4].update(chain_plasma="1")),
          ("genesis-source-change", lambda a,b:a[1].update(patch_sha256="0"*64)),
          ("claimed-network-start", lambda a,b:a[0].update(network_or_full_node_started=True)),
          ("changed-closed-image", lambda a,b:b[-1]["images"]["cache"].update(sha256="1"*64)),
          ("boolean-image-size", lambda a,b:a[-1]["images"]["ledger"].update(records=True)),
          ("unknown-stage", lambda a,b:a[3].update(stage="arbitrary")),
          ("wrong-case", lambda a,b:a[3].update(case="another")),
          ("baseline-as-candidate", lambda a,b:None)]
        self.assertEqual(len(mutations), 21)
        for name, mutation in mutations:
            first, reopened = copy.deepcopy(self.decoded["baseline"])
            mutation(first, reopened)
            variant = "candidate" if name == "baseline-as-candidate" else "baseline"
            with self.subTest(name=name), self.assertRaises((ValueError, KeyError, TypeError)):
                C.check(first, reopened, self.fixture, C.PREP.R.FIXTURE_SHA256, variant)

    def test_duplicate_json_keys_are_refused(self):
        with self.assertRaises(ValueError):
            C.decode('{"key":1,"key":2}')

    def test_nonfinite_json_is_refused(self):
        for value in ("NaN", "Infinity", "-Infinity"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                C.decode('{"key":' + value + '}')

    def test_corpus_metadata_cannot_relabel_the_recording(self):
        mutations = [
          lambda d:d.update(format_version=True),
          lambda d:d["source"].update(candidate_runtime_tree="0"*40),
          lambda d:d["source"].update(candidate_source_files=470),
          lambda d:d["source"]["probe"].update(sha256="0"*64),
          lambda d:d["recorded_native"].update(native_unit_pass_results=True),
          lambda d:d["recorded_native"].update(native_unit_root_count=29),
          lambda d:d["recorded_native"]["native_unit_pass_names"].pop(),
          lambda d:d["recorded_native"].update(platform="linux/amd64"),
          lambda d:d["scope"].update(runtime_state_value_acceptance=True),
          lambda d:d["scope"].update(full_node_or_network_validity_qualified=True),
          lambda d:d["variants"]["candidate"]["binary"].update(sha256="0"*64)]
        for mutation in mutations:
            document = copy.deepcopy(self.document)
            mutation(document)
            with self.subTest(mutation=repr(mutation)), self.assertRaises(ValueError):
                C.check_corpus(document)

    def test_all_four_exact_stream_payloads_are_required(self):
        for variant in C.PREP.VARIANTS:
            for position in range(2):
                for field, value in (("bytes", True), ("sha256", "0"*64), ("jsonl", "{}\n")):
                    document = copy.deepcopy(self.document)
                    document["variants"][variant]["streams"][position][field] = value
                    with self.subTest(variant=variant, position=position, field=field), self.assertRaises(ValueError):
                        C.check_corpus(document)
        document = copy.deepcopy(self.document)
        document["variants"]["candidate"]["streams"].reverse()
        with self.assertRaises(ValueError):
            C.check_corpus(document)

    def test_candidate_cannot_reuse_baseline_results(self):
        document = copy.deepcopy(self.document)
        document["variants"]["candidate"]["streams"] = copy.deepcopy(document["variants"]["baseline"]["streams"])
        with self.assertRaises(ValueError):
            C.check_corpus(document)

    def test_closed_images_and_semantics_survive_fresh_process(self):
        first, reopened = self.decoded["candidate"]
        C.exact(first[-1]["images"], reopened[1]["images"])
        C.exact(first[-1]["images"], reopened[-1]["images"])
        result = C.check(first, reopened, self.fixture, C.PREP.R.FIXTURE_SHA256, "candidate")
        self.assertTrue(result["closed_logical_store_images_unchanged"])
        self.assertFalse(result["cache_value_correctness_qualified"])

    def test_reader_caps_regular_inputs_without_large_allocations(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "input.json"
            path.write_bytes(b"{}")
            self.assertEqual(C.read(path, 2), b"{}")
            with self.assertRaises(ValueError):
                C.read(path, 1)
            with self.assertRaises(ValueError):
                C.read(Path(root), 100)

    def test_actual_cli_reports_the_current_reader_separately(self):
        result = subprocess.run([sys.executable, "-I", "-B", str(HERE / "check_cache_store_context.py"),
            "--source-revision", "1"*40], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        report = json.loads(result.stdout)
        self.assertEqual(report["source_revision"], "1"*40)
        self.assertEqual(report["consumer_result"], "REFUSED")
        self.assertIs(report["backend_reexecuted"], False)
        self.assertEqual(set(report["reader_inputs_sha256"]), {"prepare_cache_store_context.py", "check_cache_store_context.py"})

if __name__ == "__main__":
    unittest.main(verbosity=2)
