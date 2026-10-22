#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Portable recorded-observation controls; no reference component executes."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest import mock

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("read_Stop_recorded_controls", HERE / "check_public_chain_proof_stop.py")
R = importlib.util.module_from_spec(spec)
spec.loader.exec_module(R)
DOCUMENT = json.loads((HERE / "testdata/native-public-chain-proof-stop.json").read_bytes())


class RecordedControls(unittest.TestCase):
    def document(self):
        return copy.deepcopy(DOCUMENT)

    def refused(self, document):
        with self.assertRaises((ValueError, KeyError, TypeError, IndexError, AssertionError)):
            R.check_corpus(document)

    def observation(self, document, index=0):
        return json.loads(document["cases"][index]["stdout_utf8"])

    def replace_observation(self, document, value, index=0):
        raw = (json.dumps(value, separators=(",", ":"), allow_nan=False) + "\n").encode()
        case = document["cases"][index]
        case["stdout_utf8"] = raw.decode()
        command = case["commands"]["case"]
        command["stdout_sha256"], command["stdout_bytes"] = hashlib.sha256(raw).hexdigest(), len(raw)

    def replace_buildinfo(self, document, value, index=0):
        raw = (json.dumps(value, sort_keys=True) + "\n").encode()
        case = document["cases"][index]
        case["buildinfo_stdout_utf8"] = raw.decode()
        command = case["commands"]["buildinfo"]
        command["stdout_sha256"], command["stdout_bytes"] = hashlib.sha256(raw).hexdigest(), len(raw)

    def test_two_recorded_profiles_keep_separate_outcomes_without_reference_execution(self):
        with mock.patch("subprocess.Popen", side_effect=AssertionError("no process launch")):
            result = R.check_corpus(self.document())
        self.assertEqual(result["recorded_corrected_producer_processes"], 2)
        self.assertEqual(result["total_recorded_reference_processes"], 4)
        self.assertEqual(result["individual_Root_and_GetProof_calls"], 8708)
        self.assertEqual(result["new_reference_backend_executions"], 0)
        self.assertEqual([row["profile"] for row in result["profile_results"]], ["ordinary", "race"])
        self.assertFalse(result["internal_database_interleaving_proven"])
        self.assertFalse(result["full_M4_qualified"])
        self.assertFalse(result["production_state_value_accepted"])
        self.assertFalse(result["component_read_Stop_overlap_qualified"])
        self.assertEqual(result["consumer_result"], "REFUSED")

    def test_inconclusive_observation_cannot_be_relabelled_as_qualified(self):
        document = self.document()
        document["component_overlap_qualified"] = True
        self.refused(document)

    def test_scope_cannot_claim_header_activation_or_full_qualification(self):
        for name, value in DOCUMENT["scope"].items():
            document = self.document()
            document["scope"][name] = not value
            self.refused(document)

    def test_wrong_original_runtime_or_probe_source_is_refused(self):
        for field in ("revision", "original_tree", "runtime_tree", "build_tree", "module_sha256", "sum_sha256"):
            document = self.document()
            document["source"][field] = "0" * len(document["source"][field])
            self.refused(document)

    def test_source_counts_use_exact_integer_types(self):
        for value in (True, 472.0):
            document = self.document()
            document["source"]["source_blobs"] = value
            self.refused(document)

    def test_input_fixture_or_probe_substitution_is_refused(self):
        for field in ("probe", "selection", "contract"):
            document = self.document()
            document["source"][field]["sha256"] = "0" * 64
            self.refused(document)

    def test_execution_counts_are_not_inferred_or_coerced(self):
        for field in ("selected_builds", "actual_recorded_processes", "linked_modules_per_binary", "new_external_transports", "automatic_component_retries"):
            for value in (True, 0.0):
                document = self.document()
                document["execution"][field] = value
                self.refused(document)

    def test_initial_failed_producer_records_cannot_be_omitted_or_relabelled(self):
        for action in ("missing", "status", "runtime", "contract", "probe", "retention"):
            document = self.document()
            value = document["initial_framing_failure"]
            if action == "missing":
                value["profiles"].pop()
            elif action == "status":
                value["original_outcome"] = "MATCH"
            elif action == "runtime":
                value["core_runtime_defect_established"] = True
            elif action == "contract":
                value["original_contract_sha256"] = "0" * 64
            elif action == "probe":
                value["probe"]["sha256"] = "0" * 64
            else:
                value["original_complete_outputs_retained"] = False
            self.refused(document)

    def test_initial_failure_witnesses_are_checked_from_independent_bytes(self):
        for index in (0, 127):
            document = self.document()
            document["initial_framing_failure"]["profiles"][1]["observed_warmup_row_sha256s"][index] = "0" * 64
            self.refused(document)

    def test_initial_complete_output_digest_is_not_replaceable(self):
        document = self.document()
        document["initial_framing_failure"]["profiles"][0]["command"]["stdout_sha256"] = "0" * 64
        self.refused(document)

    def test_missing_duplicate_and_reordered_profile_records_are_refused(self):
        for action in ("missing", "duplicate", "reorder"):
            document = self.document()
            if action == "missing":
                document["cases"].pop()
            elif action == "duplicate":
                document["cases"][1] = copy.deepcopy(document["cases"][0])
            else:
                document["cases"].reverse()
            self.refused(document)

    def test_native_binary_pin_and_capture_are_required(self):
        for action in ("pin", "capture"):
            document = self.document()
            if action == "pin":
                document["cases"][0]["binary"]["sha256"] = "0" * 64
            else:
                document["cases"][0]["commands"]["binary_capture"]["stdout_bytes"] += 1
            self.refused(document)

    def test_race_build_settings_cannot_be_replaced_with_ordinary_settings(self):
        document = self.document()
        value = json.loads(document["cases"][1]["buildinfo_stdout_utf8"])
        value["Settings"] = [row for row in value["Settings"] if row["Key"] != "-race"]
        self.replace_buildinfo(document, value, 1)
        self.refused(document)

    def test_module_dependency_or_compiler_substitution_is_refused(self):
        for action in ("dependency", "compiler", "target", "duplicate_setting"):
            document = self.document()
            value = json.loads(document["cases"][0]["buildinfo_stdout_utf8"])
            if action == "dependency":
                value["Deps"][0]["Sum"] = "h1:changed"
            elif action == "compiler":
                value["GoVersion"] = "go1.0"
            elif action == "target":
                value["Path"] = "github.com/zenon-network/go-zenon/cmd/znnd"
            else:
                value["Settings"].append(copy.deepcopy(value["Settings"][0]))
            self.replace_buildinfo(document, value)
            self.refused(document)

    def test_incomplete_nonzero_and_unknown_commands_are_not_success(self):
        for field, value in (("completed", False), ("actual_exit", 1), ("actual_exit", False), ("output_complete", False)):
            document = self.document()
            document["cases"][0]["commands"]["case"][field] = value
            self.refused(document)

    def test_byte_capture_digest_and_length_bind_each_raw_output(self):
        for field, value in (("stdout_sha256", "0" * 64), ("stdout_bytes", 0), ("stderr_sha256", "0" * 64)):
            document = self.document()
            document["cases"][0]["commands"]["case"][field] = value
            self.refused(document)

    def test_extra_race_diagnostics_cannot_be_hidden_by_matching_json(self):
        document = self.document()
        case = document["cases"][1]
        raw = (case["stderr_utf8"] + "unselected diagnostic\n").encode()
        case["stderr_utf8"] = raw.decode()
        case["commands"]["case"]["stderr_bytes"] = len(raw)
        case["commands"]["case"]["stderr_sha256"] = hashlib.sha256(raw).hexdigest()
        self.refused(document)

    def test_warmup_catalog_mismatch_still_refuses_after_capture_rehash(self):
        document = self.document()
        value = self.observation(document)
        value["warmup_row_sha256s"][0] = "0" * 64
        self.replace_observation(document, value)
        self.refused(document)

    def test_partial_error_payload_is_refused_after_capture_rehash(self):
        document = self.document()
        value = self.observation(document)
        row = next(row for row in value["calls"] if row["GetProof"]["error"] is not None)
        row["GetProof"]["row_sha256"] = "0" * 64
        self.replace_observation(document, value)
        self.refused(document)

    def test_missing_request_and_wrong_key_binding_refuse_after_capture_rehash(self):
        for action in ("missing", "key"):
            document = self.document()
            value = self.observation(document)
            if action == "missing":
                value["calls"].pop()
            else:
                value["calls"][0]["key_index"] = 1
            self.replace_observation(document, value)
            self.refused(document)

    def test_post_Stop_success_or_cleanup_error_refuses_after_capture_rehash(self):
        for action in ("post", "cleanup"):
            document = self.document()
            value = self.observation(document)
            if action == "post":
                value["post_Stop"]["Root"]["error"] = None
                value["post_Stop"]["Root"]["hash"] = R.M.H.INITIAL_ROOT
            else:
                value["Stop"]["idempotent_cleanup_error"] = "failed"
            self.replace_observation(document, value)
            self.refused(document)

    def test_file_length_records_cannot_claim_physical_allocation(self):
        document = self.document()
        document["cases"][0]["physical_allocated_bytes_measured"] = True
        self.refused(document)
        document = self.document()
        document["cases"][0]["closed_file_lengths"]["tree"]["largest_file_length"] = 1 << 63
        self.refused(document)

    def test_consumer_acceptance_and_additional_top_level_fields_refuse(self):
        for field, value in (("consumer_result", "ACCEPTED"), ("production_state_value_accepted", True), ("proven", ["STATE_VALUE_INCLUSION"]), ("unselected", 0)):
            document = self.document()
            document[field] = value
            self.refused(document)

    def test_duplicate_nonfinite_and_oversized_json_are_refused(self):
        for raw in (b'{"same":1,"same":2}', b'{"value":NaN}', b" " * 11):
            with self.assertRaises((ValueError, TypeError)):
                R.decoded(raw, 10 if raw.startswith(b" ") else 1024)


if __name__ == "__main__":
    unittest.main(verbosity=2)
