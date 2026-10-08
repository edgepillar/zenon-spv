#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Controls for independently selected disk exit/reopen observations."""

import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("disk_check", HERE / "check_disk_lifecycle.py")
CHECK = importlib.util.module_from_spec(spec)
spec.loader.exec_module(CHECK)


class DiskLifecycleControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _, cls.corpus = CHECK.BYTE.read_corpus(HERE / "testdata/candidate-disk-lifecycle.json")

    def case(self, name):
        return copy.deepcopy(next(row for row in self.corpus["cases"] if row["input"]["name"] == name))

    def replace(self, name, case):
        document = copy.deepcopy(self.corpus)
        index = next(i for i, row in enumerate(document["cases"]) if row["input"]["name"] == name)
        document["cases"][index] = case
        return document

    def refused(self, document):
        with self.assertRaises((ValueError, KeyError, TypeError)):
            CHECK.check_corpus(document)

    def test_finite_inventory_matches_independent_roots_proofs_and_logical_storage(self):
        report = CHECK.check_corpus(self.corpus)
        self.assertEqual((report["disk_cases"], report["controlled_abrupt_child_exits"], report["clean_child_close_controls"],
                          report["reopen_rounds"], report["read_api_observations"]), (6, 5, 1, 12, 240))
        self.assertEqual((report["unretained_version_errors"], report["recovered_inclusion_proof_matches"],
                          report["recovered_absence_proof_matches"]), (88, 26, 50))
        self.assertEqual((report["logical_storage_records_all_rounds"], report["logical_storage_key_bytes_all_rounds"],
                          report["logical_storage_value_bytes_all_rounds"]), (102, 1974, 3222))

    def test_staged_writes_are_not_promoted_by_process_exit(self):
        case = self.case("exit-after-stage")
        self.assertEqual(case["child_observation"]["frontier_before_exit"], CHECK.identifier("A", 2))
        self.assertTrue(all(row["error"] == CHECK.NO_VERSION for row in case["rounds"][0]["reads"] if row["identifier"]["height"] == 3))
        substitute = self.case("exit-after-commit")
        case["rounds"] = substitute["rounds"]
        self.refused(self.replace("exit-after-stage", case))

    def test_returned_commit_survives_both_planned_reopen_rounds(self):
        case = self.case("exit-after-commit")
        self.assertEqual(case["child_exit"], 73)
        self.assertFalse(case["child_clean_close_marker"])
        self.assertEqual(case["rounds"][0]["reads"], case["rounds"][1]["reads"])
        case["rounds"][1] = self.case("exit-after-stage")["rounds"][1]
        self.refused(self.replace("exit-after-commit", case))

    def test_returned_truncate_removes_the_higher_version(self):
        case = self.case("exit-after-truncate")
        self.assertEqual(case["rounds"][0]["storage"]["retained_heights"], [1, 2])
        case["rounds"] = self.case("exit-after-commit")["rounds"]
        self.refused(self.replace("exit-after-truncate", case))

    def test_returned_prune_removes_history_without_changing_frontier(self):
        case = self.case("exit-after-prune")
        self.assertEqual(case["rounds"][0]["frontier"], CHECK.identifier("A", 3))
        self.assertEqual(case["rounds"][0]["storage"]["retained_heights"], [3])
        case["rounds"][0]["storage"]["retained_heights"] = [1, 2, 3]
        self.refused(self.replace("exit-after-prune", case))

    def test_unretained_version_error_cannot_become_an_absence_proof(self):
        case = self.case("exit-after-prune")
        row = next(q for q in case["rounds"][0]["reads"] if q["name"] == "absent-token" and q["identifier"]["height"] == 1)
        self.assertEqual(row["error"], CHECK.NO_VERSION)
        self.assertIsNone(row["proof"])
        root, _, levels, values = CHECK.state_bytes(1)
        row["error"] = None
        row["proof"] = CHECK.BYTE.canonical_proof(levels, values, CHECK.BYTE.digest(CHECK.selected_key(True))).hex()
        self.refused(self.replace("exit-after-prune", case))

    def test_clean_close_is_separate_from_bypassed_child_defers(self):
        self.assertTrue(self.case("clean-close")["child_clean_close_marker"])
        for name in ("exit-after-open", "exit-after-stage", "exit-after-commit", "exit-after-truncate", "exit-after-prune"):
            case = self.case(name)
            self.assertFalse(case["child_clean_close_marker"])
            case["child_clean_close_marker"] = True
            self.refused(self.replace(name, case))

    def test_child_exit_codes_have_exact_integer_types(self):
        for value in (True, 73.0, "73", 0, None):
            case = self.case("exit-after-commit")
            case["child_exit"] = value
            self.refused(self.replace("exit-after-commit", case))

    def test_selected_frontier_hash_and_height_cannot_be_retargeted(self):
        for field, value in (("hash", CHECK.identifier("X", 3)["hash"]), ("height", 2), ("height", 3.0)):
            case = self.case("exit-after-commit")
            case["rounds"][0]["frontier"][field] = value
            self.refused(self.replace("exit-after-commit", case))

    def test_height_only_other_hash_roots_do_not_authenticate_versions(self):
        rows = self.case("exit-after-commit")["rounds"][0]["reads"]
        root = next(r for r in rows if r["name"] == "root" and r["identifier"]["height"] == 3)
        other = next(r for r in rows if r["name"] == "root-other-hash" and r["identifier"]["height"] == 3)
        self.assertEqual(root["root"], other["root"])
        self.assertNotEqual(root["identifier"]["hash"], other["identifier"]["hash"])
        document = copy.deepcopy(self.corpus)
        document["scope"]["authenticated_retained_version_provenance_qualified"] = True
        self.refused(document)

    def test_coherent_provider_root_value_and_proof_cannot_replace_selection(self):
        case = self.case("exit-after-commit")
        root, value, levels, values = CHECK.state_bytes(2)
        for row in case["rounds"][0]["reads"]:
            if row["identifier"]["height"] != 3:
                continue
            if row["name"].startswith("root"):
                row["root"] = root.hex()
            else:
                key = bytes.fromhex(row["key"])
                row["proof"] = CHECK.BYTE.canonical_proof(levels, values, CHECK.BYTE.digest(key)).hex()
                row["value"] = value.hex() if row["name"] == "balance" else None
                self.assertEqual(CHECK.BYTE.proof_result(root, CHECK.BYTE.digest(key),
                    value if row["value"] is not None else b"", bytes.fromhex(row["proof"]),
                    row["value"] is not None), "match")
        self.refused(self.replace("exit-after-commit", case))

    def test_present_and_absent_proofs_remain_distinct_and_canonical(self):
        case = self.case("exit-after-commit")
        rows = case["rounds"][0]["reads"]
        positive = next(r for r in rows if r["name"] == "balance" and r["identifier"]["height"] == 3)
        absent = next(r for r in rows if r["name"] == "absent-token" and r["identifier"]["height"] == 3)
        self.assertIsNotNone(positive["value"])
        self.assertIsNone(absent["value"])
        self.assertNotEqual(positive["proof"], absent["proof"])
        absent["proof"] = positive["proof"]
        self.refused(self.replace("exit-after-commit", case))

    def test_raw_key_and_proof_path_substitution_are_refused(self):
        for field, value in (("key", CHECK.selected_key(True).hex()), ("proof", "00" * 100)):
            case = self.case("exit-after-commit")
            row = next(r for r in case["rounds"][0]["reads"] if r["name"] == "balance" and r["identifier"]["height"] == 3)
            row[field] = value
            self.refused(self.replace("exit-after-commit", case))

    def test_out_of_scope_key_does_not_become_a_balance(self):
        case = self.case("exit-after-commit")
        row = next(r for r in case["rounds"][0]["reads"] if r["name"] == "balance" and r["identifier"]["height"] == 3)
        row["key"] = "07" + row["key"][2:]
        self.refused(self.replace("exit-after-commit", case))

    def test_logical_storage_counts_are_not_physical_disk_or_memory_budgets(self):
        for field in ("records", "key_bytes", "value_bytes"):
            case = self.case("exit-after-prune")
            case["rounds"][0]["storage"][field] += 1
            self.refused(self.replace("exit-after-prune", case))
        document = copy.deepcopy(self.corpus)
        document["scope"]["realistic_retention_resource_budgets_qualified"] = True
        self.refused(document)

    def test_method_trace_cannot_hide_or_invent_commits(self):
        for trace in (("OpenFile", "NewNodeTree", "Update", "Commit"), ("OpenFile", "NewNodeTree", "Chain.Start")):
            case = self.case("exit-after-stage")
            case["child_observation"]["method_trace"] = list(trace)
            self.refused(self.replace("exit-after-stage", case))

    def test_case_round_order_inventory_and_closed_fields_are_bound(self):
        for change in (lambda d: d["cases"].reverse(), lambda d: d["cases"].pop(),
                       lambda d: d["cases"][0]["rounds"].reverse(),
                       lambda d: d["cases"][0].update({"extra": True})):
            document = copy.deepcopy(self.corpus)
            change(document)
            self.refused(document)

    def test_heights_counts_and_marker_types_do_not_coerce(self):
        for value in (True, 2.0, "2", -1, None):
            case = self.case("exit-after-stage")
            case["input"]["seed_height"] = value
            self.refused(self.replace("exit-after-stage", case))
        case = self.case("clean-close")
        case["child_clean_close_marker"] = 1
        self.refused(self.replace("clean-close", case))

    def test_scope_source_activation_power_loss_and_production_claims_are_closed(self):
        for field in ("power_loss_qualified", "torn_write_qualified", "production_crash_recovery_qualified",
                      "runtime_state_proof_acceptance", "profile_agreed", "network_activation_authenticated", "full_node_started"):
            document = copy.deepcopy(self.corpus)
            document["scope"][field] = True
            self.refused(document)
        document = copy.deepcopy(self.corpus)
        document["source"]["revision"] = "00" * 20
        self.refused(document)
        report = CHECK.check_corpus(self.corpus)
        self.assertFalse(report["reference_backend_execution_in_checker"])
        self.assertFalse(report["production_acceptance_enabled"])

    def test_duplicate_fields_trailing_json_and_byte_bounds_are_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / "fixture.json"
            for raw in (b'{"cases":[],"cases":[]}', b'{}{}', b'{} trailing', b' ' * (CHECK.BYTE.MAX_FILE_BYTES + 1)):
                file.write_bytes(raw)
                with self.assertRaises((ValueError, KeyError, TypeError)):
                    CHECK.BYTE.read_corpus(file)
        for field in ("value", "proof"):
            case = self.case("exit-after-commit")
            row = next(r for r in case["rounds"][0]["reads"] if r["name"] == "balance" and r["identifier"]["height"] == 3)
            row[field] = "00" * (CHECK.BYTE.MAX_PROOF_BYTES + 1)
            self.refused(self.replace("exit-after-commit", case))


if __name__ == "__main__":
    unittest.main(verbosity=2)
