#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Synthetic reader controls, distinct from the separately executed node cases."""
import copy
import hashlib
import importlib.util
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("offline_rebuild_reader_controls", HERE / "check_offline_rebuild_successor.py")
C = importlib.util.module_from_spec(spec)
spec.loader.exec_module(C)


def snapshot(expected, height=64, horizon=1, fault=None):
    roots = []
    for row in expected["history"]["roots"][:height]:
        h = row["height"]
        root, error = row["root"], None
        if h < horizon:
            root, error = C.ZERO, "no-version"
        if h == 32 and fault:
            root = C.ZERO
            error = "version-hash-missing" if fault == "missing-retained-hash" else "version-hash-mismatch"
        roots.append({"identifier": C.M.identifier(h), "root": root, "error": error})
    queries = []
    for h in expected["selection"]["query_heights"]:
        if h > height:
            continue
        missing = h < horizon
        proofs = [{"selection": row["selection"], "raw_key": row["raw_key"],
                   "value": None if missing else row["value"], "proof": None if missing else row["proof"],
                   "error": "no-version" if missing else None, "consumer_result": "REFUSED"}
                  for row in expected["history"]["checkpoints"][str(h)]]
        queries.append({"identifier": C.M.identifier(h), "root": C.ZERO if missing else roots[h - 1]["root"],
                        "root_error": "no-version" if missing else None, "proofs": proofs})
    return {"frontier": C.M.identifier(height), "roots": roots, "queries": queries,
            "identity_refusals": [
                {"name": "wrong-hash", "identifier": C.M.identifier(height, "X"), "root": C.ZERO, "error": "version-hash-mismatch"},
                {"name": "height-only", "identifier": {"height": height, "hash": C.ZERO}, "root": C.ZERO, "error": "version-hash-mismatch"},
                {"name": "missing-version", "identifier": C.M.identifier(height + 1), "root": C.ZERO, "error": "no-version"}],
            "logical_records": {"records": 1, "logical_bytes": 1, "sha256": C.ZERO}}


def sealed(value):
    return {"complete_snapshot_sha256": hashlib.sha256(C.M.encoded(value)).hexdigest()}


def modeled_observation(expected, variant):
    rows, full = [], snapshot(expected)
    for index, name in enumerate(C.COMMON[:3]):
        selected = snapshot(expected, horizon=59 if index == 1 else 1)
        roots = {str(row["height"]): row["root"] for row in expected["history"]["roots"]
                 if index != 1 or row["height"] >= 59}
        fixed = variant == "full-identifier"
        rows.append({"name": name, "operation": "RebuildStateTree", "archive": index == 2,
                     "retention_override": 0 if index == 0 else 5,
                     "result": {"frontier": C.M.identifier(64), "roots": roots} if fixed else None,
                     "error": None if fixed else "version-hash-mismatch",
                     "frontier_snapshots": 3 if fixed else 2, "patch_requests": C.calls(1, 64),
                     "closed_reopens": [selected, sealed(selected)]})
    for delta in (False, True):
        heights = (42, 52, 62, 64) if delta else (64,)
        before = snapshot(expected, height=32) if delta else copy.deepcopy(full)
        rows.append({"name": "prebuild-delta" if delta else "prebuild-reopen",
                     "operation": "PrebuildStateTree+StateTreeBuild",
                     "prebuild_frontier": C.M.identifier(32 if delta else 64), "prebuild_snapshot": before,
                     "initial_patch_requests": C.calls(1, 32 if delta else 64),
                     "delta_patch_requests": C.calls(33, 64) if delta else {},
                     "steps": [{"done": h == 64, "error": None, "frontier": C.M.identifier(h), "ready": h == 64} for h in heights],
                     "ready_before_stop": True, "final_root": expected["history"]["final_root"],
                     "final_root_error": None, "closed_reopens": [copy.deepcopy(full), sealed(full)]})
    if variant == "full-identifier":
        errors = ("invalid-chain-momentum", "invalid-chain-momentum", "version-hash-mismatch",
                  "chain-store-stopped", "injected-chain-read", "version-hash-missing", "version-hash-mismatch")
        for fault, error in zip(C.FAULTS, errors):
            retained = fault in ("missing-retained-hash", "wrong-retained-hash")
            selected = snapshot(expected, fault=fault if retained else None)
            rows.append({"name": "fault-" + fault, "operation": "RebuildStateTree-refusal", "fault": fault,
                         "result": None, "error": error, "frontier_snapshots": 3,
                         "fault_snapshots_applied": 0 if retained else 1,
                         "before": sealed(selected), "closed_reopens": [selected, sealed(selected)]})
    return dict({"kind": "successor-offline-rebuild-component-observation", "format_version": 1,
                 "variant": variant, "node_revision": C.P.REVISION, "node_tree": C.P.TREE,
                 "runtime_tree": C.M.R.MODIFIED_TREE if variant == "full-identifier" else C.M.R.T.MODIFIED_TREE,
                 "Go_version": "go1.25.14", "platform": "darwin/arm64",
                 "raw_input_sha256": expected["raw_input"]["sha256"], "selection_sha256": expected["selection_sha256"],
                 "history_height": 64, "cases": rows, "actual_exported_offline_helpers_executed": True,
                 "manager_and_genesis_are_controlled_adapters": True,
                 "source_identifiers_and_suffix_patches_are_synthetic": True, "consumer_result": "REFUSED"},
                **{key: False for key in C.FALSE_FIELDS})


class OfflineRebuildReaderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.expected = C.M.derive()
        cls.original = {variant: modeled_observation(cls.expected, variant) for variant in C.M.R.VARIANTS}

    def check(self, value, variant="full-identifier"):
        return C.check_observation(C.M.encoded(value), self.expected, variant)

    def test_two_synthetic_positive_contracts_are_not_new_backend_execution(self):
        for variant, cases in (("terminal-parent", 5), ("full-identifier", 12)):
            result = self.check(self.original[variant], variant)
            self.assertEqual(result["cases"], cases)
            self.assertEqual(result["complete_snapshot_reopens_checked"], 2 * cases)
            self.assertFalse(result["new_node_backend_executed_by_reader"])
            self.assertEqual(result["consumer_result"], "REFUSED")

    def test_runtime_source_and_acceptance_relabeling_is_refused(self):
        for field, value in (("runtime_tree", C.M.R.T.MODIFIED_TREE), ("node_revision", "0" * 40),
                             ("selection_sha256", C.ZERO), ("history_height", True),
                             ("platform", "linux/amd64"), ("network_executed", True),
                             ("accepted_header_root_binding", True), ("consumer_result", "ACCEPT")):
            changed = copy.deepcopy(self.original["full-identifier"])
            changed[field] = value
            with self.assertRaises(ValueError):
                self.check(changed)

    def test_parent_success_cannot_be_fabricated(self):
        changed = copy.deepcopy(self.original["terminal-parent"])
        changed["cases"][0]["result"] = self.original["full-identifier"]["cases"][0]["result"]
        changed["cases"][0]["error"] = None
        with self.assertRaises(ValueError):
            self.check(changed, "terminal-parent")

    def test_root_map_wrong_height_or_missing_retained_boundary_is_refused(self):
        for key, value in (("60", C.ZERO), ("58", self.expected["history"]["roots"][57]["root"])):
            changed = copy.deepcopy(self.original["full-identifier"])
            changed["cases"][1]["result"]["roots"][key] = value
            with self.assertRaises(ValueError):
                self.check(changed)
        changed = copy.deepcopy(self.original["full-identifier"])
        del changed["cases"][1]["result"]["roots"]["59"]
        with self.assertRaises(ValueError):
            self.check(changed)

    def test_correlated_observed_snapshot_and_digest_cannot_override_independent_root(self):
        changed = copy.deepcopy(self.original["full-identifier"])
        table = changed["cases"][0]["closed_reopens"][0]
        table["roots"][63]["root"] = C.ZERO
        changed["cases"][0]["closed_reopens"][1] = sealed(table)
        with self.assertRaises(ValueError):
            self.check(changed)

    def test_proof_bytes_value_and_complete_reopen_digest_are_bound(self):
        for field, value in (("proof", "00"), ("value", "01" * 32), ("raw_key", "ff" * 32), ("consumer_result", "ACCEPT")):
            changed = copy.deepcopy(self.original["full-identifier"])
            changed["cases"][0]["closed_reopens"][0]["queries"][0]["proofs"][0][field] = value
            with self.assertRaises(ValueError):
                self.check(changed)
        changed = copy.deepcopy(self.original["full-identifier"])
        changed["cases"][0]["closed_reopens"][1]["complete_snapshot_sha256"] = C.ZERO
        with self.assertRaises(ValueError):
            self.check(changed)

    def test_delta_batch_schedule_and_ancestry_are_bounded_without_fixing_wall_time(self):
        changed = copy.deepcopy(self.original["full-identifier"])
        heights = list(range(33, 65))
        changed["cases"][4]["steps"] = [{"done": h == 64, "error": None, "frontier": C.M.identifier(h), "ready": h == 64} for h in heights]
        self.assertEqual(self.check(changed)["cases"], 12)
        for h in (32, 43, 65):
            altered = copy.deepcopy(self.original["full-identifier"])
            altered["cases"][4]["steps"][0]["frontier"] = C.M.identifier(h)
            with self.assertRaises(ValueError):
                self.check(altered)

    def test_missing_faults_false_success_and_metadata_repair_are_refused(self):
        changed = copy.deepcopy(self.original["full-identifier"])
        changed["cases"].pop()
        with self.assertRaises(ValueError):
            self.check(changed)
        for mutate in (lambda row: row.__setitem__("error", None),
                       lambda row: row.__setitem__("result", {}),
                       lambda row: row.__setitem__("fault_snapshots_applied", 0),
                       lambda row: row["before"].__setitem__("complete_snapshot_sha256", C.ZERO)):
            changed = copy.deepcopy(self.original["full-identifier"])
            mutate(changed["cases"][5])
            with self.assertRaises(ValueError):
                self.check(changed)


if __name__ == "__main__":
    unittest.main()
