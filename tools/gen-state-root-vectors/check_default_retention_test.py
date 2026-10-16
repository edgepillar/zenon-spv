#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Finite adverse observation controls, not actual node/resource observations."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("selected_default_retention_checker", HERE / "check_default_retention.py")
C = importlib.util.module_from_spec(spec)
spec.loader.exec_module(C)
M = C.M


def key(index):
    return b"\x03" + index.to_bytes(20, "big") + b"\x03" + b"\x42" * 10


class Fixture:
    def __init__(self, policy="pruned"):
        leaves = {key(i): (100 + i).to_bytes(32, "big") for i in range(5)}
        targets = [key(i) for i in range(6)]
        root, _, _ = M.G.L.model({M.G.L.digest(k): v for k, v in leaves.items()}, [])
        witnesses, _ = M.initial_witnesses(leaves, targets, root)
        query_keys = [key(0), key(1), key(5)]
        history, _ = M.history(root, witnesses, [key(0), key(1)], query_keys, 33, 9)
        selected = [{"selection": "mutation_balance", "raw_key": k.hex()} for k in query_keys]
        selection = {"selected_proofs": selected, "query_heights": sorted(map(int, history["checkpoints"]))}
        self.expected = {"history": history, "selection": selection,
                         "selection_sha256": hashlib.sha256(M.encoded(selection)).hexdigest()}
        lookup = {r["height"]: r["root"] for r in history["roots"]}
        retained = range(1 if policy == "archive" else 24, 34)
        counts = {"00": 1, "01": 5, "02": 5, "03": len(retained), "05": 1, "06": len(retained)}
        snapshot = {"format": "03", "logical_records": sum(counts.values()),
                    "logical_key_value_bytes": 4096, "logical_records_sha256": "a" * 64,
                    "record_prefix_counts": counts,
                    "retained_roots": [{"height": h, "hash": C.identifier("G", h)["hash"], "root": lookup[h]} for h in retained]}
        queries = []
        for h in selection["query_heights"]:
            available = h in retained
            proofs = [{"selection": r["selection"], "raw_key": r["raw_key"],
                       "value": r["value"] if available else None,
                       "proof": r["proof"] if available else None,
                       "error": None if available else "no-version", "consumer_result": "REFUSED"}
                      for r in history["checkpoints"][str(h)]]
            queries.append({"height": h, "root": lookup[h] if available else C.ZERO,
                            "root_error": None if available else "no-version", "proofs": proofs})
        queries += [{"identifier": C.identifier("X", 33), "root": C.ZERO, "root_error": "version-hash-mismatch"},
                    {"identifier": {"height": 0, "hash": C.ZERO}, "root": C.ZERO, "root_error": None}]
        self.tables = {"snapshot": snapshot, "queries": queries}
        self.observation = {k: True for k in C.TRUE}
        self.observation.update({k: False for k in C.FALSE})
        self.observation.update({k: 1 for k in C.TIMERS})
        self.observation.update({"kind": "source-default-retention-component-observation", "policy": policy,
                                 "Go_version": "go1.25.14", "platform": "darwin/arm64", "history_height": 33,
                                 "selection_sha256": self.expected["selection_sha256"], "raw_input_sha256": M.G.RAW["sha256"],
                                 "retention_override": 0, "bulk_batch_override": 0, "effective_retention": 9,
                                 "rollback_cache": 3, "retention_margin": 6, "bulk_batch_cap": 10000,
                                 "tail_batch_cap": 10, "batch_budget_ns": 1000000000,
                                 "initial_root": C.ZERO, "initial_root_error": "not-ready",
                                 "post_stop_public_root": C.ZERO, "post_stop_public_error": "not-ready",
                                 "post_stop_direct_root": C.ZERO, "post_stop_direct_error": "database-closed",
                                 "patch_heights_requested": 33, "actual_patch_frame_sha256": history["mutation_frame_sha256"],
                                 "logical_snapshots_observed": 3, "proof_query_sets_observed": 2,
                                 "physical_files_after_final_close": [{"name": "000001.ldb", "bytes": 4096, "sha256": "b" * 64}],
                                 "consumer_result": "REFUSED"})

    def check(self, repin=True):
        raw = M.encoded(self.tables)
        if repin:
            self.observation["logical_tables_sha256"] = hashlib.sha256(raw).hexdigest()
            self.observation["logical_tables_bytes"] = len(raw)
        return C.check_tables(raw, self.observation, self.expected)


class DefaultRetentionObservationControls(unittest.TestCase):
    def refused(self, change, policy="pruned"):
        fixture = Fixture(policy)
        change(fixture)
        with self.assertRaises((ValueError, AssertionError, TypeError, KeyError)):
            fixture.check()

    def test_both_policies_match_finite_independent_roots_and_proofs(self):
        pruned, archive = Fixture().check(), Fixture("archive").check()
        self.assertEqual((pruned["retained_roots"], archive["retained_roots"]), (10, 33))
        self.assertGreater(pruned["pruned_proof_refusals"], 0)
        self.assertEqual(archive["pruned_proof_refusals"], 0)
        self.assertGreater(archive["canonical_proofs_matched"], pruned["canonical_proofs_matched"])
        self.assertEqual(pruned["consumer_result"], "REFUSED")
        self.assertFalse(archive["production_resources_qualified"])

    def test_same_height_different_hash_cannot_relabel_a_root(self):
        self.refused(lambda f: f.tables["snapshot"]["retained_roots"][-1].__setitem__("hash", C.identifier("X", 33)["hash"]))

    def test_wrong_root_or_missing_extra_reordered_version_is_refused(self):
        self.refused(lambda f: f.tables["snapshot"]["retained_roots"][0].__setitem__("root", "0" * 64))
        self.refused(lambda f: f.tables["snapshot"]["retained_roots"].pop())
        self.refused(lambda f: f.tables["snapshot"]["retained_roots"].append(copy.deepcopy(f.tables["snapshot"]["retained_roots"][-1])))
        self.refused(lambda f: f.tables["snapshot"]["retained_roots"].reverse())

    def test_archive_or_pruned_policy_cannot_be_changed_after_observation(self):
        self.refused(lambda f: f.observation.__setitem__("policy", "archive"))
        self.refused(lambda f: f.observation.__setitem__("policy", "pruned"), "archive")

    def test_query_key_value_and_canonical_proof_are_bound(self):
        self.refused(lambda f: f.tables["queries"][-3]["proofs"][0].__setitem__("raw_key", key(100).hex()))
        self.refused(lambda f: f.tables["queries"][-3]["proofs"][0].__setitem__("value", "00" * 32))
        self.refused(lambda f: f.tables["queries"][-3]["proofs"][0].__setitem__("proof", "00" * 99))

    def test_equal_but_invalid_expected_and_actual_proof_is_still_refused(self):
        f = Fixture()
        h = str(f.expected["selection"]["query_heights"][-1])
        f.expected["history"]["checkpoints"][h][0]["proof"] = "00" * 99
        f.tables["queries"][-3]["proofs"][0]["proof"] = "00" * 99
        with self.assertRaises((ValueError, AssertionError)):
            f.check()

    def test_pruned_query_cannot_fall_back_to_an_unauthenticated_value(self):
        self.refused(lambda f: f.tables["queries"][0]["proofs"][0].__setitem__("value", "00" * 32))
        self.refused(lambda f: f.tables["queries"][0].__setitem__("root_error", None))

    def test_wrong_hash_and_origin_lookup_refusal_contracts_stay_distinct(self):
        self.refused(lambda f: f.tables["queries"][-2].__setitem__("root_error", None))
        self.refused(lambda f: f.tables["queries"][-1].__setitem__("root_error", "no-version"))
        self.refused(lambda f: f.tables["queries"][-1]["identifier"].__setitem__("height", False))

    def test_node_defaults_cannot_be_replaced_by_a_test_override(self):
        for field, value in (("retention_override", 256), ("bulk_batch_override", 1),
                             ("effective_retention", 8), ("retention_margin", 5),
                             ("bulk_batch_cap", 1), ("tail_batch_cap", 1), ("batch_budget_ns", 1)):
            with self.subTest(field=field):
                self.refused(lambda f, k=field, v=value: f.observation.__setitem__(k, v))

    def test_actual_read_sequence_and_closed_reopen_evidence_are_required(self):
        for field, value in (("actual_patch_frame_sha256", "f" * 64), ("patch_heights_requested", 32),
                             ("each_patch_requested_once", False), ("logical_snapshots_observed", 2),
                             ("logical_snapshots_equal", False), ("proof_query_sets_observed", 1),
                             ("proof_query_sets_equal", False), ("post_stop_direct_error", None)):
            with self.subTest(field=field):
                self.refused(lambda f, k=field, v=value: f.observation.__setitem__(k, v))

    def test_boolean_counts_and_negative_or_unbounded_time_are_refused(self):
        for field, value in (("history_height", True), ("retention_override", False),
                             ("logical_snapshots_observed", True), ("fixture_initialization_ns", -1),
                             ("background_worker_elapsed_ns", 600000000001)):
            with self.subTest(field=field):
                self.refused(lambda f, k=field, v=value: f.observation.__setitem__(k, v))

    def test_raw_table_bytes_are_pinned_even_when_json_values_are_equal(self):
        f = Fixture()
        f.check()
        raw = json.dumps(f.tables, sort_keys=True, indent=2).encode()
        with self.assertRaises(ValueError):
            C.check_tables(raw, f.observation, f.expected)

    def test_prefix_counts_format_and_record_inventory_cannot_be_dropped(self):
        self.refused(lambda f: f.tables["snapshot"].__setitem__("format", "02"))
        self.refused(lambda f: f.tables["snapshot"]["record_prefix_counts"].pop("06"))
        self.refused(lambda f: f.tables["snapshot"]["record_prefix_counts"].__setitem__("03", 9))
        self.refused(lambda f: f.tables["snapshot"].__setitem__("logical_records", True))

    def test_unsafe_duplicate_or_unbounded_physical_file_records_are_refused(self):
        self.refused(lambda f: f.observation["physical_files_after_final_close"][0].__setitem__("name", "../private-file"))
        self.refused(lambda f: f.observation["physical_files_after_final_close"].append(copy.deepcopy(f.observation["physical_files_after_final_close"][0])))
        self.refused(lambda f: f.observation["physical_files_after_final_close"][0].__setitem__("bytes", (256 << 20) + 1))

    def test_extra_fields_or_production_claims_cannot_become_acceptance(self):
        self.refused(lambda f: f.observation.__setitem__("private_diagnostic", "isolated sentinel"))
        for field in C.FALSE:
            with self.subTest(field=field):
                self.refused(lambda f, k=field: f.observation.__setitem__(k, True))
        self.refused(lambda f: f.tables["queries"][-3]["proofs"][0].__setitem__("consumer_result", "ACCEPT"))

    def test_generic_finite_fixture_cannot_be_presented_as_selected_real_workload(self):
        with self.assertRaises((ValueError, KeyError)):
            C.selected_expectations(Fixture().expected)


if __name__ == "__main__":
    unittest.main(verbosity=2)
