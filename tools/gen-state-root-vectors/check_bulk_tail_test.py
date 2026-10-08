#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Independent complete fixture seed, retained tail and separate sample controls."""
import copy
import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("bulk_tail_check", HERE / "check_bulk_tail.py")
CHECK = importlib.util.module_from_spec(spec)
spec.loader.exec_module(CHECK)


class BulkTailControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw, cls.corpus = CHECK.BYTE.read_corpus(HERE / "testdata/candidate-bulk-tail.json")
        cls.digest = hashlib.sha256(cls.raw).hexdigest()

    def refused(self, document):
        with self.assertRaises((ValueError, KeyError, TypeError)):
            CHECK.check_corpus(document)

    def change(self, function):
        document = copy.deepcopy(self.corpus)
        function(document)
        self.refused(document)

    def samples(self):
        # Shape-only test data: no fabricated measurement becomes an observation.
        runs = []
        for _ in range(2):
            cases = []
            for name, _, versions, retain, _, policy in CHECK.selections():
                row = {"case": name, "platform": "darwin/arm64", "peak_rss_bytes": 100,
                       "peak_rss_method": CHECK.RSS_METHOD, **{k: 1 for k in CHECK.TIMINGS}}
                row["prepared_patch_update_commit_prune_elapsed_ns"] = 10
                row["prune_elapsed_ns"] = 0 if policy == "bulk-tail" else 1
                row["query_timings"] = [{"root_calls": 7, "root_elapsed_ns": 1,
                                         "proof_calls": 35, "proof_elapsed_ns": 1} for _ in range(3)]
                row.update({k: {"regular_files": 2, "file_bytes": 10, "largest_file_bytes": 8}
                            for k in CHECK.PHYSICAL})
                cases.append(row)
            runs.append(cases)
        return {"format_version": 1, "kind": "candidate-bulk-tail-samples",
                "source": copy.deepcopy(self.corpus["source"]), "corpus_sha256": self.digest,
                "conformance_runs": 2, "measurement_runs_expected_to_vary": True,
                "production_resource_budgets_qualified": False, "source_execution_platform": "darwin",
                "go_version": "go version go1.25.14 darwin/arm64", "reference_binary_sha256": "02" * 32, "samples": runs,
                "commands": [{"label": label, "actual_exit": 0, "completed": True,
                              "stdout_sha256": "01" * 32, "stderr_sha256": hashlib.sha256(b"").hexdigest()}
                             for label in ("generate-first", "generate-second")]}

    def sample_refused(self, document):
        with self.assertRaises((ValueError, KeyError, TypeError)):
            CHECK.check_resource_samples(document, self.digest)

    def test_finite_scale_churn_pairs_match_independent_graph_and_proofs(self):
        report = CHECK.check_corpus(self.corpus)
        self.assertEqual((report["bulk_tail_cases"], report["conformance_rounds"], report["read_api_observations"]),
                         (6, 18, 756))
        self.assertGreater(report["stored_zero_inclusion_proof_matches"], 0)
        self.assertFalse(report["production_retention_resource_budgets_qualified"])

    def test_shared_physical_edges_are_counted_once_across_versions(self):
        history = CHECK.states(64, 16, 8)
        sizes = [len(CHECK.graph(history[h])[2]) for h in range(13, 17)]
        stored = self.corpus["cases"][0]["rounds"][0]["storage"]
        self.assertLess(stored["family_counts"]["node"], sum(sizes))
        self.change(lambda d: d["cases"][0]["rounds"][0]["storage"]["family_counts"].update(node=sum(sizes)))

    def test_sequential_prune_and_bulk_tail_have_equal_retained_states(self):
        archive, pruned = self.corpus["cases"][:2]
        self.assertEqual(archive["rounds"][0]["frontier"], pruned["rounds"][0]["frontier"])
        latest = lambda c: [r for r in c["rounds"][0]["reads"] if r["identifier"]["height"] == 16]
        self.assertEqual(latest(archive), latest(pruned))
        self.change(lambda d: d["cases"][1]["rounds"][0]["storage"].update(records=0, records_sha256="00" * 32))

    def test_complete_raw_seed_map_is_bound_before_backend_construction(self):
        for case in self.corpus['cases'][1::2]:
            item=case['input']
            seed=CHECK.seed_manifest(item,CHECK.states(item['keys'],item['versions'],item['churn']))
            self.assertEqual(case['bulk_seed_manifest'],seed)
            self.assertEqual(case['input_operations'],seed['present_keys']+3*item['churn'])
        self.change(lambda d: d['cases'][1]['bulk_seed_manifest'].update(present_keys=64))
        self.change(lambda d: d['cases'][1]['bulk_seed_manifest'].update(raw_map_sha256='00'*32))

    def test_serialized_nodes_depths_and_refcounts_bind_logical_digest(self):
        for case in self.corpus["cases"]:
            storage = case["rounds"][0]["storage"]
            self.assertEqual(storage["family_counts"]["node"], storage["family_counts"]["refcount"])
            self.assertEqual(len(storage["records_sha256"]), 64)
        for field in ("key_bytes", "value_bytes", "records", "records_sha256"):
            self.change(lambda d: d["cases"][0]["rounds"][1]["storage"].update(
                {field: "00" * 32 if field == "records_sha256" else 1}))

    def test_bulk_tail_missing_older_version_cannot_be_relabelled_as_absence(self):
        d = copy.deepcopy(self.corpus)
        row = next(r for r in d["cases"][1]["rounds"][0]["reads"] if r["identifier"]["height"] == 12 and r["key"] is not None)
        self.assertEqual(row["error"], CHECK.NO_VERSION)
        row.update(error=None, value=None, proof="00" * 100)
        self.refused(d)

    def test_regular_commit_seed_gap_refuses_then_bulk_commit_preserves_tail(self):
        for replay,bulk in zip(self.corpus['cases'][::2],self.corpus['cases'][1::2]):
            self.assertIsNone(replay['regular_seed_commit_error'])
            self.assertEqual(replay['bulk_commit_calls'],0)
            self.assertEqual(bulk['regular_seed_commit_error'],'trie: commit height must be exactly one above the frontier')
            self.assertEqual((bulk['bulk_commit_calls'],bulk['commit_calls'],bulk['prune_calls']),(1,3,0))
            self.assertEqual(replay['rounds'],bulk['rounds'])
            self.assertNotIn(0,bulk['rounds'][0]['storage']['retained_heights'])
        self.change(lambda d: d['cases'][1].update(regular_seed_commit_error=None))
        self.change(lambda d: d['cases'][1].update(bulk_commit_calls=0))

    def test_stored_zero_and_deleted_keys_have_distinct_proofs(self):
        d = copy.deepcopy(self.corpus)
        rows = [r for r in d["cases"][0]["rounds"][0]["reads"] if r["identifier"]["height"] == 16 and r["key"] is not None]
        zero = next(r for r in rows if r["value"] == "00" * 32)
        deleted = next(r for r in rows if r["key"] == CHECK.key(40).hex())
        self.assertIsNone(deleted["value"])
        self.assertNotEqual(zero["proof"], deleted["proof"])
        zero["value"] = None
        self.refused(d)

    def test_raw_balance_address_token_and_path_substitutions_are_refused(self):
        for key in (CHECK.key(1).hex(), "07" + CHECK.key(0).hex()[2:], CHECK.key(0).hex()[:-2] + "44"):
            d = copy.deepcopy(self.corpus)
            d["cases"][0]["rounds"][0]["reads"][1]["key"] = key
            self.refused(d)

    def test_coherent_foreign_root_value_proof_does_not_replace_selection(self):
        d = copy.deepcopy(self.corpus)
        rows = [r for r in d["cases"][0]["rounds"][0]["reads"] if r["identifier"]["height"] == 16]
        state = copy.deepcopy(CHECK.states(64, 16, 8)[16])
        state[CHECK.BYTE.digest(CHECK.key(0))] = b"\x01" * 32
        levels, values = CHECK.BYTE.tree_levels([{"path": p.hex(), "value": v.hex()} for p, v in state.items()])
        root = levels[0][0]
        for row in rows:
            if row["key"] is None:
                row["root"] = root.hex()
            else:
                path = CHECK.BYTE.digest(bytes.fromhex(row["key"]))
                value = state.get(path)
                proof = CHECK.BYTE.canonical_proof(levels, values, path)
                row.update(value=None if value is None else value.hex(), proof=proof.hex())
                self.assertEqual(CHECK.BYTE.proof_result(root, path, value or b"", proof, value is not None), "match")
        self.refused(d)

    def test_canonical_proof_bytes_cannot_gain_trailing_or_substitute_bytes(self):
        for suffix in ("00", "01" * 32):
            d = copy.deepcopy(self.corpus)
            row = next(r for r in d["cases"][0]["rounds"][0]["reads"] if r["proof"] is not None)
            row["proof"] += suffix
            self.refused(d)

    def test_error_root_value_and_proof_nulls_are_bound(self):
        for field in ("error", "value", "proof", "root"):
            d = copy.deepcopy(self.corpus)
            row = next(r for r in d["cases"][1]["rounds"][0]["reads"] if r["error"] is not None)
            row[field] = None if field in ("error", "root") else "00"
            self.refused(d)

    def test_clean_reopen_and_compaction_cannot_change_logical_state(self):
        for case in self.corpus["cases"]:
            self.assertEqual(case["rounds"][0]["reads"], case["rounds"][2]["reads"])
            self.assertEqual(case["rounds"][0]["storage"], case["rounds"][2]["storage"])
        self.change(lambda d: d["cases"][1]["rounds"][2]["frontier"].update(height=15))

    def test_case_policy_round_order_inventory_and_fields_are_closed(self):
        for f in (lambda d: d["cases"].reverse(), lambda d: d["cases"].pop(),
                  lambda d: d["cases"][0]["rounds"].reverse(),
                  lambda d: d["cases"][1]["input"].update(retain=16),
                  lambda d: d["cases"][0].update(extra=True)):
            self.change(f)

    def test_heights_counts_identifiers_and_boolean_types_do_not_coerce(self):
        for value in (True, 16.0, "16", -1, None):
            self.change(lambda d: d["cases"][0]["input"].update(versions=value))
        self.change(lambda d: d["scope"].update(unsigned=1))

    def test_source_profile_provenance_activation_and_resource_gates_remain_open(self):
        for field in ("runtime_state_proof_acceptance", "profile_agreed", "network_activation_authenticated",
                      "authenticated_retained_version_provenance_qualified", "realistic_retention_resource_budgets_qualified",
                      "power_loss_qualified", "chain_Start_executed", "node_snapshot_import_executed", "historical_archive_replay_qualified"):
            self.change(lambda d: d["scope"].update({field: True}))
        self.change(lambda d: d["source"].update(revision="00" * 20))

    def test_duplicate_fields_trailing_json_and_byte_bounds_are_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / "fixture.json"
            for raw in (b'{"cases":[],"cases":[]}', b'{}{}', b'{} trailing', b' ' * (CHECK.BYTE.MAX_FILE_BYTES + 1)):
                file.write_bytes(raw)
                with self.assertRaises((ValueError, KeyError, TypeError)):
                    CHECK.BYTE.read_corpus(file)
        self.change(lambda d: d["cases"][0]["rounds"][0]["reads"][1].update(proof="00" * (CHECK.BYTE.MAX_PROOF_BYTES + 1)))

    def test_variable_measurements_are_separate_from_deterministic_conformance(self):
        self.change(lambda d: d.update(measurements=[]))
        samples = self.samples()
        samples["samples"][1][0]["peak_rss_bytes"] += 1
        report = CHECK.check_resource_samples(samples, self.digest)
        self.assertFalse(report["sample_execution_independently_reproduced"])
        samples["measurement_runs_expected_to_vary"] = False
        self.sample_refused(samples)

    def test_measurement_units_inventory_source_and_command_binding_are_closed(self):
        for field, value in (("peak_rss_bytes", True), ("update_elapsed_ns", 1.0), ("platform", "linux/amd64")):
            d = self.samples()
            d["samples"][0][0][field] = value
            self.sample_refused(d)
        d = self.samples()
        d["corpus_sha256"] = "00" * 32
        self.sample_refused(d)
        d = self.samples()
        d["commands"][1]["actual_exit"] = 1
        self.sample_refused(d)
        d = self.samples()
        d["samples"].pop()
        self.sample_refused(d)

    def test_physical_file_growth_is_allowed_without_resource_budget_acceptance(self):
        d = self.samples()
        d["samples"][0][0]["closed_after_compaction"].update(file_bytes=16)
        report = CHECK.check_resource_samples(d, self.digest)
        self.assertFalse(report["resource_budget_acceptance"])
        d["production_resource_budgets_qualified"] = True
        self.sample_refused(d)
        d = self.samples()
        d["samples"][0][0]["closed_before_compaction"].update(largest_file_bytes=20)
        self.sample_refused(d)


if __name__ == "__main__":
    unittest.main(verbosity=2)
