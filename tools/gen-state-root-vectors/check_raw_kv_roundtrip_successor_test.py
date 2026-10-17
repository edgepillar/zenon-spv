#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Synthetic checker controls. These fixtures are not node observations."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("raw_kv_observation_controls", HERE / "check_raw_kv_roundtrip_successor.py")
C = importlib.util.module_from_spec(spec)
spec.loader.exec_module(C)


def fixture(expected, policy):
    source = {key: expected["source"][key] for key in
              ("node_revision", "original_node_tree", "selected_runtime_tree",
               "experimental_disk_format", "source_blobs")}
    source.update(Go_version="go1.25.14", GOOS="darwin", GOARCH="arm64")
    snapshots, objects = [], {}
    for stage in expected["policies"][policy]["flow"]:
        store = expected["policies"][policy]["stores"][stage["store"]]
        dump = C.M.C.encode_dump(C.M.store_records(expected, policy, stage["store"]))
        digest = hashlib.sha256(dump).hexdigest()
        objects[digest] = dump.hex()
        proofs = []
        for query in store["root_queries"]:
            if query["error"] == "":
                for proof in expected["witnesses"][str(query["identifier"]["height"])]["proofs"]:
                    proofs.append(dict(proof, identifier=copy.deepcopy(query["identifier"]), error=""))
        snapshots.append({key: copy.deepcopy(store[key]) for key in
                          ("frontier", "record_manifest", "dump_selection", "root_queries")})
        snapshots[-1].update(name=stage["stage"], proofs=proofs)
    seed = expected["policies"][policy]["stores"]["64"]["dump_selection"]["sha256"]
    return {
        "format_version": 1, "kind": "successor-raw-kv-roundtrip-observation", "policy": policy,
        "selection_sha256": expected["selection_sha256"], "source": source, "scope": dict(C.SCOPE),
        "snapshots": snapshots, "dump_objects": objects,
        "replay": {"input_sha256_before": seed, "input_sha256_after": seed,
                   "load_error": "", "replay_error": "", "write_error": "",
                   "raw_batch_write_calls": 1, "write_sync": True,
                   "crash_or_hardware_power_loss_qualified": False},
    }


class RawKVObservationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.expected = C.M.derive()
        cls.fixtures = {policy: fixture(cls.expected, policy) for policy in C.M.POLICIES}

    def check(self, observed, policy="archive", expected=None, **kwargs):
        return C.check_observation(C.M.encoded(observed), self.expected if expected is None else expected, policy, **kwargs)

    def refuse(self, mutate, policy="archive"):
        observed = copy.deepcopy(self.fixtures[policy])
        mutate(observed)
        with self.assertRaises((ValueError, KeyError, TypeError, IndexError, AssertionError)):
            self.check(observed, policy)

    def test_two_complete_synthetic_flows_have_all_expected_positions(self):
        counts = []
        for policy, observed in self.fixtures.items():
            report = self.check(observed, policy, platform=("darwin", "arm64"), go_version="go1.25.14")
            self.assertEqual(len(report["stages"]), 5)
            self.assertEqual(report["unique_dump_preimages"], 4)
            self.assertEqual(sum(row["root_and_probe_error_queries"] for row in report["stages"]), 650)
            self.assertEqual(report["scope"]["consumer_result"], "REFUSED")
            self.assertFalse(report["scope"]["authenticated_snapshot_import"])
            counts.append(report["canonical_proof_positions"])
        self.assertEqual(sum(counts), 3015)

    def test_complete_record_boundary_truncation_is_not_a_selected_dump(self):
        self.refuse(lambda value: value["dump_objects"].__setitem__(
            value["snapshots"][0]["dump_selection"]["sha256"],
            C.M.C.encode_dump(C.M.store_records(self.expected, "archive", "64")[:-1]).hex()))

    def test_same_length_changed_record_bytes_are_refused(self):
        def mutate(value):
            digest = value["snapshots"][0]["dump_selection"]["sha256"]
            raw = bytearray.fromhex(value["dump_objects"][digest])
            raw[-1] ^= 1
            value["dump_objects"][digest] = raw.hex()
        self.refuse(mutate)

    def test_manifest_alone_cannot_substitute_for_actual_dump(self):
        self.refuse(lambda value: value["dump_objects"].clear())

    def test_extra_dump_or_missing_stage_is_refused(self):
        self.refuse(lambda value: value["dump_objects"].__setitem__("0" * 64, "01"))
        self.refuse(lambda value: value["snapshots"].pop())
        self.refuse(lambda value: value["snapshots"].__setitem__(1, copy.deepcopy(value["snapshots"][0])))

    def test_retained_hash_mismatch_cannot_be_relabelled_as_pruned(self):
        def mutate(value):
            row = next(row for row in value["snapshots"][0]["root_queries"]
                       if row["error"] == "version-hash-mismatch")
            row["error"] = row["proof_error"] = "no-version"
        self.refuse(mutate)

    def test_probe_error_is_checked_separately_from_root_error(self):
        self.refuse(lambda value: value["snapshots"][0]["root_queries"][65].__setitem__("proof_error", ""))

    def test_wrong_proof_value_presence_and_order_are_refused(self):
        for field, replacement in (("value", "ff" * 32), ("present", False), ("proof", "00")):
            self.refuse(lambda value, field=field, replacement=replacement:
                        value["snapshots"][0]["proofs"][0].__setitem__(field, replacement))
        self.refuse(lambda value: value["snapshots"][0]["proofs"].reverse())

    def test_raw_dump_and_record_manifest_digests_are_not_interchangeable(self):
        self.refuse(lambda value: value["snapshots"][0]["record_manifest"].__setitem__(
            "sha256", value["snapshots"][0]["dump_selection"]["sha256"]))

    def test_replay_mutation_partial_load_and_unsynced_write_are_refused(self):
        for field, replacement in (("input_sha256_after", "0" * 64), ("load_error", "truncated"),
                                   ("replay_error", "partial"), ("write_sync", False),
                                   ("raw_batch_write_calls", 2)):
            self.refuse(lambda value, field=field, replacement=replacement:
                        value["replay"].__setitem__(field, replacement), policy="retain-5")

    def test_source_platform_and_compiler_drift_are_refused(self):
        self.refuse(lambda value: value["source"].__setitem__("node_revision", "0" * 40))
        self.refuse(lambda value: value["source"].__setitem__("experimental_disk_format", 2))
        for args in ({"platform": ("linux", "arm64")}, {"go_version": "go1.25.13"}):
            with self.assertRaises(ValueError):
                self.check(self.fixtures["archive"], **args)

    def test_acceptance_flags_type_aliases_and_unbound_fields_are_refused(self):
        for field in ("authenticated_snapshot_import", "accepted_header_binding", "production_state_value_accepted"):
            self.refuse(lambda value, field=field: value["scope"].__setitem__(field, True))
        self.refuse(lambda value: value.__setitem__("format_version", True))
        self.refuse(lambda value: value.__setitem__("unknown", False))
        self.refuse(lambda value: value["snapshots"][0].__setitem__("unknown", False))

    def test_duplicate_keys_trailing_data_and_mutable_input_are_refused(self):
        for raw in (b'{"format_version":1,"format_version":1}', b"{} {}",
                    bytearray(b"{}"), b"", b"x" * (C.MAX_OBSERVATION_BYTES + 1)):
            with self.assertRaises((ValueError, KeyError, TypeError)):
                C.check_observation(raw, self.expected, "archive")

    def test_backend_correlated_expectations_cannot_replace_the_model(self):
        changed = copy.deepcopy(self.expected)
        changed["policies"]["archive"]["stores"]["64"]["record_manifest"]["sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            self.check(self.fixtures["archive"], expected=changed)
        self.assertFalse(self.expected["scope"]["node_backend_executed"])


if __name__ == "__main__":
    unittest.main()
