#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Finite source-identity and table controls; no node or resource measurement."""
import copy
import hashlib
import importlib.util
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


C = module("successor_retention_controls", "check_default_retention_successor.py")
F = module("successor_retention_finite_fixture", "check_default_retention_test.py")


class SuccessorRetentionObservationTests(unittest.TestCase):
    def fixture(self, policy="pruned"):
        f = F.Fixture(policy)
        f.observation.update(C.SOURCE_FIELDS)
        f.observation["kind"] = "successor-source-default-retention-component-observation"
        raw = C.M.encoded(f.tables)
        f.observation["logical_tables_sha256"] = hashlib.sha256(raw).hexdigest()
        f.observation["logical_tables_bytes"] = len(raw)
        return f, raw

    def test_two_finite_policies_reuse_byte_checks_with_separate_identity(self):
        for policy in ("pruned", "archive"):
            f, raw = self.fixture(policy)
            result = C.check_tables(raw, f.observation, f.expected)
            self.assertEqual(result["node_revision"], C.M.P.REVISION)
            self.assertEqual(result["runtime_tree"], C.M.T.MODIFIED_TREE)
            self.assertEqual(result["consumer_result"], "REFUSED")
            self.assertFalse(result["production_resources_qualified"])

    def test_historical_or_unbound_source_observation_is_refused(self):
        for name, value in (*C.SOURCE_FIELDS.items(), ("kind", "successor-source-default-retention-component-observation")):
            f, raw = self.fixture()
            f.observation[name] = "33d7d1ee1b6a915c40aea196e2a10f1e893d171f" if name != "kind" else "source-default-retention-component-observation"
            with self.subTest(field=name), self.assertRaises(ValueError):
                C.check_tables(raw, f.observation, f.expected)
        f, raw = self.fixture()
        del f.observation["runtime_tree"]
        with self.assertRaises(ValueError):
            C.check_tables(raw, f.observation, f.expected)

    def test_changed_root_and_same_height_wrong_hash_are_refused_after_repin(self):
        for field in ("root", "hash"):
            f, _ = self.fixture()
            f.tables["snapshot"]["retained_roots"][-1][field] = "00" * 32
            raw = C.M.encoded(f.tables)
            f.observation.update(logical_tables_sha256=hashlib.sha256(raw).hexdigest(), logical_tables_bytes=len(raw))
            with self.subTest(field=field), self.assertRaises(ValueError):
                C.check_tables(raw, f.observation, f.expected)

    def test_unknown_scope_escalation_and_override_are_refused(self):
        for key, value in (("production_resources_qualified", True), ("profile_agreed", True),
                           ("accepted_header_root_binding", True), ("retention_override", 9),
                           ("bulk_batch_override", 1), ("PRIVATE_FIELD", "PRIVATE")):
            f, raw = self.fixture()
            f.observation[key] = value
            with self.subTest(field=key), self.assertRaises(ValueError):
                C.check_tables(raw, f.observation, f.expected)

    def test_bool_or_partial_source_input_is_refused_before_model_derivation(self):
        for files in ({}, {"PRIVATE": b"PRIVATE"}, False):
            with self.subTest(kind=type(files).__name__), self.assertRaises(ValueError):
                C.M.checked_source(files)


if __name__ == "__main__":
    unittest.main()
