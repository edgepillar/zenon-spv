#!/usr/bin/env python3
"""Small in-memory negative controls; no node, database or nonregular fixtures."""

import copy
import importlib.util
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location("selected_genesis_bytes", Path(__file__).with_name("check_selected_devnet_genesis.py"))
C = importlib.util.module_from_spec(spec)
spec.loader.exec_module(C)


class SelectedGenesisTests(unittest.TestCase):
    cohort = "original"
    corpus_sha256 = "e11aa64274d4af0b6fd7995cf55ea2a49fdd4ca1ba6f8747acdde84467773805"

    @classmethod
    def setUpClass(cls):
        cls.raw = C.read_regular(C.selected_recording(cls.cohort)[0], 16 << 10)
        cls.value = C.parse(cls.raw, 16 << 10)
        cls.config = C.read_regular(C.ROOT / C.CONFIG_PATH, 16 << 10)
        cls.harness = C.read_regular(C.ROOT / C.HARNESS_PATH, 8 << 10)

    def check(self, value=None, config=None, harness=None):
        return C.check_corpus(self.value if value is None else value,
                              self.config if config is None else config,
                              self.harness if harness is None else harness, cohort=self.cohort)

    def bad(self, mutate):
        value = copy.deepcopy(self.value)
        mutate(value)
        with self.assertRaises(ValueError):
            self.check(value)

    def test_recorded_H1_preimage_and_scope(self):
        report = self.check()
        self.assertEqual(report["genesis_hash"], C.GENESIS_HASH)
        self.assertEqual(report["preimage_bytes"], 160)
        self.assertFalse(report["genesis_VM_or_managers_executed_by_reader"])
        self.assertFalse(report["network_identity_authenticated"])
        self.assertFalse(report["state_value_accepted"])
        self.assertEqual(C.check(self.cohort)["corpus_sha256"], self.corpus_sha256)

    def test_source_config_and_harness_pins(self):
        for section in ("source", "genesis_config", "harness", "execution"):
            for key in self.value[section]:
                with self.subTest(section=section, key=key):
                    self.bad(lambda v: v[section].__setitem__(key, None))
        for config, harness in ((self.config + b" ", self.harness),
                                (self.config.replace(b"LOCAL DEV-NET", b"LOCAL BAD-NET"), self.harness),
                                (self.config, self.harness + b"\n")):
            with self.assertRaises(ValueError):
                self.check(config=config, harness=harness)

    def test_execution_types_and_no_authority_laundering(self):
        for section in ("execution", "scope"):
            for key, selected in self.value[section].items():
                if type(selected) is bool:
                    with self.subTest(section=section, key=key):
                        self.bad(lambda v: v[section].__setitem__(key, not selected))
                        self.bad(lambda v: v[section].__setitem__(key, int(selected)))
        for section, key, replacement in (("execution", "actual_exit", False),
                                           ("execution", "actual_exit", 0.0),
                                           ("scope", "real_manager_Init_Stop_reopen_cycles", 2.0)):
            self.bad(lambda v: v[section].__setitem__(key, replacement))

    def test_all_v1_preimage_fields_are_bound(self):
        for field in ("version", "chainIdentifier", "height", "timestamp"):
            with self.subTest(field=field):
                self.bad(lambda v: v["trace"]["header"].__setitem__(field, v["trace"]["header"][field] + 1))
        for field in C.HASH_FIELDS:
            with self.subTest(field=field):
                self.bad(lambda v: v["trace"]["header"].__setitem__(field, "11" * 32))

    def test_unsigned_legacy_shape_cannot_become_v3_evidence(self):
        for field, replacement in (("stateRoot", "12" * 32), ("publicKey", "AA=="),
                                   ("signature", "AA=="), ("nextFusionPrice", 1), ("nextWorkPrice", 1)):
            with self.subTest(field=field):
                self.bad(lambda v: v["trace"]["header"].__setitem__(field, replacement))
        for field in ("Chain_Start_called", "first_incoming_v3_executed"):
            self.bad(lambda v: v["trace"].__setitem__(field, True))

    def test_numeric_widths_types_and_hash_encoding(self):
        for field in C.UINT_FIELDS:
            for replacement in (True, -1, 2**64, 1.0, "1", None):
                with self.subTest(field=field, value=replacement):
                    self.bad(lambda v: v["trace"]["header"].__setitem__(field, replacement))
        for replacement in ("AB" * 32, "00" * 31, "00" * 33, "zz" * 32, None):
            self.bad(lambda v: v["trace"]["header"].__setitem__("contentHash", replacement))

    def test_sporks_are_only_recorded_source_inputs(self):
        for mutate in (lambda v: v["trace"]["sporks"].reverse(),
                       lambda v: v["trace"]["sporks"].pop(),
                       lambda v: v["trace"]["sporks"][1].update(enforcement_height=1),
                       lambda v: v["trace"]["sporks"][1].update(activated=1),
                       lambda v: v["trace"].update(scope="NETWORK_ACTIVATED")):
            self.bad(mutate)

    def test_both_recorded_manager_cycles_remain_exact(self):
        for mutate in (lambda v: v["trace"]["cycles"].pop(),
                       lambda v: v["trace"]["cycles"][0].update(hash="11" * 32),
                       lambda v: v["trace"]["cycles"][1].update(height=2),
                       lambda v: v["trace"]["cycles"][1].update(cycle=True)):
            self.bad(mutate)

    def test_duplicate_unknown_missing_and_trailing_JSON_refuse(self):
        for raw in (b'{"x":1,"x":2}', b'{"nested":{"x":1,"x":2}}', b'{"x":NaN}',
                    b'{"x":Infinity}', self.raw + b"{}", b"\xff", b"" ):
            with self.assertRaises((ValueError, UnicodeError)):
                C.parse(raw, 16 << 10)
        with self.assertRaises(ValueError):
            C.parse(self.raw, len(self.raw) - 1)
        for mutate in (lambda v: v.update(unknown=True), lambda v: v.pop("scope"),
                       lambda v: v["trace"]["header"].pop("stateRoot"),
                       lambda v: v["trace"]["header"].update(extra=1)):
            self.bad(mutate)

    def test_cli_records_source_revision_without_executing_node(self):
        with patch.object(sys, "stdout", new_callable=io.StringIO) as output:
            self.assertEqual(C.main(["--source-revision", "a" * 40, "--cohort", self.cohort]), 0)
        report = json.loads(output.getvalue())
        self.assertEqual(report["source_revision"], "a" * 40)
        self.assertFalse(report["genesis_VM_or_managers_executed_by_reader"])

    def test_cli_failures_do_not_echo_arguments_or_private_errors(self):
        for argv in (["PRIVATE_INPUT"], ["--source-revision", "PRIVATE_INPUT"], ["--other", "a" * 40]):
            with patch.object(sys, "stderr", new_callable=io.StringIO) as error:
                self.assertEqual(C.main(argv), 64)
                self.assertNotIn("PRIVATE_INPUT", error.getvalue())
        with patch.object(C, "check", side_effect=OSError("PRIVATE_PATH")), \
                patch.object(sys, "stderr", new_callable=io.StringIO) as error, \
                patch.object(sys, "stdout", new_callable=io.StringIO) as output:
            self.assertEqual(C.main([]), 1)
            self.assertEqual(output.getvalue(), "")
            self.assertNotIn("PRIVATE_PATH", error.getvalue())


class ReferenceGasGenesisTests(SelectedGenesisTests):
    cohort = "reference-gas"
    corpus_sha256 = "8fe43fb1e46bc80957c44ad09deabba0c09380a2e015aa63c9e66602786e7d13"

    def test_identical_H1_cannot_transfer_another_sources_execution(self):
        original = C.parse(C.read_regular(C.CORPUS, 16 << 10), 16 << 10)
        self.assertEqual(original["trace"], self.value["trace"])
        with self.assertRaises(ValueError):
            C.check_corpus(original, self.config, self.harness, cohort=self.cohort)
        with self.assertRaises(ValueError):
            C.check_corpus(self.value, self.config, self.harness)
        for section in ("source", "execution"):
            self.bad(lambda v: v.__setitem__(section, copy.deepcopy(original[section])))

    def test_reconciled_native_pass_does_not_relabel_controller_failure(self):
        self.assertEqual(self.value["execution"]["actual_exit"], 0)
        self.assertEqual(self.value["execution"]["capture_controller_outcome"], "FAILURE")
        self.bad(lambda v: v["execution"].update(capture_controller_outcome="SUCCESS"))
        self.bad(lambda v: v["execution"].update(native_result_reconciled_without_rerun=False))

    def test_explicit_cohort_and_default_output_remain_distinct(self):
        for argv in ([], ["--cohort", "original"], ["--cohort", self.cohort],
                     ["--cohort", self.cohort, "--source-revision", "a" * 40]):
            with patch.object(sys, "stdout", new_callable=io.StringIO) as output:
                self.assertEqual(C.main(argv), 0)
            report = json.loads(output.getvalue())
            if self.cohort in argv:
                self.assertEqual(report["node_revision"], C.REFERENCE_GAS_SOURCE["revision"])
                self.assertEqual(report["format"], "zenon-reference-gas-devnet-genesis-byte-check/v1")
            else:
                self.assertNotIn("node_revision", report)
                self.assertEqual(report["format"], "zenon-selected-devnet-genesis-byte-check/v1")

    def test_unknown_or_repeated_selector_refuses_before_reading(self):
        for argv in (["--cohort", "PRIVATE_INPUT"], ["--cohort", self.cohort, "--cohort", self.cohort],
                     ["--source-revision", "a" * 40, "--source-revision", "a" * 40],
                     ["--cohort"], ["--cohort", self.cohort, "--other", "PRIVATE_INPUT"]):
            with patch.object(C, "check") as check, patch.object(sys, "stderr", new_callable=io.StringIO) as error:
                self.assertEqual(C.main(argv), 64)
                check.assert_not_called()
                self.assertNotIn("PRIVATE_INPUT", error.getvalue())
        with self.assertRaises(ValueError):
            C.selected_recording("PRIVATE_INPUT")


if __name__ == "__main__":
    unittest.main()
