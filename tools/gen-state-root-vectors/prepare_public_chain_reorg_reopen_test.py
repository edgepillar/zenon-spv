#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
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
spec = importlib.util.spec_from_file_location("fixture", HERE / "prepare_public_chain_reorg_reopen.py")
F = importlib.util.module_from_spec(spec)
spec.loader.exec_module(F)
SEED = F.P.read_regular(HERE / "testdata" / "successor-public-chain-lifecycle.json", 64 << 10)
DATA = F.generate(SEED)
BASE = json.loads(SEED)["selection"]["witness"]
KEY, VALUE, PROOF = bytes.fromhex(F.KEY), bytes.fromhex(F.BASE_VALUE), bytes.fromhex(BASE["proof"])

class IndependentFixtureControls(unittest.TestCase):
    def test_generation_is_deterministic(self):
        self.assertEqual(F.generate(SEED), F.generate(SEED))
    def test_preexisting_empty_v1_header(self):
        self.assertEqual(F.header(F.GENESIS["hash"], 2, F.TIMESTAMP+10, b"")["hash"], DATA["preexisting_empty_v1_control"])
    def test_seed_byte_change_refused(self):
        with self.assertRaisesRegex(ValueError, "seed file pin"): F.generate(SEED+b" ")
    def test_canonical_seed_proof_roundtrip(self):
        siblings=F.siblings_from_seed(KEY,VALUE,PROOF,F.BASE_ROOT)
        self.assertEqual(F.proof_for(F.sha3(KEY),VALUE,siblings), PROOF)
    def test_wrong_leaf_refused(self):
        proof=bytearray(PROOF);proof[33]^=1
        with self.assertRaisesRegex(ValueError,"seed path/leaf"): F.siblings_from_seed(KEY,VALUE,bytes(proof),F.BASE_ROOT)
    def test_wrong_key_refused(self):
        key=bytearray(KEY);key[1]^=1
        with self.assertRaisesRegex(ValueError,"seed path/leaf"): F.siblings_from_seed(bytes(key),VALUE,PROOF,F.BASE_ROOT)
    def test_trailing_proof_bytes_refused(self):
        with self.assertRaisesRegex(ValueError,"exact proof length"): F.siblings_from_seed(KEY,VALUE,PROOF+b"\0",F.BASE_ROOT)
    def test_bitmap_count_refused(self):
        proof=bytearray(PROOF);proof[98]^=1
        with self.assertRaisesRegex(ValueError,"bitmap count"): F.siblings_from_seed(KEY,VALUE,bytes(proof),F.BASE_ROOT)
    def test_explicit_zero_sibling_refused(self):
        proof=bytearray(PROOF);proof[99:131]=bytes(32)
        with self.assertRaisesRegex(ValueError,"canonical nonzero"): F.siblings_from_seed(KEY,VALUE,bytes(proof),F.BASE_ROOT)
    def test_wrong_expected_seed_root_refused(self):
        with self.assertRaisesRegex(ValueError,"preexisting seed root"): F.siblings_from_seed(KEY,VALUE,PROOF,"00"*32)
    def test_absence_and_stored_zero_are_distinct(self):
        zero,absent=DATA["states"]["A2"],DATA["states"]["B3"]
        self.assertTrue(zero["present"]);self.assertFalse(absent["present"])
        self.assertEqual(zero["proof"][:2],"01");self.assertEqual(absent["proof"][:2],"00")
        self.assertNotEqual(zero["root"],absent["root"])
        self.assertEqual(len(bytes.fromhex(zero["proof"]))-len(bytes.fromhex(absent["proof"])),36)
    def test_all_selected_roots_differ(self):
        self.assertEqual(len({x["root"] for x in DATA["states"].values()}),5)
    def test_patches_have_exact_batch_records(self):
        for name in ["A2","A3","B2"]:
            row=DATA["states"][name];raw=bytes.fromhex(row["patch_dump"])
            self.assertEqual(raw,b"\x01\x20"+KEY+b"\x20"+bytes.fromhex(row["value"]))
            self.assertEqual(len(raw),67)
        raw=bytes.fromhex(DATA["states"]["B3"]["patch_dump"])
        self.assertEqual(raw,b"\x00\x20"+KEY);self.assertEqual(len(raw),34)
    def test_changes_hash_covers_exact_patch(self):
        for name in ["A2","A3","B2","B3"]:
            row=DATA["states"][name];raw=bytes.fromhex(row["patch_dump"])
            self.assertEqual(row["header"]["changes_hash"],hashlib.sha3_256(raw).hexdigest())
            self.assertEqual(row["patch_sha256"],hashlib.sha256(raw).hexdigest())
    def test_header_hash_covers_preimage_and_predecessor(self):
        for name,parent in [("A2","A1"),("A3","A2"),("B2","A1"),("B3","B2")]:
            h=DATA["states"][name]["header"];raw=bytes.fromhex(h["preimage_hex"])
            self.assertEqual(len(raw),160);self.assertEqual(raw[16:48].hex(),DATA["states"][parent]["identifier"]["hash"])
            self.assertEqual(hashlib.sha3_256(raw).hexdigest(),h["hash"])
    def test_same_height_forks_are_separate(self):
        for a,b in [("A2","B2"),("A3","B3")]:
            self.assertEqual(DATA["states"][a]["identifier"]["height"],DATA["states"][b]["identifier"]["height"])
            self.assertNotEqual(DATA["states"][a]["identifier"]["hash"],DATA["states"][b]["identifier"]["hash"])
    def test_header_patch_change_changes_identity(self):
        row=DATA["states"]["A2"];h=row["header"];raw=bytearray.fromhex(row["patch_dump"]);raw[-1]^=1
        self.assertNotEqual(F.header(h["previous_hash"],h["height"],h["timestamp_unix"],bytes(raw))["hash"],h["hash"])
    def test_unsupported_width_and_noncanonical_hex_refused(self):
        with self.assertRaises(ValueError):F.patch_dump(KEY,b"\0")
        with self.assertRaises(ValueError):F.hx("AA")
    def test_fixture_authority_is_refused(self):
        self.assertEqual(DATA["consumer_result"],"REFUSED")
        self.assertFalse(DATA["production_state_value_accepted"])
        self.assertFalse(DATA["full_consensus_validation_executed"])
        self.assertFalse(DATA["network_started"])


class ReorgSourcePreparationControls(unittest.TestCase):
    def test_runtime_and_module_files_are_unchanged(self):
        manifest, modified, pins = F.H.selection()
        build = F.build_pins()
        self.assertEqual(len(manifest["files"]), 467)
        self.assertEqual(F.P.UTIL.reconstruct_tree(pins), F.H.MODIFIED_TREE)
        self.assertEqual(set(build)-set(pins), {F.PROBE_TARGET})
        for name in pins:
            self.assertEqual(build[name], pins[name])
        for name in ("go.mod","go.sum"):
            self.assertEqual(build[name], manifest["files"][name])

    def test_single_ordinary_entrypoint_tree_is_pinned(self):
        pins=F.build_pins()
        self.assertEqual(len(pins),468)
        self.assertEqual(F.P.UTIL.reconstruct_tree(pins),F.BUILD_TREE)
        raw=F.extra_source()
        self.assertEqual(F.P.sha(raw),F.PROBE_SHA256)
        self.assertEqual(pins[F.PROBE_TARGET]["bytes"],16838)

    def test_probe_byte_substitution_refuses(self):
        original=F.P.read_regular
        def changed(path,limit):
            raw=original(path,limit)
            return raw+b"\n" if Path(path).name==F.PROBE else raw
        with mock.patch.object(F.P,"read_regular",side_effect=changed):
            with self.assertRaises(ValueError):F.build_pins()

    def test_plan_selects_two_processes_and_one_case_root(self):
        plan=F.plan(Path("/selected-owned-reorg"),"selected-go")
        self.assertEqual([x[x.index("--case")+1] for x in plan["run_argv_templates"]],list(F.MODES))
        self.assertEqual({x[x.index("--root")+1] for x in plan["run_argv_templates"]},{"OWNED_CASE_ROOT"})
        self.assertIs(plan["first_case_requires_empty_root"],True)
        self.assertIs(plan["second_case_reopens_same_closed_stores"],True)
        self.assertEqual(plan["build_argv"][0],"selected-go")
        for value in ("-mod=readonly","-trimpath","-buildvcs=false"):
            self.assertIn(value,plan["build_argv"])
        self.assertEqual(plan["expected_queries"],31)

    def test_plan_preserves_execution_and_trust_boundaries(self):
        plan=F.plan(Path("/selected-owned-reorg"),"go")
        self.assertEqual(plan["consumer_result"],"REFUSED")
        for key in ("reference_backend_executed","new_dependency_transports_permitted",
                    "cache_account_block_extraction_selected","network_or_full_node_selected",
                    "consensus_validation_selected","concurrent_lifecycle_or_interruption_qualified",
                    "representative_resource_budget_qualified","accepted_header_binding","runtime_state_value_acceptance"):
            self.assertIs(plan[key],False)
        self.assertEqual(plan["minimum_free_floor_bytes"],10<<30)
        self.assertEqual(plan["expected_allocation_bytes"],2<<30)
        self.assertEqual(plan["suggested_task_quota_bytes"],3<<30)

    def test_invalid_compiler_refuses(self):
        for go in (None,"","go\0other"):
            with self.assertRaises(ValueError):F.plan(Path("/selected-owned-reorg"),go)

    def test_existing_destination_refuses_before_source_snapshot(self):
        with mock.patch.object(F.P,"private_destination",side_effect=ValueError("existing workspace")), \
                mock.patch.object(F.P.UTIL,"snapshot_source") as snapshot:
            with self.assertRaises(ValueError):
                F.prepare(Path("/selected-node-source"),Path("/selected-existing"),"go")
        snapshot.assert_not_called()

    def test_overlapping_source_and_destination_refuse_before_snapshot(self):
        pairs=[(Path("/selected-node"),Path("/selected-node/new-workspace")),
               (Path("/selected-workspace/node"),Path("/selected-workspace"))]
        for original,workspace in pairs:
            with mock.patch.object(F.P,"private_destination",return_value=workspace), \
                    mock.patch.object(F.P.UTIL,"snapshot_source") as snapshot:
                with self.assertRaisesRegex(ValueError,"disjoint source and workspace"):
                    F.prepare(original,workspace,"go")
            snapshot.assert_not_called()

    def test_fixture_output_preserves_presealed_native_input(self):
        raw=F.selected_fixture()
        self.assertEqual(len(raw),13485)
        self.assertEqual(hashlib.sha256(raw).hexdigest(),F.FIXTURE_SHA256)
        self.assertEqual(json.loads(raw),DATA)


if __name__ == "__main__":
    unittest.main(verbosity=2)
