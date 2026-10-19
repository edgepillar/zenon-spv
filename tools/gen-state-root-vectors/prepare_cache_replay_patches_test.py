#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""In-memory source and scope controls; no compiler or backend is started."""
import copy
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest import mock

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("patch_preparation_controls", HERE / "prepare_cache_replay_patches.py")
H = importlib.util.module_from_spec(spec)
spec.loader.exec_module(H)


class CacheReplayPatchPreparationTests(unittest.TestCase):
    def test_complete_runtime_identity_and_unchanged_dependency_inputs(self):
        manifest, modified, pins = H.selection()
        self.assertEqual(len(manifest["files"]), 467)
        self.assertEqual(len(pins), 467)
        self.assertEqual(H.P.UTIL.reconstruct_tree(pins), H.MODIFIED_TREE)
        self.assertEqual(set(modified), {"chain/chain.go", "chain/state_tree.go", "common/trie/nodestore.go",
                                         "chain/cache.go", "chain/cache/storage/db.go"})
        for name in ("go.mod", "go.sum"):
            self.assertEqual(pins[name], manifest["files"][name])

    def test_scope_and_full_file_substitutions_are_refused(self):
        original = H.P.document(H.PATCH, H.PATCH_SHA256)
        for mutate in (
            lambda d: d.update(runtime_parent_tree="0" * 40),
            lambda d: d.update(runtime_after_tree="0" * 40),
            lambda d: d.update(disk_format_changed=True),
            lambda d: d.update(SMT_profile_changed=True),
            lambda d: d.update(legacy_cache_manager_interface_changed=True),
            lambda d: d.update(required_patch_availability_preflight=False),
            lambda d: d.update(empty_content_nil_patch_allowed=False),
            lambda d: d.update(apply_pass_patch_rechecked=False),
            lambda d: d.update(whole_window_atomicity_claimed=True),
            lambda d: d.update(accepted_header_or_consumer_acceptance_changed=True),
            lambda d: d.update(upstream_mutated=True),
            lambda d: d["replacements"].pop(),
            lambda d: d["replacements"][0].update(before="substitution"),
            lambda d: d["replacements"][0].update(after=d["replacements"][0]["after"] + "\n"),
            lambda d: d["replacements"][0].update(after_git_blob="0" * 40),
        ):
            changed = copy.deepcopy(original)
            mutate(changed)
            real = H.P.document
            def document(name, digest):
                return changed if name == H.PATCH else real(name, digest)
            with mock.patch.object(H.P, "document", side_effect=document):
                with self.assertRaises((ValueError, KeyError, TypeError)):
                    H.selection()

    def test_complete_parent_and_candidate_build_sets_are_distinct(self):
        extras = H.extra_sources()
        self.assertEqual(len(extras), 6)
        self.assertEqual(extras[H.ENTRYPOINT], H.probe_bytes())
        self.assertNotIn(H.H.ENTRYPOINT, extras)
        self.assertEqual(len(H.build_pins()), 473)
        self.assertEqual(H.P.UTIL.reconstruct_tree(H.build_pins()), H.BUILD_TREE)
        self.assertEqual(H.parent_build_tree(), H.PARENT_BUILD_TREE)
        self.assertNotEqual(H.BUILD_TREE, H.PARENT_BUILD_TREE)
        self.assertNotIn(b".Start()", H.probe_bytes())

    def test_all_earlier_controls_are_retained_with_one_internal_argument(self):
        earlier = H.H.extra_sources()
        current = H.extra_sources()
        for name, raw in earlier.items():
            if name not in (H.H.ENTRYPOINT, H.H.CONTROL_TARGET):
                self.assertEqual(current[name], raw)
        before = earlier[H.H.CONTROL_TARGET].decode()
        after = current[H.H.CONTROL_TARGET].decode()
        old = "cache.validateReplayWindow(momentums, headers[4].Identifier(), headers[4].Identifier())"
        new = "cache.validateReplayWindow(nil, momentums, headers[4].Identifier(), headers[4].Identifier())"
        self.assertEqual(before.count(old), 1)
        self.assertEqual(after.count(new), 1)
        self.assertEqual(after.replace(new, old), before)
        self.assertEqual(set(H.NATIVE_ROOTS) - set(H.H.NATIVE_ROOTS), {"TestCandidateChainCacheReplayPatches"})

    def test_probe_and_both_control_sources_refuse_byte_substitution(self):
        original = H.P.read_regular
        for selected in (H.PROBE, H.CONTROL, H.COMPAT_CONTROL):
            def read(path, limit):
                raw = original(path, limit)
                return raw + b"\n" if Path(path).name == selected else raw
            with mock.patch.object(H.P, "read_regular", side_effect=read):
                with self.assertRaises(ValueError):
                    H.extra_sources()

    def test_recorded_parent_probe_is_preserved_by_one_diagnostic_addition(self):
        parent = H.parent_probe_bytes()
        current = H.probe_bytes()
        self.assertEqual(len(parent), H.PARENT_PROBE_BYTES)
        self.assertEqual(H.P.sha(parent), H.PARENT_PROBE_SHA256)
        self.assertNotEqual(H.PROBE_SHA256, H.PARENT_PROBE_SHA256)
        category = (b'\tcase strings.HasPrefix(err.Error(), "cache replay patch for momentum ") && strings.HasSuffix(err.Error(), " is missing"):\n'
                    b'\t\treturn "missing-replay-patch"\n')
        self.assertEqual(current.count(category), 1)
        self.assertEqual(current.replace(category, b""), parent)

    def test_retained_positive_source_has_its_own_complete_build_identity(self):
        self.assertEqual(H.retained_positive_build_tree(), H.RETAINED_POSITIVE_BUILD_TREE)
        self.assertNotEqual(H.RETAINED_POSITIVE_BUILD_TREE, H.PARENT_BUILD_TREE)
        raw = H.source_bytes(H.RETAINED_PROBE, H.RETAINED_PROBE_BYTES, H.RETAINED_PROBE_SHA256)
        self.assertNotEqual(H.P.sha(raw), H.PARENT_PROBE_SHA256)
        self.assertNotIn(b".Start()", raw)

    def test_finite_plan_keeps_execution_and_acceptance_separate(self):
        plan = H.plan(Path("/selected-owned-replay-patches"), "/selected/go")
        self.assertEqual(plan["cases"], list(H.CASES))
        self.assertEqual(len(plan["native_control_roots"]), 15)
        self.assertEqual(plan["expected_native_unit_pass_results"], 58)
        self.assertEqual(plan["build_argv"][:7], ["/selected/go", "build", "-mod=readonly", "-trimpath",
                                                "-buildvcs=false", "-tags", "candidate_public_cache_replay_patch"])
        self.assertEqual(plan["registered_capture_files"], list(H.CAPTURE_FILES))
        self.assertEqual(plan["metadata_capture_limit_bytes"], 4 << 20)
        self.assertEqual(plan["mismatch_capture_limit_bytes"], 16 << 20)
        self.assertEqual(plan["recorded_parent_probe"], {"bytes": H.PARENT_PROBE_BYTES, "sha256": H.PARENT_PROBE_SHA256})
        self.assertEqual(plan["retained_positive_case"], H.CASES[0])
        self.assertEqual(plan["retained_positive_build_tree"], H.RETAINED_POSITIVE_BUILD_TREE)
        self.assertEqual(plan["minimum_free_floor_bytes"], 10 << 30)
        for name in ("reference_backend_executed", "native_control_execution_selected", "accepted_header_binding",
                     "runtime_state_value_acceptance", "whole_window_atomicity_claimed", "legacy_cache_manager_interface_changed"):
            self.assertIs(plan[name], False)
        for name in ("required_patch_availability_preflight", "empty_content_nil_patch_allowed", "apply_pass_patch_rechecked"):
            self.assertIs(plan[name], True)
        self.assertEqual(plan["consumer_result"], "REFUSED")
        self.assertNotIn("-race", plan["build_argv"])
        self.assertNotIn("-overlay", plan["build_argv"])

    def test_invalid_compiler_is_refused(self):
        for value in (None, "", "go\x00other"):
            with self.assertRaises(ValueError):
                H.plan(Path("/selected-owned-replay-patches"), value)

    def test_preparation_does_not_overwrite_an_existing_path(self):
        with mock.patch.object(H.P, "private_destination", side_effect=ValueError("existing path")), \
             mock.patch.object(H.P.UTIL, "snapshot_source") as snapshot:
            with self.assertRaises(ValueError):
                H.prepare(Path("/selected-source"), Path("/selected-existing-workspace"), "go")
        snapshot.assert_not_called()


if __name__ == "__main__":
    unittest.main()
