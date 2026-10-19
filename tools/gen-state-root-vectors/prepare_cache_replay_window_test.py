#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Source, workspace and scope controls; no compiler/backend is executed."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("window_preparation_controls", HERE / "prepare_cache_replay_window.py")
H = importlib.util.module_from_spec(spec)
spec.loader.exec_module(H)


class CacheReplayWindowPreparationTests(unittest.TestCase):
    def test_complete_runtime_trees_and_unchanged_module_inputs(self):
        manifest, modified, pins = H.selection()
        self.assertEqual(len(manifest["files"]), 467)
        self.assertEqual(len(pins), 467)
        self.assertEqual(H.P.UTIL.reconstruct_tree(pins), H.MODIFIED_TREE)
        self.assertEqual(set(modified), {"chain/chain.go", "chain/state_tree.go", "common/trie/nodestore.go",
                                         "chain/cache.go", "chain/cache/storage/db.go"})
        _, _, parent = H.H.selection()
        self.assertEqual(H.P.UTIL.reconstruct_tree(parent), H.H.MODIFIED_TREE)
        for name in ("go.mod", "go.sum"):
            self.assertEqual(pins[name], manifest["files"][name])

    def test_full_file_and_scope_substitutions_refused(self):
        original = H.P.document(H.PATCH, H.PATCH_SHA256)
        for mutate in (
            lambda d: d.update(runtime_parent_tree="0" * 40),
            lambda d: d.update(disk_format_changed=True),
            lambda d: d.update(legacy_cache_manager_interface_changed=True),
            lambda d: d.update(replay_window_full_linkage_preflight_required=False),
            lambda d: d.update(missing_momentum_refused_before_write=False),
            lambda d: d.update(whole_window_atomicity_claimed=True),
            lambda d: d.update(accepted_header_or_consumer_acceptance_changed=True),
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

    def test_complete_build_source_sets_are_distinct_and_pinned(self):
        extras = H.extra_sources()
        self.assertEqual(len(extras), 5)
        self.assertEqual(extras[H.ENTRYPOINT], H.probe_bytes())
        self.assertNotIn(H.H.ENTRYPOINT, extras)
        for name, raw in H.H.extra_sources().items():
            if name not in (H.H.ENTRYPOINT, H.H.CONTROL_TARGET):
                self.assertEqual(extras[name], raw)
        self.assertEqual(len(H.build_pins()), 472)
        self.assertEqual(H.P.UTIL.reconstruct_tree(H.build_pins()), H.BUILD_TREE)
        self.assertEqual(H.parent_build_tree(), H.PARENT_BUILD_TREE)
        self.assertNotIn(b".Start()", extras[H.ENTRYPOINT])

    def test_prior_forward_controls_have_only_declared_fixture_and_trace_changes(self):
        before = H.H.P.read_regular(HERE / H.H.CONTROL, 64 << 10).decode()
        after = H.source_bytes(H.COMPAT_CONTROL, H.COMPAT_BYTES, H.COMPAT_SHA256).decode()
        for old, new in (
            ('second := &nom.Momentum{Hash: types.NewHash([]byte("selected second")), Height: 2}',
             'second := &nom.Momentum{Hash: types.NewHash([]byte("selected second")), PreviousHash: first.Hash, Height: 2}'),
            ('{"canonical-base-reaches-forward-read", first.Identifier(), first, nil, prefetchFailure, []uint64{1, 2}, true}',
             '{"canonical-base-reaches-forward-read", first.Identifier(), first, nil, prefetchFailure, []uint64{1, 2, 2}, true}'),
            ('{"zero-base-skips-height-zero-lookup", types.ZeroHashHeight, first, nil, prefetchFailure, []uint64{1}, true}',
             '{"zero-base-skips-height-zero-lookup", types.ZeroHashHeight, first, nil, prefetchFailure, []uint64{1, 2, 1}, true}'),
        ):
            self.assertEqual(after.count(new), 1)
            after = after.replace(new, old)
        self.assertEqual(after, before)

    def test_probe_and_both_control_sources_reject_byte_substitution(self):
        original = H.P.read_regular
        for selected in (H.PROBE, H.CONTROL, H.COMPAT_CONTROL):
            def read(path, limit):
                raw = original(path, limit)
                return raw + b"\n" if Path(path).name == selected else raw
            with mock.patch.object(H.P, "read_regular", side_effect=read):
                with self.assertRaises(ValueError):
                    H.extra_sources()

    def test_finite_plan_preserves_execution_and_acceptance_boundaries(self):
        plan = H.plan(Path("/selected-owned-replay-window"), "/selected/go")
        self.assertEqual(plan["build_argv"][:5], ["/selected/go", "build", "-mod=readonly", "-trimpath", "-buildvcs=false"])
        self.assertEqual(plan["build_argv"][5:7], ["-tags", "candidate_public_cache_replay_window"])
        self.assertEqual(plan["cases"], list(H.CASES))
        self.assertEqual(len(plan["native_control_roots"]), 14)
        self.assertEqual(plan["expected_native_unit_pass_results"], 46)
        for name in ("reference_backend_executed", "native_control_execution_selected", "accepted_header_binding",
                     "runtime_state_value_acceptance", "whole_window_atomicity_claimed", "legacy_cache_manager_interface_changed"):
            self.assertIs(plan[name], False)
        for name in ("replay_window_linkage_preflight_required", "missing_replay_momentum_refused",
                     "prefetch_identity_checked", "final_uint64_increment_avoided", "explicit_fixture_restore_is_not_runtime_repair"):
            self.assertIs(plan[name], True)
        self.assertEqual(plan["consumer_result"], "REFUSED")
        self.assertNotIn("-race", plan["build_argv"])
        self.assertNotIn("-overlay", plan["build_argv"])
        self.assertEqual(plan["minimum_free_floor_bytes"], 10 << 30)

    def test_invalid_compiler_is_refused(self):
        for value in (None, "", "go\x00other"):
            with self.assertRaises(ValueError):
                H.plan(Path("/selected-owned-replay-window"), value)

    def test_existing_workspace_and_link_predicates_preserve_data(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            sentinel = root / "preserved-evidence"
            sentinel.write_bytes(b"preserve")
            with self.assertRaises(ValueError):
                H.prepare(root / "absent", root, "go")
            self.assertEqual(sentinel.read_bytes(), b"preserve")
            alias = root / "alias"
            alias.mkdir()
            real = Path.is_symlink
            def linked(path):
                return True if path == alias else real(path)
            for original, destination in ((alias, root / "new"), (root, alias / "new")):
                with mock.patch.object(Path, "is_symlink", new=linked):
                    with self.assertRaises(ValueError):
                        H.prepare(original, destination, "go")
                self.assertFalse((root / "new").exists())

    def test_inventory_and_preparation_record_substitutions_are_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            node = root / "node"
            node.mkdir()
            entry = node / "selected.go"
            entry.write_bytes(b"selected source")
            entry.chmod(0o644)
            expected = {"isolated_inventory_fixture": True}
            record = root / "cache-replay-window-prepared.json"
            record.write_text(json.dumps(expected))
            pins = {"selected.go": {"mode": "100644", "bytes": 15, "sha256": H.P.sha(b"selected source")}}
            with mock.patch.object(H, "build_pins", return_value=pins), \
                 mock.patch.object(H, "plan", return_value=expected):
                self.assertEqual(H.verify(root, "go"), expected)
                entry.write_bytes(b"different")
                with self.assertRaises(ValueError):
                    H.verify(root, "go")
                entry.write_bytes(b"selected source")
                extra = node / "unexpected"
                extra.write_bytes(b"extra")
                with self.assertRaises(ValueError):
                    H.verify(root, "go")
                extra.unlink()
                record.write_text('{"isolated_inventory_fixture":true,"extra":true}')
                with self.assertRaises(ValueError):
                    H.verify(root, "go")
                record.write_text(json.dumps(expected))
                if sys.platform != "win32":
                    entry.chmod(0o755)
                    with self.assertRaises(ValueError):
                        H.verify(root, "go")

    def test_new_native_inputs_follow_the_existing_lf_policy(self):
        attributes = (HERE.parents[1] / ".gitattributes").read_bytes()
        self.assertEqual(attributes.count(b"*.go.txt text eol=lf\n"), 1)
        for name in (H.PROBE, H.CONTROL, H.COMPAT_CONTROL):
            self.assertNotIn(b"\r", (HERE / name).read_bytes())


if __name__ == "__main__":
    unittest.main()
