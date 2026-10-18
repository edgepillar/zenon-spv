#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Source and workspace refusal controls; no native backend is executed."""
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
spec = importlib.util.spec_from_file_location("cache_forward_preparation_controls", HERE / "prepare_cache_forward_replay.py")
H = importlib.util.module_from_spec(spec)
spec.loader.exec_module(H)


class CacheForwardPreparationTests(unittest.TestCase):
    def test_complete_runtime_parent_and_candidate_trees(self):
        manifest, modified, pins = H.selection()
        self.assertEqual(len(manifest["files"]), 467)
        self.assertEqual(len(pins), 467)
        self.assertEqual(H.P.UTIL.reconstruct_tree(pins), H.MODIFIED_TREE)
        self.assertEqual(set(modified), {"chain/chain.go", "chain/state_tree.go", "common/trie/nodestore.go",
                                         "chain/cache.go", "chain/cache/storage/db.go"})
        _, _, parent = H.G.selection()
        self.assertEqual(H.P.UTIL.reconstruct_tree(parent), H.G.MODIFIED_TREE)
        self.assertNotEqual(H.MODIFIED_TREE, H.G.MODIFIED_TREE)
        for name in ("go.mod", "go.sum"):
            self.assertEqual(pins[name], manifest["files"][name])

    def test_full_file_inverse_and_substitution_refusals(self):
        original = H.P.document(H.PATCH, H.PATCH_SHA256)
        for mutate in (
            lambda d: d.update(runtime_parent_tree="0" * 40),
            lambda d: d.update(disk_format_changed=True),
            lambda d: d.update(legacy_cache_manager_interface_changed=True),
            lambda d: d.update(prewrite_parent_identity_required=False),
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

    def test_probe_inherited_controls_and_complete_build_tree(self):
        extras = H.extra_sources()
        self.assertEqual(len(extras), 4)
        self.assertEqual(extras[H.ENTRYPOINT], H.probe_bytes())
        self.assertNotIn(H.G.F.ENTRYPOINT, extras)
        for name, raw in H.G.extra_sources().items():
            if name != H.G.F.ENTRYPOINT:
                self.assertEqual(extras[name], raw)
        _, _, pins = H.selection()
        for name, raw in extras.items():
            pins[name] = {"mode": "100644", "bytes": len(raw), "sha256": H.P.sha(raw),
                          "git_blob": H.P.UTIL.git_hash("blob", raw)}
        plan = H.plan(Path("/selected-owned-forward-cache"), "go")
        self.assertEqual(H.P.UTIL.reconstruct_tree(pins), plan["build_tree"])
        self.assertEqual(plan["added_source_files"], sorted(extras))
        self.assertEqual(H.parent_build_tree(), H.PARENT_BUILD_TREE)
        self.assertNotIn(b".Start()", extras[H.ENTRYPOINT])

    def test_probe_and_control_byte_substitution_refused(self):
        original = H.P.read_regular
        for selected in (H.PROBE, H.CONTROL):
            def read(path, limit):
                raw = original(path, limit)
                return raw + b"\n" if Path(path).name == selected else raw
            with mock.patch.object(H.P, "read_regular", side_effect=read):
                with self.assertRaises(ValueError):
                    H.extra_sources()

    def test_finite_plan_keeps_native_execution_and_acceptance_unselected(self):
        plan = H.plan(Path("/selected-owned-forward-cache"), "/selected/go")
        self.assertEqual(plan["build_argv"][:5], ["/selected/go", "build", "-mod=readonly", "-trimpath", "-buildvcs=false"])
        self.assertEqual(plan["build_argv"][5:7], ["-tags", "candidate_public_cache_forward_replay"])
        self.assertEqual(plan["cases"], list(H.CASES))
        self.assertEqual(len(plan["cases"]), 4)
        for name in ("reference_backend_executed", "native_control_execution_selected", "accepted_header_binding",
                     "runtime_state_value_acceptance", "whole_window_atomicity_claimed", "legacy_cache_manager_interface_changed"):
            self.assertIs(plan[name], False)
        self.assertIs(plan["cache_predecessor_full_identifier_required"], True)
        self.assertEqual(plan["consumer_result"], "REFUSED")
        self.assertNotIn("-race", plan["build_argv"])
        self.assertNotIn("-overlay", plan["build_argv"])
        self.assertEqual(plan["minimum_free_floor_bytes"], 10 << 30)

    def test_invalid_compiler_refused(self):
        for value in (None, "", "go\x00other"):
            with self.assertRaises(ValueError):
                H.plan(Path("/selected-owned-forward-cache"), value)

    def test_existing_destination_is_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            sentinel = root / "preserved-evidence"
            sentinel.write_bytes(b"preserve")
            with self.assertRaises(ValueError):
                H.prepare(root / "absent", root, "go")
            self.assertEqual(sentinel.read_bytes(), b"preserve")

    def test_source_and_destination_link_predicate_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            alias = root / "alias"
            alias.mkdir()
            real = Path.is_symlink
            def linked(path):
                return True if path == alias else real(path)
            # Existing parent controls exercise real links in hosted CI. Avoid
            # making an invalid OS link beneath supervised qualification scratch.
            for original, destination in ((alias, root / "new"), (root, alias / "new")):
                with mock.patch.object(Path, "is_symlink", new=linked):
                    with self.assertRaises(ValueError):
                        H.prepare(original, destination, "go")
                self.assertFalse((root / "new").exists())

    def test_inventory_mode_and_preparation_record_refusals(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            node = root / "node"
            node.mkdir()
            entry = node / "selected.go"
            entry.write_bytes(b"selected source")
            entry.chmod(0o644)
            expected = {"isolated_inventory_fixture": True}
            record = root / "cache-forward-replay-prepared.json"
            record.write_text(json.dumps(expected))
            with mock.patch.object(H, "selection", return_value=({}, {}, {})), \
                 mock.patch.object(H, "extra_sources", return_value={"selected.go": b"selected source"}), \
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

    def test_new_native_sources_follow_existing_lf_checkout_policy(self):
        attributes = (HERE.parents[1] / ".gitattributes").read_bytes()
        self.assertEqual(attributes.count(b"*.go.txt text eol=lf\n"), 1)
        self.assertEqual(attributes.count(b".gitattributes text eol=lf\n"), 1)
        for name in (H.PROBE, H.CONTROL):
            raw = (HERE / name).read_bytes()
            self.assertNotIn(b"\r", raw)
        # The prior rollback preparer retains its actual autocrlf Git regression.
        # New containers use the same glob; no repeated Git fixture is needed.


if __name__ == "__main__":
    unittest.main()
