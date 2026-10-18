#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Complete-source and fresh-workspace controls; no reference node is run."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("cache_rollback_preparation_controls", HERE / "prepare_cache_identifier_rollback.py")
G = importlib.util.module_from_spec(spec)
spec.loader.exec_module(G)


class CacheIdentifierPreparationTests(unittest.TestCase):
    def test_full_parent_and_candidate_runtime_trees(self):
        manifest, modified, pins = G.selection()
        self.assertEqual(len(manifest["files"]), 467)
        self.assertEqual(len(pins), 467)
        self.assertEqual(G.P.UTIL.reconstruct_tree(pins), G.MODIFIED_TREE)
        self.assertEqual(set(modified), {"chain/chain.go", "chain/state_tree.go", "common/trie/nodestore.go", *G.AFTER})
        for name in ("go.mod", "go.sum"):
            self.assertEqual(pins[name], manifest["files"][name])
        _, _, parent = G.F.selection()
        self.assertEqual(G.P.UTIL.reconstruct_tree(parent), G.F.C.MODIFIED_TREE)
        self.assertNotEqual(G.MODIFIED_TREE, G.F.C.MODIFIED_TREE)

    def test_patch_full_file_inverses_and_pin_substitution(self):
        original = G.P.document(G.PATCH, G.PATCH_SHA256)
        for mutate in (
            lambda d: d.update(runtime_parent_tree="0" * 40),
            lambda d: d.update(disk_format_changed=True),
            lambda d: d.update(legacy_cache_manager_interface_changed=True),
            lambda d: d.update(whole_window_atomicity_claimed=True),
            lambda d: d["replacements"].reverse(),
            lambda d: d["replacements"].pop(),
            lambda d: d["replacements"][0].update(before="substituted"),
            lambda d: d["replacements"][0].update(after=d["replacements"][0]["after"] + "\n"),
            lambda d: d["replacements"][0].update(after_git_blob="0" * 40),
        ):
            changed = copy.deepcopy(original)
            mutate(changed)
            # Only replace this descriptor; ancestor selectors retain their
            # complete independent file/tree checks.
            real = G.P.document
            def selected(name, pin):
                return changed if name == G.PATCH else real(name, pin)
            with mock.patch.object(G.P, "document", side_effect=selected):
                with self.assertRaises((ValueError, KeyError, TypeError)):
                    G.selection()

    def test_complete_probe_and_explicit_native_controls_are_bound(self):
        extras = G.extra_sources()
        self.assertEqual(len(extras), 3)
        self.assertEqual(extras[G.F.ENTRYPOINT], G.F.probe_bytes())
        _, _, pins = G.selection()
        for name, raw in extras.items():
            pins[name] = {"mode": "100644", "bytes": len(raw), "sha256": G.P.sha(raw),
                          "git_blob": G.P.UTIL.git_hash("blob", raw)}
        plan = G.plan(Path("/selected-owned-cache"), "go")
        self.assertEqual(G.P.UTIL.reconstruct_tree(pins), plan["build_tree"])
        self.assertEqual(plan["added_source_files"], sorted(extras))
        self.assertNotIn(b".Start()", extras[G.F.ENTRYPOINT])

    def test_control_source_substitution_refused(self):
        original = G.P.read_regular
        for selected in G.CONTROL_SOURCES:
            def read(path, limit):
                raw = original(path, limit)
                return raw + b"\n" if Path(path).name == selected else raw
            with mock.patch.object(G.P, "read_regular", side_effect=read):
                with self.assertRaises(ValueError):
                    G.extra_sources()

    def test_autocrlf_checkout_preserves_pinned_native_control_bytes(self):
        # Use an isolated Git index and real checkout conversion, without a
        # commit, network, global configuration or reference node execution.
        attributes = (HERE.parents[1] / ".gitattributes").read_bytes()
        rule = b"*.go.txt text eol=lf\n"
        self_rule = b".gitattributes text eol=lf\n"
        self.assertEqual(attributes.count(rule), 1)
        self.assertEqual(attributes.count(self_rule), 1)
        original_extras = G.extra_sources()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            repository = root / "fixture"
            repository.mkdir()
            template = root / "empty-template"
            template.mkdir()
            environment = os.environ.copy()
            for name in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY",
                         "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_CONFIG_COUNT"):
                environment.pop(name, None)
            environment.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
                               GIT_CONFIG_SYSTEM=os.devnull, GIT_TERMINAL_PROMPT="0")
            def git(*arguments):
                result = subprocess.run(["git", "-c", "core.autocrlf=true", "-c", "core.safecrlf=false",
                                         "-c", "gc.auto=0", "-c", "maintenance.auto=false", *arguments],
                                        cwd=repository, env=environment, capture_output=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
            git("init", "--quiet", "--template=" + template.as_posix())
            attr = repository / ".gitattributes"
            before_attributes = attributes.replace(rule, b"").replace(self_rule, b"")
            attr.write_bytes(before_attributes)
            paths = []
            for name in G.CONTROL_SOURCES:
                relative = "tools/gen-state-root-vectors/" + name
                path = repository / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                raw = (HERE / name).read_bytes()
                self.assertNotIn(b"\r", raw)
                path.write_bytes(raw)
                paths.append(relative)
            git("add", "--", ".gitattributes", *paths)
            before = root / "before"
            before.mkdir()
            git("checkout-index", "--prefix=" + before.as_posix() + "/", "--", ".gitattributes", *paths)
            self.assertEqual((before / ".gitattributes").read_bytes(),
                             before_attributes.replace(b"\n", b"\r\n"))
            for name, pin in G.CONTROL_SOURCES.items():
                raw = (before / "tools/gen-state-root-vectors" / name).read_bytes()
                self.assertIn(b"\r\n", raw)
                self.assertNotEqual(G.P.sha(raw), pin["sha256"])
            with mock.patch.object(G, "HERE", before / "tools/gen-state-root-vectors"):
                with self.assertRaises(ValueError):
                    G.extra_sources()
            attr.write_bytes(attributes)
            git("add", "--", ".gitattributes")
            after = root / "after"
            after.mkdir()
            git("checkout-index", "--prefix=" + after.as_posix() + "/", "--", ".gitattributes", *paths)
            self.assertEqual((after / ".gitattributes").read_bytes(), attributes)
            with mock.patch.object(G, "HERE", after / "tools/gen-state-root-vectors"):
                self.assertEqual(G.extra_sources(), original_extras)
            for name, pin in G.CONTROL_SOURCES.items():
                raw = (after / "tools/gen-state-root-vectors" / name).read_bytes()
                self.assertNotIn(b"\r", raw)
                self.assertEqual(G.P.sha(raw), pin["sha256"])

    def test_finite_ordinary_plan_and_refusal_scope(self):
        plan = G.plan(Path("/selected-owned-cache"), "/selected/go")
        self.assertEqual(plan["build_argv"][:5], ["/selected/go", "build", "-mod=readonly", "-trimpath", "-buildvcs=false"])
        self.assertEqual(plan["cases"], list(G.F.CASES))
        self.assertEqual(len(plan["cases"]), 4)
        for flag in ("reference_backend_executed", "native_control_execution_selected", "accepted_header_binding",
                     "runtime_state_value_acceptance", "legacy_cache_manager_interface_changed", "whole_window_atomicity_claimed"):
            self.assertIs(plan[flag], False)
        self.assertIs(plan["runtime_changed"], True)
        self.assertEqual(plan["consumer_result"], "REFUSED")
        self.assertNotIn("-race", plan["build_argv"])
        self.assertNotIn("-overlay", plan["build_argv"])
        self.assertEqual(plan["minimum_free_floor_bytes"], 10 << 30)

    def test_invalid_compiler_refused(self):
        for value in (None, "", "go\x00other"):
            with self.assertRaises(ValueError):
                G.plan(Path("/selected-owned-cache"), value)

    def test_existing_destination_not_adopted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            sentinel = root / "preserved-evidence"
            sentinel.write_bytes(b"preserve")
            with self.assertRaises(ValueError):
                G.prepare(root / "absent", root, "go")
            self.assertEqual(sentinel.read_bytes(), b"preserve")

    def test_source_and_destination_link_predicate_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            alias = root / "alias"
            alias.mkdir()
            real = Path.is_symlink
            hits = []
            def linked(path):
                if path == alias:
                    hits.append(path)
                    return True
                return real(path)
            # A deliberately invalid OS link would also trip the supervising
            # task-storage scanner. Exercise this preparer's rejection of the
            # link predicate without creating one. Existing parent preparation
            # tests separately exercise real symlinks in hosted CI.
            for original, destination in ((alias, root / "new"), (root, alias / "new")):
                hits.clear()
                with mock.patch.object(Path, "is_symlink", new=linked):
                    with self.assertRaises(ValueError):
                        G.prepare(original, destination, "go")
                self.assertIn(alias, hits)
                self.assertFalse((root / "new").exists())

    def test_prepared_inventory_bytes_modes_and_record_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            node = root / "node"
            node.mkdir()
            entry = node / "selected.go"
            entry.write_bytes(b"selected source")
            entry.chmod(0o644)
            expected = {"isolated_inventory_fixture": True}
            record = root / "cache-identifier-rollback-prepared.json"
            record.write_text(json.dumps(expected))
            with mock.patch.object(G, "selection", return_value=({}, {}, {})), \
                 mock.patch.object(G, "extra_sources", return_value={"selected.go": b"selected source"}), \
                 mock.patch.object(G, "plan", return_value=expected):
                self.assertEqual(G.verify(root, "go"), expected)
                entry.write_bytes(b"different source")
                with self.assertRaises(ValueError):
                    G.verify(root, "go")
                entry.write_bytes(b"selected source")
                extra = node / "unexpected"
                extra.write_bytes(b"extra")
                with self.assertRaises(ValueError):
                    G.verify(root, "go")
                extra.unlink()
                record.write_text('{"isolated_inventory_fixture":true,"extra":true}')
                with self.assertRaises(ValueError):
                    G.verify(root, "go")
                record.write_text(json.dumps(expected))
                if sys.platform != "win32":
                    entry.chmod(0o755)
                    with self.assertRaises(ValueError):
                        G.verify(root, "go")


if __name__ == "__main__":
    unittest.main()
