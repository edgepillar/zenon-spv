# SPDX-License-Identifier: GPL-3.0-only
"""Tree/lockfile and regular-file controls; no Git checkout or package execution."""
import argparse
import base64
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
HERE = Path(__file__).absolute().parent
sys.path.insert(0, str(HERE))
import model
import sources


def blob(raw):
    return hashlib.sha1(("blob " + str(len(raw)) + "\0").encode() + raw).hexdigest()


def tree_row(name="a.txt", value=b"a", mode="100644", kind="blob", size=None):
    return (mode + " " + kind + " " + blob(value) + " "
            + str(len(value) if size is None else size) + "\t" + name).encode() + b"\0"


class SourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.contract = model.read_contract(HERE / "contract.json")

    def test_bounded_regular_tree_records_include_empty_files(self):
        raw = tree_row("entrypoint.sh", b"#!/bin/sh\n", "100755") + tree_row("sub/empty", b"")
        records = sources.parse_tree(raw, 10, 100)
        self.assertEqual(len(records), 2)
        self.assertEqual(records[1].size, 0)
        self.assertEqual(records[0].mode, "100755")
        for limit_records, limit_bytes in ((1, 100), (10, 1)):
            with self.assertRaises(model.Refused):
                sources.parse_tree(raw, limit_records, limit_bytes)

    def test_nonregular_git_modes_are_rejected_before_checkout(self):
        for mode, kind in (("120000", "blob"), ("160000", "commit"),
                           ("040000", "tree"), ("100600", "blob")):
            with self.subTest(mode=mode):
                with self.assertRaises(model.Refused):
                    sources.parse_tree(tree_row(mode=mode, kind=kind), 10, 100)

    def test_tree_paths_and_aliases_are_rejected_without_creating_them(self):
        for name in ("../a", "/a", "x\\a", "x:a", "x/.git/config", "a b", "a\tb"):
            with self.subTest(name=name):
                with self.assertRaises(model.Refused):
                    sources.parse_tree(tree_row(name), 10, 100)
        for raw in (tree_row("a") + tree_row("A"), tree_row("a") + tree_row("a")):
            with self.assertRaises(model.Refused):
                sources.parse_tree(raw, 10, 100)

    def test_tree_size_and_record_encodings_are_strict(self):
        for raw in (b"", tree_row()[:-1], tree_row() + b"\0",
                    tree_row(size="01"), tree_row(size="-1"), tree_row(size="NaN"),
                    tree_row().replace(blob(b"a").encode(), b"0" * 40)):
            with self.subTest(value=raw[:30]):
                with self.assertRaises(model.Refused):
                    sources.parse_tree(raw, 10, 100)

    def test_every_declared_role_file_must_match_the_selected_git_tree(self):
        for role in sources.ROLES:
            selected = [row for row in self.contract.data["source_files"] if row["role"] == role]
            records = [sources.TreeFile(row["path"], "100644", row["git_blob"], row["bytes"])
                       for row in selected]
            self.assertEqual(sources.selected_files(self.contract, role, records), selected)
            for changed in (records[:-1], [sources.TreeFile(records[0].name, "100644", "1" * 40,
                                                          records[0].size), *records[1:]]):
                with self.assertRaises(model.Refused):
                    sources.selected_files(self.contract, role, changed)

    def test_regular_content_is_bound_to_both_git_blob_and_identity(self):
        with tempfile.TemporaryDirectory(prefix="source-regular-control-") as temporary:
            root = Path(temporary)
            (root / "sub").mkdir()
            path = root / "sub/data"
            raw = b"source fixture"
            path.write_bytes(raw)
            record = sources.TreeFile("sub/data", "100644", blob(raw), len(raw))
            pin, identity = sources.read_tracked(root, record)
            self.assertEqual(pin, {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)})
            self.assertEqual(sources.read_tracked(root, record, identity), (pin, identity))
            path.write_bytes(b"changed value!")
            with self.assertRaises(model.Refused):
                sources.read_tracked(root, record, identity)

    def test_empty_regular_file_and_executable_bit_are_checked(self):
        with tempfile.TemporaryDirectory(prefix="source-regular-control-") as temporary:
            root = Path(temporary)
            path = root / "entry"
            path.write_bytes(b"")
            record = sources.TreeFile("entry", "100644", blob(b""), 0)
            self.assertEqual(sources.read_tracked(root, record)[0]["bytes"], 0)
            if os.name == "posix":
                path.chmod(0o700)
                with self.assertRaisesRegex(model.Refused, "source_executable_mode"):
                    sources.read_tracked(root, record)
                executable = sources.TreeFile("entry", "100755", blob(b""), 0)
                for mode in (0o700, 0o755, 0o500):
                    path.chmod(mode)
                    self.assertEqual(sources.read_tracked(root, executable)[0]["bytes"], 0)
                path.chmod(0o641)
                for selected in (record, executable):
                    with self.assertRaisesRegex(model.Refused, "source_executable_mode"):
                        sources.read_tracked(root, selected)

    def locked_dependencies(self):
        packages = {"": {"dependencies": {}}}
        integrity = "sha512-" + base64.b64encode(bytes(range(64))).decode("ascii")
        for role, name in (("typescript_client", "zeno-client"),
                           ("typescript_sdk", "znn-typescript-sdk")):
            row = self.contract.data["sources"][role]
            packages[""]["dependencies"][name] = "github:" + row["repository"] + "#" + row["revision"]
            packages["node_modules/" + name] = {
                "resolved": "git+ssh://git@github.com/" + row["repository"] + ".git#" + row["revision"],
                "integrity": integrity}
        return {"packages": packages}

    def test_locked_git_dependencies_do_not_require_a_second_checkout(self):
        value = self.locked_dependencies()
        result = sources.lockfile_binding(self.contract, model.canonical(value))
        self.assertEqual(len(result), 2)
        self.assertTrue(all(row["second_explicit_checkout"] is False for row in result))
        for package in ("zeno-client", "znn-typescript-sdk"):
            for field, changed in (("resolved", "github:other/repository#" + "1" * 40),
                                   ("integrity", "sha512-short")):
                selected = deepcopy(value)
                selected["packages"]["node_modules/" + package][field] = changed
                with self.assertRaises(model.Refused):
                    sources.lockfile_binding(self.contract, model.canonical(selected))
        with self.assertRaises(model.Refused):
            sources.lockfile_binding(self.contract, b'{"packages":{},"packages":{}}')

    def test_source_environment_excludes_inherited_credentials_and_options(self):
        environment = sources.git_environment({"PATH": "/fixture/bin", "LANG": "C.UTF-8",
            "GH_TOKEN": "not-a-real-token", "HOME": "/fixture-home",
            "SSH_AUTH_SOCK": "/fixture-agent", "NODE_OPTIONS": "fixture-option",
            "LD_PRELOAD": "fixture-loader", "GIT_CONFIG_COUNT": "9", "GIT_TRACE": "1"},
            Path("/owned/empty-git-config"))
        for key in ("GH_TOKEN", "HOME", "SSH_AUTH_SOCK", "NODE_OPTIONS", "LD_PRELOAD",
                    "GIT_CONFIG_COUNT", "GIT_TRACE"):
            self.assertNotIn(key, environment)
        self.assertEqual(environment["GIT_ALLOW_PROTOCOL"], "https")
        self.assertEqual(environment["GIT_CONFIG_GLOBAL"], str(Path("/owned/empty-git-config")))

    def test_layout_selects_original_source_root_without_console_or_extra_ts_clone(self):
        self.assertEqual(set(sources.LAYOUT), {"devnet", "node", "executor", "contract_sdk"})
        self.assertEqual(sources.LAYOUT["node"], "devnet/.sources/zenon-network/go-zenon")
        self.assertEqual(sources.LAYOUT["contract_sdk"], "devnet/.sources/zeno/zeno-contract-sdk-rs")
        root = Path("/owned")
        rows = tuple(sources.Checkout(role, root / sources.LAYOUT[role], (), "", "", "", (), (), b"[]")
                     for role in sources.ROLES)
        self.assertEqual(sources.PreparedSources(rows).source_root, root / "devnet/.sources")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-revision")
    arguments = parser.parse_args()
    if arguments.source_revision is not None:
        model.digest(arguments.source_revision, model.HEX40)
    result = unittest.TextTestRunner(stream=sys.stderr, verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__]))
    sys.stdout.buffer.write(model.canonical({"format": "owned-devnet-query-source-controls/v1",
        "source_revision": arguments.source_revision, "root_tests": result.testsRun,
        "errors": len(result.errors), "failures": len(result.failures), "skipped": len(result.skipped),
        "successful": result.wasSuccessful(), "Git_or_network_or_package_execution": False,
        "binary_or_engine_or_signing_executed": False}))
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
