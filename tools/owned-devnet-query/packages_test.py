# SPDX-License-Identifier: GPL-3.0-only
"""Owned configuration and installed-metadata fixtures, without npm execution."""
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
import packages


def installed_fixture(root, contract):
    integrity = "sha512-" + base64.b64encode(bytes(range(64))).decode("ascii")
    declared = {"packages": {"": {"dependencies": {}}, "node_modules/tsx": {"version": "4.22.4"}}}
    installed = {"packages": {}}
    for role, name in (("typescript_client", "zeno-client"),
                       ("typescript_sdk", "znn-typescript-sdk")):
        selected = contract.data["sources"][role]
        repo, revision = selected["repository"], selected["revision"]
        declared["packages"][""]["dependencies"][name] = "github:" + repo + "#" + revision
        row = {"resolved": "git+ssh://git@github.com/" + repo + ".git#" + revision,
               "integrity": integrity}
        declared["packages"]["node_modules/" + name] = row
        installed["packages"]["node_modules/" + name] = deepcopy(row)
    (root / "package-lock.json").write_bytes(model.canonical(declared))
    for name, entry in packages.ENTRYPOINTS.items():
        prefix = root / "node_modules" / name
        prefix.mkdir(parents=True)
        version = {"zeno-client": "0.1.0", "znn-typescript-sdk": "1.0.5", "tsx": "4.22.4"}[name]
        (prefix / "package.json").write_bytes(model.canonical({"name": name, "version": version}))
        target = prefix / entry
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(b"// installed output fixture; never executed\n")
    (root / "node_modules/.package-lock.json").write_bytes(model.canonical(installed))
    return declared, installed


class PackageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.contract = model.read_contract(HERE / "contract.json")

    def test_environment_uses_only_owned_config_cache_and_selected_node(self):
        root, node = Path("/owned/cache"), Path("/owned/node")
        environment = packages.npm_environment({"PATH": "/system/bin", "GH_TOKEN": "fixture-token",
            "HOME": "/foreign-home", "NODE_OPTIONS": "inherited-option", "npm_config_userconfig": "/foreign-config",
            "GIT_CONFIG_VALUE_0": "inherited-rewrite", "EXECUTOR_KEY": "not-a-real-key"}, node, root)
        for name in ("GH_TOKEN", "HOME", "NODE_OPTIONS", "EXECUTOR_KEY"):
            self.assertNotIn(name, environment)
        self.assertEqual(environment["PATH"].split(os.pathsep)[0], str(node / "bin"))
        self.assertEqual(environment["npm_config_cache"], str(root / "npm-cache"))
        self.assertEqual(environment["npm_config_userconfig"], str(root / "npm-userconfig"))
        self.assertEqual(environment["npm_config_globalconfig"], str(root / "npm-globalconfig"))
        self.assertEqual(environment["npm_config_nodedir"], str(node))
        self.assertEqual(environment["TMPDIR"], str(root / "tmp"))
        self.assertEqual(environment["XDG_CACHE_HOME"], str(root / "xdg-cache"))
        self.assertEqual(environment["npm_config_devdir"], str(root / "node-gyp"))
        self.assertEqual(environment["npm_config_ignore_scripts"], "false")
        self.assertEqual(environment["npm_config_fetch_retries"], "0")
        self.assertEqual(environment["npm_config_registry"], "https://registry.npmjs.org/")

    def test_git_rewrites_are_scoped_to_the_child_environment(self):
        base = {"PATH": "/system/bin", "GIT_CONFIG_COUNT": "9"}
        expected = deepcopy(base)
        environment = packages.npm_environment(base, Path("/owned/node"), Path("/owned/cache"))
        self.assertEqual(base, expected)
        self.assertEqual(environment["GIT_CONFIG_COUNT"], "2")
        self.assertEqual(environment["GIT_CONFIG_VALUE_0"], "ssh://git@github.com/")
        self.assertEqual(environment["GIT_CONFIG_VALUE_1"], "git@github.com:")
        self.assertEqual(environment["GIT_ALLOW_PROTOCOL"], "https")

    def test_installed_entrypoints_are_content_pinned_after_declared_git_bindings(self):
        with tempfile.TemporaryDirectory(prefix="package-regular-control-") as temporary:
            root = Path(temporary)
            installed_fixture(root, self.contract)
            result = packages.installed_entries(self.contract, root)
            self.assertEqual(len(result["entrypoints"]), 3)
            self.assertIs(result["whole_installed_tree_independently_reproduced"], False)
            for row in result["entrypoints"]:
                raw = (root / "node_modules" / row["package"] / row["entrypoint"]).read_bytes()
                self.assertEqual(row["entrypoint_pin"], {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)})

    def test_wrong_installed_revision_and_integrity_refuse(self):
        for field, value in (("resolved", "git+https://github.com/other/repository.git#" + "1" * 40),
                             ("integrity", "sha512-other")):
            with self.subTest(field=field):
                with tempfile.TemporaryDirectory(prefix="package-regular-control-") as temporary:
                    root = Path(temporary)
                    _, installed = installed_fixture(root, self.contract)
                    installed["packages"]["node_modules/zeno-client"][field] = value
                    (root / "node_modules/.package-lock.json").write_bytes(model.canonical(installed))
                    with self.assertRaises(model.Refused):
                        packages.installed_entries(self.contract, root)

    def test_matching_name_or_version_cannot_replace_the_git_binding(self):
        with tempfile.TemporaryDirectory(prefix="package-regular-control-") as temporary:
            root = Path(temporary)
            _, installed = installed_fixture(root, self.contract)
            del installed["packages"]["node_modules/zeno-client"]["resolved"]
            (root / "node_modules/.package-lock.json").write_bytes(model.canonical(installed))
            with self.assertRaisesRegex(model.Refused, "installed_git_dependency_binding"):
                packages.installed_entries(self.contract, root)

    def test_wrong_built_package_version_refuses(self):
        with tempfile.TemporaryDirectory(prefix="package-regular-control-") as temporary:
            root = Path(temporary)
            installed_fixture(root, self.contract)
            (root / "node_modules/znn-typescript-sdk/package.json").write_bytes(
                model.canonical({"name": "znn-typescript-sdk", "version": "another"}))
            with self.assertRaisesRegex(model.Refused, "installed_package_version"):
                packages.installed_entries(self.contract, root)

    def test_regular_read_bound_and_file_identity(self):
        with tempfile.TemporaryDirectory(prefix="package-regular-control-") as temporary:
            root = Path(temporary)
            (root / "data").write_bytes(b"fixture")
            pin, raw = packages._regular_below(root, "data", 7, keep=True)
            self.assertEqual(raw, b"fixture")
            self.assertEqual(pin["bytes"], 7)
            with self.assertRaisesRegex(model.Refused, "installed_package_file"):
                packages._regular_below(root, "data", 6, keep=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-revision")
    arguments = parser.parse_args()
    if arguments.source_revision is not None:
        model.digest(arguments.source_revision, model.HEX40)
    result = unittest.TextTestRunner(stream=sys.stderr, verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__]))
    sys.stdout.buffer.write(model.canonical({"format": "owned-devnet-query-package-controls/v1",
        "source_revision": arguments.source_revision, "root_tests": result.testsRun,
        "errors": len(result.errors), "failures": len(result.failures), "skipped": len(result.skipped),
        "successful": result.wasSuccessful(), "npm_or_package_or_network_or_engine_executed": False}))
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
