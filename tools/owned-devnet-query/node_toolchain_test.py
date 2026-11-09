# SPDX-License-Identifier: GPL-3.0-only
"""Synthetic Node-shaped archives, with no native binary or package execution."""
import argparse
from copy import deepcopy
import hashlib
import io
import json
import lzma
import os
from pathlib import Path
import stat
import sys
import tarfile
import tempfile
import unittest

sys.dont_write_bytecode = True
HERE = Path(__file__).absolute().parent
sys.path.insert(0, str(HERE))
import inputs_test as fixtures
import model
import node_toolchain
import process as owned_process

PREFIX = "node-v22.23.0-linux-x64"


def pin(raw):
    return {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}


def base_files():
    package = model.canonical({"name": "npm", "version": "10.9.8",
                              "bin": {"npm": "bin/npm-cli.js", "npx": "bin/npx-cli.js"}})
    return {"bin/node": (fixtures.elf(), True),
            "lib/node_modules/npm/package.json": (package, False),
            "lib/node_modules/npm/bin/npm-cli.js": (b"// npm fixture\n", True),
            "lib/node_modules/npm/bin/npx-cli.js": (b"// npx fixture\n", True),
            "include/node/node_api.h": (b"/* header fixture */\n", False),
            "lib/node_modules/npm/node_modules/@scope/" + "long-name-" * 9 + "/index.js": (b"// module\n", False),
            "lib/node_modules/npm/empty": (b"", False)}


def fixture(files=None, extra=(), alter_tar=None, alter_xz=None, links=None):
    files = base_files() if files is None else files
    links = node_toolchain.EXPECTED_LINKS if links is None else links
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.GNU_FORMAT) as archive:
        root = tarfile.TarInfo(PREFIX)
        root.type = tarfile.DIRTYPE
        archive.addfile(root)
        for name, (raw, executable) in sorted(files.items()):
            row = tarfile.TarInfo(PREFIX + "/" + name)
            row.size = len(raw)
            row.mode = 0o755 if executable else 0o644
            archive.addfile(row, io.BytesIO(raw))
        for name, target in links.items():
            row = tarfile.TarInfo(PREFIX + "/" + name)
            row.type = tarfile.SYMTYPE
            row.linkname = target
            archive.addfile(row)
        for row, raw in extra:
            archive.addfile(row, io.BytesIO(raw))
    decoded = buffer.getvalue()
    decoded = alter_tar(decoded) if alter_tar else decoded
    encoded = lzma.compress(decoded)
    encoded = alter_xz(encoded) if alter_xz else encoded
    selected = [{"path": name, **pin(raw), "executable": executable}
                for name, (raw, executable) in sorted(files.items())]
    manifest = model.canonical({"format": "owned-devnet-node-selected-manifest/v1",
        "files": selected, "skipped_links": sorted([{"path": name, "target": target, "kind": "2"}
            for name, target in links.items()], key=lambda row: row["path"])})
    specification = deepcopy(model.NODE_TOOLCHAIN)
    specification.update({"sha256": pin(encoded)["sha256"], "archive_bytes": len(encoded),
        "decoded_tar": pin(decoded), "selected_manifest": pin(manifest),
        "selected_regular_count": len(selected), "selected_regular_bytes": sum(row["bytes"] for row in selected),
        "node_binary": pin(files.get("bin/node", (fixtures.elf(), True))[0])})
    return encoded, specification


class CodecTests(unittest.TestCase):
    def refuse(self, raw, selected, reason=None):
        with self.assertRaises(model.Refused) as error:
            node_toolchain.unpack_node(io.BytesIO(raw), selected)
        if reason:
            self.assertEqual(error.exception.reason, reason)

    def test_stream_inspection_supports_scoped_and_gnu_long_names(self):
        raw, selected = fixture()
        result = node_toolchain.unpack_node(io.BytesIO(raw), selected)
        self.assertEqual(result["selected_manifest"], selected["selected_manifest"])
        self.assertEqual(result["files_extracted"], 0)
        self.assertIs(result["binary_or_package_executed"], False)
        self.assertIs(result["symlink_or_hardlink_created"], False)

    def test_original_size_and_digest_are_required(self):
        raw, selected = fixture()
        for changed in (raw[:-1], raw + b"suffix", bytes([raw[0] ^ 1]) + raw[1:]):
            with self.subTest(size=len(changed)):
                self.refuse(changed, selected)

    def test_inner_decoded_and_selected_manifest_digests_are_independent(self):
        raw, selected = fixture()
        for path in ("decoded_tar", "selected_manifest", "node_binary"):
            changed = deepcopy(selected)
            changed[path]["sha256"] = "1" * 64
            with self.subTest(field=path):
                self.refuse(raw, changed)

    def test_limits_and_count_types_are_strict(self):
        raw, selected = fixture()
        for key, value in (("archive_bytes", True), ("selected_regular_count", True),
                           ("max_archive_bytes", 1 << 30), ("max_selected_regular_bytes", 1 << 30)):
            changed = deepcopy(selected)
            changed[key] = value
            with self.subTest(field=key):
                self.refuse(raw, changed)
        for field, value in (("selected_regular_count", 1), ("selected_regular_bytes", 1)):
            changed = deepcopy(selected)
            changed[field] = value
            self.refuse(raw, changed, "node_selection_bound")

    def test_only_the_three_declared_links_are_skipped(self):
        for name, target in (("bin/npm", "../../outside"), ("bin/other", "inside")):
            links = dict(node_toolchain.EXPECTED_LINKS)
            links[name] = target
            raw, selected = fixture(links=links)
            self.refuse(raw, selected, "node_link_selection")
        raw, selected = fixture(links={"bin/npm": node_toolchain.EXPECTED_LINKS["bin/npm"]})
        self.refuse(raw, selected, "node_link_closure")

    def test_hardlink_and_special_types_are_refused_without_creating_them(self):
        for kind in (tarfile.LNKTYPE, tarfile.FIFOTYPE, tarfile.CHRTYPE,
                     tarfile.BLKTYPE, tarfile.XHDTYPE, tarfile.XGLTYPE):
            entry = tarfile.TarInfo(PREFIX + "/special")
            entry.type = kind
            if kind == tarfile.LNKTYPE:
                entry.linkname = PREFIX + "/bin/node"
            raw, selected = fixture(extra=[(entry, b"")])
            with self.subTest(kind=repr(kind)):
                self.refuse(raw, selected)

    def test_path_and_case_aliases_are_refused_in_memory(self):
        for name in (PREFIX + "/../outside", "/absolute", "another-root/file",
                     PREFIX + "/a\\b", PREFIX + "/a:b", PREFIX + "/bin/NODE"):
            entry = tarfile.TarInfo(name)
            entry.size = 1
            raw, selected = fixture(extra=[(entry, b"x")])
            with self.subTest(name=name):
                self.refuse(raw, selected)

    def test_node_and_npm_entrypoints_are_mandatory(self):
        for name in ("bin/node", "lib/node_modules/npm/bin/npm-cli.js", "include/node/node_api.h"):
            files = base_files()
            del files[name]
            raw, selected = fixture(files=files)
            self.refuse(raw, selected, "node_required_files")

    def test_npm_name_version_and_bin_mapping_are_bound(self):
        for key, value in (("name", "another"), ("version", "1.0.0"),
                           ("bin", {"npm": "another.js", "npx": "another.js"})):
            files = base_files()
            package = json.loads(files["lib/node_modules/npm/package.json"][0])
            package[key] = value
            files["lib/node_modules/npm/package.json"] = (model.canonical(package), False)
            raw, selected = fixture(files=files)
            self.refuse(raw, selected, "node_npm_binding")

    def test_wrong_binary_architecture_is_not_accepted_by_a_matching_digest(self):
        files = base_files()
        value = bytearray(files["bin/node"][0])
        value[18:20] = (183).to_bytes(2, "little")
        files["bin/node"] = (bytes(value), True)
        raw, selected = fixture(files=files)
        self.refuse(raw, selected, "linux_amd64_binary_header")

    def test_truncated_or_concatenated_xz_and_hidden_tar_payload_refuse(self):
        for changed in (lambda raw: raw[:-8], lambda raw: raw + raw, lambda raw: raw + b"suffix"):
            raw, selected = fixture(alter_xz=changed)
            self.refuse(raw, selected)
        raw, selected = fixture(alter_tar=lambda raw: raw + b"hidden")
        self.refuse(raw, selected, "tar_trailing_data")

    def test_nonzero_tar_padding_and_unsupported_directory_spellings_refuse(self):
        def changed_tar(raw):
            result = bytearray(raw)
            first_file = tarfile.TarInfo.frombuf(raw[512:1024], "ascii", "strict")
            self.assertNotEqual(first_file.size % 512, 0)
            result[1024 + first_file.size] = 1
            return bytes(result)
        raw, selected = fixture(alter_tar=changed_tar)
        self.refuse(raw, selected, "node_tar_padding")
        directory = tarfile.TarInfo(PREFIX + "/extra//")
        directory.type = tarfile.DIRTYPE
        raw, selected = fixture(extra=[(directory, b"")])
        self.refuse(raw, selected, "node_member_path")


class RegularMaterializationTests(unittest.TestCase):
    def test_only_regular_files_and_wrappers_are_materialized_and_sealed(self):
        raw, selected = fixture()
        with tempfile.TemporaryDirectory(prefix="node-regular-control-") as temporary:
            destination = Path(temporary) / "prefix"
            result = node_toolchain.unpack_node(io.BytesIO(raw), selected, destination)
            self.assertIsInstance(result, node_toolchain.Installation)
            self.assertEqual(len(result.files), selected["selected_regular_count"] + 2)
            self.assertEqual(result.verify()["selected_manifest"], selected["selected_manifest"])
            self.assertFalse((destination / "bin/corepack").exists())
            for row in result.files:
                path = destination / row.path
                self.assertTrue(stat.S_ISREG(path.lstat().st_mode))
                self.assertEqual(path.stat().st_nlink, 1)
                if os.name == "posix":
                    self.assertEqual(path.stat().st_mode & 0o111, 0)
            for name, expected in node_toolchain.WRAPPERS.items():
                self.assertEqual((destination / "bin" / name).read_bytes(), expected)
            changed = result.inspection
            changed["npm_version"] = "changed"
            self.assertEqual(result.inspection["npm_version"], selected["npm_version"])

    def test_invalid_manifest_leaves_only_nonexecutable_partial_files(self):
        raw, selected = fixture()
        selected["selected_manifest"]["sha256"] = "1" * 64
        with tempfile.TemporaryDirectory(prefix="node-regular-control-") as temporary:
            destination = Path(temporary) / "prefix"
            with self.assertRaisesRegex(model.Refused, "node_manifest_binding"):
                node_toolchain.unpack_node(io.BytesIO(raw), selected, destination)
            self.assertFalse((destination / "bin/npm").exists())
            for parent, _, names in os.walk(destination):
                for name in names:
                    if os.name == "posix":
                        self.assertEqual((Path(parent) / name).stat().st_mode & 0o111, 0)

    def test_existing_destination_is_preserved(self):
        raw, selected = fixture()
        with tempfile.TemporaryDirectory(prefix="node-regular-control-") as temporary:
            destination = Path(temporary) / "prefix"
            destination.mkdir()
            (destination / "foreign").write_bytes(b"preserve")
            with self.assertRaisesRegex(model.Refused, "node_destination_exists"):
                node_toolchain.unpack_node(io.BytesIO(raw), selected, destination)
            self.assertEqual((destination / "foreign").read_bytes(), b"preserve")

    def test_execution_mode_requires_a_separate_complete_intake_action(self):
        raw, selected = fixture()
        with tempfile.TemporaryDirectory(prefix="node-regular-control-") as temporary:
            result = node_toolchain.unpack_node(io.BytesIO(raw), selected, Path(temporary) / "prefix")
            if os.name == "posix":
                enabled = result.enable_execution()
                self.assertIs(enabled.execution_enabled, True)
                self.assertEqual(enabled.verify()["npm_version"], selected["npm_version"])
                for row in enabled.files:
                    self.assertEqual((enabled.root / row.path).stat().st_mode & 0o777,
                                     0o500 if row.executable else 0o400)
            else:
                with self.assertRaisesRegex(model.Refused, "node_execution_platform"):
                    result.enable_execution()


@unittest.skipUnless(os.name == "posix", "Recorded POSIX leases are not Windows qualification")
class LeaseTests(unittest.TestCase):
    def test_lease_is_one_new_recorded_regular_inode_and_releases(self):
        import fcntl
        with tempfile.TemporaryDirectory(prefix="node-lease-control-") as temporary:
            recorder = owned_process.Recorder(Path(temporary) / "commands")
            with owned_process.owned_lease(recorder, "node.lease"):
                path = recorder.directory / "node.lease"
                before = path.stat()
                self.assertEqual(before.st_nlink, 1)
                self.assertEqual(path.read_bytes(), b"")
            self.assertEqual(path.stat().st_ino, before.st_ino)
            with path.open("rb") as stream:
                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)

    def test_body_failure_closes_the_owned_lease(self):
        import fcntl
        with tempfile.TemporaryDirectory(prefix="node-lease-control-") as temporary:
            recorder = owned_process.Recorder(Path(temporary) / "commands")
            with self.assertRaisesRegex(model.Refused, "fixture_failure"):
                with owned_process.owned_lease(recorder, "node.lease"):
                    raise model.Refused("fixture_failure")
            with (recorder.directory / "node.lease").open("rb") as stream:
                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)

    def test_foreign_or_repeated_lease_paths_are_not_adopted(self):
        with tempfile.TemporaryDirectory(prefix="node-lease-control-") as temporary:
            recorder = owned_process.Recorder(Path(temporary) / "commands")
            path = recorder.directory / "foreign.lease"
            path.write_bytes(b"preserve")
            with self.assertRaises(FileExistsError):
                with owned_process.owned_lease(recorder, "foreign.lease"):
                    self.fail("must not acquire a foreign path")
            self.assertEqual(path.read_bytes(), b"preserve")
            with owned_process.owned_lease(recorder, "new.lease"):
                with self.assertRaises(model.Refused):
                    with owned_process.owned_lease(recorder, "new.lease"):
                        self.fail("must not duplicate transport ownership")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-revision")
    arguments = parser.parse_args()
    if arguments.source_revision is not None:
        model.digest(arguments.source_revision, model.HEX40)
    result = unittest.TextTestRunner(stream=sys.stderr, verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__]))
    sys.stdout.buffer.write(model.canonical({"format": "owned-devnet-query-node-controls/v1",
        "source_revision": arguments.source_revision, "root_tests": result.testsRun,
        "errors": len(result.errors), "failures": len(result.failures), "skipped": len(result.skipped),
        "successful": result.wasSuccessful(), "synthetic_archives_only": True,
        "network_or_native_binary_or_package_or_engine_executed": False}))
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
