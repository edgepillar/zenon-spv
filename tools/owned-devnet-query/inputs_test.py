# SPDX-License-Identifier: GPL-3.0-only
"""Synthetic archives and regular files only; no binary is executed."""
import argparse
import hashlib
import io
import json
import lzma
import os
from pathlib import Path
import stat
import struct
import sys
import tarfile
import tempfile
import unittest
from unittest import mock
import warnings
import zipfile

sys.dont_write_bytecode = True
HERE = Path(__file__).absolute().parent
sys.path.insert(0, str(HERE))
import inputs
import model


def pin(raw):
    return {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}


def elf(suffix=b"fixture"):
    raw = bytearray(64)
    raw[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHI", raw, 16, 2, 62, 1)
    struct.pack_into("<H", raw, 52, 64)
    return bytes(raw) + suffix


def zip_bytes(rows, compression=zipfile.ZIP_STORED, comment=b""):
    out = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(out, "w", compression=compression) as archive:
            for name, raw, mode in rows:
                entry = zipfile.ZipInfo(name)
                # Keep malformed separators and NULs in the serialized fixture.
                entry.filename = name
                entry.create_system = 3
                entry.external_attr = mode << 16
                entry.compress_type = compression
                archive.writestr(entry, raw)
            archive.comment = comment
    return out.getvalue()


def tar_bytes(rows):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, raw, kind in rows:
            entry = tarfile.TarInfo(name)
            entry.type = kind
            entry.size = len(raw)
            if kind == tarfile.SYMTYPE:
                entry.linkname = "unselected-target"
            archive.addfile(entry, io.BytesIO(raw))
    return out.getvalue()


def consumer(rows=None, decoded=None, encoded=None, compression=zipfile.ZIP_STORED):
    files = {name: elf(name.encode()) for name in inputs.CONSUMER_MEMBERS}
    files["manifest.json"] = b'{"fixture":true}\n'
    files["offline-pilot.json"] = b'{"fixture":true}\n'
    if rows is None:
        rows = [(name, value, tarfile.REGTYPE) for name, value in sorted(files.items())]
    decoded = tar_bytes(rows) if decoded is None else decoded
    encoded = lzma.compress(decoded) if encoded is None else encoded
    raw = zip_bytes([("candidate-v1.tar.xz", encoded, stat.S_IFREG | 0o400)], compression)
    specification = {"archive": pin(raw), "artifact_id": 1, "run_attempt": 1,
                     "run_id": 2, "decoded_tar": pin(decoded),
                     "payload": {"filename": "candidate-v1.tar.xz", **pin(encoded)},
                     "binaries": {name: pin(files[name]) for name in inputs.SELECTED["consumer"]}}
    return raw, specification, files


def helper(extra=(), selected=None):
    selected = elf() if selected is None else selected
    rows = [("spv-closed-parent-oracle.exe", selected, stat.S_IFREG | 0o500),
            ("manifest.json", b'{"fixture":true}\n', stat.S_IFREG | 0o400), *extra]
    raw = zip_bytes(rows, zipfile.ZIP_DEFLATED)
    return raw, {"archive": pin(raw), "artifact_id": 3, "run_attempt": 1, "run_id": 4,
                 "binaries": {"spv-closed-parent-oracle.exe": pin(selected)}}


class IntakeTests(unittest.TestCase):
    def unpack(self, raw, specification, destination, kind="consumer"):
        return inputs.unpack_binaries(io.BytesIO(raw), kind, specification, destination)

    def refusal(self, raw, specification, kind="consumer", reason=None):
        with tempfile.TemporaryDirectory(prefix="owned-input-control-") as root:
            destination = Path(root) / "selected"
            with self.assertRaises(model.Refused) as raised:
                self.unpack(raw, specification, destination, kind)
            if reason is not None:
                self.assertEqual(raised.exception.reason, reason)
            if destination.is_dir():
                for path in destination.iterdir():
                    self.assertTrue(path.is_file())
                    if os.name == "posix":
                        self.assertEqual(path.stat().st_mode & 0o111, 0)

    def test_consumer_selects_two_regular_files_without_tar_or_xz_copy(self):
        raw, specification, files = consumer()
        with tempfile.TemporaryDirectory(prefix="owned-input-control-") as root:
            destination = Path(root) / "selected"
            result = self.unpack(raw, specification, destination)
            self.assertEqual(result.verify(), specification["binaries"])
            self.assertEqual({p.name for p in destination.iterdir()}, inputs.SELECTED["consumer"])
            self.assertEqual({p.name for p in Path(root).iterdir()}, {"selected"})
            for name in specification["binaries"]:
                self.assertEqual((destination / name).read_bytes(), files[name])
                self.assertEqual((destination / name).stat().st_nlink, 1)
                if os.name == "posix":
                    self.assertEqual((destination / name).stat().st_mode & 0o777, 0o400)

    def test_helper_metadata_is_read_but_not_materialized(self):
        raw, specification = helper([("source-inputs/adapter.txt", b"source", stat.S_IFREG)])
        with tempfile.TemporaryDirectory(prefix="owned-input-control-") as root:
            result = self.unpack(raw, specification, Path(root) / "selected", "parent_oracle")
            self.assertEqual(result.verify(), specification["binaries"])
            self.assertEqual(len(list(result.directory.iterdir())), 1)

    def test_archive_digest_and_length_are_checked_before_output_creation(self):
        raw, specification, _ = consumer()
        for changed in (raw[:-1], raw + b"x", bytes([raw[0] ^ 1]) + raw[1:]):
            with self.subTest(size=len(changed)):
                self.refusal(changed, specification)

    def test_inner_and_decoded_digests_are_both_required(self):
        raw, specification, _ = consumer()
        for field in ("payload", "decoded_tar"):
            selected = json.loads(json.dumps(specification))
            selected[field]["sha256"] = "1" * 64
            with self.subTest(field=field):
                self.refusal(raw, selected)

    def test_truncated_and_concatenated_xz_are_refused(self):
        raw, specification, _ = consumer()
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            encoded = archive.read("candidate-v1.tar.xz")
        for changed in (encoded[:-8], encoded + encoded, encoded + b"trailing"):
            with self.subTest(bytes=len(changed)):
                candidate, selected, _ = consumer(encoded=changed)
                self.refusal(candidate, selected)

    def test_decoded_size_limit_stops_expansion(self):
        raw, specification, _ = consumer()
        specification["decoded_tar"]["bytes"] = 512
        self.refusal(raw, specification, reason="xz_decoded_bound")

    def test_tar_members_cannot_select_links_extensions_or_other_paths(self):
        _, _, files = consumer()
        for name, kind in (("../fetch-bundle", tarfile.REGTYPE),
                           ("foreign", tarfile.REGTYPE),
                           ("fetch-bundle", tarfile.SYMTYPE),
                           ("fetch-bundle", tarfile.LNKTYPE),
                           ("fetch-bundle", tarfile.FIFOTYPE),
                           ("fetch-bundle", tarfile.XHDTYPE)):
            with self.subTest(name=name, kind=repr(kind)):
                rows = [(name, b"", kind), *[(n, b, tarfile.REGTYPE) for n, b in files.items()]]
                raw, specification, _ = consumer(rows=rows)
                self.refusal(raw, specification)

    def test_tar_requires_exact_members_without_duplicates(self):
        _, _, files = consumer()
        rows = [(n, b, tarfile.REGTYPE) for n, b in sorted(files.items())]
        for changed in (rows[:-1], rows + rows[:1]):
            raw, specification, _ = consumer(rows=changed)
            self.refusal(raw, specification)

    def test_tar_padding_and_hidden_second_payload_are_refused(self):
        raw, _, _ = consumer()
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            decoded = lzma.decompress(archive.read("candidate-v1.tar.xz"))
        first = tarfile.TarInfo.frombuf(decoded[:512], "utf-8", "strict")
        changed = bytearray(decoded)
        self.assertNotEqual(first.size % 512, 0)
        changed[512 + first.size] = 1
        for value in (bytes(changed), decoded + b"hidden"):
            candidate, selected, _ = consumer(decoded=value)
            self.refusal(candidate, selected)

    def test_consumer_zip_requires_one_stored_payload(self):
        raw, specification, _ = consumer(compression=zipfile.ZIP_DEFLATED)
        self.refusal(raw, specification, reason="consumer_zip_closure")
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            payload = archive.read("candidate-v1.tar.xz")
        raw = zip_bytes([("candidate-v1.tar.xz", payload, stat.S_IFREG),
                         ("extra.txt", b"extra", stat.S_IFREG)])
        specification["archive"] = pin(raw)
        self.refusal(raw, specification, reason="consumer_zip_closure")

    def test_zip_paths_aliases_and_nonregular_metadata_are_refused_in_memory(self):
        for name, mode in (("../outside", stat.S_IFREG), ("a\\b", stat.S_IFREG),
                           ("truncated\0suffix", stat.S_IFREG),
                           ("/absolute", stat.S_IFREG), ("a:b", stat.S_IFREG),
                           ("alias", stat.S_IFLNK), ("pipe", stat.S_IFIFO),
                           ("socket", stat.S_IFSOCK), ("dir/", stat.S_IFDIR),
                           ("MANIFEST.JSON", stat.S_IFREG), ("manifest.json", stat.S_IFREG)):
            with self.subTest(name=name, mode=mode):
                raw, specification = helper([(name, b"unselected", mode)])
                self.refusal(raw, specification, "parent_oracle")

    def test_zip_directory_bound_comments_and_trailing_bytes(self):
        raw, specification = helper()
        inflated = bytearray(raw)
        struct.pack_into("<HH", inflated, len(raw) - 14, inputs.MAX_MEMBERS + 1,
                         inputs.MAX_MEMBERS + 1)
        comment = zip_bytes([("spv-closed-parent-oracle.exe", elf(), stat.S_IFREG)], comment=b"x")
        for changed in (bytes(inflated), comment, raw + b"suffix"):
            with self.subTest(bytes=len(changed)):
                specification["archive"] = pin(changed)
                self.refusal(changed, specification, "parent_oracle", "zip_directory")

    def test_binary_digest_size_and_architecture_are_required(self):
        raw, original = helper()
        for field, value in (("sha256", "2" * 64), ("bytes", len(elf()) - 1)):
            specification = json.loads(json.dumps(original))
            specification["binaries"]["spv-closed-parent-oracle.exe"][field] = value
            self.refusal(raw, specification, "parent_oracle")
        changed = bytearray(elf())
        struct.pack_into("<H", changed, 18, 183)
        for binary in (b"not an ELF binary", bytes(changed)):
            raw, specification = helper(selected=binary)
            self.refusal(raw, specification, "parent_oracle", "linux_amd64_binary_header")

    def test_intake_never_adopts_or_overwrites_a_destination(self):
        raw, specification = helper()
        with tempfile.TemporaryDirectory(prefix="owned-input-control-") as root:
            for directory in (False, True):
                path = Path(root) / ("existing-directory" if directory else "existing-file")
                path.mkdir() if directory else path.write_bytes(b"preserve")
                if directory:
                    (path / "foreign").write_bytes(b"preserve")
                with self.assertRaisesRegex(model.Refused, "binary_directory_exists"):
                    self.unpack(raw, specification, path, "parent_oracle")
                self.assertEqual((path / "foreign" if directory else path).read_bytes(), b"preserve")

    def test_equal_bytes_replacement_is_not_the_original_file(self):
        raw, specification = helper()
        with tempfile.TemporaryDirectory(prefix="owned-input-control-") as root:
            result = self.unpack(raw, specification, Path(root) / "selected", "parent_oracle")
            path = result.directory / "spv-closed-parent-oracle.exe"
            original = path.read_bytes()
            path.rename(Path(root) / "retained-original")
            path.write_bytes(original)
            with self.assertRaisesRegex(model.Refused, "binary_file_changed"):
                result.verify()

    def test_in_place_changes_cannot_be_hidden_by_restoring_mtime(self):
        raw, specification = helper()
        with tempfile.TemporaryDirectory(prefix="owned-input-control-") as root:
            result = self.unpack(raw, specification, Path(root) / "selected", "parent_oracle")
            path = result.directory / "spv-closed-parent-oracle.exe"
            before = path.stat()
            path.chmod(0o600)
            path.write_bytes(elf(b"changed"))
            self.assertEqual(path.stat().st_size, before.st_size)
            os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
            with self.assertRaisesRegex(model.Refused, "binary_file_changed"):
                result.verify()

    def test_execution_mode_is_a_separate_action_after_complete_verification(self):
        raw, specification, _ = consumer()
        with tempfile.TemporaryDirectory(prefix="owned-input-control-") as root:
            result = self.unpack(raw, specification, Path(root) / "selected")
            identities = [p.stat().st_ino for p in sorted(result.directory.iterdir())]
            if os.name == "posix":
                result.enable_execution()
                self.assertEqual([p.stat().st_mode & 0o777 for p in result.directory.iterdir()],
                                 [0o500, 0o500])
                self.assertEqual([p.stat().st_ino for p in sorted(result.directory.iterdir())], identities)
            else:
                with self.assertRaisesRegex(model.Refused, "binary_execution_platform"):
                    result.enable_execution()
            self.assertEqual(result.verify(), specification["binaries"])

    def test_pin_types_and_selection_are_strict(self):
        raw, specification = helper()
        for field in ("run_id", "run_attempt", "artifact_id"):
            selected = json.loads(json.dumps(specification))
            selected[field] = True
            self.refusal(raw, selected, "parent_oracle")
        selected = json.loads(json.dumps(specification))
        selected["binaries"]["other-binary"] = pin(elf())
        self.refusal(raw, selected, "parent_oracle", "binary_selection")


    def test_read_only_intake_checks_both_components_without_output_objects(self):
        raw_consumer, consumer_spec, _ = consumer()
        raw_helper, helper_spec = helper()
        with mock.patch.object(inputs, "_Outputs", side_effect=AssertionError("unexpected materialization")):
            for kind, raw, selected in (("consumer", raw_consumer, consumer_spec),
                                        ("parent_oracle", raw_helper, helper_spec)):
                with self.subTest(kind=kind):
                    self.assertEqual(inputs.verify_binaries(io.BytesIO(raw), kind, selected),
                                     selected["binaries"])
                    with self.assertRaisesRegex(model.Refused, "archive_size|archive_digest"):
                        inputs.verify_binaries(io.BytesIO(raw[:-1]), kind, selected)

    def test_read_only_intake_checks_the_selected_binary_pin(self):
        raw, selected = helper()
        selected["binaries"]["spv-closed-parent-oracle.exe"]["sha256"] = "a" * 64
        with self.assertRaisesRegex(model.Refused, "binary_digest"):
            inputs.verify_binaries(io.BytesIO(raw), "parent_oracle", selected)

    def test_read_only_cli_emits_bound_pins_and_keeps_only_the_original_zip(self):
        raw, selected = helper()
        contract = model.Contract(model.canonical({"qualified_components": {
            "source_revision": "a" * 40, "parent_oracle": selected}}), "b" * 64)
        with tempfile.TemporaryDirectory(prefix="owned-input-control-") as root:
            archive = Path(root) / "source.zip"
            archive.write_bytes(raw)
            args = ["--component", "parent_oracle", "--archive", str(archive)]
            output, error = io.BytesIO(), io.StringIO()
            with mock.patch.object(inputs, "read_contract", return_value=contract):
                self.assertEqual(inputs.main(args, stdout=output, stderr=error), 0)
                report = json.loads(output.getvalue())
                self.assertEqual(report["contract_sha256"], contract.sha256)
                self.assertEqual(report["artifact_id"], selected["artifact_id"])
                self.assertEqual(report["binaries"], selected["binaries"])
                self.assertEqual(report["materialized_binary_bytes"], 0)
                self.assertFalse(report["ci_metadata_verified"])
                self.assertEqual(error.getvalue(), "")
                self.assertEqual(list(Path(root).iterdir()), [archive])
                archive.write_bytes(raw[:-1])
                refused = io.BytesIO()
                self.assertEqual(inputs.main(args, stdout=refused, stderr=error), 2)
                self.assertEqual(refused.getvalue(), b"")
                self.assertNotIn(str(archive), error.getvalue())

    def test_read_only_intake_refuses_equal_bytes_under_a_replaced_path(self):
        raw, selected = helper()
        with tempfile.TemporaryDirectory(prefix="owned-input-control-") as root:
            archive = Path(root) / "source.zip"
            replacement = Path(root) / "replacement.zip"
            archive.write_bytes(raw)
            replacement.write_bytes(raw)
            identities = [archive.lstat(), replacement.lstat()]
            self.assertFalse(os.path.samestat(*identities))
            with mock.patch.object(Path, "lstat", side_effect=identities):
                with self.assertRaisesRegex(model.Refused, "archive_file_changed"):
                    inputs._verify_archive_file(archive, "parent_oracle", selected)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-revision")
    arguments = parser.parse_args()
    if arguments.source_revision is not None:
        model.digest(arguments.source_revision, model.HEX40)
    suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
    result = unittest.TextTestRunner(stream=sys.stderr, verbosity=2).run(suite)
    receipt = {"format": "owned-devnet-query-input-controls/v1",
               "source_revision": arguments.source_revision, "root_tests": result.testsRun,
               "errors": len(result.errors), "failures": len(result.failures),
               "skipped": len(result.skipped), "successful": result.wasSuccessful(),
               "network_or_binary_or_engine_or_signing_executed": False,
               "synthetic_archives_only": True}
    sys.stdout.buffer.write(model.canonical(receipt))
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
