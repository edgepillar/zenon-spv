#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Bounded format controls; synthetic payloads are not native CI evidence."""
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import lzma
from pathlib import Path
import struct
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
import zipfile
import zlib

sys.dont_write_bytecode = True


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


original = load("stream_original_fixture", "check-candidate-archive_test.py")
checker = original.checker
stream = load("candidate_stream_controls", "candidate_stream.py")
packer = load("candidate_stream_packer_controls", "pack-candidate-stream.py")


class Members:
    def __init__(self, files):
        self.files, self.opened = files, []

    @contextlib.contextmanager
    def open(self, info):
        self.opened.append(info.filename)
        with io.BytesIO(self.files[info.filename]) as source:
            yield source


def fixture(os_name="linux", complete=True):
    files, manifest, report = original.fixture(os_name)
    if complete:
        report["schema_version"] = 2
        report["skip_ledger"] = {"schema_version": 1, "coverage": "complete", "records": []}
    raw = original.pack(files, manifest, report)
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        files = {i.filename: archive.read(i) for i in archive.infolist()}
    suffix = ".exe" if os_name == "windows" else ""
    names = ("manifest.json", "offline-pilot.json") + tuple(c + suffix for c in checker.COMMANDS)
    limits = {c + suffix: checker.BINARY_LIMIT for c in checker.COMMANDS}
    limits.update({"manifest.json": 256 << 10, "offline-pilot.json": 4 << 20})
    infos = {name: SimpleNamespace(filename=name, file_size=len(data)) for name, data in files.items()}
    return raw, files, names, limits, infos


def validate(members, infos, os_name="linux", complete=True, revision=original.REVISION,
             inputs=original.INPUTS):
    return checker.check_payloads(members, infos, revision, inputs, os_name, "amd64",
                                  require_skip_ledger=complete)


def encode(os_name="linux", complete=True):
    _, files, names, limits, infos = fixture(os_name, complete)
    output = io.BytesIO()
    result = stream.write_checked(Members(files), infos, names, limits, output,
        lambda m, i: validate(m, i, os_name, complete))
    return output.getvalue(), result, names, limits


def decode(raw, os_name="linux", complete=True, names=None, limits=None):
    if names is None:
        _, _, names, limits, _ = fixture(os_name, complete)
    with stream.open_payload(io.BytesIO(raw), len(raw), names, limits) as (members, infos):
        return validate(members, infos, os_name, complete)


def compress(raw, check=lzma.CHECK_CRC64):
    return lzma.compress(raw, format=lzma.FORMAT_XZ, check=check, preset=1)


def envelope(raw, compression=zipfile.ZIP_STORED, extra=None):
    target = io.BytesIO()
    with zipfile.ZipFile(target, "w", compression=compression) as archive:
        archive.writestr(stream.PAYLOAD_NAME, raw)
        if extra:
            archive.writestr(*extra)
    return target.getvalue()


class CandidateStreamControls(unittest.TestCase):
    def test_complete_roundtrip_all_selected_payload_platforms(self):
        for platform in ("linux", "darwin", "windows"):
            with self.subTest(platform=platform):
                raw, result, _, _ = encode(platform)
                self.assertEqual(decode(raw, platform), result["verification"])
                self.assertEqual(result["payload"], {"bytes": len(raw), "sha256": original.sha(raw)})
                self.assertEqual(result["decoded"], {"bytes": len(lzma.decompress(raw)),
                                                     "sha256": original.sha(lzma.decompress(raw))})
                self.assertTrue(result["output_complete"])
                self.assertEqual(result["members"], 9)

    def test_same_inputs_produce_same_complete_encoded_bytes(self):
        first, _, _, _ = encode()
        second, _, _, _ = encode()
        self.assertEqual(first, second)

    def test_direct_legacy_zip_contract_remains_available(self):
        for platform in ("linux", "darwin", "windows"):
            raw, _, _, _, _ = fixture(platform)
            result = checker.check_contents(io.BytesIO(raw), original.REVISION, original.INPUTS,
                                            platform, "amd64", require_skip_ledger=True)
            self.assertEqual((result["status"], result["binaries"]), ("verified", 7))

    def test_existing_scenario_companion_accepts_selected_reader(self):
        companion = load("stream_scenario_companion_controls", "check-scenario-inventory.py")
        companion.dependencies_intact()
        self.assertTrue(callable(companion.primitives().checker.check_payloads))

    def test_new_envelope_uses_the_same_payload_verifier(self):
        for platform in ("linux", "darwin", "windows"):
            raw, expected, _, _ = encode(platform)
            result = checker.check_contents(io.BytesIO(envelope(raw)), original.REVISION,
                                            original.INPUTS, platform, "amd64", require_skip_ledger=True)
            self.assertEqual(result, expected["verification"])

    def test_selected_raw_file_matches_existing_payload_validation(self):
        for platform in ("linux", "darwin", "windows"):
            with self.subTest(platform=platform), tempfile.TemporaryDirectory() as directory:
                raw, expected, _, _ = encode(platform)
                selected = Path(directory) / "selected.tar.xz"
                selected.write_bytes(raw)
                result = checker.check(selected, original.sha(raw), original.REVISION, original.INPUTS,
                                       platform, "amd64", require_skip_ledger=True, raw_stream=True)
                self.assertEqual(result, expected["verification"])
                self.assertEqual(selected.read_bytes(), raw)
                self.assertEqual(set(Path(directory).iterdir()), {selected})

    def test_raw_file_format_is_selected_explicitly(self):
        raw, _, _, _ = encode()
        legacy, _, _, _, _ = fixture()
        controls = ((raw, False), (legacy, True), (envelope(raw), True))
        with tempfile.TemporaryDirectory() as directory:
            selected = Path(directory) / "selected"
            for data, raw_mode in controls:
                selected.write_bytes(data)
                with self.subTest(raw_mode=raw_mode, size=len(data)), self.assertRaises(checker.Rejected):
                    checker.check(selected, original.sha(data), original.REVISION, original.INPUTS,
                                  "linux", "amd64", raw_stream=raw_mode)

    def test_raw_cli_preserves_selected_hash_source_skip_and_eof_checks(self):
        raw, _, _, _ = encode()
        incomplete, _, _, _ = encode(complete=False)
        with tempfile.TemporaryDirectory() as directory:
            selected = Path(directory) / "PRIVATE_selected.tar.xz"
            def invoke(data, revision=original.REVISION, inputs=original.INPUTS, digest=None):
                selected.write_bytes(data)
                output = io.StringIO()
                code = checker.main(["--archive", str(selected), "--expect-archive-sha256",
                                     original.sha(data) if digest is None else digest,
                                     "--expect-revision", revision, "--expect-inputs", inputs,
                                     "--expect-os", "linux", "--expect-architecture", "amd64",
                                     "--raw-stream", "--require-skip-ledger"], output)
                self.assertNotIn("PRIVATE", output.getvalue())
                self.assertNotIn(directory, output.getvalue())
                return code, json.loads(output.getvalue())
            code, result = invoke(raw)
            self.assertEqual((code, result["status"], result["binaries"]), (0, "verified", 7))
            code, result = invoke(raw, digest="a" * 64)
            self.assertEqual((code, result["category"]), (2, "archive_pin"))
            for data in (raw[:-1], raw + b"x", raw + raw, incomplete, b""):
                with self.subTest(size=len(data)):
                    self.assertEqual(invoke(data)[0], 2)
            for revision, inputs in (("a" * 40, original.INPUTS), (original.REVISION, "a" * 64)):
                with self.subTest(revision=revision, inputs=inputs):
                    self.assertEqual(invoke(raw, revision, inputs)[0], 2)

    def test_raw_mode_arguments_refuse_before_opening_and_do_not_echo(self):
        for value in (None, 0, 1, "true"):
            with self.subTest(value=value), mock.patch.object(checker, "regular_archive") as opened:
                with self.assertRaises(checker.Rejected) as failure:
                    checker.check(Path("PRIVATE"), "a" * 64, original.REVISION, original.INPUTS,
                                  "linux", "amd64", raw_stream=value)
                self.assertEqual(failure.exception.category, "arguments")
                opened.assert_not_called()
        args = ["--archive", "PRIVATE", "--expect-archive-sha256", "a" * 64,
                "--expect-revision", original.REVISION, "--expect-inputs", original.INPUTS,
                "--expect-os", "linux", "--expect-architecture", "amd64"]
        for extra in (("--raw-stream", "--raw-stream"), ("--raw-stream=true",)):
            with mock.patch.object(checker, "check") as opened:
                output = io.StringIO()
                self.assertEqual(checker.main(args + list(extra), output), 64)
                self.assertNotIn("PRIVATE", output.getvalue())
                opened.assert_not_called()

    def test_wrong_source_and_complete_skip_requirements_remain_refusals(self):
        raw, _, _, _ = encode()
        for revision, inputs in (("a" * 40, original.INPUTS), (original.REVISION, "a" * 64)):
            with self.subTest(revision=revision, inputs=inputs), self.assertRaises(checker.Rejected):
                checker.check_contents(io.BytesIO(envelope(raw)), revision, inputs, "linux", "amd64", True)
        legacy, _, _, _ = encode(complete=False)
        with self.assertRaises(checker.Rejected):
            checker.check_contents(io.BytesIO(envelope(legacy)), original.REVISION, original.INPUTS,
                                   "linux", "amd64", True)

    def test_corruption_truncation_trailing_data_and_multiple_streams_refuse(self):
        raw, _, _, _ = encode()
        changed = bytearray(raw)
        changed[len(changed) // 2] ^= 1
        samples = [raw[:1], raw[:12], raw[:-1], raw[:-8], raw + b"x", raw + raw, bytes(changed)]
        for sample in samples:
            with self.subTest(bytes=len(sample)), self.assertRaises((stream.StreamRejected, checker.Rejected)):
                decode(sample)

    def test_xz_integrity_kind_is_explicit(self):
        raw, _, _, _ = encode()
        plain = lzma.decompress(raw)
        for check in (lzma.CHECK_NONE, lzma.CHECK_CRC32, lzma.CHECK_SHA256):
            if not lzma.is_check_supported(check):
                continue
            with self.subTest(check=check), self.assertRaises(stream.StreamRejected):
                decode(compress(plain, check))

    def test_dictionary_exceeding_decoder_budget_refuses_before_payload(self):
        raw, _, _, _ = encode()
        changed = bytearray(raw)
        size = (changed[12] + 1) * 4
        self.assertEqual(changed[14:16], b"\x21\x01")
        changed[16] = 40  # Declared 4 GiB LZMA2 dictionary; no such fixture is allocated.
        struct.pack_into("<I", changed, 12 + size - 4, zlib.crc32(changed[12:12 + size - 4]))
        with self.assertRaises(stream.StreamRejected):
            decode(bytes(changed))

    def test_noncanonical_tar_metadata_and_types_refuse(self):
        raw, _, _, _ = encode()
        plain = lzma.decompress(raw)
        mutations = {"name": "../manifest.json", "mode": 0o644, "uid": 1, "gid": 1,
                     "mtime": 1, "uname": "other", "gname": "other", "linkname": "target",
                     "type": tarfile.SYMTYPE, "size": 0}
        for key, value in mutations.items():
            item = tarfile.TarInfo.frombuf(plain[:512], "ascii", "strict")
            setattr(item, key, value)
            changed = item.tobuf(format=tarfile.USTAR_FORMAT, encoding="ascii") + plain[512:]
            with self.subTest(field=key), self.assertRaises(stream.StreamRejected):
                decode(compress(changed))
        for kind in (tarfile.LNKTYPE, tarfile.FIFOTYPE, tarfile.DIRTYPE, tarfile.XHDTYPE,
                     tarfile.GNUTYPE_LONGNAME, tarfile.AREGTYPE):
            item = tarfile.TarInfo.frombuf(plain[:512], "ascii", "strict")
            item.type = kind
            with self.subTest(kind=kind), self.assertRaises(stream.StreamRejected):
                decode(compress(item.tobuf(format=tarfile.USTAR_FORMAT) + plain[512:]))

    def test_member_order_padding_footer_and_additional_members_refuse(self):
        raw, _, names, _ = encode()
        plain = lzma.decompress(raw)
        first = tarfile.TarInfo.frombuf(plain[:512], "ascii", "strict")
        after = 512 + first.size + (-first.size % 512)
        second = tarfile.TarInfo.frombuf(plain[after:after + 512], "ascii", "strict")
        second.name = names[0]
        samples = [plain[after:], plain[:after] + second.tobuf(format=tarfile.USTAR_FORMAT) + plain[after + 512:],
                   plain[:-1], plain + b"\0" * 512]
        changed = bytearray(plain)
        self.assertGreater(-first.size % 512, 0)
        changed[512 + first.size] = 1
        samples.append(bytes(changed))
        changed = bytearray(plain)
        changed[-1] = 1
        samples.append(bytes(changed))
        for sample in samples:
            with self.subTest(bytes=len(sample)), self.assertRaises((stream.StreamRejected, checker.Rejected)):
                decode(compress(sample))

    def test_encoded_size_is_typed_bounded_and_exact(self):
        raw, _, names, limits = encode()
        for size in (False, True, 0, -1, stream.TOTAL_LIMIT + 1, len(raw) - 1, len(raw) + 1):
            with self.subTest(size=size), self.assertRaises(stream.StreamRejected):
                with stream.open_payload(io.BytesIO(raw), size, names, limits) as (members, infos):
                    validate(members, infos)

    def test_declared_and_observed_total_bounds_refuse(self):
        raw, _, names, limits = encode()
        with mock.patch.object(stream, "TOTAL_LIMIT", 32), self.assertRaises(stream.StreamRejected):
            decode(raw, names=names, limits=limits)
        _, files, names, limits, infos = fixture()
        infos[names[0]].file_size = limits[names[0]] + 1
        with self.assertRaises(stream.StreamRejected):
            stream.write_checked(Members(files), infos, names, limits, io.BytesIO(), validate)
        decoder = stream._Decoded(io.BytesIO(raw), len(raw))
        with mock.patch.object(stream, "TOTAL_LIMIT", len(raw) + 1), self.assertRaises(stream.StreamRejected):
            decoder.read(stream.PIECE)
        _, files, names, limits, infos = fixture()
        for name in names[2:4]:
            infos[name].file_size = checker.BINARY_LIMIT
        with self.assertRaises(stream.StreamRejected):
            stream.write_checked(Members(files), infos, names, limits, io.BytesIO(), validate)

    def test_unexpected_or_unconsumed_members_do_not_finalize(self):
        _, files, names, limits, infos = fixture()
        callbacks = [lambda m, i: {"status": "verified", "binaries": 7},
                     lambda m, i: {"status": "rejected", "binaries": 7},
                     lambda m, i: {"status": "verified", "binaries": True}]
        for callback in callbacks:
            output = io.BytesIO()
            with self.subTest(callback=callbacks.index(callback)), self.assertRaises(stream.StreamRejected):
                stream.write_checked(Members(files), infos, names, limits, output, callback)
            decoder = lzma.LZMADecompressor()
            decoder.decompress(output.getvalue())
            self.assertFalse(decoder.eof)

    def test_member_views_refuse_reuse_foreign_info_and_unbounded_read(self):
        raw, _, names, limits = encode()
        with stream.open_payload(io.BytesIO(raw), len(raw), names, limits) as (members, infos):
            with self.assertRaises(stream.StreamRejected):
                with members.open(None):
                    pass
            with self.assertRaises(stream.StreamRejected):
                _ = infos[names[1]]
            info = infos[names[0]]
            with self.assertRaises(stream.StreamRejected):
                with members.open(SimpleNamespace(filename=info.filename, file_size=info.file_size)):
                    pass
            with members.open(info) as first:
                for size in (-1, True, None, stream.READ_LIMIT + 1):
                    with self.subTest(size=size), self.assertRaises(stream.StreamRejected):
                        first.read(size)
                first.read(info.file_size)
            with self.assertRaises(stream.StreamRejected):
                _ = infos[names[0]]
            for name in names[1:]:
                info = infos[name]
                with members.open(info) as source:
                    source.read(info.file_size)

    def test_failed_postcheck_does_not_emit_a_complete_xz(self):
        _, files, names, limits, infos = fixture()
        output = io.BytesIO()
        def fail():
            raise OSError("private source changed")
        with self.assertRaises(OSError):
            stream.write_checked(Members(files), infos, names, limits, output, validate, fail)
        decoder = lzma.LZMADecompressor()
        decoder.decompress(output.getvalue())
        self.assertFalse(decoder.eof)

    def test_writer_source_length_and_read_bounds_are_preserved(self):
        _, files, names, limits, infos = fixture()
        for changed in (files[names[0]][:-1], files[names[0]] + b"x"):
            selected = dict(files, **{names[0]: changed})
            with self.subTest(bytes=len(changed)), self.assertRaises((stream.StreamRejected, checker.Rejected)):
                stream.write_checked(Members(selected), infos, names, limits, io.BytesIO(), validate)
        for size in (-1, True, None, stream.READ_LIMIT + 1):
            def invalid(members, selected):
                with members.open(selected[names[0]]) as source:
                    source.read(size)
            with self.subTest(size=size), self.assertRaises(stream.StreamRejected):
                stream.write_checked(Members(files), infos, names, limits, io.BytesIO(), invalid)

    def test_foreign_writer_member_and_replaced_source_cannot_complete(self):
        _, files, names, limits, infos = fixture()
        def foreign(members, selected):
            with members.open(SimpleNamespace(filename=names[0], file_size=selected[names[0]].file_size)):
                pass
        with self.assertRaises(stream.StreamRejected):
            stream.write_checked(Members(files), infos, names, limits, io.BytesIO(), foreign)
        events = []
        @contextlib.contextmanager
        def opened(*args):
            yield Members(files), infos
            events.append("closed")
        output = io.BytesIO()
        with mock.patch.object(packer.exported, "source_pin", side_effect=[original.INPUTS, "d" * 64]), \
                mock.patch.object(packer.exported, "opened_candidate", side_effect=opened), \
                self.assertRaises(packer.checker.Rejected):
            packer.pack(Path("unused"), Path("unused"), original.REVISION, "linux", "amd64", output, True)
        self.assertEqual(events, ["closed"])
        decoder = lzma.LZMADecompressor()
        decoder.decompress(output.getvalue())
        self.assertFalse(decoder.eof)

    def test_short_or_failed_binary_output_refuses(self):
        _, files, names, limits, infos = fixture()
        class Short(io.BytesIO):
            def write(self, raw):
                super().write(raw)
                return len(raw) - 1
        class Failed(io.BytesIO):
            def write(self, raw):
                raise OSError("private output failed")
        for output in (Short(), Failed(), io.StringIO()):
            with self.subTest(kind=type(output).__name__), self.assertRaises(stream.OutputFailure):
                stream.write_checked(Members(files), infos, names, limits, output, validate)

    def test_envelope_has_one_stored_ordinary_payload_only(self):
        raw, _, _, _ = encode()
        for data in (envelope(raw, zipfile.ZIP_DEFLATED), envelope(raw, extra=("extra", b"x"))):
            with self.assertRaises(checker.Rejected):
                checker.check_contents(io.BytesIO(data), original.REVISION, original.INPUTS, "linux", "amd64", True)

    def test_packer_rechecks_source_and_descriptor_scope_before_finalizing(self):
        _, files, names, _, infos = fixture()
        events = []
        @contextlib.contextmanager
        def opened(*args):
            events.append("opened")
            yield Members(files), infos
            events.append("checked-and-closed")
        output = io.BytesIO()
        with mock.patch.object(packer.exported, "source_pin", side_effect=lambda *a: events.append("source") or original.INPUTS), \
                mock.patch.object(packer.exported, "opened_candidate", side_effect=opened):
            result = packer.pack(Path("unused"), Path("unused"), original.REVISION, "linux", "amd64", output, True)
        self.assertEqual(events, ["source", "opened", "checked-and-closed", "source"])
        self.assertEqual(result["verification"], decode(output.getvalue()))
        self.assertEqual(names[:2], ("manifest.json", "offline-pilot.json"))

    def test_actual_exported_files_use_the_existing_descriptor_checks(self):
        for platform in ("linux", "darwin", "windows"):
            with self.subTest(platform=platform), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                _, files, _, _, _ = fixture(platform)
                for name, raw in files.items():
                    (root / name).write_bytes(raw)
                def snapshot(path):
                    info = path.stat()
                    # Reads may update atime on some filesystems.
                    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
                            info.st_size, info.st_mtime_ns, info.st_ctime_ns, path.read_bytes())
                before = {p.name: snapshot(p) for p in root.iterdir()}
                output = io.BytesIO()
                # Source-root qualification has separate existing filesystem controls.
                # Keep the actual exported-directory and opened-descriptor path here.
                with mock.patch.object(packer.exported, "source_pin", return_value=original.INPUTS):
                    result = packer.pack(root, root, original.REVISION, platform, "amd64", output, True)
                self.assertEqual(result["verification"], decode(output.getvalue(), platform))
                after = {p.name: snapshot(p) for p in root.iterdir()}
                self.assertEqual(set(before), set(after))
                for name in before:
                    self.assertEqual(before[name], after[name])

    def test_packer_cli_has_binary_stdout_and_private_safe_failures(self):
        options = ["--directory", "PRIVATE", "--expect-revision", original.REVISION,
                   "--expect-os", "linux", "--expect-architecture", "amd64"]
        output, errors = io.BytesIO(), io.StringIO()
        with mock.patch.object(packer, "pack", side_effect=OSError("PRIVATE failure")):
            self.assertEqual(packer.main(options, output, errors), 2)
        self.assertNotIn("PRIVATE", errors.getvalue())
        self.assertEqual(output.getvalue(), b"")
        for extra in (("--expect-os", "linux"), ("--unknown", "PRIVATE")):
            with mock.patch.object(packer, "pack") as called:
                self.assertEqual(packer.main(options + list(extra), io.BytesIO(), io.StringIO()), 64)
                called.assert_not_called()

    def test_missing_optional_codec_does_not_change_legacy_zip_reading(self):
        raw, _, _, _, _ = fixture()
        with mock.patch.object(checker.importlib.util, "spec_from_file_location", side_effect=ImportError("PRIVATE codec")):
            result = checker.check_contents(io.BytesIO(raw), original.REVISION, original.INPUTS, "linux", "amd64", True)
        self.assertEqual(result["status"], "verified")
        errors = io.StringIO()
        with mock.patch.object(packer, "stream", None), mock.patch.object(packer, "pack") as called:
            self.assertEqual(packer.main([], io.BytesIO(), errors), 2)
        called.assert_not_called()
        self.assertNotIn("PRIVATE", errors.getvalue())

    def test_packer_output_and_flush_failures_are_not_success(self):
        options = ["--directory", "unused", "--expect-revision", original.REVISION,
                   "--expect-os", "linux", "--expect-architecture", "amd64"]
        with mock.patch.object(packer, "pack", side_effect=packer.stream.OutputFailure("PRIVATE write")):
            errors = io.StringIO()
            self.assertEqual(packer.main(options, io.BytesIO(), errors), 70)
            self.assertNotIn("PRIVATE", errors.getvalue())
        class Flush(io.BytesIO):
            def flush(self):
                raise OSError("PRIVATE flush")
        with mock.patch.object(packer, "pack", return_value={}):
            errors = io.StringIO()
            self.assertEqual(packer.main(options, Flush(), errors), 70)
            self.assertNotIn("PRIVATE", errors.getvalue())


if __name__ == "__main__":
    unittest.main(verbosity=2)
