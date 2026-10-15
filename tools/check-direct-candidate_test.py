"""Direct/ZIP parity and bounded, read-only candidate descriptor controls.

All payloads are opaque synthetic data, not executable or network evidence.
"""

import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock
import zipfile
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


EXPORT = load("direct_candidate_export", "check-exported-candidate.py")
FIXTURES = load("direct_candidate_fixtures", "check-candidate-archive_test.py")
CHECK = EXPORT.checker


def payloads(os_name="linux", binary_bytes=None):
    files, manifest, report = FIXTURES.fixture(os_name)
    if binary_bytes is not None:
        for record in manifest["binaries"]:
            raw = (record["command"].encode() + b"\0\xff")
            raw = (raw * ((binary_bytes + len(raw) - 1) // len(raw)))[:binary_bytes]
            files[record["filename"]] = raw
            record.update(bytes=len(raw), sha256=FIXTURES.sha(raw))
        selected = {row["command"]: row["sha256"] for row in manifest["binaries"]}
        for case in report["cases"]:
            for binary in case["binaries"]:
                binary["sha256"] = selected[binary["command"]]
    raw = json.dumps(report).encode()
    manifest["report"] = {"filename": "offline-pilot.json", "bytes": len(raw), "sha256": FIXTURES.sha(raw)}
    return files | {"manifest.json": json.dumps(manifest).encode(), "offline-pilot.json": raw}


def write_members(directory, files):
    for name, raw in files.items():
        (directory / name).write_bytes(raw)


def invoke(directory, os_name="linux"):
    output = io.StringIO()
    arguments = ["--directory", str(directory), "--expect-revision", FIXTURES.REVISION,
                 "--expect-os", os_name, "--expect-architecture", "amd64"]
    with mock.patch.object(EXPORT, "source_pin", return_value=FIXTURES.INPUTS):
        code = EXPORT.main(arguments, output)
    raw = output.getvalue()
    assert "PRIVATE" not in raw and str(directory) not in raw
    return code, json.loads(raw)


class ObservedStream:
    def __init__(self, stream, name, totals, short_reads=False, fault=None):
        self.stream, self.name, self.totals = stream, name, totals
        self.short_reads, self.fault = short_reads, fault

    def fileno(self):
        return self.stream.fileno()

    def read(self, size):
        assert type(size) is int and size > 0
        limit = (4 << 20) + 1 if self.name == "offline-pilot.json" else (1 << 20)
        assert size <= limit
        if self.fault:
            raise OSError("PRIVATE_READ_FAILURE")
        raw = self.stream.read(min(size, 37) if self.short_reads else size)
        self.totals[self.name] = self.totals.get(self.name, 0) + len(raw)
        return raw


class DirectCandidateControls(unittest.TestCase):
    def observed_files(self, short_reads=False, fault=None):
        actual, self.descriptors, self.totals = EXPORT.regular_file, [], {}

        @contextlib.contextmanager
        def observed(path, limit, category):
            with actual(path, limit, category) as (stream, size):
                self.descriptors.append(stream.fileno())
                short = short_reads and path.name not in ("manifest.json", "offline-pilot.json")
                yield ObservedStream(stream, path.name, self.totals, short, path.name == fault), size

        return mock.patch.object(EXPORT, "regular_file", side_effect=observed)

    def closed_descriptors(self):
        self.assertTrue(self.descriptors)
        for descriptor in self.descriptors:
            with self.assertRaises(OSError):
                os.fstat(descriptor)

    def test_complete_direct_and_ZIP_results_match_on_three_platforms(self):
        for os_name in ("linux", "darwin", "windows"):
            with self.subTest(os=os_name), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary) / "PRIVATE_CANDIDATE"
                directory.mkdir()
                write_members(directory, payloads(os_name))
                archive = Path(temporary) / "candidate.zip"
                EXPORT.write_archive(directory, archive, os_name)
                expected = CHECK.check(archive, FIXTURES.sha(archive.read_bytes()), FIXTURES.REVISION,
                                       FIXTURES.INPUTS, os_name, "amd64")
                self.assertEqual(invoke(directory, os_name), (0, expected))

    def test_default_verification_creates_no_archive_or_workspace(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            write_members(directory, payloads())
            before = {p.name: (FIXTURES.sha(p.read_bytes()), EXPORT.file_identity(p.stat())) for p in directory.iterdir()}
            with mock.patch.object(EXPORT, "write_archive", side_effect=AssertionError("packaging forbidden")), \
                    mock.patch.object(zipfile, "ZipFile", side_effect=AssertionError("ZIP forbidden")), \
                    mock.patch.object(tempfile, "TemporaryDirectory", side_effect=AssertionError("workspace forbidden")):
                self.assertEqual(invoke(directory)[0], 0)
            self.assertEqual({p.name: (FIXTURES.sha(p.read_bytes()), EXPORT.file_identity(p.stat()))
                              for p in directory.iterdir()}, before)

    def test_realistic_28_MiB_payload_is_streamed_once_without_packaging(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            files = payloads(binary_bytes=4 << 20)
            write_members(directory, files)
            sizes = {name: len(raw) for name, raw in files.items()}
            del files
            with self.observed_files(), mock.patch.object(EXPORT, "write_archive", side_effect=AssertionError("packaging forbidden")):
                self.assertEqual(invoke(directory)[0], 0)
            self.closed_descriptors()
            self.assertEqual(self.totals, sizes)
            self.assertEqual(len(self.descriptors), 9)
            self.assertEqual({p.name for p in directory.iterdir()}, set(sizes))
        print('direct-candidate-stream-controls {"schema_version":1,"opaque_binary_bytes":29360128,'
              '"opened_regular_members":9,"each_member_streamed_once":true,"candidate_ZIP_created":false,'
              '"descriptors_closed":true,"payload_executed":false,"production_budget_qualified":false}')

    def test_short_binary_reads_preserve_complete_hash_and_size_checks(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            files = payloads(binary_bytes=1025)
            write_members(directory, files)
            with self.observed_files(short_reads=True):
                self.assertEqual(invoke(directory)[0], 0)
            self.closed_descriptors()
            self.assertEqual(self.totals, {name: len(raw) for name, raw in files.items()})

    def test_complete_payload_refusal_parity(self):
        mutations = [
            ("manifest_revision", "manifest", lambda m: m["source"].update(revision="d" * 40)),
            ("manifest_modified", "manifest", lambda m: m["source"].update(modified=True)),
            ("manifest_inputs", "manifest", lambda m: m["source"].update(inputs_sha256="d" * 64)),
            ("manifest_platform", "manifest", lambda m: m.update(os="windows")),
            ("manifest_architecture", "manifest", lambda m: m.update(architecture="arm64")),
            ("manifest_Go", "manifest", lambda m: m.update(go_version="PRIVATE_VERSION")),
            ("manifest_extra", "manifest", lambda m: m.update(extra=True)),
            ("manifest_schema_bool", "manifest", lambda m: m.update(schema_version=True)),
            ("manifest_binary_digest", "manifest", lambda m: m["binaries"][0].update(sha256="0" * 64)),
            ("manifest_binary_size", "manifest", lambda m: m["binaries"][0].update(bytes=1)),
            ("manifest_binary_bool", "manifest", lambda m: m["binaries"][0].update(bytes=True)),
            ("manifest_binary_order", "manifest", lambda m: m["binaries"].reverse()),
            ("manifest_corpus_order", "manifest", lambda m: m["corpus"].reverse()),
            ("manifest_report_digest", "manifest", lambda m: m["report"].update(sha256="0" * 64)),
            ("manifest_report_count", "manifest", lambda m: m["report"].update(bytes=1)),
            ("report_status", "report", lambda r: r.update(status="failed")),
            ("report_source", "report", lambda r: r["source"].update(modified=True)),
            ("report_race_type", "report", lambda r: r.update(test_parent_race_enabled=1)),
            ("report_runner", "report", lambda r: r["runner"].update(architecture="arm64")),
            ("report_error", "report", lambda r: r.update(error="PRIVATE_FAILURE")),
            ("report_corpus", "report", lambda r: r["corpus"][0].update(sha256="0" * 64)),
            ("report_execution", "report", lambda r: r["cases"][0]["binaries"][0].update(sha256="0" * 64)),
            ("report_duplicates", "report", lambda r: r["cases"].append(r["cases"][0])),
            ("report_skips", "report", lambda r: r["cases"][0].update(skipped_subtests=1)),
            ("report_failures", "report", lambda r: r["cases"][0].update(failed_subtests=1)),
            ("report_sample_count", "report", lambda r: r["cases"][1]["query_resource_samples"][0]["observations"].pop()),
            ("report_sample_type", "report", lambda r: r["cases"][1]["query_resource_samples"][0]["observations"][0].update(elapsed_ns=True)),
            ("report_memory_scope", "report", lambda r: r["cases"][2]["resource_samples"][0].update(peak_rss_source="PRIVATE_SCOPE")),
        ]
        for name, selected, mutate in mutations:
            with self.subTest(control=name), tempfile.TemporaryDirectory() as temporary:
                files, manifest, report = FIXTURES.fixture()
                if selected == "report":
                    mutate(report)
                raw = FIXTURES.pack(files, manifest, report, mutate_manifest=mutate if selected == "manifest" else None)
                archive = Path(temporary) / "candidate.zip"
                archive.write_bytes(raw)
                directory = Path(temporary) / "PRIVATE_CANDIDATE"
                directory.mkdir()
                with zipfile.ZipFile(io.BytesIO(raw)) as fixture_zip:
                    write_members(directory, {name: fixture_zip.read(name) for name in fixture_zip.namelist()})
                with self.assertRaises(CHECK.Rejected) as failure:
                    CHECK.check(archive, FIXTURES.sha(raw), FIXTURES.REVISION, FIXTURES.INPUTS, "linux", "amd64")
                code, result = invoke(directory)
                self.assertEqual(code, 2)
                self.assertEqual(result["category"], failure.exception.category)
        print('direct-candidate-payload-parity {"schema_version":1,"adverse_controls":28,'
              '"same_refusal_categories":true,"tests_filtered":false}')

    def test_layout_and_per_file_limits_precede_payload_validation(self):
        for mode in ("missing", "extra", "directory", "empty", "metadata_size", "binary_size"):
            with self.subTest(control=mode), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                write_members(directory, payloads())
                path = directory / "zenon-spv"
                if mode == "missing":
                    path.unlink()
                elif mode == "extra":
                    (directory / "PRIVATE_EXTRA").write_bytes(b"extra")
                elif mode == "directory":
                    path.unlink()
                    path.mkdir()
                elif mode == "empty":
                    path.write_bytes(b"")
                else:
                    path = directory / ("manifest.json" if mode == "metadata_size" else "zenon-spv")
                    with path.open("wb") as stream:
                        stream.truncate(((256 << 10) if mode == "metadata_size" else CHECK.BINARY_LIMIT) + 1)
                with mock.patch.object(CHECK, "check_payloads", side_effect=AssertionError("validation before layout")):
                    code, result = invoke(directory)
                self.assertEqual((code, result["category"]), (2, "export"))

    def test_aggregate_limit_is_checked_before_validation_at_exact_boundary(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            files = payloads()
            write_members(directory, files)
            size = sum(map(len, files.values()))
            with mock.patch.object(CHECK, "ARCHIVE_LIMIT", size + (64 << 10)):
                self.assertEqual(invoke(directory)[0], 0)
            with mock.patch.object(CHECK, "ARCHIVE_LIMIT", size + (64 << 10) - 1), self.observed_files(), \
                    mock.patch.object(CHECK, "check_payloads", side_effect=AssertionError("validation before aggregate limit")):
                code, result = invoke(directory)
            self.assertEqual((code, result["category"]), (2, "export"))
            self.closed_descriptors()
            self.assertEqual(self.totals, {})

    def test_read_failure_closes_all_descriptors_and_never_reports_success(self):
        for selected in ("manifest.json", "offline-pilot.json", "zenon-spv"):
            with self.subTest(member=selected), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                write_members(directory, payloads())
                with self.observed_files(fault=selected):
                    code, result = invoke(directory)
                self.closed_descriptors()
                self.assertEqual((code, result["status"], result["category"]), (2, "rejected", "input"))

    def test_member_and_directory_changes_after_read_are_refused(self):
        for mode in ("equal_replacement", "changed_replacement", "in_place", "metadata", "missing", "extra", "root"):
            with self.subTest(control=mode), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary) / "PRIVATE_CANDIDATE"
                directory.mkdir()
                files = payloads()
                write_members(directory, files)
                actual = CHECK.check_payloads

                def change_after_read(*args):
                    result = actual(*args)
                    path = directory / "zenon-spv"
                    if mode.endswith("replacement"):
                        replacement = Path(temporary) / "replacement"
                        raw = files["zenon-spv"]
                        replacement.write_bytes(raw if mode == "equal_replacement" else b"X" * len(raw))
                        os.replace(replacement, path)
                    elif mode == "in_place":
                        path.write_bytes(b"X" * len(files["zenon-spv"]))
                    elif mode == "metadata":
                        info = path.stat()
                        os.utime(path, ns=(info.st_atime_ns, info.st_mtime_ns + 1_000_000_000))
                    elif mode == "missing":
                        path.unlink()
                    elif mode == "extra":
                        (directory / "PRIVATE_EXTRA").write_bytes(b"extra")
                    else:
                        directory.rename(Path(temporary) / "previous")
                        directory.mkdir()
                        write_members(directory, files)
                    return result

                with self.observed_files(), mock.patch.object(CHECK, "check_payloads", side_effect=change_after_read):
                    code, result = invoke(directory)
                self.closed_descriptors()
                self.assertEqual((code, result["status"]), (2, "rejected"))

    def test_member_adapter_refuses_reuse_and_nonselected_info(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            write_members(directory, payloads())
            with self.assertRaises(CHECK.Rejected):
                with EXPORT.opened_candidate(directory, "linux") as (members, infos):
                    info = infos["zenon-spv"]
                    with self.assertRaises(CHECK.Rejected):
                        members.open(type(info)(**vars(info)))
                    with members.open(info):
                        pass
                    with self.assertRaises(CHECK.Rejected):
                        members.open(info)
                    # Successful partial consumption must also fail the context.

    def test_native_path_and_descriptor_metadata_views_stay_stable(self):
        fields = ("st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            write_members(directory, payloads())
            path = directory / "zenon-spv"
            with EXPORT.regular_file(path, CHECK.BINARY_LIMIT, "export") as (stream, _):
                descriptor_before, path_before = os.fstat(stream.fileno()), path.lstat()
                self.assertTrue(os.path.samestat(descriptor_before, path_before))
                stream.read(1)
                self.assertEqual(EXPORT.file_identity(os.fstat(stream.fileno())), EXPORT.file_identity(descriptor_before))
                self.assertEqual(EXPORT.file_identity(path.lstat()), EXPORT.file_identity(path_before))
                native_differences = [field for field in fields if getattr(descriptor_before, field) != getattr(path_before, field)]
            actual_fstat, actual_check = os.fstat, CHECK.check_payloads
            for field in ("st_mode", "st_mtime_ns", "st_ctime_ns"):
                for drift in (False, True):
                    changed = False

                    def descriptor_view(fd):
                        info = actual_fstat(fd)
                        values = {name: getattr(info, name) for name in fields}
                        delta = (2 if changed else 1) * (0o200 if field == "st_mode" else 100)
                        values[field] = values[field] ^ delta if field == "st_mode" else values[field] + delta
                        return SimpleNamespace(**values)

                    def complete_payloads(*args):
                        nonlocal changed
                        result = actual_check(*args)
                        changed = drift
                        return result

                    with self.subTest(field=field, drift=drift), \
                            mock.patch.object(EXPORT.os, "fstat", side_effect=descriptor_view), \
                            mock.patch.object(CHECK, "check_payloads", side_effect=complete_payloads):
                        code, result = invoke(directory)
                    self.assertEqual(code, 2 if drift else 0, result)
                    if drift:
                        self.assertEqual(result["category"], "export")
        print("direct-candidate-metadata-views " + json.dumps({"schema_version": 1,
              "same_file_identity_required": True, "metadata_views_checked_independently": True,
              "synthetic_stable_views": 3, "synthetic_descriptor_drift_refusals": 3,
              "native_differing_fields": native_differences, "native_each_view_stable": True}, separators=(",", ":")))

    @unittest.skipUnless(hasattr(os, "mkfifo"), "native FIFO creation is unavailable")
    def test_fifo_is_refused_before_open(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            write_members(directory, payloads())
            path = directory / "zenon-spv"
            path.unlink()
            os.mkfifo(path, 0o600)
            with mock.patch.object(EXPORT.os, "open", wraps=os.open) as opened:
                code, result = invoke(directory)
            self.assertEqual((code, result["category"]), (2, "export"))
            self.assertFalse(any(Path(call.args[0]) == path for call in opened.call_args_list))
            self.assertTrue(stat.S_ISFIFO(path.lstat().st_mode))

    def test_symbolic_member_and_directory_links_are_refused(self):
        for mode in ("member", "directory"):
            with self.subTest(control=mode), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary) / "candidate"
                directory.mkdir()
                write_members(directory, payloads())
                try:
                    if mode == "member":
                        path = directory / "zenon-spv"
                        path.rename(Path(temporary) / "binary")
                        path.symlink_to(Path(temporary) / "binary")
                    else:
                        alias = Path(temporary) / "alias"
                        alias.symlink_to(directory, target_is_directory=True)
                        directory = alias
                except (OSError, NotImplementedError):
                    self.skipTest("native symbolic link creation is unavailable")
                self.assertEqual(invoke(directory)[0], 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
