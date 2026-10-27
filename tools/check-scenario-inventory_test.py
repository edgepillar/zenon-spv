"""Source selection and bounded report controls; all payload fixtures are synthetic."""
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import sys
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


M = module("tested_source_scenario_inventory", "check-scenario-inventory.py")
F = module("original_opaque_archive_fixtures", "check-candidate-archive_test.py")
P = M.primitives()

# Independently authored source fixture. These rows are selected before report
# mutations. The fixture contains no Go implementation or executable payload.
HEADER = """package main
// A literal source-owned inventory.
type scenario struct {
 ID string `json:"id"`
 Package string `json:"package"`
 Test string `json:"test"`
 Commands []string `json:"-"`
}
var scenarios = []scenario{
"""


def source_bytes(report, requirements=None):
    requirements = {} if requirements is None else requirements
    rows = []
    for case in report["cases"]:
        commands = requirements.get(case["id"], ())
        command_literal = ("[]string{" + ",".join(json.dumps(name) for name in commands) + "}"
                           if commands else "nil")
        rows.append("{" + ",".join(json.dumps(case[key]) for key in ("id", "package", "test"))
                    + "," + command_literal + "},\n")
    tail = ('}\nconst modulePath = "github.com/0x3639/zenon-spv"\n'
            'const binaryMarker = "offline-pilot-binary "\nvar corpusPaths = []string{\n'
            + "".join(json.dumps(name) + ",\n" for name in F.checker.CORPUS) + "}\n")
    return (HEADER + "".join(rows) + tail).encode()


class ScenarioInventoryControls(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(
            prefix="scenario-inventory-", dir=os.environ.get("SPV_TASK_SCRATCH"))
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "tools/offline-pilot/manifest.go"
        self.source.parent.mkdir(parents=True)
        self.report_path = self.root / "validated-report.json"
        self.files, self.manifest, self.report = F.fixture()
        self.report["cases"].append({
            "id": "selected_example", "package": "internal/conformance", "test": "TestSelectedExample",
            "status": "passed", "passed_subtests": 1, "skipped_subtests": 0, "failed_subtests": 0,
            "binaries": [{"command": "fetch-bundle",
                          "sha256": next(row["sha256"] for row in self.manifest["binaries"]
                                         if row["command"] == "fetch-bundle")}],
        })
        self.source.write_bytes(source_bytes(
            self.report, {"example": ("zenon-spv",), "selected_example": ("fetch-bundle",)}))
        self.pin = mock.patch.object(P, "source_pin", return_value=F.INPUTS)
        self.source_pin = self.pin.start()
        self.addCleanup(self.pin.stop)

    def write_report(self, report=None, raw=None):
        raw = json.dumps(self.report if report is None else report).encode() if raw is None else raw
        self.report_path.write_bytes(raw)
        return hashlib.sha256(raw).hexdigest()

    def verify(self, report=None, os_name="linux", require_skip_ledger=False):
        digest = self.write_report(report)
        return M.verify(self.report_path, digest, self.root, F.REVISION, os_name, "amd64", require_skip_ledger)

    def argv(self, digest=None):
        return ["--report", str(self.report_path), "--expect-report-sha256", digest or self.write_report(),
                "--source", str(self.root), "--expect-revision", F.REVISION,
                "--expect-os", "linux", "--expect-architecture", "amd64"]

    def reject_source(self, raw):
        with self.assertRaises(M.Rejected) as captured:
            M.parse_scenarios(raw)
        self.assertEqual(captured.exception.category, "scenario_source_syntax")

    def test_current_source_has_all_59_unique_literal_entries(self):
        selected = M.parse_scenarios((HERE / "offline-pilot/manifest.go").read_bytes())
        self.assertEqual(len(selected), 59)
        self.assertEqual(selected["consumer_input_fifo"]["commands"], frozenset())
        self.assertEqual(selected["genesis_pinning"]["commands"], {"verify-mainnet-genesis"})

    def test_comments_crlf_and_literal_command_lists_preserve_selection(self):
        raw = self.source.read_bytes()
        changed = raw.replace(b"var scenarios", b"/* reviewed */\r\nvar scenarios").replace(b"\n", b"\r\n")
        self.assertEqual(M.parse_scenarios(raw), M.parse_scenarios(changed))
        empty = raw.replace(b'"TestSelectedExample",[]string{"fetch-bundle"}',
                            b'"TestSelectedExample",[]string{}')
        self.assertEqual(M.parse_scenarios(empty)["selected_example"]["commands"], frozenset())

    def test_go_and_json_compatible_string_escape_is_interpreted(self):
        raw = self.source.read_bytes().replace(b'"example"', b'"\\u0065xample"', 1)
        self.assertIn("example", M.parse_scenarios(raw))

    def test_duplicate_ids_or_test_identities_are_refused(self):
        raw = self.source.read_bytes()
        for changed in (
            raw.replace(b'"selected_example"', b'"example"'),
            raw.replace(b'"TestSelectedExample"', b'"TestExample"'),
        ):
            with self.subTest(source=changed[:40]):
                self.reject_source(changed)

    def test_duplicate_unknown_or_computed_commands_are_refused(self):
        raw = self.source.read_bytes()
        for replacement in (b'[]string{"fetch-bundle","fetch-bundle"}',
                            b'[]string{"unknown-command"}', b"requiredCommands"):
            with self.subTest(replacement=replacement):
                self.reject_source(raw.replace(b'[]string{"fetch-bundle"}', replacement))

    def test_computed_entries_or_trailing_go_code_are_refused(self):
        raw = self.source.read_bytes()
        for changed in (raw.replace(b"var scenarios = []scenario{", b"var scenarios = buildScenarios("),
                        raw + b"\nfunc init() { scenarios = scenarios[:2] }\n",
                        raw.replace(b'"example","internal/conformance"', b'"example",selectedPackage')):
            with self.subTest(source=changed[:40]):
                self.reject_source(changed)

    def test_changed_schema_or_corpus_tail_is_refused(self):
        raw = self.source.read_bytes()
        for changed in (raw.replace(b"Commands []string", b"Binaries []string"),
                        raw.replace(b'json:"id"', b'json:"other"'),
                        raw.replace(b"momentum-v1-v2.json", b"other-corpus.json"),
                        raw + b'var other = "ignored"\n'):
            with self.subTest(source=changed[:40]):
                self.reject_source(changed)

    def test_invalid_encoding_strings_comments_and_widths_are_refused(self):
        raw = self.source.read_bytes()
        for changed in (b"\xff", raw + b"/* unclosed", raw.replace(b'"example"', b'"unclosed', 1),
                        raw.replace(b'"example"', b'"example//not-a-comment"', 1),
                        raw.replace(b'"example"', b'"' + b"x" * 129 + b'"', 1),
                        raw + b" " * M.SCENARIO_SOURCE_LIMIT):
            with self.subTest(size=len(changed)):
                self.reject_source(changed)

    def test_source_token_count_is_bounded(self):
        with self.assertRaises(M.Rejected):
            M.tokens("word " * (M.TOKEN_LIMIT + 1))

    def test_positive_selection_checks_source_twice_and_preserves_scope(self):
        result = self.verify()
        self.assertEqual((result["status"], result["scenarios"]), ("consistent", 4))
        self.assertEqual(result["required_command_records"], 2)
        self.assertEqual(self.source_pin.call_args_list, [mock.call(self.root, F.REVISION)] * 2)
        self.assertEqual(result["skip_ledger_coverage"], "unknown")
        for key in ("candidate_payloads_validated", "test_execution_authenticated", "network_or_state_value_acceptance"):
            self.assertIs(result[key], False)

    def test_windows_metadata_remains_synthetic_and_context_bound(self):
        _, _, windows = F.fixture("windows")
        windows["cases"].append(copy.deepcopy(self.report["cases"][-1]))
        result = self.verify(windows, "windows")
        self.assertEqual((result["os"], result["scenarios"]), ("windows", 4))
        self.assertIs(result["candidate_payloads_validated"], False)

    def test_omission_refused_even_when_original_archive_consistency_passes(self):
        changed = copy.deepcopy(self.report)
        changed["cases"].pop()
        raw = F.pack(self.files, self.manifest, changed)
        self.assertEqual(F.checker.check_contents(
            io.BytesIO(raw), F.REVISION, F.INPUTS, "linux", "amd64")["status"], "verified")
        with self.assertRaises(M.Rejected) as captured:
            self.verify(changed)
        self.assertEqual(captured.exception.category, "scenario_coverage")

    def test_extra_selected_identity_or_wrong_package_or_test_is_refused(self):
        variants = []
        extra = copy.deepcopy(self.report)
        added = dict(extra["cases"][-1], id="unselected", test="TestUnselected")
        extra["cases"].append(added)
        variants.append(extra)
        for field, value in (("package", "internal/verify"), ("test", "TestDifferent")):
            changed = copy.deepcopy(self.report)
            changed["cases"][-1][field] = value
            variants.append(changed)
        for changed in variants:
            with self.subTest(cases=len(changed["cases"])), self.assertRaises(M.Rejected):
                self.verify(changed)

    def test_required_command_cannot_be_satisfied_by_another_case(self):
        changed = copy.deepcopy(self.report)
        changed["cases"][-1]["binaries"] = []
        raw = F.pack(self.files, self.manifest, changed)
        self.assertEqual(F.checker.check_contents(
            io.BytesIO(raw), F.REVISION, F.INPUTS, "linux", "amd64")["status"], "verified")
        with self.assertRaises(M.Rejected) as captured:
            self.verify(changed)
        self.assertEqual(captured.exception.category, "binary_selection")

    def test_source_command_records_are_minimum_requirements(self):
        self.assertEqual(len(self.report["cases"][0]["binaries"]), 7)
        self.assertEqual(self.verify()["status"], "consistent")

    def test_wrong_report_pin_is_refused_before_metadata_parsing(self):
        self.write_report()
        with mock.patch.object(P.checker, "metadata", side_effect=AssertionError("must not parse")):
            with self.assertRaises(M.Rejected) as captured:
                M.verify(self.report_path, "0" * 64, self.root, F.REVISION, "linux", "amd64")
        self.assertEqual(captured.exception.category, "report_pin")

    def test_source_fingerprint_drift_is_refused(self):
        self.source_pin.side_effect = [F.INPUTS, "d" * 64]
        with self.assertRaises(M.Rejected) as captured:
            self.verify()
        self.assertEqual(captured.exception.category, "source")

    def test_bad_report_context_never_becomes_consistent(self):
        variants = []
        for field, value in (("revision", "e" * 40), ("inputs_sha256", "f" * 64), ("modified", True)):
            changed = copy.deepcopy(self.report)
            changed["source"][field] = value
            variants.append(changed)
        for field, value in (("os", "windows"), ("architecture", "arm64"), ("command", "other"),
                             ("go_version", "go" + "1" * 40 + ".2")):
            changed = copy.deepcopy(self.report)
            changed["runner"][field] = value
            variants.append(changed)
        changed = copy.deepcopy(self.report)
        changed["source_matches_after_run"] = False
        variants.append(changed)
        for changed in variants:
            with self.subTest(source=changed["source"]), self.assertRaises(M.Rejected):
                self.verify(changed)

    def test_ambiguous_json_bad_counts_and_failed_cases_are_refused(self):
        ordinary = json.dumps(self.report).encode()
        for raw in (ordinary.replace(b'"schema_version": 1', b'"schema_version": 1, "schema_version": 1', 1),
                    ordinary.replace(b'"failed_subtests": 0', b'"failed_subtests": true', 1),
                    ordinary.replace(b'"failed_subtests": 0', b'"failed_subtests": 1', 1),
                    ordinary.replace(b'"passed_subtests": 1', b'"passed_subtests": 1.0', 1)):
            digest = self.write_report(raw=raw)
            with self.subTest(size=len(raw)), self.assertRaises(M.Rejected):
                M.verify(self.report_path, digest, self.root, F.REVISION, "linux", "amd64")

    def test_complete_skip_ledger_and_legacy_unknown_coverage_are_distinct(self):
        self.assertEqual(self.verify()["skip_ledger_coverage"], "unknown")
        with self.assertRaises(M.Rejected):
            self.verify(require_skip_ledger=True)
        changed = dict(self.report, schema_version=2, skip_ledger={
            "schema_version": 1, "coverage": "complete", "records": []})
        result = self.verify(changed, require_skip_ledger=True)
        self.assertEqual((result["skip_ledger_coverage"], result["skip_ledger_records"]), ("complete", 0))

    def test_unknown_skip_records_cannot_claim_complete_v2_coverage(self):
        changed = copy.deepcopy(self.report)
        changed["schema_version"] = 2
        changed["status"] = changed["cases"][-1]["status"] = "passed_with_skips"
        changed["cases"][-1]["skipped_subtests"] = 1
        changed["skip_ledger"] = {"schema_version": 1, "coverage": "unknown", "records": [{
            "scenario": "selected_example", "scope": "child", "ordinal": 1,
            "control": "unknown", "reason": "unreported"}]}
        with self.assertRaises(M.Rejected):
            self.verify(changed)

    def test_empty_and_oversized_files_are_refused_before_content_read(self):
        for target, size in ((self.source, 0), (self.source, M.SCENARIO_SOURCE_LIMIT + 1),
                             (self.report_path, 0), (self.report_path, M.REPORT_LIMIT + 1)):
            self.source.write_bytes(source_bytes(self.report))
            self.write_report()
            with target.open("wb") as stream:
                stream.truncate(size)
            with self.subTest(target=target.name, size=size), self.assertRaises(M.Rejected):
                M.verify(self.report_path, "a" * 64, self.root, F.REVISION, "linux", "amd64")

    def test_partial_reads_continue_to_real_eof_and_close(self):
        regular = P.regular_file
        observed = []
        @contextlib.contextmanager
        def short_reads(path, limit, category):
            with regular(path, limit, category) as (stream, size):
                observed.append(stream)
                class Reader:
                    def fileno(self):
                        return stream.fileno()
                    def read(self, count):
                        self_count = min(7, count)
                        return stream.read(self_count)
                yield Reader(), size
        with mock.patch.object(P, "regular_file", short_reads):
            self.assertEqual(self.verify()["status"], "consistent")
        self.assertEqual(len(observed), 2)
        self.assertTrue(all(stream.closed for stream in observed))

    def test_read_and_close_errors_discard_success_and_close_handles(self):
        regular = P.regular_file
        for phase in ("read", "close"):
            observed = []
            @contextlib.contextmanager
            def failing(path, limit, category):
                with regular(path, limit, category) as (stream, size):
                    observed.append(stream)
                    class Reader:
                        def fileno(self):
                            return stream.fileno()
                        def read(self, count):
                            if phase == "read":
                                raise OSError("private diagnostic must not escape")
                            return stream.read(count)
                    yield Reader(), size
                if phase == "close":
                    raise OSError("private close diagnostic")
            with self.subTest(phase=phase), mock.patch.object(P, "regular_file", failing):
                output = io.StringIO()
                self.assertEqual(M.main(self.argv(), output), 2)
                self.assertEqual(json.loads(output.getvalue())["status"], "rejected")
                self.assertNotIn("private", output.getvalue())
            self.assertTrue(all(stream.closed for stream in observed))

    def test_distinct_stat_clock_origins_are_kept_separate(self):
        # Windows stat() and fstat() can expose different ctime semantics.
        # Model that distinction without changing the file or its identity.
        original = os.fstat
        fields = ("st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
        def descriptor_stat(descriptor):
            info = original(descriptor)
            values = {name: getattr(info, name) for name in fields}
            values["st_ctime_ns"] += 1_000_000_000
            return SimpleNamespace(**values)
        expected = self.source.read_bytes()
        with mock.patch.object(M.os, "fstat", side_effect=descriptor_stat):
            self.assertEqual(M.read_regular(self.source, M.SCENARIO_SOURCE_LIMIT, "scenario_source_read"), expected)

    def test_identity_drift_before_close_is_refused(self):
        descriptor = P.file_identity(self.source.lstat())
        pathname = descriptor[:-1] + (descriptor[-1] + 1,)
        # Cross-API identity fields must agree. Both complete snapshots,
        # including their distinct change clocks, must then remain stable.
        for snapshot in (1, 2, 3):
            for field in range(6 if snapshot == 1 else 7):
                values = [descriptor, pathname, descriptor, pathname]
                changed = list(values[snapshot])
                changed[field] += 1
                values[snapshot] = tuple(changed)
                with self.subTest(snapshot=snapshot, field=field), mock.patch.object(
                        P, "file_identity", side_effect=values):
                    with self.assertRaises(M.Rejected):
                        M.read_regular(self.source, M.SCENARIO_SOURCE_LIMIT, "scenario_source_read")

    def test_cli_success_and_argument_errors_do_not_leak_paths(self):
        output = io.StringIO()
        self.assertEqual(M.main(self.argv(), output), 0)
        self.assertEqual(json.loads(output.getvalue())["scenarios"], 4)
        for argv in ([], self.argv() + ["--source", "/private/unrelated"],
                     self.argv() + ["--unknown", "/private/unrelated"],
                     self.argv() + ["--require-skip-ledger", "--require-skip-ledger"]):
            with self.subTest(argv_count=len(argv)):
                output = io.StringIO()
                self.assertEqual(M.main(argv, output), 64)
                self.assertNotIn("/private", output.getvalue())

    def test_invalid_context_arguments_never_inspect_source(self):
        for digest, revision, os_name, architecture in (("bad", F.REVISION, "linux", "amd64"),
                ("a" * 64, "bad", "linux", "amd64"), ("a" * 64, F.REVISION, "other", "amd64"),
                ("a" * 64, F.REVISION, "linux", "../amd64")):
            with self.subTest(os=os_name), self.assertRaises(M.Rejected):
                M.verify(self.report_path, digest, self.root, revision, os_name, architecture)
        self.source_pin.assert_not_called()

    def test_short_write_and_flush_failure_keep_nonzero_completion(self):
        class Output:
            def __init__(self, phase):
                self.phase = phase
            def write(self, raw):
                return len(raw) - 1 if self.phase == "short" else len(raw)
            def flush(self):
                if self.phase == "flush":
                    raise OSError("closed output")
        for phase in ("short", "flush"):
            with self.subTest(phase=phase):
                self.assertEqual(M.main(self.argv(), Output(phase)), 70)

    def test_legacy_validator_sources_are_byte_identical(self):
        M.dependencies_intact()
        for name, (size, digest) in M.DEPENDENCIES.items():
            raw = (HERE / name).read_bytes()
            self.assertEqual((len(raw), hashlib.sha256(raw).hexdigest()), (size, digest))

    def test_changed_pinned_helpers_are_refused_before_import(self):
        pinned = self.root / "pinned-dependencies"
        pinned.mkdir()
        originals = {name: (HERE / name).read_bytes() for name in M.DEPENDENCIES}
        for name, raw in originals.items():
            (pinned / name).write_bytes(raw)
        with mock.patch.object(M, "HERE", pinned):
            M.dependencies_intact()
            for name, raw in originals.items():
                changes = {"same_size": bytes([raw[0] ^ 1]) + raw[1:],
                           "shorter": raw[:-1], "longer": raw + b"x"}
                for change, altered in changes.items():
                    (pinned / name).write_bytes(altered)
                    with self.subTest(helper=name, change=change), \
                            mock.patch.object(M, "_PRIMITIVES", None), \
                            mock.patch.object(M.importlib.util, "spec_from_file_location") as load:
                        with self.assertRaises(M.Rejected) as failure:
                            M.primitives()
                        self.assertEqual(failure.exception.category, "checker_source")
                        load.assert_not_called()
                    (pinned / name).write_bytes(raw)
            M.dependencies_intact()


if __name__ == "__main__":
    unittest.main(verbosity=2)
