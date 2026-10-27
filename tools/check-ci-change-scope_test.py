# SPDX-License-Identifier: GPL-3.0-only
"""Synthetic scope controls and small owned subprocess/CLI observations.

No Git repository, archive, large fixture file, network or runtime binary is
created. Graph/diff fixtures are literal; Git source bytes are read separately.
"""
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import unittest
from unittest import mock

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
SCRIPT = HERE / "check-ci-change-scope.py"
SPEC = importlib.util.spec_from_file_location("tested_ci_change_scope", SCRIPT)
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)
BASE, FEATURE, CHECKOUT, TREE = (character * 40 for character in "1234")


def selection(event="pull_request"):
    return {"repository": "edgepillar/zenon-spv", "event": event,
            "base_revision": BASE, "feature_revision": FEATURE,
            "checkout_revision": CHECKOUT if event == "pull_request" else FEATURE,
            "run_id": 123, "run_attempt": 1}


def record(path=b"docs/contract.md", change=b"M", old_mode=b"100644", new_mode=b"100644"):
    old = b"0" * 40 if change == b"A" else b"a" * 40
    new = b"0" * 40 if change == b"D" else b"b" * 40
    return b":" + old_mode + b" " + new_mode + b" " + old + b" " + new + b" " + change + b"\0" + path + b"\0"


def receipt(raw=b"", actual_exit=0, complete=True):
    return {"actual_exit": actual_exit, "capture_complete": complete,
            "launch_error": False, "timed_out": False, "readers_joined": complete,
            "streams": {"stdout": {"sha256": hashlib.sha256(raw).hexdigest(),
                                     "captured_bytes": len(raw), "observed_bytes": len(raw),
                                     "eof": complete, "truncated": False, "read_error": False},
                        "stderr": {"sha256": hashlib.sha256(b"").hexdigest(),
                                   "captured_bytes": 0, "observed_bytes": 0,
                                   "eof": complete, "truncated": False, "read_error": False}}}


class FixtureRunner:
    def __init__(self, selected=None, diff=None):
        self.selection = selection() if selected is None else selected
        self.diff = record() if diff is None else diff
        self.calls = []
        self.overrides = {}

    def __call__(self, root, args, limit):
        self.calls.append((args, limit))
        if args[0] in self.overrides:
            raw, result = self.overrides[args[0]]
            return raw, copy.deepcopy(result)
        s = self.selection
        if args[0] == "rev-list":
            parents = BASE + (" " + FEATURE if s["event"] == "pull_request" else "")
            raw = (s["checkout_revision"] + " " + parents + "\n").encode()
        elif args[0] == "rev-parse":
            raw = (TREE + "\n").encode()
        elif args[0] == "show":
            raw = (ROOT / args[1].split(":", 1)[1]).read_bytes()
        elif args[0] == "diff":
            raw = self.diff
        else:
            raise AssertionError("Unexpected read-only Git request")
        return raw, receipt(raw)


class CIChangeScopeControls(unittest.TestCase):
    def require_full(self, raw, reason=None):
        runner = FixtureRunner(diff=raw)
        result = M.select_scope(ROOT, runner.selection, runner)
        self.assertTrue(result["run_runtime"])
        self.assertEqual(result["status"], "RUNTIME_REQUIRED")
        self.assertEqual(result["documentation_paths"], [])
        if reason:
            self.assertEqual(result["reason"], reason)
        return result

    def test_regular_added_modified_and_deleted_markdown(self):
        raw = (record(b"README.md", b"A", b"000000")
               + record(b"docs/deep/contract.md")
               + record(b"docs/old.md", b"D", new_mode=b"000000"))
        result = M.select_scope(ROOT, selection(), FixtureRunner(diff=raw))
        self.assertFalse(result["run_runtime"])
        self.assertEqual(result["status"], "DOCUMENTATION_ONLY")
        self.assertTrue(result["source_binding_complete"])
        self.assertEqual(len(result["source_pins"]), 3)
        self.assertEqual([p["change"] for p in result["documentation_paths"]], ["A", "M", "D"])
        self.assertFalse(result["runtime_qualification_transferred"])

    def test_direct_parent_push_can_select_only_documentation(self):
        selected = selection("push")
        result = M.select_scope(ROOT, selected, FixtureRunner(selected))
        self.assertFalse(result["run_runtime"])

    def test_code_workflow_corpus_and_nonmarkdown_require_runtime(self):
        for path in (b"internal/proof/code.go", b"tools/control.py", b"docs/vector.json",
                     b"docs/example.go.txt", b".github/workflows/ci.yml", b"LICENSE",
                     b"tools/README.md", b"README.MD"):
            with self.subTest(path=path):
                self.require_full(record() + record(path), "outside_documentation")

    def test_empty_diff_requires_runtime_even_after_identity_only_changes(self):
        self.require_full(b"", "empty_diff")

    def test_executable_symlink_submodule_and_type_changes_require_runtime(self):
        for old, new, change in ((b"100644", b"100755", b"M"),
                                 (b"120000", b"120000", b"M"),
                                 (b"000000", b"120000", b"A"),
                                 (b"160000", b"160000", b"M"),
                                 (b"100644", b"120000", b"T")):
            with self.subTest(old=old, new=new, change=change):
                self.require_full(record(old_mode=old, new_mode=new, change=change))

    def test_rename_copy_unknown_and_incomplete_records_require_runtime(self):
        for raw in (record(change=b"R100"), record(change=b"C100"), record(change=b"U"),
                    record()[:-1], record() + b"\0", b"header\0path\0", b"\0"):
            with self.subTest(raw=raw[:24]):
                self.require_full(raw)

    def test_rename_between_docs_and_runtime_paths_cannot_skip(self):
        self.require_full(record(b"docs/source.md", b"D", new_mode=b"000000")
                          + record(b"internal/source.go", b"A", b"000000"), "outside_documentation")

    def test_zero_and_unchanged_object_ids_require_runtime(self):
        raw = record()
        for changed in (raw.replace(b"a" * 40, b"0" * 40),
                        raw.replace(b"b" * 40, b"0" * 40),
                        raw.replace(b"b" * 40, b"a" * 40)):
            with self.subTest(raw=changed[:90]):
                self.require_full(changed, "diff_identity")

    def test_duplicate_paths_require_runtime(self):
        self.require_full(record() + record(), "duplicate_path")

    def test_ambiguous_private_and_nonportable_names_require_runtime(self):
        for path in (b"docs/../source.md", b"docs//contract.md", b"docs/.hidden.md",
                     b"docs/a\n.md", b"docs/a\\b.md", b"/docs/a.md", b"docs/\xff.md",
                     b"docs/" + b"a" * 512 + b".md"):
            with self.subTest(path=path[:24]):
                self.require_full(record(path), "outside_documentation")

    def test_diff_byte_and_record_limits_require_runtime(self):
        over = b"x" * (M.MAX_DIFF_BYTES + 1)
        self.require_full(over, "git_bounds")
        with self.assertRaises(M.ScopeError) as observed:
            M.parse_diff(over)
        self.assertEqual(observed.exception.reason, "diff_bounds")
        raw = b"".join(record(("docs/" + str(n) + ".md").encode()) for n in range(M.MAX_RECORDS + 1))
        self.require_full(raw, "diff_framing")

    def test_windows_reserved_names_and_case_aliases_require_runtime(self):
        for path in (b"docs/CON.md", b"docs/aux/file.md", b"docs/LPT9.md", b"docs/name./file.md"):
            with self.subTest(path=path):
                self.require_full(record(path), "outside_documentation")
        self.require_full(record(b"docs/Case.md") + record(b"docs/case.md"), "case_alias")

    def test_invalid_selection_refuses_before_any_git_query(self):
        for key, value in (("repository", "other/repository"), ("event", "workflow_dispatch"),
                           ("base_revision", "0" * 40), ("feature_revision", "a" * 39),
                           ("checkout_revision", "A" * 40), ("run_id", 0), ("run_attempt", True)):
            selected = selection()
            selected[key] = value
            runner = FixtureRunner(selected)
            with self.subTest(key=key):
                result = M.select_scope(ROOT, selected, runner)
                self.assertTrue(result["run_runtime"])
                self.assertEqual(result["reason"], "invalid_selection")
                self.assertEqual(runner.calls, [])

    def test_checkout_and_parent_mismatch_require_runtime(self):
        for line, reason in (((FEATURE + " " + BASE + " " + CHECKOUT + "\n").encode(), "checkout_mismatch"),
                             ((CHECKOUT + " " + FEATURE + " " + BASE + "\n").encode(), "pull_request_parents"),
                             ((CHECKOUT + " " + BASE + "\n").encode(), "pull_request_parents")):
            runner = FixtureRunner()
            runner.overrides["rev-list"] = line, receipt(line)
            result = M.select_scope(ROOT, selection(), runner)
            self.assertTrue(result["run_runtime"])
            self.assertEqual(result["reason"], reason)

    def test_octopus_missing_and_malformed_parent_records_require_runtime(self):
        for line in (b"", b"bad\n", (CHECKOUT + " " + BASE + " " + FEATURE + " " + TREE + "\n").encode()):
            runner = FixtureRunner()
            runner.overrides["rev-list"] = line, receipt(line)
            self.assertTrue(M.select_scope(ROOT, selection(), runner)["run_runtime"])

    def test_push_feature_or_previous_head_mismatch_requires_runtime(self):
        for patch in ({"feature_revision": CHECKOUT}, {"base_revision": TREE}):
            selected = selection("push")
            runner = FixtureRunner(selection("push"))
            selected.update(patch)
            result = M.select_scope(ROOT, selected, runner)
            self.assertTrue(result["run_runtime"])
            self.assertEqual(result["reason"], "push_parent")

    def test_failed_incomplete_and_unknown_git_results_require_runtime(self):
        for step in ("rev-list", "rev-parse", "show", "diff"):
            for code, complete in ((1, True), (0, False), (None, False)):
                runner = FixtureRunner()
                runner.overrides[step] = b"", receipt(actual_exit=code, complete=complete)
                result = M.select_scope(ROOT, selection(), runner)
                self.assertTrue(result["run_runtime"])
                self.assertEqual(result["reason"], "git_incomplete_or_failed")
                self.assertEqual(result["commands"][-1]["actual_exit"], code)

    def test_invalid_tree_record_requires_runtime(self):
        for raw in (b"", b"0" * 40 + b"\n", b"4" * 40 + b"\nextra"):
            runner = FixtureRunner()
            runner.overrides["rev-parse"] = raw, receipt(raw)
            self.assertEqual(M.select_scope(ROOT, selection(), runner)["reason"], "tree_record")

    def test_changed_helper_or_workflow_source_requires_runtime(self):
        runner = FixtureRunner()
        runner.overrides["show"] = b"different source\n", receipt(b"different source\n")
        result = M.select_scope(ROOT, selection(), runner)
        self.assertTrue(result["run_runtime"])
        self.assertEqual(result["reason"], "source_binding")

    def test_crlf_working_source_matches_only_the_exact_git_lf_bytes(self):
        runner = FixtureRunner()
        original = runner.__call__
        def lf_source(root, args, limit):
            raw, result = original(root, args, limit)
            if args[0] == "show":
                raw = raw.replace(b"\r\n", b"\n")
                result = receipt(raw)
            return raw, result
        result = M.select_scope(ROOT, selection(), lf_source)
        self.assertFalse(result["run_runtime"])
        self.assertTrue(all(v["checkout_relation"] in ("exact", "CRLF-only") for v in result["source_pins"].values()))

    def test_reader_that_exceeds_its_declared_bounds_cannot_select_docs(self):
        runner = FixtureRunner()
        runner.overrides["show"] = b"x" * (M.MAX_SOURCE_BYTES + 1), receipt(b"x" * (M.MAX_SOURCE_BYTES + 1))
        result = M.select_scope(ROOT, selection(), runner)
        self.assertTrue(result["run_runtime"])
        self.assertEqual(result["reason"], "git_bounds")

    def test_successful_child_retains_both_eof_and_actual_exit(self):
        raw, result = M.bounded_command([sys.executable, "-I", "-B", "-c", "print('owned-control')"], ROOT, 128)
        self.assertEqual(raw, b"owned-control\n" if os.name != "nt" else b"owned-control\r\n")
        self.assertEqual(result["actual_exit"], 0)
        self.assertTrue(result["capture_complete"])
        self.assertTrue(result["readers_joined"])

    def test_nonzero_child_does_not_fabricate_success(self):
        raw, result = M.bounded_command([sys.executable, "-I", "-B", "-c", "raise SystemExit(7)"], ROOT, 128)
        self.assertEqual(raw, b"")
        self.assertEqual(result["actual_exit"], 7)
        self.assertTrue(result["capture_complete"])

    def test_stdout_overflow_is_capped_and_never_complete(self):
        raw, result = M.bounded_command([sys.executable, "-I", "-B", "-c", "import sys;sys.stdout.write('x'*4096)"], ROOT, 31)
        self.assertEqual(len(raw), 31)
        self.assertEqual(result["streams"]["stdout"]["observed_bytes"], 32)
        self.assertTrue(result["streams"]["stdout"]["truncated"])
        self.assertFalse(result["capture_complete"])
        self.assertTrue(result["readers_joined"])

    def test_stderr_overflow_is_capped_and_never_complete(self):
        _, result = M.bounded_command([sys.executable, "-I", "-B", "-c", "import sys;sys.stderr.write('x'*8192)"], ROOT, 31)
        self.assertEqual(result["streams"]["stderr"]["captured_bytes"], 4096)
        self.assertTrue(result["streams"]["stderr"]["truncated"])
        self.assertFalse(result["capture_complete"])

    def test_owned_timeout_is_joined_and_not_a_successful_git_observation(self):
        _, result = M.bounded_command([sys.executable, "-I", "-B", "-c", "import time;time.sleep(5)"], ROOT, 31, timeout=0.05)
        self.assertTrue(result["timed_out"])
        self.assertIsNotNone(result["actual_exit"])
        self.assertFalse(result["capture_complete"])
        self.assertTrue(result["readers_joined"])

    def test_launch_failure_has_unknown_exit_and_no_eof_claim(self):
        with mock.patch.object(subprocess, "Popen", side_effect=OSError("private launch detail")):
            raw, result = M.bounded_command(["missing-owned-command"], ROOT, 31)
        self.assertEqual(raw, b"")
        self.assertIsNone(result["actual_exit"])
        self.assertTrue(result["launch_error"])
        self.assertFalse(result["capture_complete"])
        self.assertNotIn("private", json.dumps(result))

    def test_reader_start_failure_still_closes_the_owned_process_and_pipes(self):
        original = subprocess.Popen
        processes = []
        def launched(*args, **kwargs):
            process = original(*args, **kwargs)
            processes.append(process)
            return process
        with mock.patch.object(subprocess, "Popen", side_effect=launched), \
                mock.patch.object(M.threading.Thread, "start", side_effect=RuntimeError("owned control")):
            with self.assertRaises(RuntimeError):
                M.bounded_command([sys.executable, "-I", "-B", "-c", "import time;time.sleep(5)"], ROOT, 31)
        self.assertEqual(len(processes), 1)
        self.assertIsNotNone(processes[0].poll())
        self.assertTrue(processes[0].stdout.closed)
        self.assertTrue(processes[0].stderr.closed)

    def argv(self):
        s = selection()
        return [item for key, value in s.items() for item in ("--" + key.replace("_", "-"), str(value))]

    def test_cli_preserves_full_decision_and_complete_output(self):
        selected = selection()
        report = M.select_scope(ROOT, selected, FixtureRunner(diff=record(b"internal/test.go")))
        output = io.StringIO()
        with mock.patch.object(M, "select_scope", return_value=report):
            self.assertEqual(M.main(self.argv(), stdout=output), 0)
        self.assertEqual(json.loads(output.getvalue()), report)
        self.assertTrue(output.getvalue().endswith("\n"))

    def test_output_write_or_flush_failure_is_nonzero(self):
        for method in ("write", "flush"):
            output = mock.Mock()
            getattr(output, method).side_effect = OSError("private output detail")
            with mock.patch.object(M, "select_scope", return_value={"run_runtime": True}):
                self.assertEqual(M.main(self.argv(), stdout=output), 70)

    def test_fresh_cli_invalid_options_are_fixed_and_private(self):
        result = subprocess.run([sys.executable, "-I", "-B", str(SCRIPT), "--unknown-private-value"],
                                cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        self.assertEqual(result.returncode, 64)
        self.assertEqual(result.stdout, b"")
        self.assertEqual(result.stderr.replace(b"\r\n", b"\n"), b"ci-scope: invalid options\n")

    def test_fresh_cli_invalid_selection_has_no_git_queries(self):
        argv = self.argv()
        argv[argv.index("--repository") + 1] = "unknown/repository"
        result = subprocess.run([sys.executable, "-I", "-B", str(SCRIPT), *argv],
                                cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stderr, b"")
        report = json.loads(result.stdout)
        self.assertTrue(report["run_runtime"])
        self.assertEqual(report["commands"], [])

    def test_fresh_cli_help_does_not_claim_a_runtime_result(self):
        result = subprocess.run([sys.executable, "-I", "-B", str(SCRIPT), "--help"],
                                cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stderr, b"")
        self.assertIn(b"documentation-only", result.stdout)
        self.assertNotIn(b'"run_runtime":false', result.stdout)

    def workflow_guard(self, raw):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text("utf-8")
        block = workflow.split("          python -I -B - <<'PY'\n", 1)[1].split("          PY\n", 1)[0]
        self.assertTrue(all(line.startswith("          ") for line in block.splitlines()))
        program = compile("\n".join(line[10:] for line in block.splitlines()), "<workflow-scope-output-guard>", "exec")
        selected = selection()
        env = {"RUNNER_TEMP": "owned-runner-temp", "GITHUB_OUTPUT": "owned-scope-output",
               "GITHUB_REPOSITORY": selected["repository"], "GITHUB_EVENT_NAME": selected["event"],
               "CI_SCOPE_BASE": BASE, "CI_SCOPE_FEATURE": FEATURE, "GITHUB_SHA": CHECKOUT,
               "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1"}
        output = io.StringIO()
        def output_file(name, mode, encoding):
            self.assertEqual((name, mode, encoding), ("owned-scope-output", "a", "utf-8"))
            return contextlib.nullcontext(output)
        with mock.patch.dict(os.environ, env, clear=True), \
                mock.patch.object(Path, "open", return_value=io.BytesIO(raw)), \
                mock.patch("builtins.open", side_effect=output_file):
            try:
                exec(program, {})
            except (AssertionError, ValueError, KeyError, TypeError) as error:
                self.assertEqual(output.getvalue(), "")
                return type(error).__name__, output.getvalue()
        return None, output.getvalue()

    def guard_bytes(self, value):
        return (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()

    def test_actual_workflow_guard_writes_only_the_selected_literal_boolean(self):
        for diff, expected in ((record(), "false"), (record(b"internal/control.go"), "true")):
            result = M.select_scope(ROOT, selection(), FixtureRunner(diff=diff))
            self.assertEqual(self.workflow_guard(self.guard_bytes(result)), (None, "run_runtime=" + expected + "\n"))

    def test_actual_workflow_guard_rejects_missing_binding_or_failure_facts(self):
        report = M.select_scope(ROOT, selection(), FixtureRunner())
        mutations = []
        for path, value in (("source_binding_complete", False), ("source_pins", {}),
                            ("documentation_paths", []), ("run_runtime", "false"),
                            ("runtime_qualification_transferred", True), ("commands", [])):
            changed = copy.deepcopy(report)
            changed[path] = value
            mutations.append(changed)
        for field, value in (("actual_exit", 7), ("capture_complete", False),
                             ("actual_exit", False), ("timed_out", True),
                             ("readers_joined", False), ("streams", {})):
            changed = copy.deepcopy(report)
            changed["commands"][-1][field] = value
            mutations.append(changed)
        changed = copy.deepcopy(report)
        changed["commands"][-1]["streams"]["stdout"]["eof"] = False
        mutations.append(changed)
        for index, changed in enumerate(mutations):
            with self.subTest(mutation=index):
                self.assertIsNotNone(self.workflow_guard(self.guard_bytes(changed))[0])

    def test_actual_workflow_guard_rejects_other_selection_and_incomplete_json(self):
        report = M.select_scope(ROOT, selection(), FixtureRunner())
        changed = copy.deepcopy(report)
        changed["selection"]["checkout_revision"] = FEATURE
        self.assertIsNotNone(self.workflow_guard(self.guard_bytes(changed))[0])
        raw = self.guard_bytes(report)
        for changed_raw in (raw[:-1], raw[:-2], raw + b"extra", raw.replace(b'{', b'{"format":"unknown",', 1), b"x" * (M.MAX_REPORT_BYTES + 1)):
            with self.subTest(size=len(changed_raw)):
                self.assertIsNotNone(self.workflow_guard(changed_raw)[0])


class ControlResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.attempted_names = []
        self.passed_names = []
        self.skipped_names = []

    def name(self, test):
        return ".".join(test.id().split(".")[-2:])

    def startTest(self, test):
        self.attempted_names.append(self.name(test))
        super().startTest(test)

    def addSuccess(self, test):
        self.passed_names.append(self.name(test))
        super().addSuccess(test)

    def addSkip(self, test, reason):
        self.skipped_names.append(self.name(test))
        super().addSkip(test, reason)


def run_controls():
    args = list(sys.argv[1:])
    revision = None
    if "--source-revision" in args:
        try:
            if args.count("--source-revision") != 1:
                raise ValueError
            index = args.index("--source-revision")
            revision = args[index + 1]
            if not M.valid_oid(revision):
                raise ValueError
            del args[index:index + 2]
        except (IndexError, ValueError):
            sys.stderr.write("ci-scope-controls: invalid source revision\n")
            return 64
    runner = unittest.TextTestRunner(verbosity=2, resultclass=ControlResult)
    program = unittest.main(argv=[sys.argv[0], *args], testRunner=runner, exit=False)
    result = program.result
    if revision is not None:
        pins = {}
        for name in M.SOURCE_FILES:
            with (ROOT / name).open("rb") as stream:
                raw = stream.read(M.MAX_SOURCE_BYTES + 1)
            if len(raw) > M.MAX_SOURCE_BYTES:
                return 70
            pins[name] = {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}
        report = {"format": "zenon-ci-change-scope-controls/v1",
                  "status": "PASS" if result.wasSuccessful() else "FAILURE",
                  "source_revision": revision, "source_pins": pins,
                  "runtime": {"os": sys.platform, "machine": platform.machine().lower(),
                              "python": platform.python_version(),
                              "implementation": platform.python_implementation()},
                  "tests": result.testsRun, "failures": len(result.failures),
                  "errors": len(result.errors), "skipped": len(result.skipped),
                  "attempted_names": sorted(result.attempted_names),
                  "passed_names": sorted(result.passed_names),
                  "skipped_names": sorted(result.skipped_names),
                  "failed_or_unfinished_names": sorted(set(result.attempted_names) - set(result.passed_names)),
                  "fixture_files_created": False, "runtime_qualification_transferred": False}
        raw = json.dumps(report, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n"
        if len(raw.encode("utf-8")) > 64 << 10:
            return 70
        try:
            sys.stdout.write(raw)
            sys.stdout.flush()
        except (OSError, ValueError):
            return 70
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(run_controls())
