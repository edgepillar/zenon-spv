# SPDX-License-Identifier: GPL-3.0-only
"""Synthetic scope controls and small owned subprocess/CLI observations.

No Git repository, archive, large fixture file, network or runtime binary is
created. Graph/diff fixtures are literal; Git source bytes are read separately.
"""
import ast
import contextlib
import copy
import hashlib
import fnmatch
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
TRANSPORT = ".github/workflows/ledger-transport.yml"
EXPORT = ".github/workflows/ledger-export.yml"
PREPARATION = ".github/workflows/owned-devnet-query.yml"


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


def tree_record(path, mode=b"100644", kind=b"blob", oid=b"a" * 40):
    return mode + b" " + kind + b" " + oid + b"\t" + path + b"\0"


def base_tree():
    return (tree_record(b"internal/proof/core.go")
            + tree_record(b".github/workflows/ci.yml", oid=b"b" * 40)
            + tree_record(b"docs/contract.md")
            + tree_record(b"tools/check-ci-change-scope.py"))


def native_tree():
    return (base_tree()
            + tree_record(b"tools/ledger-transport/archive_tail.py")
            + tree_record(b"internal/verify/experimental_v3_state.go")
            + tree_record(b"tools/gen-state-root-vectors/check_patch_file.py")
            + tree_record(b"tools/gen-state-root-vectors/testdata/candidate-patch-file.json"))


def portable_tree():
    return (base_tree() + b"".join(tree_record(path.encode()) for path in
            (TRANSPORT, EXPORT, PREPARATION, "tools/owned-devnet-query/contract.json"))
            + b"".join(tree_record(path.encode()) for path in sorted(M.PORTABLE_FILES)))


class FixtureRunner:
    def __init__(self, selected=None, diff=None):
        self.selection = selection() if selected is None else selected
        self.diff = record() if diff is None else diff
        self.calls = []
        self.overrides = {}

    def __call__(self, root, args, limit):
        self.calls.append((args, limit))
        key = tuple(args) if tuple(args) in self.overrides else args[0]
        if key in self.overrides:
            raw, result = self.overrides[key]
            return raw, {**copy.deepcopy(result), "git_arguments": args}
        s = self.selection
        if args[0] == "rev-list":
            parents = BASE + (" " + FEATURE if s["event"] == "pull_request" else "")
            raw = (s["checkout_revision"] + " " + parents + "\n").encode()
        elif args[0] == "rev-parse":
            raw = (TREE + "\n").encode()
        elif args[0] == "cat-file":
            raw = f"tree {TREE}\nparent {BASE}\n\nfixture\n".encode()
        elif args[0] == "show":
            raw = (ROOT / args[1].split(":", 1)[1]).read_bytes()
            if args[1].split(":", 1)[1] in (TRANSPORT, EXPORT, PREPARATION):
                raw = raw.replace(b"\r\n", b"\n")
        elif args[0] == "diff":
            raw = self.diff
        elif args[0] == "ls-tree":
            raw = portable_tree()
        else:
            raise AssertionError("Unexpected read-only Git request")
        return raw, {**receipt(raw), "git_arguments": args}


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

    def workflow_guard(self, raw, selected=None):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text("utf-8")
        block = workflow.split("          python -I -B - <<'PY'\n", 1)[1].split("          PY\n", 1)[0]
        self.assertTrue(all(line.startswith("          ") for line in block.splitlines()))
        program = compile("\n".join(line[10:] for line in block.splitlines()), "<workflow-scope-output-guard>", "exec")
        selected = selection() if selected is None else selected
        env = {"RUNNER_TEMP": "owned-runner-temp", "GITHUB_OUTPUT": "owned-scope-output",
               "GITHUB_REPOSITORY": selected["repository"], "GITHUB_EVENT_NAME": selected["event"],
               "CI_SCOPE_BASE": selected["base_revision"], "CI_SCOPE_FEATURE": selected["feature_revision"],
               "GITHUB_SHA": selected["checkout_revision"],
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
            self.assertEqual(self.workflow_guard(self.guard_bytes(result)),
                             (None, "run_runtime=" + expected + "\nrun_recorded_oracles=" + expected + "\n"))

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

    def native_result(self, diff=None, runner=None, selected=None):
        selected = selection() if selected is None else selected
        if runner is None:
            runner = FixtureRunner(selected, record(b"internal/verify/experimental_v3_state.go")
                                   if diff is None else diff)
            raw = native_tree()
            runner.overrides["ls-tree"] = raw, receipt(raw)
        with mock.patch.object(M, "ORACLE_SOURCE_PIN", M.oracle_fingerprint(native_tree())["sha256"]):
            return M.select_scope(ROOT, selected, runner)

    def test_native_reviewed_modified_leaves_keep_native_and_skip_only_oracles(self):
        for path in sorted(M.NATIVE_FILES):
            with self.subTest(path=path):
                report = self.native_result(record(path.encode()) + record())
                self.assertEqual((report["format"], report["status"]), (M.NATIVE_FORMAT, "NATIVE_RUNTIME_ONLY"))
                self.assertIs(report["run_runtime"], True)
                self.assertIs(report["run_recorded_oracles"], False)
                self.assertEqual(report["native_paths"], [{"path": path, "change": "M"}])
                self.assertEqual(report["documentation_paths"], [{"path": "docs/contract.md", "change": "M"}])
                self.assertEqual(set(report["source_pins"]), set(M.SOURCE_FILES))
                self.assertEqual(len(report["commands"]), 7)
                self.assertFalse(report["runtime_qualification_transferred"])

    def test_native_direct_parent_push_uses_the_same_bounded_selection(self):
        selected = selection("push")
        report = self.native_result(selected=selected)
        self.assertEqual(report["selection"], selected)
        self.assertIs(report["run_runtime"], True)
        self.assertIs(report["run_recorded_oracles"], False)

    def test_native_additions_deletions_modes_aliases_and_incomplete_records_keep_full_lane(self):
        path = b"internal/verify/experimental_v3_state.go"
        for raw in (record(path, b"A", b"000000"), record(path, b"D", new_mode=b"000000"),
                    record(path, old_mode=b"100755", new_mode=b"100755"),
                    record(path, old_mode=b"120000", new_mode=b"120000"),
                    record(path, change=b"R100"), record(path) + record(path), record(path)[:-1],
                    record(path) + record(path.upper()), record(path.replace(b"/", b"//", 1))):
            with self.subTest(raw=raw[:90]):
                report = self.native_result(raw)
                self.assertTrue(report["run_runtime"])
                self.assertTrue(report.get("run_recorded_oracles", True))
                self.assertEqual(report["status"], "RUNTIME_REQUIRED")

    def test_native_unreviewed_go_python_fixtures_and_policy_changes_keep_full_lane(self):
        paths = ("internal/verify/experimental_v3_future.go", "internal/verify/retained.go",
                 "internal/chain/hash.go", "go.mod", "internal/testdata/conformance/profile.json",
                 "tools/gen-state-root-vectors/check.py", "tools/ledger-transport/archive_tail.py",
                 *M.SOURCE_FILES)
        for path in paths:
            with self.subTest(path=path):
                report = self.native_result(record(b"internal/verify/experimental_v3_state.go") + record(path.encode()))
                self.assertTrue(report["run_runtime"])
                self.assertTrue(report.get("run_recorded_oracles", True))
                self.assertEqual(report["status"], "RUNTIME_REQUIRED")
                self.assertEqual(len(report["commands"]), 6)

    def test_native_closure_changes_and_nonregular_excluded_paths_keep_full_lane(self):
        for path in ("internal/proof/core.go", ".github/workflows/ci.yml",
                     "tools/gen-state-root-vectors/check_patch_file.py",
                     "tools/gen-state-root-vectors/testdata/candidate-patch-file.json",
                     "tools/ledger-transport/archive_tail.py"):
            original = native_tree()
            raw = original.replace(tree_record(path.encode()), tree_record(path.encode(), oid=b"c" * 40))
            if path == ".github/workflows/ci.yml":
                raw = original.replace(b"b" * 40, b"c" * 40)
            runner = FixtureRunner(diff=record(b"internal/verify/experimental_v3_state.go"))
            runner.overrides["ls-tree"] = raw, receipt(raw)
            with self.subTest(path=path):
                report = self.native_result(runner=runner)
                self.assertEqual(report["reason"], "oracle_source_pin")
                self.assertTrue(report["run_recorded_oracles"])
        for raw in (native_tree() + tree_record(b"tools/new-dependency.py"),
                    native_tree() + tree_record(b"docs/linked.md", mode=b"120000"),
                    native_tree().replace(tree_record(b"internal/verify/experimental_v3_state.go"),
                        tree_record(b"internal/verify/experimental_v3_state.go", mode=b"120000"))):
            runner = FixtureRunner(diff=record(b"internal/verify/experimental_v3_state.go"))
            runner.overrides["ls-tree"] = raw, receipt(raw)
            self.assertTrue(self.native_result(runner=runner)["run_recorded_oracles"])

    def test_native_closure_literal_digest_excludes_only_regular_reviewed_leaves(self):
        kept = [tree_record(b"internal/proof/core.go"), tree_record(b".github/workflows/ci.yml", oid=b"b" * 40),
                tree_record(b"tools/ledger-transport/archive_tail.py"),
                tree_record(b"tools/gen-state-root-vectors/check_patch_file.py"),
                tree_record(b"tools/gen-state-root-vectors/testdata/candidate-patch-file.json")]
        expected = {"sha256": hashlib.sha256(b"".join(sorted(kept))).hexdigest(),
                    "bytes": sum(map(len, kept)), "entries": len(kept)}
        self.assertEqual(M.oracle_fingerprint(native_tree()), expected)
        for path in sorted(M.NATIVE_FILES | set(M.SOURCE_FILES[:2]) | {"README.md", "docs/extra.md"}):
            if path in ("internal/verify/experimental_v3_state.go", "tools/check-ci-change-scope.py"):
                continue
            with self.subTest(path=path):
                self.assertEqual(M.oracle_fingerprint(native_tree() + tree_record(path.encode())), expected)
                self.assertNotEqual(M.oracle_fingerprint(native_tree() + tree_record(path.encode(), mode=b"120000")), expected)

    def test_native_closure_malformed_duplicate_empty_and_oversized_trees_are_refused(self):
        for raw in (b"", b"unknown", b"x" * (M.MAX_TREE_BYTES + 1), tree_record(b"../escape"),
                    native_tree() + tree_record(b"internal/proof/core.go"),
                    tree_record(b"internal/verify/experimental_v3_state.go")):
            with self.subTest(size=len(raw)), self.assertRaises(M.ScopeError):
                M.oracle_fingerprint(raw)

    def test_native_incomplete_or_failed_tree_observations_preserve_failure_and_full_lane(self):
        for code, complete in ((1, True), (0, False), (None, False)):
            runner = FixtureRunner(diff=record(b"internal/verify/experimental_v3_state.go"))
            runner.overrides["ls-tree"] = b"", receipt(actual_exit=code, complete=complete)
            with self.subTest(code=code, complete=complete):
                report = self.native_result(runner=runner)
                self.assertTrue(report["run_runtime"])
                self.assertTrue(report["run_recorded_oracles"])
                self.assertEqual(report["reason"], "git_incomplete_or_failed")
                self.assertEqual(report["commands"][-1]["actual_exit"], code)

    def test_native_workflow_guard_keeps_native_jobs_enabled(self):
        report = self.native_result()
        self.assertEqual(self.workflow_guard(self.guard_bytes(report)),
                         (None, "run_runtime=true\nrun_recorded_oracles=false\n"))
        workflow = (ROOT / ".github/workflows/ci.yml").read_text("utf-8")
        for name in ("test", "native-platform"):
            block = workflow.split("\n  " + name + ":\n", 1)[1].split("    runs-on:", 1)[0]
            self.assertIn("needs.change_scope.outputs.run_runtime != 'false'", block)
            self.assertNotIn("outputs.run_recorded_oracles", block)
        block = workflow.split("\n  recorded-oracles:\n", 1)[1].split("    runs-on:", 1)[0]
        self.assertIn("needs.change_scope.outputs.run_recorded_oracles != 'false'", block)
        self.assertIn("needs.change_scope.result != 'success'", block)

    def test_native_workflow_guard_rejects_incomplete_closures_paths_and_exit_facts(self):
        report = self.native_result()
        mutations = []
        for key, value in (("run_runtime", False), ("run_recorded_oracles", "false"),
                           ("status", "RUNTIME_REQUIRED"), ("source_binding_complete", False),
                           ("source_pins", {}), ("native_paths", []), ("documentation_paths", "unknown"),
                           ("commands", report["commands"][:-1])):
            changed = copy.deepcopy(report);changed[key] = value;mutations.append(changed)
        for paths in ([{"path": "internal/verify/unreviewed.go", "change": "M"}],
                      [{"path": "internal/verify/experimental_v3_state.go", "change": "A"}],
                      report["native_paths"] * 2):
            changed = copy.deepcopy(report);changed["native_paths"] = paths;mutations.append(changed)
        for key, value in (("matched", False), ("expected_sha256", "0" * 64), ("bytes", True),
                           ("bytes", (2 << 20) + 1), ("entries", 0), ("entries", True)):
            changed = copy.deepcopy(report);changed["oracle_closure"][key] = value;mutations.append(changed)
        for key, value in (("actual_exit", False), ("actual_exit", 7), ("capture_complete", False)):
            changed = copy.deepcopy(report);changed["commands"][-1][key] = value;mutations.append(changed)
        for index, changed in enumerate(mutations):
            with self.subTest(mutation=index):
                self.assertIsNotNone(self.workflow_guard(self.guard_bytes(changed))[0])

    def test_native_workflow_guard_cannot_apply_oracle_flags_to_legacy_reports(self):
        report = M.select_scope(ROOT, selection(), FixtureRunner(diff=record(b"internal/unselected.go")))
        report["run_recorded_oracles"] = False
        self.assertEqual(self.workflow_guard(self.guard_bytes(report)),
                         (None, "run_runtime=true\nrun_recorded_oracles=true\n"))

    def test_native_workflow_guard_falls_back_after_an_unmatched_closure(self):
        runner = FixtureRunner(diff=record(b"internal/verify/experimental_v3_state.go"))
        report = M.select_scope(ROOT, selection(), runner)
        self.assertEqual(report["format"], M.NATIVE_FORMAT)
        self.assertTrue(report["run_recorded_oracles"])
        self.assertEqual(self.workflow_guard(self.guard_bytes(report)),
                         (None, "run_runtime=true\nrun_recorded_oracles=true\n"))

    def portable_result(self, runner):
        pin = M.portable_fingerprint(portable_tree())["sha256"]
        with mock.patch.object(M, "PORTABLE_SOURCE_PIN", pin):
            return M.select_scope(ROOT, runner.selection, runner)

    def test_each_portable_leaf_selects_its_three_platform_workflows(self):
        for event in ("pull_request", "push"):
            selected = selection(event)
            for path in sorted(M.PORTABLE_FILES):
                with self.subTest(event=event, path=path):
                    if path == "tools/ledger-transport/transport.py":
                        required = [TRANSPORT, EXPORT]
                    else:
                        directory = path.split("/")[1]
                        required = [{"ledger-transport": TRANSPORT, "ledger-export": EXPORT,
                                     "owned-devnet-query": PREPARATION}[directory]]
                    runner = FixtureRunner(selected, record(path.encode()) + record())
                    result = self.portable_result(runner)
                    self.assertEqual((result["format"], result["status"], result["run_runtime"]),
                                     (M.PORTABLE_FORMAT, "PORTABLE_WORKFLOWS_ONLY", False))
                    self.assertEqual(result["portable_paths"], [{"path": path, "change": "M"}])
                    self.assertEqual(result["documentation_paths"], [{"path": "docs/contract.md", "change": "M"}])
                    self.assertEqual(result["required_workflows"], required)
                    self.assertEqual([row["path"] for row in result["portable_workflows"]], required)
                    self.assertEqual(result["portable_event_tree"], TREE)
                    self.assertEqual(set(result["source_pins"]), set(M.SOURCE_FILES) | set(required))
                    self.assertEqual(len(result["commands"]), 7 + 2 * len(required) + (event == "pull_request"))
                    self.assertFalse(result["runtime_qualification_transferred"])
                    self.assertEqual(self.workflow_guard(self.guard_bytes(result), selected),
                                     (None, "run_runtime=false\nrun_recorded_oracles=false\n"))

    def test_portable_mixed_diff_selects_the_union(self):
        archive = record(b"tools/ledger-transport/archive_tail.py")
        exporter = record(b"tools/ledger-export/inventory_completed_export.py")
        preparation = record(b"tools/owned-devnet-query/review.py")
        for paths, required in ((archive + exporter, [TRANSPORT, EXPORT]),
                                (exporter + preparation, [EXPORT, PREPARATION]),
                                (archive + preparation, [TRANSPORT, PREPARATION]),
                                (archive + exporter + preparation, [TRANSPORT, EXPORT, PREPARATION])):
            with self.subTest(required=required):
                report = self.portable_result(FixtureRunner(diff=paths))
                self.assertEqual(report["required_workflows"], required)
                self.assertEqual(self.workflow_guard(self.guard_bytes(report))[0], None)

    def test_roadmap_mixed_portable_changes_require_only_the_selected_tool_workflows(self):
        leaves = ((b"tools/owned-devnet-query/review.py", [PREPARATION]),
                  (b"tools/ledger-export/inventory_completed_export.py", [EXPORT]),
                  (b"tools/ledger-transport/archive_tail.py", [TRANSPORT]),
                  (b"tools/ledger-transport/transport.py", [TRANSPORT, EXPORT]))
        for event in ("pull_request", "push"):
            for change, old_mode, new_mode in ((b"A", b"000000", b"100644"),
                                               (b"M", b"100644", b"100644"),
                                               (b"D", b"100644", b"000000")):
                document = record(b"docs/native-roadmap.md", change, old_mode, new_mode)
                for path, required in leaves:
                    with self.subTest(event=event, change=change, path=path):
                        selected = selection(event)
                        report = self.portable_result(FixtureRunner(selected, document + record(path)))
                        self.assertFalse(report["run_runtime"])
                        self.assertEqual(report["required_workflows"], required)
                        self.assertEqual(self.workflow_guard(self.guard_bytes(report), selected),
                                         (None, "run_runtime=false\nrun_recorded_oracles=false\n"))

    def test_intake_mixed_portable_changes_still_require_transport(self):
        for event in ("pull_request", "push"):
            for change, old_mode, new_mode in ((b"A", b"000000", b"100644"),
                                               (b"M", b"100644", b"100644"),
                                               (b"D", b"100644", b"000000")):
                for path, required in ((b"tools/owned-devnet-query/review.py", [TRANSPORT, PREPARATION]),
                                       (b"tools/ledger-export/inventory_completed_export.py", [TRANSPORT, EXPORT])):
                    with self.subTest(event=event, change=change, path=path):
                        selected = selection(event)
                        document = record(b"docs/state-root-r1-intake.md", change, old_mode, new_mode)
                        report = self.portable_result(FixtureRunner(selected, document + record(path)))
                        self.assertFalse(report["run_runtime"])
                        self.assertEqual(report["required_workflows"], required)
                        self.assertEqual(self.workflow_guard(self.guard_bytes(report), selected),
                                         (None, "run_runtime=false\nrun_recorded_oracles=false\n"))

    def test_roadmap_alone_selects_documentation_without_transferred_runtime(self):
        for event in ("pull_request", "push"):
            selected = selection(event)
            report = M.select_scope(ROOT, selected, FixtureRunner(selected, record(b"docs/native-roadmap.md")))
            self.assertEqual(report["status"], "DOCUMENTATION_ONLY")
            self.assertNotIn("required_workflows", report)
            self.assertFalse(report["runtime_qualification_transferred"])
            self.assertEqual(self.workflow_guard(self.guard_bytes(report), selected),
                             (None, "run_runtime=false\nrun_recorded_oracles=false\n"))

    def test_transport_event_filters_preserve_the_execution_dependencies(self):
        lines = (ROOT / TRANSPORT).read_text(encoding="utf-8").splitlines()
        expected = ["tools/ledger-transport/**", "tools/ledger-inventory/inventory.py",
                    TRANSPORT, "docs/state-root-r1-intake.md", "LICENSE",
                    "tools/gen-state-root-vectors/LICENSE"]
        for event in ("push", "pull_request"):
            start = lines.index("  " + event + ":") + 1
            end = next(index for index in range(start, len(lines))
                       if lines[index] and not lines[index].startswith("    "))
            block = lines[start:end]
            self.assertIn("    branches: [main]", block)
            self.assertIn("    paths:", block)
            filters = [ast.literal_eval(line.strip()[2:]) for line in block
                       if line.startswith("      - ")]
            self.assertEqual(filters, expected)
            self.assertFalse(any(fnmatch.fnmatchcase("docs/native-roadmap.md", path) for path in filters))
            for name in ("tools/ledger-transport/archive_tail.py", "tools/ledger-inventory/inventory.py",
                         TRANSPORT, "docs/state-root-r1-intake.md", "LICENSE",
                         "tools/gen-state-root-vectors/LICENSE"):
                self.assertTrue(any(fnmatch.fnmatchcase(name, path) for path in filters), name)
        # The file remains part of transport evidence when that workflow runs.
        self.assertIn("                   'docs/native-roadmap.md', 'LICENSE', 'tools/ledger-transport/THIRD_PARTY_NOTICES',", lines)

    def test_portable_events_require_the_exact_path_filter_comparison(self):
        raw = record(b"tools/ledger-transport/archive_tail.py")
        for header in (f"tree {FEATURE}\nparent {BASE}\n",
                       f"tree {TREE}\nparent {FEATURE}\n",
                       f"tree {TREE}\nparent {BASE}\nparent {FEATURE}\n"):
            runner = FixtureRunner(diff=raw)
            commit = (header + "\nfixture\n").encode()
            runner.overrides["cat-file"] = commit, receipt(commit)
            report = self.portable_result(runner)
            self.assertEqual((report["run_runtime"], report["reason"]), (True, "portable_event_diff"))
        runner = FixtureRunner(selection("push"), raw)
        parents = f"{FEATURE} {CHECKOUT} {BASE}\n".encode()
        runner.overrides["rev-list"] = parents, receipt(parents)
        self.assertEqual(self.portable_result(runner)["reason"], "portable_event_diff")

    def test_portable_event_diff_count_is_bounded_even_with_markdown(self):
        raw = record(b"tools/owned-devnet-query/inputs.py")
        accepted = raw + b"".join(record(f"docs/{index}.md".encode())
                                  for index in range(M.MAX_FILTERED_DIFF_RECORDS - 1))
        self.assertFalse(self.portable_result(FixtureRunner(diff=accepted))["run_runtime"])
        refused = self.portable_result(FixtureRunner(diff=accepted + record()))
        self.assertEqual((refused["run_runtime"], refused["reason"]), (True, "portable_diff_count"))

    def test_portable_additions_deletions_mode_changes_and_invalid_diffs_keep_runtime(self):
        path = b"tools/ledger-transport/archive_tail.py"
        for raw in (record(path, b"A", b"000000"), record(path, b"D", new_mode=b"000000"),
                    record(path, old_mode=b"100755", new_mode=b"100755"),
                    record(path, old_mode=b"120000", new_mode=b"120000"),
                    record(path, change=b"R100"), record(path)[:-1], record(path) + b"bad\0unknown\0",
                    record(path) * 2, record(path) + record(path.upper())):
            with self.subTest(raw=raw[:90]):
                self.assertTrue(self.portable_result(FixtureRunner(diff=raw))["run_runtime"])

    def test_portable_never_selects_native_or_unreviewed_dependencies(self):
        first = record(b"tools/ledger-transport/transport.py")
        other = ("internal/verify/experimental_v3_state.go", "tools/ledger-transport/new.py",
                 "tools/ledger-export/consume_completion.py", "tools/ledger-inventory/inventory.py",
                 "tools/owned-devnet-query/runner.py", "tools/owned-devnet-query/contract.json",
                 "tools/owned-devnet-query/query_checks.py", "tools/owned-devnet-query/controls.py",
                 TRANSPORT, EXPORT, PREPARATION, *M.SOURCE_FILES)
        for path in other:
            with self.subTest(path=path):
                report = self.portable_result(FixtureRunner(diff=first + record(path.encode())))
                self.assertTrue(report["run_runtime"])
                self.assertEqual(len(report["commands"]), 6)

    def test_portable_workflow_pins_bind_base_checkout_and_working_bytes(self):
        diff = (record(b"tools/ledger-transport/transport.py")
                + record(b"tools/owned-devnet-query/review.py"))
        for path in (TRANSPORT, EXPORT, PREPARATION):
            committed = (ROOT / path).read_bytes().replace(b"\r\n", b"\n")
            for revision, reason in ((BASE, "portable_workflow_pin"), (CHECKOUT, "source_binding")):
                runner = FixtureRunner(diff=diff)
                runner.overrides[("show", revision + ":" + path)] = committed + b"\n", receipt(committed + b"\n")
                with self.subTest(path=path, revision=revision):
                    report = self.portable_result(runner)
                    self.assertEqual((report["run_runtime"], report["reason"]), (True, reason))
            runner = FixtureRunner(diff=diff)
            modified = committed + b"\n"
            for revision in (BASE, CHECKOUT):
                runner.overrides[("show", revision + ":" + path)] = modified, receipt(modified)
            read = Path.open
            def changed_working_file(current, *args, **kwargs):
                return io.BytesIO(modified) if current == ROOT / path else read(current, *args, **kwargs)
            with mock.patch.object(Path, "open", changed_working_file):
                report = self.portable_result(runner)
                self.assertEqual(report["reason"], "portable_workflow_pin")
                self.assertTrue(report["run_runtime"])

    def test_portable_required_git_failures_retain_the_full_runtime_lane(self):
        diff = record(b"tools/ledger-transport/transport.py")
        for command in ("cat-file", ("show", BASE + ":" + EXPORT), "ls-tree"):
            for code, complete in ((5, True), (0, False)):
                runner = FixtureRunner(diff=diff)
                runner.overrides[command] = b"", receipt(actual_exit=code, complete=complete)
                with self.subTest(command=command, code=code, complete=complete):
                    report = self.portable_result(runner)
                    self.assertEqual(report["reason"], "git_incomplete_or_failed")
                    self.assertEqual(report["commands"][-1]["actual_exit"], code)
                    self.assertEqual(report["commands"][-1]["capture_complete"], complete)
                    self.assertEqual(self.workflow_guard(self.guard_bytes(report)),
                                     (None, "run_runtime=true\nrun_recorded_oracles=true\n"))
        for command, limit in (("cat-file", M.MAX_SOURCE_BYTES), ("ls-tree", M.MAX_TREE_BYTES)):
            raw = b"x" * (limit + 1)
            runner = FixtureRunner(diff=diff)
            runner.overrides[command] = raw, receipt(raw)
            self.assertEqual(self.portable_result(runner)["reason"], "git_bounds")

    def test_portable_closure_keeps_unselected_workflows_and_dependency_changes(self):
        baseline = portable_tree()
        diff = record(b"tools/ledger-transport/archive_tail.py")
        for path, oid in ((b"internal/proof/core.go", b"a" * 40),
                          (b".github/workflows/ci.yml", b"b" * 40),
                          (EXPORT.encode(), b"a" * 40), (PREPARATION.encode(), b"a" * 40),
                          (b"tools/owned-devnet-query/contract.json", b"a" * 40)):
            raw = baseline.replace(tree_record(path, oid=oid), tree_record(path, oid=b"c" * 40))
            runner = FixtureRunner(diff=diff)
            runner.overrides["ls-tree"] = raw, receipt(raw)
            report = self.portable_result(runner)
            self.assertEqual((report["run_runtime"], report["reason"]), (True, "portable_source_pin"))
        for added in (tree_record(b"tools/new.py"), tree_record(b"docs/linked.md", mode=b"120000")):
            runner = FixtureRunner(diff=diff)
            raw = baseline + added
            runner.overrides["ls-tree"] = raw, receipt(raw)
            self.assertEqual(self.portable_result(runner)["reason"], "portable_source_pin")

    def test_portable_closure_remains_stable_after_another_reviewed_leaf_changes(self):
        baseline = portable_tree()
        diff = record(b"tools/ledger-transport/archive_tail.py")
        for path in (b"tools/owned-devnet-query/review.py",
                     b"tools/ledger-export/inventory_completed_export.py", b"docs/contract.md"):
            original = tree_record(path)
            runner = FixtureRunner(diff=diff)
            raw = baseline.replace(original, tree_record(path, oid=b"c" * 40))
            runner.overrides["ls-tree"] = raw, receipt(raw)
            report = self.portable_result(runner)
            self.assertEqual(report["required_workflows"], [TRANSPORT])
            self.assertEqual(report["commands"][-1]["streams"]["stdout"]["sha256"], hashlib.sha256(raw).hexdigest())
            changed_mode = raw.replace(tree_record(path, oid=b"c" * 40), tree_record(path, mode=b"120000"))
            runner.overrides["ls-tree"] = changed_mode, receipt(changed_mode)
            self.assertEqual(self.portable_result(runner)["reason"], "portable_source_pin")

    def test_portable_closure_literal_digest_and_bounds(self):
        kept = [tree_record(b"internal/proof/core.go"), tree_record(b".github/workflows/ci.yml", oid=b"b" * 40),
                tree_record(b"tools/owned-devnet-query/contract.json"),
                *(tree_record(path.encode()) for path in (TRANSPORT, EXPORT, PREPARATION))]
        expected = b"".join(sorted(kept))
        for raw in (portable_tree(), b"\0".join(reversed(portable_tree().split(b"\0")[:-1])) + b"\0"):
            self.assertEqual(M.portable_fingerprint(raw), {"sha256": hashlib.sha256(expected).hexdigest(),
                                                            "bytes": len(expected), "entries": len(kept)})
        for raw in (b"", b"x" * (M.MAX_TREE_BYTES + 1), portable_tree()[:-1], portable_tree() * 2,
                    tree_record(b"docs/only.md"), tree_record(b"source", mode=b"160000"),
                    tree_record(b"bad//path"), tree_record(b"/absolute"), tree_record(b"../path")):
            with self.subTest(size=len(raw)):
                with self.assertRaises(M.ScopeError):
                    M.portable_fingerprint(raw)

    def test_portable_output_guard_rejects_missing_or_altered_workflow_obligations(self):
        diff = (record(b"tools/ledger-transport/transport.py")
                + record(b"tools/owned-devnet-query/review.py") + record())
        result = self.portable_result(FixtureRunner(diff=diff))
        for key, value in (("required_workflows", [TRANSPORT, EXPORT]),
                           ("portable_workflows", result["portable_workflows"][:-1]),
                           ("portable_event_tree", FEATURE),
                           ("portable_paths", result["portable_paths"] * 2),
                           ("portable_paths", [{"path": "tools/owned-devnet-query/runner.py", "change": "M"}]),
                           ("portable_paths", [{**result["portable_paths"][0], "change": "A"}]),
                           ("documentation_paths", [{"path": "docs/CON.md", "change": "R"}]),
                           ("runtime_closure", {**result["runtime_closure"], "matched": False})):
            with self.subTest(key=key):
                self.assertIsNotNone(self.workflow_guard(self.guard_bytes({**result, key: value}))[0])
        for path in (TRANSPORT, EXPORT, PREPARATION):
            changed = copy.deepcopy(result)
            changed["source_pins"][path]["git_sha256"] = "0" * 64
            self.assertIsNotNone(self.workflow_guard(self.guard_bytes(changed))[0])
        changed = copy.deepcopy(result)
        changed["commands"][6]["git_arguments"][2] = BASE
        self.assertIsNotNone(self.workflow_guard(self.guard_bytes(changed))[0])
        for version in ("v2", "v4", "v5"):
            historical = {**result, "format": "zenon-ci-change-scope/" + version}
            self.assertIsNotNone(self.workflow_guard(self.guard_bytes(historical))[0])


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
