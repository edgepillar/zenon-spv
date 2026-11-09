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


def tree_record(path, mode=b"100644", kind=b"blob", oid=b"a" * 40):
    return mode + b" " + kind + b" " + oid + b"\t" + path + b"\0"


def archive_tree():
    return (tree_record(b"internal/proof/core.go")
            + tree_record(b".github/workflows/ci.yml", oid=b"b" * 40)
            + tree_record(b"docs/contract.md")
            + tree_record(b"tools/check-ci-change-scope.py")
            + tree_record(b"tools/ledger-transport/archive_tail.py"))


def native_tree():
    return (archive_tree()
            + tree_record(b"internal/verify/experimental_v3_state.go")
            + tree_record(b"tools/gen-state-root-vectors/check_patch_file.py")
            + tree_record(b"tools/gen-state-root-vectors/testdata/candidate-patch-file.json"))


def preparation_tree():
    return (archive_tree()
            + tree_record(M.PREPARATION_WORKFLOW.encode())
            + tree_record(b"tools/owned-devnet-query/inputs.py")
            + tree_record(b"tools/owned-devnet-query/contract.json"))


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
            return raw, copy.deepcopy(result)
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
            if args[1].split(":", 1)[1] in (M.ARCHIVE_WORKFLOW, M.PREPARATION_WORKFLOW,
                                            M.R1_EXPORT_WORKFLOW):
                raw = raw.replace(b"\r\n", b"\n")
        elif args[0] == "diff":
            raw = self.diff
        elif args[0] == "ls-tree":
            raw = archive_tree()
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

    def archive_result(self, diff=None, runner=None, selected=None):
        selected = selection() if selected is None else selected
        runner = FixtureRunner(selected, record(b"tools/ledger-transport/archive_tail.py")
                               if diff is None else diff) if runner is None else runner
        with mock.patch.object(M, "RUNTIME_SOURCE_PIN", M.runtime_fingerprint(archive_tree())["sha256"]):
            return M.select_scope(ROOT, selected, runner)

    def test_archive_modified_leaves_and_mixed_documents_select_portable(self):
        for path in sorted(M.ARCHIVE_FILES):
            with self.subTest(path=path):
                result = self.archive_result(record(path.encode()) + record())
                self.assertFalse(result["run_runtime"])
                self.assertEqual((result["format"], result["status"]), (M.ARCHIVE_FORMAT, "PORTABLE_ARCHIVE_ONLY"))
                self.assertEqual(result["portable_archive_paths"], [{"path": path, "change": "M"}])
                self.assertEqual(result["documentation_paths"], [{"path": "docs/contract.md", "change": "M"}])
                self.assertEqual(result["required_workflows"], [M.ARCHIVE_WORKFLOW])
                self.assertEqual(len(result["source_pins"]), 4)
                self.assertEqual(len(result["commands"]), 9)
                self.assertFalse(result["runtime_qualification_transferred"])

    def test_archive_direct_parent_push_selects_same_portable_lane(self):
        selected = selection("push")
        result = self.archive_result(selected=selected)
        self.assertFalse(result["run_runtime"])
        self.assertEqual(result["selection"], selected)

    def test_archive_add_delete_modes_renames_and_aliases_require_runtime(self):
        path = b"tools/ledger-transport/archive_tail.py"
        records = [record(path, b"A", b"000000"), record(path, b"D", new_mode=b"000000"),
                   record(path, old_mode=b"100755", new_mode=b"100755"),
                   record(path, old_mode=b"120000", new_mode=b"120000"),
                   record(path, change=b"R100"), record(path) + record(path),
                   record(path) + record(path.upper()), record(path.replace(b"/", b"//", 1))]
        for raw in records:
            with self.subTest(raw=raw[:90]):
                self.require_full(raw)

    def test_archive_raw_stream_export_and_other_dependencies_keep_runtime(self):
        for path in ("tools/ledger-transport/transport.py", "tools/ledger-transport/transport_test.py",
                     "tools/ledger-inventory/inventory.py", "tools/ledger-export/cli_test.go",
                     "tools/ledger-transport/future.py", "internal/proof/core.go", "go.mod"):
            with self.subTest(path=path):
                self.require_full(record(b"tools/ledger-transport/archive_index.py") + record(path.encode()))

    def test_archive_pinned_workflow_base_and_checkout_must_match(self):
        runner = FixtureRunner(diff=record(b"tools/ledger-transport/archive_tail.py"))
        original = runner.__call__
        def changed_base(root, args, limit):
            raw, result = original(root, args, limit)
            if args == ["show", BASE + ":" + M.ARCHIVE_WORKFLOW]:
                raw += b"\n"
                result = receipt(raw)
            return raw, result
        result = self.archive_result(runner=changed_base)
        self.assertTrue(result["run_runtime"])
        self.assertEqual(result["reason"], "archive_workflow_pin")
        for field, bad in (("ARCHIVE_WORKFLOW_SHA256", "0" * 64), ("ARCHIVE_WORKFLOW_BYTES", 1)):
            with self.subTest(field=field), mock.patch.object(M, field, bad):
                result = self.archive_result()
                self.assertTrue(result["run_runtime"])
                self.assertEqual(result["reason"], "archive_workflow_pin")

    def test_archive_workflow_and_tree_incomplete_results_keep_runtime(self):
        for target in ("archive-source", "archive-base", "ls-tree"):
            for code, complete in ((1, True), (0, False), (None, False)):
                runner = FixtureRunner(diff=record(b"tools/ledger-transport/archive_index.py"))
                original = runner.__call__
                def incomplete(root, args, limit):
                    raw, value = original(root, args, limit)
                    selected = (args[0] == "ls-tree" if target == "ls-tree" else
                                args == ["show", (CHECKOUT if target == "archive-source" else BASE)
                                         + ":" + M.ARCHIVE_WORKFLOW])
                    return (b"", receipt(actual_exit=code, complete=complete)) if selected else (raw, value)
                with self.subTest(target=target, code=code, complete=complete):
                    result = self.archive_result(runner=incomplete)
                    self.assertTrue(result["run_runtime"])
                    self.assertEqual(result["reason"], "git_incomplete_or_failed")
                    self.assertEqual(result["commands"][-1]["actual_exit"], code)

    def test_archive_future_runtime_source_changes_disable_portable(self):
        original = archive_tree()
        for raw in (original.replace(b"a" * 40, b"c" * 40, 1),
                    original.replace(b"b" * 40, b"c" * 40, 1),
                    original + tree_record(b"tools/new-dependency.py"),
                    original + tree_record(b"docs/linked.md", mode=b"120000"),
                    original + tree_record(b"tools/ledger-transport/transport.py")):
            runner = FixtureRunner(diff=record(b"tools/ledger-transport/archive_tail.py"))
            runner.overrides["ls-tree"] = raw, receipt(raw)
            with self.subTest(size=len(raw)):
                result = self.archive_result(runner=runner)
                self.assertTrue(result["run_runtime"])
                self.assertEqual(result["reason"], "runtime_source_pin")

    def test_archive_tree_excludes_only_regular_reviewed_paths(self):
        expected = M.runtime_fingerprint(archive_tree())
        for path in sorted(M.ARCHIVE_FILES | set(M.SOURCE_FILES[:2]) | {"README.md", "docs/new.md"}):
            if path in ("tools/ledger-transport/archive_tail.py", "tools/check-ci-change-scope.py"):
                continue
            with self.subTest(path=path):
                self.assertEqual(M.runtime_fingerprint(archive_tree() + tree_record(path.encode())), expected)
                self.assertNotEqual(M.runtime_fingerprint(archive_tree() + tree_record(path.encode(), mode=b"120000")), expected)

    def test_archive_tree_bounds_shapes_and_duplicates_are_refused(self):
        invalid = [b"", b"x", "not bytes", b"x" * (M.MAX_TREE_BYTES + 1),
                   tree_record(b"/absolute"), tree_record(b"a/../b"), tree_record(b"a\\b"),
                   tree_record(b"source", oid=b"0" * 40), tree_record(b"source", mode=b"040000", kind=b"tree"),
                   tree_record(b"source", mode=b"160000"), archive_tree() + tree_record(b"internal/proof/core.go"),
                   b"".join(tree_record(("code/" + str(n)).encode()) for n in range(M.MAX_TREE_RECORDS + 1)),
                   tree_record(b"README.md")]
        for raw in invalid:
            with self.subTest(type=type(raw).__name__, size=len(raw)):
                with self.assertRaises(M.ScopeError):
                    M.runtime_fingerprint(raw)

    def test_archive_tree_ordering_and_literal_digest_are_independent(self):
        kept = [tree_record(b"internal/proof/core.go"), tree_record(b".github/workflows/ci.yml", oid=b"b" * 40)]
        expected = {"sha256": hashlib.sha256(b"".join(sorted(kept))).hexdigest(),
                    "bytes": sum(map(len, kept)), "entries": 2}
        self.assertEqual(M.runtime_fingerprint(archive_tree()), expected)
        self.assertEqual(M.runtime_fingerprint(b"\0".join(reversed(archive_tree().split(b"\0")[:-1])) + b"\0"), expected)

    def test_archive_workflow_guard_accepts_complete_portable_selection(self):
        for path in sorted(M.ARCHIVE_FILES):
            result = self.archive_result(record(path.encode()))
            with self.subTest(path=path):
                self.assertEqual(self.workflow_guard(self.guard_bytes(result)),
                                 (None, "run_runtime=false\nrun_recorded_oracles=false\n"))

    def test_archive_workflow_guard_refuses_other_lanes_bindings_and_closures(self):
        result = self.archive_result()
        mutations = []
        for key, value in (("format", M.FORMAT), ("status", "DOCUMENTATION_ONLY"),
                           ("required_workflows", []), ("required_workflows", ["other"]),
                           ("portable_archive_paths", []), ("documentation_paths", "unknown"),
                           ("runtime_qualification_transferred", True), ("commands", result["commands"][:-1])):
            changed = copy.deepcopy(result);changed[key] = value;mutations.append(changed)
        for path in ([{"path": "tools/ledger-transport/transport.py", "change": "M"}],
                     [{"path": "tools/ledger-transport/archive_tail.py", "change": "A"}],
                     result["portable_archive_paths"] * 2):
            changed = copy.deepcopy(result);changed["portable_archive_paths"] = path;mutations.append(changed)
        for target, field, value in (("archive_workflow", "base_matches_checkout", False),
                                     ("archive_workflow", "sha256", "0" * 64),
                                     ("runtime_closure", "matched", False),
                                     ("runtime_closure", "expected_sha256", "0" * 64),
                                     ("runtime_closure", "bytes", True),
                                     ("runtime_closure", "bytes", (2 << 20) + 1),
                                     ("runtime_closure", "entries", 0),
                                     ("runtime_closure", "entries", True)):
            changed = copy.deepcopy(result);changed[target][field] = value;mutations.append(changed)
        changed = copy.deepcopy(result);del changed["source_pins"][M.ARCHIVE_WORKFLOW];mutations.append(changed)
        changed = copy.deepcopy(result);changed["source_pins"][M.ARCHIVE_WORKFLOW]["git_sha256"] = "0" * 64;mutations.append(changed)
        for index, changed in enumerate(mutations):
            with self.subTest(mutation=index):
                self.assertIsNotNone(self.workflow_guard(self.guard_bytes(changed))[0])

    def test_archive_workflow_guard_runtime_fallback_never_skips(self):
        result = M.select_scope(ROOT, selection(), FixtureRunner(diff=record(b"tools/ledger-transport/archive_tail.py")))
        self.assertTrue(result["run_runtime"])
        self.assertEqual(result["format"], M.ARCHIVE_FORMAT)
        self.assertEqual(self.workflow_guard(self.guard_bytes(result)),
                         (None, "run_runtime=true\nrun_recorded_oracles=true\n"))

    def test_archive_selector_controls_and_workflow_changes_need_full_lane(self):
        for path in (*M.SOURCE_FILES, M.ARCHIVE_WORKFLOW):
            with self.subTest(path=path):
                self.require_full(record(b"tools/ledger-transport/archive_tail.py") + record(path.encode()))

    def test_archive_tree_receipts_and_source_byte_caps_are_retained(self):
        result = self.archive_result()
        self.assertEqual(result["commands"][-1]["streams"]["stdout"]["sha256"], hashlib.sha256(archive_tree()).hexdigest())
        runner = FixtureRunner(diff=record(b"tools/ledger-transport/archive_tail.py"))
        raw = b"x" * (M.MAX_TREE_BYTES + 1)
        runner.overrides["ls-tree"] = raw, receipt(raw)
        result = self.archive_result(runner=runner)
        self.assertTrue(result["run_runtime"])
        self.assertEqual(result["reason"], "git_bounds")

    def test_archive_branch_cannot_mask_malformed_or_unselected_diff_records(self):
        for raw in (record(b"tools/ledger-transport/archive_tail.py")[:-1],
                    record(b"tools/ledger-transport/archive_tail.py") + b"bad\0unknown\0",
                    record(b"tools/ledger-transport/archive_tail.py") + record(b"internal/other.go")):
            runner = FixtureRunner(diff=raw)
            result = self.archive_result(runner=runner)
            self.assertTrue(result["run_runtime"])
            self.assertFalse(any(args[0] == "ls-tree" for args, _ in runner.calls))


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

    def preparation_result(self, runner):
        raw = preparation_tree()
        runner.overrides.setdefault("ls-tree", (raw, receipt(raw)))
        with mock.patch.object(M, "PREPARATION_SOURCE_PIN", M.preparation_fingerprint(raw)["sha256"]):
            return M.select_scope(ROOT, runner.selection, runner)

    def test_preparation_selected_leaves_require_the_pinned_three_platform_workflow(self):
        for event in ("pull_request", "push"):
            for path in sorted(M.PREPARATION_FILES):
                with self.subTest(event=event, path=path):
                    runner = FixtureRunner(selection(event), record(path.encode()) + record())
                    report = self.preparation_result(runner)
                    self.assertIs(report["run_runtime"], False)
                    self.assertEqual((report["format"], report["status"]),
                                     (M.PREPARATION_FORMAT, "OWNED_DEVNET_PREPARATION_ONLY"))
                    self.assertEqual(report["preparation_paths"], [{"path": path, "change": "M"}])
                    self.assertEqual(report["required_workflows"], [M.PREPARATION_WORKFLOW])
                    self.assertEqual(report["preparation_event_tree"], TREE)
                    self.assertEqual(len(report["commands"]), 10 if event == "pull_request" else 9)
                    self.assertFalse(report["runtime_qualification_transferred"])
                    if event == "pull_request":
                        self.assertEqual(self.workflow_guard(self.guard_bytes(report)),
                                         (None, "run_runtime=false\nrun_recorded_oracles=false\n"))

    def test_preparation_other_source_paths_modes_and_large_diffs_keep_full_lane(self):
        path = b"tools/owned-devnet-query/inputs.py"
        rows = [record(path, b"A", b"000000"), record(path, b"D", new_mode=b"000000"),
                record(path, old_mode=b"100755", new_mode=b"100755"), record(path) + record(path.upper()),
                record(path) + b"".join(record(f"docs/d{i}.md".encode())
                                         for i in range(M.MAX_FILTERED_DIFF_RECORDS))]
        for unrelated in (M.PREPARATION_WORKFLOW, "tools/owned-devnet-query/contract.json",
                          "tools/owned-devnet-query/controls.py", "tools/owned-devnet-query/runner.py",
                          "internal/testdata/conformance/prepared-devnet-query-profile.json",
                          "tools/ledger-transport/archive_tail.py", "internal/verify/experimental_v3_state.go"):
            rows.append(record(path) + record(unrelated.encode()))
        for index, raw in enumerate(rows):
            with self.subTest(case=index):
                report = self.preparation_result(FixtureRunner(diff=raw))
                self.assertTrue(report["run_runtime"])
                self.assertEqual(report["status"], "RUNTIME_REQUIRED")

    def test_preparation_parent_tree_workflow_and_dependency_drift_require_full_lane(self):
        path = b"tools/owned-devnet-query/inputs.py"
        workflow = (ROOT / M.PREPARATION_WORKFLOW).read_bytes().replace(b"\r\n", b"\n")
        cases = (
            ("cat-file", f"tree {TREE}\nparent {FEATURE}\n\n".encode(), "preparation_event_diff"),
            ("cat-file", f"tree {FEATURE}\nparent {BASE}\n\n".encode(), "preparation_event_diff"),
            (("show", BASE + ":" + M.PREPARATION_WORKFLOW), workflow + b"\n", "preparation_workflow_pin"),
            ("ls-tree", preparation_tree() + tree_record(b"tools/other.py"), "preparation_source_pin"),
        )
        for command, raw, reason in cases:
            with self.subTest(command=command, reason=reason):
                runner = FixtureRunner(diff=record(path))
                runner.overrides[command] = raw, receipt(raw)
                report = self.preparation_result(runner)
                self.assertTrue(report["run_runtime"])
                self.assertEqual(report["reason"], reason)
                self.assertEqual(self.workflow_guard(self.guard_bytes(report)),
                                 (None, "run_runtime=true\nrun_recorded_oracles=true\n"))

    def test_preparation_workflow_guard_requires_event_binding_and_complete_selection(self):
        runner = FixtureRunner(diff=record(b"tools/owned-devnet-query/inputs.py"))
        report = self.preparation_result(runner)
        for key, value in (("required_workflows", []), ("preparation_event_tree", FEATURE),
                           ("preparation_workflow", {"path": M.PREPARATION_WORKFLOW}),
                           ("preparation_paths", [{"path": "tools/owned-devnet-query/runner.py", "change": "M"}]),
                           ("commands", report["commands"][:-1])):
            with self.subTest(key=key):
                changed = {**report, key: value}
                self.assertIsNotNone(self.workflow_guard(self.guard_bytes(changed))[0])

    def r1_handoff_result(self, runner):
        tree = archive_tree() + b"".join(
            tree_record(path.encode()) for path in sorted(
                M.R1_HANDOFF_FILES | {M.ARCHIVE_WORKFLOW, M.R1_EXPORT_WORKFLOW}))
        runner.overrides.setdefault("ls-tree", (tree, receipt(tree)))
        with mock.patch.object(M, "R1_HANDOFF_SOURCE_PIN", M.r1_handoff_fingerprint(tree)["sha256"]):
            return M.select_scope(ROOT, runner.selection, runner)

    def test_r1_handoff_selects_each_required_three_platform_workflow(self):
        transport, exporter = M.ARCHIVE_WORKFLOW, M.R1_EXPORT_WORKFLOW
        shared = record(b"tools/ledger-transport/transport.py")
        handoff = record(b"tools/ledger-export/inventory_completed_export.py")
        cases = ((shared, [transport, exporter]),
                 (record(b"tools/ledger-transport/transport_test.py"), [transport]),
                 (handoff, [exporter]),
                 (record(b"tools/ledger-export/inventory_completed_export_test.py"), [exporter]),
                 (record(b"tools/ledger-export/README.md"), [exporter]),
                 (handoff + record(b"docs/state-root-r1-intake.md"), [transport, exporter]),
                 (handoff + record(b"docs/native-roadmap.md"), [transport, exporter]),
                 (handoff + record(b"docs/contract.md"), [exporter]))
        for event in ("pull_request", "push"):
            for diff, required in cases:
                with self.subTest(event=event, diff=diff):
                    runner = FixtureRunner(selection(event), diff)
                    result = self.r1_handoff_result(runner)
                    self.assertEqual((result["format"], result["status"], result["run_runtime"]),
                                     (M.R1_HANDOFF_FORMAT, "R1_HANDOFF_ONLY", False))
                    self.assertEqual(result["required_workflows"], required)
                    self.assertEqual([v["path"] for v in result["r1_handoff_workflows"]], required)
                    self.assertEqual(set(result["source_pins"]), set(M.SOURCE_FILES) | set(required))
                    self.assertEqual(result["r1_handoff_event_tree"], TREE)
                    self.assertEqual(len(result["commands"]), 7 + 2 * len(required) + (event == "pull_request"))
                    self.assertEqual(self.workflow_guard(self.guard_bytes(result), runner.selection),
                                     (None, "run_runtime=false\nrun_recorded_oracles=false\n"))

    def test_r1_handoff_requires_direct_event_diff_and_bounded_paths(self):
        leaf = b"tools/ledger-transport/transport.py"
        for raw in (f"tree {FEATURE}\nparent {BASE}\n\n",
                    f"tree {TREE}\nparent {CHECKOUT}\n\n",
                    f"tree {TREE}\nparent {BASE}\nparent {FEATURE}\n\n"):
            runner = FixtureRunner(diff=record(leaf))
            runner.overrides["cat-file"] = raw.encode(), receipt(raw.encode())
            result = self.r1_handoff_result(runner)
            self.assertEqual((result["run_runtime"], result["reason"]), (True, "r1_handoff_event_diff"))
        runner = FixtureRunner(selection("push"), record(leaf))
        raw = f"{FEATURE} {CHECKOUT} {BASE}\n".encode()
        runner.overrides["rev-list"] = raw, receipt(raw)
        self.assertEqual(self.r1_handoff_result(runner)["reason"], "r1_handoff_event_diff")
        raw = record(leaf) + b"".join(record(f"docs/d{i}.md".encode())
                                      for i in range(M.MAX_FILTERED_DIFF_RECORDS))
        self.assertEqual(self.r1_handoff_result(FixtureRunner(diff=raw))["reason"], "r1_handoff_diff_count")

    def test_r1_handoff_other_paths_and_file_actions_require_full_ci(self):
        leaf = b"tools/ledger-transport/transport.py"
        records = [record(leaf, b"A", b"000000"), record(leaf, b"D", new_mode=b"000000"),
                   record(leaf, old_mode=b"100755", new_mode=b"100755"),
                   record(leaf) + record(leaf.upper())]
        records.extend(record(leaf) + record(path.encode()) for path in (
            *M.SOURCE_FILES, M.ARCHIVE_WORKFLOW, M.R1_EXPORT_WORKFLOW,
            "tools/ledger-inventory/inventory.py", "tools/ledger-export/main.go",
            "tools/ledger-export/consume_completion.py", "tools/ledger-transport/archive_tail.py",
            "internal/proof/core.go"))
        for index, diff in enumerate(records):
            with self.subTest(case=index):
                result = self.r1_handoff_result(FixtureRunner(diff=diff))
                self.assertEqual((result["run_runtime"], result["status"]), (True, "RUNTIME_REQUIRED"))

    def test_r1_handoff_refuses_workflow_drift_and_keeps_other_sources_in_closure(self):
        leaf = record(b"tools/ledger-transport/transport.py")
        for path, reason in ((M.ARCHIVE_WORKFLOW, "r1_transport_workflow_pin"),
                             (M.R1_EXPORT_WORKFLOW, "r1_export_workflow_pin")):
            runner = FixtureRunner(diff=leaf)
            raw = (ROOT / path).read_bytes() + b"\n"
            runner.overrides[("show", BASE + ":" + path)] = raw, receipt(raw)
            result = self.r1_handoff_result(runner)
            self.assertEqual((result["run_runtime"], result["reason"]), (True, reason))
        for path in (b"tools/ledger-inventory/inventory.py", b"tools/ledger-export/main.go", b"tools/new.py"):
            runner = FixtureRunner(diff=leaf)
            self.r1_handoff_result(runner)
            raw = runner.overrides["ls-tree"][0] + tree_record(path)
            runner.overrides["ls-tree"] = raw, receipt(raw)
            result = self.r1_handoff_result(runner)
            self.assertEqual((result["run_runtime"], result["reason"]), (True, "r1_handoff_source_pin"))
        runner = FixtureRunner(diff=leaf)
        runner.overrides["ls-tree"] = b"", receipt(actual_exit=1, complete=False)
        result = self.r1_handoff_result(runner)
        self.assertEqual((result["run_runtime"], result["reason"]), (True, "git_incomplete_or_failed"))
        self.assertEqual(self.workflow_guard(self.guard_bytes(result)),
                         (None, "run_runtime=true\nrun_recorded_oracles=true\n"))

    def test_r1_handoff_workflow_guard_refuses_missing_or_altered_requirements(self):
        result = self.r1_handoff_result(FixtureRunner(diff=record(b"tools/ledger-transport/transport.py")))
        for key, value in (("required_workflows", [M.ARCHIVE_WORKFLOW]),
                           ("r1_handoff_workflows", result["r1_handoff_workflows"][:1]),
                           ("r1_handoff_event_tree", FEATURE),
                           ("r1_handoff_paths", result["r1_handoff_paths"] * 2),
                           ("documentation_paths", [{"path": "internal/proof/core.go", "change": "M"}]),
                           ("documentation_paths", [{"path": "docs/../private.md", "change": "M"}]),
                           ("commands", result["commands"][:-1]),
                           ("runtime_closure", {**result["runtime_closure"], "matched": False})):
            with self.subTest(key=key):
                self.assertIsNotNone(self.workflow_guard(self.guard_bytes({**result, key: value}))[0])
        changed = copy.deepcopy(result)
        changed["source_pins"][M.R1_EXPORT_WORKFLOW]["git_sha256"] = "0" * 64
        self.assertIsNotNone(self.workflow_guard(self.guard_bytes(changed))[0])


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
