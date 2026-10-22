#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Controls for explicit child recipes; mocked records are isolated unit inputs."""
import ast
from contextlib import contextmanager
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
from types import ModuleType
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("child_hex_control_subject", HERE / "selected_child_hex.py")
C = importlib.util.module_from_spec(spec)
spec.loader.exec_module(C)
REVISION = "ab" * 20


def semantic_ast(node):
    """Keep parsed semantics; normalize only the version-added empty type list."""
    if isinstance(node, ast.AST):
        return {"node": type(node).__name__, "fields": {
            name: semantic_ast(value) for name, value in ast.iter_fields(node)
            if not (name == "type_params" and type(value) is list and not value)}}
    if type(node) is list:
        return [semantic_ast(value) for value in node]
    if type(node) is bytes:
        return {"literal_bytes_hex": node.hex()}
    if node is None or type(node) in (str, int, float, bool):
        return node
    raise ValueError("Unselected AST field")


def semantic_fingerprint(node):
    return C.sha(json.dumps(semantic_ast(node), sort_keys=True, separators=(",", ":"), allow_nan=False).encode())


def control_module():
    program = ModuleType("controlled_test_local_dispatch")
    program.__file__ = str(HERE / C.CONTROL)
    program.CLI_RUN = subprocess.run
    return program


def arguments(kind):
    tail = {"valid-revision": ["--source-revision", REVISION],
            "invalid-revision": ["--source-revision", "invalid"],
            "tampered-corpus": ["--corpus", str(HERE / "tampered.json")]}[kind]
    return [sys.executable, "-I", "-B", str(HERE / C.TARGET), *tail]


def simulated_recipe(owner, status=0, stdout=b"control stdout\n", stderr=b""):
    return {"format_version": 1, "kind": "selected-child-target-hex-CLI",
            "execution_revision": REVISION, "program": C.TARGET, "mode": owner.mode,
            "helper_sha256": owner.tool_pin, "declared_exit": status,
            "stdout_sha256": C.sha(stdout), "stdout_bytes": len(stdout),
            "stderr_sha256": C.sha(stderr), "stderr_bytes": len(stderr),
            "binding_manifest": copy.deepcopy(owner.expected_bindings),
            "selected_function_identities_restored": True, "original_entrypoint_guard_executed": True,
            "recorded_producer_source_inputs_rebound": False, "reference_backend_executed": False,
            "production_acceptance_enabled": False}


@contextmanager
def simulated_child(owner, change=None, status=0, stdout=b"control stdout\n", stderr=b""):
    report = simulated_recipe(owner, status, stdout, stderr)
    if change:
        change(report)
    result = subprocess.CompletedProcess(["controlled-synthetic-command"], status, stdout, stderr)
    with mock.patch.object(C.subprocess, "run", return_value=result) as run, \
            mock.patch.object(C, "read_report", return_value=report):
        yield run, result


class SelectedChildControls(unittest.TestCase):
    def test_all_original_23_control_assertions_and_order_are_preserved(self):
        tree = ast.parse((HERE / C.CONTROL).read_bytes())
        cls = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "FileResourceControls")

        class OriginalCalls(ast.NodeTransformer):
            def visit_Name(self, node):
                if node.id == "CLI_RUN":
                    return ast.copy_location(ast.Attribute(value=ast.Name(id="subprocess", ctx=ast.Load()),
                                                           attr="run", ctx=node.ctx), node)
                return node

        cls = OriginalCalls().visit(cls)
        self.assertEqual(semantic_fingerprint(cls),
                         "6b2b6acc4b6cbd13a035f951fd3fa2956552544b3cc51fd0fcb6d0cbaa62e424")
        self.assertEqual(len([n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name.startswith("test_")]), 23)

    def test_empty_version_added_type_parameters_do_not_change_semantics(self):
        before = ast.parse("class C:\n    pass\n").body[0]
        before._fields = tuple(name for name in before._fields if name != "type_params")
        after = copy.deepcopy(before)
        after._fields = (*before._fields, "type_params")
        after.type_params = []
        self.assertEqual(semantic_fingerprint(before), semantic_fingerprint(after))
        after.type_params = [ast.Name(id="T", ctx=ast.Load())]
        self.assertNotEqual(semantic_fingerprint(before), semantic_fingerprint(after))

    def test_assertions_literals_and_order_remain_fingerprint_inputs(self):
        baseline = semantic_fingerprint(ast.parse("assert True\n"))
        for source in ("assert False\n", "assert 1\n", "assert b'True'\n", "assert True, 'changed'\n"):
            self.assertNotEqual(baseline, semantic_fingerprint(ast.parse(source)))
        first = ast.parse("assert True\nassert False\n")
        second = ast.parse("assert False\nassert True\n")
        self.assertNotEqual(semantic_fingerprint(first), semantic_fingerprint(second))

    def test_recorded_checker_and_selected_control_source_bytes_are_pinned(self):
        self.assertEqual(C.sha((HERE / C.TARGET).read_bytes()), C.TARGET_SHA256)
        self.assertEqual(C.sha((HERE / C.CONTROL).read_bytes()), C.CONTROL_SHA256)
        real = C.load("unchanged_direct_cli_controls", C.CONTROL)
        self.assertIs(real.CLI_RUN, subprocess.run)

    def test_test_local_selection_restores_and_does_not_patch_subprocess(self):
        program = control_module()
        original = subprocess.run
        with C.selected_children(program, C.CONTROL, "translated", REVISION) as owner:
            self.assertIs(program.CLI_RUN, owner.replacement)
            self.assertIs(subprocess.run, original)
        self.assertIs(program.CLI_RUN, original)
        self.assertTrue(owner.closed)

    def test_exception_and_nested_selection_preserve_outer_owner(self):
        program = control_module()
        with self.assertRaisesRegex(RuntimeError, "controlled failure"):
            with C.selected_children(program, C.CONTROL, "translated", REVISION) as owner:
                with self.assertRaises(ValueError):
                    with C.selected_children(program, C.CONTROL, "translated", REVISION):
                        self.fail("nested selection entered")
                self.assertIs(program.CLI_RUN, owner.replacement)
                raise RuntimeError("controlled failure")
        self.assertIs(program.CLI_RUN, subprocess.run)

    def test_replaced_dispatch_refuses_after_restoring_original(self):
        program = control_module()
        with self.assertRaises(ValueError):
            with C.selected_children(program, C.CONTROL, "translated", REVISION):
                program.CLI_RUN = lambda *a, **k: None
        self.assertIs(program.CLI_RUN, subprocess.run)

    def test_unknown_program_mode_revision_and_owner_refuse_before_install(self):
        program = control_module()
        for selected, mode, revision in (("other.py", "translated", REVISION),
                                         (C.CONTROL, "fast", REVISION), (C.CONTROL, "translated", "main")):
            with self.assertRaises(ValueError):
                with C.selected_children(program, selected, mode, revision):
                    self.fail("unselected scope entered")
            self.assertIs(program.CLI_RUN, subprocess.run)
        program.__file__ = str(HERE / "other.py")
        with self.assertRaises(ValueError):
            C.SelectedChildren(program, "translated", REVISION)

    def test_changed_control_or_target_pin_refuses(self):
        program = control_module()
        for name in ("CONTROL_SHA256", "TARGET_SHA256"):
            with mock.patch.object(C, name, "00" * 32):
                with self.assertRaises(ValueError):
                    C.SelectedChildren(program, "translated", REVISION)
            self.assertIs(program.CLI_RUN, subprocess.run)

    def test_cross_thread_invocation_refuses_without_a_child_launch(self):
        program = control_module()
        errors = []
        with C.selected_children(program, C.CONTROL, "translated", REVISION) as owner:
            def invoke():
                try:
                    owner.invoke(arguments("valid-revision"), capture_output=True)
                except ValueError:
                    errors.append("refused")
            thread = threading.Thread(target=invoke)
            thread.start()
            thread.join(timeout=5)
            self.assertFalse(thread.is_alive())
            self.assertEqual(errors, ["refused"])
            self.assertEqual(owner.records, [])

    def test_unselected_arguments_order_or_output_mode_refuse_before_launch(self):
        program = control_module()
        with C.selected_children(program, C.CONTROL, "translated", REVISION) as owner:
            cases = [arguments("invalid-revision"), [sys.executable, "-I", "-B", str(HERE / "other.py")],
                     arguments("valid-revision") + ["--case", "one"]]
            with mock.patch.object(C.subprocess, "run") as run:
                for argv in cases:
                    with self.assertRaises(ValueError):
                        owner.invoke(argv, capture_output=True)
                with self.assertRaises(ValueError):
                    owner.invoke(arguments("valid-revision"), capture_output=False)
                run.assert_not_called()

    def test_completed_child_output_is_returned_without_filtering(self):
        program = control_module()
        with C.selected_children(program, C.CONTROL, "translated", REVISION) as owner:
            with simulated_child(owner) as (run, result):
                actual = owner.invoke(arguments("valid-revision"), capture_output=True)
            self.assertIs(actual, result)
            self.assertEqual(actual.stdout, b"control stdout\n")
            self.assertEqual(run.call_args.kwargs, {"capture_output": True, "timeout": 60})
            self.assertEqual(run.call_args.args[0][0:4], [sys.executable, "-I", "-B", str(C.TOOL)])

    def test_untyped_or_mismatched_exit_and_stream_receipts_refuse(self):
        changes = [lambda r: r.update(declared_exit=True), lambda r: r.update(declared_exit=1),
                   lambda r: r.update(stdout_sha256="00" * 32), lambda r: r.update(stderr_sha256="00" * 32),
                   lambda r: r.update(stdout_bytes=True), lambda r: r.update(stderr_bytes=1)]
        for change in changes:
            program = control_module()
            with C.selected_children(program, C.CONTROL, "translated", REVISION) as owner:
                with simulated_child(owner, change):
                    with self.assertRaises(ValueError):
                        owner.invoke(arguments("valid-revision"), capture_output=True)
                self.assertEqual(owner.records, [])

    def test_wrong_source_scope_mode_and_ownership_receipts_refuse(self):
        changes = [lambda r: r.update(format_version=True), lambda r: r.update(mode="reference"),
                   lambda r: r.update(program="other.py"), lambda r: r.update(execution_revision="cd" * 20),
                   lambda r: r.update(helper_sha256="00" * 32), lambda r: r.update(extra=True),
                   lambda r: r.pop("binding_manifest"),
                   lambda r: r["binding_manifest"]["current_execution_inputs"].update({"check.py": "00" * 32}),
                   lambda r: r.update(original_entrypoint_guard_executed=False),
                   lambda r: r.update(selected_function_identities_restored=False),
                   lambda r: r.update(recorded_producer_source_inputs_rebound=True),
                   lambda r: r.update(reference_backend_executed=True),
                   lambda r: r.update(production_acceptance_enabled=True)]
        for change in changes:
            program = control_module()
            with C.selected_children(program, C.CONTROL, "translated", REVISION) as owner:
                with simulated_child(owner, change):
                    with self.assertRaises((ValueError, KeyError)):
                        owner.invoke(arguments("valid-revision"), capture_output=True)
                self.assertEqual(owner.records, [])

    def test_all_three_recipes_and_exits_are_required_and_returned_independently(self):
        program = control_module()
        with C.selected_children(program, C.CONTROL, "translated", REVISION) as owner:
            with self.assertRaises(ValueError):
                owner.report()
            for kind, status in zip(C.KINDS, (0, 1, 1)):
                with simulated_child(owner, status=status, stdout=b"" if status else b"control stdout\n"):
                    owner.invoke(arguments(kind), capture_output=True)
            with self.assertRaises(ValueError):
                owner.invoke(arguments("valid-revision"), capture_output=True)
        report = owner.report()
        self.assertEqual([r["actual_exit"] for r in report["children"]], [0, 1, 1])
        self.assertEqual(report["actual_fresh_CLI_processes"], 3)
        report["children"].clear()
        self.assertEqual(len(owner.report()["children"]), 3)

    def test_incomplete_selection_never_emits_a_complete_recipe(self):
        with C.selected_children(control_module(), C.CONTROL, "translated", REVISION) as owner:
            pass
        with self.assertRaises(ValueError):
            owner.report()

    def test_new_report_is_exclusive_canonical_and_bounded(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "report.json"
            C.write_report(C.report_destination(path), {"kind": "isolated-unit-control"})
            self.assertEqual(C.read_report(path), {"kind": "isolated-unit-control"})
            before = path.read_bytes()
            with self.assertRaises((ValueError, FileExistsError)):
                C.write_report(path, {"replacement": True})
            self.assertEqual(path.read_bytes(), before)
            for raw in (b'{"kind":"one","kind":"two"}\n', b'{"kind": "noncanonical"}\n',
                        b"x" * (C.MAX_REPORT_BYTES + 1)):
                path.write_bytes(raw)
                with self.assertRaises((ValueError, json.JSONDecodeError)):
                    C.read_report(path)

    def test_existing_report_refuses_before_import_or_computation(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "retained.json"
            path.write_bytes(b"retained original bytes")
            with mock.patch.object(C, "load") as load:
                with self.assertRaises(ValueError):
                    C.main(["--mode", "translated", "--execution-revision", REVISION,
                            "--report", str(path), "--", "--source-revision", REVISION])
                load.assert_not_called()
            self.assertEqual(path.read_bytes(), b"retained original bytes")

    def test_actual_fresh_child_preserves_original_failure_console_and_guard(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "execution.json"
            result = subprocess.run([sys.executable, "-I", "-B", str(C.TOOL), "--mode", "translated",
                                     "--execution-revision", REVISION, "--report", str(path),
                                     "--", "--source-revision", "invalid"], capture_output=True, timeout=60)
            original = subprocess.run([sys.executable, "-I", "-B", str(HERE / C.TARGET),
                                       "--source-revision", "invalid"], capture_output=True, timeout=60)
            self.assertEqual(original.returncode, 1)
            self.assertEqual((result.returncode, result.stdout, result.stderr),
                             (original.returncode, original.stdout, original.stderr))
            recipe = C.read_report(path)
            self.assertEqual(recipe["declared_exit"], result.returncode)
            self.assertEqual(recipe["stderr_sha256"], C.sha(result.stderr))
            self.assertTrue(recipe["original_entrypoint_guard_executed"])
            self.assertTrue(recipe["selected_function_identities_restored"])
            self.assertFalse(recipe["binding_manifest"]["recorded_producer_source_inputs_rebound"])

    def test_actual_fresh_child_success_is_byte_identical_to_direct_original(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "execution.json"
            original = subprocess.run([sys.executable, "-I", "-B", str(HERE / C.TARGET),
                                       "--source-revision", REVISION], capture_output=True, timeout=180)
            result = subprocess.run([sys.executable, "-I", "-B", str(C.TOOL), "--mode", "translated",
                                     "--execution-revision", REVISION, "--report", str(path),
                                     "--", "--source-revision", REVISION], capture_output=True, timeout=60)
            self.assertEqual(original.returncode, 0)
            self.assertEqual((result.returncode, result.stdout, result.stderr),
                             (original.returncode, original.stdout, original.stderr))
            recipe = C.read_report(path)
            self.assertEqual(recipe["declared_exit"], 0)
            self.assertEqual(recipe["stdout_sha256"], C.sha(original.stdout))
            self.assertEqual(json.loads(result.stdout)["recorded_fresh_child_samples"], 180)
            self.assertFalse(recipe["reference_backend_executed"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
