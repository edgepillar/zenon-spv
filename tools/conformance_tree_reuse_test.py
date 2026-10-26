#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Pure Git tree reuse bounds, input independence and source-binding controls."""
import copy
import hashlib
import importlib.util
from pathlib import Path
import threading
from types import ModuleType
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("git_tree_reuse_controls", HERE / "conformance_tree_reuse.py")
C = importlib.util.module_from_spec(spec)
spec.loader.exec_module(C)


def oid(kind, raw):
    return hashlib.sha1(kind + b" " + str(len(raw)).encode() + b"\0" + raw).hexdigest()


def pins(raw=b"reference\n", mode="100644"):
    return {"hello.txt": {"mode": mode, "git_blob": oid(b"blob", raw),
                          "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}}


def leaf_tree(raw=b"reference\n", mode=b"100644"):
    # Independent one-leaf Git object framing, without the reference tree walk.
    payload = mode + b" hello.txt\0" + bytes.fromhex(oid(b"blob", raw))
    return oid(b"tree", payload)


def program():
    path = C.HERE / C.PROGRAM
    spec = importlib.util.spec_from_file_location("tree_reuse_selected_program", path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


class CompleteKeyCacheControls(unittest.TestCase):
    def test_empty_and_one_leaf_objects_match_an_independent_byte_oracle(self):
        cache = C.TreeCache()
        self.assertEqual(cache.get({}, C.REFERENCE.reconstruct_tree), "4b825dc642cb6eb9a060e54bf8d69288fbee4904")
        self.assertEqual(cache.get(pins(), C.REFERENCE.reconstruct_tree), leaf_tree())
        self.assertEqual(cache.get(pins(), C.REFERENCE.reconstruct_tree), leaf_tree())
        self.assertEqual(cache.hits, 1)

    def test_nested_names_modes_and_git_directory_sorting_match_original(self):
        value = pins()
        value["folder/a"] = value.pop("hello.txt")
        value["folder.txt"] = dict(pins(b"other\n", "100755")["hello.txt"])
        value["unicode-\u00e9.txt"] = dict(pins()["hello.txt"])
        cache = C.TreeCache()
        expected = C.REFERENCE.reconstruct_tree(value)
        self.assertEqual(cache.get(value, C.REFERENCE.reconstruct_tree), expected)
        self.assertEqual(cache.get(copy.deepcopy(value), C.REFERENCE.reconstruct_tree), expected)
        self.assertEqual(cache.hits, 1)

    def test_path_mode_and_blob_bytes_all_select_their_own_computation(self):
        cache = C.TreeCache()
        first = cache.get(pins(), C.REFERENCE.reconstruct_tree)
        self.assertNotEqual(cache.get(pins(b"other\n"), C.REFERENCE.reconstruct_tree), first)
        self.assertNotEqual(cache.get(pins(mode="100755"), C.REFERENCE.reconstruct_tree), first)
        renamed = {"other.txt": pins()["hello.txt"]}
        self.assertNotEqual(cache.get(renamed, C.REFERENCE.reconstruct_tree), first)
        self.assertEqual(cache.computations, 4)

    def test_unused_pin_metadata_still_belongs_to_the_complete_key(self):
        cache = C.TreeCache()
        value = pins()
        expected = cache.get(value, C.REFERENCE.reconstruct_tree)
        value["hello.txt"]["bytes"] += 1
        self.assertEqual(cache.get(value, C.REFERENCE.reconstruct_tree), expected)
        value["hello.txt"]["sha256"] = "0" * 64
        self.assertEqual(cache.get(value, C.REFERENCE.reconstruct_tree), expected)
        self.assertEqual(cache.computations, 3)
        self.assertEqual(cache.hits, 0)

    def test_order_is_preserved_even_for_a_reference_prefix_collision(self):
        row = pins()["hello.txt"]
        first = {"folder": dict(row), "folder/a": dict(row)}
        second = dict(reversed(list(first.items())))
        cache = C.TreeCache()
        self.assertEqual(cache.get(first, C.REFERENCE.reconstruct_tree), C.REFERENCE.reconstruct_tree(first))
        with self.assertRaises(ValueError):
            cache.get(second, C.REFERENCE.reconstruct_tree)
        self.assertEqual(cache.hits, 0)

    def test_caller_mutation_does_not_change_a_retained_answer(self):
        cache = C.TreeCache()
        value = pins()
        first = cache.get(value, C.REFERENCE.reconstruct_tree)
        value["hello.txt"].update(pins(b"changed\n")["hello.txt"])
        self.assertEqual(cache.get(pins(), C.REFERENCE.reconstruct_tree), first)
        self.assertNotEqual(cache.get(value, C.REFERENCE.reconstruct_tree), first)
        self.assertEqual(cache.hits, 1)

    def test_changed_input_during_computation_is_not_retained(self):
        cache, value = C.TreeCache(), pins()
        def changing(argument):
            argument["hello.txt"]["bytes"] += 1
            return leaf_tree()
        with self.assertRaises(ValueError):
            cache.get(value, changing)
        self.assertFalse(cache.entries)

    def test_original_exception_is_propagated_and_never_cached(self):
        cache = C.TreeCache()
        def failure(_):
            raise RuntimeError("selected original failure")
        for _ in range(2):
            with self.assertRaisesRegex(RuntimeError, "selected original failure"):
                cache.get(pins(), failure)
        self.assertEqual(cache.computations, 2)
        self.assertFalse(cache.entries)

    def test_entry_bound_evicts_and_missing_inputs_are_recomputed(self):
        cache = C.TreeCache(max_entries=2)
        for raw in (b"one", b"two", b"three", b"one"):
            self.assertEqual(cache.get(pins(raw), C.REFERENCE.reconstruct_tree), leaf_tree(raw))
        self.assertEqual(len(cache.entries), 2)
        self.assertEqual(cache.evictions, 2)
        self.assertEqual(cache.computations, 4)

    def test_logical_byte_bound_falls_back_to_unretained_original_results(self):
        cache = C.TreeCache(max_bytes=1)
        for _ in range(2):
            self.assertEqual(cache.get(pins(), C.REFERENCE.reconstruct_tree), leaf_tree())
        self.assertFalse(cache.entries)
        self.assertEqual(cache.bytes, 0)
        self.assertEqual(cache.computations, 2)

    def test_lru_hits_preserve_the_recent_entry(self):
        cache = C.TreeCache(max_entries=2)
        for raw in (b"one", b"two", b"one", b"three", b"one"):
            cache.get(pins(raw), C.REFERENCE.reconstruct_tree)
        self.assertEqual((cache.hits, cache.computations, cache.evictions), (2, 3, 1))

    def test_complete_logical_accounting_and_byte_eviction_are_bounded(self):
        # Forty root characters, nine filename bytes and every field/value byte;
        # the admitted integer is conservatively charged as eight bytes.
        self.assertEqual(C.logical_bytes(C.cache_key(pins()), leaf_tree()), 190)
        cache = C.TreeCache(max_bytes=200)
        for raw in (b"one", b"two", b"one"):
            cache.get(pins(raw), C.REFERENCE.reconstruct_tree)
            self.assertLessEqual(cache.bytes, 200)
        self.assertEqual(cache.evictions, 2)
        self.assertEqual(cache.peak_bytes, 190)

    def test_invalid_bounds_refuse_without_coercion(self):
        for bound in (True, False, 0, -1, 33, 1.0, None):
            with self.subTest(bound=bound), self.assertRaises(ValueError):
                C.TreeCache(max_entries=bound)
        for bound in (True, 0, -1, C.MAX_BYTES + 1, 1.0):
            with self.subTest(bound=bound), self.assertRaises(ValueError):
                C.TreeCache(max_bytes=bound)

    def test_nonbuiltin_maps_and_values_keep_the_original_path(self):
        class Derived(dict):
            pass
        values = [Derived(pins()), {"hello.txt": Derived(pins()["hello.txt"])},
                  {"hello.txt": dict(pins()["hello.txt"], bytes=True)},
                  {"hello.txt": dict(pins()["hello.txt"], unknown="extra")},
                  {"hello.txt": dict(pins()["hello.txt"], bytes=1 << 64)}]
        for value in values:
            with self.subTest(value=value):
                cache = C.TreeCache()
                self.assertEqual(cache.get(value, C.REFERENCE.reconstruct_tree), C.REFERENCE.reconstruct_tree(value))
                self.assertEqual(cache.fallbacks, 1)
                self.assertFalse(cache.entries)

    def test_oversize_maps_and_fields_use_the_original_path(self):
        row = pins()["hello.txt"]
        for value in ({str(n): dict(row) for n in range(C.MAX_PINS + 1)},
                      {"a" * 2049: dict(row)}, {"a": dict(row, sha256="x" * 4097)}):
            cache = C.TreeCache()
            self.assertEqual(cache.get(value, C.REFERENCE.reconstruct_tree), C.REFERENCE.reconstruct_tree(value))
            self.assertEqual(cache.fallbacks, 1)
            self.assertFalse(cache.entries)

    def test_unsupported_pin_key_is_not_hashed_by_the_cache(self):
        class Key:
            def __init__(self):
                self.allowed = True
            def __hash__(self):
                if not self.allowed:
                    raise AssertionError("cache invoked a custom key")
                return 7
        key = Key()
        row = {key: value for key, value in pins()["hello.txt"].items() if key in ("mode", "git_blob")}
        row[key] = "ignored"
        key.allowed = False
        self.assertIsNone(C.cache_key({"a": row}))

    def test_bad_result_is_returned_without_retention(self):
        cache = C.TreeCache()
        marker = object()
        self.assertIs(cache.get(pins(), lambda _: marker), marker)
        self.assertFalse(cache.entries)

    def test_clear_and_report_do_not_leak_mutable_cache_state(self):
        cache = C.TreeCache()
        cache.get(pins(), C.REFERENCE.reconstruct_tree)
        snapshot = cache.report()
        snapshot["entries"] = 999
        self.assertEqual(len(cache.entries), 1)
        cache.clear()
        self.assertFalse(cache.entries)
        self.assertEqual(cache.bytes, 0)
        self.assertGreater(cache.peak_bytes, 0)


class SourceBoundSessionControls(unittest.TestCase):
    def test_exact_two_private_instances_share_only_complete_tree_results(self):
        value = program()
        seams, _ = C.selected_seams(value)
        self.assertEqual(tuple(name for name, _, _ in seams), C.SEAMS)
        with C.reuse(value) as scope:
            for _, module, _ in seams:
                self.assertEqual(module.reconstruct_tree(pins()), leaf_tree())
        report = scope.report()
        self.assertEqual((report["cache"]["original_computations"], report["cache"]["lookup_hits"]), (1, 1))
        self.assertTrue(report["original_functions_restored"])
        self.assertTrue(report["cache_cleared"])
        self.assertFalse(report["source_validation_cached"])

    def test_exception_restores_every_original_and_clears_retained_inputs(self):
        value = program()
        seams, _ = C.selected_seams(value)
        with self.assertRaisesRegex(RuntimeError, "owned test failure"):
            with C.reuse(value) as scope:
                seams[0][1].reconstruct_tree(pins())
                raise RuntimeError("owned test failure")
        self.assertTrue(scope.report()["original_functions_restored"])
        self.assertTrue(scope.report()["cache_cleared"])
        self.assertTrue(all(module.reconstruct_tree is original for _, module, original in seams))

    def test_each_new_scope_starts_with_an_empty_cache(self):
        value = program()
        module = C.selected_seams(value)[0][0][1]
        for _ in range(2):
            with C.reuse(value) as scope:
                module.reconstruct_tree(pins())
            self.assertEqual(scope.report()["cache"]["original_computations"], 1)
            self.assertEqual(scope.report()["cache"]["lookup_hits"], 0)

    def test_nested_scope_refuses_and_outer_scope_remains_usable(self):
        value = program()
        with C.reuse(value) as scope:
            with self.assertRaises(ValueError):
                with C.reuse(value):
                    pass
            value.C.P.UTIL.reconstruct_tree(pins())
        self.assertTrue(scope.report()["original_functions_restored"])

    def test_other_thread_cannot_consume_or_fill_the_cache(self):
        value = program()
        errors = []
        def other():
            try:
                value.C.P.UTIL.reconstruct_tree(pins())
            except ValueError:
                errors.append("refused")
        with C.reuse(value) as scope:
            thread = threading.Thread(target=other)
            thread.start()
            thread.join(timeout=5)
            self.assertFalse(thread.is_alive())
            self.assertEqual(errors, ["refused"])
            self.assertEqual(scope.report()["cache"]["calls"], 0)

    def test_changed_function_binding_is_refused_and_original_restored(self):
        value = program()
        module = value.C.P.UTIL
        original = module.reconstruct_tree
        with self.assertRaises(ValueError):
            with C.reuse(value) as scope:
                module.reconstruct_tree = lambda _: "0" * 40
        self.assertIs(module.reconstruct_tree, original)
        self.assertTrue(scope.report()["cache_cleared"])

    def test_changed_dependency_is_refused_even_on_a_hit(self):
        for name, wrong in (("git_hash", lambda *_: "0" * 40),
                            ("require", lambda *_: None), ("PurePosixPath", object())):
            value = program()
            with C.reuse(value):
                module = value.C.P.UTIL
                module.reconstruct_tree(pins())
                with mock.patch.object(module, name, wrong), self.assertRaises(ValueError):
                    module.reconstruct_tree(pins())

    def test_changed_hash_primitive_is_refused_on_a_hit(self):
        value = program()
        argument = pins()
        with C.reuse(value):
            value.C.P.UTIL.reconstruct_tree(argument)
            with mock.patch.object(C.hashlib, "sha1", lambda *_: None), self.assertRaises(ValueError):
                value.C.P.UTIL.reconstruct_tree(argument)

    def test_interrupted_scope_restores_functions_and_clears_inputs(self):
        value = program()
        with self.assertRaises(KeyboardInterrupt):
            with C.reuse(value) as scope:
                value.C.P.UTIL.reconstruct_tree(pins())
                raise KeyboardInterrupt()
        self.assertTrue(scope.report()["original_functions_restored"])
        self.assertTrue(scope.report()["cache_cleared"])

    def test_source_pin_change_is_refused_on_entry_and_exit(self):
        value = program()
        changed = dict(C.SOURCE_PINS, **{"regenerate.py": "0" * 64})
        with mock.patch.object(C, "SOURCE_PINS", changed), self.assertRaises(ValueError):
            C.selected_seams(value)
        original = dict(C.SOURCE_PINS)
        try:
            with self.assertRaises(ValueError):
                with C.reuse(value) as scope:
                    C.SOURCE_PINS["regenerate.py"] = "0" * 64
        finally:
            C.SOURCE_PINS.clear()
            C.SOURCE_PINS.update(original)
        self.assertTrue(scope.report()["original_functions_restored"])

    def test_wrong_program_missing_or_additional_instances_refuse(self):
        value = program()
        with self.assertRaises(ValueError):
            C.selected_seams(value, "unselected.py")
        value.C.W.P.UTIL = value.C.P.UTIL
        with self.assertRaises(ValueError):
            C.selected_seams(value)
        value = program()
        spec = importlib.util.spec_from_file_location("extra_tree_instance", C.HERE / "regenerate.py")
        extra = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(extra)
        value.EXTRA = extra
        with self.assertRaises(ValueError):
            C.selected_seams(value)

    def test_unknown_module_in_selected_source_closure_refuses(self):
        value = program()
        extra = ModuleType("unselected_source")
        extra.__file__ = str(C.HERE / "unselected.py")
        value.EXTRA = extra
        with self.assertRaises(ValueError):
            C.selected_seams(value)

    def test_later_private_imports_keep_the_original_function(self):
        value = program()
        with C.reuse(value) as scope:
            later = program()
            self.assertTrue(C.dependencies(later.C.P.UTIL, later.C.P.UTIL.reconstruct_tree))
            later.C.P.UTIL.reconstruct_tree(pins())
            self.assertEqual(scope.report()["cache"]["calls"], 0)

    def test_session_report_is_an_independent_snapshot(self):
        value = program()
        with C.reuse(value) as scope:
            report = scope.report()
            report["source_pins"]["regenerate.py"] = "changed"
            report["selected_instances"].clear()
            report["cache"]["calls"] = 999
            self.assertEqual(scope.report()["cache"]["calls"], 0)
            self.assertEqual(tuple(scope.report()["selected_instances"]), C.SEAMS)


if __name__ == "__main__":
    unittest.main()
