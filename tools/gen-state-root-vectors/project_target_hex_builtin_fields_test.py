#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Preserve complete field validation, refusal order and observable fallback."""
import gc
import hashlib
import importlib.util
import json
from pathlib import Path
import tracemalloc
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("builtin_field_subject", HERE / "project_target_hex.py")
HEX = importlib.util.module_from_spec(spec)
spec.loader.exec_module(HEX)
LIMITS = {"entries": 4096, "hex_bytes": 1 << 20}


def target(count=32, width=64):
    return {format(index, "064x"): "01" * (width // 2) for index in range(count)}


def captured(function, factory):
    value, trace = factory()
    try:
        result = function(value, dict(LIMITS))
        outcome = ("return", type(result).__name__, result)
    except Exception as error:
        outcome = ("exception", type(error).__name__, str(error))
    return outcome, trace


class BuiltinFieldValidationControls(unittest.TestCase):
    def assert_reference(self, value):
        self.assertEqual(HEX.target_refusal(value, dict(LIMITS), HEX.REFERENCE.CEILINGS),
                         HEX.REFERENCE.target_refusal(value, dict(LIMITS)))

    def test_every_latin1_character_keeps_key_and_value_classification(self):
        checked = 0
        for code in range(256):
            text = chr(code) + "0"
            for field in ("key", "value"):
                selected = target()
                first = next(iter(selected))
                if field == "key":
                    selected[text] = selected.pop(first)
                else:
                    selected[first] = text
                self.assert_reference(selected)
                checked += 1
        self.assertEqual(checked, 512)

    def test_small_and_full_map_boundaries_keep_complete_field_checks(self):
        for count in (0, 1, 31, 32, 33, 64, 4096, 4097):
            self.assert_reference(target(count))
        for count in (31, 32, 33, 4096):
            for position in (0, count - 1):
                for text in ("g0", "A0", "\u0100a", "\0\0", "a"):
                    selected = target(count)
                    selected[list(selected)[position]] = text
                    self.assert_reference(selected)

    def test_two_odd_fields_cannot_become_one_valid_joined_field(self):
        selected = target()
        names = list(selected)
        selected[names[0]], selected[names[1]] = "a", "b"
        self.assertEqual(HEX.target_refusal(selected, dict(LIMITS), HEX.REFERENCE.CEILINGS),
                         "invalid_target_encoding")
        self.assertIs(HEX.batched_encoding(selected, 0), True)
        self.assert_reference(selected)

    def test_actual_collected_cap_preserves_earlier_encoding_refusal(self):
        selected = target(4096, 194)
        self.assertGreater(sum(len(k) + len(v) for k, v in selected.items()), 1 << 20)
        self.assertIsNone(HEX.batched_encoding(selected, 0))
        for text, expected in (("\u00e9" * 194, True), ("a", True), ("g0", None)):
            changed = dict(selected)
            changed[next(iter(changed))] = text
            self.assertIs(HEX.batched_encoding(changed, 0), expected)
            self.assert_reference(changed)
        exact = target(4096, 192)
        self.assertEqual(sum(len(k) + len(v) for k, v in exact.items()), 1 << 20)
        self.assertIs(HEX.batched_encoding(exact, 0), False)
        self.assert_reference(exact)

    def test_limit_refusals_precede_any_field_collector(self):
        previous = HEX.batched_encoding
        calls = []
        def forbidden(*args):
            calls.append(args)
            raise AssertionError("field collector ran before required refusal")
        try:
            HEX.batched_encoding = forbidden
            for selected, limits, expected in (
                    (target(), {"entries": 0, "hex_bytes": 1 << 20}, "invalid_target_limits"),
                    (target(4097), dict(LIMITS), "target_entry_limit"),
                    (target(4096, 194), dict(LIMITS), "target_hex_limit")):
                self.assertEqual(HEX.target_refusal(selected, limits, HEX.REFERENCE.CEILINGS), expected)
        finally:
            HEX.batched_encoding = previous
        self.assertEqual(calls, [])

    def test_subclass_hooks_keep_pointwise_order_and_exceptions(self):
        for placement in ("key", "value", "after-invalid"):
            def factory():
                trace = []
                class Observed(str):
                    def __len__(self):
                        trace.append("length")
                        return super().__len__()
                    def __iter__(self):
                        trace.append("iteration")
                        return super().__iter__()
                selected = {}
                for index in range(32):
                    key, value = format(index, "064x"), "00"
                    if placement == "key" and index == 0:
                        key = Observed(key)
                    if placement == "value" and index == 0:
                        value = Observed(value)
                    if placement == "after-invalid":
                        if index == 0:
                            value = "\u00e9a"
                        if index == 31:
                            value = Observed(value)
                    selected[key] = value
                return selected, trace
            current = lambda value, limits: HEX.target_refusal(value, limits, HEX.REFERENCE.CEILINGS)
            self.assertEqual(captured(current, factory),
                             captured(HEX.REFERENCE.target_refusal, factory))

    def test_length_hook_changes_are_not_hidden_by_field_collection(self):
        def factory():
            trace, selected = [], target()
            class ChangesLaterValue(str):
                def __len__(self):
                    trace.append("length")
                    selected[format(31, "064x")] = "g0"
                    return super().__len__()
                def __iter__(self):
                    trace.append("iteration")
                    return super().__iter__()
            selected[format(0, "064x")] = ChangesLaterValue("00")
            return selected, trace
        current = lambda value, limits: HEX.target_refusal(value, limits, HEX.REFERENCE.CEILINGS)
        self.assertEqual(captured(current, factory),
                         captured(HEX.REFERENCE.target_refusal, factory))

    def test_non_builtin_maps_keep_the_original_fallback(self):
        def factory():
            trace = []
            class ObservedMap(dict):
                def __len__(self):
                    trace.append("length")
                    return super().__len__()
                def items(self):
                    trace.append("items")
                    return super().items()
            return ObservedMap(target()), trace
        selected, trace = factory()
        self.assertIsNone(HEX.batched_encoding(selected, 0))
        self.assertEqual(trace, [])
        current = lambda value, limits: HEX.target_refusal(value, limits, HEX.REFERENCE.CEILINGS)
        self.assertEqual(captured(current, factory),
                         captured(HEX.REFERENCE.target_refusal, factory))


    def test_nonascii_refusal_precedes_wide_join_allocation(self):
        selected = target(4096, 192)
        wide = chr(0x10000) * 192
        for key in selected:
            selected[key] = wide
        self.assertEqual(sum(len(k) + len(v) for k, v in selected.items()), 1 << 20)
        self.assertFalse(tracemalloc.is_tracing())
        gc.collect()
        tracemalloc.start()
        try:
            before, _ = tracemalloc.get_traced_memory()
            result = HEX.target_refusal(selected, dict(LIMITS), HEX.REFERENCE.CEILINGS)
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        delta = peak - before
        self.assertEqual(result, "invalid_target_encoding")
        print("builtin-field-allocation " + json.dumps({
            "scope": "Python traced peak for one validation; input allocated before tracing",
            "input_characters": 1 << 20, "traced_peak_delta_bytes": delta,
            "allowed_peak_delta_bytes": 1 << 20,
            "process_RSS_or_representative_budget_qualified": False}, sort_keys=True), flush=True)
        self.assertLessEqual(delta, 1 << 20)

    def test_complete_file_resource_document_matches_pointwise_reference(self):
        digests = []
        for mode in ("reference", "translated"):
            program = HEX.load("complete_builtin_document_" + mode, "check_patch_file_resources.py")
            with HEX.selected_oracles(program, "check_patch_file_resources.py", mode):
                document = program.expected_document()
            self.assertEqual(len(document["cases"]), 15)
            raw = json.dumps(document, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
            digests.append(hashlib.sha256(raw).hexdigest())
        self.assertEqual(digests, ["55928a6bd42344c27dacaeadb1fb147f816a08539a944b88c82bac427488e593"] * 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
