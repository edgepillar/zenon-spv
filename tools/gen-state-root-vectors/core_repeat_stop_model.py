#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Check finite repeated Stop observations without running a reference backend."""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
PARENT = HERE / "core_stop_error_model.py"
raw = PARENT.read_bytes()
if len(raw) != 3089 or hashlib.sha256(raw).hexdigest() != "7c5649cb057a73afa8cbb46b5c8e7cd1de61cabf2f942bf64227e4557c584a82":
    raise ValueError("Repeated Stop model parent refused")
spec = importlib.util.spec_from_file_location("core_repeat_stop_independent_parent", PARENT)
BASE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(BASE)
exact, pairs, constant, read_bounded = BASE.exact, BASE.pairs, BASE.constant, BASE.read_bounded
VARIANTS = ("baseline", "candidate")
MODES = BASE.MODES
SELECTION_SHA256, SELECTION_BYTES = BASE.SELECTION_SHA256, BASE.SELECTION_BYTES
MAX_STREAM = 32768

def require(ok):
    if not ok:
        raise ValueError("Repeated Stop evidence refused")

def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()

def selected_input():
    return BASE.selected_input()

def expected_report(variant, mode):
    require(type(variant) is str and variant in VARIANTS)
    require(type(mode) is str and mode in MODES)
    # The preceding complete-cleanup runtime is the new baseline. Its first
    # result and independent source-genesis witness remain unchanged.
    result = BASE.expected_report("candidate", mode)
    result["schema"] = "zenon-core-repeat-stop-observation-v1"
    result["stop"]["panic_stack"] = ""
    result["repeated_stop"] = (dict(result["stop"]) if variant == "candidate" else {
        "error": "", "panic": "close of closed channel", "closed_error": False,
        "leaf_classes": [], "panic_stack": ""})
    result["after_repeated_stop"] = dict(result["after_stop"])
    return result

def check(raw, variant, mode):
    require(type(raw) is bytes and 0 < len(raw) <= MAX_STREAM and raw.endswith(b"\n"))
    require(len(raw.splitlines()) == 1)
    value = json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    expected = expected_report(variant, mode)
    if variant == "baseline":
        repeat = value.get("repeated_stop")
        require(type(repeat) is dict and type(repeat.get("panic_stack")) is str)
        trace = repeat["panic_stack"]
        require(0 < len(trace) <= 16384)
        require("protocol.(*ProtocolManager).Stop" in trace and "zenon.(*zenon).Stop" in trace)
        require("pillar.(*worker).Stop" not in trace)
        # The full immutable capture separately pins runtime-generated stack
        # addresses and line numbers; semantic checks bind its manager origin.
        value = dict(value, repeated_stop=dict(repeat, panic_stack=""))
    exact(value, expected)
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
