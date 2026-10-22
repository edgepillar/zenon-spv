#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Check finite real-manager close errors without running a node backend."""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
PARENT = HERE / "zenon_worker_stop_model.py"
raw = PARENT.read_bytes()
if len(raw) != 4282 or hashlib.sha256(raw).hexdigest() != "89ff7e2f682554069ee611972457639457370d6d86521d0e284ff309ce5a0993":
    raise ValueError("Core Stop model parent refused")
spec = importlib.util.spec_from_file_location("core_stop_error_independent_parent", PARENT)
BASE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(BASE)
exact, pairs, constant, read_bounded = BASE.exact, BASE.pairs, BASE.constant, BASE.read_bounded
VARIANTS = ("baseline", "candidate")
MODES = ("healthy", "cache-closed", "both-closed")
SELECTION_SHA256, SELECTION_BYTES = BASE.SELECTION_SHA256, BASE.SELECTION_BYTES
MAX_STREAM = 16384

def require(ok):
    if not ok:
        raise ValueError("Core Stop error evidence refused")

def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()

def selected_input():
    # Reuse the source-bound key and unsigned genesis selection, not an expected
    # root, value or proof supplied to the ordinary comparison child.
    return BASE.selected_input()

def expected_report(variant, mode):
    require(type(variant) is str and variant in VARIANTS)
    require(type(mode) is str and mode in MODES)
    # The independently rebuilt genesis witness and stopped-query contract are
    # unchanged. The candidate stdout is never used to select expected values.
    report = BASE.expected_report("candidate", "init-stop")
    failed = mode != "healthy"
    count = (2 if variant == "candidate" and mode == "both-closed" else 1) if failed else 0
    left_open = variant == "baseline" and mode == "cache-closed"
    report.update({
        "schema": "zenon-core-stop-error-observation-v1", "case": mode,
        "stop": {"error": "\n".join(["leveldb: closed"] * count), "panic": "",
                 "closed_error": failed, "leaf_classes": ["leveldb-closed"] * count},
        "controlled_closed_handles": (["cache-handle", "consensus-handle"] if mode == "both-closed"
                                      else ["cache-handle"] if failed else []),
        "consensus_before_fault": "open",
        "consensus_after_fault": "closed" if mode == "both-closed" else "open",
        "consensus_after_stop": "open" if left_open else "closed",
        "caller_teardown_after_observation": ["consensus-handle"] if left_open else [],
        "final_consensus_status": "closed", "consensus_reopened_after_teardown": True,
    })
    return report

def check(raw, variant, mode):
    require(type(raw) is bytes and 0 < len(raw) <= MAX_STREAM and raw.endswith(b"\n"))
    require(len(raw.splitlines()) == 1)
    value = json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    exact(value, expected_report(variant, mode))
    return value
