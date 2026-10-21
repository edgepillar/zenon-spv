#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Model finite core-manager Stop observations without executing a backend."""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent

def load(name, file):
    spec = importlib.util.spec_from_file_location(name, HERE / file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

COMMON = load("worker_stop_json_contract", "cache_read_error_model.py")
GENESIS = load("worker_stop_independent_genesis", "prepare_public_chain_reorg_reopen.py")
exact, pairs, constant, read_bounded = COMMON.exact, COMMON.pairs, COMMON.constant, COMMON.read_bounded
VARIANTS = ("baseline", "candidate")
MODES = ("construct-stop", "init-stop", "reopen-start-stop")
SELECTION_SHA256 = "2ba2ac5f86cf8870a08566ce9de7f93d65ac3774d788adf6ca4146ae214f041f"
SELECTION_BYTES = 375
MAX_STREAM = 16384

def require(ok):
    if not ok:
        raise ValueError("Core-manager Stop evidence refused")

def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()

def fixture():
    # This rebuilds the already selected unsigned genesis witness. The expected
    # root, value and proof never come from the observation being checked.
    return json.loads(GENESIS.selected_fixture(), object_pairs_hook=pairs, parse_constant=constant)

def selected_input():
    data = fixture()
    value = {"schema": "zenon-worker-stop-selection-v1", "raw_key": data["raw_key"],
             "genesis": data["states"]["A1"]["identifier"],
             "genesis_patch_bytes": data["source"]["genesis_patch"]["bytes"],
             "genesis_patch_sha256": data["source"]["genesis_patch"]["sha256"]}
    raw = encoded(value)
    require(len(raw) == SELECTION_BYTES and hashlib.sha256(raw).hexdigest() == SELECTION_SHA256)
    return raw

def expected_query(ready, state):
    require(type(ready) is bool)
    return {"ready": ready, "root": state["root"] if ready else "0" * 64,
            "value": state["value"] if ready else "", "present": ready,
            "proof": state["proof"] if ready else "",
            "root_error": "none" if ready else "not-ready",
            "proof_error": "none" if ready else "not-ready", "foreign_root": "0" * 64,
            "foreign_error": "identity-mismatch" if ready else "not-ready"}

def expected_report(variant, mode):
    require(type(variant) is str and variant in VARIANTS)
    require(type(mode) is str and mode in MODES)
    data = fixture()
    state = data["states"]["A1"]
    initialized, started = mode != MODES[0], mode == MODES[2]
    panic = "close of nil channel" if variant == "baseline" and not started else ""
    teardown = [{"component": name, "error": "", "panic": ""} for name in
                ("subscribe", "event-printer", "consensus", "chain", "consensus-database")] if panic else []
    return {"schema": "zenon-core-worker-stop-observation-v1", "case": mode,
            "selection_sha256": SELECTION_SHA256, "genesis_identifier": state["identifier"],
            "genesis_patch_bytes": data["source"]["genesis_patch"]["bytes"],
            "genesis_patch_sha256": data["source"]["genesis_patch"]["sha256"],
            "initialized": initialized, "core_started": started,
            "before_stop": expected_query(initialized, state), "stop": {"error": "", "panic": panic},
            "after_stop": expected_query(initialized and bool(panic), state),
            "caller_teardown_after_observation": teardown, "final_tree_ready": False,
            "producing_key_configured": False, "wallet_manager_created": False,
            "node_wrapper_created": False, "p2p_server_created": False, "RPC_listener_started": False,
            "external_peer_configured": False, "production_state_value_accepted": False,
            "header_authentication_executed": False, "consumer_result": "REFUSED"}

def check(raw, variant, mode):
    require(type(raw) is bytes and 0 < len(raw) <= MAX_STREAM and raw.endswith(b"\n"))
    require(len(raw.splitlines()) == 1)
    value = json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    exact(value, expected_report(variant, mode))
    return value
