#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Independent finite retained-identity, SMT-byte and logical-record oracle.

No backend, node source, subprocess, network, wallet or migration is executed.
The selected states, identities, faults and observations are derived before the
reference run. Full-tree levels and compressed DAG/refcounts are separate models.
This finite component comparison never accepts a production state-value proof.
"""
import argparse
import copy
import functools
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("hash_bound_independent_graph", HERE / "check_retention.py")
RET = importlib.util.module_from_spec(spec)
spec.loader.exec_module(RET)
BYTE, ZERO = RET.BYTE, RET.ZERO
REVISION = "33d7d1ee1b6a915c40aea196e2a10f1e893d171f"
TREE = "40d71efb7e462d5bbd0f27d83ed7588e121c3cb6"
MODIFIED_TREE = "28c9eec1156633836357028e16a3958edbc635c4"
PATCH_SHA256 = "a1a00190d81fcd5eed0326570d95b29e8869d82edd2c5a0804bb3af440e506ef"
MANIFEST_SHA256 = "12ec9f524b1a4c3ba45344fa619f433df2b11a63eaf523ea695d9ca4ba84f460"
VARIANTS = ("baseline", "hash-bound")
MAX_FILE_BYTES = 4 << 20
INPUTS = (
    "check.py", "check_retention.py", "check_hash_bound_versions.py",
    "prepare_hash_bound_versions.py", "hash_bound_versions_probe_test.go",
    "hash-bound-versions-patch.json", "node-recovery-source-pins.json",
    "regenerate.py", "go.mod", "go.sum",
)
SCOPE = {
    "synthetic": True, "unsigned": True,
    "current_439_blob_source_selected": True,
    "actual_chain_component_Init_executed": True,
    "actual_NodeTree_disk_APIs_executed": True,
    "recording_manager_cache_genesis_inputs": True,
    "small_owned_temporary_disk_LevelDB": True,
    "controlled_clean_reopen_executed": True,
    "complete_logical_records_compared": True,
    "custom_missing_record_faults": True,
    "custom_Patch_Replay_fault": True,
    "fresh_fixture_format_transformations_only": True,
    "owned_databases_closed_and_removed": True,
    **{name: False for name in (
        "complete_current_node_revision_qualified", "full_node_started",
        "chain_Start_executed", "background_build_executed", "upstream_tests_executed",
        "network_execution", "RPC_executed", "signing", "transactions",
        "automatic_existing_database_migration", "automatic_incompatible_database_wipe",
        "full_descendant_integrity_scan", "all_corruption_shapes_qualified",
        "crash_recovery_qualified", "power_loss_qualified", "torn_write_qualified",
        "realistic_retention_resource_budgets_qualified", "authenticated_retained_provenance",
        "header_authentication_executed", "state_transition_correctness_qualified",
        "profile_agreed", "network_activation_authenticated",
        "runtime_state_proof_acceptance", "production_state_value_accepted",
    )},
}


def require(condition, message="hash-bound finite research input refused"):
    if not condition:
        raise ValueError(message)


def exact(actual, expected, location="document"):
    require(type(actual) is type(expected), "type differs at " + location)
    if type(expected) is dict:
        require(set(actual) == set(expected), "fields differ at " + location)
        for name in expected:
            exact(actual[name], expected[name], location + "." + str(name))
    elif type(expected) is list:
        require(len(actual) == len(expected), "inventory differs at " + location)
        for index, (left, right) in enumerate(zip(actual, expected)):
            exact(left, right, location + "[" + str(index) + "]")
    else:
        require(actual == expected, "selected bytes or outcome differ at " + location)


def read_corpus(path):
    with Path(path).open("rb") as stream:
        raw = stream.read(MAX_FILE_BYTES + 1)
    require(len(raw) <= MAX_FILE_BYTES, "hash-bound corpus size exceeds limit")
    return raw, json.loads(raw, object_pairs_hook=BYTE.object_pairs)


def key(token=0x22):
    require(token in (0x22, 0x33, 0x44))
    return BYTE.balance_key("11" * 20, ("%02x" % token) * 10)


PRIMARY, SECONDARY, ABSENT = key(), key(0x33), key(0x44)
ORIGIN = {"hash": ZERO.hex(), "height": 0}


def identifier(fork, height):
    require(fork in ("A", "B", "X") and type(height) is int and 0 <= height < 1 << 64)
    if fork == "B" and height == 1:
        fork = "A"
    return {"height": height, "hash": BYTE.digest(
        ("synthetic-hash-bound-node-v1/%s/%d" % (fork, height)).encode("ascii")).hex()}


def value(number):
    require(type(number) is int and 0 <= number <= 255)
    return number.to_bytes(32, "big")


def patch(fork, height):
    result = {PRIMARY: value(22 if fork == "B" and height == 2 else 91 if fork == "X" else height % 256)}
    if fork == "B" and height == 2:
        result[SECONDARY] = value(222)
    return result


@functools.lru_cache(maxsize=128)
def tree(items):
    state = {BYTE.digest(raw): val for raw, val in items}
    levels, values = BYTE.tree_levels([{"path": path.hex(), "value": val.hex()} for path, val in state.items()])
    node, commitment, nodes, edges = RET.graph(state)
    require(levels[0].get(0, ZERO) == commitment, "full SMT and compressed DAG disagree")
    return node, commitment, nodes, edges, levels, values


def view(state):
    return tree(tuple(sorted(state.items())))


def root(state):
    return view(state)[1]


def proof(state, raw):
    _, commitment, _, _, levels, values = view(state)
    path = BYTE.digest(raw)
    val = state.get(raw)
    encoded = BYTE.canonical_proof(levels, values, path)
    require(BYTE.proof_result(commitment, path, val or b"", encoded, val is not None) == "match")
    return None if val is None else val.hex(), encoded.hex()


class Model:
    """Selected logical records and identity guards, never a LevelDB emulator."""
    def __init__(self, variant, fork="A", height=0):
        self.bound = variant == "hash-bound"
        self.marker = 3 if self.bound else 2
        self.frontier = dict(ORIGIN)
        self.frontier_written = False
        self.versions = {}
        self.overrides = {}
        self.closed = False
        state = {}
        for h in range(1, height + 1):
            state.update(patch(fork, h))
            self.commit(identifier(fork, h), state)

    def commit(self, selected, state):
        self.versions[selected["height"]] = (dict(selected), dict(state))
        self.frontier = dict(selected)
        self.frontier_written = True

    def records(self):
        nodes, edges, roots = {}, {}, {}
        for height, (_, state) in sorted(self.versions.items()):
            node, _, current, links, _, _ = view(state)
            roots[height] = node
            for node_id, raw in current.items():
                require(node_id not in nodes or nodes[node_id] == raw)
                nodes[node_id] = raw
            edges.update(links)
        refs = {node: 0 for node in nodes}
        for node in roots.values():
            if node != ZERO:
                refs[node] += 1
        for left, right in edges.values():
            refs[left] += 1
            refs[right] += 1
        require(all(count > 0 for count in refs.values()))
        rows = {b"\x05": bytes([self.marker])}
        if self.frontier_written:
            rows[b"\x00"] = bytes.fromhex(self.frontier["hash"]) + BYTE.uint64(self.frontier["height"])
        rows.update({b"\x01" + node: raw for node, raw in nodes.items()})
        rows.update({b"\x02" + node: BYTE.uint64(count) for node, count in refs.items()})
        rows.update({b"\x03" + BYTE.uint64(h): node for h, node in roots.items()})
        if self.bound:
            rows.update({b"\x06" + BYTE.uint64(h): bytes.fromhex(selected["hash"])
                         for h, (selected, _) in self.versions.items()})
        for raw, replacement in self.overrides.items():
            if replacement is None:
                rows.pop(raw, None)
            else:
                rows[raw] = replacement
        return rows

    def snapshot(self):
        return [{"key": raw.hex(), "value": val.hex()} for raw, val in sorted(self.records().items())]

    def fault(self, name, fork, height):
        if name == "":
            return
        if name == "legacy-2":
            self.marker = 2
            for h in range(1, height + 1):
                self.overrides[b"\x06" + BYTE.uint64(h)] = None
        elif name == "candidate-3":
            self.marker = 3
            for h in range(1, height + 1):
                self.overrides[b"\x06" + BYTE.uint64(h)] = bytes.fromhex(identifier(fork, h)["hash"])
        elif name == "foreign-4":
            self.marker = 4
        elif name == "frontier-hash":
            self.frontier = identifier("B", height)
        elif name in ("missing-frontier-hash", "short-frontier-hash", "missing-historical-hash"):
            h = 1 if name == "missing-historical-hash" else height
            self.overrides[b"\x06" + BYTE.uint64(h)] = bytes(31) if name == "short-frontier-hash" else None
        elif name == "missing-root-node":
            self.overrides[b"\x01" + view(self.versions[height][1])[0]] = None
        elif name in ("missing-primary-node", "missing-secondary-node"):
            raw = PRIMARY if name == "missing-primary-node" else SECONDARY
            amount = height if raw == PRIMARY else 222
            self.overrides[b"\x01" + BYTE.digest(BYTE.digest(raw) + value(amount))] = None
        else:
            raise ValueError("unselected missing-record fault")

    def lookup(self, selected):
        h = selected["height"]
        if h == 0:
            return "version-hash-mismatch" if self.bound and selected != ORIGIN else None
        if self.closed:
            return "database-closed"
        if h not in self.versions:
            return "no-version"
        if self.bound:
            metadata = self.records().get(b"\x06" + BYTE.uint64(h))
            if metadata is None:
                return "version-hash-missing"
            if len(metadata) != 32:
                return "corrupt"
            if metadata.hex() != selected["hash"]:
                return "version-hash-mismatch"
        return None

    def selected_state(self, selected):
        return {} if selected["height"] == 0 else self.versions[selected["height"]][1]

    def missing(self, state):
        return {raw for raw, val in state.items()
                if self.overrides.get(b"\x01" + BYTE.digest(BYTE.digest(raw) + val), b"present") is None}

    def read_root(self, selected):
        error = self.lookup(selected)
        if error is not None:
            return ZERO, error
        state = self.selected_state(selected)
        missing = self.missing(state)
        if state and self.overrides.get(b"\x01" + view(state)[0], b"present") is None:
            return ZERO, "corrupt" if self.bound else None
        # Both selected two-key paths share bit 0 and branch at bit 1.
        # Padding reads the left representative, SECONDARY, even if level=1.
        if SECONDARY in missing:
            return ZERO, "corrupt"
        return root(state), None

    def read_proof(self, selected, raw):
        error = self.lookup(selected)
        if error is not None:
            return None, None, error
        state = self.selected_state(selected)
        if state and self.overrides.get(b"\x01" + view(state)[0], b"present") is None:
            if self.bound:
                return None, None, "corrupt"
            val, encoded = proof({}, raw)
            return val, encoded, None
        missing = self.missing(state)
        if SECONDARY in missing or self.bound and raw in missing:
            return None, None, "corrupt"
        if raw in missing:
            visible = {k: v for k, v in state.items() if k != raw}
            val, encoded = proof(visible, raw)
            return val, encoded, None
        val, encoded = proof(state, raw)
        return val, encoded, None

    def compute(self, selected):
        error = self.lookup(selected)
        if error is not None:
            return ZERO, error, 0
        state = dict(self.selected_state(selected))
        root_missing = bool(state) and self.overrides.get(b"\x01" + view(state)[0], b"present") is None
        missing = self.missing(state)
        if self.bound and (root_missing or missing) or SECONDARY in missing:
            return ZERO, "corrupt", 1
        if root_missing:
            state = {}
        state.update(patch("A", 99))
        return root(state), None, 1

    def open_error(self):
        if self.marker != (3 if self.bound else 2):
            return "format-mismatch"
        return self.read_root(self.frontier)[1] if self.bound else None

    def truncate(self, selected):
        if selected["height"] > self.frontier["height"]:
            return "no-version"
        error = self.lookup(self.frontier) if self.bound else None
        error = error or self.lookup(selected)
        if error is not None:
            return error
        self.versions = {h: state for h, state in self.versions.items() if h <= selected["height"]}
        self.frontier, self.frontier_written = dict(selected), True
        return None

    def prune(self, horizon):
        if self.bound and self.frontier["height"] != 0 and horizon > self.frontier["height"]:
            return "prune-frontier"
        error = self.lookup(self.frontier) if self.bound else None
        if error is not None:
            return error
        self.versions = {h: state for h, state in self.versions.items() if h >= horizon}
        return None


def queries(model, selected, chain=False, ready=True, cache=None):
    rows = []
    wrong = identifier("X", selected["height"])
    for name, context, raw in (
        ("root", selected, None), ("root-wrong-hash", wrong, None),
        ("balance", selected, PRIMARY), ("balance-wrong-hash", wrong, PRIMARY),
        ("secondary", selected, SECONDARY), ("absent-token", selected, ABSENT),
        ("compute", selected, None), ("compute-repeat", selected, None),
        ("compute-wrong-hash", wrong, None),
        ("origin-root", ORIGIN, None), ("origin-wrong-hash", identifier("X", 0), None),
    ):
        row = {"name": name, "identifier": dict(context), "key": None if raw is None else raw.hex(),
               "root": None, "value": None, "proof": None, "error": None,
               "patch_callbacks": {"dump": 0, "replay": 0}}
        if chain and not ready:
            row["error"] = "not-ready"
            if raw is None:
                row["root"] = ZERO.hex()
        elif name.startswith("compute"):
            result, error = ZERO, None
            if chain and model.bound:
                _, error = model.read_root(context)
            if error is None:
                if chain:
                    row["patch_callbacks"]["dump"] = 1
                if chain and cache and cache.get("identifier") == context:
                    result = cache["root"]
                else:
                    result, error, count = model.compute(context)
                    row["patch_callbacks"]["replay"] = count
                    if chain and error is None:
                        cache.clear()
                        cache.update(identifier=dict(context), root=result)
            row["root"], row["error"] = result.hex(), error
        elif raw is None:
            result, row["error"] = model.read_root(context)
            row["root"] = result.hex()
        else:
            row["value"], row["proof"], row["error"] = model.read_proof(context, raw)
        rows.append(row)
    return rows


def selected_inputs():
    rows = (
        ("empty-short", "A", 0, "A", 2, 1, False, "", "", "", 0),
        ("empty-tail-bound", "A", 0, "A", 10, 1, False, "", "", "", 0),
        ("empty-tail-plus-one", "A", 0, "A", 11, 1, False, "", "", "", 0),
        ("matching-prebuild", "A", 2, "A", 2, 1, False, "", "", "", 0),
        ("same-height-other-hash", "A", 2, "B", 2, 1, False, "", "", "", 0),
        ("below-matching-ancestor", "A", 1, "A", 2, 1, False, "", "", "", 0),
        ("below-other-ancestor", "X", 1, "A", 2, 1, False, "", "", "", 0),
        ("above-matching-retained", "A", 3, "A", 2, 1, False, "", "", "", 0),
        ("above-divergent-retained", "A", 3, "B", 2, 1, False, "", "", "", 0),
        ("reopened-divergent-retained", "A", 3, "B", 2, 2, False, "", "", "", 0),
        ("previously-ready-divergent", "A", 3, "B", 2, 1, True, "", "", "", 0),
        ("previously-ready-equal-height", "A", 3, "B", 3, 1, True, "", "", "", 0),
        ("previously-ready-behind-wrong-ancestor", "A", 3, "B", 4, 1, True, "", "", "", 0),
        ("legacy-format-2", "A", 3, "A", 3, 2, False, "legacy-2", "", "", 0),
        ("candidate-format-3", "A", 3, "A", 3, 1, False, "candidate-3", "", "", 0),
        ("foreign-format-4", "A", 3, "B", 3, 1, False, "foreign-4", "", "", 0),
        ("corrupt-frontier-hash", "A", 3, "B", 3, 2, False, "frontier-hash", "", "", 0),
        ("missing-frontier-hash", "A", 3, "A", 3, 1, False, "missing-frontier-hash", "", "", 0),
        ("short-frontier-hash", "A", 3, "A", 3, 1, False, "short-frontier-hash", "", "", 0),
        ("missing-historical-hash", "A", 3, "A", 3, 1, False, "missing-historical-hash", "", "A", 1),
        ("missing-root-node", "A", 3, "A", 3, 1, False, "missing-root-node", "", "", 0),
        ("missing-secondary-node", "B", 3, "B", 3, 1, False, "missing-secondary-node", "", "", 0),
        ("missing-primary-node", "B", 3, "B", 3, 1, False, "missing-primary-node", "", "", 0),
        ("warm-cache-pruned-base", "A", 3, "A", 3, 1, False, "", "cache-prune", "A", 1),
        ("warm-cache-truncated-base", "A", 3, "A", 3, 1, False, "", "cache-truncate", "", 0),
        ("warm-cache-closed-backend", "A", 3, "A", 3, 1, False, "", "cache-close", "", 0),
    )
    names = ("name", "seed_fork", "seed_height", "chain_fork", "chain_height",
             "rounds", "prime_ready", "fault", "action", "query_fork", "query_height")
    return [dict(zip(names, row)) for row in rows]


LOW_LEVEL = (
    "queries", "truncate-matching", "truncate-divergent", "truncate-origin",
    "truncate-origin-alias", "prune-retained", "prune-frontier", "bulk-gap",
    "empty-version", "failed-compute-preserves-staging", "commit-origin-after-max",
)


def chain_cases(variant):
    result = []
    for item in selected_inputs():
        model = Model(variant, item["seed_fork"], item["seed_height"])
        model.fault(item["fault"], item["seed_fork"], item["seed_height"])
        rounds = []
        for number in range(1, item["rounds"] + 1):
            cache, ready, ancestry, opened = {}, False, False, False
            phases = []
            targets = [(item["seed_fork"], item["seed_height"], True)] if item["prime_ready"] else []
            targets.append((item["chain_fork"], item["chain_height"], False))
            for fork, height, prime in targets:
                before = model.snapshot()
                target, action = identifier(fork, height), None
                if model.bound:
                    ready, ancestry = False, False
                    cache.clear()
                error = model.open_error() if not opened or model.bound else None
                if error == "format-mismatch" and not model.bound:
                    # The unpatched chain wrapper wipes foreign formats. This is
                    # an observed baseline defect, never a cleanup/migration API.
                    model = Model(variant)
                    error = None
                calls, patches = 5, []
                if error is None:
                    opened = True
                    calls += 1
                    if height - model.frontier["height"] > 10:
                        pass  # No background driver is started.
                    else:
                        calls += 1
                        if not ancestry:
                            ancestry = True
                            h = model.frontier["height"]
                            if 0 < h < height and model.frontier != identifier(fork, h):
                                error = "wrong-chain-identity"
                        if error is None:
                            if model.frontier["height"] >= height:
                                if model.frontier["height"] > height:
                                    error = model.truncate(target)
                                    if model.bound:
                                        cache.clear()
                                elif model.frontier != target:
                                    error = "wrong-chain-identity"
                                if error is None:
                                    ready = True
                            else:
                                state = dict(model.selected_state(model.frontier))
                                for h in range(model.frontier["height"] + 1, height + 1):
                                    state.update(patch(fork, h))
                                    context = identifier(fork, h)
                                    patches.append({"method": "GetPatch", "identifier": context})
                                    model.commit(context, state)
                                    if model.bound:
                                        cache.clear()
                                ready = True
                after_init = model.snapshot()
                if not prime and item["action"]:
                    require(error is None and ready)
                    warm = identifier("A", 1 if item["action"] == "cache-prune" else 3)
                    computed, failure, callbacks = model.compute(warm)
                    require(failure is None and callbacks == 1)
                    cache.clear()
                    cache.update(identifier=dict(warm), root=computed)
                    if item["action"] == "cache-prune":
                        action_error = model.prune(2)
                    elif item["action"] == "cache-truncate":
                        action_error = model.truncate(identifier("A", 2))
                    else:
                        model.closed, action_error = True, None
                    if model.bound and item["action"] != "cache-close":
                        cache.clear()
                    action = {"name": item["action"], "warm_identifier": warm,
                              "warm_root": computed.hex(), "warm_error": None,
                              "warm_patch_callbacks": {"dump": 1, "replay": 1},
                              "error": action_error, "records_after": model.snapshot()}
                query = identifier(item["query_fork"], item["query_height"]) if item["query_fork"] else target
                trace = [{"method": "Frontier"} for _ in range(calls)] + patches
                phases.append({
                    "prime": prime, "selected_identifier": target, "query_identifier": query,
                    "init_error": error, "ready": ready,
                    "retained_frontier": dict(model.frontier) if opened else None,
                    "handle_open": opened, "action": action,
                    "records_before": before, "records_after_init": after_init,
                    "queries": queries(model, query, chain=True, ready=ready, cache=cache),
                    "records_after_queries": model.snapshot(), "manager_trace": trace,
                    "cache_trace": ["DB"], "genesis_trace": ["GetGenesisMomentum", "GetSporkAddress"],
                })
            stopped_closed = model.closed
            model.closed = False
            rounds.append({
                "round": number, "phases": phases,
                "stop_error": "database-closed" if stopped_closed else None,
                "ready_after_stop": False if model.bound else ready,
                "records_after_close_reopen": model.snapshot(),
                "final_manager_trace": trace + ([] if stopped_closed else [{"method": "Stop"}]),
                "final_cache_trace": ["DB"] + ([] if stopped_closed else ["Stop"]),
            })
        result.append({"input": item, "rounds": rounds})
    return result


def low_level_cases(variant):
    cases = []
    for name in LOW_LEVEL:
        model = Model(variant)
        if name == "bulk-gap":
            state = {}
            for h in range(1, 6):
                state.update(patch("A", h))
            model.commit(identifier("A", 5), state)
        elif name == "empty-version":
            model.commit(identifier("A", 1), {})
        elif name == "commit-origin-after-max":
            model.commit(identifier("A", (1 << 64) - 1), patch("A", 1))
        else:
            model = Model(variant, "A", 3)
        before, operations = model.snapshot(), []
        target = identifier("A", 3)
        method, selected, error = None, None, None
        if name in ("truncate-matching", "truncate-divergent", "truncate-origin", "truncate-origin-alias", "bulk-gap"):
            target = (dict(ORIGIN) if name == "truncate-origin" else identifier("X", 0)
                      if name == "truncate-origin-alias" else identifier("B", 2)
                      if name == "truncate-divergent" else identifier("A", 2))
            method, selected, error = "Truncate", target, model.truncate(target)
        elif name.startswith("prune-"):
            horizon = 2 if name == "prune-retained" else 4
            if horizon == 2:
                target = identifier("A", 1)
            method, selected, error = "Prune:" + str(horizon), dict(ORIGIN), model.prune(horizon)
        elif name == "empty-version":
            target = identifier("A", 1)
        elif name == "failed-compute-preserves-staging":
            wrong = identifier("B", 2)
            error = model.lookup(wrong)
            operations.append({
                "method": "ComputeRoot:injected-replay", "identifier": wrong, "root": ZERO.hex(),
                "error": error or "injected-replay", "patch_callbacks": {"dump": 0, "replay": 0 if error else 1},
            })
            target = identifier("A", 4)
            model.commit(target, patch("A", 99))
            method, selected, error = "Commit:pending", target, None
        elif name == "commit-origin-after-max":
            if model.bound:
                error = "commit-order"
            else:
                model.commit(ORIGIN, patch("A", 2))
            method, selected, target = "Commit:origin", dict(ORIGIN), identifier("A", (1 << 64) - 1)
        if method is not None:
            operations.append({"method": method, "identifier": selected, "root": None, "error": error})
        after = model.snapshot()
        front_root, front_error = model.read_root(model.frontier)
        observations = queries(model, target)
        open_error = model.open_error()
        next_root, next_error = model.read_root(model.frontier) if open_error is None else (None, None)
        cases.append({
            "name": name, "records_before": before, "operations": operations, "records_after": after,
            "frontier": dict(model.frontier), "frontier_root": front_root.hex(), "frontier_root_error": front_error,
            "query_identifier": target, "queries": observations, "records_after_close_reopen": model.snapshot(),
            "reopen_error": open_error,
            "reopen_frontier": dict(model.frontier) if open_error is None else None,
            "reopen_root": next_root.hex() if next_root is not None else None, "reopen_root_error": next_error,
        })
    return cases


@functools.lru_cache(maxsize=2)
def expected_variant(variant):
    require(variant in VARIANTS)
    return {
        "format_version": 1, "kind": "current-node-hash-bound-version-research", "variant": variant,
        "chain_cases": chain_cases(variant), "low_level_cases": low_level_cases(variant),
        "source_revision": REVISION, "consumer_result": "REFUSED",
        "production_state_value_accepted": False, "header_authentication_executed": False,
    }


def source_pins():
    inputs = {name: hashlib.sha256((HERE / name).read_bytes()).hexdigest() for name in INPUTS}
    require(inputs["hash-bound-versions-patch.json"] == PATCH_SHA256)
    require(inputs["node-recovery-source-pins.json"] == MANIFEST_SHA256)
    return {
        "repository": "https://github.com/digitalSloth/go-zenon", "revision": REVISION, "tree": TREE,
        "blob_count": 439, "modified_node_tree_without_probe": MODIFIED_TREE,
        "source_manifest_sha256": MANIFEST_SHA256, "patch_sha256": PATCH_SHA256,
        "producer_inputs": inputs, "selection": "complete-current-source-explicit-local-variants",
        "historical_56ce_source_and_records_rebound": False,
    }


def expected_corpus():
    return {"format_version": 1, "kind": "current-node-hash-bound-version-comparison",
            "source": source_pins(), "scope": dict(SCOPE),
            "variants": {name: expected_variant(name) for name in VARIANTS}, "consumer_result": "REFUSED"}


def check_variant(document, variant):
    exact(document, expected_variant(variant), variant)


def check_corpus(document):
    exact(document, expected_corpus())
    phases = [phase for variant in document["variants"].values() for case in variant["chain_cases"]
              for round in case["rounds"] for phase in round["phases"]]
    low = [case for variant in document["variants"].values() for case in variant["low_level_cases"]]
    snapshots = sum(3 + int(phase["action"] is not None) for phase in phases)
    snapshots += sum(len(case["rounds"]) for v in document["variants"].values() for case in v["chain_cases"])
    snapshots += 3 * len(low)
    return {"kind": "hash-bound-retained-version-offline-check",
            "variants": list(VARIANTS), "chain_cases_per_variant": len(selected_inputs()),
            "low_level_cases_per_variant": len(LOW_LEVEL), "component_initializations": len(phases),
            "read_api_observations": 11 * (len(phases) + len(low)),
            "complete_logical_database_snapshots": snapshots,
            "current_node_revision": REVISION, "consumer_result": "REFUSED",
            "complete_current_node_revision_qualified": False, "production_state_value_accepted": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus", nargs="?", default=str(HERE / "testdata/candidate-hash-bound-versions.json"))
    args = parser.parse_args()
    try:
        _, document = read_corpus(args.corpus)
        report = check_corpus(document)
    except (ValueError, OSError, TypeError, KeyError, IndexError):
        print("Hash-bound retained-version research corpus refused", file=sys.stderr)
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())

