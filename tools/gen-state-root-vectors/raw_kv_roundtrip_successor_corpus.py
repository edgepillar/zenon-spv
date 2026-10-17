#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Share complete captured record/proof preimages without repeated transport JSON.

Indices are local corpus references, never trust inputs. Reconstructed dumps and
proofs preserve exact bytes; JSON whitespace/order and original transport bytes
are not reconstructed. The original transport digests are separate observations.
"""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("shared_raw_kv_corpus_checker", HERE / "check_raw_kv_roundtrip_successor.py")
C = importlib.util.module_from_spec(spec)
spec.loader.exec_module(C)
COUNTS = {"records": 2974, "record_orders": 8, "proofs": 585, "proof_sets": 65, "query_sets": 8}
MAX_BYTES = 8 << 20
KIND = "successor-raw-kv-roundtrip-complete-shared-preimages"
SNAPSHOT_FIELDS = ("name", "frontier", "record_manifest", "dump_selection")
PROOF_FIELDS = {"key", "value", "present", "proof", "error"}


def require(value):
    if not value:
        raise ValueError("Shared raw KV corpus refused")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def encoded(value):
    return C.M.encoded(value)


def pack(observations, expected):
    """Pack verified actual or explicitly synthetic test frames; claim no provenance."""
    require(type(observations) is tuple and len(observations) == 2)
    C.selected_expectations(expected)
    tables, indices = {name: [] for name in COUNTS}, {name: {} for name in COUNTS}

    def intern(name, value):
        key = canonical(value)
        if key not in indices[name]:
            require(len(tables[name]) < COUNTS[name])
            indices[name][key] = len(tables[name])
            tables[name].append(copy.deepcopy(value))
        return indices[name][key]

    selected = []
    for (policy, raw), required_policy in zip(observations, C.M.POLICIES):
        require(policy == required_policy)
        C.check_observation(raw, expected, policy)
        observed = C.document(raw, C.MAX_OBSERVATION_BYTES)
        frames = []
        for snapshot in observed["snapshots"]:
            dump = C.raw_hex(observed["dump_objects"][snapshot["dump_selection"]["sha256"]], 8 << 20, 1)
            records = C.M.C.decode_selected_dump(dump, snapshot["dump_selection"])
            order = [intern("records", {"key": key.hex(), "value": value.hex()}) for key, value in records]
            groups = []
            proofs = snapshot["proofs"]
            require(len(proofs) % 9 == 0)
            for offset in range(0, len(proofs), 9):
                group = proofs[offset:offset + 9]
                identity = group[0]["identifier"]
                require(all(row["identifier"] == identity for row in group))
                proof_ids = [intern("proofs", {key: value for key, value in row.items() if key != "identifier"})
                             for row in group]
                groups.append({"identifier": identity, "proof_set": intern("proof_sets", proof_ids)})
            frame = {key: snapshot[key] for key in SNAPSHOT_FIELDS}
            frame.update(record_order=intern("record_orders", order),
                         query_set=intern("query_sets", snapshot["root_queries"]), proof_groups=groups)
            frames.append(frame)
        selected.append({
            "policy": policy, "header": {key: value for key, value in observed.items()
                                       if key not in ("snapshots", "dump_objects")},
            "original_transport": {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)},
            "snapshots": frames,
        })
    corpus = {"format_version": 1, "kind": KIND, "tables": tables, "observations": selected,
              "original_transport_JSON_reconstructed": False}
    require(len(encoded(corpus)) <= MAX_BYTES)
    restored = unpack(corpus)
    for (policy, raw), (restored_policy, value) in zip(observations, restored):
        require(policy == restored_policy)
        C.P.exact(C.document(raw, C.MAX_OBSERVATION_BYTES), value)
    return corpus


def unpack(corpus):
    require(type(corpus) is dict and set(corpus) == {
        "format_version", "kind", "tables", "observations", "original_transport_JSON_reconstructed"})
    C.P.exact([corpus["format_version"], corpus["kind"], corpus["original_transport_JSON_reconstructed"]],
              [1, KIND, False])
    tables, rows = corpus["tables"], corpus["observations"]
    require(type(tables) is dict and set(tables) == set(COUNTS))
    for name, count in COUNTS.items():
        values = tables[name]
        require(type(values) is list and len(values) == count
                and len({canonical(value) for value in values}) == count)
    require(type(rows) is list and len(rows) == 2)
    used = {name: set() for name in tables}

    def get(name, index):
        require(type(index) is int and 0 <= index < len(tables[name]))
        used[name].add(index)
        return tables[name][index]

    restored = []
    for row, policy in zip(rows, C.M.POLICIES):
        require(type(row) is dict and set(row) == {"policy", "header", "original_transport", "snapshots"})
        C.P.exact(row["policy"], policy)
        capture = row["original_transport"]
        require(type(capture) is dict and set(capture) == {"bytes", "sha256"}
                and type(capture["bytes"]) is int and 0 < capture["bytes"] <= C.MAX_OBSERVATION_BYTES)
        C.raw_hex(capture["sha256"], 32, 32)
        require(type(row["header"]) is dict and not ({"snapshots", "dump_objects"} & set(row["header"])))
        observed = copy.deepcopy(row["header"])
        require(type(row["snapshots"]) is list and len(row["snapshots"]) == 5)
        observed.update(snapshots=[], dump_objects={})
        for frame in row["snapshots"]:
            require(type(frame) is dict and set(frame) == set(SNAPSHOT_FIELDS) | {
                "record_order", "query_set", "proof_groups"})
            order = get("record_orders", frame["record_order"])
            require(type(order) is list and 0 < len(order) <= 32768 and len(set(order)) == len(order))
            records = []
            for index in order:
                value = get("records", index)
                require(type(value) is dict and set(value) == {"key", "value"})
                records.append((C.raw_hex(value["key"], 128, 1), C.raw_hex(value["value"], 1 << 20)))
            dump = C.M.C.encode_dump(tuple(records))
            pin = frame["dump_selection"]
            C.M.C.decode_selected_dump(dump, pin)
            digest = hashlib.sha256(dump).hexdigest()
            require(digest not in observed["dump_objects"] or observed["dump_objects"][digest] == dump.hex())
            observed["dump_objects"][digest] = dump.hex()
            snapshot = {key: copy.deepcopy(frame[key]) for key in SNAPSHOT_FIELDS}
            queries = get("query_sets", frame["query_set"])
            require(type(queries) is list and len(queries) == 130)
            snapshot["root_queries"] = copy.deepcopy(queries)
            groups = frame["proof_groups"]
            require(type(groups) is list and len(groups) <= 65)
            snapshot["proofs"] = []
            for group in groups:
                require(type(group) is dict and set(group) == {"identifier", "proof_set"})
                proof_ids = get("proof_sets", group["proof_set"])
                require(type(proof_ids) is list and len(proof_ids) == 9 and len(set(proof_ids)) == 9)
                for index in proof_ids:
                    proof = get("proofs", index)
                    require(type(proof) is dict and set(proof) == PROOF_FIELDS
                            and type(proof["present"]) is bool and proof["error"] == "")
                    C.raw_hex(proof["key"], 128, 1)
                    C.raw_hex(proof["value"], 1 << 20)
                    C.raw_hex(proof["proof"], 16384, 99)
                    snapshot["proofs"].append(dict(proof, identifier=copy.deepcopy(group["identifier"])))
            observed["snapshots"].append(snapshot)
        restored.append((policy, observed))
    require(all(used[name] == set(range(count)) for name, count in COUNTS.items()))
    return restored


def check(raw, expected):
    corpus = C.document(raw, MAX_BYTES)
    observations = unpack(corpus)
    checks = [C.check_observation(encoded(value), expected, policy) for policy, value in observations]
    return {
        "format_version": 1, "kind": "successor-raw-kv-shared-preimage-check",
        "corpus_sha256": hashlib.sha256(raw).hexdigest(), "corpus_bytes": len(raw),
        "shared_preimage_counts": dict(COUNTS), "policies": checks,
        "complete_raw_dump_and_proof_bytes_preserved": True,
        "original_transport_JSON_reconstructed": False,
        "original_transport_digests_are_separate_capture_observations": True,
        "reference_node_executed_by_this_checker": False, "consumer_result": "REFUSED",
    }
