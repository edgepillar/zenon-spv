#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Derive complete finite raw-store expectations before any node execution.

This uses controlled logical L1 patches, not a ledger or an agreed balance
encoding. Empty Put values delete leaves; nonempty zero bytes remain stored.
The compressed-DAG model and full sparse levels independently bind all roots.
Record preimages are shared explicitly between finite store states.
"""
import functools
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct
import sys
from types import ModuleType

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


R = module("raw_store_selected_successor", "prepare_offline_rebuild_successor.py")
G = module("raw_store_independent_compressed_DAG", "check_retention.py")
C = module("raw_store_canonical_record_codec", "raw_kv_roundtrip_codec.py")
B = G.BYTE
KEY_COUNT = 64
TIP = 65
PROOF_INDICES = (0, 1, 2, 15, 32, 33, 34, 47, 64)
POLICIES = ("archive", "retain-5")
STAGES = ("seed-64", "restored-64", "tail-65", "rollback-60", "fork-61")


def require(condition):
    if not condition:
        raise ValueError("Raw store independent model refused")


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def identifier(height, fork="G"):
    require(type(height) is int and 1 <= height <= TIP and fork in ("G", "X"))
    return {"height": height, "hash": hashlib.sha3_256(
        ("synthetic-node-raw-kv-roundtrip-v1/" + fork + "/" + str(height)).encode()).hexdigest()}


def raw_key(index):
    require(type(index) is int and 0 <= index <= KEY_COUNT)
    if index == KEY_COUNT:
        return b"\x03" + b"\x99" * 20 + b"\x03" + b"\x44" * 10
    address = b"\x11" * 16 + (index % 16).to_bytes(4, "big")
    suffix = (b"\x03" + (index // 16).to_bytes(10, "big") if index < 32
              else b"\x04" + (index - 32).to_bytes(32, "big"))
    return b"\x03" + address + suffix


def fold_keep(key):
    require(type(key) is bytes)
    return len(key) > 21 and key[0] == 3 and key[21] in (3, 4)


def operations(height):
    require(type(height) is int and 1 <= height <= TIP)
    result = []
    if height == 1:
        for index in range(KEY_COUNT):
            value = (b"" if index in (1, 33) else bytes(32) if index in (0, 32)
                     else (index + 1).to_bytes(32, "big"))
            result.append({"operation": "put", "key": raw_key(index).hex(), "value": value.hex()})
    else:
        mutable = [index for index in range(KEY_COUNT) if index not in (0, 1, 32, 33)]
        start = ((height - 2) * 4) % len(mutable)
        for offset in range(4):
            index = mutable[(start + offset) % len(mutable)]
            delete = height % 3 == 0 and offset == 0
            value = b"" if height % 4 == 0 and offset == 1 else (height * KEY_COUNT + index + 1).to_bytes(32, "big")
            result.append({"operation": "delete" if delete else "put",
                           "key": raw_key(index).hex(), "value": "" if delete else value.hex()})
    # These are generic excluded domains, not proofs about any excluded state.
    for key in (b"\x00", b"\x03" + bytes(20), b"\x03" + bytes(20) + b"\x05"):
        result.append({"operation": "put", "key": key.hex(), "value": height.to_bytes(8, "big").hex()})
    return result


def apply_operations(state, changes):
    require(type(state) is dict and type(changes) is list)
    require(all(type(key) is bytes and type(value) is bytes for key, value in state.items()))
    result = dict(state)
    for row in changes:
        require(type(row) is dict and set(row) == {"operation", "key", "value"})
        require(type(row["operation"]) is str and row["operation"] in ("put", "delete")
                and type(row["key"]) is str and type(row["value"]) is str)
        require(row["operation"] != "delete" or row["value"] == "")
        key, value = bytes.fromhex(row["key"]), bytes.fromhex(row["value"])
        require(key.hex() == row["key"] and value.hex() == row["value"])
        if not fold_keep(key):
            continue
        if row["operation"] == "delete" or not value:
            result.pop(key, None)
        else:
            result[key] = value
    return result


def logical_history():
    result = {0: {}}
    for height in range(1, TIP + 1):
        result[height] = apply_operations(result[height - 1], operations(height))
    return result


def selection():
    return {
        "format_version": 1, "kind": "selected-successor-raw-kv-roundtrip",
        "policies": list(POLICIES), "initial_tip": 64, "tail_tip": TIP,
        "rollback_identifier": identifier(60), "fork_identifier": identifier(61, "X"),
        "fork_changes_reuse_height": 61,
        "keys": [raw_key(index).hex() for index in range(KEY_COUNT)],
        "proof_keys": [raw_key(index).hex() for index in PROOF_INDICES],
        "query_identifiers": [identifier(height, fork) for fork in ("G", "X") for height in range(1, TIP + 1)],
        "history": [{"identifier": identifier(height), "changes": operations(height)}
                    for height in range(1, TIP + 1)],
        "empty_Put_means_delete_in_selected_L1_fold": True,
        "balance_value_encoding_agreed": False,
    }


def source_identity():
    original, _, _, pins = R.runtime_selection("full-identifier")
    return {
        "repository": original["repository"], "node_revision": original["revision"],
        "original_node_tree": original["tree"], "source_blobs": len(pins),
        "selected_runtime_tree": R.MODIFIED_TREE, "experimental_disk_format": 3,
        "module_sha256": original["files"]["go.mod"]["sha256"],
        "sum_sha256": original["files"]["go.sum"]["sha256"],
        "nodestore_sha256": pins["common/trie/nodestore.go"]["sha256"],
        "L1_fold_sha256": original["files"]["common/trie/momentum_fold.go"]["sha256"],
        "selected_Batch_source_sha256": C.BATCH_SOURCE_SHA256,
    }


def source_inputs():
    queue, seen, names = [R, G, C], set(), {Path(__file__).name}
    while queue:
        current = queue.pop(0)
        if id(current) in seen:
            continue
        seen.add(id(current))
        require(len(seen) <= 128)
        path = Path(current.__file__).resolve()
        require(path.parent == HERE)
        names.add(path.name)
        for value in vars(current).values():
            file = getattr(value, "__file__", None) if type(value) is ModuleType else None
            if type(file) is str and Path(file).resolve().parent == HERE:
                queue.append(value)
    names.update(("node-recovery-9c71-source-pins.json", "node-recovery-9c71-patch.json",
                  "node-terminal-stop-9c71-patch.json", "node-offline-rebuild-9c71-patch.json"))
    return {name: {"sha256": hashlib.sha256(R.P.read_regular(HERE / name, 8 << 20)).hexdigest(),
                   "bytes": (HERE / name).stat().st_size} for name in sorted(names)}


def record_manifest(records):
    digest = hashlib.sha256()
    for key, value in records:
        digest.update(struct.pack(">Q", len(key)) + key + struct.pack(">Q", len(value)) + value)
    return {"records": len(records), "key_bytes": sum(len(key) for key, _ in records),
            "value_bytes": sum(len(value) for _, value in records), "sha256": digest.hexdigest()}


def _graphs_and_witnesses(history):
    graphs, witnesses = {}, {}
    for height in range(1, TIP + 1):
        state = {B.digest(key): value for key, value in history[height].items()}
        require(len(state) == len(history[height]))
        graph = G.graph(state)
        levels, values = B.tree_levels([{"path": key.hex(), "value": value.hex()}
                                       for key, value in sorted(state.items())])
        require(graph[1] == levels[0].get(0, B.ZERO))
        proofs = []
        for index in PROOF_INDICES:
            key, path = raw_key(index), B.digest(raw_key(index))
            proofs.append({"key": key.hex(), "value": history[height].get(key, b"").hex(),
                           "present": key in history[height],
                           "proof": B.canonical_proof(levels, values, path).hex()})
        graphs[height] = graph
        witnesses[str(height)] = {"root_id": graph[0].hex(), "root": graph[1].hex(),
                                  "leaf_count": len(state), "proofs": proofs}
    return graphs, witnesses


def _record_id(key, value):
    return hashlib.sha256(b"raw-store-record-v1\x00" + struct.pack(">Q", len(key)) + key
                          + struct.pack(">Q", len(value)) + value).hexdigest()


def _store(frontier, retained, graphs, witnesses, objects):
    nodes, edges, roots = {}, {}, {}
    for height in sorted(retained):
        root, _, current, links = graphs[height]
        roots[height] = root
        for key, value in current.items():
            require(key not in nodes or nodes[key] == value)
            nodes[key] = value
        for key, value in links.items():
            require(key not in edges or edges[key] == value)
            edges[key] = value
    refs = {key: 0 for key in nodes}
    for root in roots.values():
        if root != B.ZERO:
            refs[root] += 1
    for left, right in edges.values():
        require(left in refs and right in refs)
        refs[left] += 1
        refs[right] += 1
    require(all(number > 0 for number in refs.values()))
    records = {b"\x00": bytes.fromhex(frontier["hash"]) + frontier["height"].to_bytes(8, "big"),
               b"\x05": b"\x03"}
    records.update({b"\x01" + key: value for key, value in nodes.items()})
    records.update({b"\x02" + key: number.to_bytes(8, "big") for key, number in refs.items()})
    records.update({b"\x03" + height.to_bytes(8, "big"): value for height, value in roots.items()})
    records.update({b"\x06" + height.to_bytes(8, "big"): bytes.fromhex(identity["hash"])
                    for height, identity in retained.items()})
    ordered = tuple(sorted(records.items()))
    dump = C.encode_dump(ordered)
    selection_pin = {"bytes": len(dump), "records": len(ordered), "sha256": hashlib.sha256(dump).hexdigest()}
    require(C.decode_selected_dump(dump, selection_pin) == ordered)
    record_order = []
    for key, value in ordered:
        record_id = _record_id(key, value)
        row = {"key": key.hex(), "value": value.hex()}
        require(record_id not in objects or objects[record_id] == row)
        objects[record_id] = row
        record_order.append(record_id)
    queries = []
    for fork in ("G", "X"):
        for height in range(1, TIP + 1):
            query = identifier(height, fork)
            error = ("no-version" if height not in retained else
                     "version-hash-mismatch" if retained[height] != query else "")
            queries.append({"identifier": query, "error": error, "proof_error": error,
                            "root": B.ZERO.hex() if error else witnesses[str(height)]["root"]})
    return {"frontier": frontier, "retained": [{"identifier": retained[height], "witness_height": height}
                                               for height in sorted(retained)],
            "record_order": record_order, "record_manifest": record_manifest(ordered),
            "dump_selection": selection_pin, "root_queries": queries,
            "family_counts": {"frontier": 1, "format": 1, "node": len(nodes), "refcount": len(refs),
                              "version": len(retained), "version_hash": len(retained)}}


def store_records(document, policy, store):
    require(type(document) is dict and type(policy) is str and type(store) is str
            and policy in POLICIES and store in ("64", "65", "60", "fork-61"))
    ids = document["policies"][policy]["stores"][store]["record_order"]
    require(type(ids) is list and len(ids) <= 32768)
    result = []
    for key in ids:
        require(type(key) is str and re.fullmatch("[0-9a-f]{64}", key) is not None)
        row = document["record_objects"][key]
        require(type(row) is dict and set(row) == {"key", "value"})
        require(type(row["key"]) is str and 0 < len(row["key"]) <= 256)
        require(type(row["value"]) is str and len(row["value"]) <= 2 << 20)
        raw_key_value, raw_value = bytes.fromhex(row["key"]), bytes.fromhex(row["value"])
        require(raw_key_value.hex() == row["key"] and raw_value.hex() == row["value"])
        require(_record_id(raw_key_value, raw_value) == key)
        result.append((raw_key_value, raw_value))
    result = tuple(result)
    C.encode_dump(result)
    return result


@functools.lru_cache(maxsize=1)
def _derive_bytes(source_key):
    sources = json.loads(source_key)
    source = source_identity()
    history = logical_history()
    require(apply_operations(history[60], operations(61)) == history[61])
    graphs, witnesses = _graphs_and_witnesses(history)
    objects, policies = {}, {}
    for policy in POLICIES:
        start = 1 if policy == "archive" else 59
        retained64 = {height: identifier(height) for height in range(start, 65)}
        retained65 = {height: identifier(height) for height in range(1 if policy == "archive" else 60, 66)}
        retained60 = {height: identity for height, identity in retained65.items() if height <= 60}
        fork61 = dict(retained60)
        fork61[61] = identifier(61, "X")
        stores = {}
        for name, frontier, retained in (("64", identifier(64), retained64),
                                         ("65", identifier(65), retained65),
                                         ("60", identifier(60), retained60),
                                         ("fork-61", identifier(61, "X"), fork61)):
            stores[name] = _store(frontier, retained, graphs, witnesses, objects)
        policies[policy] = {"stores": stores,
                            "flow": [{"stage": name, "store": target} for name, target in
                                     zip(STAGES, ("64", "64", "65", "60", "fork-61"))]}
    require(encoded(source_inputs()) == source_key)
    return encoded({"format_version": 1, "kind": "successor-raw-kv-roundtrip-independent-expectations",
                    "source": source, "source_inputs": sources, "selection": selection(),
                    "selection_sha256": hashlib.sha256(encoded(selection())).hexdigest(),
                    "record_objects": objects, "policies": policies, "witnesses": witnesses,
                    "scope": {"independent_model_before_backend": True, "synthetic_logical_L1_patches": True,
                              "raw_store_codec_and_SMT_root_are_separate": True,
                              "raw_record_preimages_shared_by_content": True,
                              "source_genesis_execution_relabelled": False, "node_backend_executed": False,
                              "authenticated_snapshot_import": False, "accepted_header_binding": False,
                              "balance_value_encoding_agreed": False, "representative_resources_qualified": False,
                              "consumer_result": "REFUSED", "production_state_value_accepted": False}})


def derive():
    return json.loads(_derive_bytes(encoded(source_inputs())))


if __name__ == "__main__":
    try:
        sys.stdout.buffer.write(_derive_bytes(encoded(source_inputs())))
    except (OSError, ValueError, KeyError, TypeError, IndexError, AssertionError):
        print("Raw store independent derivation refused; preserve inputs and output.", file=sys.stderr)
        sys.exit(1)
