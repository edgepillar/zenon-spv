#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Derive finite component expectations from a pinned unsigned source-genesis dump.

No node, process, network, wallet, signing or database API is executed. The caller
must bound stdout and own the input acquisition. A matching source or input hash
does not authenticate a network, genesis, activation schedule or header root.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent


def module(name, file):
    spec = importlib.util.spec_from_file_location(name, HERE / file)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


B = module("genesis_derivation_byte_contract", "check.py")
D = module("genesis_derivation_batch_contract", "check_patch_decode.py")
I = module("genesis_derivation_source_decoder", "genesis_input_decode.py")
L = module("genesis_derivation_sparse_layers", "genesis_sparse_model.py")
F = module("genesis_derivation_witness_forest", "genesis_witness_model.py")
RAW = {"sha256": "a222aac55304b1a489d395235c61af4182ac08b887d24d0c3f654aa402f35e75", "bytes": 10849399}
INITIAL_ROOT = "864dbad1c3ef38e2c867950390364878c58238183d01b8bf97ef73e2efa4383d"
FINAL_ROOT = "886e79750c9cbe90479e8e4a4f3afe81a07f26bdc11601bbee79a86a5415d465"
CHECKPOINTS = (1, 3840, 3841, 3968, 4096)


def require(condition, message="Independent genesis expectation derivation refused"):
    if not condition:
        raise ValueError(message)


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def admitted(key):
    return len(key) >= 22 and key[0] == 3 and key[21] in (3, 4)


def derive_initial(raw, source_config=None):
    require(type(raw) is bytes and len(raw) == RAW["bytes"]
              and hashlib.sha256(raw).hexdigest() == RAW["sha256"], "source input identity differs")
    counts, state = I.counts_and_state(raw, D)
    leaves = {k: v for k, v in state.items() if admitted(k) and v}
    balances = sorted(k for k in leaves if k[21] == 3)
    storage = sorted(k for k in leaves if k[21] == 4)
    require((len(state), len(balances), len(storage)) == (103821, 14091, 5166))
    if source_config is not None:
        require({k: v for k, v in state.items() if len(k) >= 22 and k[0] == 3 and k[21] == 3}
                  == I.balances(source_config), "independent source balance map differs")
    samples = [("balance", k) for k in balances[:4] + balances[-4:]]
    samples += [("contract_storage", k) for k in storage[:2] + storage[-2:]]
    tokens = sorted({k[22:] for k in balances})
    require(len(tokens) == 2)
    missing = None
    for token in tokens:
        candidate = b"\x03" + balances[0][1:21] + b"\x03" + token
        if candidate not in state:
            missing = candidate
            break
    if missing is None:
        for key in balances:
            candidate = key[:22] + next(token for token in tokens if token != key[22:])
            if candidate not in state:
                missing = candidate
                break
    require(missing is not None)
    samples.append(("absent_balance_existing_address", missing))
    for index in range(1, 65536):
        candidate = b"\x03\x00" + index.to_bytes(19, "big") + b"\x03" + tokens[0]
        if candidate not in state:
            samples.append(("absent_balance_selected_address", candidate))
            break
    samples.append(("excluded_ledger_key", next(k for k in sorted(state) if not admitted(k))))
    require(len(samples) == len({k for _, k in samples}) == 15)
    positions = {L.digest(k): v for k, v in leaves.items()}
    require(len(positions) == len(leaves))
    root, proofs, _ = L.model(positions, [L.digest(k) for _, k in samples])
    require(root.hex() == INITIAL_ROOT)
    rows = []
    for domain, key in samples:
        position = L.digest(key)
        value = leaves.get(key)
        proof = proofs[position]
        require(B.proof_result(root, position, value or b"", proof, value is not None) == "match")
        rows.append({"selection": domain, "raw_key": key.hex(), "path": position.hex(),
                     "present_in_projection": value is not None,
                     "value": None if value is None else value.hex(), "proof": proof.hex(),
                     "ledger_raw_input_has_key": key in state,
                     "typed_domain_refused": domain == "excluded_ledger_key", "consumer_result": "REFUSED"})
    result = {"raw_input": dict(RAW), "logical_input_keys": len(state),
              "admitted_nonempty_leaf_keys": len(leaves), "balance_leaf_keys": len(balances),
              "storage_leaf_keys": len(storage),
              "excluded_logical_keys": sum(not admitted(k) for k in state),
              "empty_admitted_values_omitted": sum(admitted(k) and not v for k, v in state.items()),
              "sorted_projection_mapping_sha256": I.mapping_sha(leaves),
              "expected_root": root.hex(), "selected_proofs": rows}
    return result, leaves, counts


def derive_history(base, final_input_state=None):
    require(base["raw_input"] == RAW and base["expected_root"] == INITIAL_ROOT)
    samples = base["selected_proofs"]
    require(type(samples) is list and len(samples) == 15)
    selected = [bytes.fromhex(row["path"]) for row in samples]
    require(len(set(selected)) == 15)
    for row, position in zip(samples, selected):
        value = None if row["value"] is None else bytes.fromhex(row["value"])
        require(B.proof_result(bytes.fromhex(INITIAL_ROOT), position, value or b"",
                                 bytes.fromhex(row["proof"]), value is not None) == "match")
    forest = F.Forest(bytes.fromhex(INITIAL_ROOT), samples)
    keys = [bytes.fromhex(row["raw_key"]) for row in samples if row["selection"] == "balance"]
    require(len(keys) == len(set(keys)) == 8)
    roots = [{"height": 1, "root": INITIAL_ROOT}]
    checkpoints = {"1": [dict(row) for row in samples]}
    actions = []
    for height in range(2, 4097):
        key = keys[(height - 2) % 8]
        value = (None if height % 11 == 0 else
                 (0 if height % 7 == 0 else 1000000 + height).to_bytes(32, "big"))
        root = forest.update(F.digest(key), value)
        roots.append({"height": height, "root": root.hex()})
        actions.append({"height": height, "operation": "Delete" if value is None else "Put",
                        "key": key.hex(), "value": None if value is None else value.hex()})
        if final_input_state is not None:
            if value is None:
                final_input_state.pop(key, None)
            else:
                final_input_state[key] = value
        if height in CHECKPOINTS:
            rows = []
            for initial, position in zip(samples, selected):
                value = forest.values.get(position)
                proof = forest.proof(position)
                present = position in forest.values
                require(B.proof_result(root, position, value or b"", proof, present) == "match")
                rows.append(dict(initial, present_in_projection=present,
                                 value=None if value is None else value.hex(), proof=proof.hex()))
            checkpoints[str(height)] = rows
    require(forest.root().hex() == FINAL_ROOT and len(forest.nodes) <= 8192)
    if final_input_state is not None:
        root, proofs, _ = L.model({F.digest(k): v for k, v in final_input_state.items()}, selected)
        require(root == forest.root() and all(proofs[p] == forest.proof(p) for p in selected))
    return {"archive_policy_roots": roots, "selected_checkpoints": checkpoints,
            "history_height": 4096, "retention_test_policy": 256,
            "mutation_keys": [k.hex() for k in keys],
            "mutation_rule": {"index": "(height-2)%8", "Delete": "height divisible by 11",
                              "present_zero": "otherwise height divisible by 7",
                              "other_value": "uint256_be(1000000+height)"},
            "mutation_frame_sha256": hashlib.sha256(encoded(actions)).hexdigest(),
            "complete_root_table_sha256": hashlib.sha256(encoded(roots)).hexdigest(),
            "final_root": forest.root().hex()}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--node-source", type=Path, required=True)
    args = parser.parse_args(argv)
    P = module("genesis_derivation_complete_source", "prepare_hash_bound_versions.py")
    _, manifest = P.source_manifest()
    files = P.snapshot_source(args.node_source, manifest["files"])
    config = json.loads(files["chain/genesis/embedded_genesis_string.go"].split(b"`")[1],
                        object_pairs_hook=B.object_pairs)
    raw = P.read_regular(args.input, RAW["bytes"])
    base, state, counts = derive_initial(raw, config)
    history = derive_history(base, state)
    print(json.dumps({"kind": "source-genesis-background-independent-expectations",
                      "node_revision": P.REVISION, "base": base, "history": history,
                      "input_replay_counts": counts, "source_balances_independently_checked": 14091,
                      "full_initial_and_final_projection_recomputed": True,
                      "reference_or_network_execution": False, "profile_agreed": False,
                      "production_resources_qualified": False, "consumer_result": "REFUSED"},
                     sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError, IndexError, AssertionError):
        print("Independent genesis derivation refused; preserve the selected input and error output.", file=sys.stderr)
        sys.exit(1)
