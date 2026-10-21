#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Preselect a finite unsigned public-Chain reorg/reopen fixture.

This independently encodes patches, v1 header hashes and partial-SMT witnesses.
It extends a previously checked genesis witness; it is not consensus, activation
or an independently selected network-root oracle.
"""
import argparse
import hashlib
import json
import re
from pathlib import Path
import importlib.util
import stat
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("reorg_source_parent", HERE / "prepare_public_chain_startup_record.py")
H = importlib.util.module_from_spec(spec)
spec.loader.exec_module(H)
P = H.P

SEED_SHA256 = "50cd1a5960562735f27708959bf8d2420a8e0f4e3e2d6d9e4e3c8a997154efb6"
GENESIS = {"hash": "9e204601d1b7b1427fe12bc82622e610d8a6ad43c40abf020eb66e538bb8eeb0", "height": 1}
BASE_ROOT = "864dbad1c3ef38e2c867950390364878c58238183d01b8bf97ef73e2efa4383d"
KEY = "0300000000000000000000000000000000000000000304066318c6318c6318c6"
BASE_VALUE = (100000).to_bytes(32, "big").hex()
TIMESTAMP = 1637755200
ZERO = bytes(32)

def require(ok, reason="fixture invariant"):
    if not ok:
        raise ValueError(reason)

def hx(text, size=None):
    require(type(text) is str and re.fullmatch("[0-9a-f]*", text) is not None and len(text) % 2 == 0, "canonical hex")
    raw = bytes.fromhex(text)
    require(size is None or len(raw) == size, "hex length")
    return raw

def sha3(raw):
    return hashlib.sha3_256(raw).digest()

def siblings_from_seed(key, value, proof, expected_root):
    path = sha3(key)
    leaf = sha3(path + value)
    require(len(proof) >= 103 and proof[:1] == b"\x01", "present seed proof")
    require(proof[1:33] == path and proof[33:65] == leaf, "seed path/leaf")
    bitmap, count = proof[65:97], int.from_bytes(proof[97:99], "big")
    require(count <= 256 and count == sum(bin(x).count("1") for x in bitmap), "bitmap count")
    end = 99 + 32 * count
    require(len(proof) == end + 4 + len(value), "exact proof length")
    require(int.from_bytes(proof[end:end+4], "big") == len(value) and proof[end+4:] == value, "seed value")
    siblings, cursor = [], 99
    for index in range(256):
        if bitmap[index // 8] & (1 << (7 - index % 8)):
            sibling = proof[cursor:cursor+32]
            require(len(sibling) == 32 and sibling != ZERO, "canonical nonzero sibling")
            cursor += 32
        else:
            sibling = ZERO
        siblings.append(sibling)
    require(cursor == end, "sibling consumption")
    require(root_for(path, value, siblings).hex() == expected_root, "preexisting seed root")
    return siblings

def root_for(path, value, siblings):
    require(len(path) == 32 and len(siblings) == 256 and all(len(x) == 32 for x in siblings), "tree shape")
    require(value is None or len(value) == 32, "selected balance width")
    current = ZERO if value is None else sha3(path + value)
    for index, sibling in enumerate(siblings):
        depth = 255 - index
        right = (path[depth // 8] >> (7 - depth % 8)) & 1
        left, right_node = (sibling, current) if right else (current, sibling)
        current = ZERO if left == right_node == ZERO else sha3(left + right_node)
    return current

def proof_for(path, value, siblings):
    bitmap = bytearray(32)
    payload = bytearray()
    for index, sibling in enumerate(siblings):
        if sibling != ZERO:
            bitmap[index // 8] |= 1 << (7 - index % 8)
            payload.extend(sibling)
    present = value is not None
    leaf = sha3(path + value) if present else ZERO
    raw = bytes([int(present)]) + path + leaf + bytes(bitmap) + (len(payload)//32).to_bytes(2, "big") + payload
    if present:
        raw += len(value).to_bytes(4, "big") + value
    return raw

def uvarint(value):
    require(type(value) is int and 0 <= value < 1 << 64, "unsigned varint")
    out = bytearray()
    while value >= 128:
        out.append((value & 127) | 128)
        value >>= 7
    out.append(value)
    return bytes(out)

def patch_dump(key, value):
    require(len(key) == 32 and (value is None or len(value) == 32), "selected patch shape")
    # Pinned goleveldb Batch.Dump contains records, without a sequence/count header.
    return bytes([0 if value is None else 1]) + uvarint(len(key)) + key + (b"" if value is None else uvarint(len(value)) + value)

def header(previous, height, timestamp, dump):
    require(type(height) is int and height >= 2 and type(timestamp) is int and timestamp > TIMESTAMP, "selected header range")
    prev = hx(previous, 32)
    changes = sha3(dump)
    preimage = (1).to_bytes(8, "big") * 2 + prev + height.to_bytes(8, "big") + timestamp.to_bytes(8, "big") + sha3(b"") * 2 + changes
    require(len(preimage) == 160, "v1 preimage length")
    return {"version": 1, "chain_identifier": 1, "previous_hash": previous, "height": height,
            "timestamp_unix": timestamp, "changes_hash": changes.hex(), "hash": sha3(preimage).hex(),
            "data_hex": "", "content_count": 0, "preimage_hex": preimage.hex(),
            "public_key_bytes": 0, "signature_bytes": 0, "state_root": ZERO.hex()}

def generate(seed_raw):
    require(hashlib.sha256(seed_raw).hexdigest() == SEED_SHA256, "seed file pin")
    seed = json.loads(seed_raw)["selection"]
    require(seed["genesis_identifier"] == GENESIS and seed["root"] == BASE_ROOT, "seed identity")
    witness = seed["witness"]
    require(witness["raw_key"] == KEY and witness["value"] == BASE_VALUE and witness["present_in_projection"] is True, "seed selection")
    key, value, proof = hx(KEY, 32), hx(BASE_VALUE, 32), hx(witness["proof"])
    path = sha3(key)
    require(witness["path"] == path.hex(), "seed path pin")
    siblings = siblings_from_seed(key, value, proof, BASE_ROOT)
    require(proof_for(path, value, siblings) == proof, "canonical seed roundtrip")
    control = header(GENESIS["hash"], 2, TIMESTAMP + 10, b"")
    require(control["hash"] == "fbe4d2002715d5993894e36fe23eefab052ffe697861465b1be8c07d786beed0", "preexisting empty-v1 control")
    states = {"A1": {"identifier": GENESIS, "root": BASE_ROOT, "present": True, "value": BASE_VALUE,
                     "proof": proof.hex(), "header": None, "patch_dump": None, "patch_sha256": None}}
    choices = [("A2", "A1", 2, 10, bytes(32)), ("A3", "A2", 3, 20, (1).to_bytes(32, "big")),
               ("B2", "A1", 2, 30, (42).to_bytes(32, "big")), ("B3", "B2", 3, 40, None)]
    for name, parent, height, seconds, value in choices:
        dump = patch_dump(key, value)
        h = header(states[parent]["identifier"]["hash"], height, TIMESTAMP + seconds, dump)
        states[name] = {"identifier": {"hash": h["hash"], "height": height}, "root": root_for(path, value, siblings).hex(),
                        "present": value is not None, "value": "" if value is None else value.hex(),
                        "proof": proof_for(path, value, siblings).hex(), "header": h,
                        "patch_dump": dump.hex(), "patch_sha256": hashlib.sha256(dump).hexdigest()}
    require(len({row["root"] for row in states.values()}) == 5, "five distinct roots")
    require(states["A2"]["root"] != states["B3"]["root"], "stored zero differs from absent")
    require(states["A2"]["identifier"]["hash"] != states["B2"]["identifier"]["hash"] and
            states["A3"]["identifier"]["hash"] != states["B3"]["identifier"]["hash"], "fork identities")
    return {"schema": "zenon-public-chain-reorg-reopen-fixture-v1",
            "source": {"node_repository": "https://github.com/digitalSloth/go-zenon",
                       "original_revision": "9c71ae82fc983e16f914ae085d4034030c8ebe3b",
                       "experimental_runtime_tree": "d56bf37a23ddf0ec0f8af2eca62be01bb6c54dbc",
                       "seed_file_sha256": SEED_SHA256,
                       "genesis_patch": {"sha256": "a222aac55304b1a489d395235c61af4182ac08b887d24d0c3f654aa402f35e75", "bytes": 10849399}},
            "raw_key": KEY, "path": path.hex(), "states": states,
            "steps": ["append-A2", "append-A3", "rollback-A1", "append-B2", "append-B3"],
            "processes": ["advance-reorg", "reopen"], "preexisting_empty_v1_control": control["hash"],
            "unsigned_local_component_fixture": True, "full_consensus_validation_executed": False,
            "network_started": False, "consumer_result": "REFUSED", "production_state_value_accepted": False}

PROBE = "public_chain_reorg_reopen_probe.go"
PROBE_BYTES = 16838
PROBE_SHA256 = "12d93e8e9dbb41442464dcb0b87a514858f43d6bb6ec78f095efa90b636bb754"
PROBE_TARGET = "cmd/candidate-public-chain-reorg-reopen/main.go"
BUILD_TREE = "6a0803e012483bfc612cbdfa28581cc74be40c43"
FIXTURE_SHA256 = "220bb05cd50a6e3b174022950f66530c28c0c8f93529ac1194bfa5c15b323b3f"
FIXTURE_BYTES = 13485
FIXTURE_FILE = "reorg-reopen-fixture.json"
PREPARED_FILE = "reorg-reopen-prepared.json"
MODES = ("advance-reorg", "reopen")


def selected_fixture(seed=None):
    path = HERE / "testdata" / "successor-public-chain-lifecycle.json" if seed is None else Path(seed)
    raw = P.UTIL.encoded(generate(P.read_regular(path, 64 << 10)))
    require(len(raw) == FIXTURE_BYTES and hashlib.sha256(raw).hexdigest() == FIXTURE_SHA256, "independent fixture digest")
    return raw


def extra_source():
    raw = P.read_regular(HERE / PROBE, 64 << 10)
    require(len(raw) == PROBE_BYTES and hashlib.sha256(raw).hexdigest() == PROBE_SHA256, "ordinary probe pin")
    return raw


def build_pins():
    _, _, pins = H.selection()
    require(len(pins) == 467 and P.UTIL.reconstruct_tree(pins) == H.MODIFIED_TREE, "unchanged experimental runtime")
    raw = extra_source()
    require(PROBE_TARGET not in pins, "fresh entrypoint")
    pins[PROBE_TARGET] = {"mode": "100644", "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
                          "git_blob": P.UTIL.git_hash("blob", raw)}
    require(len(pins) == 468 and P.UTIL.reconstruct_tree(pins) == BUILD_TREE, "ordinary build tree")
    return pins


def plan(workspace, go):
    require(type(go) is str and bool(go) and "\x00" not in go, "selected compiler")
    workspace = Path(workspace).absolute()
    pins = build_pins()
    selected_fixture()
    return {
        "kind": "prepared-public-chain-reorg-reopen", "node_revision": P.REVISION,
        "original_node_tree": P.TREE, "experimental_runtime_tree": H.MODIFIED_TREE,
        "build_tree": BUILD_TREE, "source_blobs": len(pins),
        "probe": {"bytes": PROBE_BYTES, "sha256": PROBE_SHA256},
        "fixture": {"bytes": FIXTURE_BYTES, "sha256": FIXTURE_SHA256},
        "minimum_free_floor_bytes": 10 << 30, "expected_allocation_bytes": 2 << 30,
        "suggested_task_quota_bytes": 3 << 30,
        "build_argv": [go, "build", "-mod=readonly", "-p=2", "-trimpath", "-buildvcs=false",
                       "-tags", "candidate_public_chain_reorg_reopen",
                       "-o", str(workspace / "reorg-reopen"), "./cmd/candidate-public-chain-reorg-reopen"],
        "native_working_directory": str(workspace / "node"),
        "run_argv_templates": [
            [str(workspace / "reorg-reopen"), "--case", mode, "--root", "OWNED_CASE_ROOT",
             "--fixture", str(workspace / FIXTURE_FILE), "--fixture-sha256", FIXTURE_SHA256]
            for mode in MODES],
        "first_case_requires_empty_root": True, "second_case_reopens_same_closed_stores": True,
        "expected_queries": 31, "expected_exact_matches": 15, "expected_version_refusals": 16,
        "reference_backend_executed": False, "new_dependency_transports_permitted": False,
        "public_Chain_Init_and_Start_selected": True, "cache_account_block_extraction_selected": False,
        "network_or_full_node_selected": False, "consensus_validation_selected": False,
        "concurrent_lifecycle_or_interruption_qualified": False, "representative_resource_budget_qualified": False,
        "accepted_header_binding": False, "runtime_state_value_acceptance": False, "consumer_result": "REFUSED",
    }


def prepare(node_source, workspace, go):
    expected = plan(workspace, go)
    workspace = P.private_destination(workspace)
    node_source = Path(node_source).absolute()
    require(not any(path.is_symlink() for path in (node_source, *node_source.parents)), "ordinary source ancestors")
    original_root, prepared_root = node_source.resolve(), workspace.resolve()
    require(original_root != prepared_root and original_root not in prepared_root.parents and
            prepared_root not in original_root.parents, "disjoint source and workspace")
    manifest, modified, _ = H.selection()
    original = P.UTIL.snapshot_source(node_source, manifest["files"])
    rows = {name: modified.get(name, raw) for name, raw in original.items()}
    rows[PROBE_TARGET] = extra_source()
    workspace.mkdir(mode=0o700)
    for name, pin in build_pins().items():
        path = workspace / "node" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as stream:
            stream.write(rows[name])
        path.chmod(int(pin["mode"], 8) & 0o777)
    P.UTIL.seal(workspace / FIXTURE_FILE, selected_fixture())
    P.UTIL.seal(workspace / PREPARED_FILE, P.UTIL.encoded(expected))
    P.exact(verify(workspace, go), expected)
    return expected


def verify(workspace, go):
    workspace = Path(workspace).absolute()
    require(workspace.is_dir() and not any(path.is_symlink() for path in (workspace, *workspace.parents)), "ordinary workspace")
    expected, pins = plan(workspace, go), build_pins()
    node = workspace / "node"
    require(node.is_dir() and not node.is_symlink(), "ordinary selected node source")
    files = set()
    for path in node.rglob("*"):
        info = path.lstat()
        require(not path.is_symlink() and (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)), "ordinary source inventory")
        if stat.S_ISREG(info.st_mode):
            require(info.st_nlink == 1, "independent source files")
            files.add(path.relative_to(node).as_posix())
    require(files == set(pins), "complete source inventory")
    for name, pin in pins.items():
        path = node / name
        raw = P.read_regular(path, 16 << 20)
        require(len(raw) == pin["bytes"] and hashlib.sha256(raw).hexdigest() == pin["sha256"], "source bytes")
        require(sys.platform == "win32" or stat.S_IMODE(path.stat().st_mode) == (int(pin["mode"], 8) & 0o777), "source mode")
    require(P.read_regular(workspace / FIXTURE_FILE, 64 << 10) == selected_fixture(), "prepared fixture")
    recorded = json.loads(P.read_regular(workspace / PREPARED_FILE, 128 << 10), object_pairs_hook=P.pairs)
    P.exact(recorded, expected)
    return expected


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    fixture = commands.add_parser("fixture")
    fixture.add_argument("--seed")
    fixture.add_argument("--output")
    for name in ("plan", "prepare", "verify"):
        sub = commands.add_parser(name)
        sub.add_argument("--workspace", required=True)
        sub.add_argument("--go", default="go")
        if name == "prepare":
            sub.add_argument("--node-source", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "fixture":
            raw = selected_fixture(args.seed)
            if args.output:
                P.UTIL.seal(Path(args.output), raw)
            sys.stdout.write(raw.decode())
            return 0
        result = prepare(args.node_source, args.workspace, args.go) if args.command == "prepare" else \
            verify(args.workspace, args.go) if args.command == "verify" else plan(args.workspace, args.go)
    except (OSError, ValueError, KeyError, TypeError, OverflowError):
        print(json.dumps({"kind": "public-chain-reorg-reopen-preparation", "result": "REFUSED"}))
        return 1
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
