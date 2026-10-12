#!/usr/bin/env python3
"""Check preserved node static results with independent bytes and OpenSSL.

This qualifies finite synthetic observations, never an accepting network or
state-value profile. The node is not executed by this offline checker.
"""

import base64
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
import tempfile

HERE = Path(__file__).resolve().parent
FIXTURES = HERE.parents[1] / "internal/testdata/conformance"
NODE = {"repository": "https://github.com/zenon-network/go-zenon",
        "commit": "c64ed6279ff1d07335dab0ac36156dec8b5b71e9",
        "module_version": "v0.0.8-alphanet.0.20261009223306-c64ed6279ff1",
        "module_sum": "h1:3Vyk+6hw2dcWJLg15JEq7ITFOkaYvrVyI+W8Qb3Jlr4=",
        "function": "verifier.MomentumStatic"}
INPUTS = {"momentum-v1-v2.json": "91747c6b7adba4e256fcb397d64348117edc9df874df7f25e2c56b776426dec9",
          "historical-testnet-genesis.json": "c43c63adecc5e0ccbca5a0be40070ac911d71b7466f998801c84aebc23d7f89b"}
CORPUS_SHA256 = "1873c677ea64936cea90262dbe70a5a76e497a8c6d7736394dd4eaee7da766c3"
SCOPE = {"actual_node_static_execution": True, "new_signatures_generated": False,
         "full_node_validation": False, "network_transport": False, "network_activation": False,
         "producer_authorization": False, "canonicality": False, "consensus_finality": False,
         "state_value_acceptance": False}
MUTATIONS = ("hash", "data", "chain", "height", "previous", "signature-empty", "public-key-empty",
             "both-empty", "public-key-short", "public-key-long", "signature-short", "signature-long",
             "signature-bit", "public-key-bit", "prices", "hash-and-empty")


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


bytes_oracle = load("static_bytes_oracle", HERE.parent / "gen-node-momentum-vectors/check.py")
signatures = load("static_signature_backend", HERE.parent / "gen-node-momentum-vectors/check-signatures.py")


def need(condition, stage):
    if not condition:
        raise signatures.Refused(stage)


def exact(a, b):
    # Python's ordinary equality aliases 0/False and 1/True/1.0.
    return json.dumps(a, sort_keys=True, separators=(",", ":")) == json.dumps(b, sort_keys=True, separators=(",", ":"))


def read_selected(path, digest):
    with signatures.regular_file(path, 256 << 10, "static_corpus_file") as (stream, before):
        raw = stream.read((256 << 10) + 1)
        after = os.fstat(stream.fileno())
        need(len(raw) <= 256 << 10 and (before.st_size, before.st_mtime_ns) ==
             (after.st_size, after.st_mtime_ns), "static_corpus_changed_or_bound")
    need(hashlib.sha256(raw).hexdigest() == digest, "static_input_pin")
    # The inherited signature parser pins its own historical node source.
    # Keep it unchanged; this corpus has a separate source checked by validate.
    return json.loads(raw.decode("utf-8"), object_pairs_hook=signatures.json_pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(signatures.Refused("static_corpus_json")))


def expected_cases():
    corpus = read_selected(FIXTURES / "momentum-v1-v2.json", INPUTS["momentum-v1-v2.json"])
    genesis = read_selected(FIXTURES / "historical-testnet-genesis.json", INPUTS["historical-testnet-genesis.json"])
    originals = bytes_oracle.check_corpus(corpus)
    cases = [("baseline/" + v["name"], v["name"], v["momentum"], "") for v in originals]
    cases.append(("nil", "", None, "missing_momentum"))
    cases.append(("historical-unsigned-genesis", genesis["vector"]["name"], genesis["vector"]["momentum"], "signature_missing"))
    baselines = {v["name"]: v["momentum"] for v in originals}
    for selected in ("v1-empty", "v2-nonzero-prices"):
        for mutation in MUTATIONS:
            wire = copy.deepcopy(baselines[selected])
            error = "hash_mismatch"
            if mutation in ("hash", "hash-and-empty", "previous"):
                field = "previousHash" if mutation == "previous" else "hash"
                raw = bytearray(bytes.fromhex(wire[field])); raw[0] ^= 1
                wire[field] = raw.hex()
                if mutation == "hash-and-empty": wire["publicKey"] = wire["signature"] = ""
            elif mutation == "data":
                wire["data"] = base64.b64encode(bytes_oracle.base64_bytes(wire["data"]) + b"\xff").decode()
            elif mutation == "chain": wire["chainIdentifier"] ^= 1
            elif mutation == "height": wire["height"] += 1
            elif mutation == "prices":
                wire["nextFusionPrice"] += 1; wire["nextWorkPrice"] += 1
                if wire["version"] == 1: error = ""
            elif mutation in ("signature-empty", "public-key-empty", "both-empty"):
                if mutation != "signature-empty": wire["publicKey"] = ""
                if mutation != "public-key-empty": wire["signature"] = ""
                error = "public_key_missing" if mutation == "public-key-empty" else "signature_missing"
            else:
                field = "publicKey" if mutation.startswith("public-key") else "signature"
                raw = bytearray(bytes_oracle.base64_bytes(wire[field]))
                if mutation.endswith("short"): raw = raw[:-1]
                elif mutation.endswith("long"): raw.append(0)
                else: raw[0] ^= 1
                wire[field] = base64.b64encode(raw).decode()
                error = "internal_signature_format" if field == "publicKey" and not mutation.endswith("bit") else "signature_invalid"
            cases.append((selected + "/" + mutation, selected, wire, error))
    need(len(cases) == 55 and len({c[0] for c in cases}) == 55, "static_selection_inventory")
    return cases


def projection(wire):
    rows = [bytes_oracle.address_bytes(r["address"]) + bytes_oracle.uint64(r["height"]) + bytes_oracle.hash_bytes(r["hash"])
            for r in wire["content"]]
    data = b"" if wire["data"] is None else bytes_oracle.base64_bytes(wire["data"])
    header = {k: wire[k] for k in ("version", "chainIdentifier", "hash", "previousHash", "height", "timestamp",
                                 "changesHash", "publicKey", "signature", "nextFusionPrice", "nextWorkPrice")}
    header.update(dataHash=bytes_oracle.digest(data).hex(), contentHash=bytes_oracle.digest(b"".join(rows)).hex())
    preimage = signatures.projected_preimage(header)
    return header, bytes_oracle.digest(preimage)


def validate(data):
    need(type(data) is dict and set(data) == {"format_version", "source", "input_files_sha256", "observations", "scope"}, "static_corpus_shape")
    need(type(data["format_version"]) is int and data["format_version"] == 1, "static_format")
    need(exact(data["source"], NODE) and exact(data["input_files_sha256"], INPUTS), "static_source")
    need(exact(data["scope"], SCOPE), "static_scope")
    cases = expected_cases()
    need(type(data["observations"]) is list and len(data["observations"]) == len(cases), "static_inventory")
    jobs = []
    for row, (name, baseline, wire, error) in zip(data["observations"], cases):
        need(type(row) is dict and set(row) == {"name", "baseline", "momentum", "header", "computed_hash", "node_static_result", "node_error"}, "static_row_shape")
        need(exact(row["name"], name) and exact(row["baseline"], baseline) and exact(row["momentum"], wire), "static_selected_input")
        need(exact(row["node_error"], error) and row["node_static_result"] == ("REJECT" if error else "MATCH"), "static_node_outcome")
        if wire is None:
            need(row["header"] is None and row["computed_hash"] is None, "static_nil_projection")
            continue
        header, computed = projection(wire)
        need(exact(row["header"], header) and row["computed_hash"] == computed.hex(), "static_byte_projection")
        need((computed.hex() != wire["hash"]) == (error == "hash_mismatch"), "static_hash_precedence")
        if computed.hex() == wire["hash"]:
            key = b"" if wire["publicKey"] is None else bytes_oracle.base64_bytes(wire["publicKey"])
            signature = b"" if wire["signature"] is None else bytes_oracle.base64_bytes(wire["signature"])
            if len(key) == 32 and len(signature) == 64:
                jobs.append((name, key, computed, signature, not error))
    need(len(jobs) == 26 and sum(j[-1] for j in jobs) == 22, "static_signature_inventory")
    return jobs


def run(path, selected, revision):
    need(revision is None or re.fullmatch("[0-9a-f]{40}", revision) is not None, "source_revision")
    data = read_selected(path, CORPUS_SHA256)
    jobs = validate(data)  # Complete source/selection/byte preflight before OpenSSL.
    outcomes = []
    try:
        with tempfile.TemporaryDirectory(prefix="node-static-signatures-") as temporary:
            backend = signatures.Backend(selected, Path(temporary))
            for name, key, message, signature, expected in jobs:
                actual, details = backend.verify(key, message, signature)
                details.update(name=name, expected=expected, actual=actual)
                outcomes.append(details)
                need(actual == expected, "static_signature_outcome")
            identity = backend.identity()
    except signatures.Refused as failure:
        if failure.details is not None:
            outcomes.append(failure.details)
        failure.outcomes = outcomes
        raise
    return {"schema_version": 1, "status": "verified", "source_revision": revision,
            "source_revision_is_caller_asserted": True, "node_source": NODE, "corpus_sha256": CORPUS_SHA256,
            "input_files_sha256": INPUTS, "node_static_observations": 55, "node_static_matches": 22,
            "node_static_rejections": 33, "independent_byte_projections": 54,
            "independent_signature_processes": 26, "independent_signature_matches": 22,
            "independent_signature_rejections": 4, "backend": identity, "outcomes": outcomes,
            "new_node_execution": False, "new_signatures_generated": False,
            "network_or_production_qualified": False, "production_state_value_accepted": False}


def main(argv=None):
    try:
        parser = signatures.QuietParser(description=__doc__, allow_abbrev=False)
        parser.add_argument("--openssl", required=True)
        parser.add_argument("--corpus", type=Path, default=FIXTURES / "node-static-v1-v2.json")
        parser.add_argument("--source-revision")
        args = parser.parse_args(argv)
        report = run(args.corpus, args.openssl, args.source_revision)
    except signatures.Refused as failure:
        return signatures.emit_report({"schema_version": 1, "status": "refused", "error_stage": failure.stage,
                                       "outcomes": failure.outcomes, "network_or_production_qualified": False}, 2)
    except (OSError, ValueError, KeyError, TypeError, RecursionError, OverflowError):
        return signatures.emit_report({"schema_version": 1, "status": "refused", "error_stage": "static_corpus_or_backend_input",
                                       "network_or_production_qualified": False}, 2)
    return signatures.emit_report(report, 0, pretty=True)


if __name__ == "__main__":
    code = main()
    if code == 70:
        signatures.discard_failed_output_at_shutdown()
    sys.exit(code)
