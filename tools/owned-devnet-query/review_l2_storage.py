# SPDX-License-Identifier: GPL-3.0-only
"""Check one historical L2 storage path under a retained owned BatchEntry."""
from __future__ import annotations

import argparse
import hashlib
import re
import struct
import sys
import zipfile
import zlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import capture
import inputs
import model
import review
from artifacts import api_json
from model import Refused, canonical, exact_keys, require, same
from query_checks import H, hex_bytes, membership, proof_sibling_count, sparse_proof_root, uint

MAX_KEY_BYTES = 32
MAX_VALUE_BYTES = 4096
MAX_SIBLINGS = 256
MAX_PROOF_BYTES = 103 + 32 * MAX_SIBLINGS + MAX_VALUE_BYTES
MAX_RESULT_BYTES = 64 << 10
EMPTY_ROOT = bytes(32)


def bounded_hex(text, maximum):
    require(type(text) is str and len(text) <= 2 * maximum and len(text) % 2 == 0
            and re.fullmatch(r"[0-9a-f]*", text) is not None, "l2_storage_hex")
    return bytes.fromhex(text)


def storage_path(contract_id, local_key):
    require(type(contract_id) is bytes and len(contract_id) == 32
            and type(local_key) is bytes and len(local_key) <= MAX_KEY_BYTES, "l2_storage_key")
    return H(contract_id + local_key)


def check_storage_proof(root, path, present, value, proof):
    require(type(root) is bytes and len(root) == 32 and type(path) is bytes and len(path) == 32
            and type(present) is bool and type(proof) is bytes and len(proof) <= MAX_PROOF_BYTES,
            "l2_storage_proof_bounds")
    if present:
        return membership(root, path, proof, value, MAX_PROOF_BYTES, MAX_VALUE_BYTES, MAX_SIBLINGS)
    require(value is None and len(proof) >= 99 and proof[0] == 0
            and proof[1:33] == path and proof[33:65] == EMPTY_ROOT, "l2_storage_absence")
    count = proof_sibling_count(proof, MAX_SIBLINGS, "l2_storage_absence_siblings")
    require(len(proof) == 99 + 32 * count, "l2_storage_absence_length")
    require(sparse_proof_root(path, proof, "l2_storage_noncanonical_sibling") == root, "l2_storage_absence_root")
    return count


def gateway_witness(result, domain_id, batch_id, root, path):
    exact_keys(result, {"domainId", "batchId", "verified", "postStateRoot", "proofs"}, "l2_gateway_result")
    require(uint(result["domainId"], 32) == domain_id and uint(result["batchId"]) == batch_id,
            "l2_gateway_batch")
    require(hex_bytes(result["postStateRoot"], 32) == root, "l2_gateway_root")
    # This bit describes the gateway's view. The selected L1 BatchEntry supplies
    # the root authority for this operation.
    require(type(result["verified"]) is bool, "l2_gateway_result")
    proofs = result["proofs"]
    require(type(proofs) is list and len(proofs) == 1, "l2_gateway_proof_count")
    row = proofs[0]
    exact_keys(row, {"path", "present", "value", "proof"}, "l2_gateway_proof")
    require(hex_bytes(row["path"], 32) == path, "l2_gateway_path")
    require(type(row["present"]) is bool, "l2_gateway_proof")
    value = None if row["value"] is None else bounded_hex(row["value"], MAX_VALUE_BYTES)
    return row["present"], value, bounded_hex(row["proof"], MAX_PROOF_BYTES)


def read_storage(domain_id, batch_id, root, contract_id, local_key, *, proof_result=None, empty_root=False):
    path = storage_path(contract_id, local_key)
    if empty_root:
        require(proof_result is None and root == EMPTY_ROOT, "l2_empty_commitment_required")
        present, value = False, None
        proof = b"\0" + path + bytes(66)
        origin = "local_empty_commitment"
    else:
        require(proof_result is not None, "l2_witness_unavailable")
        present, value, proof = gateway_witness(proof_result, domain_id, batch_id, root, path)
        origin = "gateway_witness"
    siblings = check_storage_proof(root, path, present, value, proof)
    return {"domain_id": domain_id, "batch_id": batch_id, "post_state_root": root.hex(),
            "contract_id": contract_id.hex(), "local_key_hex": local_key.hex(), "path": path.hex(),
            "present": present, "value_hex": None if value is None else value.hex(),
            "proof_origin": origin, "proof_bytes": len(proof), "siblings": siblings,
            "proof_sha256": hashlib.sha256(proof).hexdigest()}


def recorded_batch(stream, selection, contract, checkout, expected_height, expected_hash, expected_context):
    archive = {key: selection["artifact"][key] for key in ("bytes", "sha256")}
    retained = review.review_stream(stream, archive, selection["source_revision"], selection["run_id"], contract, checkout)
    comparison = retained["comparison"]
    require(comparison is not None and retained["recorded_terminal_outcome"] == "DEVNET_CONSUMER_ACCEPTED",
            "l2_retained_batch_unqualified")
    request = comparison["request"]
    require(request["height"] == expected_height and request["header_hash"] == expected_hash
            and request["context"] == expected_context, "l2_l1_selection")
    # The reader bound this member to the original successful command and
    # independently compared its decoded ABI fields with the three proven rows.
    with zipfile.ZipFile(stream) as pack:
        member = pack.getinfo("evidence/" + capture.CONSUMER_STDOUT)
        require(0 < member.file_size <= 256 << 10, "l2_retained_consumer_size")
        raw = pack.read(member)
    decoded = api_json(raw, 256 << 10)["result"]
    same(decoded["request"], request, "l2_l1_selection")
    same(decoded["root"], comparison["root"], "l2_l1_selection")
    require(uint(decoded["entry"]["ProtocolVersion"], 16) == 1
            and uint(decoded["domain_record"]["RuntimeKind"], 8) == 0
            and uint(decoded["domain_record"]["ExecProfile"], 8) == 0, "l2_storage_profile")
    return request, comparison["root"], hex_bytes(decoded["entry"]["PostStateRoot"], 32)


def main(argv=None, stdout=None, stderr=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    for name in ("archive", "run-metadata", "jobs-metadata", "artifact-metadata"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("source-revision", "contract-sha256", "header-hash", "query-context"):
        parser.add_argument("--expect-" + name, required=True)
    for name in ("run-id", "artifact-id", "height"):
        parser.add_argument("--expect-" + name, type=int, required=True)
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--contract-id", required=True)
    parser.add_argument("--local-key-hex", required=True)
    witness = parser.add_mutually_exclusive_group(required=True)
    witness.add_argument("--proof-result", type=Path, help="Recorded zeno_getProof result object for one path.")
    witness.add_argument("--empty-root", action="store_true", help="Derive a proof for a proven zero post-state root.")
    args = parser.parse_args(argv)
    stdout = sys.stdout.buffer if stdout is None else stdout
    stderr = sys.stderr if stderr is None else stderr

    try:
        height = uint(args.expect_height)
        require(height >= 3, "l2_l1_selection")
        header = model.digest(args.expect_header_hash)
        context = model.digest(args.expect_query_context)
        contract_id = hex_bytes(args.contract_id, 32)
        local_key = bounded_hex(args.local_key_hex, MAX_KEY_BYTES)
        contract = model.read_contract(args.contract)
        same(contract.sha256, model.digest(args.expect_contract_sha256), "l2_contract_pin")
        metadata = {name: review.read_hosted_metadata(getattr(args, name + "_metadata"))
                    for name in ("run", "jobs", "artifact")}
        selected = review.select_hosted_result(
            api_json(metadata["run"]), api_json(metadata["jobs"]), api_json(metadata["artifact"]),
            args.expect_source_revision, args.expect_run_id, args.expect_artifact_id, contract.sha256)
        require(all(selected[key] == "success" for key in ("run_conclusion", "experiment_conclusion",
                                                           "execution_conclusion")), "l2_hosted_batch_unqualified")
        request, l1_root, root = inputs._read_archive_file(args.archive, selected["artifact"]["bytes"],
            lambda stream: recorded_batch(stream, selected, contract, HERE.parents[1], height, header, context))
        profile = contract.data["selection"]
        same(request["batch_id"], int(profile["batch_id_decimal"]), "l2_l1_selection")
        proof_result = None if args.empty_root else api_json(review.read_hosted_metadata(args.proof_result), MAX_RESULT_BYTES)
        storage = read_storage(profile["domain_id"], request["batch_id"], root, contract_id, local_key,
                               proof_result=proof_result, empty_root=args.empty_root)
        report = {"format": "owned-devnet-recorded-l2-storage/v1",
                  "scope": "RECORDED_EXECUTOR_BATCH_COMMITMENT",
                  "l1_request": request, "l1_state_root": l1_root, "storage": storage,
                  "source_revision": selected["source_revision"], "contract_sha256": contract.sha256,
                  "run_id": selected["run_id"], "attempt": selected["run_attempt"], "archive": selected["artifact"],
                  "metadata_pins": {name: {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
                                    for name, data in metadata.items()},
                  "rpc_requests": 0, "new_devnet_acceptance_established": False,
                  "state_transition_verified": False, "production_qualified": False}
        raw = canonical(report)
        require(stdout.write(raw) == len(raw), "l2_short_output")
        stdout.flush()
        return 0
    except Refused as error:
        stderr.write("L2 storage review refused (" + error.reason + ").\n")
    except (OSError, ValueError, TypeError, KeyError, IndexError, AttributeError,
            EOFError, RuntimeError, struct.error, zipfile.BadZipFile, zlib.error):
        stderr.write("L2 storage review could not complete.\n")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
