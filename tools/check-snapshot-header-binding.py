#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exercise a framed projection and the already built verifier on recorded inputs."""

import argparse
import base64
import copy
from email.message import Message
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import platform
import re
import subprocess
import sys
import tempfile
import urllib.response


ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "internal/testdata/conformance"
EXPORT = ROOT / "tools/ledger-export"
CHURN = ROOT / "tools/ledger-inventory/churn.py"
RANGE = ROOT / "tools/ledger-transport/archive_tail.py"
COMMAND = "inspect-experimental-snapshot-root"
EXPORT_COMMAND = "export-experimental-snapshot-header-state"
TYPED_QUERY = "query-experimental-batch-context"
PROJECTION_LIMIT = 148 << 10
UNIT_PIN = "e4bfbdb7bff55f9719782c7e609240b2ba9aeefd0d0f42b7ee1948286e890366"
NODE_PIN = "773cda402e08709ffd73adfea355f73269b1470b7336c5a027ddd5b331ab9d96"


def load_json(path, limit, digest=None):
    with path.open("rb") as stream:
        raw = stream.read(limit + 1)
    assert 0 < len(raw) <= limit
    if digest is not None:
        assert hashlib.sha256(raw).hexdigest() == digest
    return raw, json.loads(raw)


def file_pin(path, limit):
    assert path.is_file() and not path.is_symlink()
    digest, size = hashlib.sha256(), 0
    with path.open("rb") as stream:
        for part in iter(lambda: stream.read(64 << 10), b""):
            size += len(part)
            assert size <= limit
            digest.update(part)
    assert size > 0
    return {"bytes": size, "sha256": digest.hexdigest()}


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def invoke(argv, expected_exit, payload=None):
    run = subprocess.run(argv, input=payload, cwd=ROOT, capture_output=True, timeout=25)
    assert run.returncode == expected_exit and run.stderr == b"", (expected_exit, run.returncode)
    assert 0 < len(run.stdout) <= PROJECTION_LIMIT
    return run.stdout, json.loads(run.stdout)


def projection_request(builder, records, height, header_hash, root):
    receipt, options, manifest, wire = builder.projection_fixture(
        records, height=height, hash_hex=header_hash)
    command = [sys.executable, "-I", "-B", str(EXPORT / "inventory_completed_export.py"),
               *options, *builder.projection_options(root), builder.PROGRAM.RECEIPT_OPTION, json.dumps(receipt)]
    return command, manifest, wire


def project(command, payload, wire, root):
    raw, projection = invoke(command, 0, payload)
    assert projection["status"] == "SELECTED_CANDIDATE_PROJECTION_MATCHED"
    assert projection["candidate_projection"]["computed_root"] == root
    assert projection["candidate_projection"]["qualification"] == "MATH_ONLY"
    assert projection["stream_inventory"]["input_bytes"] == len(wire)
    assert projection["transport_verification"]["selection"]["sha256"] == hashlib.sha256(wire).hexdigest()
    return raw, projection


def byte_pin(raw):
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def check_typed_checkpoint(verifier, unit, trace, checkpoint, state_input, controls):
    sys.path.insert(0, str(ROOT / "tools/owned-devnet-query"))
    try:
        import query_checks
    finally:
        sys.path.pop(0)

    config, request = unit["config"], unit["request"]
    profile, pins = config["query_profile"], unit["expected"]
    root = trace["root_hex"]
    witnesses = {
        row["name"]: {"root": root, "value": base64.b64encode(bytes.fromhex(row["value_hex"])).decode("ascii"),
                      "proof": base64.b64encode(bytes.fromhex(row["proof_hex"])).decode("ascii")}
        for row in trace["rows"] if row["present"]
    }
    independently_decoded = query_checks.witness_rows(profile, request["batch_id"], root, witnesses)
    entry = independently_decoded["decoded"]["entry"]
    gateway = {
        name[0].lower() + name[1:]: base64.b64encode(value).decode("ascii") if isinstance(value, bytes) else value
        for name, value in entry.items()
    }
    gateway.update(domainId=profile["entry"]["domain_id"], batchId=request["batch_id"], isFinalized=True)
    provider = {"version": 1, "momentums": unit["momentums"], "witnesses": witnesses, "gateway": gateway}
    proof_only = {**provider, "momentums": []}
    work = checkpoint.parent
    config_path = work / "PRIVATE_TYPED_CONFIG.json"
    request_path = work / "PRIVATE_TYPED_REQUEST.json"
    provider_path = work / "PRIVATE_TYPED_PROVIDER.json"
    config_path.write_bytes(encoded(config))
    request_path.write_bytes(encoded(request))
    options = [str(verifier), TYPED_QUERY, "--config", str(config_path), "--request", str(request_path),
               "--expect-header-context", pins["header_context"], "--expect-query-context", pins["context"],
               "--compare-gateway"]
    state_args = ["--trusted-state", str(checkpoint), "--expect-state-sha256", state_input["sha256"]]
    before = checkpoint.stat()

    def query(name, bundle, extra=(), exit_code=0, error=None):
        provider_path.write_bytes(encoded(bundle))
        raw, report = invoke(options + list(extra) + [str(provider_path)], exit_code)
        assert b"PRIVATE_TYPED_" not in raw and b"PRIVATE_SNAPSHOT_" not in raw
        assert report["command"] == TYPED_QUERY and report["exit_code"] == exit_code
        assert report["scope"] == "EXPERIMENTAL_CONFIGURED_HEADER_THREE_ROW_MEMBERSHIP"
        assert report["persistence"] == "read_only" and report["rpc_requests"] == 0
        assert report["production_state_value_guarantee"] is False and "state_output" not in report
        assert report["error"] == (None if error is None else {"stage": error[0], "category": error[1]})
        if exit_code:
            assert report["result"] is None and report["gateway_comparison"] is None
        controls.append({"name": name, "exit": exit_code, "error": report["error"]})
        return report

    anchor = query("typed_anchor_checks_three_memberships", provider)
    independent = query_checks.consumer_result(anchor, config, request, provider, root)
    assert independent["gateway_stored_fields_compared"] == 17 and independent["gateway_stored_fields_match"]
    restored = query("typed_query_from_snapshot_checkpoint", proof_only, state_args)
    assert restored["status"] == "matched" and restored["headers"] is None and restored["state_input"] == state_input
    for name in ("header_context", "query_context", "gateway_comparison"):
        assert restored[name] == anchor[name]
    result = {**anchor["result"], "header_trust": anchor["result"]["header_trust"] + ["TRUST_PERSISTED_STATE"]}
    assert restored["result"] == result

    mismatch = {**proof_only, "gateway": {**gateway, "finalizeAtHeight": gateway["finalizeAtHeight"] + 1}}
    changed = query("typed_checkpoint_gateway_mismatch_preserves_membership", mismatch, state_args)
    assert changed["result"] == result and changed["state_input"] == state_input
    assert changed["gateway_comparison"] == {**restored["gateway_comparison"], "stored_fields_match": False}
    incorrect = {**witnesses["domain_config"], "root": "aa" * 32}
    query("typed_checkpoint_refuses_wrong_witness_root",
          {**proof_only, "witnesses": {**witnesses, "domain_config": incorrect}},
          state_args, 1, ("query", "invalid_witness"))
    query("typed_query_refuses_wrong_snapshot_checkpoint_digest", proof_only,
          [*state_args[:-1], "aa" * 32], 1, ("state_input", "digest_mismatch"))
    after = checkpoint.stat()
    assert (before.st_dev, before.st_ino, before.st_mode, before.st_mtime_ns) == (
        after.st_dev, after.st_ino, after.st_mode, after.st_mtime_ns)
    assert file_pin(checkpoint, PROJECTION_LIMIT) == {key: state_input[key] for key in ("bytes", "sha256")}
    return {"query_fingerprint": pins["query"], "checkpoint": state_input,
            "anchor_provider_headers": len(provider["momentums"]),
            "anchor_provider_bytes": len(encoded(provider)), "proof_only_provider_bytes": len(encoded(proof_only)),
            "membership_proofs_checked": independent["three_membership_proofs_checked"],
            "stored_gateway_fields_compared": independent["gateway_stored_fields_compared"]}


def recover_projection(command, manifest, wire, directory, controls):
    spec = importlib.util.spec_from_file_location("snapshot_range_reader", RANGE)
    downloader = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(downloader)
    description = json.loads(manifest)
    selected = description["selection"]
    chunks = description["chunks"]
    first = len(chunks) - 2
    assert first > 0 and selected["sha256"] == byte_pin(wire)["sha256"]
    offset = first * description["chunk_bytes"]
    suffix_bytes = len(wire) - offset
    span = f"{offset}-{len(wire) - 1}"
    url, etag = "https://snapshot-fixture.invalid/stream", '"recorded-fixture"'
    options = ["manifest-range", "--url", url, "--etag", etag,
               "--expect-bytes", str(len(wire)), "--expect-sha256", selected["sha256"],
               "--expect-height", str(selected["height"]), "--expect-hash", selected["hash"],
               "--provenance-sha256", selected["provenance_sha256"],
               "--manifest-bytes", str(len(manifest)), "--manifest-sha256", byte_pin(manifest)["sha256"],
               "--first-chunk", str(first), "--chunk-count", "2"]

    def recover(body):
        requests = []
        def open_response(request, timeout):
            assert request.get_method() == "GET" and request.full_url == url and timeout == 15
            assert request.get_header("Range") == f"bytes={span}"
            assert request.get_header("If-match") == etag and request.get_header("Accept-encoding") == "identity"
            requests.append(request.get_header("Range"))
            headers = Message()
            headers["Content-Range"] = f"bytes {span}/{len(wire)}"
            headers["Content-Length"] = str(suffix_bytes)
            headers["ETag"] = etag
            return urllib.response.addinfourl(io.BytesIO(body), headers, url, 206)

        raw_range, diagnostic = io.BytesIO(), io.StringIO()
        code = downloader.main(options, raw_range, diagnostic, opener=open_response, reader=io.BytesIO(manifest))
        assert requests == [f"bytes={span}"]
        return code, json.loads(diagnostic.getvalue()), raw_range.getvalue()

    code, recovered, suffix = recover(wire[offset:])
    assert code == 0 and recovered["status"] == "SELECTED_MANIFEST_RANGE_MATCHED"
    assert recovered["manifest"] == byte_pin(manifest) and recovered["selection"] == selected
    assert recovered["range"] == {**byte_pin(suffix), "first_chunk": first, "offset": offset,
                                  "chunk_count": 2, "chunks": chunks[first:]}
    assert suffix == wire[offset:] and recovered["response_body_eof_observed"]

    directory.mkdir()
    prefix_path, suffix_path = directory / "prefix.raw", directory / "suffix.raw"
    plan_path = directory / "fragment-plan.json"
    prefix_path.write_bytes(wire[:offset])
    suffix_path.write_bytes(suffix)
    plan_path.write_bytes(encoded({"format": "zenon-r1-retained-fragments/v1", "fragments": [
        {"path": str(prefix_path), "bytes": offset}, {"path": str(suffix_path), "bytes": suffix_bytes},
    ]}))
    selected_command = command + ["--transport-fragment-plan", str(plan_path)]
    raw, projection = invoke(selected_command, 0, manifest)
    assert projection["status"] == "SELECTED_CANDIDATE_PROJECTION_MATCHED"
    assert set(directory.iterdir()) == {prefix_path, suffix_path, plan_path}
    assert file_pin(prefix_path, offset) == byte_pin(wire[:offset])
    assert file_pin(suffix_path, suffix_bytes) == byte_pin(suffix)

    code, incomplete, partial = recover(wire[offset:-1])
    assert (code, incomplete["status"], incomplete["reason"]) == (2, "UNKNOWN", "stream_truncated")
    assert partial == wire[offset:-1] and len(partial) < suffix_bytes
    suffix_path.write_bytes(partial)
    _, refusal = invoke(selected_command, 2, manifest)
    assert refusal["status"] == "UNKNOWN" and refusal["reason"] == "transport_fragment_file"
    assert refusal["stream_inventory"] is None and "candidate_projection" not in refusal
    controls.append({"name": "incomplete_recovered_fragment_refuses_projection", "exit": 2,
                     "error": {"stage": "fragment_recount", "category": refusal["reason"]}})
    return raw, {"conditional_requests": 1, "retrieved_range": byte_pin(suffix),
                 "retained_prefix": byte_pin(wire[:offset]), "chunks_checked": len(chunks),
                 "joined_payload_files": 0, "controlled_https_response": True, "live_https_peer_qualified": False}


def project_replay(builder, records, before, after, root):
    _, _, _, base = builder.projection_fixture(records, height=before["height"], hash_hex=before["hash"])
    receipt, _, manifest, target = builder.projection_fixture(
        records, height=after["height"], hash_hex=after["hash"])
    _, _, _, patch = builder.projection_fixture((), height=after["height"], hash_hex=after["hash"])
    plan = {
        "format": "zenon-r1-ledger-churn-plan/v1",
        "record_space": "effective-raw-ledger",
        "provenance_sha256": receipt["selection"]["provenance_sha256"],
        "before": {**byte_pin(base), "records": len(records) + 1, "momentum": before},
        "after": {**byte_pin(target), "records": len(records) + 1, "momentum": after},
        "patch": {**byte_pin(patch), "records": 1},
    }
    plan_bytes = encoded(plan)
    raw, report = invoke([sys.executable, "-I", "-B", str(CHURN),
        "--plan-bytes", str(len(plan_bytes)), "--plan-sha256", byte_pin(plan_bytes)["sha256"],
        "--after-manifest-bytes", str(len(manifest)), "--after-manifest-sha256", byte_pin(manifest)["sha256"],
        "--projection-profile", builder.PROGRAM.PROJECTION.PROFILE, "--expect-candidate-root", root],
        0, plan_bytes + manifest + patch + base)
    assert report["status"] == "SELECTED_PATCH_REPLAY_TRANSPORT_AND_PROJECTION_MATCHED"
    assert report["selection"] == plan and report["plan"] == byte_pin(plan_bytes)
    assert report["candidate_projection"]["computed_root"] == root
    assert report["after_snapshot_bytes_read"] == report["derived_snapshot_bytes_written"] == 0
    return raw, report


def check(verifier, revision, candidate_manifest):
    source_revision = subprocess.check_output(["git", "--no-optional-locks", "rev-parse", "HEAD"],
                                              cwd=ROOT, timeout=5).decode().strip()
    assert source_revision == revision
    binary = file_pin(verifier, 128 << 20)
    manifest_pin = None
    if candidate_manifest is not None:
        raw, selected = load_json(candidate_manifest, 256 << 10)
        assert selected["source"]["revision"] == revision
        selected_binary, = [row for row in selected["binaries"] if row["command"] == "zenon-spv"]
        assert selected_binary == {"command": "zenon-spv", "filename": verifier.name, **binary}
        manifest_pin = {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}

    _, unit = load_json(DATA / "batch-context-unit.json", 16 << 10, UNIT_PIN)
    _, trace = load_json(DATA / "batch-context-node-witness.json", 16 << 10, NODE_PIN)
    assert unit["expected"]["root"] == trace["root_hex"]
    assert trace["original_trie_implementations_agree"] is True
    assert trace["source_fixture_values_are_one_original_snapshot"] is False
    records = [(bytes.fromhex(row["ledger_key_hex"]), bytes.fromhex(row["value_hex"]))
               for row in trace["rows"] if row["present"]]
    assert len(records) == 3
    config = {name: unit["config"][name] for name in
              ("version", "header_profile", "header_policy", "producer_schedule")}
    header = unit["request"]
    height, header_hash = header["height"], header["header_hash"]
    context = unit["expected"]["header_context"]
    spec = importlib.util.spec_from_file_location("snapshot_fixture_builder", EXPORT / "inventory_completed_export_test.py")
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)

    controls = []
    with tempfile.TemporaryDirectory(prefix="snapshot-header-binding-") as directory:
        work = Path(directory).resolve()
        config_path = work / "PRIVATE_SNAPSHOT_CONFIG.json"
        headers_path = work / "PRIVATE_SNAPSHOT_HEADERS.json"
        projection_path = work / "PRIVATE_SNAPSHOT_PROJECTION.json"
        config_path.write_bytes(encoded(config))
        headers_path.write_bytes(encoded(unit["momentums"]))
        options = ["--config", str(config_path), "--expect-header-context", context,
                   "--expect-height", str(height), "--expect-header-hash", header_hash]

        def native(name, flags, expected, error=None, momentum_input=headers_path):
            paths = [str(momentum_input)] if momentum_input is not None else []
            raw, report = invoke([str(verifier), COMMAND, *flags, *paths], expected)
            assert b"PRIVATE_SNAPSHOT_" not in raw
            assert report["command"] == COMMAND and report["exit_code"] == expected
            assert report["scope"] == "EXPERIMENTAL_CONFIGURED_HEADER_ROOT"
            for field in ("production_state_value_guarantee", "excluded_state_authenticated",
                          "projection_computation_rechecked", "report_provenance_authenticated"):
                assert report[field] is False
            if error is not None:
                assert report["error"] == {"stage": error[0], "category": error[1]}
                assert report["header"] is None and report["projection_comparison"] is None
            else:
                assert report["error"] is None
                if momentum_input is None:
                    assert report["header_checks"] is None
                else:
                    assert report["header_checks"]["outcome"] == "ACCEPT"
            controls.append({"name": name, "exit": expected, "error": report["error"]})
            return report

        def export_state(name, flags, momentum_input, expected=0, error=None):
            paths = [str(momentum_input)] if momentum_input is not None else []
            run = subprocess.run([str(verifier), EXPORT_COMMAND, *flags, *paths],
                                 cwd=ROOT, capture_output=True, timeout=25)
            assert run.returncode == expected and 0 < len(run.stderr) <= PROJECTION_LIMIT
            assert b"PRIVATE_SNAPSHOT_" not in run.stdout + run.stderr
            report = json.loads(run.stderr)
            assert report["command"] == EXPORT_COMMAND and report["exit_code"] == expected
            assert report["scope"] == "EXPERIMENTAL_CONFIGURED_HEADER_ROOT"
            assert not report["production_state_value_guarantee"]
            if expected == 0:
                assert report["error"] is None and 0 < len(run.stdout) <= PROJECTION_LIMIT
                assert report["state_output"] == {
                    "sha256": hashlib.sha256(run.stdout).hexdigest(), "bytes": len(run.stdout),
                    "complete": True, "trust": "trusted_local_provenance_required",
                    "provenance_label_removed": True,
                }
            else:
                assert report["error"] == {"stage": error[0], "category": error[1]}
                assert run.stdout == b"" and "state_output" not in report
            controls.append({"name": name, "exit": expected, "error": report["error"]})
            return run.stdout, report

        def checkpoint_flags(path, raw):
            return ["--trusted-state", str(path), "--expect-state-sha256", hashlib.sha256(raw).hexdigest()]

        def replace_flag(flag, value):
            result = list(options)
            result[result.index(flag) + 1] = str(value)
            return result

        def projection_flags(raw, selected_digest=None):
            projection_path.write_bytes(raw)
            digest = hashlib.sha256(raw).hexdigest() if selected_digest is None else selected_digest
            return options + ["--projection-report", str(projection_path), "--expect-projection-sha256", digest]

        selected = native("owned_root", options, 0)
        assert selected["status"] == "selected" and selected["projection_comparison"] is None
        assert selected["header"] == {"height": height, "hash": header_hash, "state_root": trace["root_hex"],
                                      "tip_height": header["tip_height"], "tip_hash": header["tip_hash"]}
        assert selected["header_context"]["fingerprint"] == context
        root = selected["header"]["state_root"]
        command, manifest, wire = projection_request(builder, records, height, header_hash, root)
        raw, projection = project(command, manifest + wire, wire, root)
        recovered_raw, recovery = recover_projection(command, manifest, wire, work / "fragments", controls)
        assert recovered_raw == raw
        matched = native("same_frontier_projection", projection_flags(raw), 0)
        assert matched["status"] == "matched" and matched["header"] == selected["header"]
        assert native("recovered_fragments_match_accepted_header", projection_flags(recovered_raw), 0) == matched
        comparison = matched["projection_comparison"]
        transport = projection["transport_verification"]
        stream = transport["selection"]
        assert comparison == {"report_sha256": hashlib.sha256(raw).hexdigest(),
            "profile": projection["candidate_projection"]["profile"], "manifest": transport["manifest"],
            "stream": {"bytes": stream["bytes"], "sha256": stream["sha256"]},
            "provenance_sha256": stream["provenance_sha256"],
            "producer_receipt_sha256": projection["producer_completion"]["producer_receipt_sha256"]}

        checkpoint, emitted = export_state("export_matched_state", projection_flags(recovered_raw), headers_path)
        checkpoint_path = work / "PRIVATE_SNAPSHOT_STATE.json"
        checkpoint_path.write_bytes(checkpoint)
        checkpoint_before = checkpoint_path.stat()
        checkpoint_args = checkpoint_flags(checkpoint_path, checkpoint)
        assert emitted["projection_comparison"] == comparison and emitted["header"] == matched["header"]
        assert "state_input" not in emitted and "state_output" not in matched and "state_input" not in matched
        restored = native("checkpoint_without_provider_headers", projection_flags(raw) + checkpoint_args,
                          0, momentum_input=None)
        assert restored["header"] == matched["header"] and restored["projection_comparison"] == comparison
        assert restored["state_input"] == {
            "sha256": hashlib.sha256(checkpoint).hexdigest(), "bytes": len(checkpoint),
            "provider_headers": 0, "trust": "trusted_local_provenance_required",
        }
        assert native("recovered_fragments_match_checkpoint", projection_flags(recovered_raw) + checkpoint_args,
                      0, momentum_input=None) == restored
        typed_handoff = check_typed_checkpoint(verifier, unit, trace, checkpoint_path,
                                               restored["state_input"], controls)
        exported_again, _ = export_state("reexport_same_checkpoint", projection_flags(raw) + checkpoint_args, None)
        assert exported_again == checkpoint

        other = unit["momentums"][-3]
        earlier = replace_flag("--expect-height", other["height"])
        earlier[earlier.index("--expect-header-hash") + 1] = other["hash"]
        successor_path = work / "PRIVATE_SNAPSHOT_SUCCESSORS.json"
        successor_path.write_bytes(encoded(unit["momentums"][:-1]))
        earlier_bytes, _ = export_state("export_earlier_tip", earlier, successor_path)
        earlier_path = work / "PRIVATE_SNAPSHOT_EARLIER.json"
        earlier_path.write_bytes(earlier_bytes)
        earlier_args = checkpoint_flags(earlier_path, earlier_bytes)
        successor_path.write_bytes(encoded(unit["momentums"][-1:]))
        resumed = native("checkpoint_and_successor", projection_flags(raw) + earlier_args, 0,
                         momentum_input=successor_path)
        assert resumed["header"] == matched["header"] and resumed["projection_comparison"] == comparison
        assert resumed["state_input"]["provider_headers"] == 1
        native("checkpoint_and_repeated_tip", options + checkpoint_args, 1, ("headers", "not_accepted"),
               momentum_input=successor_path)
        native("checkpoint_unpaired_path", options + checkpoint_args[:2], 64, ("arguments", "usage"),
               momentum_input=None)
        native("checkpoint_unpaired_digest", options + checkpoint_args[2:], 64, ("arguments", "usage"),
               momentum_input=None)
        native("missing_headers_and_checkpoint", options, 64, ("arguments", "usage"), momentum_input=None)
        native("checkpoint_wrong_digest", options + checkpoint_args[:3] + ["aa" * 32], 1,
               ("state_input", "digest_mismatch"), momentum_input=None)
        native("checkpoint_wrong_context", replace_flag("--expect-header-context", "aa" * 32) + checkpoint_args,
               70, ("configuration_pin", "mismatch"), momentum_input=None)
        invalid_state = checkpoint + b"{}"
        earlier_path.write_bytes(invalid_state)
        native("checkpoint_invalid_bytes", options + checkpoint_flags(earlier_path, invalid_state), 70,
               ("state_input", "invalid_checkpoint"), momentum_input=None)
        checkpoint_after = checkpoint_path.stat()
        assert checkpoint_path.read_bytes() == checkpoint
        assert (checkpoint_before.st_mode, checkpoint_before.st_ino, checkpoint_before.st_mtime_ns) == (
            checkpoint_after.st_mode, checkpoint_after.st_ino, checkpoint_after.st_mtime_ns)

        other_command, other_manifest, other_wire = projection_request(
            builder, records, other["height"], other["hash"], root)
        other_raw, _ = project(other_command, other_manifest + other_wire, other_wire, root)
        export_state("no_checkpoint_on_projection_refusal", projection_flags(other_raw) + checkpoint_args,
                     None, 1, ("projection", "frontier_mismatch"))
        native("same_root_other_frontier", projection_flags(other_raw), 1, ("projection", "frontier_mismatch"))
        native("wrong_report_digest", projection_flags(raw, "aa" * 32), 1, ("projection", "digest_mismatch"))
        native("unpaired_report_path", options + ["--projection-report", str(projection_path)], 64,
               ("arguments", "usage"))
        native("repeated_height", options + ["--expect-height", str(height)], 64, ("arguments", "usage"))
        native("wrong_header_context", replace_flag("--expect-header-context", "aa" * 32), 70,
               ("configuration_pin", "mismatch"))
        native("wrong_selected_hash", replace_flag("--expect-header-hash", "aa" * 32), 1,
               ("selection", "header_hash_mismatch"))
        tip = replace_flag("--expect-height", header["tip_height"])
        tip[tip.index("--expect-header-hash") + 1] = header["tip_hash"]
        native("insufficient_depth", tip, 2, ("selection", "insufficient_depth"))
        native("checkpoint_preserves_depth", tip + checkpoint_args, 2, ("selection", "insufficient_depth"),
               momentum_input=None)
        native("unavailable_height", replace_flag("--expect-height", 1), 2, ("selection", "header_unavailable"))

        changed = copy.deepcopy(projection)
        changed["candidate_projection"]["expected_root"] = "aa" * 32
        changed["candidate_projection"]["computed_root"] = "aa" * 32
        native("different_projected_root", projection_flags(encoded(changed)), 1, ("projection", "root_mismatch"))
        for name, section, field, value in (
                ("wrong_projection_profile", "candidate_projection", "profile", "other/v1"),
                ("supplied_header_authority", "candidate_projection", "accepted_header_binding", True),
                ("incomplete_transport", "transport_verification", "stream_eof_observed", False),
                ("different_recount_bytes", "stream_inventory", "input_bytes", 1)):
            changed = copy.deepcopy(projection)
            changed[section][field] = value
            native(name, projection_flags(encoded(changed)), 70, ("projection", "invalid_report"))
        duplicate = b'{"format":"duplicate",' + raw[1:]
        native("duplicate_report_field", projection_flags(duplicate), 70, ("projection", "invalid_report"))
        native("oversized_report", projection_flags(raw.ljust(PROJECTION_LIMIT + 1, b" ")), 70,
               ("projection", "invalid_input"))

        base = {"height": other["height"], "hash": other["hash"]}
        target = {"height": height, "hash": header_hash}
        replay_raw, replay = project_replay(builder, records, base, target, trace["root_hex"])
        replay_comparison = {
            "report_sha256": byte_pin(replay_raw)["sha256"],
            "profile": replay["candidate_projection"]["profile"],
            "manifest": replay["after_transport"]["manifest"],
            "stream": {key: replay["selection"]["after"][key] for key in ("bytes", "sha256")},
            "provenance_sha256": replay["selection"]["provenance_sha256"],
            "replay": {"plan": replay["plan"], "base_height": base["height"], "base_hash": base["hash"],
                       "base": {key: replay["selection"]["before"][key] for key in ("bytes", "sha256")},
                       "patch": {key: replay["selection"]["patch"][key] for key in ("bytes", "sha256")}},
        }
        replay_matched = native("manifest_replay_matches_accepted_header", projection_flags(replay_raw), 0)
        assert replay_matched["header"] == matched["header"]
        assert replay_matched["projection_comparison"] == replay_comparison
        replay_restored = native("manifest_replay_matches_checkpoint", projection_flags(replay_raw) + checkpoint_args,
                                 0, momentum_input=None)
        assert replay_restored["header"] == matched["header"]
        assert replay_restored["projection_comparison"] == replay_comparison
        bad_root = copy.deepcopy(replay)
        bad_root["candidate_projection"].update(expected_root="aa" * 32, computed_root="aa" * 32)
        native("replay_different_root", projection_flags(encoded(bad_root)), 1, ("projection", "root_mismatch"))
        other_base = {"height": other["height"] - 1, "hash": other["previousHash"]}
        other_replayed, _ = project_replay(builder, records, other_base, base, trace["root_hex"])
        native("replay_same_root_other_frontier", projection_flags(other_replayed), 1,
               ("projection", "frontier_mismatch"))
        for name, section, field, value in (
                ("replay_plan_digest", "plan", "sha256", "aa" * 32),
                ("replay_emission_incomplete", "after_transport", "emitted_stream_completed", False),
                ("replay_wrong_raw_digest", "after_transport", "selection",
                 {**replay["after_transport"]["selection"], "sha256": "aa" * 32}),
                ("replay_wrong_byte_accounting", "after_totals", "put_wire_bytes", 1),
                ("replay_claimed_parent_authentication", "scope", "momentum_parent_link_authenticated", True),
                ("replay_claimed_projection_authority", "candidate_projection", "accepted_header_binding", True)):
            changed = copy.deepcopy(replay)
            changed[section][field] = value
            native(name, projection_flags(encoded(changed)), 70, ("projection", "invalid_report"))
        changed = copy.deepcopy(replay)
        del changed["after_transport"]
        changed.update(format="zenon-r1-ledger-churn-projection/v1",
                       status="SELECTED_PATCH_REPLAY_AND_CANDIDATE_PROJECTION_MATCHED")
        native("replay_without_manifest", projection_flags(encoded(changed)), 70, ("projection", "invalid_report"))

        changed_headers = copy.deepcopy(unit["momentums"])
        changed_headers[-2]["stateRoot"] = "aa" * 32
        headers_path.write_bytes(encoded(changed_headers))
        native("tampered_signed_root", projection_flags(raw), 70, ("headers", "invalid_encoding"))
        changed_headers = copy.deepcopy(unit["momentums"])
        signature = bytearray(base64.b64decode(changed_headers[-2]["signature"], validate=True))
        signature[0] ^= 1
        changed_headers[-2]["signature"] = base64.b64encode(signature).decode("ascii")
        headers_path.write_bytes(encoded(changed_headers))
        native("invalid_signature", projection_flags(raw), 1, ("headers", "not_accepted"))

    assert file_pin(verifier, 128 << 20) == binary
    return {"format": "zenon-snapshot-header-binding-controls/v1", "status": "PASS", "source_revision": revision,
            "platform": platform.system().lower(), "machine": platform.machine().lower(),
            "verifier": binary, "candidate_manifest": manifest_pin,
            "fixture_pins": {"batch-context-unit.json": UNIT_PIN, "batch-context-node-witness.json": NODE_PIN},
            "scope": "recorded_headers_and_generated_ledger", "controls": controls,
            "matched": matched["header"], "projection": comparison, "fragment_recovery": recovery,
            "typed_checkpoint_handoff": typed_handoff,
            "inputs_share_original_snapshot": False, "node_or_network_started": False,
            "snapshot_import_performed": False, "production_qualified": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--verifier", type=Path, required=True)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--candidate-manifest", type=Path)
    args = parser.parse_args()
    assert re.fullmatch("[0-9a-f]{40}", args.source_revision)
    print(encoded(check(args.verifier.resolve(), args.source_revision, args.candidate_manifest)).decode(), end="")
