#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exercise a framed projection and the already built verifier on recorded inputs."""

import argparse
import base64
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import platform
import re
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "internal/testdata/conformance"
EXPORT = ROOT / "tools/ledger-export"
COMMAND = "inspect-experimental-snapshot-root"
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


def project(builder, records, height, header_hash, root):
    receipt, options, manifest, wire = builder.projection_fixture(
        records, height=height, hash_hex=header_hash)
    raw, projection = invoke([sys.executable, "-I", "-B", str(EXPORT / "inventory_completed_export.py"),
        *options, *builder.projection_options(root), builder.PROGRAM.RECEIPT_OPTION, json.dumps(receipt)],
        0, manifest + wire)
    assert projection["status"] == "SELECTED_CANDIDATE_PROJECTION_MATCHED"
    assert projection["candidate_projection"]["computed_root"] == root
    assert projection["candidate_projection"]["qualification"] == "MATH_ONLY"
    assert projection["stream_inventory"]["input_bytes"] == len(wire)
    assert projection["transport_verification"]["selection"]["sha256"] == hashlib.sha256(wire).hexdigest()
    return raw, projection


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
        work = Path(directory)
        config_path = work / "PRIVATE_SNAPSHOT_CONFIG.json"
        headers_path = work / "PRIVATE_SNAPSHOT_HEADERS.json"
        projection_path = work / "PRIVATE_SNAPSHOT_PROJECTION.json"
        config_path.write_bytes(encoded(config))
        headers_path.write_bytes(encoded(unit["momentums"]))
        options = ["--config", str(config_path), "--expect-header-context", context,
                   "--expect-height", str(height), "--expect-header-hash", header_hash]

        def native(name, flags, expected, error=None):
            raw, report = invoke([str(verifier), COMMAND, *flags, str(headers_path)], expected)
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
                assert report["error"] is None and report["header_checks"]["outcome"] == "ACCEPT"
            controls.append({"name": name, "exit": expected, "error": report["error"]})
            return report

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
        raw, projection = project(builder, records, height, header_hash, selected["header"]["state_root"])
        matched = native("same_frontier_projection", projection_flags(raw), 0)
        assert matched["status"] == "matched" and matched["header"] == selected["header"]
        comparison = matched["projection_comparison"]
        transport = projection["transport_verification"]
        stream = transport["selection"]
        assert comparison == {"report_sha256": hashlib.sha256(raw).hexdigest(),
            "profile": projection["candidate_projection"]["profile"], "manifest": transport["manifest"],
            "stream": {"bytes": stream["bytes"], "sha256": stream["sha256"]},
            "provenance_sha256": stream["provenance_sha256"],
            "producer_receipt_sha256": projection["producer_completion"]["producer_receipt_sha256"]}

        other = unit["momentums"][-3]
        other_raw, _ = project(builder, records, other["height"], other["hash"], trace["root_hex"])
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
            "matched": matched["header"], "projection": comparison,
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
