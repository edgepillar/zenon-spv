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
CHURN = ROOT / "tools/ledger-inventory/churn.py"
COMMAND = "inspect-experimental-snapshot-root"
EXPORT_COMMAND = "export-experimental-snapshot-header-state"
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


def byte_pin(raw):
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


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
        work = Path(directory)
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

        checkpoint, emitted = export_state("export_matched_state", projection_flags(raw), headers_path)
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

        other_raw, _ = project(builder, records, other["height"], other["hash"], trace["root_hex"])
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
