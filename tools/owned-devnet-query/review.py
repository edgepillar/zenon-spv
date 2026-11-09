# SPDX-License-Identifier: GPL-3.0-only
"""Recheck a retained owned-devnet result without extracting or executing it."""
from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
from pathlib import Path
import re
import struct
import sys
import zipfile
import zlib

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import capture
import inputs
import model
from artifacts import API_LIMIT, REPOSITORY, WORKFLOWS, api_json
from model import Refused, canonical, exact_keys, require, same
from process import FILE
from query_checks import consumer_result

INDEX = "evidence/evidence-index.json"
INDEX_BYTES = 512 << 10
FILE_BYTES = 2 << 20
MAX_FILES = 2048
MAX_ARCHIVE = model.LIMITS["max_evidence_bytes"] + (2 << 20)
EXECUTE_STEP = "Run the reviewed fixture and read-only query"
UPLOAD_STEP = "Retain selected evidence and command receipts"
TERMINAL_CONCLUSIONS = ("success", "failure", "cancelled", "timed_out")
CONTROL_JOBS = ("controls", "controls (ubuntu-24.04, linux-amd64)",
                "controls (macos-15-intel, darwin-amd64)", "controls (windows-latest, windows-amd64)")


def select_hosted_result(run, jobs, artifact, source_revision, run_id, artifact_id, contract_sha256):
    """Bind supplied Actions metadata before transporting a selected result."""
    model.digest(source_revision, model.HEX40)
    model.digest(contract_sha256)
    model.uint(run_id)
    model.uint(artifact_id)
    selection = model.bind_owned_workflow_run(run, source_revision, run_id)
    require(run.get("status") == "completed" and run.get("conclusion") in TERMINAL_CONCLUSIONS,
            "hosted_run_completion")
    repository_id = model.uint(run["repository"].get("id"))
    same(run["head_repository"].get("id"), repository_id, "hosted_repository_identity")

    rows = jobs.get("jobs")
    require(type(rows) is list and 1 <= len(rows) <= 5
            and all(type(row) is dict for row in rows), "hosted_job_roster")
    same(jobs.get("total_count"), len(rows), "hosted_job_roster")
    job_ids = {model.uint(row.get("id")) for row in rows}
    names = [row.get("name") for row in rows]
    require(len(job_ids) == len(rows) and all(name in (*CONTROL_JOBS, "experiment") for name in names)
            and len(set(names)) == len(rows) and "experiment" in names, "hosted_job_roster")
    for row in rows:
        same(row.get("run_id"), run_id, "hosted_job_run")
        same(row.get("run_attempt"), selection.run_attempt, "hosted_job_run")
        require(row.get("head_sha") == source_revision and row.get("workflow_name") == "owned-devnet-query"
                and row.get("status") == "completed", "hosted_job_source")
        if row["name"] != "experiment":
            require(row.get("conclusion") == "skipped" and row.get("steps") == [], "hosted_control_job")
    experiment = rows[names.index("experiment")]
    steps = experiment.get("steps")
    require(experiment.get("conclusion") in TERMINAL_CONCLUSIONS and type(steps) is list
            and len(steps) <= 32 and all(type(step) is dict for step in steps), "hosted_experiment_job")
    selected = [step for step in steps if step.get("name") in (EXECUTE_STEP, UPLOAD_STEP)]
    require([step["name"] for step in selected] == [EXECUTE_STEP, UPLOAD_STEP], "hosted_experiment_steps")
    execution, upload = selected
    require(execution.get("status") == upload.get("status") == "completed"
            and execution.get("conclusion") in TERMINAL_CONCLUSIONS and upload.get("conclusion") == "success"
            and model.uint(execution.get("number"), 32) < model.uint(upload.get("number"), 32),
            "hosted_experiment_completion")
    require((run["conclusion"] != "success" or experiment["conclusion"] == "success")
            and (experiment["conclusion"] != "success" or execution["conclusion"] == "success"),
            "hosted_conclusion")

    name = f"owned-devnet-query-{run_id}-{selection.run_attempt}"
    same(artifact.get("id"), artifact_id, "hosted_artifact_id")
    require(artifact.get("name") == name and artifact.get("expired") is False, "hosted_artifact_selection")
    owner = artifact.get("workflow_run")
    require(type(owner) is dict and owner.get("head_sha") == source_revision
            and owner.get("head_branch") == run["head_branch"], "hosted_artifact_source")
    same(owner.get("id"), run_id, "hosted_artifact_run")
    for key in ("repository_id", "head_repository_id"):
        same(owner.get(key), repository_id, "hosted_artifact_repository")
    timestamps = (experiment.get("started_at"), artifact.get("created_at"), experiment.get("completed_at"))
    try:
        start, created, end = (datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ") for value in timestamps)
    except (TypeError, ValueError) as error:
        raise Refused("hosted_artifact_time") from error
    require(start <= created <= end, "hosted_artifact_time")
    digest = artifact.get("digest")
    require(type(digest) is str and digest.startswith("sha256:"), "hosted_artifact_digest")
    archive = model.pin({"bytes": artifact.get("size_in_bytes"), "sha256": digest[7:]}, MAX_ARCHIVE)
    return {"format": "owned-devnet-hosted-result-selection/v1", "status": "SELECTED_HOSTED_RESULT",
            "repository": REPOSITORY, "repository_id": repository_id, "source_revision": source_revision,
            "expected_contract_sha256": contract_sha256, "run_id": run_id, "run_attempt": selection.run_attempt,
            "run_conclusion": run["conclusion"], "experiment_job_id": experiment["id"],
            "experiment_conclusion": experiment["conclusion"], "execution_conclusion": execution["conclusion"],
            "artifact": {"id": artifact_id, "name": name, **archive},
            "supplied_workflow_metadata_bound": True, "artifact_payload_verified": False,
            "new_devnet_acceptance_established": False}


def read_hosted_metadata(path):
    size = path.lstat().st_size
    model.uint(size, API_LIMIT)

    def read(stream):
        raw = stream.read(size + 1)
        require(len(raw) == size, "hosted_metadata_size")
        return raw

    return inputs._read_archive_file(path, size, read)


class Evidence:
    def __init__(self, archive, count):
        self.archive = archive
        rows = inputs._zip_members(archive, count)
        # A failed run that only uploaded evidence/ files has that directory
        # as the upload action's common root. Mixed layouts are refused.
        prefix = "evidence/" if all("/" not in row.filename for row in rows) else ""
        self.rows = {prefix + row.filename: row for row in rows}
        require(INDEX in self.rows and 0 < self.rows[INDEX].file_size <= INDEX_BYTES,
                "review_index_bound")
        index = api_json(archive.read(self.rows.pop(INDEX)), INDEX_BYTES)
        exact_keys(index, {"format", "files", "transport_archive_copies",
                           "raw_service_logs_or_private_configuration_exported"}, "review_index_fields")
        require(index["format"] == "owned-devnet-evidence-index/v1"
                and type(index["transport_archive_copies"]) is int and index["transport_archive_copies"] == 0
                and index["raw_service_logs_or_private_configuration_exported"] is False
                and type(index["files"]) is list and len(index["files"]) == len(self.rows),
                "review_index_shape")
        self.pins, self.verified = {}, set()
        for record in index["files"]:
            exact_keys(record, {"path", "bytes", "sha256"}, "review_member_pin_fields")
            path = model.relative_name(record["path"])
            parent, _, name = path.partition("/")
            retained_stream = parent == "evidence" and (
                name == "consume-query.stdout" or re.fullmatch(r"parent-oracle-[0-9]{2}\.stdout", name))
            require(parent in {"evidence", "transport"} and FILE.fullmatch(name) is not None
                    and (name.endswith(".json") or retained_stream)
                    and path in self.rows and path not in self.pins, "review_member_selection")
            size = model.uint(record["bytes"], FILE_BYTES, minimum=0)
            require(size == self.rows[path].file_size, "review_member_size")
            self.pins[path] = {"bytes": size, "sha256": model.digest(record["sha256"])}

    def bytes(self, path, limit):
        require(path in self.pins and self.pins[path]["bytes"] <= limit, "review_member_bound")
        raw = self.archive.read(self.rows[path])
        same({"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}, self.pins[path],
             "review_member_digest")
        self.verified.add(path)
        return raw

    def json(self, name, limit=128 << 10, *, folder="evidence"):
        return api_json(self.bytes(folder + "/" + name, limit), limit)

    def verify_remaining(self):
        for name in self.pins.keys() - self.verified:
            with self.archive.open(self.rows[name]) as source:
                digest, size = hashlib.sha256(), 0
                for part in iter(lambda: source.read(inputs.CHUNK), b""):
                    digest.update(part)
                    size += len(part)
                    require(size <= self.pins[name]["bytes"], "review_member_size")
            same({"bytes": size, "sha256": digest.hexdigest()}, self.pins[name], "review_member_digest")


def recorded_output(evidence, label, name, *, folder="evidence", external_pin=None):
    receipt = evidence.json(label + ".complete.json", folder=folder)
    require(receipt.get("format") == "owned-devnet-command-capture/v1"
            and receipt.get("label") == label and receipt.get("launch_outcome") == "STARTED"
            and type(receipt.get("actual_exit")) is int and receipt["actual_exit"] == 0
            and receipt.get("output_complete") is True and receipt.get("reason") is None
            and receipt.get("process_group_quiescent") is True, "review_recorded_command_completion")
    pin = evidence.pins[folder + "/" + name] if external_pin is None else external_pin
    stdout = {"file": name, **pin}
    same(receipt["outputs"]["stdout"], stdout, "review_recorded_command_stdout")
    group = model.uint(receipt["process_group"])
    same(evidence.json(label + ".started.json", folder=folder), {"format": "owned-devnet-command-started/v1",
         "label": label, "pid": group, "process_group": group, "new_session_requested": True},
         "review_recorded_command_start")
    return stdout


def recorded_consumer(evidence, contract, checkout, selection):
    same(evidence.json("dispatch-selection.json"), {"format": "owned-devnet-dispatch-selection/v1",
         "repository": REPOSITORY, **selection, "actor": "edgepillar", "host_attested": False,
         "explicit_dispatch_selected": True}, "review_dispatch_binding")
    components = contract.data["qualified_components"]
    for role, workflow in WORKFLOWS.items():
        component = components[role]
        label = "input-" + role.replace("_", "-")
        same(evidence.json(label + "-selection.json", folder="transport"), {
            "component": role, "repository": REPOSITORY, "source_revision": components["source_revision"],
            "workflow": workflow, "authenticated_distribution": False, "new_ci_execution_qualified": False,
            **{key: component[key] for key in ("run_id", "run_attempt", "artifact_id", "archive")}},
            "review_component_binding")
        recorded_output(evidence, label + "-archive", f"artifact-{component['artifact_id']}.zip",
                        folder="transport", external_pin=component["archive"])

    opening_raw = evidence.bytes("evidence/opening-momentums.json", 384 << 10)
    request_id = model.uint(api_json(opening_raw, 384 << 10)["id"], 96)
    recorded_output(evidence, f"rpc-{request_id:02d}", "opening-momentums.json")
    opening_result = capture.rpc_result(opening_raw, request_id, 384 << 10)
    model.uint(opening_result["count"], minimum=3)
    opening = capture.opening_headers(contract, opening_result["list"])
    provider = evidence.json("provider.json", contract.data["limits"]["stdout_bytes"])
    recorded_output(evidence, "collect-provider", "provider.json")

    rows = provider["momentums"]
    require(type(rows) is list and 0 < len(rows) < contract.data["limits"]["max_header_targets"],
            "review_header_range")
    query_selection = evidence.json("selected-query-header.json")
    target_index = model.uint(query_selection["height"], len(rows) + 2, minimum=3) - 3
    chain = contract.data["selection"]["chain_id"]
    query, tip = (capture.Header.read(row, chain) for row in (rows[target_index], rows[-1]))
    same(query_selection, query.identifier(), "review_query_header")
    same(evidence.json("selected-capture-frontier.json"), tip.identifier(), "review_frontier")
    window = capture.Window(capture.captured_headers(contract, opening, query, tip, provider),
                            query, provider, None)

    oracle_outputs = []

    def oracle_reports():
        for index, (request, _) in enumerate(capture.oracle_requests(contract, window), 1):
            label = f"parent-oracle-{index:02d}"
            name, output = label + ".request.json", label + ".stdout"
            require(evidence.bytes("evidence/" + name, 32 << 10) == request, "review_oracle_request")
            oracle_outputs.append({"request": {"file": name, **evidence.pins["evidence/" + name]},
                                   "stdout": recorded_output(evidence, label, output)})
            yield evidence.json(output, capture.ORACLE_REPORT_BYTES)

    schedule = capture.oracle_schedule(contract, window, oracle_reports())
    provenance = evidence.json("closed-ledger-provenance.json")
    oracle_pin = contract.data["qualified_components"]["parent_oracle"]["binaries"][capture.ORACLE_NAME]
    for name, expected in {"format": "owned-devnet-closed-ledger-provenance/v1",
            "genesis": opening[0].identifier(), "anchor": opening[1].identifier(),
            "first_v3": opening[2].identifier(), "frontier": tip.identifier(), "oracle_binary": oracle_pin,
            "oracle_reports": oracle_outputs, "schedule_hash": schedule["schedule_hash"],
            "ledger_copied": False, "ledger_opened_read_only": True}.items():
        same(provenance[name], expected, "review_closed_ledger_binding")
    cleanup = evidence.json("owned-container-cleanup.json")
    rows = cleanup["containers"]
    require(cleanup.get("format") == "owned-devnet-cleanup/v1"
            and type(rows) is list and len(rows) == len(model.SERVICES)
            and cleanup.get("volume_image_or_network_removal_performed") is False, "review_owned_closure")
    closed = {}
    for row in rows:
        exact_keys(row, {"id", "service", "observed_closed"}, "review_owned_closure")
        role = row["service"]
        require(role in model.SERVICES and role not in closed and row["observed_closed"] is True,
                "review_owned_closure")
        closed[role] = model.digest(row["id"])
    require(len(set(closed.values())) == len(rows) and provenance["rpc_container_id"] == closed["rpc"],
            "review_owned_closure")

    descriptor, profile = capture.selected_profile(contract, checkout)
    config, request, pins = capture.query_inputs(contract, window, schedule, profile)
    for name, expected in (("query-config.json", config), ("query-request.json", request),
                           ("query-context-pins.json", pins)):
        same(evidence.json(name, 256 << 10), expected, "review_query_inputs")
    result = evidence.json("consume-query.stdout", 256 << 10)
    recorded_output(evidence, "consume-query", "consume-query.stdout")
    matched = consumer_result(result, config, request, provider, query.root, descriptor)
    same(evidence.json("consumer-comparison.json"), matched, "review_consumer_comparison")
    require(matched["gateway_stored_fields_match"] is True, "review_consumer_gateway")
    return matched


def review_stream(stream, archive_pin, source_revision, run_id, contract, checkout):
    model.pin(archive_pin, MAX_ARCHIVE)
    model.digest(source_revision, model.HEX40)
    model.uint(run_id)
    inputs._hash_stream(stream, archive_pin)
    count = inputs._zip_preflight(stream, archive_pin["bytes"], max_members=MAX_FILES)
    with zipfile.ZipFile(stream) as archive:
        evidence = Evidence(archive, count)
        terminal = evidence.json("terminal.json")
        selection = {"source_revision": source_revision, "contract_sha256": contract.sha256,
                     "run_id": run_id, "run_attempt": 1}
        exact_keys(terminal, {*selection, "format", "outcome", "stage", "reason",
                             "owned_runtime_observed_closed", "production_qualified",
                             "consensus_finality_or_funds_release"}, "review_terminal_fields")
        require(terminal["format"] == "owned-devnet-query-terminal/v1"
                and terminal["production_qualified"] is False
                and terminal["consensus_finality_or_funds_release"] is False
                and type(terminal["owned_runtime_observed_closed"]) is bool, "review_terminal_scope")
        reported = terminal["outcome"]
        require(reported in ("DEVNET_CONSUMER_ACCEPTED", "FAILURE", "REFUSED", "UNKNOWN"),
                "review_terminal_outcome")
        recorded = {name: terminal[name] for name in selection}
        binding_present = any(value is not None for value in recorded.values())
        if binding_present:
            same(recorded, selection, "review_terminal_binding")
        matched = None
        if reported == "DEVNET_CONSUMER_ACCEPTED":
            require(binding_present and terminal["stage"] == "consumer" and terminal["reason"] is None
                    and terminal["owned_runtime_observed_closed"] is True, "review_terminal_completion")
            matched = recorded_consumer(evidence, contract, checkout, selection)
        else:
            require(binding_present or terminal["stage"] == "dispatch", "review_terminal_binding")
        evidence.verify_remaining()
        return {"format": "owned-devnet-evidence-review/v1",
                "status": "RECORDED_CONSUMER_BYTES_MATCH" if matched else "RECORDED_NON_ACCEPTING_OUTCOME",
                "archive": archive_pin, "selection": selection, "recorded_terminal_outcome": reported,
                "recorded_run_binding_present": binding_present, "indexed_files": len(evidence.pins),
                "comparison": matched, "materialized_bytes": 0, "native_consumer_reexecuted": False,
                "hosted_run_provenance_checked": False, "new_devnet_acceptance_established": False,
                "production_qualified": False}


def main(argv=None, stdout=None, stderr=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    hosted = bool(argv) and argv[0] in ("select-hosted", "review-hosted")
    mode = argv.pop(0) if hosted else "review"
    description = "Select an owned devnet result from retained Actions metadata." if mode == "select-hosted" else __doc__
    parser = argparse.ArgumentParser(description=description, allow_abbrev=False)
    if hosted:
        for name in ("run", "jobs", "artifact"):
            parser.add_argument("--" + name + "-metadata", type=Path, required=True)
        parser.add_argument("--expect-artifact-id", type=int, required=True)
    if mode != "select-hosted":
        parser.add_argument("--archive", type=Path, required=True)
    if not hosted:
        parser.add_argument("--expect-archive-sha256", required=True)
        parser.add_argument("--expect-archive-bytes", type=int, required=True)
    parser.add_argument("--expect-contract-sha256", required=True)
    parser.add_argument("--expect-source-revision", required=True)
    parser.add_argument("--expect-run-id", type=int, required=True)
    args = parser.parse_args(argv)
    stdout = sys.stdout.buffer if stdout is None else stdout
    stderr = sys.stderr if stderr is None else stderr
    try:
        contract = model.read_contract(HERE / "contract.json")
        require(model.digest(args.expect_contract_sha256) == contract.sha256, "review_contract_pin")
        if hosted:
            metadata = {name: read_hosted_metadata(getattr(args, name + "_metadata"))
                        for name in ("run", "jobs", "artifact")}
            selected = select_hosted_result(
                api_json(metadata["run"]), api_json(metadata["jobs"]), api_json(metadata["artifact"]),
                args.expect_source_revision, args.expect_run_id, args.expect_artifact_id, contract.sha256)
            selected["metadata_pins"] = {name: {"bytes": len(value), "sha256": hashlib.sha256(value).hexdigest()}
                                         for name, value in metadata.items()}
            archive_pin = {key: selected["artifact"][key] for key in ("sha256", "bytes")}
        else:
            archive_pin = model.pin({"sha256": args.expect_archive_sha256,
                                     "bytes": args.expect_archive_bytes}, MAX_ARCHIVE)
        if mode == "select-hosted":
            report, matched = selected, True
        else:
            report = inputs._read_archive_file(args.archive, archive_pin["bytes"],
                lambda stream: review_stream(stream, archive_pin, args.expect_source_revision,
                                             args.expect_run_id, contract, HERE.parents[1]))
            matched = report["comparison"] is not None
            if mode == "review-hosted":
                execution = selected["execution_conclusion"]
                require(execution not in ("success", "failure") or (execution == "success") == matched,
                        "review_hosted_execution_outcome")
                matched = matched and selected["run_conclusion"] == "success"
                report = {"format": "owned-devnet-hosted-result-review/v1",
                          "status": ("HOSTED_RECORDED_CONSUMER_BYTES_MATCH" if matched
                                     else "HOSTED_RECORDED_NON_ACCEPTING_OUTCOME"),
                          "metadata_selection": selected, "archive_review": report,
                          "artifact_payload_verified": True, "new_devnet_acceptance_established": False}
        raw = canonical(report)
        require(stdout.write(raw) == len(raw), "review_short_output")
        stdout.flush()
        return 0 if matched else 1
    except Refused as error:
        stderr.write("Evidence review refused (" + error.reason + ").\n")
    except (OSError, ValueError, TypeError, KeyError, IndexError, AttributeError,
            EOFError, RuntimeError, struct.error, zipfile.BadZipFile, zlib.error):
        stderr.write("Evidence review could not complete.\n")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
