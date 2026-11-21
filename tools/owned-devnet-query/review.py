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
from capture import OPENING_BYTES, OPENING_FILE
import inputs
import model
import node_diagnostics as node_diag
import node_file_logs
from artifacts import API_LIMIT, REPOSITORY, WORKFLOWS, api_json
from model import Refused, canonical, exact_keys, require, same
from process import FILE
from query_checks import consumer_result, opening_batch_witness

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
                name == capture.CONSUMER_STDOUT or re.fullmatch(r"parent-oracle-[0-9]{2}\.stdout", name))
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


def recorded_output(evidence, label, name, *, folder="evidence", external_pin=None, actual_exit=0):
    receipt = evidence.json(label + ".complete.json", folder=folder)
    require(receipt.get("format") == "owned-devnet-command-capture/v1"
            and receipt.get("label") == label and receipt.get("launch_outcome") == "STARTED"
            and type(receipt.get("actual_exit")) is int and receipt["actual_exit"] == actual_exit
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


def recorded_consumer_failure(evidence, terminal, binding_present):
    if terminal["reason"] != "consumer_reported_failure":
        return None
    name = capture.CONSUMER_STDOUT
    require(binding_present and terminal["outcome"] == "FAILURE" and terminal["stage"] == "consumer"
            and "evidence/" + name in evidence.pins, "review_consumer_failure_scope")
    code = evidence.json("consume-query.complete.json").get("actual_exit")
    raw = evidence.bytes("evidence/" + name, capture.CONSUMER_FAILURE_BYTES)
    report = capture.consumer_failure(raw, code)
    stdout = recorded_output(evidence, "consume-query", name, actual_exit=code)
    return {**report, "stdout": stdout}


def recorded_opening(evidence, contract):
    envelope = evidence.json(OPENING_FILE, OPENING_BYTES)
    exact_keys(envelope, {"jsonrpc", "id", "result"}, "owned_rpc_result_envelope")
    request_id = model.uint(envelope["id"], 96)
    result = envelope["result"]
    require(envelope["jsonrpc"] == "2.0" and type(result) is dict, "owned_rpc_result_identity")
    label = f"rpc-{request_id:02d}"
    recorded_output(evidence, label, OPENING_FILE)
    request_file = label + ".request.json"
    request = evidence.pins.get("evidence/" + request_file)
    if request is not None:
        same(evidence.json(request_file, 4096), {"jsonrpc": "2.0", "id": request_id,
             "method": "ledger.getMomentumsByHeight", "params": [1, 3]}, "review_opening_request")
    model.uint(result["count"], minimum=3)
    headers = capture.opening_headers(contract, result["list"])
    observation = {
        "request_id": request_id,
        "request": request,
        "response": evidence.pins["evidence/" + OPENING_FILE],
        "headers": [{**header.identifier(), "version": header.version, "timestamp": header.timestamp,
                     "state_root": header.root} for header in headers],
        "signature_verified": False,
        "accepted_header_authority": False,
    }
    return headers, observation


def recorded_opening_proof(evidence, contract, checkout, opening, opening_observation, terminal):
    name = capture.OPENING_PROOF_FILE
    version_unavailable = terminal["reason"] == capture.OPENING_PROOF_VERSION_UNAVAILABLE
    if "evidence/" + name not in evidence.pins:
        require(not version_unavailable, "review_opening_proof_refusal_evidence")
        return None
    require(opening is not None and opening_observation["request"] is not None, "review_opening_proof_context")
    request_id = model.uint(opening_observation["request_id"] + 1, capture.RPC_CALL_LIMIT)
    label = f"rpc-{request_id:02d}"
    header = opening[2]
    _, profile = capture.selected_profile(contract, checkout)
    key, parameters = capture.opening_proof_target(contract, profile, header)
    request_file = label + ".request.json"
    same(evidence.json(request_file, 4096), {"jsonrpc": "2.0", "id": request_id,
         "method": "ledger.getProof", "params": parameters}, "review_opening_proof_request")
    response = recorded_output(evidence, label, name)
    raw = evidence.bytes("evidence/" + name, capture.OPENING_PROOF_BYTES)
    try:
        witness = capture.opening_proof_result(raw, request_id, capture.OPENING_PROOF_BYTES)
    except Refused as error:
        if error.reason != capture.OPENING_PROOF_VERSION_UNAVAILABLE:
            raise
        require(version_unavailable and terminal["stage"] == "opening-proof" and terminal["outcome"] == "REFUSED",
                "review_opening_proof_refusal_scope")
        observation = {"status": "VERSION_UNAVAILABLE", "rpc_error_code": -32000}
    else:
        require(not version_unavailable, "review_opening_proof_refusal_scope")
        observation = opening_batch_witness(profile, header.root, key, witness)
    return {**observation, "ledger_key": key.hex(),
            "header": header.identifier(), "state_root": header.root, "request_id": request_id,
            "request": evidence.pins["evidence/" + request_file], "response": response,
            "accepted_header_authority": False}


def recorded_opening_signatures(evidence, opening, observation, proof):
    name = capture.OPENING_SIGNATURE_REPORT
    if "evidence/" + name not in evidence.pins:
        return None
    require(opening is not None and observation["request"] is not None and proof is not None
            and proof.get("presence") in ("present", "absent"), "review_opening_signature_context")
    report = capture.opening_signature_report(opening, observation["response"])
    same(evidence.json(name), report, "review_opening_signature_report")
    success = capture.OPENING_SIGNATURE_OK
    pin = {"bytes": len(success), "sha256": hashlib.sha256(success).hexdigest()}
    for label in capture.OPENING_SIGNATURE_LABELS:
        recorded_output(evidence, label, label + ".stdout", external_pin=pin)
        stderr = evidence.json(label + ".complete.json")["outputs"]["stderr"]
        same(stderr, {"file": label + ".stderr", "bytes": 0, "sha256": hashlib.sha256(b"").hexdigest()},
             "review_opening_signature_stderr")
    return report


def recorded_consumer(evidence, contract, checkout, selection, opening):
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
    result = evidence.json(capture.CONSUMER_STDOUT, 256 << 10)
    recorded_output(evidence, "consume-query", capture.CONSUMER_STDOUT)
    matched = consumer_result(result, config, request, provider, query.root, descriptor)
    same(evidence.json("consumer-comparison.json"), matched, "review_consumer_comparison")
    return matched


def recorded_frontiers(evidence, contract):
    """Read optional candidate observations without creating header authority."""
    rows = []
    for path in sorted(evidence.pins):
        if not path.endswith(".frontier.json"):
            continue
        match = re.fullmatch(r"evidence/rpc-([0-9]{2})\.frontier\.json", path)
        require(match is not None, "review_frontier_filename")
        request_id = model.uint(int(match[1]), 96)
        label, name = f"rpc-{request_id:02d}", path.split("/")[1]
        frontier_request(evidence, label, request_id)
        rows.append(frontier_observation(evidence, contract, label, name, request_id))
    return rows


def frontier_request(evidence, label, request_id):
    same(evidence.json(label + ".request.json"), {"jsonrpc": "2.0", "id": request_id,
         "method": "ledger.getFrontierMomentum", "params": []}, "review_frontier_request")


def frontier_observation(evidence, contract, label, name, request_id):
    # Bind the exact body to a complete command before checking its ID and header.
    path = "evidence/" + name
    require(path in evidence.pins, "review_frontier_body_missing")
    recorded_output(evidence, label, name)
    raw = evidence.bytes(path, capture.FRONTIER_BYTES)
    result = capture.rpc_result(raw, request_id, capture.FRONTIER_BYTES)
    header = capture.Header.read(result, contract.data["selection"]["chain_id"])
    return {"request_id": request_id, "response": evidence.pins[path],
            "candidate_header": header.identifier(), "version": header.version,
            "timestamp": header.timestamp, "accepted_header_authority": False}


def diagnostic_receipt(evidence, label, reason):
    if "evidence/" + label + ".complete.json" not in evidence.pins:
        return None
    receipt = evidence.json(label + ".complete.json")
    require(receipt.get("format") == "owned-devnet-command-capture/v1"
            and receipt.get("label") == label
            and (receipt.get("actual_exit") is None or type(receipt.get("actual_exit")) is int)
            and type(receipt.get("output_complete")) is bool, reason)
    return receipt


def recorded_startup_sync(evidence, terminal):
    path = "evidence/" + capture.SYNC_REPORT
    bodies = {name for name in evidence.pins if name.endswith(".sync-info.json")}
    if path not in evidence.pins:
        require(not bodies, "review_sync_summary_missing")
        return None
    summary = evidence.json(capture.SYNC_REPORT, 4096)
    exact_keys(summary, {"format", "trigger", "status", "reason", "request_id", "response_file",
                        "accepted_header_authority", "production_qualified"}, "review_sync_summary_fields")
    status, reason = summary["status"], summary["reason"]
    require(summary["format"] == "owned-devnet-startup-sync/v1"
            and summary["trigger"] == "owned_rpc_readiness_deadline"
            and terminal["stage"] == "nodes" and terminal["outcome"] != "DEVNET_CONSUMER_ACCEPTED"
            and summary["accepted_header_authority"] is False and summary["production_qualified"] is False
            and type(status) is str and status in capture.SYNC_REASONS
            and (reason is None or type(reason) is str)
            and reason in capture.SYNC_REASONS[status], "review_sync_summary_scope")
    request_id = summary["request_id"]
    result = {"status": status, "reason": reason, "request_id": request_id,
              "observation": None, "actual_exit": None, "output_complete": None,
              "accepted_header_authority": False, "production_qualified": False}
    if request_id is None:
        require((status == "NOT_ATTEMPTED" or status == "REFUSED"
                 or status == "UNKNOWN" and reason == "capture_interrupted")
                and summary["response_file"] is None and not bodies, "review_sync_missing_request")
        return result
    model.uint(request_id, 96)
    require(status != "NOT_ATTEMPTED", "review_sync_request_scope")
    label = f"rpc-{request_id:02d}"
    same(evidence.json(label + ".request.json"), {"jsonrpc": "2.0", "id": request_id,
         "method": "stats.syncInfo", "params": []}, "review_sync_request")
    receipt = diagnostic_receipt(evidence, label, "review_sync_command")
    if receipt is not None:
        result.update(actual_exit=receipt["actual_exit"], output_complete=receipt["output_complete"])
    if status == "OBSERVED":
        response = label + ".sync-info.json"
        require(summary["response_file"] == response and bodies == {"evidence/" + response},
                "review_sync_response_selection")
        recorded_output(evidence, label, response)
        raw = evidence.bytes("evidence/" + response, capture.SYNC_INFO_BYTES)
        result["observation"] = capture.sync_info(capture.rpc_result(raw, request_id, capture.SYNC_INFO_BYTES))
    else:
        require(summary["response_file"] is None and not bodies, "review_sync_response_selection")
        if status == "FAILURE":
            require(receipt is not None and type(receipt["actual_exit"]) is int
                    and receipt["actual_exit"] != 0 and receipt["output_complete"] is True,
                    "review_sync_failure")
        if status == "UNKNOWN" and reason == "command_incomplete":
            require(receipt is not None and receipt["output_complete"] is False, "review_sync_incomplete")
    return result


def recorded_post_sync_frontier(evidence, terminal, startup_sync, frontiers):
    if "evidence/" + capture.POST_SYNC_REPORT not in evidence.pins:
        return None
    summary = evidence.json(capture.POST_SYNC_REPORT, 4096)
    exact_keys(summary, {"format", "after_sync_request_id", "status", "reason", "request_id",
                        "response_file", "accepted_header_authority", "production_qualified"},
               "review_post_sync_fields")
    status, reason = summary["status"], summary["reason"]
    require(summary["format"] == "owned-devnet-post-sync-frontier/v1"
            and terminal["stage"] == "nodes" and terminal["outcome"] != "DEVNET_CONSUMER_ACCEPTED"
            and startup_sync is not None and startup_sync["status"] == "OBSERVED"
            and summary["accepted_header_authority"] is False and summary["production_qualified"] is False
            and type(status) is str and status in capture.SYNC_REASONS
            and (reason is None or type(reason) is str) and reason in capture.SYNC_REASONS[status],
            "review_post_sync_scope")
    after = model.uint(summary["after_sync_request_id"], 96)
    same(after, startup_sync["request_id"], "review_post_sync_parent")
    if reason == "shared_call_limit":
        require(status == "NOT_ATTEMPTED" and after == 96, "review_post_sync_call_limit")
    request_id = summary["request_id"]
    later = [row for row in frontiers if row["request_id"] > after]
    result = {"status": status, "reason": reason, "after_sync_request_id": after,
              "request_id": request_id, "observation": None, "actual_exit": None,
              "output_complete": None, "accepted_header_authority": False,
              "production_qualified": False, "atomic_with_sync_observation": False}
    if request_id is None:
        require((status in ("NOT_ATTEMPTED", "REFUSED")
                 or status == "UNKNOWN" and reason == "capture_interrupted")
                and summary["response_file"] is None and not later, "review_post_sync_missing_request")
        return result
    model.uint(request_id, 96)
    require(request_id == after + 1 and status != "NOT_ATTEMPTED", "review_post_sync_request_scope")
    label = f"rpc-{request_id:02d}"
    same(evidence.json(label + ".request.json"), {"jsonrpc": "2.0", "id": request_id,
         "method": "ledger.getFrontierMomentum", "params": []}, "review_post_sync_request")
    receipt = diagnostic_receipt(evidence, label, "review_post_sync_command")
    if receipt is not None:
        result.update(actual_exit=receipt["actual_exit"], output_complete=receipt["output_complete"])
    if status == "OBSERVED":
        require(summary["response_file"] == label + ".frontier.json" and len(later) == 1
                and later[0]["request_id"] == request_id, "review_post_sync_response")
        # recorded_frontiers already checked the exact body, request and complete
        # started-command binding. These two RPC reads are not an atomic view.
        result["observation"] = later[0]
    else:
        require(summary["response_file"] is None and not later, "review_post_sync_response")
        if status == "FAILURE":
            require(receipt is not None and type(receipt["actual_exit"]) is int
                    and receipt["actual_exit"] != 0 and receipt["output_complete"] is True,
                    "review_post_sync_failure")
        if status == "UNKNOWN" and reason == "command_incomplete":
            require(receipt is not None and receipt["output_complete"] is False,
                    "review_post_sync_incomplete")
    return result


def recorded_startup_peer_frontiers(evidence, terminal, post_sync, contract):
    roles = tuple(capture.STARTUP_FRONTIER_URLS)
    labels = tuple(f"startup-{role}-frontier" for role in roles)
    requests = {"evidence/" + label + ".request.json" for label in labels} & evidence.pins.keys()
    bodies = {"evidence/" + label + ".json" for label in labels} & evidence.pins.keys()
    receipts = {"evidence/" + label + suffix for label in labels
                for suffix in (".started.json", ".complete.json")} & evidence.pins.keys()
    if "evidence/" + capture.STARTUP_FRONTIERS_REPORT not in evidence.pins:
        require(not (requests or bodies or receipts), "review_startup_peer_report_missing")
        return None
    report = evidence.json(capture.STARTUP_FRONTIERS_REPORT, 4096)
    exact_keys(report, {"format", "after_rpc_request_id", "observations",
                        "accepted_header_authority", "production_qualified"}, "review_startup_peer_fields")
    require(report["format"] == "owned-devnet-startup-peer-frontiers/v1"
            and terminal["stage"] == "nodes" and terminal["outcome"] != "DEVNET_CONSUMER_ACCEPTED"
            and post_sync is not None and post_sync["status"] == "OBSERVED"
            and report["accepted_header_authority"] is False
            and report["production_qualified"] is False, "review_startup_peer_scope")
    after = model.uint(report["after_rpc_request_id"], capture.RPC_CALL_LIMIT)
    same(after, post_sync["request_id"], "review_startup_peer_parent")
    rows = report["observations"]
    require(type(rows) is list and 1 <= len(rows) <= len(roles), "review_startup_peer_count")
    observations, expected_requests, expected_bodies = [], set(), set()
    for index, row in enumerate(rows):
        exact_keys(row, {"role", "status", "reason", "request_id", "response_file"}, "review_startup_peer_row")
        role, status, reason = row["role"], row["status"], row["reason"]
        require(role == roles[index] and type(status) is str and status in capture.SYNC_REASONS
                and (reason is None or type(reason) is str) and reason in capture.SYNC_REASONS[status]
                and (index == 0 or observations[-1]["status"] == "OBSERVED"), "review_startup_peer_row_scope")
        label = labels[index]
        request_id = row["request_id"]
        observation = {"role": role, "status": status, "reason": reason, "request_id": request_id,
                       "observation": None, "actual_exit": None, "output_complete": None}
        if reason == "shared_call_limit":
            require(index == 0 and after + len(roles) > capture.RPC_CALL_LIMIT, "review_startup_peer_call_limit")
        if request_id is None:
            require((status in ("NOT_ATTEMPTED", "REFUSED") or reason == "capture_interrupted")
                    and not any(path.startswith("evidence/" + label + ".") for path in receipts),
                    "review_startup_peer_request_missing")
        else:
            model.uint(request_id, capture.RPC_CALL_LIMIT)
            require(request_id == after + index + 1 and after + len(roles) <= capture.RPC_CALL_LIMIT
                    and status != "NOT_ATTEMPTED", "review_startup_peer_request_id")
            frontier_request(evidence, label, request_id)
            expected_requests.add("evidence/" + label + ".request.json")
            receipt = diagnostic_receipt(evidence, label, "review_startup_peer_receipt")
            if receipt is not None:
                observation.update(actual_exit=receipt["actual_exit"], output_complete=receipt["output_complete"])
            if status == "FAILURE":
                require(receipt is not None and type(receipt["actual_exit"]) is int
                        and receipt["actual_exit"] != 0 and receipt["output_complete"] is True,
                        "review_startup_peer_failure")
            if reason == "command_incomplete":
                require(receipt is not None and receipt["output_complete"] is False, "review_startup_peer_incomplete")
        if status == "OBSERVED":
            name = label + ".json"
            same(row["response_file"], name, "review_startup_peer_response")
            observation["observation"] = frontier_observation(evidence, contract, label, name, request_id)
            expected_bodies.add("evidence/" + name)
        else:
            require(row["response_file"] is None, "review_startup_peer_response")
        observations.append(observation)
    require(requests == expected_requests and bodies == expected_bodies,
            "review_startup_peer_member_selection")
    require(len(observations) == len(roles) or observations[-1]["status"] != "OBSERVED",
            "review_startup_peer_followup_missing")
    comparison = None
    if len(observations) == len(roles) and all(row["status"] == "OBSERVED" for row in observations):
        first = post_sync["observation"]["candidate_header"]
        pillar, final = (row["observation"]["candidate_header"] for row in observations)
        if final != first:
            comparison = "rpc_frontier_changed"
        elif pillar == first:
            comparison = "same_candidate"
        elif pillar["height"] == first["height"]:
            comparison = "different_hash_at_same_height"
        else:
            comparison = ("pillar_ahead_of_unchanged_rpc" if pillar["height"] > first["height"]
                          else "pillar_behind_unchanged_rpc")
    return {"after_rpc_request_id": after, "observations": observations, "comparison": comparison,
            "sequential_observations": True, "accepted_header_authority": False,
            "production_qualified": False}


def recorded_startup_nodes(evidence, terminal):
    command_files = {name for name in evidence.pins if name.startswith("evidence/")
                     and node_diag.COMMAND_FILE.fullmatch(name[len("evidence/"):])}
    require(not any(name.endswith((".stdout", ".stderr")) for name in command_files),
            "review_startup_node_raw_stream")
    if "evidence/" + node_diag.REPORT not in evidence.pins:
        require(not command_files, "review_startup_nodes_summary_missing")
        return None
    summary = evidence.json(node_diag.REPORT, 32 << 10)
    exact_keys(summary, {"format", "trigger", "status", "reason", "engine_probe", "engine_identity_verified",
                        "observed_before_cleanup", "atomic_snapshot", "accepted_header_authority",
                        "production_qualified", "raw_logs_exported", "nodes"}, "review_startup_nodes_fields")
    require(summary["format"] == "owned-devnet-startup-nodes/v1"
            and summary["trigger"] == "owned_rpc_readiness_deadline" and terminal["stage"] == "nodes"
            and terminal["outcome"] != "DEVNET_CONSUMER_ACCEPTED"
            and summary["observed_before_cleanup"] is True and summary["atomic_snapshot"] is False
            and summary["accepted_header_authority"] is False and summary["production_qualified"] is False
            and summary["raw_logs_exported"] is False and type(summary["engine_identity_verified"]) is bool,
            "review_startup_nodes_scope")
    reasons = {"OBSERVED": {None}, "NOT_ATTEMPTED": {"budget_refused"},
               "UNKNOWN": {"capture_interrupted", "incomplete_diagnostics"}}
    require(type(summary["status"]) is str and summary["status"] in reasons
            and (summary["reason"] is None or type(summary["reason"]) is str)
            and summary["reason"] in reasons[summary["status"]], "review_startup_nodes_status")
    rows = summary["nodes"]
    require(type(rows) is list and len(rows) == len(node_diag.ROLES), "review_startup_nodes_count")
    phases, counters = [], []

    def phase(value, suffix, kind):
        exact_keys(value, set(node_diag.empty_phase()), "review_startup_node_phase_fields")
        status, reason = value["status"], value["reason"]
        require(type(status) is str and status in node_diag.PHASE_REASONS
                and (reason is None or type(reason) is str) and reason in node_diag.PHASE_REASONS[status],
                "review_startup_node_phase_status")
        phases.append(value)
        label = value["command"]
        if label is None:
            require(status not in ("OBSERVED", "FAILURE") and reason != "command_incomplete"
                    and value["actual_exit"] is None and value["output_complete"] is None
                    and value["outputs"] is None and value["data"] is None, "review_startup_node_no_command")
            return
        require(status != "NOT_ATTEMPTED", "review_startup_node_started_status")
        require(type(label) is str and re.fullmatch(r"docker-([0-9]{3,6})-" + re.escape(suffix), label),
                "review_startup_node_command_scope")
        counters.append(model.uint(int(label.split("-", 2)[1]), 999999))
        receipt = diagnostic_receipt(evidence, label, "review_startup_node_receipt")
        require(receipt is not None, "review_startup_node_missing_receipt")
        same(value["actual_exit"], receipt["actual_exit"], "review_startup_node_exit")
        same(value["output_complete"], receipt["output_complete"], "review_startup_node_completeness")
        require(type(value["actual_exit"]) is int or value["actual_exit"] is None,
                "review_startup_node_exit_type")
        require(type(value["output_complete"]) is bool, "review_startup_node_completeness_type")
        exact_keys(value["outputs"], {"stdout", "stderr"}, "review_startup_node_outputs")
        require(type(receipt.get("outputs")) is dict and {"stdout", "stderr"} <= set(receipt["outputs"]),
                "review_startup_node_receipt_streams")
        for channel in ("stdout", "stderr"):
            pin = value["outputs"][channel]
            exact_keys(pin, {"sha256", "bytes"}, "review_startup_node_stream_fields")
            model.digest(pin["sha256"])
            limit = node_diag.LOG_BYTES if kind == "logs" else (16 << 10 if channel == "stdout" else 4096)
            model.uint(pin["bytes"], limit, minimum=0)
            recorded = receipt["outputs"][channel]
            same(pin, {key: recorded[key] for key in pin}, "review_startup_node_stream_binding")
            require(type(recorded["file"]) is str and FILE.fullmatch(recorded["file"])
                    and "evidence/" + recorded["file"] not in evidence.pins, "review_startup_node_raw_stream")
        if status == "OBSERVED":
            require(value["actual_exit"] == 0 and value["output_complete"] is True
                    and receipt.get("launch_outcome") == "STARTED" and receipt.get("reason") is None
                    and receipt.get("process_group_quiescent") is True, "review_startup_node_success")
            group = model.uint(receipt.get("process_group"))
            same(evidence.json(label + ".started.json"), {"format": "owned-devnet-command-started/v1",
                 "label": label, "pid": group, "process_group": group, "new_session_requested": True},
                 "review_startup_node_start")
            if kind == "inspection":
                node_diag.check_state_summary(value["data"])
            elif kind == "logs":
                node_diag.check_log_summary(value["data"])
            else:
                require(value["data"] is None, "review_startup_node_probe_data")
        else:
            require(value["data"] is None, "review_startup_node_unvalidated_data")
            if status == "FAILURE":
                require(type(value["actual_exit"]) is int and value["actual_exit"] != 0
                        and value["output_complete"] is True, "review_startup_node_failure")
            if reason == "command_incomplete":
                require(value["output_complete"] is False, "review_startup_node_incomplete")

    phase(summary["engine_probe"], "startup-engine-info", "probe")
    for role, row in zip(node_diag.ROLES, rows):
        exact_keys(row, {"service", "inspection", "logs"}, "review_startup_node_row")
        same(row["service"], role, "review_startup_node_role")
        phase(row["inspection"], "startup-inspect-" + role, "inspection")
        phase(row["logs"], "startup-logs-" + role, "logs")
        require(row["inspection"]["status"] == "OBSERVED" or row["logs"]["status"] == "NOT_ATTEMPTED",
                "review_startup_node_log_scope")
    require(counters == sorted(set(counters)), "review_startup_node_command_order")
    stops = [int(match[1]) for name in evidence.pins if (match := re.fullmatch(
        r"evidence/docker-([0-9]{3,6})-(?:inspect-(?:pillar|pillar2|pillar3|rpc)-stop-state\.json"
        r"|stop-(?:pillar|pillar2|pillar3|rpc)\.(?:started|complete)\.json)", name))]
    require(not counters or not stops or max(counters) < min(stops), "review_startup_node_cleanup_order")
    if summary["engine_identity_verified"]:
        require(summary["engine_probe"]["status"] == "OBSERVED", "review_startup_node_engine")
    if any(p["command"] is not None for p in phases[1:]):
        require(summary["engine_identity_verified"], "review_startup_node_engine")
    if summary["status"] == "OBSERVED":
        require(summary["engine_identity_verified"] and all(p["status"] == "OBSERVED" for p in phases),
                "review_startup_nodes_complete")
    if summary["status"] == "NOT_ATTEMPTED":
        require(not summary["engine_identity_verified"]
                and not command_files and all(p["status"] == "NOT_ATTEMPTED" for p in phases),
                "review_startup_nodes_unlaunched")
    if summary["reason"] == "incomplete_diagnostics":
        require(any(p["status"] != "OBSERVED" for p in phases), "review_startup_nodes_incomplete")
    return {"summary": summary, "diagnostic_assertions_only": True,
            "original_log_text_independently_rechecked": False, "accepted_header_authority": False}


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
        startup_sync = recorded_startup_sync(evidence, terminal)
        frontiers = recorded_frontiers(evidence, contract)
        post_sync = recorded_post_sync_frontier(evidence, terminal, startup_sync, frontiers)
        startup_peers = recorded_startup_peer_frontiers(evidence, terminal, post_sync, contract)
        startup_nodes = recorded_startup_nodes(evidence, terminal)
        file_logs = node_file_logs.recorded(evidence, terminal, startup_nodes, diagnostic_receipt)
        consumer_failure = recorded_consumer_failure(evidence, terminal, binding_present)
        accepted = reported == "DEVNET_CONSUMER_ACCEPTED"
        gateway_refusal = terminal["reason"] == "gateway_stored_fields_differ"
        if accepted:
            require(binding_present and terminal["stage"] == "consumer" and terminal["reason"] is None
                    and terminal["owned_runtime_observed_closed"] is True, "review_terminal_completion")
        else:
            require(binding_present or terminal["stage"] == "dispatch", "review_terminal_binding")
        if gateway_refusal:
            require(binding_present and terminal["stage"] == "consumer" and reported == "REFUSED",
                    "review_gateway_refusal_scope")

        opening = opening_observation = matched = gateway_mismatch = None
        if accepted or "evidence/" + OPENING_FILE in evidence.pins:
            require(binding_present, "review_opening_run_binding")
            opening, opening_observation = recorded_opening(evidence, contract)
        opening_proof = recorded_opening_proof(evidence, contract, checkout, opening, opening_observation, terminal)
        opening_signatures = recorded_opening_signatures(evidence, opening, opening_observation, opening_proof)
        if accepted or (gateway_refusal and terminal["owned_runtime_observed_closed"]):
            require(opening is not None, "review_consumer_opening")
            comparison = recorded_consumer(evidence, contract, checkout, selection, opening)
            same(comparison["gateway_stored_fields_match"], accepted, "review_consumer_gateway")
            if accepted:
                matched = comparison
            else:
                gateway_mismatch = comparison
        evidence.verify_remaining()
        report = {"format": "owned-devnet-evidence-review/v1",
                "status": "RECORDED_CONSUMER_BYTES_MATCH" if matched else "RECORDED_NON_ACCEPTING_OUTCOME",
                "archive": archive_pin, "selection": selection, "recorded_terminal_outcome": reported,
                "recorded_run_binding_present": binding_present, "indexed_files": len(evidence.pins),
                "comparison": matched, "materialized_bytes": 0, "native_consumer_reexecuted": False,
                "hosted_run_provenance_checked": False, "new_devnet_acceptance_established": False,
                "production_qualified": False}
        if frontiers:
            report["candidate_frontier_observations"] = frontiers
        if opening_observation is not None and not accepted:
            report["candidate_opening_observation"] = opening_observation
        if opening_proof is not None:
            report["candidate_opening_proof"] = opening_proof
        if opening_signatures is not None:
            report["recorded_opening_signatures"] = opening_signatures
        if startup_sync is not None:
            report["startup_sync_diagnostic"] = startup_sync
        if post_sync is not None:
            report["post_sync_frontier_diagnostic"] = post_sync
        if startup_peers is not None:
            report["startup_peer_frontier_diagnostic"] = startup_peers
        if startup_nodes is not None:
            report["startup_node_diagnostics"] = startup_nodes
        if file_logs is not None:
            report["startup_file_log_diagnostics"] = file_logs
        if consumer_failure is not None:
            report["recorded_consumer_failure"] = consumer_failure
        if gateway_mismatch is not None:
            report["recorded_gateway_mismatch"] = gateway_mismatch
        return report


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
    parser.add_argument("--contract", type=Path, default=HERE / "contract.json")
    parser.add_argument("--expect-source-revision", required=True)
    parser.add_argument("--expect-run-id", type=int, required=True)
    args = parser.parse_args(argv)
    stdout = sys.stdout.buffer if stdout is None else stdout
    stderr = sys.stderr if stderr is None else stderr
    try:
        contract = model.read_contract(args.contract)
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
