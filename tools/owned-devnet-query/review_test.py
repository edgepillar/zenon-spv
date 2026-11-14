# SPDX-License-Identifier: GPL-3.0-only
"""Synthetic hosted metadata and archive controls with no external service."""
import base64
from copy import deepcopy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
import capture
from artifacts import WORKFLOWS
from capture_test import CONTRACT, synthetic_reports, synthetic_window
from model import Refused, canonical
import query_checks as checks
import review

SOURCE = "6" * 40
RUN = 1001
ARTIFACT = 7001


def pin(raw):
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def hosted_metadata():
    repository = {"full_name": "edgepillar/zenon-spv", "id": 101}
    run = {"id": RUN, "run_attempt": 1, "event": "workflow_dispatch",
           "path": ".github/workflows/owned-devnet-query.yml", "head_sha": SOURCE, "head_branch": "main",
           "repository": repository, "head_repository": dict(repository),
           "actor": {"login": "edgepillar"}, "triggering_actor": {"login": "edgepillar"},
           "status": "completed", "conclusion": "success"}
    job = {"run_id": RUN, "run_attempt": 1, "head_sha": SOURCE, "workflow_name": "owned-devnet-query",
           "status": "completed"}
    experiment = {**job, "name": "experiment", "id": 501, "conclusion": "success",
                  "started_at": "2026-11-09T10:00:00Z", "completed_at": "2026-11-09T10:20:00Z",
                  "steps": [{"name": name, "number": number, "status": "completed", "conclusion": "success"}
                            for name, number in ((review.EXECUTE_STEP, 3), (review.UPLOAD_STEP, 4))]}
    controls = {**job, "name": "controls", "id": 502, "conclusion": "skipped", "steps": []}
    jobs = {"total_count": 2, "jobs": [experiment, controls]}
    artifact = {"id": ARTIFACT, "name": f"owned-devnet-query-{RUN}-1", "expired": False,
                "size_in_bytes": 128, "digest": "sha256:" + "b" * 64,
                "created_at": "2026-11-09T10:19:00Z",
                "workflow_run": {"id": RUN, "repository_id": repository["id"],
                                 "head_repository_id": repository["id"], "head_sha": SOURCE, "head_branch": "main"}}
    return run, jobs, artifact


class HostedSelectionTests(unittest.TestCase):
    def select(self, run, jobs, artifact):
        return review.select_hosted_result(run, jobs, artifact, SOURCE, RUN, ARTIFACT, CONTRACT.sha256)

    def test_cli_binds_the_three_metadata_inputs_without_reading_a_zip(self):
        out, error = io.BytesIO(), io.StringIO()
        expected_pins = {}
        args = ["select-hosted", "--expect-source-revision", SOURCE, "--expect-run-id", str(RUN),
                "--expect-artifact-id", str(ARTIFACT), "--expect-contract-sha256", CONTRACT.sha256]
        with tempfile.TemporaryDirectory(prefix="owned-hosted-metadata-") as root:
            for name, row in zip(("run", "jobs", "artifact"), hosted_metadata()):
                path = Path(root) / (name + ".json")
                raw = canonical(row)
                path.write_bytes(raw)
                args.extend(["--" + name + "-metadata", str(path)])
                expected_pins[name] = pin(raw)
            with patch.object(review, "review_stream", side_effect=AssertionError):
                self.assertEqual(review.main(args, out, error), 0, error.getvalue())
            self.assertEqual(sorted(path.name for path in Path(root).iterdir()),
                             ["artifact.json", "jobs.json", "run.json"])
        result = json.loads(out.getvalue())
        self.assertEqual(result["status"], "SELECTED_HOSTED_RESULT")
        self.assertEqual(result["metadata_pins"], expected_pins)
        self.assertEqual(result["artifact"], {"id": ARTIFACT, "name": f"owned-devnet-query-{RUN}-1",
                                              "bytes": 128, "sha256": "b" * 64})
        self.assertEqual(result["expected_contract_sha256"], CONTRACT.sha256)
        self.assertTrue(result["supplied_workflow_metadata_bound"])
        self.assertFalse(result["artifact_payload_verified"])
        self.assertFalse(result["new_devnet_acceptance_established"])

    def test_selects_retained_failure_but_requires_consistent_completion(self):
        run, jobs, artifact = hosted_metadata()
        experiment = jobs["jobs"][0]
        run["conclusion"] = experiment["conclusion"] = experiment["steps"][0]["conclusion"] = "failure"
        result = self.select(run, jobs, artifact)
        self.assertEqual(result["run_conclusion"], "failure")
        self.assertEqual(result["execution_conclusion"], "failure")
        self.assertFalse(result["new_devnet_acceptance_established"])
        run["conclusion"] = "success"
        with self.assertRaisesRegex(Refused, "hosted_conclusion"):
            self.select(run, jobs, artifact)

    def test_refuses_wrong_run_job_step_and_archive_metadata(self):
        for part, key, value, reason in (
                ("run", "event", "push", "workflow_source_binding"),
                ("run", "event", "pull_request", "workflow_source_binding"),
                ("run", "run_attempt", 2, "workflow_run_binding"),
                ("run", "actor", {"login": "another"}, "workflow_actor_or_repository"),
                ("run", "head_sha", "7" * 40, "workflow_source_binding"),
                ("head_repository", "id", 102, "hosted_repository_identity"),
                ("jobs", "total_count", 3, "hosted_job_roster"),
                ("experiment", "id", 502, "hosted_job_roster"),
                ("experiment", "name", "controls", "hosted_job_roster"),
                ("experiment", "run_id", RUN + 1, "hosted_job_run"),
                ("experiment", "run_attempt", 2, "hosted_job_run"),
                ("experiment", "conclusion", "skipped", "hosted_experiment_job"),
                ("controls", "conclusion", "success", "hosted_control_job"),
                ("upload", "conclusion", "skipped", "hosted_experiment_completion"),
                ("upload", "number", 2, "hosted_experiment_completion"),
                ("artifact", "id", ARTIFACT + 1, "hosted_artifact_id"),
                ("artifact", "name", f"owned-devnet-query-{RUN}-2", "hosted_artifact_selection"),
                ("artifact", "expired", True, "hosted_artifact_selection"),
                ("artifact", "created_at", "2026-11-09T09:59:59Z", "hosted_artifact_time"),
                ("artifact", "digest", "sha256:invalid", "digest_format"),
                ("artifact", "size_in_bytes", review.MAX_ARCHIVE + 1, "integer_bounds"),
                ("owner", "repository_id", 102, "hosted_artifact_repository"),
                ("owner", "head_sha", "7" * 40, "hosted_artifact_source")):
            with self.subTest(part=part, key=key, value=value):
                run, jobs, artifact = hosted_metadata()
                experiment, controls = jobs["jobs"]
                parts = {"run": run, "head_repository": run["head_repository"], "jobs": jobs,
                         "experiment": experiment, "controls": controls, "upload": experiment["steps"][1],
                         "artifact": artifact, "owner": artifact["workflow_run"]}
                parts[part][key] = value
                with self.assertRaisesRegex(Refused, reason):
                    self.select(run, jobs, artifact)


def make_archive(files, *, flat=False, override=None, extra=None):
    index = {"format": "owned-devnet-evidence-index/v1",
             "files": [{"path": name, **pin(raw)} for name, raw in files.items()],
             "transport_archive_copies": 0,
             "raw_service_logs_or_private_configuration_exported": False}
    if override is not None:
        override(index)
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, raw in {**files, review.INDEX: canonical(index), **(extra or {})}.items():
            archive.writestr(name.split("/")[-1] if flat else name, raw)
    return stream.getvalue()


def terminal(outcome, contract=None):
    selected = {"source_revision": SOURCE, "contract_sha256": contract.sha256,
                "run_id": RUN, "run_attempt": 1} if contract is not None else dict.fromkeys(
                    ("source_revision", "contract_sha256", "run_id", "run_attempt"))
    accepted = outcome == "DEVNET_CONSUMER_ACCEPTED"
    return {"format": "owned-devnet-query-terminal/v1", **selected, "outcome": outcome,
            "stage": "consumer" if contract is not None else "dispatch",
            "reason": None if accepted else "command_incomplete",
            "owned_runtime_observed_closed": accepted, "production_qualified": False,
            "consensus_finality_or_funds_release": False}


def encoded(row):
    return {name: base64.b64encode(value).decode("ascii") if type(value) is bytes else value
            for name, value in row.items()}


def selected_witnesses(descriptor, profile):
    # Rebuild the three synthetic leaves with the independent bottom-up oracle.
    spec = importlib.util.spec_from_file_location("review_fixture_oracle",
        ROOT / "tools/gen-state-root-vectors/check.py")
    oracle = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(oracle)
    trace = json.loads((ROOT / "internal/testdata/conformance/batch-context-node-witness.json").read_bytes())
    values = {row["name"]: bytes.fromhex(row["value_hex"]) for row in trace["rows"][:3]}
    entry = values["batch_entry"]
    values["batch_entry"] = entry[:384] + (3).to_bytes(32, "big") + (33).to_bytes(32, "big") + entry[448:]
    record = values["domain_record"]
    values["domain_record"] = record[:64] + bytes.fromhex(descriptor["source_profile"]["stf_spec_hash"]) + record[96:]
    config = values["domain_config"]
    values["domain_config"] = config[:32] + descriptor["source_profile"]["runtime_upgrade_delay"].to_bytes(32, "big")
    positions = {name: oracle.digest(key) for name, key in checks.ledger_keys(profile, 0).items()}
    levels, by_position = oracle.tree_levels(
        [{"path": positions[name].hex(), "value": value.hex()} for name, value in values.items()])
    root = levels[0][0]
    witnesses = {name: {"root": root.hex(), **encoded({"value": values[name],
                  "proof": oracle.canonical_proof(levels, by_position, position)})}
                 for name, position in positions.items()}
    return root, witnesses, checks.decode_rows(profile, values)


def accepted_files():
    descriptor, profile = capture.selected_profile(CONTRACT, ROOT)
    root, witnesses, typed = selected_witnesses(descriptor, profile)
    contract, headers, window = synthetic_window(state_root=root)
    oracle_reports = list(synthetic_reports(contract, window))
    schedule = capture.oracle_schedule(contract, window, oracle_reports)
    config, request, pins = capture.query_inputs(contract, window, schedule, profile)
    provider = {**window.provider, "witnesses": witnesses, "gateway": {
        "domainId": 1, "batchId": 0, "isFinalized": False,
        **{key[0].lower() + key[1:]: value for key, value in encoded(typed["entry"]).items()}}}
    members = checks.witness_rows(profile, 0, root.hex(), witnesses)["memberships"]
    scope = "EXPERIMENTAL_CONFIGURED_HEADER_THREE_ROW_MEMBERSHIP"
    header, context = checks.consumer_context_diagnostics(config, pins)
    result = {"scope": scope, "context": context, "request": request, "root": root.hex(),
              "query_fingerprint": pins["query"], **{k: encoded(v) for k, v in typed.items()},
              "header_trust": list(checks.OWNED_HEADER_TRUST),
              "batch_membership": encoded(members["batch_entry"]),
              "record_membership": encoded(members["domain_record"]),
              "config_membership": encoded(members["domain_config"])}
    cli = {"schema_version": 1, "command": "query-experimental-batch-context", "scope": scope,
           "status": "matched", "exit_code": 0, "error": None, "persistence": "read_only",
           "rpc_requests": 0, "production_state_value_guarantee": False, "header_context": header,
           "headers": {"outcome": "ACCEPT", "reason": "ReasonOK", "failed_at": -1},
           "query_context": context, "result": result, "gateway_comparison_requested": True,
           "gateway_comparison": {"stored_fields_match": True, "frontier_is_finalized_hint": False,
                                  "frontier_identity_authenticated": False}}
    matched = checks.consumer_result(cli, config, request, provider, root.hex(), descriptor)
    final = terminal("DEVNET_CONSUMER_ACCEPTED", contract)
    files = {"evidence/" + name: canonical(data) for name, data in {
        "terminal.json": final, "dispatch-selection.json": {"format": "owned-devnet-dispatch-selection/v1",
            "repository": "edgepillar/zenon-spv", "actor": "edgepillar", "host_attested": False,
            "explicit_dispatch_selected": True, **{key: final[key] for key in
                ("source_revision", "contract_sha256", "run_id", "run_attempt")}},
        "selected-query-header.json": window.query.identifier(),
        "selected-capture-frontier.json": window.headers[-1].identifier(),
        "query-config.json": config, "query-request.json": request,
        "query-context-pins.json": pins, "consumer-comparison.json": matched}.items()}

    def output(label, name, raw=None, *, folder="evidence", external_pin=None):
        if raw is not None:
            files[folder + "/" + name] = raw
        stdout = {"file": name, **(pin(raw) if raw is not None else external_pin)}
        files[folder + "/" + label + ".complete.json"] = canonical({
            "format": "owned-devnet-command-capture/v1", "label": label, "launch_outcome": "STARTED",
            "actual_exit": 0, "output_complete": True, "reason": None, "process_group": 42,
            "process_group_quiescent": True, "outputs": {"stdout": stdout}})
        files[folder + "/" + label + ".started.json"] = canonical({
            "format": "owned-devnet-command-started/v1", "label": label, "pid": 42,
            "process_group": 42, "new_session_requested": True})
        return stdout

    output("rpc-02", "opening-momentums.json", canonical({"jsonrpc": "2.0", "id": 2,
           "result": {"count": 3, "list": headers[:3]}}))
    output("collect-provider", "provider.json", canonical(provider))
    output("consume-query", "consume-query.stdout", canonical(cli))
    components = contract.data["qualified_components"]
    for role, workflow in WORKFLOWS.items():
        component = components[role]
        label = "input-" + role.replace("_", "-")
        files["transport/" + label + "-selection.json"] = canonical({
            "component": role, "repository": "edgepillar/zenon-spv",
            "source_revision": components["source_revision"], "workflow": workflow,
            "authenticated_distribution": False, "new_ci_execution_qualified": False,
            **{key: component[key] for key in ("run_id", "run_attempt", "artifact_id", "archive")}})
        output(label + "-archive", f"artifact-{component['artifact_id']}.zip",
               folder="transport", external_pin=component["archive"])
    reports = []
    for index, ((raw, _), report) in enumerate(zip(capture.oracle_requests(contract, window), oracle_reports), 1):
        label = f"parent-oracle-{index:02d}"
        request_file = label + ".request.json"
        files["evidence/" + request_file] = raw
        reports.append({"request": {"file": request_file, **pin(raw)},
                        "stdout": output(label, label + ".stdout", canonical(report))})
    containers = {name: str(index) * 64 for index, name in enumerate(CONTRACT.data["runtime"]["services"], 1)}
    files["evidence/owned-container-cleanup.json"] = canonical({
        "format": "owned-devnet-cleanup/v1", "volume_image_or_network_removal_performed": False,
        "containers": [{"service": role, "id": value, "observed_closed": True}
                       for role, value in containers.items()]})
    files["evidence/closed-ledger-provenance.json"] = canonical({
        "format": "owned-devnet-closed-ledger-provenance/v1", "genesis": window.headers[0].identifier(),
        "anchor": window.headers[1].identifier(), "first_v3": window.headers[2].identifier(),
        "frontier": window.headers[-1].identifier(), "oracle_reports": reports,
        "oracle_binary": contract.data["qualified_components"]["parent_oracle"]["binaries"][capture.ORACLE_NAME],
        "schedule_hash": schedule["schedule_hash"], "ledger_copied": False, "ledger_opened_read_only": True,
        "rpc_container_id": containers["rpc"]})
    return contract, files


class FrontierReviewTests(unittest.TestCase):
    """Candidate frontier bytes cannot replace the completed consumer path."""
    @staticmethod
    def files(request_id=2, *, raw=None):
        contract, rows, _ = synthetic_window()
        label = f"rpc-{request_id:02d}"
        name = label + ".frontier.json"
        if raw is None:
            raw = json.dumps({"jsonrpc": "2.0", "id": request_id, "result": rows[1]},
                             separators=(",", ":")).encode() + b"\n"
        final = terminal("REFUSED", contract)
        final.update(stage="nodes", reason="owned_rpc_readiness_deadline")
        files = {"evidence/terminal.json": canonical(final), "evidence/" + name: raw,
            "evidence/" + label + ".request.json": canonical({"jsonrpc": "2.0", "id": request_id,
                "method": "ledger.getFrontierMomentum", "params": []}),
            "evidence/" + label + ".started.json": canonical({"format": "owned-devnet-command-started/v1",
                "label": label, "pid": 42, "process_group": 42, "new_session_requested": True}),
            "evidence/" + label + ".complete.json": canonical({"format": "owned-devnet-command-capture/v1",
                "label": label, "launch_outcome": "STARTED", "actual_exit": 0,
                "output_complete": True, "reason": None, "process_group": 42,
                "process_group_quiescent": True, "outputs": {"stdout": {"file": name, **pin(raw)}}})}
        return contract, files

    @staticmethod
    def review(contract, files):
        raw = make_archive(files)
        return review.review_stream(io.BytesIO(raw), pin(raw), SOURCE, RUN, contract, ROOT)

    def test_retains_exact_candidate_bytes_after_refusal_without_accepting_a_header(self):
        contract, files = self.files()
        result = self.review(contract, files)
        observed = result["candidate_frontier_observations"]
        self.assertEqual(result["status"], "RECORDED_NON_ACCEPTING_OUTCOME")
        self.assertEqual(result["recorded_terminal_outcome"], "REFUSED")
        self.assertIsNone(result["comparison"])
        self.assertFalse(result["new_devnet_acceptance_established"])
        self.assertFalse(result["production_qualified"])
        self.assertEqual(len(observed), 1)
        self.assertEqual(observed[0]["candidate_header"]["height"], 2)
        self.assertEqual(observed[0]["request_id"], 2)
        self.assertEqual(observed[0]["response"], pin(files["evidence/rpc-02.frontier.json"]))
        self.assertFalse(observed[0]["accepted_header_authority"])

    def test_a_frontier_cannot_hide_failed_incomplete_or_mismatched_command_evidence(self):
        for field, value in (("actual_exit", 56), ("actual_exit", False),
                             ("output_complete", False), ("process_group_quiescent", False),
                             ("launch_outcome", "UNKNOWN"), ("reason", "timeout"),
                             ("process_group", 43)):
            with self.subTest(field=field, value=value):
                contract, files = self.files()
                name = "evidence/rpc-02.complete.json"
                receipt = json.loads(files[name])
                receipt[field] = value
                files[name] = canonical(receipt)
                with self.assertRaises(Refused):
                    self.review(contract, files)
        contract, files = self.files()
        name = "evidence/rpc-02.complete.json"
        receipt = json.loads(files[name])
        receipt["outputs"]["stdout"]["sha256"] = "b" * 64
        files[name] = canonical(receipt)
        with self.assertRaisesRegex(Refused, "review_recorded_command_stdout"):
            self.review(contract, files)

    def test_frontier_request_method_parameters_and_identity_are_checked(self):
        for field, value in (("method", "another.read"), ("params", [1]),
                             ("id", 3), ("id", True), ("jsonrpc", "1.0")):
            with self.subTest(field=field, value=value):
                contract, files = self.files()
                name = "evidence/rpc-02.request.json"
                request = json.loads(files[name])
                request[field] = value
                files[name] = canonical(request)
                with self.assertRaisesRegex(Refused, "review_frontier_request"):
                    self.review(contract, files)

    def test_frontier_response_identity_chain_and_size_stay_bounded(self):
        _, rows, _ = synthetic_window()
        wrong_chain = deepcopy(rows[1])
        wrong_chain["chainIdentifier"] += 1
        for raw in (b"{", canonical({"jsonrpc": "2.0", "id": 3, "result": rows[1]}),
                    canonical({"jsonrpc": "2.0", "id": 2, "result": wrong_chain}),
                    b" " * ((128 << 10) + 1)):
            with self.subTest(bytes=len(raw)):
                contract, files = self.files(raw=raw)
                with self.assertRaises((Refused, ValueError)):
                    self.review(contract, files)

    def test_missing_receipts_or_unbounded_call_names_are_refused(self):
        for name in ("evidence/rpc-02.request.json", "evidence/rpc-02.started.json",
                     "evidence/rpc-02.complete.json"):
            with self.subTest(missing=name):
                contract, files = self.files()
                del files[name]
                with self.assertRaises(Refused):
                    self.review(contract, files)
        for request_id in (0, 97, 100):
            with self.subTest(request_id=request_id):
                contract, files = self.files(request_id)
                with self.assertRaises(Refused):
                    self.review(contract, files)

    def test_legacy_failure_without_frontier_bytes_keeps_its_report_shape(self):
        contract, files = self.files()
        result = self.review(contract, {"evidence/terminal.json": files["evidence/terminal.json"]})
        self.assertEqual(result["status"], "RECORDED_NON_ACCEPTING_OUTCOME")
        self.assertNotIn("candidate_frontier_observations", result)
        self.assertNotIn("startup_sync_diagnostic", result)
        self.assertNotIn("post_sync_frontier_diagnostic", result)


class StartupSyncReviewTests(unittest.TestCase):
    @staticmethod
    def files(raw=None):
        contract, files = FrontierReviewTests.files()
        del files["evidence/rpc-02.frontier.json"]
        if raw is None:
            raw = canonical({"jsonrpc": "2.0", "id": 2,
                "result": {"state": 3, "currentHeight": 1, "targetHeight": 0}})
        files["evidence/rpc-02.sync-info.json"] = raw
        files["evidence/rpc-02.request.json"] = canonical({"jsonrpc": "2.0", "id": 2,
            "method": "stats.syncInfo", "params": []})
        receipt = json.loads(files["evidence/rpc-02.complete.json"])
        receipt["outputs"]["stdout"] = {"file": "rpc-02.sync-info.json", **pin(raw)}
        files["evidence/rpc-02.complete.json"] = canonical(receipt)
        files["evidence/startup-sync.json"] = canonical({"format": "owned-devnet-startup-sync/v1",
            "trigger": "owned_rpc_readiness_deadline", "status": "OBSERVED", "reason": None,
            "request_id": 2, "response_file": "rpc-02.sync-info.json",
            "accepted_header_authority": False, "production_qualified": False})
        return contract, files

    @staticmethod
    def review(contract, files):
        return FrontierReviewTests.review(contract, files)

    def test_node_reported_sync_state_is_bound_without_readiness_or_header_acceptance(self):
        contract, files = self.files()
        result = self.review(contract, files)
        sync = result["startup_sync_diagnostic"]
        self.assertEqual(sync["observation"], {"state": 3, "current_height": 1, "target_height": 0})
        self.assertEqual((sync["actual_exit"], sync["output_complete"]), (0, True))
        self.assertEqual(result["recorded_terminal_outcome"], "REFUSED")
        self.assertEqual(result["status"], "RECORDED_NON_ACCEPTING_OUTCOME")
        self.assertFalse(sync["accepted_header_authority"])
        self.assertFalse(result["new_devnet_acceptance_established"])
        self.assertIsNone(result["comparison"])

    def test_summary_requires_fixed_scope_status_request_and_false_authority(self):
        for field, value in (("format", "another/v1"), ("trigger", "unselected"),
                             ("status", "READY"), ("status", True), ("reason", []),
                             ("reason", "private text"), ("request_id", None),
                             ("request_id", True), ("request_id", 0), ("request_id", 97),
                             ("response_file", "rpc-03.sync-info.json"),
                             ("accepted_header_authority", True), ("production_qualified", True)):
            with self.subTest(field=field, value=value):
                contract, files = self.files()
                summary = json.loads(files["evidence/startup-sync.json"])
                summary[field] = value
                files["evidence/startup-sync.json"] = canonical(summary)
                with self.assertRaises(Refused):
                    self.review(contract, files)

    def test_observation_requires_exact_request_and_complete_matching_command(self):
        for change in ("missing_request", "wrong_method", "wrong_parameters", "wrong_id", "missing_start",
                       "missing_receipt", "failed_exit", "incomplete", "wrong_stdout", "wrong_group"):
            with self.subTest(change=change):
                contract, files = self.files()
                if change.startswith("missing_"):
                    suffix = {"missing_request": "request", "missing_start": "started", "missing_receipt": "complete"}[change]
                    del files[f"evidence/rpc-02.{suffix}.json"]
                elif change.startswith("wrong_") and change not in ("wrong_stdout", "wrong_group"):
                    request = json.loads(files["evidence/rpc-02.request.json"])
                    request[{"wrong_method": "method", "wrong_parameters": "params", "wrong_id": "id"}[change]] = {
                        "wrong_method": "another.read", "wrong_parameters": [1], "wrong_id": 3}[change]
                    files["evidence/rpc-02.request.json"] = canonical(request)
                else:
                    receipt = json.loads(files["evidence/rpc-02.complete.json"])
                    if change == "failed_exit": receipt["actual_exit"] = 7
                    elif change == "incomplete": receipt["output_complete"] = False
                    elif change == "wrong_stdout": receipt["outputs"]["stdout"]["sha256"] = "f" * 64
                    else: receipt["process_group"] = 43
                    files["evidence/rpc-02.complete.json"] = canonical(receipt)
                with self.assertRaises(Refused):
                    self.review(contract, files)

    def test_malformed_unbounded_or_private_extra_fields_are_refused(self):
        for raw in (b"{", canonical({"jsonrpc": "2.0", "id": True, "result": {}}),
                    canonical({"jsonrpc": "2.0", "id": 2, "result": {
                        "state": 3, "currentHeight": 1, "targetHeight": 0, "peers": []}}),
                    canonical({"jsonrpc": "2.0", "id": 2, "result": {
                        "state": 4, "currentHeight": 1, "targetHeight": 0}}),
                    b" " * (capture.SYNC_INFO_BYTES + 1)):
            with self.subTest(bytes=len(raw)):
                contract, files = self.files(raw)
                with self.assertRaises(Refused):
                    self.review(contract, files)

    def test_failed_incomplete_and_unlaunched_diagnostics_invent_no_observation(self):
        for status, reason, actual_exit, complete in (("FAILURE", "command_failed", 7, True),
                ("UNKNOWN", "command_incomplete", -15, False), ("REFUSED", "capture_refused", 0, True),
                ("NOT_ATTEMPTED", "shared_call_limit", None, None),
                ("NOT_ATTEMPTED", "budget_refused", None, None),
                ("UNKNOWN", "capture_interrupted", None, None)):
            with self.subTest(status=status, reason=reason):
                contract, files = self.files()
                del files["evidence/rpc-02.sync-info.json"]
                summary = json.loads(files["evidence/startup-sync.json"])
                summary.update(status=status, reason=reason, response_file=None)
                if complete is None:
                    summary["request_id"] = None
                    for suffix in ("request", "started", "complete"):
                        del files[f"evidence/rpc-02.{suffix}.json"]
                else:
                    receipt = json.loads(files["evidence/rpc-02.complete.json"])
                    receipt.update(actual_exit=actual_exit, output_complete=complete)
                    files["evidence/rpc-02.complete.json"] = canonical(receipt)
                files["evidence/startup-sync.json"] = canonical(summary)
                result = self.review(contract, files)["startup_sync_diagnostic"]
                self.assertEqual((result["status"], result["reason"]), (status, reason))
                self.assertEqual((result["actual_exit"], result["output_complete"]), (actual_exit, complete))
                self.assertIsNone(result["observation"])

    def test_orphan_multiple_or_successful_consumer_diagnostics_are_not_accepted(self):
        contract, files = self.files()
        del files["evidence/startup-sync.json"]
        with self.assertRaisesRegex(Refused, "review_sync_summary_missing"):
            self.review(contract, files)
        contract, files = self.files()
        files["evidence/rpc-03.sync-info.json"] = files["evidence/rpc-02.sync-info.json"]
        with self.assertRaisesRegex(Refused, "review_sync_response_selection"):
            self.review(contract, files)
        contract, accepted = accepted_files()
        _, extra = self.files()
        for name, raw in extra.items():
            if name != "evidence/terminal.json":
                accepted[name] = raw
        with self.assertRaisesRegex(Refused, "review_sync_summary_scope"):
            self.review(contract, accepted)


class PostSyncFrontierReviewTests(unittest.TestCase):
    @staticmethod
    def files():
        contract, files = StartupSyncReviewTests.files()
        _, post = FrontierReviewTests.files(3)
        files.update({name: raw for name, raw in post.items() if name != "evidence/terminal.json"})
        files["evidence/" + capture.POST_SYNC_REPORT] = canonical({
            "format": "owned-devnet-post-sync-frontier/v1", "after_sync_request_id": 2,
            "status": "OBSERVED", "reason": None, "request_id": 3,
            "response_file": "rpc-03.frontier.json", "accepted_header_authority": False,
            "production_qualified": False})
        return contract, files

    @staticmethod
    def review(contract, files):
        return FrontierReviewTests.review(contract, files)

    def test_later_candidate_is_distinct_from_sync_and_never_completes_the_consumer(self):
        contract, files = self.files()
        result = self.review(contract, files)
        post = result["post_sync_frontier_diagnostic"]
        self.assertEqual((post["after_sync_request_id"], post["request_id"]), (2, 3))
        self.assertEqual(post["observation"]["candidate_header"]["height"], 2)
        self.assertEqual((post["actual_exit"], post["output_complete"]), (0, True))
        self.assertFalse(post["atomic_with_sync_observation"])
        self.assertFalse(post["accepted_header_authority"])
        self.assertEqual(result["recorded_terminal_outcome"], "REFUSED")
        self.assertIsNone(result["comparison"])
        self.assertFalse(result["new_devnet_acceptance_established"])

    def test_summary_requires_an_observed_parent_and_one_next_bounded_request(self):
        for field, value in (("format", "another/v1"), ("after_sync_request_id", True),
                ("after_sync_request_id", 1), ("after_sync_request_id", 97),
                ("status", True), ("status", "READY"), ("reason", []),
                ("request_id", None), ("request_id", True), ("request_id", 2),
                ("request_id", 4), ("request_id", 97), ("response_file", "rpc-04.frontier.json"),
                ("accepted_header_authority", True), ("production_qualified", True)):
            with self.subTest(field=field, value=value):
                contract, files = self.files()
                name = "evidence/" + capture.POST_SYNC_REPORT
                summary = json.loads(files[name]);summary[field] = value
                files[name] = canonical(summary)
                with self.assertRaises(Refused):self.review(contract, files)
        contract, files = self.files()
        del files["evidence/startup-sync.json"]
        with self.assertRaises(Refused):self.review(contract, files)

    def test_response_request_receipt_and_single_later_body_are_bound(self):
        for change in ("missing_request", "missing_start", "missing_receipt", "wrong_method",
                       "wrong_params", "wrong_id", "failed", "incomplete", "digest", "extra_later"):
            with self.subTest(change=change):
                contract, files = self.files()
                if change.startswith("missing_"):
                    suffix = {"missing_request": "request", "missing_start": "started", "missing_receipt": "complete"}[change]
                    del files[f"evidence/rpc-03.{suffix}.json"]
                elif change.startswith("wrong_"):
                    request = json.loads(files["evidence/rpc-03.request.json"])
                    key, value = {"wrong_method": ("method", "stats.syncInfo"),
                                  "wrong_params": ("params", [1]), "wrong_id": ("id", 4)}[change]
                    request[key] = value;files["evidence/rpc-03.request.json"] = canonical(request)
                elif change == "extra_later":
                    _, extra = FrontierReviewTests.files(4)
                    files.update({name: raw for name, raw in extra.items() if name != "evidence/terminal.json"})
                else:
                    receipt = json.loads(files["evidence/rpc-03.complete.json"])
                    if change == "failed":receipt["actual_exit"] = 7
                    elif change == "incomplete":receipt["output_complete"] = False
                    else:receipt["outputs"]["stdout"]["sha256"] = "f" * 64
                    files["evidence/rpc-03.complete.json"] = canonical(receipt)
                with self.assertRaises(Refused):self.review(contract, files)

    def test_failure_incomplete_and_unlaunched_outcomes_invent_no_candidate(self):
        for status, reason, actual_exit, complete in (("FAILURE", "command_failed", 7, True),
                ("UNKNOWN", "command_incomplete", -15, False), ("REFUSED", "capture_refused", 0, True),
                ("NOT_ATTEMPTED", "budget_refused", None, None),
                ("UNKNOWN", "capture_interrupted", None, None)):
            with self.subTest(status=status, reason=reason):
                contract, files = self.files()
                del files["evidence/rpc-03.frontier.json"]
                name = "evidence/" + capture.POST_SYNC_REPORT
                summary = json.loads(files[name]);summary.update(status=status, reason=reason, response_file=None)
                if complete is None:
                    summary["request_id"] = None
                    for suffix in ("request", "started", "complete"):del files[f"evidence/rpc-03.{suffix}.json"]
                else:
                    receipt = json.loads(files["evidence/rpc-03.complete.json"])
                    receipt.update(actual_exit=actual_exit, output_complete=complete)
                    files["evidence/rpc-03.complete.json"] = canonical(receipt)
                files[name] = canonical(summary)
                result = self.review(contract, files)["post_sync_frontier_diagnostic"]
                self.assertEqual((result["actual_exit"], result["output_complete"]), (actual_exit, complete))
                self.assertIsNone(result["observation"])

    def test_nonobserved_sync_cannot_authorize_a_followup(self):
        contract, files = self.files()
        summary = json.loads(files["evidence/startup-sync.json"])
        summary.update(status="REFUSED", reason="capture_refused", response_file=None)
        files["evidence/startup-sync.json"] = canonical(summary)
        del files["evidence/rpc-02.sync-info.json"]
        with self.assertRaisesRegex(Refused, "review_post_sync_scope"):self.review(contract, files)

    def test_legacy_sync_archive_keeps_its_report_shape(self):
        contract, files = StartupSyncReviewTests.files()
        result = self.review(contract, files)
        self.assertIn("startup_sync_diagnostic", result)
        self.assertNotIn("post_sync_frontier_diagnostic", result)

    def test_exhausted_slot_requires_the_actual_final_sync_request(self):
        contract, files = self.files()
        for suffix in ("frontier", "request", "started", "complete"):
            del files[f"evidence/rpc-03.{suffix}.json"]
        summary = json.loads(files["evidence/" + capture.POST_SYNC_REPORT])
        summary.update(status="NOT_ATTEMPTED", reason="shared_call_limit", request_id=None, response_file=None)
        files["evidence/" + capture.POST_SYNC_REPORT] = canonical(summary)
        with self.assertRaisesRegex(Refused, "review_post_sync_call_limit"):
            self.review(contract, files)
        moved = {}
        for name, raw in files.items():
            value = json.loads(raw)
            def shift(row):
                if isinstance(row, dict):
                    return {k: (96 if k in ("id", "request_id", "after_sync_request_id") and v == 2
                                else shift(v)) for k, v in row.items()}
                if isinstance(row, list):return [shift(v) for v in row]
                if isinstance(row, str):return row.replace("rpc-02", "rpc-96")
                return row
            value = shift(value)
            # The renamed original stdout is still bound to its exact bytes.
            moved[name.replace("rpc-02", "rpc-96")] = canonical(value)
        body = moved["evidence/rpc-96.sync-info.json"]
        receipt = json.loads(moved["evidence/rpc-96.complete.json"])
        receipt["outputs"]["stdout"] = {"file": "rpc-96.sync-info.json", **pin(body)}
        moved["evidence/rpc-96.complete.json"] = canonical(receipt)
        result = self.review(contract, moved)["post_sync_frontier_diagnostic"]
        self.assertEqual(result["after_sync_request_id"], 96)
        self.assertIsNone(result["request_id"])

    def test_post_summary_cannot_be_attached_to_an_accepted_consumer(self):
        contract, files = accepted_files()
        _, extra = self.files()
        files.update({name: raw for name, raw in extra.items() if name != "evidence/terminal.json"})
        with self.assertRaises(Refused):self.review(contract, files)


class ReviewTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.contract, cls.files = accepted_files()

    def review(self, raw, contract=None, archive_pin=None, run=RUN):
        return review.review_stream(io.BytesIO(raw), archive_pin or pin(raw), SOURCE, run,
                                    contract or self.contract, ROOT)

    def hosted_review(self, raw, *, conclusion="success", execution="success", archive_sha256=None):
        run, jobs, artifact = hosted_metadata()
        run["conclusion"] = jobs["jobs"][0]["conclusion"] = conclusion
        jobs["jobs"][0]["steps"][0]["conclusion"] = execution
        artifact.update(size_in_bytes=len(raw), digest="sha256:" + (archive_sha256 or pin(raw)["sha256"]))
        out, error = io.BytesIO(), io.StringIO()
        args = ["review-hosted", "--expect-source-revision", SOURCE, "--expect-run-id", str(RUN),
                "--expect-artifact-id", str(ARTIFACT), "--expect-contract-sha256", self.contract.sha256]
        with tempfile.TemporaryDirectory(prefix="owned-hosted-review-") as directory:
            root = Path(directory)
            archive = root / "original.zip"
            archive.write_bytes(raw)
            args.extend(("--archive", str(archive)))
            for name, row in zip(("run", "jobs", "artifact"), (run, jobs, artifact)):
                path = root / (name + ".json")
                path.write_bytes(canonical(row))
                args.extend(("--" + name + "-metadata", str(path)))
            with patch.object(review.model, "read_contract", return_value=self.contract):
                exit_code = review.main(args, out, error)
            self.assertEqual(sorted(path.name for path in root.iterdir()),
                             ["artifact.json", "jobs.json", "original.zip", "run.json"])
        result = json.loads(out.getvalue()) if out.getvalue() else None
        return exit_code, result, error.getvalue()

    def test_hosted_review_uses_the_selected_archive_and_rechecks_the_consumer(self):
        raw = make_archive(self.files)
        with patch.object(review.inputs, "_hash_stream", wraps=review.inputs._hash_stream) as digest:
            code, result, error = self.hosted_review(raw)
        self.assertEqual(code, 0, error)
        digest.assert_called_once()
        self.assertEqual(result["status"], "HOSTED_RECORDED_CONSUMER_BYTES_MATCH")
        self.assertEqual(result["archive_review"]["archive"], pin(raw))
        self.assertEqual(result["metadata_selection"]["artifact"]["id"], ARTIFACT)
        self.assertEqual(result["archive_review"]["comparison"]["three_membership_proofs_checked"], 3)
        self.assertEqual(result["archive_review"]["materialized_bytes"], 0)
        self.assertTrue(result["artifact_payload_verified"])
        self.assertFalse(result["new_devnet_acceptance_established"])

    def test_hosted_failure_preserves_both_conclusions_without_acceptance(self):
        cases = (
            (make_archive(self.files), "failure", "success", "RECORDED_CONSUMER_BYTES_MATCH"),
            (make_archive(self.files), "cancelled", "cancelled", "RECORDED_CONSUMER_BYTES_MATCH"),
            (make_archive({"evidence/terminal.json": canonical(terminal("UNKNOWN"))}),
             "failure", "failure", "RECORDED_NON_ACCEPTING_OUTCOME"),
        )
        for raw, conclusion, execution, expected in cases:
            with self.subTest(conclusion=conclusion, execution=execution):
                code, result, error = self.hosted_review(raw, conclusion=conclusion, execution=execution)
                self.assertEqual(code, 1, error)
                self.assertEqual(result["status"], "HOSTED_RECORDED_NON_ACCEPTING_OUTCOME")
                self.assertEqual(result["metadata_selection"]["run_conclusion"], conclusion)
                self.assertEqual(result["archive_review"]["status"], expected)
                self.assertFalse(result["new_devnet_acceptance_established"])

    def test_hosted_review_refuses_archive_and_execution_mismatches(self):
        accepted = make_archive(self.files)
        incomplete = make_archive({"evidence/terminal.json": canonical(terminal("UNKNOWN"))})
        for raw, options, reason in (
                (accepted, {"archive_sha256": "a" * 64}, "archive_digest"),
                (accepted, {"conclusion": "failure", "execution": "failure"}, "review_hosted_execution_outcome"),
                (incomplete, {}, "review_hosted_execution_outcome")):
            with self.subTest(options=options, reason=reason):
                code, result, error = self.hosted_review(raw, **options)
                self.assertEqual(code, 2)
                self.assertIsNone(result)
                self.assertIn(reason, error)

    def test_rechecks_complete_index_three_proofs_and_gateway_without_extraction(self):
        raw = make_archive(self.files)
        with patch.object(zipfile.ZipFile, "extractall", side_effect=AssertionError):
            result = self.review(raw)
        self.assertEqual(result["status"], "RECORDED_CONSUMER_BYTES_MATCH")
        self.assertEqual(result["indexed_files"], len(self.files))
        self.assertEqual(result["comparison"]["three_membership_proofs_checked"], 3)
        self.assertEqual(result["comparison"]["gateway_stored_fields_compared"], 17)
        self.assertEqual(result["materialized_bytes"], 0)
        self.assertFalse(result["new_devnet_acceptance_established"])
        self.assertFalse(result["native_consumer_reexecuted"])

    def test_outer_digest_and_selected_run_are_independent_inputs(self):
        raw = make_archive(self.files)
        with self.assertRaisesRegex(Refused, "archive_digest"):
            self.review(raw, archive_pin={**pin(raw), "sha256": "a" * 64})
        with self.assertRaisesRegex(Refused, "review_terminal_binding"):
            self.review(raw, run=RUN + 1)

    def test_altered_index_and_unindexed_member_are_refused(self):
        for label, override, extra, reason in (
                ("digest", lambda index: index["files"][-1].update(sha256="a" * 64), None,
                 "review_member_digest"),
                ("extra", None, {"evidence/unknown.txt": b"extra"}, "review_index_shape"),
                ("raw archive", lambda index: index.update(transport_archive_copies=1), None,
                 "review_index_shape")):
            raw = make_archive(self.files, override=override, extra=extra)
            with self.subTest(label=label), self.assertRaisesRegex(Refused, reason):
                self.review(raw)
        with self.assertRaisesRegex(Refused, "review_member_selection"):
            self.review(make_archive({**self.files, "transport/redundant.zip": b"extra"}))

    def test_incomplete_command_or_changed_context_cannot_use_accepted_label(self):
        for filename, mutate, reason in (
                ("consume-query.complete.json", lambda row: row.update(actual_exit=-9),
                 "review_recorded_command_completion"),
                ("collect-provider.complete.json", lambda row: row.update(output_complete=False),
                 "review_recorded_command_completion"),
                ("query-context-pins.json", lambda row: row.update(context="a" * 64),
                 "review_query_inputs"),
                ("parent-oracle-01.request.json", lambda row: row.update(version=2),
                 "review_oracle_request"),
                ("closed-ledger-provenance.json", lambda row: row.update(rpc_container_id="e" * 64),
                 "review_owned_closure"),
                ("selected-query-header.json", lambda row: row.update(hash="b" * 64),
                 "review_query_header")):
            files = dict(self.files)
            path = "evidence/" + filename
            data = json.loads(files[path])
            mutate(data)
            files[path] = canonical(data)
            with self.subTest(file=filename), self.assertRaisesRegex(Refused, reason):
                self.review(make_archive(files))

    def test_input_archive_receipt_is_bound_without_including_a_copy(self):
        files = dict(self.files)
        name = "transport/input-consumer-archive.complete.json"
        receipt = json.loads(files[name])
        receipt["outputs"]["stdout"]["sha256"] = "a" * 64
        files[name] = canonical(receipt)
        with self.assertRaisesRegex(Refused, "review_recorded_command_stdout"):
            self.review(make_archive(files))

    def test_retained_result_refuses_changed_header_trust_with_rebound_stdout(self):
        files = dict(self.files)
        report_path = "evidence/consume-query.stdout"
        report = json.loads(files[report_path])
        report["result"]["header_trust"].append("TRUST_PERSISTED_STATE")
        files[report_path] = canonical(report)
        receipt_path = "evidence/consume-query.complete.json"
        receipt = json.loads(files[receipt_path])
        receipt["outputs"]["stdout"].update(pin(files[report_path]))
        files[receipt_path] = canonical(receipt)
        with self.assertRaisesRegex(Refused, "consumer_header_trust"):
            self.review(make_archive(files))

    def test_changed_proof_refused_even_with_updated_archive_and_stdout_pins(self):
        files = dict(self.files)
        provider = json.loads(files["evidence/provider.json"])
        provider["witnesses"]["domain_record"]["proof"] = provider["witnesses"]["batch_entry"]["proof"]
        raw = files["evidence/provider.json"] = canonical(provider)
        name = "evidence/collect-provider.complete.json"
        receipt = json.loads(files[name])
        receipt["outputs"]["stdout"].update(pin(raw))
        files[name] = canonical(receipt)
        with self.assertRaisesRegex(Refused, "independent_membership_leaf"):
            self.review(make_archive(files))

    def test_failed_dispatch_archive_retains_outcome_and_does_not_review_consumer(self):
        files = {"evidence/terminal.json": canonical(terminal("UNKNOWN"))}
        raw = make_archive(files, flat=True)
        with tempfile.TemporaryDirectory(prefix="owned-evidence-review-") as root:
            path = Path(root) / "original.zip"
            path.write_bytes(raw)
            out, error = io.BytesIO(), io.StringIO()

            def arguments(value):
                return ["--archive", str(path), "--expect-archive-sha256", pin(value)["sha256"],
                        "--expect-archive-bytes", str(len(value)), "--expect-contract-sha256", CONTRACT.sha256,
                        "--expect-source-revision", SOURCE, "--expect-run-id", str(RUN)]

            self.assertEqual(review.main(arguments(raw), out, error), 1, error.getvalue())
            self.assertEqual(path.read_bytes(), raw)
            self.assertEqual(list(path.parent.iterdir()), [path])
            # ZipFile raises before member validation for unsupported versions.
            invalid = bytearray(raw)
            directory = struct.unpack_from("<I", raw, len(raw) - 6)[0]
            invalid[directory + 6] = 255
            path.write_bytes(invalid)
            invalid_out, invalid_error = io.BytesIO(), io.StringIO()
            self.assertEqual(review.main(arguments(invalid), invalid_out, invalid_error), 2)
            self.assertEqual(invalid_out.getvalue(), b"")
            self.assertEqual(invalid_error.getvalue(), "Evidence review could not complete.\n")
        result = json.loads(out.getvalue())
        self.assertEqual(result["status"], "RECORDED_NON_ACCEPTING_OUTCOME")
        self.assertEqual(result["recorded_terminal_outcome"], "UNKNOWN")
        self.assertFalse(result["recorded_run_binding_present"])
        self.assertIsNone(result["comparison"])

    def test_zip_count_lie_refused_before_library_allocation(self):
        raw = bytearray(make_archive(self.files))
        struct.pack_into("<HH", raw, len(raw) - 14, 1, 1)
        with patch.object(zipfile, "ZipFile", side_effect=AssertionError):
            with self.assertRaisesRegex(Refused, "zip_directory(_record_count)?"):
                self.review(bytes(raw))


if __name__ == "__main__":
    unittest.main(verbosity=2)
