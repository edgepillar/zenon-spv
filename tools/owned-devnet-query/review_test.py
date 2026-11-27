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
from capture_test import CONTRACT, consumer_failure_fixture, synthetic_reports, synthetic_window
import fixture_progress
import model
from model import Refused, canonical
import query_checks as checks
from query_checks_test import opening_absence_fixture
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


def selected_witnesses(descriptor, profile, *, submission_height=3):
    # Rebuild the three synthetic leaves with the independent bottom-up oracle.
    spec = importlib.util.spec_from_file_location("review_fixture_oracle",
        ROOT / "tools/gen-state-root-vectors/check.py")
    oracle = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(oracle)
    trace = json.loads((ROOT / "internal/testdata/conformance/batch-context-node-witness.json").read_bytes())
    values = {row["name"]: bytes.fromhex(row["value_hex"]) for row in trace["rows"][:3]}
    entry = values["batch_entry"]
    values["batch_entry"] = (entry[:384] + submission_height.to_bytes(32, "big")
                             + (submission_height + 30).to_bytes(32, "big") + entry[448:])
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


def accepted_files(*, gateway_matches=True, terminal_format=None):
    descriptor, profile = capture.selected_profile(CONTRACT, ROOT)
    requires_absence = terminal_format == model.TERMINAL_FORMAT
    root, witnesses, typed = selected_witnesses(descriptor, profile, submission_height=4 if requires_absence else 3)
    if requires_absence:
        opening_witness = opening_absence_fixture()
        contract, headers, window = synthetic_window(last=5, state_root=root,
                                                     opening_root=bytes.fromhex(opening_witness["root"]))
    else:
        opening_witness = witnesses["batch_entry"]
        contract, headers, window = synthetic_window(state_root=root)
    oracle_reports = list(synthetic_reports(contract, window))
    schedule = capture.oracle_schedule(contract, window.headers, oracle_reports)
    config, request, pins = capture.query_inputs(contract, window, schedule, profile)
    provider = {**window.provider, "witnesses": witnesses, "gateway": {
        "domainId": 1, "batchId": 0, "isFinalized": False,
        **{key[0].lower() + key[1:]: value for key, value in encoded(typed["entry"]).items()}}}
    if not gateway_matches:
        provider["gateway"]["executorPillar"] = "Different gateway pillar"
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
           "gateway_comparison": {"stored_fields_match": gateway_matches, "frontier_is_finalized_hint": False,
                                  "frontier_identity_authenticated": False}}
    matched = checks.consumer_result(cli, config, request, provider, root.hex(), descriptor)
    final = terminal("DEVNET_CONSUMER_ACCEPTED", contract)
    if terminal_format is not None:
        final["format"] = terminal_format
    if not gateway_matches:
        final.update(outcome="REFUSED", reason="gateway_stored_fields_differ")
    files = {"evidence/" + name: canonical(data) for name, data in {
        "terminal.json": final, "dispatch-selection.json": {"format": "owned-devnet-dispatch-selection/v1",
            "repository": "edgepillar/zenon-spv", "actor": "edgepillar", "host_attested": False,
            "explicit_dispatch_selected": True, **{key: final[key] for key in
                ("source_revision", "contract_sha256", "run_id", "run_attempt")}},
        "selected-query-header.json": window.query.identifier(),
        "selected-capture-frontier.json": window.headers[-1].identifier(),
        "query-config.json": config, "query-request.json": request,
        "query-context-pins.json": pins, "consumer-comparison.json": matched}.items()}

    def output(label, name, raw=None, *, folder="evidence", external_pin=None, stderr_pin=None):
        if raw is not None:
            files[folder + "/" + name] = raw
        stdout = {"file": name, **(pin(raw) if raw is not None else external_pin)}
        outputs = {"stdout": stdout}
        if stderr_pin is not None:
            outputs["stderr"] = {"file": label + ".stderr", **stderr_pin}
        files[folder + "/" + label + ".complete.json"] = canonical({
            "format": "owned-devnet-command-capture/v1", "label": label, "launch_outcome": "STARTED",
            "actual_exit": 0, "output_complete": True, "reason": None, "process_group": 42,
            "process_group_quiescent": True, "outputs": outputs})
        files[folder + "/" + label + ".started.json"] = canonical({
            "format": "owned-devnet-command-started/v1", "label": label, "pid": 42,
            "process_group": 42, "new_session_requested": True})
        return stdout

    opening = canonical({"jsonrpc": "2.0", "id": 2, "result": {"count": 3, "list": headers[:3]}})
    output("rpc-02", capture.OPENING_FILE, opening)
    if terminal_format is not None:
        _, parameters = capture.opening_proof_target(contract, profile, window.headers[2])
        files["evidence/rpc-02.request.json"] = canonical(
            {"jsonrpc": "2.0", "id": 2, "method": "ledger.getMomentumsByHeight", "params": [1, 3]})
        files["evidence/rpc-03.request.json"] = canonical(
            {"jsonrpc": "2.0", "id": 3, "method": "ledger.getProof", "params": parameters})
        output("rpc-03", capture.OPENING_PROOF_FILE, canonical(
            {"jsonrpc": "2.0", "id": 3, "result": opening_witness}))
        files["evidence/" + capture.OPENING_SIGNATURE_REPORT] = canonical(
            capture.opening_signature_report(window.headers[:3], pin(opening)))
        for label in capture.OPENING_SIGNATURE_LABELS:
            output(label, label + ".stdout", external_pin=pin(capture.OPENING_SIGNATURE_OK), stderr_pin=pin(b""))
        for label in ("fixture-configure", "fixture-deposit"):
            output(label, label + ".stdout", external_pin=pin(b"fixture control\n"), stderr_pin=pin(b""))
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
    for index, ((raw, _), report) in enumerate(zip(capture.oracle_requests(contract, window.headers), oracle_reports), 1):
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


class StartupPeerFrontierReviewTests(unittest.TestCase):
    @staticmethod
    def files(pillar_height=3, final_height=2):
        contract, files = PostSyncFrontierReviewTests.files()
        _, rows, _ = synthetic_window()
        observations = []
        for role, request_id, height in (("pillar", 4, pillar_height), ("rpc", 5, final_height)):
            raw = canonical({"jsonrpc": "2.0", "id": request_id, "result": rows[height - 1]})
            _, probe = FrontierReviewTests.files(request_id, raw=raw)
            old_label, label = f"rpc-{request_id:02d}", f"startup-{role}-frontier"
            for name, value in probe.items():
                if name == "evidence/terminal.json":
                    continue
                if name == f"evidence/{old_label}.frontier.json":
                    files[f"evidence/{label}.json"] = raw
                else:
                    if name.endswith(".complete.json"):
                        value = value.replace(f"{old_label}.frontier.json".encode(), f"{label}.json".encode())
                    files[name.replace(old_label, label)] = value.replace(old_label.encode(), label.encode())
            observations.append({"role": role, "status": "OBSERVED", "reason": None, "request_id": request_id,
                                 "response_file": label + ".json"})
        files["evidence/" + capture.STARTUP_FRONTIERS_REPORT] = canonical({
            "format": "owned-devnet-startup-peer-frontiers/v1", "after_rpc_request_id": 3,
            "observations": observations, "accepted_header_authority": False, "production_qualified": False})
        return contract, files

    @staticmethod
    def review(contract, files):
        return FrontierReviewTests.review(contract, files)

    def test_distinguishes_pillar_progress_from_movement_of_the_rpc_bracket(self):
        for heights, comparison in (((3, 2), "pillar_ahead_of_unchanged_rpc"),
                                    ((2, 2), "same_candidate"),
                                    ((1, 2), "pillar_behind_unchanged_rpc"),
                                    ((3, 3), "rpc_frontier_changed")):
            with self.subTest(heights=heights):
                contract, files = self.files(*heights)
                result = self.review(contract, files)
                self.assertEqual(result["recorded_terminal_outcome"], "REFUSED")
                self.assertIsNone(result["comparison"])
                peer = result["startup_peer_frontier_diagnostic"]
                self.assertEqual(peer["comparison"], comparison)
                self.assertTrue(peer["sequential_observations"])
                self.assertFalse(peer["accepted_header_authority"])
                self.assertEqual([item["observation"]["candidate_header"]["height"]
                                  for item in peer["observations"]], list(heights))
                self.assertEqual([item["request_id"] for item in result["candidate_frontier_observations"]], [3])

    def test_partial_bracket_is_retained_without_a_comparison(self):
        contract, files = self.files()
        for name in list(files):
            if name.startswith("evidence/startup-rpc-frontier."):
                del files[name]
        name = "evidence/" + capture.STARTUP_FRONTIERS_REPORT
        report = json.loads(files[name])
        report["observations"][1].update(status="NOT_ATTEMPTED", reason="budget_refused",
                                         request_id=None, response_file=None)
        files[name] = canonical(report)
        peer = self.review(contract, files)["startup_peer_frontier_diagnostic"]
        self.assertIsNone(peer["comparison"])
        self.assertEqual(peer["observations"][1]["status"], "NOT_ATTEMPTED")
        self.assertEqual(peer["observations"][0]["actual_exit"], 0)

    def test_rejects_unbound_parent_probe_and_role_receipt(self):
        for missing in (capture.STARTUP_FRONTIERS_REPORT, capture.POST_SYNC_REPORT,
                        "startup-pillar-frontier.request.json", "startup-pillar-frontier.complete.json",
                        "startup-rpc-frontier.json"):
            with self.subTest(missing=missing):
                contract, files = self.files()
                del files["evidence/" + missing]
                with self.assertRaises(Refused):
                    self.review(contract, files)
        for field, value in (("role", "rpc"), ("request_id", True), ("request_id", 5),
                             ("response_file", "startup-rpc-frontier.json")):
            with self.subTest(field=field, value=value):
                contract, files = self.files()
                name = "evidence/" + capture.STARTUP_FRONTIERS_REPORT
                report = json.loads(files[name])
                report["observations"][0][field] = value
                files[name] = canonical(report)
                with self.assertRaises(Refused):
                    self.review(contract, files)

    def test_failed_followup_retains_exit_and_rejects_a_false_completion(self):
        contract, files = self.files()
        label = "evidence/startup-rpc-frontier"
        del files[label + ".json"]
        receipt = json.loads(files[label + ".complete.json"])
        receipt.update(actual_exit=7, outputs={"stdout": {"file": "startup-rpc-frontier.json", **pin(b"")}})
        files[label + ".complete.json"] = canonical(receipt)
        name = "evidence/" + capture.STARTUP_FRONTIERS_REPORT
        report = json.loads(files[name])
        report["observations"][1].update(status="FAILURE", reason="command_failed", response_file=None)
        files[name] = canonical(report)
        peer = self.review(contract, files)["startup_peer_frontier_diagnostic"]
        self.assertIsNone(peer["comparison"])
        self.assertEqual((peer["observations"][1]["actual_exit"], peer["observations"][1]["output_complete"]),
                         (7, True))
        files[label + ".complete.json"] = canonical({**receipt, "actual_exit": 0})
        with self.assertRaisesRegex(Refused, "review_startup_peer_failure"):
            self.review(contract, files)

    def test_peer_reports_are_optional_for_historical_archives(self):
        contract, files = PostSyncFrontierReviewTests.files()
        result = self.review(contract, files)
        self.assertNotIn("startup_peer_frontier_diagnostic", result)


class ReviewTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.contract, cls.files = accepted_files()

    def review(self, raw, contract=None, archive_pin=None, run=RUN, *, include_resources=False):
        return review.review_stream(io.BytesIO(raw), archive_pin or pin(raw), SOURCE, run,
                                    contract or self.contract, ROOT, include_resources=include_resources)

    def hosted_review(self, raw, *, conclusion="success", execution="success", archive_sha256=None,
                      include_resources=False, contract=None):
        contract = contract or self.contract
        run, jobs, artifact = hosted_metadata()
        run["conclusion"] = jobs["jobs"][0]["conclusion"] = conclusion
        jobs["jobs"][0]["steps"][0]["conclusion"] = execution
        artifact.update(size_in_bytes=len(raw), digest="sha256:" + (archive_sha256 or pin(raw)["sha256"]))
        out, error = io.BytesIO(), io.StringIO()
        args = ["review-hosted", "--expect-source-revision", SOURCE, "--expect-run-id", str(RUN),
                "--expect-artifact-id", str(ARTIFACT), "--expect-contract-sha256", contract.sha256]
        if include_resources:
            args.append("--include-resources")
        with tempfile.TemporaryDirectory(prefix="owned-hosted-review-") as directory:
            root = Path(directory)
            archive = root / "original.zip"
            archive.write_bytes(raw)
            args.extend(("--archive", str(archive)))
            for name, row in zip(("run", "jobs", "artifact"), (run, jobs, artifact)):
                path = root / (name + ".json")
                path.write_bytes(canonical(row))
                args.extend(("--" + name + "-metadata", str(path)))
            with patch.object(review.model, "read_contract", return_value=contract):
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

    def test_hosted_gateway_refusal_checks_the_opening_once_and_retains_the_mismatch(self):
        _, files = accepted_files(gateway_matches=False)
        opening_request = "evidence/rpc-02.request.json"
        files[opening_request] = canonical(
            {"jsonrpc": "2.0", "id": 2, "method": "ledger.getMomentumsByHeight", "params": [1, 3]})
        with patch.object(zipfile.ZipFile, "extractall", side_effect=AssertionError), \
                patch.object(review, "recorded_opening", wraps=review.recorded_opening) as opening:
            code, result, error = self.hosted_review(make_archive(files), conclusion="failure", execution="failure")
        opening.assert_called_once()
        self.assertEqual(code, 1, error)
        self.assertEqual(result["status"], "HOSTED_RECORDED_NON_ACCEPTING_OUTCOME")
        archived = result["archive_review"]
        self.assertEqual(archived["recorded_terminal_outcome"], "REFUSED")
        self.assertIsNone(archived["comparison"])
        self.assertNotIn("recorded_consumer_failure", archived)
        observation = archived["candidate_opening_observation"]
        self.assertEqual(observation["request"], pin(files[opening_request]))
        self.assertFalse(observation["accepted_header_authority"])
        mismatch = archived["recorded_gateway_mismatch"]
        self.assertFalse(mismatch["gateway_stored_fields_match"])
        self.assertEqual(mismatch["gateway_stored_fields_compared"], 17)
        self.assertEqual(mismatch["three_membership_proofs_checked"], 3)
        self.assertEqual(mismatch["typed_rows_checked"], 3)
        self.assertEqual(archived["materialized_bytes"], 0)
        self.assertFalse(archived["native_consumer_reexecuted"])
        self.assertFalse(result["new_devnet_acceptance_established"])

    def test_terminal_gateway_result_must_agree_with_the_recomputed_comparison(self):
        _, mismatch = accepted_files(gateway_matches=False)
        for source, outcome, reason in ((self.files, "REFUSED", "gateway_stored_fields_differ"),
                                        (mismatch, "DEVNET_CONSUMER_ACCEPTED", None)):
            with self.subTest(outcome=outcome):
                files = dict(source)
                path = "evidence/terminal.json"
                final = json.loads(files[path])
                final.update(outcome=outcome, reason=reason)
                files[path] = canonical(final)
                with self.assertRaisesRegex(Refused, "review_consumer_gateway"):
                    self.review(make_archive(files))

    def test_gateway_refusal_requires_consumer_stage_completed_cli_and_same_context(self):
        _, mismatch = accepted_files(gateway_matches=False)
        for filename, changes, reason in (
                ("terminal.json", {"stage": "closed-ledger"}, "review_gateway_refusal_scope"),
                ("terminal.json", {"outcome": "UNKNOWN"}, "review_gateway_refusal_scope"),
                ("consume-query.complete.json", {"actual_exit": 2}, "review_recorded_command_completion"),
                ("consume-query.complete.json", {"output_complete": False}, "review_recorded_command_completion"),
                ("query-context-pins.json", {"context": "a" * 64}, "review_query_inputs")):
            with self.subTest(file=filename, reason=reason), self.assertRaisesRegex(Refused, reason):
                files = dict(mismatch)
                path = "evidence/" + filename
                row = json.loads(files[path])
                row.update(changes)
                files[path] = canonical(row)
                self.review(make_archive(files))
        del mismatch["evidence/" + review.OPENING_FILE]
        with self.assertRaisesRegex(Refused, "review_consumer_opening"):
            self.review(make_archive(mismatch))

    def test_gateway_refusal_with_unconfirmed_closure_preserves_opening_and_terminal(self):
        _, files = accepted_files(gateway_matches=False)
        path = "evidence/terminal.json"
        final = json.loads(files[path])
        final["owned_runtime_observed_closed"] = False
        files[path] = canonical(final)
        result = self.review(make_archive(files))
        self.assertEqual(result["recorded_terminal_outcome"], "REFUSED")
        self.assertIsNone(result["comparison"])
        self.assertIn("candidate_opening_observation", result)
        self.assertNotIn("recorded_gateway_mismatch", result)

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
        self.assertNotIn("candidate_opening_observation", result)

    def opening_files(self, outcome="FAILURE"):
        files = {"evidence/" + name: self.files["evidence/" + name] for name in (
            review.OPENING_FILE, "rpc-02.started.json", "rpc-02.complete.json")}
        files["evidence/terminal.json"] = canonical({
            **terminal(outcome, self.contract), "stage": "fixture-configuration"})
        return files

    def test_current_reviews_bind_the_opening_and_both_fixture_commands(self):
        for gateway_matches in (True, False):
            contract, files = accepted_files(gateway_matches=gateway_matches, terminal_format=model.TERMINAL_FORMAT)
            with self.subTest(gateway_matches=gateway_matches):
                report = self.review(make_archive(files), contract)
                comparison = report["comparison" if gateway_matches else "recorded_gateway_mismatch"]
                self.assertEqual(comparison["gateway_stored_fields_match"], gateway_matches)
                self.assertEqual(report["candidate_opening_proof"]["presence"], "absent")
                self.assertEqual(report["candidate_opening_proof"]["header"]["height"], 3)
                self.assertEqual(comparison["request"]["height"], 4)
                self.assertFalse(report["recorded_opening_signatures"]["producer_schedule_verified"])
                self.assertEqual(report["recorded_fixture_commands"], {
                    label: {"start": pin(files[f"evidence/{label}.started.json"]),
                            "completion": pin(files[f"evidence/{label}.complete.json"])}
                    for label in ("fixture-configure", "fixture-deposit")})
                self.assertFalse(report["new_devnet_acceptance_established"])
                self.assertEqual(report["materialized_bytes"], 0)
                for filename, reason in (
                        (capture.OPENING_PROOF_FILE, "review_opening_signature_context"),
                        (capture.OPENING_SIGNATURE_REPORT, "review_consumer_opening_gate"),
                        ("opening-signature-h3.complete.json", "review_member_bound"),
                        ("fixture-configure.started.json", "review_member_bound"),
                        ("fixture-deposit.complete.json", "review_member_bound")):
                    with self.subTest(filename=filename), self.assertRaisesRegex(Refused, reason):
                        missing = dict(files)
                        del missing["evidence/" + filename]
                        self.review(make_archive(missing), contract)

    def test_current_reviews_require_completed_fixture_commands_and_bounded_stream_pins(self):
        contract, files = accepted_files(terminal_format=model.TERMINAL_FORMAT)
        path = "evidence/fixture-deposit.complete.json"
        for changes, reason in (
                ({"actual_exit": 1}, "review_recorded_command_completion"),
                ({"output_complete": False}, "review_recorded_command_completion"),
                ({"process_group_quiescent": False}, "review_recorded_command_completion"),
                ({"process_group": 43}, "review_recorded_command_start"),
                ({"outputs": {"stdout": {"file": "fixture-deposit.stdout", **pin(b"")}}},
                 "review_fixture_output_pins")):
            with self.subTest(changes=changes), self.assertRaisesRegex(Refused, reason):
                updated = canonical({**json.loads(files[path]), **changes})
                self.review(make_archive({**files, path: updated}), contract)
        for changes, reason in (
                ({"file": "fixture-configure.stdout"}, "review_fixture_output_pins"),
                ({"bytes": model.FIXTURE_OUTPUT_BYTES + 1}, "integer_bounds"),
                ({"sha256": "invalid"}, "digest_format")):
            with self.subTest(changes=changes), self.assertRaisesRegex(Refused, reason):
                receipt = json.loads(files[path])
                receipt["outputs"]["stdout"].update(changes)
                self.review(make_archive({**files, path: canonical(receipt)}), contract)

    def test_legacy_membership_does_not_supply_the_current_opening_baseline(self):
        contract, files = accepted_files(terminal_format=model.TERMINAL_FORMAT_V2)
        legacy = self.review(make_archive(files), contract)
        self.assertEqual(legacy["status"], "RECORDED_CONSUMER_BYTES_MATCH")
        self.assertEqual(legacy["candidate_opening_proof"]["presence"], "present")
        terminal_path = "evidence/terminal.json"
        current = canonical({**json.loads(files[terminal_path]), "format": model.TERMINAL_FORMAT})
        with self.assertRaisesRegex(Refused, "review_opening_batch_scope"):
            self.review(make_archive({**files, terminal_path: current}), contract)

    def test_current_present_opening_is_replayed_only_as_a_pre_fixture_refusal(self):
        contract, legacy = accepted_files(terminal_format=model.TERMINAL_FORMAT_V2)
        terminal_path = "evidence/terminal.json"
        proof_path = "evidence/" + capture.OPENING_PROOF_FILE
        opening_paths = {"evidence/" + capture.OPENING_FILE, proof_path}
        files = {path: raw for path, raw in legacy.items()
                 if path in opening_paths or path.startswith(("evidence/rpc-02.", "evidence/rpc-03."))}
        refusal = {**terminal("REFUSED", contract), "format": model.TERMINAL_FORMAT,
                   "stage": "opening-proof", "reason": capture.OPENING_BATCH_ALREADY_PRESENT}
        files[terminal_path] = canonical(refusal)
        report = self.review(make_archive(files), contract)
        self.assertEqual(report["status"], "RECORDED_NON_ACCEPTING_OUTCOME")
        self.assertEqual(report["candidate_opening_proof"]["presence"], "present")
        self.assertFalse(report["candidate_opening_proof"]["accepted_header_authority"])
        self.assertIsNone(report["comparison"])
        for change in ({"stage": "query-inputs"}, {"outcome": "FAILURE"}, {"reason": "command_failed"},
                       {"format": model.TERMINAL_FORMAT_V2}):
            with self.subTest(change=change), self.assertRaisesRegex(Refused, "review_opening_batch_scope"):
                self.review(make_archive({**files, terminal_path: canonical({**refusal, **change})}), contract)
        later = "evidence/fixture-configure.started.json"
        with self.assertRaisesRegex(Refused, "review_opening_batch_scope"):
            self.review(make_archive({**files, later: legacy[later]}), contract)
        del files[proof_path]
        with self.assertRaisesRegex(Refused, "review_opening_proof_refusal_evidence"):
            self.review(make_archive(files), contract)

    def test_current_early_failure_can_lack_preparation_receipts(self):
        files = self.opening_files()
        path = "evidence/terminal.json"
        files[path] = canonical({**json.loads(files[path]), "format": model.TERMINAL_FORMAT,
                                 "stage": "opening-proof"})
        report = self.review(make_archive(files))
        self.assertEqual(report["recorded_terminal_outcome"], "FAILURE")
        self.assertIsNone(report["comparison"])
        self.assertNotIn("recorded_fixture_commands", report)

    def fixture_timeout_files(self, stage="fixture-deposit", *, progress_source=False):
        contract, original = accepted_files(terminal_format=model.TERMINAL_FORMAT)
        if progress_source:
            data = contract.data
            selected = model.read_contract(HERE / "reference-gas-renewal-1-contract.json")
            data["sources"]["devnet"] = selected.data["sources"]["devnet"]
            raw = canonical(data)
            contract = model.Contract(raw, pin(raw)["sha256"])
        prefixes = ("evidence/opening-", "evidence/rpc-02.", "evidence/rpc-03.", "evidence/fixture-configure.")
        if stage == "fixture-deposit":
            prefixes += ("evidence/fixture-deposit.",)
        files = {name: raw for name, raw in original.items() if name.startswith(prefixes)}
        files["evidence/terminal.json"] = canonical({**terminal("UNKNOWN", contract),
            "format": model.TERMINAL_FORMAT, "stage": stage})
        label = "fixture-deposit" if stage == "fixture-deposit" else "fixture-configure"
        path = f"evidence/{label}.complete.json"
        receipt = json.loads(files[path])
        receipt.update(reason="timeout", actual_exit=143, output_complete=False, elapsed_nanoseconds=420_000_000_000)
        files[path] = canonical(receipt)
        return contract, files, label, path

    def test_fixture_timeout_preserves_exit_and_leaves_submission_unverified(self):
        for stage in ("fixture-configuration", "fixture-deposit"):
            with self.subTest(stage=stage):
                contract, files, label, path = self.fixture_timeout_files(stage)
                result = self.review(make_archive(files), contract)
                self.assertEqual(result["recorded_fixture_timeout"], {"stage": stage, "command": label,
                    "reason": "timeout", "actual_exit": 143, "output_complete": False,
                    "elapsed_nanoseconds": 420_000_000_000, "process_group_quiescent": True,
                    "completion": pin(files[path]), "transaction_submission_verified": False})
                self.assertEqual(result["recorded_terminal_outcome"], "UNKNOWN")
                self.assertIsNone(result["comparison"])
                self.assertNotIn("recorded_fixture_commands", result)

    def test_hosted_review_opt_in_retains_sampled_resources_and_timeout(self):
        contract, files, _, deposit_path = self.fixture_timeout_files()
        configure_path = "evidence/fixture-configure.complete.json"
        files[configure_path] = canonical({**json.loads(files[configure_path]), "elapsed_nanoseconds": 53})
        budget_path = "evidence/budget-report.json"
        files[budget_path] = canonical({"format": "owned-devnet-budget-observation/v1",
            "initial": {"free_bytes": 900}, "samples": 11, "peak_observed_new_disk_bytes": 72,
            "last_sample": {"elapsed_seconds": 601.25, "free_bytes": 854, "observed_new_disk_bytes": 46},
            "cleanup_reserve_seconds": 300})
        raw = make_archive(files)
        code, default, error = self.hosted_review(raw, conclusion="failure", execution="failure", contract=contract)
        self.assertEqual(code, 1, error)
        with patch.object(review.inputs, "_hash_stream", wraps=review.inputs._hash_stream) as digest, \
                patch.object(zipfile.ZipFile, "extractall", side_effect=AssertionError):
            code, result, error = self.hosted_review(raw, conclusion="failure", execution="failure",
                                                    include_resources=True, contract=contract)
        self.assertEqual(code, 1, error)
        digest.assert_called_once()
        observations = result["archive_review"].pop("recorded_resource_observations")
        self.assertEqual(result, default)
        self.assertEqual(observations, {"fixture_commands": {
            "fixture-configure": {"actual_exit": 0, "output_complete": True, "process_group_quiescent": True,
                                  "elapsed_nanoseconds": 53, "completion": pin(files[configure_path])},
            "fixture-deposit": {"actual_exit": 143, "output_complete": False, "process_group_quiescent": True,
                                "elapsed_nanoseconds": 420_000_000_000, "completion": pin(files[deposit_path])}},
            "sampled_disk": {"samples": 11, "initial_free_bytes": 900, "last_sample_elapsed_seconds": 601.25,
                             "peak_observed_new_disk_bytes": 72, "observation": pin(files[budget_path])}})

    def test_resource_projection_handles_missing_evidence_and_refuses_inconsistent_values(self):
        empty = self.review(make_archive(self.opening_files()), include_resources=True)
        self.assertEqual(empty["recorded_resource_observations"], {"fixture_commands": {}, "sampled_disk": None})
        unbound = self.review(make_archive({"evidence/terminal.json": canonical(terminal("UNKNOWN"))}),
                              include_resources=True)
        self.assertIsNone(unbound["recorded_resource_observations"])
        contract, files, _, _ = self.fixture_timeout_files()
        configure_path = "evidence/fixture-configure.complete.json"
        configure = {**json.loads(files[configure_path]), "elapsed_nanoseconds": 53}
        budget_path = "evidence/budget-report.json"
        budget = {"format": "owned-devnet-budget-observation/v1", "initial": {"free_bytes": 900},
                  "samples": 2, "peak_observed_new_disk_bytes": 72, "cleanup_reserve_seconds": 300,
                  "last_sample": {"elapsed_seconds": 601.25, "free_bytes": 854, "observed_new_disk_bytes": 46}}
        files.update({configure_path: canonical(configure), budget_path: canonical(budget)})
        for member, raw, reason in (
            (configure_path, canonical({**configure, "process_group": 43}), "review_recorded_command_start"),
            (configure_path, canonical({**configure, "elapsed_nanoseconds": True}), "integer_bounds"),
            (budget_path, canonical({**budget, "peak_observed_new_disk_bytes": 45}), "review_resource_budget"),
            (budget_path, canonical({**budget, "last_sample": {**budget["last_sample"], "free_bytes": 855}}),
             "review_resource_budget"),
            (budget_path, canonical(budget).replace(b'"samples": 2', b'"samples": 3, "samples": 2'),
             "review_resource_budget_encoding"),
            (budget_path, canonical(budget).replace(b"601.25", b"1e999"), "review_resource_budget_encoding"),
        ):
            with self.subTest(member=member, reason=reason), self.assertRaisesRegex(Refused, reason):
                self.review(make_archive({**files, member: raw}), contract, include_resources=True)

    def setup_resource_files(self):
        contract, files, _, _ = self.fixture_timeout_files()
        config = "evidence/fixture-configure"
        started = json.loads(files[config + ".started.json"])
        completed = json.loads(files[config + ".complete.json"])
        for label, duration in (("docker-020-build-node", 59), ("docker-022-build-executor", 29),
                                ("package-npm-ci", 39)):
            files[f"evidence/{label}.started.json"] = canonical({**started, "label": label})
            files[f"evidence/{label}.complete.json"] = canonical({
                **completed, "label": label, "elapsed_nanoseconds": duration * 10**9})
        files[config + ".complete.json"] = canonical({**completed, "elapsed_nanoseconds": 53})
        return contract, files

    def test_resource_projection_reads_bound_setup_receipts_without_extracting(self):
        contract, files = self.setup_resource_files()
        raw = make_archive(files)
        default = self.review(raw, contract)
        with patch.object(zipfile.ZipFile, "extractall", side_effect=AssertionError):
            reported = self.review(raw, contract, include_resources=True)
        setup = reported.pop("recorded_resource_observations")["setup_commands"]
        self.assertEqual(reported, default)
        self.assertEqual(set(setup), {"node-image-build", "executor-image-build", "npm-ci"})
        for stage, label, seconds in (("node-image-build", "docker-020-build-node", 59),
                                      ("executor-image-build", "docker-022-build-executor", 29),
                                      ("npm-ci", "package-npm-ci", 39)):
            self.assertEqual(setup[stage], {"label": label, "actual_exit": 0, "output_complete": True,
                "process_group_quiescent": True, "elapsed_nanoseconds": seconds * 10**9,
                "completion": pin(files[f"evidence/{label}.complete.json"])})

    def test_resource_projection_refuses_ambiguous_setup_and_preserves_incomplete_exit(self):
        contract, files = self.setup_resource_files()
        node = "evidence/docker-020-build-node.complete.json"
        npm = "evidence/package-npm-ci.complete.json"
        receipt = json.loads(files[npm])
        for changed, reason in (
            ({**files, "evidence/docker-040-build-node.complete.json": files[node]},
             "review_resource_build_duplicate"),
            ({**files, npm: canonical({**receipt, "process_group": 43})}, "review_recorded_command_start"),
            ({name: raw for name, raw in files.items() if name != "evidence/package-npm-ci.started.json"},
             "review_member_bound"),
            ({**files, npm: canonical({**receipt, "elapsed_nanoseconds": True})}, "integer_bounds"),
        ):
            with self.subTest(reason=reason), self.assertRaisesRegex(Refused, reason):
                self.review(make_archive(changed), contract, include_resources=True)
        for launched in ("STARTED", "NOT_STARTED"):
            with self.subTest(launched=launched):
                changed = {**files, npm: canonical({
                    **receipt, "launch_outcome": launched, "reason": "timeout",
                    "actual_exit": 143 if launched == "STARTED" else None, "output_complete": False})}
                report = self.review(make_archive(changed), contract, include_resources=True)
                setup = report["recorded_resource_observations"]["setup_commands"]
                if launched == "STARTED":
                    self.assertEqual(setup["npm-ci"]["actual_exit"], 143)
                    self.assertIs(setup["npm-ci"]["output_complete"], False)
                else:
                    self.assertNotIn("npm-ci", setup)
                self.assertEqual(report["recorded_terminal_outcome"], "UNKNOWN")
                self.assertIsNone(report["comparison"])

    def test_fixture_timeout_requires_start_binding_prior_configuration_and_no_consumer(self):
        contract, files, _, path = self.fixture_timeout_files()
        invalid = (
            ({**files, path: canonical({**json.loads(files[path]), "process_group": 43})},
             "review_recorded_command_start"),
            ({k: v for k, v in files.items() if k != "evidence/fixture-configure.complete.json"},
             "review_member_bound"),
            ({**files, path: canonical({**json.loads(files[path]), "output_complete": True})},
             "review_fixture_timeout_scope"),
            ({**files, "evidence/consume-query.started.json": self.files["evidence/consume-query.started.json"]},
             "review_fixture_timeout_scope"),
        )
        for changed, reason in invalid:
            with self.subTest(reason=reason), self.assertRaisesRegex(Refused, reason):
                self.review(make_archive(changed), contract)

    def test_fixture_progress_preserves_the_timeout_and_unverified_submission(self):
        contract, files, _, path = self.fixture_timeout_files(progress_source=True)
        for markers in (None, [], ["vault_artifacts", "vault_deploy_started"]):
            with self.subTest(markers=markers):
                summary = {"format": fixture_progress.FORMAT, "reported_checkpoints": markers,
                           "stdout": json.loads(files[path])["outputs"]["stdout"]}
                archive = make_archive({**files, "evidence/" + fixture_progress.REPORT: canonical(summary)})
                result = self.review(archive, contract)
                timeout = result["recorded_fixture_timeout"]
                self.assertEqual(timeout["progress"], {**summary, "original_stdout_independently_rechecked": False})
                self.assertFalse(timeout["transaction_submission_verified"])
                self.assertEqual(result["recorded_terminal_outcome"], "UNKNOWN")
                self.assertIsNone(result["comparison"])

    def test_configuration_progress_is_bound_to_the_configuration_timeout(self):
        contract, files, _, path = self.fixture_timeout_files("fixture-configuration", progress_source=True)
        receipt = json.loads(files[path])
        summary = {"format": fixture_progress.CONFIGURE_FORMAT,
                   "reported_checkpoints": ["register_domain_received", "set_asset_config_received"],
                   "stdout": receipt["outputs"]["stdout"]}
        report = "evidence/" + fixture_progress.CONFIGURE_REPORT
        result = self.review(make_archive({**files, report: canonical(summary)}), contract)
        timeout = result["recorded_fixture_timeout"]
        self.assertEqual(timeout["progress"], {**summary, "original_stdout_independently_rechecked": False})
        self.assertEqual(timeout["command"], "fixture-configure")
        self.assertFalse(timeout["transaction_submission_verified"])
        self.assertEqual(result["recorded_terminal_outcome"], "UNKNOWN")
        self.assertIsNone(result["comparison"])
        for markers in (list(reversed(summary["reported_checkpoints"])), ["vault_artifacts"],
                        ["register_domain_received"] * 2, ["already_configured", "configured"]):
            changed = {**files, report: canonical({**summary, "reported_checkpoints": markers})}
            with self.subTest(markers=markers), self.assertRaisesRegex(Refused, "review_fixture_progress_checkpoints"):
                self.review(make_archive(changed), contract)
        deposit, deposit_files, _, _ = self.fixture_timeout_files(progress_source=True)
        with self.assertRaisesRegex(Refused, "review_fixture_progress_scope"):
            self.review(make_archive({**deposit_files, report: canonical(summary)}), deposit)

    def test_fixture_progress_requires_the_selected_source_and_a_bound_timeout_prefix(self):
        contract, files, _, path = self.fixture_timeout_files(progress_source=True)
        receipt = json.loads(files[path])
        summary = {"format": fixture_progress.FORMAT, "reported_checkpoints": ["vault_artifacts"],
                   "stdout": receipt["outputs"]["stdout"]}
        report = "evidence/" + fixture_progress.REPORT
        invalid = (
            ({**files, report: canonical({**summary, "reported_checkpoints": ["deposit_step"]})},
             contract, "review_fixture_progress_checkpoints"),
            ({**files, report: canonical({**summary, "original_stdout": "private diagnostic"})},
             contract, "review_fixture_progress_fields"),
            ({**files, report: canonical({**summary, "stdout": {**summary["stdout"], "sha256": "1" * 64}})},
             contract, "review_fixture_progress_stdout"),
            ({**files, report: canonical(summary), path: canonical({**receipt, "process_group_quiescent": False})},
             contract, "review_fixture_progress_checkpoints"),
            ({**files, report: canonical(summary), path: canonical({**receipt, "reason": "guard_refused"})},
             contract, "review_fixture_progress_scope"),
            ({**files, report: canonical(summary), "evidence/fixture-deposit.stderr": b"private"},
             contract, "review_member_selection"),
        )
        other, other_files, _, _ = self.fixture_timeout_files()
        invalid += (({**other_files, report: canonical(summary)}, other, "review_fixture_progress_scope"),)
        for changed, selected, reason in invalid:
            with self.subTest(reason=reason), self.assertRaisesRegex(Refused, reason):
                self.review(make_archive(changed), selected)

    def closed_opening_files(self, stage="fixture-deposit"):
        contract, files, _, timeout_path = self.fixture_timeout_files(stage, progress_source=True)
        _, original = accepted_files(terminal_format=model.TERMINAL_FORMAT)
        files["evidence/terminal.json"] = canonical({
            **json.loads(files["evidence/terminal.json"]), "owned_runtime_observed_closed": True})
        files.update({name: raw for name, raw in original.items() if name.startswith("transport/input-parent-oracle")})
        closure = json.loads(original["evidence/owned-container-cleanup.json"])
        if stage == "fixture-configuration":
            closure["containers"] = [row for row in closure["containers"] if row["service"] in model.NODE_SERVICES]
        files["evidence/owned-container-cleanup.json"] = canonical(closure)
        files["evidence/dispatch-selection.json"] = canonical({
            **json.loads(original["evidence/dispatch-selection.json"]), "contract_sha256": contract.sha256})
        opening_rows = json.loads(files["evidence/" + capture.OPENING_FILE])["result"]["list"]
        opening = capture.opening_headers(contract, opening_rows)
        frontier_row = json.loads(original["evidence/provider.json"])["momentums"][-1]
        frontier = capture.Header.read(frontier_row, contract.data["selection"]["chain_id"]).identifier()
        files["evidence/rpc-09.request.json"] = canonical(
            {"jsonrpc": "2.0", "id": 9, "method": "ledger.getFrontierMomentum", "params": []})
        last = "rpc-09.frontier.json"
        raw = canonical({"jsonrpc": "2.0", "id": 9, "result": frontier_row})
        files["evidence/" + last] = raw
        files["evidence/rpc-09.started.json"] = canonical({
            **json.loads(original["evidence/rpc-02.started.json"]), "label": "rpc-09"})
        files["evidence/rpc-09.complete.json"] = canonical({
            **json.loads(original["evidence/rpc-02.complete.json"]), "label": "rpc-09",
            "outputs": {"stdout": {"file": last, **pin(raw)}}})
        ((request, _),) = capture.oracle_requests(contract, opening, frontier)
        request_file = "parent-oracle-01.request.json"
        response_file = "parent-oracle-01.stdout"
        oracle = json.loads(original["evidence/" + response_file])
        oracle.update(rows=oracle["rows"][:2], request_sha256=pin(request)["sha256"])
        schedule = capture.oracle_schedule(contract, opening, [oracle], frontier)
        response = canonical(oracle)
        stdout = {"file": response_file, **pin(response)}
        files.update({"evidence/" + request_file: request, "evidence/" + response_file: response,
            "evidence/parent-oracle-01.started.json": original["evidence/parent-oracle-01.started.json"],
            "evidence/parent-oracle-01.complete.json": canonical({
                **json.loads(original["evidence/parent-oracle-01.complete.json"]), "outputs": {"stdout": stdout}})})
        provenance = {**json.loads(original["evidence/closed-ledger-provenance.json"]),
            "engine_id": "e" * 64, "reader_source_sha256": "f" * 64, "schedule_hash": schedule["schedule_hash"],
            "oracle_reports": [{"request": {"file": request_file, **pin(request)}, "stdout": stdout}]}
        files["evidence/" + capture.CLOSED_OPENING_REPORT] = canonical({
            "format": "owned-devnet-closed-opening-authorization/v1",
            "frontier_request_id": 9, "closed_ledger": provenance})
        return contract, files, timeout_path, opening

    def test_closed_opening_replays_only_two_parents_at_the_later_closed_frontier(self):
        for stage in ("fixture-configuration", "fixture-deposit"):
            with self.subTest(stage=stage):
                contract, files, _, opening = self.closed_opening_files(stage)
                report = self.review(make_archive(files), contract)
                observed = report["recorded_closed_opening_authorization"]
                self.assertEqual(observed["frontier_request_id"], 9)
                self.assertEqual(observed["closed_ledger_frontier"]["height"], 5)
                self.assertEqual(observed["target_headers"], [header.identifier() for header in opening[1:]])
                self.assertFalse(observed["accepted_header_authority"])
                self.assertEqual(report["recorded_terminal_outcome"], "UNKNOWN")
                self.assertFalse(report["recorded_fixture_timeout"]["transaction_submission_verified"])
                self.assertIsNone(report["comparison"])

    def test_configuration_and_deposit_openings_require_their_exact_closed_rosters(self):
        member = "evidence/owned-container-cleanup.json"
        config_contract, configured, _, _ = self.closed_opening_files("fixture-configuration")
        deposit_contract, deposited, _, _ = self.closed_opening_files()
        four = json.loads(configured[member])
        rows = four["containers"]
        wrong_roles = canonical({**four, "containers": [*rows[:-1], {**rows[-1], "service": "executor"}]})
        wrong_id = canonical({**four, "containers": [
            {**row, "id": "f" * 64} if row["service"] == "rpc" else row for row in rows]})
        for contract, files, different in ((config_contract, configured, deposited[member]),
                (deposit_contract, deposited, configured[member]), (config_contract, configured, wrong_roles),
                (config_contract, configured, wrong_id)):
            with self.assertRaisesRegex(Refused, "review_owned_closure"):
                self.review(make_archive({**files, member: different}), contract)

    def test_closed_opening_requires_quiescence_owned_closure_and_bound_inputs(self):
        contract, files, timeout_path, _ = self.closed_opening_files()
        report_path = "evidence/" + capture.CLOSED_OPENING_REPORT
        terminal_path = "evidence/terminal.json"
        for path, changed, reason in (
                (timeout_path, {"process_group_quiescent": False}, "review_closed_opening_scope"),
                (terminal_path, {"owned_runtime_observed_closed": False}, "review_closed_opening_scope"),
                (report_path, {"frontier_request_id": 8}, "review_closed_opening_frontier_selection")):
            altered = canonical({**json.loads(files[path]), **changed})
            with self.subTest(path=path), self.assertRaisesRegex(Refused, reason):
                self.review(make_archive({**files, path: altered}), contract)
        path = "transport/input-parent-oracle-selection.json"
        with self.assertRaisesRegex(Refused, "review_component_binding"):
            self.review(make_archive({**files, path: canonical({
                **json.loads(files[path]), "artifact_id": 1})}), contract)

    def test_closed_opening_rechecks_request_frontier_and_evidence_bound_parent(self):
        contract, files, _, _ = self.closed_opening_files()
        report_path = "evidence/" + capture.CLOSED_OPENING_REPORT
        request_path = "evidence/parent-oracle-01.request.json"
        request = json.loads(files[request_path])
        request["expected_frontier"]["hash"] = "1" * 64
        with self.assertRaisesRegex(Refused, "review_oracle_request"):
            self.review(make_archive({**files, request_path: canonical(request)}), contract)
        stdout = "evidence/parent-oracle-01.stdout"
        raw = json.loads(files[stdout])
        raw["rows"][1]["parent"]["hash"] = "2" * 64
        raw = canonical(raw)
        pin_row = {"file": "parent-oracle-01.stdout", **pin(raw)}
        receipt = "evidence/parent-oracle-01.complete.json"
        summary = json.loads(files[report_path])
        summary["closed_ledger"]["oracle_reports"][0]["stdout"] = pin_row
        with self.assertRaisesRegex(Refused, "closed_oracle_header_or_parent_binding"):
            self.review(make_archive({**files, stdout: raw, report_path: canonical(summary),
                receipt: canonical({**json.loads(files[receipt]), "outputs": {"stdout": pin_row}})}), contract)

    def test_replays_retained_opening_after_a_nonaccepting_terminal_outcome(self):
        for outcome in ("FAILURE", "REFUSED", "UNKNOWN"):
            with self.subTest(outcome=outcome):
                files = self.opening_files(outcome)
                result = self.review(make_archive(files, flat=True))
                observation = result["candidate_opening_observation"]
                body = files["evidence/" + review.OPENING_FILE]
                headers = json.loads(body)["result"]["list"]
                self.assertEqual(result["status"], "RECORDED_NON_ACCEPTING_OUTCOME")
                self.assertEqual(result["recorded_terminal_outcome"], outcome)
                self.assertIsNone(result["comparison"])
                self.assertEqual(observation["request_id"], 2)
                self.assertIsNone(observation["request"])
                self.assertEqual(observation["response"], pin(body))
                self.assertEqual(observation["headers"],
                    [{**{key: header[key] for key in ("height", "hash", "version", "timestamp")},
                      "state_root": header["stateRoot"]} for header in headers])
                self.assertFalse(observation["signature_verified"])
                self.assertFalse(observation["accepted_header_authority"])
                self.assertFalse(result["new_devnet_acceptance_established"])
                self.assertEqual(result["materialized_bytes"], 0)

    def test_hosted_failure_retains_the_opening_observation_and_failure_exit(self):
        raw = make_archive(self.opening_files())
        code, result, error = self.hosted_review(raw, conclusion="failure", execution="failure")
        self.assertEqual(code, 1, error)
        self.assertEqual(result["status"], "HOSTED_RECORDED_NON_ACCEPTING_OUTCOME")
        self.assertEqual(result["archive_review"]["candidate_opening_observation"]["headers"][-1]["height"], 3)
        self.assertIsNone(result["archive_review"]["comparison"])
        self.assertFalse(result["new_devnet_acceptance_established"])

    def consumer_failure_files(self):
        files = self.opening_files()
        files["evidence/terminal.json"] = canonical({**terminal("FAILURE", self.contract),
            "stage": "consumer", "reason": "consumer_reported_failure"})
        output = consumer_failure_fixture()
        name = capture.CONSUMER_STDOUT
        files["evidence/" + name] = output
        files["evidence/consume-query.started.json"] = self.files["evidence/consume-query.started.json"]
        receipt = json.loads(self.files["evidence/consume-query.complete.json"])
        receipt["actual_exit"] = 2
        receipt["outputs"]["stdout"] = {"file": name, **pin(output)}
        files["evidence/consume-query.complete.json"] = canonical(receipt)
        return files

    def test_hosted_consumer_failure_rechecks_the_original_capture(self):
        files = self.consumer_failure_files()
        code, result, error = self.hosted_review(make_archive(files), conclusion="failure", execution="failure")
        self.assertEqual(code, 1, error)
        archive = result["archive_review"]
        expected = {"file": capture.CONSUMER_STDOUT, **pin(files["evidence/" + capture.CONSUMER_STDOUT])}
        self.assertEqual(archive["recorded_consumer_failure"], {
            **capture.consumer_failure(consumer_failure_fixture(), 2), "stdout": expected})
        self.assertEqual(archive["recorded_terminal_outcome"], "FAILURE")
        self.assertEqual(archive["materialized_bytes"], 0)
        self.assertIsNone(archive["comparison"])
        self.assertFalse(result["new_devnet_acceptance_established"])

    def test_consumer_failure_cannot_replace_run_receipt_or_start_binding(self):
        for filename, changes, reason in (
                ("terminal.json", {"stage": "nodes"}, "review_consumer_failure_scope"),
                ("terminal.json", {"outcome": "UNKNOWN"}, "review_consumer_failure_scope"),
                ("consume-query.complete.json", {"actual_exit": 1}, "consumer_failure_scope"),
                ("consume-query.complete.json", {"output_complete": False}, "review_recorded_command_completion"),
                ("consume-query.started.json", {"process_group": 43}, "review_recorded_command_start")):
            with self.subTest(file=filename, changes=changes), self.assertRaisesRegex(Refused, reason):
                files = self.consumer_failure_files()
                path = "evidence/" + filename
                files[path] = canonical({**json.loads(files[path]), **changes})
                self.review(make_archive(files))
        with self.assertRaisesRegex(Refused, "review_consumer_failure_scope"):
            files = self.consumer_failure_files()
            del files["evidence/" + capture.CONSUMER_STDOUT]
            self.review(make_archive(files))

    def test_opening_version_refusal_requires_the_bound_request_response_and_terminal(self):
        files = self.opening_files("REFUSED")
        _, profile = capture.selected_profile(self.contract, ROOT)
        key = checks.ledger_keys(profile, 0)["batch_entry"]
        response = (b'{"jsonrpc":"2.0","id":3,"error":{"code":-32000,'
                    b'"message":"trie: no such version"}}\n')
        response_path = "evidence/" + capture.OPENING_PROOF_FILE
        files.update({
            "evidence/terminal.json": canonical({**terminal("REFUSED", self.contract),
                "stage": "opening-proof", "reason": capture.OPENING_PROOF_VERSION_UNAVAILABLE}),
            "evidence/rpc-02.request.json": canonical(
                {"jsonrpc": "2.0", "id": 2, "method": "ledger.getMomentumsByHeight", "params": [1, 3]}),
            "evidence/rpc-03.request.json": canonical({"jsonrpc": "2.0", "id": 3,
                "method": "ledger.getProof", "params": [3, base64.b64encode(key).decode("ascii")]}),
            "evidence/rpc-03.started.json": canonical({
                **json.loads(files["evidence/rpc-02.started.json"]), "label": "rpc-03"}),
            "evidence/rpc-03.complete.json": canonical({
                **json.loads(files["evidence/rpc-02.complete.json"]), "label": "rpc-03",
                "outputs": {"stdout": {"file": capture.OPENING_PROOF_FILE, **pin(response)}}}),
            response_path: response,
        })
        result = self.review(make_archive(files))
        self.assertEqual(result["recorded_terminal_outcome"], "REFUSED")
        self.assertIsNone(result["comparison"])
        self.assertEqual(result["candidate_opening_proof"]["status"], "VERSION_UNAVAILABLE")
        self.assertFalse(result["candidate_opening_proof"]["accepted_header_authority"])
        for path, changes, reason in (
                ("terminal.json", {"stage": "nodes"}, "review_opening_proof_refusal_scope"),
                ("terminal.json", {"outcome": "FAILURE"}, "review_opening_proof_refusal_scope"),
                ("terminal.json", {"reason": "command_failed"}, "review_opening_proof_refusal_scope"),
                ("rpc-03.complete.json", {"actual_exit": 28}, "review_recorded_command_completion"),
                ("rpc-03.complete.json", {"output_complete": False}, "review_recorded_command_completion"),
                ("rpc-03.request.json", {"id": 4}, "review_opening_proof_request")):
            with self.subTest(path=path, changes=changes), self.assertRaisesRegex(Refused, reason):
                path = "evidence/" + path
                changed = {**files, path: canonical({**json.loads(files[path]), **changes})}
                self.review(make_archive(changed))
        del files[response_path]
        with self.assertRaisesRegex(Refused, "review_opening_proof_refusal_evidence"):
            self.review(make_archive(files))

    def test_checks_the_exact_opening_request_when_retained(self):
        files = self.opening_files()
        path = "evidence/rpc-02.request.json"
        request = {"jsonrpc": "2.0", "id": 2, "method": "ledger.getMomentumsByHeight", "params": [1, 3]}
        files[path] = canonical(request)
        observed = self.review(make_archive(files))["candidate_opening_observation"]
        self.assertEqual(observed["request"], pin(files[path]))
        for changes in ({"params": [2, 3]}, {"id": 3}, {"method": "ledger.getFrontierMomentum"}):
            with self.subTest(changes=changes), self.assertRaisesRegex(Refused, "review_opening_request"):
                files[path] = canonical({**request, **changes})
                self.review(make_archive(files))

    def test_refuses_opening_without_a_complete_matching_command_and_run_binding(self):
        files = self.opening_files()
        receipt = "evidence/rpc-02.complete.json"
        for changes, reason in (({"actual_exit": 28}, "review_recorded_command_completion"),
                                ({"output_complete": False}, "review_recorded_command_completion"),
                                ({"process_group": 43}, "review_recorded_command_start"),
                                ({"outputs": {"stdout": {"file": review.OPENING_FILE, "bytes": 1,
                                                          "sha256": "0" * 64}}}, "review_recorded_command_stdout")):
            with self.subTest(changes=changes), self.assertRaisesRegex(Refused, reason):
                changed = {**files, receipt: canonical({**json.loads(files[receipt]), **changes})}
                self.review(make_archive(changed))
        with self.assertRaisesRegex(Refused, "review_opening_run_binding"):
            self.review(make_archive({**files, "evidence/terminal.json": canonical(terminal("UNKNOWN"))}))

    def test_opening_replay_refuses_changed_hash_and_version_order_even_with_matching_payload_pins(self):
        for mutate, reason in (
                (lambda result: result["list"][2].update(hash="a" * 64), "independent_header_hash"),
                (lambda result: result["list"].reverse(), "observed_genesis_anchor_or_v3_boundary"),
                (lambda result: result["list"].pop(), "opening_header_count")):
            with self.subTest(reason=reason), self.assertRaisesRegex(Refused, reason):
                files = self.opening_files()
                body_path = "evidence/" + review.OPENING_FILE
                body = json.loads(files[body_path])
                mutate(body["result"])
                files[body_path] = canonical(body)
                receipt = json.loads(files["evidence/rpc-02.complete.json"])
                receipt["outputs"]["stdout"].update(pin(files[body_path]))
                files["evidence/rpc-02.complete.json"] = canonical(receipt)
                self.review(make_archive(files))

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
