# SPDX-License-Identifier: GPL-3.0-only
"""Synthetic hosted metadata and archive controls with no external service."""
import base64
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
