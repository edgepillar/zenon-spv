# SPDX-License-Identifier: GPL-3.0-only
"""Regular-file and in-memory startup diagnostic controls; no Docker or signing."""
from copy import deepcopy
from dataclasses import replace
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True
HERE = Path(__file__).absolute().parent
sys.path.insert(0, str(HERE))
import engine
import engine_test
import model
import node_diagnostics as diag
import node_file_logs
import process
import review_test
import runner


def file_archive(kind="run", payload=b'msg="failed to generate momentum" reason="private-marker"\n'):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        entry = tarfile.TarInfo(dict(node_file_logs.FILES)[kind].rsplit("/", 1)[-1])
        entry.size = len(payload)
        archive.addfile(entry, io.BytesIO(payload))
    return buffer.getvalue()


class LogSummaryTests(unittest.TestCase):
    def test_events_and_source_frames_exclude_arguments_and_unclassified_text(self):
        raw = (b'Producing momentum ...\nmsg="momentum producer triggered" event="private-marker"\n'
               b'msg="do not process current event" reason="sync is not done"\n'
               b'panic: private-marker /Users/private-marker\n'
               b'\t/app/pillar/worker.go:100 +0xabc\n'
               b'\t/app/unknown/private-marker.go:100\nsecret=private-marker\n')
        row = diag.log_summary(raw, b'msg="failed to generate momentum" reason="private-marker"\n')
        diag.check_log_summary(row)
        self.assertEqual(row["events"]["producer_triggered"], 1)
        self.assertEqual(row["events"]["sync_not_done"], 1)
        self.assertEqual(row["events"]["generation_failed"], 1)
        self.assertEqual(row["events"]["panic"], 1)
        self.assertEqual(row["source_frames"], [{"file": "pillar/worker.go", "line": 100}])
        self.assertNotIn("private-marker", json.dumps(row))
        self.assertNotIn("/Users/", json.dumps(row))
        self.assertFalse(row["raw_logs_exported"])

    def test_empty_and_invalid_utf8_streams_remain_bounded_summaries(self):
        empty = diag.log_summary(b"", b"")
        diag.check_log_summary(empty)
        self.assertEqual(empty["total_lines"], 0)
        row = diag.log_summary(b"\xffunclassified\n", b"")
        diag.check_log_summary(row)
        self.assertTrue(row["invalid_utf8"])
        self.assertEqual(row["unclassified_lines"], 1)

    def test_byte_and_line_limits_are_checked_before_reporting(self):
        for raw in (b"x" * (diag.LOG_BYTES + 1), b"x\n" * (diag.MAX_LINES + 1)):
            with self.subTest(bytes=len(raw)), self.assertRaises(model.Refused):
                diag.log_summary(raw, b"")
        with self.assertRaises(model.Refused):
            diag.log_summary("text", b"")

    def test_frames_are_canonical_unique_and_truncation_is_explicit(self):
        raw = b"".join(f"\t/app/pillar/manager.go:{i} +0xab\n".encode() for i in range(20, 0, -1))
        row = diag.log_summary(raw + raw, b"")
        diag.check_log_summary(row)
        self.assertEqual(len(row["source_frames"]), diag.MAX_FRAMES)
        self.assertTrue(row["source_frames_truncated"])
        self.assertEqual(row["source_frames"][0]["line"], 1)

    def test_paths_suffixes_and_secret_like_messages_are_not_exported(self):
        raw = (b"/app/../private.go:1\n/app/pillar/worker.go:1 private-marker\n"
               b"/app/pillar/worker.go:100000\nmsg=private-marker\n")
        row = diag.log_summary(raw, b"")
        self.assertEqual(row["source_frames"], [])
        self.assertEqual(row["classified_lines"], 0)
        self.assertNotIn("private-marker", json.dumps(row))

    def test_summary_validation_rejects_unbounded_or_raw_fields(self):
        base = diag.log_summary(b"unclassified\n", b"")
        for key, value in (("raw_logs_exported", True), ("total_lines", True),
                           ("classified_lines", 2), ("unclassified_lines", 0),
                           ("source_frames", [{"file": "../private.go", "line": 1}]),
                           ("unexpected", "private-marker")):
            row = deepcopy(base);row[key] = value
            with self.subTest(key=key), self.assertRaises(model.Refused):
                diag.check_log_summary(row)
        row = deepcopy(base);row["events"]["panic"] = True
        with self.assertRaises(model.Refused):diag.check_log_summary(row)

    def test_state_summary_retains_exit_and_oom_without_arbitrary_error_text(self):
        row = engine.stop_state_summary({"State": {"Running": False, "ExitCode": 2,
                                                   "OOMKilled": False, "Error": "private-marker"}})
        diag.check_state_summary(row)
        self.assertEqual(row["fields"]["ExitCode"], 2)
        self.assertFalse(row["fields"]["OOMKilled"])
        self.assertEqual(row["error_class"], "nonempty")
        self.assertNotIn("private-marker", json.dumps(row))

    def test_state_validation_rejects_unknown_fields_and_coerced_values(self):
        for fields in ({"Pid": True}, {"Running": 1}, {"ExitCode": 256}, {"Status": "private-marker"},
                       {"unexpected": "private-marker"}):
            row = {"state_is_object": True, "fields": fields,
                   "unavailable_fields": sorted(diag.STATE_FIELDS - set(fields)), "error_class": "empty"}
            with self.subTest(fields=fields), self.assertRaises(model.Refused):diag.check_state_summary(row)


class CapturedStderrTests(unittest.TestCase):
    def result(self, directory, raw=b"private captured text"):
        out, err = directory / "capture.stdout", directory / "capture.stderr"
        out.write_bytes(b"out");err.write_bytes(raw)
        outputs = {"stdout": {"file": out.name, **process.regular_pin(out, 1024)},
                   "stderr": {"file": err.name, **process.regular_pin(err, 1024)}}
        return process.Result(directory, out.name, err.name, model.canonical({"outputs": outputs}),
                              process._file_identity(out.lstat()), process._file_identity(err.lstat()))

    def test_both_original_streams_match_their_own_receipts(self):
        with tempfile.TemporaryDirectory(prefix="startup-regular-streams-") as tmp:
            result = self.result(Path(tmp))
            self.assertEqual(result.stdout(1024), b"out")
            self.assertEqual(result.stderr(1024), b"private captured text")

    def test_equal_content_replacement_is_not_the_original_stderr_inode(self):
        with tempfile.TemporaryDirectory(prefix="startup-regular-replacement-") as tmp:
            result = self.result(Path(tmp));replacement = Path(tmp) / "replacement"
            replacement.write_bytes(b"private captured text")
            os.replace(replacement, Path(tmp) / result.stderr_name)
            with self.assertRaisesRegex(model.Refused, "command_result_changed"):result.stderr(1024)

    def test_changed_bytes_wrong_receipt_and_byte_limit_refuse(self):
        with tempfile.TemporaryDirectory(prefix="startup-regular-change-") as tmp:
            result = self.result(Path(tmp))
            with self.assertRaises(model.Refused):result.stderr(2)
            receipt = result.receipt;receipt["outputs"]["stderr"]["sha256"] = "f" * 64
            with self.assertRaises(model.Refused):replace(result, receipt_raw=model.canonical(receipt)).stderr(1024)
            (Path(tmp) / result.stderr_name).write_bytes(b"changed")
            with self.assertRaises(model.Refused):result.stderr(1024)

    def test_legacy_stdout_result_keeps_its_api_and_has_no_stderr_authority(self):
        with tempfile.TemporaryDirectory(prefix="startup-regular-legacy-") as tmp:
            result = self.result(Path(tmp));legacy = replace(result, stderr_identity=None)
            self.assertEqual(legacy.stdout(1024), b"out")
            with self.assertRaisesRegex(model.Refused, "command_result_identity"):legacy.stderr(1024)


class MemoryResult:
    """A response fixture, without execution or original-file provenance."""
    def __init__(self, label, stdout, stderr=b"", *, actual_exit=0, complete=True, reason=None):
        self.out, self.err = stdout, stderr
        self.receipt = {"format": "owned-devnet-command-capture/v1", "label": label,
            "actual_exit": actual_exit, "output_complete": complete, "reason": reason,
            "launch_outcome": "STARTED", "process_group_quiescent": True, "process_group": 42,
            "outputs": {key: {"file": label + "." + key, "bytes": len(raw),
                               "sha256": hashlib.sha256(raw).hexdigest()}
                        for key, raw in (("stdout", stdout), ("stderr", stderr))}}

    def stdout(self, limit):
        assert len(self.out) <= limit
        return self.out

    def stderr(self, limit):
        assert len(self.err) <= limit
        return self.err


class StartupNodeCaptureTests(unittest.TestCase):
    def prepare(self, root):
        setup = engine_test.LifecycleTests()
        setup.contract = model.read_contract(HERE / "contract.json")
        client, recorder = setup.prepare(root)
        setup.runtime(root, client)
        original = client._run
        calls = []

        def run(label, arguments, **options):
            calls.append((label, arguments, options))
            if arguments[:2] == ["container", "cp"]:
                client.guard();client.counter += 1
                return MemoryResult(f"docker-{client.counter:03d}-{label}", file_archive(label.rsplit("-", 1)[-1]))
            if arguments[:2] == ["container", "logs"]:
                client.guard();client.counter += 1
                return MemoryResult(f"docker-{client.counter:03d}-{label}", b"Producing momentum ...\n",
                                    b'panic: private-marker\n\t/app/pillar/worker.go:100 +0xab\n')
            result = original(label, arguments, **options)
            return MemoryResult(f"docker-{client.counter:03d}-{label}", result.stdout(options.get("stdout_cap", 128 << 10)))
        return client, recorder, run, calls

    def test_four_owned_nodes_are_observed_once_before_cleanup_with_fixed_bounds(self):
        with tempfile.TemporaryDirectory(prefix="startup-regular-engine-") as tmp:
            client, recorder, run, calls = self.prepare(Path(tmp))
            with mock.patch.object(client, "_run", side_effect=run):
                client.capture_startup_diagnostics()
                with self.assertRaises(model.Refused):client.capture_startup_diagnostics()
            row = json.loads(recorder.seals[diag.REPORT])
            self.assertEqual(row["status"], "OBSERVED")
            self.assertEqual(len(calls), 17)
            self.assertTrue(all(c[2]["timeout"] == 5 for c in calls))
            self.assertEqual([n["service"] for n in row["nodes"]], list(diag.ROLES))
            for node in row["nodes"]:
                self.assertEqual(node["logs"]["data"]["events"]["panic"], 1)
                self.assertEqual(node["logs"]["data"]["source_frames"], [{"file": "pillar/worker.go", "line": 100}])
            self.assertNotIn("private-marker", json.dumps(row))
            self.assertTrue(row["observed_before_cleanup"])
            self.assertFalse(row["atomic_snapshot"])
            self.assertFalse(row["accepted_header_authority"])
            self.assertTrue(all(c[1][:2] in (["container", "inspect"], ["container", "logs"], ["container", "cp"])
                                or c[1][:1] == ["info"] for c in calls))

    def test_budget_refusal_launches_nothing_and_cannot_be_retried(self):
        with tempfile.TemporaryDirectory(prefix="startup-regular-budget-") as tmp:
            client, recorder, run, calls = self.prepare(Path(tmp))
            client.guard = mock.Mock(side_effect=model.Refused("unit_budget"))
            with mock.patch.object(client, "_run", side_effect=run):client.capture_startup_diagnostics()
            row = json.loads(recorder.seals[diag.REPORT]);self.assertEqual(row["status"], "NOT_ATTEMPTED")
            self.assertEqual(calls, [])
            client.guard = lambda: None
            with self.assertRaises(model.Refused):client.capture_startup_diagnostics()

    def test_changed_engine_refuses_all_node_reads(self):
        with tempfile.TemporaryDirectory(prefix="startup-regular-foreign-") as tmp:
            client, recorder, run, calls = self.prepare(Path(tmp))
            with mock.patch.object(client, "_run", return_value=MemoryResult("docker-001-startup-engine-info",
                    model.canonical({"ID": "foreign", "OSType": "linux", "Architecture": "amd64"}))):
                client.capture_startup_diagnostics()
            row = json.loads(recorder.seals[diag.REPORT])
            self.assertFalse(row["engine_identity_verified"])
            self.assertTrue(all(n["inspection"]["status"] == "NOT_ATTEMPTED" for n in row["nodes"]))

    def test_logs_require_the_owned_image_and_keep_command_failures(self):
        with tempfile.TemporaryDirectory(prefix="startup-regular-failure-") as tmp:
            client, recorder, run, calls = self.prepare(Path(tmp))
            client.expected_images["pillar"] = "sha256:" + "f" * 64
            def failed(label, arguments, **options):
                if label == "startup-logs-pillar2":
                    client.counter += 1
                    raise process.CommandFailed(MemoryResult(f"docker-{client.counter:03d}-{label}",
                        b"private-marker", actual_exit=7))
                return run(label, arguments, **options)
            with mock.patch.object(client, "_run", side_effect=failed):client.capture_startup_diagnostics()
            row = json.loads(recorder.seals[diag.REPORT])
            self.assertEqual(row["nodes"][0]["logs"]["status"], "NOT_ATTEMPTED")
            self.assertEqual(row["nodes"][1]["logs"]["status"], "FAILURE")
            self.assertEqual(row["nodes"][1]["logs"]["actual_exit"], 7)
            self.assertIsNone(row["nodes"][1]["logs"]["data"])
            self.assertEqual(row["status"], "UNKNOWN")

    def test_interruption_seals_unknown_and_propagates(self):
        with tempfile.TemporaryDirectory(prefix="startup-regular-interruption-") as tmp:
            client, recorder, run, calls = self.prepare(Path(tmp))
            def interrupted(label, arguments, **options):
                if label == "startup-logs-pillar":raise KeyboardInterrupt
                return run(label, arguments, **options)
            with mock.patch.object(client, "_run", side_effect=interrupted), self.assertRaises(KeyboardInterrupt):
                client.capture_startup_diagnostics()
            row = json.loads(recorder.seals[diag.REPORT])
            self.assertEqual((row["status"], row["reason"]), ("UNKNOWN", "capture_interrupted"))
            self.assertIsNone(row["nodes"][0]["logs"]["data"])

    def test_malformed_nested_inspection_preserves_the_nonaccepting_path(self):
        with tempfile.TemporaryDirectory(prefix="startup-regular-malformed-") as tmp:
            client, recorder, run, calls = self.prepare(Path(tmp))
            recorder.containers[client.owned["pillar"].identity]["HostConfig"]["RestartPolicy"] = []
            with mock.patch.object(client, "_run", side_effect=run):client.capture_startup_diagnostics()
            row = json.loads(recorder.seals[diag.REPORT])
            self.assertEqual(row["nodes"][0]["inspection"]["status"], "REFUSED")
            self.assertIsNone(row["nodes"][0]["inspection"]["data"])
            self.assertEqual(row["nodes"][0]["logs"]["status"], "NOT_ATTEMPTED")
            self.assertEqual(row["status"], "UNKNOWN")
            self.assertFalse(row["accepted_header_authority"])

    def test_cleanup_has_no_startup_diagnostic_authority(self):
        with tempfile.TemporaryDirectory(prefix="startup-regular-cleanup-") as tmp:
            client, recorder, run, calls = self.prepare(Path(tmp));client.cleanup_deadline = 1
            with self.assertRaises(model.Refused):client.capture_startup_diagnostics()
            self.assertNotIn(diag.REPORT, recorder.seals)

    @unittest.skipUnless(os.name == "posix", "Actual command recorder requires POSIX")
    def test_actual_streams_keep_raw_log_text_outside_the_public_index(self):
        with tempfile.TemporaryDirectory(prefix="startup-regular-recorder-") as tmp:
            root = Path(tmp);client, fixture, _, _ = self.prepare(root)
            recorder = process.Recorder(root / "evidence");client.recorder = recorder

            def run(label, arguments, **options):
                client.counter += 1
                name = f"docker-{client.counter:03d}-{label}"
                if arguments[:1] == ["info"]:
                    raw = model.canonical({"ID": client.admission.engine_id, "OSType": "linux", "Architecture": "amd64"})
                    err = b""
                elif arguments[:2] == ["container", "inspect"]:
                    raw, err = model.canonical(fixture.containers[arguments[-1]]), b""
                elif arguments[:2] == ["container", "cp"]:
                    raw, err = file_archive(label.rsplit("-", 1)[-1]), b""
                else:
                    raw = b"Producing momentum ...\n"
                    err = b'panic: private-marker /Users/private-marker\n\t/app/pillar/worker.go:100 +0xab\n'
                code = "import sys;sys.stdout.buffer.write(" + repr(raw) + ");sys.stderr.buffer.write(" + repr(err) + ")"
                return recorder.run(name, [sys.executable, "-I", "-B", "-c", code], root,
                    {"PATH": os.environ.get("PATH", "")}, timeout=5,
                    stdout_cap=options["stdout_cap"], stderr_cap=options["stderr_cap"])

            with mock.patch.object(client, "_run", side_effect=run):client.capture_startup_diagnostics()
            entries = runner.evidence_index((recorder,), {"evidence": {diag.REPORT, node_file_logs.REPORT}})
            selected = {row["path"] for row in entries}
            self.assertIn("evidence/" + diag.REPORT, selected)
            self.assertFalse(any(name.endswith((".stdout", ".stderr")) for name in selected))
            summary = (recorder.directory / diag.REPORT).read_bytes()
            self.assertNotIn(b"private-marker", summary)
            self.assertNotIn(b"/Users/", summary)
            self.assertEqual(json.loads(summary)["status"], "OBSERVED")
            file_summary = (recorder.directory / node_file_logs.REPORT).read_bytes()
            self.assertIn("evidence/" + node_file_logs.REPORT, selected)
            self.assertNotIn(b"private-marker", file_summary)
            self.assertNotIn(b"/Users/", file_summary)
            self.assertEqual(json.loads(file_summary)["status"], "OBSERVED")
            self.assertEqual(len(recorder.records), 17)


class StartupNodeRunnerTests(unittest.TestCase):
    def test_original_deadline_survives_diagnostics_and_no_new_height_wait_runs(self):
        rpc = mock.Mock();error = model.Refused("owned_rpc_readiness_deadline")
        rpc.wait_height.side_effect = error;rpc.capture_startup_sync.return_value = None
        callback = mock.Mock()
        with self.assertRaises(model.Refused) as caught:runner.wait_for_initial_height(rpc, 3, observe_nodes=callback)
        self.assertIs(caught.exception, error);callback.assert_called_once_with()
        rpc.wait_height.assert_called_once_with(3, starting=True)

    def test_success_and_other_refusals_do_not_collect_diagnostics(self):
        for failure in (None, model.Refused("different_refusal")):
            rpc = mock.Mock();rpc.wait_height.side_effect = failure;callback = mock.Mock()
            if failure:
                with self.assertRaises(model.Refused):runner.wait_for_initial_height(rpc, 3, observe_nodes=callback)
            else:runner.wait_for_initial_height(rpc, 3, observe_nodes=callback)
            callback.assert_not_called()

    def test_diagnostic_interruption_remains_an_interruption(self):
        rpc = mock.Mock();rpc.wait_height.side_effect = model.Refused("owned_rpc_readiness_deadline")
        rpc.capture_startup_sync.return_value = None
        with self.assertRaises(KeyboardInterrupt):runner.wait_for_initial_height(rpc, 3,
            observe_nodes=mock.Mock(side_effect=KeyboardInterrupt))


class StartupNodeArchiveTests(unittest.TestCase):
    def files(self):
        contract, files = review_test.FrontierReviewTests.files(1)
        counter = 40

        def phase(suffix, data):
            nonlocal counter
            counter += 1
            label = f"docker-{counter:03d}-{suffix}"
            result = MemoryResult(label, b"private stdout", b"private stderr")
            files["evidence/" + label + ".complete.json"] = model.canonical(result.receipt)
            files["evidence/" + label + ".started.json"] = model.canonical({
                "format": "owned-devnet-command-started/v1", "label": label,
                "pid": 42, "process_group": 42, "new_session_requested": True})
            row = diag.empty_phase();diag.complete_command(row, result)
            row.update(status="OBSERVED", reason=None, data=data)
            return row

        summary = {"format": "owned-devnet-startup-nodes/v1", "trigger": "owned_rpc_readiness_deadline",
            "status": "OBSERVED", "reason": None, "engine_probe": phase("startup-engine-info", None),
            "engine_identity_verified": True, "observed_before_cleanup": True, "atomic_snapshot": False,
            "accepted_header_authority": False, "production_qualified": False, "raw_logs_exported": False,
            "nodes": []}
        for role in diag.ROLES:
            state = engine.stop_state_summary({"State": {"Running": role != "pillar3", "Pid": 0,
                "ExitCode": 2 if role == "pillar3" else 0, "OOMKilled": False, "Status": "exited", "Error": ""}})
            summary["nodes"].append({"service": role, "inspection": phase("startup-inspect-" + role, state),
                                     "logs": phase("startup-logs-" + role, diag.log_summary(b"panic: omitted\n", b""))})
        files["evidence/" + diag.REPORT] = model.canonical(summary)
        return contract, files, summary

    def review(self, contract, files):
        return review_test.FrontierReviewTests.review(contract, files)

    def test_node_diagnostics_remain_assertions_and_preserve_nonacceptance(self):
        contract, files, summary = self.files();row = self.review(contract, files)
        diagnostic = row["startup_node_diagnostics"]
        self.assertTrue(diagnostic["diagnostic_assertions_only"])
        self.assertFalse(diagnostic["original_log_text_independently_rechecked"])
        self.assertFalse(diagnostic["accepted_header_authority"])
        self.assertEqual(diagnostic["summary"]["nodes"][2]["inspection"]["data"]["fields"]["ExitCode"], 2)
        self.assertEqual(row["recorded_terminal_outcome"], "REFUSED")
        self.assertIsNone(row["comparison"])

    def test_legacy_archive_omits_the_optional_report(self):
        contract, files = review_test.FrontierReviewTests.files(1)
        self.assertNotIn("startup_node_diagnostics", self.review(contract, files))

    def test_unknown_fields_raw_text_and_authority_flags_refuse(self):
        for field, value in (("format", "different/v1"), ("raw_logs_exported", True),
                ("accepted_header_authority", True), ("production_qualified", True),
                ("atomic_snapshot", True), ("observed_before_cleanup", False),
                ("status", True), ("reason", []), ("unknown", "private-marker")):
            with self.subTest(field=field):
                contract, files, summary = self.files();summary[field] = value
                files["evidence/" + diag.REPORT] = model.canonical(summary)
                with self.assertRaises(model.Refused):self.review(contract, files)

    def test_node_order_and_command_start_completion_and_digest_are_bound(self):
        for change in ("node_order", "missing_start", "missing_receipt", "exit", "complete", "digest", "reuse",
                       "unlaunched_failure", "started_not_attempted", "missing_stderr", "engine_unverified"):
            with self.subTest(change=change):
                contract, files, summary = self.files();node = summary["nodes"][0];label = node["logs"]["command"]
                if change == "node_order":summary["nodes"].reverse()
                elif change == "missing_start":del files["evidence/" + label + ".started.json"]
                elif change == "missing_receipt":del files["evidence/" + label + ".complete.json"]
                elif change == "exit":node["logs"]["actual_exit"] = 7
                elif change == "complete":node["logs"]["output_complete"] = False
                elif change == "digest":node["logs"]["outputs"]["stdout"]["sha256"] = "f" * 64
                elif change == "reuse":node["logs"]["command"] = node["inspection"]["command"]
                elif change == "unlaunched_failure":node["logs"] = {**diag.empty_phase(), "status": "FAILURE",
                                                                     "reason": "command_failed"}
                elif change == "started_not_attempted":node["logs"].update(status="NOT_ATTEMPTED",
                    reason="preceding_observation_unavailable", data=None)
                elif change == "missing_stderr":
                    receipt = json.loads(files["evidence/" + label + ".complete.json"])
                    del receipt["outputs"]["stderr"]
                    files["evidence/" + label + ".complete.json"] = model.canonical(receipt)
                else:summary["engine_identity_verified"] = False
                files["evidence/" + diag.REPORT] = model.canonical(summary)
                with self.assertRaises(model.Refused):self.review(contract, files)

    def test_raw_capture_streams_cannot_be_added_to_the_public_index(self):
        contract, files, summary = self.files();label = summary["nodes"][0]["logs"]["command"]
        files["evidence/" + label + ".stderr"] = b"private stderr"
        with self.assertRaisesRegex(model.Refused, "review_member_selection"):
            self.review(contract, files)

    def test_partial_failures_have_no_parsed_data_and_keep_actual_exit(self):
        contract, files, summary = self.files();phase = summary["nodes"][0]["logs"];label = phase["command"]
        phase.update(status="FAILURE", reason="command_failed", actual_exit=7, data=None)
        receipt = json.loads(files["evidence/" + label + ".complete.json"]);receipt["actual_exit"] = 7
        files["evidence/" + label + ".complete.json"] = model.canonical(receipt)
        summary.update(status="UNKNOWN", reason="incomplete_diagnostics")
        files["evidence/" + diag.REPORT] = model.canonical(summary)
        row = self.review(contract, files)["startup_node_diagnostics"]["summary"]
        self.assertEqual(row["nodes"][0]["logs"]["actual_exit"], 7)
        phase["data"] = diag.log_summary(b"panic: omitted\n", b"")
        files["evidence/" + diag.REPORT] = model.canonical(summary)
        with self.assertRaises(model.Refused):self.review(contract, files)

    def test_budget_refusal_reports_no_started_commands(self):
        contract, files, summary = self.files()
        summary.update(status="NOT_ATTEMPTED", reason="budget_refused", engine_identity_verified=False,
                       engine_probe=diag.empty_phase(), nodes=[{"service": role, "inspection": diag.empty_phase(),
                           "logs": diag.empty_phase()} for role in diag.ROLES])
        files["evidence/" + diag.REPORT] = model.canonical(summary)
        with self.assertRaisesRegex(model.Refused, "review_startup_nodes_unlaunched"):
            self.review(contract, files)
        files = {name: raw for name, raw in files.items()
                 if not name.startswith("evidence/") or not diag.COMMAND_FILE.fullmatch(name[len("evidence/"):])}
        row = self.review(contract, files)["startup_node_diagnostics"]["summary"]
        self.assertEqual(row["status"], "NOT_ATTEMPTED")

    def test_orphan_diagnostic_records_and_false_incomplete_status_refuse(self):
        contract, files, summary = self.files()
        summary.update(status="UNKNOWN", reason="incomplete_diagnostics")
        files["evidence/" + diag.REPORT] = model.canonical(summary)
        with self.assertRaisesRegex(model.Refused, "review_startup_nodes_incomplete"):
            self.review(contract, files)
        del files["evidence/" + diag.REPORT]
        with self.assertRaisesRegex(model.Refused, "review_startup_nodes_summary_missing"):
            self.review(contract, files)
        files["evidence/docker-041-startup-engine-info.stderr"] = b""
        with self.assertRaisesRegex(model.Refused, "review_member_selection"):
            self.review(contract, files)

    def test_recorded_cleanup_order_and_scope_are_checked(self):
        for suffix in ("inspect-pillar-stop-state.json", "stop-pillar.started.json", "stop-pillar.complete.json"):
            with self.subTest(suffix=suffix):
                contract, files, summary = self.files()
                files["evidence/docker-042-" + suffix] = model.canonical({"diagnostic_only": True})
                with self.assertRaisesRegex(model.Refused, "review_startup_node_cleanup_order"):
                    self.review(contract, files)

    def test_node_diagnostics_cannot_be_attached_to_an_accepted_consumer(self):
        contract, files = review_test.accepted_files()
        _, extra, _ = self.files()
        files.update({name: raw for name, raw in extra.items() if name != "evidence/terminal.json"})
        with self.assertRaisesRegex(model.Refused, "review_startup_nodes_scope"):
            self.review(contract, files)


if __name__ == "__main__":
    unittest.main()
