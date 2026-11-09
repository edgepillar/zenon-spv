# SPDX-License-Identifier: GPL-3.0-only
"""Metadata counterexamples and a benign local API-output fixture, without networking."""
import argparse
import base64
from copy import deepcopy
from contextlib import contextmanager
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True
HERE = Path(__file__).absolute().parent
sys.path.insert(0, str(HERE))
import artifacts
import inputs_test as archive_fixtures
import model
import process as owned_process


def contract_and_metadata(role="consumer"):
    value = model.read_contract(HERE / "contract.json").data
    raw, specification = (archive_fixtures.consumer()[:2] if role == "consumer"
                          else archive_fixtures.helper())
    specification["run_id"] = value["qualified_components"][role]["run_id"]
    value["qualified_components"][role] = specification
    contract = model.decode_contract(model.canonical(value))
    repository = {"id": 17, "full_name": artifacts.REPOSITORY}
    run = {"id": specification["run_id"], "run_attempt": 1,
           "status": "completed", "conclusion": "success", "event": "push",
           "head_branch": "main", "path": artifacts.WORKFLOWS[role],
           "head_sha": value["qualified_components"]["source_revision"],
           "repository": repository, "head_repository": deepcopy(repository)}
    artifact = {"id": specification["artifact_id"], "expired": False,
                "size_in_bytes": len(raw), "digest": "sha256:" + specification["archive"]["sha256"],
                "workflow_run": {"id": specification["run_id"], "repository_id": 17,
                                 "head_repository_id": 17, "head_sha": run["head_sha"]}}
    return contract, run, artifact, raw


class MetadataTests(unittest.TestCase):
    def test_two_selected_lanes_bind_their_own_workflows(self):
        for role in artifacts.WORKFLOWS:
            contract, run, artifact, _ = contract_and_metadata(role)
            result = artifacts.bind_metadata(contract, role, run, artifact)
            self.assertEqual(result["workflow"], artifacts.WORKFLOWS[role])
            self.assertIs(result["new_ci_execution_qualified"], False)
            self.assertIs(result["authenticated_distribution"], False)

    def test_run_and_artifact_field_changes_refuse(self):
        contract, original_run, original_artifact, _ = contract_and_metadata()
        cases = [("run", ["id"], True), ("run", ["run_attempt"], 2),
                 ("run", ["status"], "in_progress"), ("run", ["conclusion"], "failure"),
                 ("run", ["event"], "pull_request"), ("run", ["head_branch"], "another"),
                 ("run", ["path"], artifacts.WORKFLOWS["parent_oracle"]),
                 ("run", ["head_sha"], "1" * 40),
                 ("run", ["repository", "full_name"], "other/zenon-spv"),
                 ("run", ["head_repository", "full_name"], "other/zenon-spv"),
                 ("run", ["repository", "id"], True),
                 ("artifact", ["id"], True), ("artifact", ["size_in_bytes"], 1),
                 ("artifact", ["expired"], True), ("artifact", ["expired"], None),
                 ("artifact", ["digest"], "sha256:" + "2" * 64),
                 ("artifact", ["workflow_run", "id"], 1),
                 ("artifact", ["workflow_run", "repository_id"], 18),
                 ("artifact", ["workflow_run", "head_repository_id"], 18),
                 ("artifact", ["workflow_run", "head_sha"], "2" * 40)]
        for source, keys, changed in cases:
            run, artifact = deepcopy(original_run), deepcopy(original_artifact)
            selected = run if source == "run" else artifact
            for key in keys[:-1]:
                selected = selected[key]
            selected[keys[-1]] = changed
            with self.subTest(source=source, keys=keys):
                with self.assertRaises(model.Refused):
                    artifacts.bind_metadata(contract, "consumer", run, artifact)

    def test_bounded_api_json_refuses_ambiguous_values(self):
        for raw in (b"", b"[]", b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":1.0}',
                    b"\xff", b"{} {}", b" " * (artifacts.API_LIMIT + 1)):
            with self.subTest(prefix=raw[:16]):
                with self.assertRaises(model.Refused):
                    artifacts.api_json(raw)
        self.assertEqual(artifacts.api_json(b'{"id":1,"value":null}'), {"id": 1, "value": None})


FIXTURE_PROGRAM = '''import base64,json,sys
from pathlib import Path
configuration=Path(sys.argv[1])
with (configuration.parent/"calls.jsonl").open("a")as out:out.write(json.dumps(sys.argv[2:])+"\\n")
assert len(sys.argv)==4 and sys.argv[2]=="api"
row=json.loads(configuration.read_bytes())[sys.argv[3]]
sys.stdout.buffer.write(base64.b64decode(row["stdout"]))
sys.stdout.buffer.flush()
sys.stderr.write("benign local response fixture\\n")
sys.exit(row["exit"])
'''


@unittest.skipUnless(os.name == "posix", "The actual lease and process-group lane requires POSIX")
class TransportTests(unittest.TestCase):
    def prepare(self, root, *, run_change=None, payload_change=None, exit_code=0, guard=None,
                oracle_expired=None):
        contract, run, artifact, raw = contract_and_metadata()
        if run_change is not None:
            run.update(run_change)
        selected = contract.data["qualified_components"]["consumer"]
        base = artifacts.ACTIONS
        rows = {}
        for endpoint, data, status in (
                (base + "runs/" + str(selected["run_id"]) + "/attempts/1", model.canonical(run), 0),
                (base + "artifacts/" + str(selected["artifact_id"]), model.canonical(artifact), 0),
                (base + "artifacts/" + str(selected["artifact_id"]) + "/zip",
                 raw if payload_change is None else payload_change(raw), exit_code)):
            rows[endpoint] = {"stdout": base64.b64encode(data).decode("ascii"), "exit": status}
        if oracle_expired is not None:
            oracle, oracle_run, oracle_metadata, oracle_raw = contract_and_metadata("parent_oracle")
            oracle_spec = oracle.data["qualified_components"]["parent_oracle"]
            value = contract.data
            value["qualified_components"]["parent_oracle"] = oracle_spec
            contract = model.decode_contract(model.canonical(value))
            oracle_metadata["expired"] = oracle_expired
            for endpoint, data in (
                    (base + f"runs/{oracle_spec['run_id']}/attempts/1", model.canonical(oracle_run)),
                    (base + f"artifacts/{oracle_spec['artifact_id']}", model.canonical(oracle_metadata)),
                    (base + f"artifacts/{oracle_spec['artifact_id']}/zip", oracle_raw)):
                rows[endpoint] = {"stdout": base64.b64encode(data).decode("ascii"), "exit": 0}
        configuration = root / "responses.json"
        configuration.write_bytes(model.canonical(rows))
        program = root / "local-response-fixture.py"
        program.write_text(FIXTURE_PROGRAM)
        recorder = owned_process.Recorder(root / "commands")
        lane = artifacts.Artifacts(contract, recorder, root / "binaries",
                                   [sys.executable, "-I", "-B", str(program), str(configuration)],
                                   {"PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                                    "PYTHONDONTWRITEBYTECODE": "1"}, guard or (lambda: None))
        return lane, recorder, raw, root / "calls.jsonl"

    def calls(self, path):
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def test_preflight_binds_both_inputs_before_either_transport(self):
        with tempfile.TemporaryDirectory(prefix="artifact-lane-control-") as temporary:
            lane, recorder, _, calls = self.prepare(Path(temporary), oracle_expired=False)
            lane.preflight()
            metadata_calls = self.calls(calls)
            self.assertEqual(len(metadata_calls), 4)
            self.assertEqual(list(recorder.directory.glob("*.zip")), [])
            with mock.patch.object(owned_process.Result, "open_stdout",
                                   side_effect=AssertionError("duplicate archive digest pass")), \
                    mock.patch.object(artifacts.inputs, "_hash_stream",
                                      wraps=artifacts.inputs._hash_stream) as hash_stream:
                materialized = {role: lane.fetch(role) for role in artifacts.WORKFLOWS}
                self.assertEqual([call.args[1] for call in hash_stream.call_args_list], [
                    lane.contract.data["qualified_components"][role]["archive"] for role in materialized])
            for role, first in materialized.items():
                self.assertIs(first, lane.fetch(role))
                self.assertEqual(first.binding["component"], role)
            transports = self.calls(calls)[4:]
            self.assertEqual(len(transports), 2)
            self.assertEqual(len(set(call[-1] for call in transports)), 2)
            self.assertTrue(all(call[-1].endswith("/zip") for call in transports))
            self.assertEqual(len(list(recorder.directory.glob("*.zip"))), 2)

    def test_expired_second_artifact_prevents_both_transports(self):
        with tempfile.TemporaryDirectory(prefix="artifact-lane-control-") as temporary:
            lane, recorder, _, calls = self.prepare(Path(temporary), oracle_expired=True)
            with self.assertRaisesRegex(model.Refused, "artifact_digest_or_expiry"):
                lane.preflight()
            with self.assertRaisesRegex(model.Refused, "artifact_preflight_incomplete"):
                lane.fetch("consumer")
            with self.assertRaisesRegex(model.Refused, "artifact_preflight_already_attempted"):
                lane.preflight()
            self.assertEqual(len(self.calls(calls)), 4)
            self.assertEqual(list(recorder.directory.glob("*.zip")), [])
            self.assertEqual(list(lane.directory.iterdir()), [])

    def test_one_original_archive_and_no_second_transport_on_verified_hit(self):
        with tempfile.TemporaryDirectory(prefix="artifact-lane-control-") as temporary:
            lane, recorder, raw, calls = self.prepare(Path(temporary))
            first = lane.fetch("consumer")
            identities = {p.name: p.stat().st_ino for p in recorder.directory.iterdir()}
            second = lane.fetch("consumer")
            self.assertIs(first, second)
            self.assertEqual(len(self.calls(calls)), 3)
            self.assertEqual(len(recorder.records), 3)
            self.assertEqual({p.name: p.stat().st_ino for p in recorder.directory.iterdir()}, identities)
            archive = recorder.directory / first.original.stdout_name
            self.assertEqual(archive.read_bytes(), raw)
            self.assertEqual(len(list(recorder.directory.glob("*.zip"))), 1)
            self.assertEqual(archive.stat().st_nlink, 1)
            self.assertEqual(first.verify(), lane.contract.data["qualified_components"]["consumer"]["binaries"])
            changed = first.binding
            changed["source_revision"] = "1" * 40
            self.assertNotEqual(first.binding["source_revision"], changed["source_revision"])

    def test_wrong_source_stops_before_archive_transport(self):
        with tempfile.TemporaryDirectory(prefix="artifact-lane-control-") as temporary:
            lane, recorder, _, calls = self.prepare(Path(temporary), run_change={"head_sha": "1" * 40})
            with self.assertRaisesRegex(model.Refused, "artifact_run_source"):
                lane.fetch("consumer")
            self.assertEqual(len(self.calls(calls)), 2)
            self.assertEqual(list(recorder.directory.glob("*.zip")), [])
            with self.assertRaisesRegex(model.Refused, "artifact_attempt_already_consumed"):
                lane.fetch("consumer")
            self.assertEqual(len(self.calls(calls)), 2)

    def test_failed_transport_retains_actual_exit_and_is_not_retried(self):
        with tempfile.TemporaryDirectory(prefix="artifact-lane-control-") as temporary:
            lane, recorder, raw, calls = self.prepare(Path(temporary), payload_change=lambda b: b[:13], exit_code=7)
            with self.assertRaises(owned_process.CommandFailed) as error:
                lane.fetch("consumer")
            self.assertEqual(error.exception.result.receipt["actual_exit"], 7)
            self.assertIs(error.exception.result.receipt["output_complete"], True)
            self.assertEqual(error.exception.result.stdout(), raw[:13])
            self.assertEqual(recorder.records[-1]["outcome"], "FAILURE")
            self.assertEqual(lane.cache, {})
            with self.assertRaisesRegex(model.Refused, "artifact_attempt_already_consumed"):
                lane.fetch("consumer")
            self.assertEqual(len(self.calls(calls)), 3)

    def test_zero_exit_short_transport_never_materializes_a_binary(self):
        with tempfile.TemporaryDirectory(prefix="artifact-lane-control-") as temporary:
            lane, _, _, calls = self.prepare(Path(temporary), payload_change=lambda b: b[:13])
            with self.assertRaisesRegex(model.Refused, "artifact_transport_content"):
                lane.fetch("consumer")
            self.assertEqual(list(lane.directory.iterdir()), [])
            self.assertEqual(lane.cache, {})
            with self.assertRaisesRegex(model.Refused, "artifact_attempt_already_consumed"):
                lane.fetch("consumer")
            self.assertEqual(len(self.calls(calls)), 3)

    def test_replaced_cached_archive_refuses_without_a_redownload(self):
        with tempfile.TemporaryDirectory(prefix="artifact-lane-control-") as temporary:
            root = Path(temporary)
            lane, recorder, raw, calls = self.prepare(root)
            first = lane.fetch("consumer")
            path = recorder.directory / first.original.stdout_name
            path.rename(root / "preserved-original.zip")
            path.write_bytes(raw)
            with self.assertRaisesRegex(model.Refused, "command_result_changed"):
                lane.fetch("consumer")
            self.assertEqual(len(self.calls(calls)), 3)

    def test_guard_refusal_launches_nothing_and_has_no_automatic_retry(self):
        def refuse():
            raise model.Refused("resource_guard")
        with tempfile.TemporaryDirectory(prefix="artifact-lane-control-") as temporary:
            lane, recorder, _, calls = self.prepare(Path(temporary), guard=refuse)
            with self.assertRaisesRegex(model.Refused, "resource_guard"):
                lane.fetch("consumer")
            self.assertEqual(self.calls(calls), [])
            self.assertEqual(recorder.records, [])
            lane.guard = lambda: None
            with self.assertRaisesRegex(model.Refused, "artifact_attempt_already_consumed"):
                lane.fetch("consumer")

    def test_lease_reconciliation_failure_cannot_publish_a_cache_entry(self):
        with tempfile.TemporaryDirectory(prefix="artifact-lane-control-") as temporary:
            root = Path(temporary)
            lane, recorder, _, calls = self.prepare(root)
            original_unpack = artifacts.inputs.unpack_binaries

            def replace_lease(*arguments, **keywords):
                result = original_unpack(*arguments, **keywords)
                path = next(recorder.directory.glob("*.lease"))
                path.rename(root / "preserved-lease")
                path.write_bytes(b"")
                return result

            with mock.patch.object(artifacts.inputs, "unpack_binaries", replace_lease):
                with self.assertRaisesRegex(model.Refused, "artifact_lease_identity"):
                    lane.fetch("consumer")
            self.assertEqual(lane.cache, {})
            with self.assertRaisesRegex(model.Refused, "artifact_attempt_already_consumed"):
                lane.fetch("consumer")
            self.assertEqual(len(self.calls(calls)), 3)

    def test_foreign_archive_path_is_not_adopted_or_overwritten(self):
        with tempfile.TemporaryDirectory(prefix="artifact-lane-control-") as temporary:
            lane, recorder, _, calls = self.prepare(Path(temporary))
            selected = lane.contract.data["qualified_components"]["consumer"]
            foreign = recorder.directory / ("artifact-" + str(selected["artifact_id"]) + ".zip")
            foreign.write_bytes(b"preserve foreign regular fixture")
            with self.assertRaisesRegex(model.Refused, "command_files_exist_or_alias"):
                lane.fetch("consumer")
            self.assertEqual(foreign.read_bytes(), b"preserve foreign regular fixture")
            self.assertEqual(len(self.calls(calls)), 2)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-revision")
    parser.add_argument("--metadata-only", action="store_true",
                        help="Run pure metadata controls; keep the complete transport lane for hosted CI")
    arguments = parser.parse_args()
    if arguments.source_revision is not None:
        model.digest(arguments.source_revision, model.HEX40)
    suite = (unittest.defaultTestLoader.loadTestsFromTestCase(MetadataTests)
             if arguments.metadata_only else
             unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__]))
    result = unittest.TextTestRunner(stream=sys.stderr, verbosity=2).run(suite)
    receipt = {"format": "owned-devnet-query-artifact-controls/v1",
               "source_revision": arguments.source_revision, "root_tests": result.testsRun,
               "errors": len(result.errors), "failures": len(result.failures),
               "skipped": len(result.skipped), "successful": result.wasSuccessful(),
               "scope": "METADATA_ONLY" if arguments.metadata_only else "FULL_DECLARED_SUITE",
               "complete_transport_suite_executed": not arguments.metadata_only and os.name == "posix",
               "simulated_api_responses": True, "external_transport_performed": False,
               "live_ci_or_binary_or_engine_or_signing_executed": False}
    sys.stdout.buffer.write(model.canonical(receipt))
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
