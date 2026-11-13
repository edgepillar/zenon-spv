# SPDX-License-Identifier: GPL-3.0-only
"""Two exact source selections and synthetic consumer seams; no live devnet."""
from copy import deepcopy
import base64
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))

import artifacts
import capture
import inputs
from inputs_test import helper
import model
import query_checks as checks
import review
from review_test import hosted_metadata, SOURCE, RUN, ARTIFACT
import runner
import sources


class ReferenceGasTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.old = model.read_contract(HERE / "contract.json")
        cls.new = model.read_contract(HERE / "reference-gas-contract.json")
        cls.unit = json.loads((ROOT / "internal/testdata/conformance/batch-context-unit.json").read_bytes())

    def test_original_contract_and_prepared_inputs_keep_their_byte_identity(self):
        self.assertEqual(self.old.sha256, "1178cb1161d8e21a3f6e657aa2519900c8a0d4dbe6d207ecb667edf473cfe93e")
        self.assertEqual(self.old.data["format"], model.FORMAT)
        self.assertEqual(self.old.data["sources"]["node"]["revision"], model.SOURCE_PINS["node"][1])
        self.assertEqual(self.old.data["selection"]["descriptor_sha256"],
                         "cc426de7117a58812a1d43e914de044827abbd4941f4fb4ec123964a5b665d43")
        capture.selected_profile(self.old, ROOT)

    def test_reference_selection_binds_qualified_components_without_new_authority(self):
        value = self.new.data
        self.assertEqual(self.new.sha256, "6f67a35cf6db1e2fd91a529880b9fa555461a4687ed0a76d9a27c900ca6b6f31")
        self.assertEqual(value["format"], model.REFERENCE_GAS_FORMAT)
        self.assertEqual(value["qualified_components"]["source_revision"], model.REFERENCE_GAS_COMPONENT_REVISION)
        self.assertEqual(value["qualified_components"]["consumer"]["run_id"], 43355485323)
        self.assertEqual(value["qualified_components"]["parent_oracle"]["run_id"], 43355485426)
        for name in ("limits", "scope", "runtime", "images", "node_toolchain", "vault_module"):
            self.assertEqual(value[name], self.old.data[name])
        plan = model.preparation_report(self.new)
        self.assertEqual(plan["qualified_component_revision"], model.REFERENCE_GAS_COMPONENT_REVISION)
        self.assertFalse(plan["execution_authorized"])
        self.assertFalse(plan["actual_devnet_query_executed"])

    def test_cross_cohort_sources_selection_and_binaries_are_refused(self):
        for name in ("format", "sources", "selection", "qualified_components"):
            for original, foreign in ((self.new, self.old), (self.old, self.new)):
                with self.subTest(name=name, original=original.data["format"]):
                    value = original.data
                    value[name] = foreign.data[name]
                    with self.assertRaises(model.Refused):
                        model.decode_contract(model.canonical(value))
        for role in ("consumer", "parent_oracle"):
            value = self.new.data
            value["qualified_components"][role]["binaries"] = self.old.data["qualified_components"][role]["binaries"]
            with self.assertRaisesRegex(model.Refused, "component_selection"):
                model.decode_contract(model.canonical(value))

    def test_only_two_exact_contract_digests_are_selected(self):
        for contract in (self.old, self.new):
            self.assertEqual(model.read_selected_contract(HERE, contract.sha256), contract)
        for digest in ("a" * 64, "latest", self.new.sha256.upper(), True):
            with self.subTest(digest=digest), self.assertRaises(model.Refused):
                model.read_selected_contract(HERE, digest)

    def test_filename_cannot_relabel_an_original_contract_as_reference_gas(self):
        with tempfile.TemporaryDirectory(prefix="regular-cohort-control-") as temporary:
            root = Path(temporary)
            for name, _ in model.CONTRACT_FILES:
                (root / name).write_bytes(self.old.raw)
            with self.assertRaisesRegex(model.Refused, "contract_file_cohort"):
                model.read_selected_contract(root, self.old.sha256)

    def test_new_metadata_and_profile_are_bound_to_the_new_source_set(self):
        descriptor, profile = capture.selected_profile(self.new, ROOT)
        for role, selected in self.new.data["sources"].items():
            self.assertEqual(descriptor["source_cohort"][role], selected["revision"])
        self.assertEqual(descriptor["source_cohort"]["node_tree"], "f89d645c7f5be85dfe10dc7a510d80df7965d22f")
        self.assertEqual(profile["entry"]["runtime_identity"], self.new.data["selection"]["descriptor_sha256"])
        self.assertNotEqual(profile["entry"]["runtime_identity"], self.old.data["selection"]["descriptor_sha256"])
        self.assertEqual(descriptor["source_profile"], capture.selected_profile(self.old, ROOT)[0]["source_profile"])
        self.assertFalse(descriptor["authority"]["authenticated_runtime_or_STF_execution"])

    def test_profile_from_the_other_cohort_cannot_satisfy_the_selected_digest(self):
        with tempfile.TemporaryDirectory(prefix="regular-profile-control-") as temporary:
            root = Path(temporary)
            target = root / "internal/testdata/conformance"
            target.mkdir(parents=True)
            for (name, _), (foreign, _) in zip(model.metadata_files(self.new), model.metadata_files(self.old)):
                (target / name).write_bytes((ROOT / "internal/testdata/conformance" / foreign).read_bytes())
            with self.assertRaisesRegex(model.Refused, "selected_local_profile_pin"):
                capture.selected_profile(self.new, root)

    def test_new_source_pair_matches_the_separate_native_context_goldens(self):
        config = deepcopy(self.unit["config"])
        config["header_profile"]["node_revision"] = model.REFERENCE_GAS_SOURCE_PINS["node"][1]
        got = checks.fingerprints(config)
        # Frozen independently in TestExperimentalReferenceGasBatchContextAndCheckpoint.
        self.assertEqual(got["header_context"], "539dbc070da4f32ecf17a9b6fb6750849cfa94486986095ffccb936f195ee397")
        self.assertEqual(got["entry_context"], "1b87299ca02ada9244e001a3413844998692d5f81f4084616c16445a64f1e978")
        self.assertEqual(got["context"], "29dc0740c26bfaffc4672d5a576ef8b6960174abb166d00d76155282b50dd596")
        with self.assertRaisesRegex(model.Refused, "independent_request_context"):
            checks.fingerprints(config, self.unit["request"])

    def test_detached_consumer_diagnostics_use_the_selected_executor(self):
        config = deepcopy(self.unit["config"])
        config["header_profile"]["node_revision"] = model.REFERENCE_GAS_SOURCE_PINS["node"][1]
        header, query = checks.consumer_context_diagnostics(config, checks.fingerprints(config))
        self.assertEqual(header["node_revision"], model.REFERENCE_GAS_SOURCE_PINS["node"][1])
        self.assertEqual(query["entry"]["executor_revision"], model.REFERENCE_GAS_SOURCE_PINS["executor"][1])
        self.assertEqual(query["entry"]["sdk_revision"], model.SOURCE_PINS["contract_sdk"][1])
        self.assertNotEqual(query["entry"]["executor_revision"], model.SOURCE_PINS["executor"][1])

    def test_unknown_node_revision_has_no_implicit_original_pair(self):
        for revision in ("1" * 40, "latest", model.REFERENCE_GAS_SOURCE_PINS["node"][1].upper(), None):
            with self.subTest(revision=revision), self.assertRaises(model.Refused):
                model.query_source_pair(revision)

    def test_selected_local_keys_remain_the_original_literal_ledger_keys(self):
        _, profile = capture.selected_profile(self.new, ROOT)
        got = checks.ledger_keys(profile, 0)
        self.assertEqual(got["batch_entry"].hex(), "0301b3b6e5adcb4d0cad7fcef33598c6318c6318c00402000000010000000000000000")
        self.assertEqual(got["domain_record"].hex(), "0301b3b6e5adcb4d0cad7fcef33598c6318c6318c0040100000001")
        self.assertEqual(got["domain_config"].hex(), "0301b3b6e5adcb4d0cad7fcef33598c6318c6318c0041500000001")

    def lockfile(self, contract):
        packages = {"": {"dependencies": {}}}
        for role, name in (("typescript_client", "zeno-client"), ("typescript_sdk", "znn-typescript-sdk")):
            selected = contract.data["sources"][role]
            repo, revision = selected["repository"], selected["revision"]
            packages[""]["dependencies"][name] = "github:" + repo + "#" + revision
            packages["node_modules/" + name] = {"resolved": "git+ssh://git@github.com/" + repo + ".git#" + revision,
                "integrity": "sha512-" + base64.b64encode(bytes(64)).decode("ascii")}
        return model.canonical({"packages": packages})

    def test_lockfile_cannot_reuse_the_original_typescript_sdk(self):
        rows = sources.lockfile_binding(self.new, self.lockfile(self.new))
        self.assertEqual(rows[1]["revision"], "75cd2565bd388c1df6b441bfcc1670e8da483c77")
        with self.assertRaisesRegex(model.Refused, "npm_dependency_source_binding"):
            sources.lockfile_binding(self.new, self.lockfile(self.old))

    def metadata(self, role):
        item = self.new.data["qualified_components"][role]
        repository = {"id": 17, "full_name": artifacts.REPOSITORY}
        run = {"id": item["run_id"], "run_attempt": 1, "status": "completed", "conclusion": "success",
               "event": "push", "head_branch": "main", "path": artifacts.WORKFLOWS[role],
               "head_sha": model.REFERENCE_GAS_COMPONENT_REVISION,
               "repository": repository, "head_repository": dict(repository)}
        artifact = {"id": item["artifact_id"], "expired": False, "size_in_bytes": item["archive"]["bytes"],
                    "digest": "sha256:" + item["archive"]["sha256"], "workflow_run": {
                        "id": item["run_id"], "repository_id": 17, "head_repository_id": 17,
                        "head_sha": run["head_sha"]}}
        return run, artifact

    def test_both_selected_binary_components_bind_their_own_run_and_workflow(self):
        for role in artifacts.WORKFLOWS:
            run, artifact = self.metadata(role)
            result = artifacts.bind_metadata(self.new, role, run, artifact)
            self.assertEqual(result["source_revision"], model.REFERENCE_GAS_COMPONENT_REVISION)
            self.assertFalse(result["new_ci_execution_qualified"])

    def test_old_source_or_expired_artifact_cannot_enter_the_new_selection(self):
        for role in artifacts.WORKFLOWS:
            run, artifact = self.metadata(role)
            run["head_sha"] = model.QUALIFIED_COMPONENT_REVISION
            with self.assertRaisesRegex(model.Refused, "artifact_run_source"):
                artifacts.bind_metadata(self.new, role, run, artifact)
            run, artifact = self.metadata(role)
            artifact["expired"] = True
            with self.assertRaisesRegex(model.Refused, "artifact_digest_or_expiry"):
                artifacts.bind_metadata(self.new, role, run, artifact)

    def dispatch_environment(self, path, contract):
        revision = "1" * 40
        event = {"inputs": {"execute_owned_fixture": "true", "ack_contract_sha256": contract.sha256,
                            "expected_source_revision": revision}}
        path.write_bytes(model.canonical(event))
        environment = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted",
            "RUNNER_OS": "Linux", "RUNNER_ARCH": "X64", "GITHUB_REPOSITORY": artifacts.REPOSITORY,
            "GITHUB_ACTOR": "edgepillar", "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_SHA": revision, "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_EVENT_PATH": str(path)}
        run = {"id": 123, "run_attempt": 1, "event": "workflow_dispatch", "head_branch": "main",
            "path": ".github/workflows/owned-devnet-query.yml", "head_sha": revision,
            "repository": {"full_name": artifacts.REPOSITORY}, "head_repository": {"full_name": artifacts.REPOSITORY},
            "actor": {"login": "edgepillar"}, "triggering_actor": {"login": "edgepillar"}}
        return environment, event, run

    def test_dispatch_selects_either_contract_from_its_exact_acknowledged_digest(self):
        with tempfile.TemporaryDirectory(prefix="regular-dispatch-control-") as temporary:
            for contract in (self.old, self.new):
                environment, _, run = self.dispatch_environment(Path(temporary) / "event.json", contract)
                recorder = mock.Mock()
                recorder.run.return_value.stdout.return_value = model.canonical(run)
                with mock.patch.object(runner, "verify_checkout") as verify:
                    selected, execution = runner.dispatch(recorder, environment, {}, ROOT, Path(temporary))
                self.assertEqual(selected, contract)
                self.assertEqual(execution, model.ExecutionIdentity("1" * 40, 123, 1, "edgepillar"))
                self.assertEqual(recorder.run.call_count, 1)
                verify.assert_called_once()

    def test_unknown_dispatch_digest_refuses_before_api_or_engine_contact(self):
        with tempfile.TemporaryDirectory(prefix="regular-dispatch-refusal-") as temporary:
            path = Path(temporary) / "event.json"
            environment, event, _ = self.dispatch_environment(path, self.new)
            event["inputs"]["ack_contract_sha256"] = "a" * 64
            path.write_bytes(model.canonical(event))
            recorder = mock.Mock()
            with self.assertRaisesRegex(model.Refused, "selected_contract_digest"):
                runner.dispatch(recorder, environment, {}, ROOT, Path(temporary))
            recorder.run.assert_not_called()
            recorder.seal.assert_not_called()

    def test_archive_inspection_can_explicitly_select_another_contract_file(self):
        raw, specification = helper()
        # This tiny synthetic ZIP tests the CLI selection; it is not a CI binary.
        value = self.new.data
        value["qualified_components"]["parent_oracle"] = specification
        contract = model.Contract(model.canonical(value), "b" * 64)
        with tempfile.TemporaryDirectory(prefix="regular-contract-inspection-") as temporary:
            archive = Path(temporary) / "fixture.zip"
            archive.write_bytes(raw)
            selected_path = HERE / "reference-gas-contract.json"
            output = io.BytesIO()
            with mock.patch.object(inputs, "read_contract", return_value=contract) as read:
                self.assertEqual(inputs.main(["--component", "parent_oracle", "--archive", str(archive),
                    "--contract", str(selected_path)], output, io.StringIO()), 0)
            read.assert_called_once_with(selected_path)
            self.assertEqual(json.loads(output.getvalue())["contract_sha256"], contract.sha256)
            self.assertEqual(list(Path(temporary).iterdir()), [archive])

    def test_retained_hosted_selection_uses_the_explicit_new_contract(self):
        with tempfile.TemporaryDirectory(prefix="regular-reference-hosted-") as temporary:
            args = ["select-hosted", "--contract", str(HERE / "reference-gas-contract.json"),
                "--expect-source-revision", SOURCE, "--expect-run-id", str(RUN),
                "--expect-artifact-id", str(ARTIFACT), "--expect-contract-sha256", self.new.sha256]
            for name, row in zip(("run", "jobs", "artifact"), hosted_metadata()):
                path = Path(temporary) / (name + ".json")
                path.write_bytes(model.canonical(row))
                args.extend(["--" + name + "-metadata", str(path)])
            output, error = io.BytesIO(), io.StringIO()
            with mock.patch.object(review, "review_stream", side_effect=AssertionError("unexpected archive read")):
                self.assertEqual(review.main(args, output, error), 0, error.getvalue())
            self.assertEqual(json.loads(output.getvalue())["expected_contract_sha256"], self.new.sha256)
            wrong = list(args)
            wrong[wrong.index("--expect-contract-sha256") + 1] = self.old.sha256
            with mock.patch.object(review, "read_hosted_metadata",
                                   side_effect=AssertionError("metadata read after wrong contract")):
                self.assertEqual(review.main(wrong, io.BytesIO(), io.StringIO()), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
