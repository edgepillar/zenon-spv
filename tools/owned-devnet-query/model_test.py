# SPDX-License-Identifier: GPL-3.0-only
"""Regular-file and in-memory controls; no engine, wallet, signing or service."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
HERE = Path(__file__).absolute().parent
sys.path.insert(0, str(HERE))
import model


class ModelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = (HERE / "contract.json").read_bytes()
        cls.contract = model.decode_contract(cls.raw)
        cls.value = cls.contract.data

    def test_selected_plan_has_no_execution_authority(self):
        report = model.preparation_report(self.contract, "1" * 40)
        self.assertEqual(report["required_free_bytes"], 19 << 30)
        self.assertEqual(report["runtime_memory_limit_sum"], 8053063680)
        for key in ("execution_authorized", "engine_contacted", "wallet_or_signing_started",
                    "actual_devnet_query_executed", "production_qualified"):
            self.assertIs(report[key], False)
        self.assertEqual(report["status"], "PLAN_ONLY")

    def test_decoded_data_cannot_mutate_reviewed_contract(self):
        decoded = self.contract.data
        decoded["selection"]["chain_id"] = 1
        self.assertEqual(self.contract.data["selection"]["chain_id"], 69)
        self.assertEqual(self.contract.sha256, hashlib.sha256(self.raw).hexdigest())

    def test_regular_file_read(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "contract.json"
            path.write_bytes(self.raw)
            self.assertEqual(model.read_contract(path), self.contract)

    def test_contract_encoding_refusals(self):
        cases = [
            b"", self.raw[:-1], b" " + self.raw, self.raw + b"\n",
            b'{"format":1,"format":2}\n', b'{"x":NaN}\n',
            b'{"x":1.5}\n', b'{"x":-1}\n', b'{"x":' + b"9" * 21 + b"}\n",
            b"[]" + b" " * model.MAX_CONTRACT_BYTES,
        ]
        for raw in cases:
            with self.subTest(size=len(raw), prefix=raw[:20]):
                with self.assertRaises(model.Refused):
                    model.decode_contract(raw)

    def test_cross_binding_and_budget_refusals(self):
        def set_path(value, path, selected):
            for key in path[:-1]:
                value = value[key]
            value[path[-1]] = selected

        cases = [
            (("selection", "chain_id"), 1),
            (("selection", "choose_another_batch_on_absence"), True),
            (("selection", "batch_id_decimal"), "1"),
            (("selection", "anchor_height"), True),
            (("selection", "source_expected_first_v3_height"), 2),
            (("limits", "min_free_bytes"), 1),
            (("limits", "max_new_disk_bytes"), 16 << 30),
            (("limits", "max_elapsed_seconds"), 0),
            (("scope", "production_qualified"), True),
            (("scope", "execution_requires_explicit_dispatch"), False),
            (("runtime", "project"), "another-project"),
            (("runtime", "publish_address"), "0.0.0.0"),
            (("runtime", "host_docker_socket_mounted_into_containers"), True),
            (("images", "runtime"), "alpine:latest"),
            (("sources", "node", "revision"), "a" * 40),
            (("qualified_components", "source_revision"), "b" * 40),
            (("qualified_components", "consumer", "run_attempt"), True),
            (("qualified_components", "consumer", "run_id"), 42113991877),
            (("qualified_components", "parent_oracle", "run_attempt"), 2),
            (("qualified_components", "consumer", "artifact_id"), False),
            (("qualified_components", "consumer", "archive", "sha256"), "0" * 64),
            (("qualified_components", "consumer", "decoded_tar", "bytes"), 128 << 20),
            (("qualified_components", "consumer", "payload", "filename"), "../candidate-v1.tar.xz"),
            (("node_toolchain", "archive_url"), "https://another.example/toolchain"),
            (("node_toolchain", "max_archive_bytes"), 1 << 30),
            (("node_toolchain", "archive_bytes"), 1),
            (("node_toolchain", "sha256"), "a" * 64),
            (("node_toolchain", "npm_version"), "10.9.9"),
            (("node_toolchain", "selected_regular_count"), 1),
            (("node_toolchain", "decoded_tar", "sha256"), "b" * 64),
            (("node_toolchain", "selected_manifest", "sha256"), "c" * 64),
            (("vault_module", "Rust_rebuild_required"), True),
            (("vault_module", "sha256"), "a" * 64),
        ]
        for path, selected in cases:
            with self.subTest(field=".".join(path)):
                changed = copy.deepcopy(self.value)
                set_path(changed, path, selected)
                with self.assertRaises(model.Refused):
                    model.decode_contract(model.canonical(changed))

    def test_unselected_and_missing_inputs_refuse(self):
        for mutation in (
            lambda v: v.__setitem__("provider_root", "a" * 64),
            lambda v: v["source_files"].append(copy.deepcopy(v["source_files"][0])),
            lambda v: v["source_files"].pop(),
            lambda v: v["source_files"][0].__setitem__("path", "../config"),
            lambda v: v["qualified_components"]["consumer"]["binaries"].__setitem__(
                "unselected", {"bytes": 1, "sha256": "a" * 64}),
        ):
            changed = copy.deepcopy(self.value)
            mutation(changed)
            with self.assertRaises(model.Refused):
                model.decode_contract(model.canonical(changed))

    def test_runtime_source_and_selected_genesis_bindings(self):
        for role, path in (("devnet", "config/executor.json"),
                           ("devnet", "scripts/devnet.sh"),
                           ("devnet", "config/gateway.json"), ("executor", "Dockerfile"),
                           ("node", "docker/devnet/genesis.json")):
            changed = copy.deepcopy(self.value)
            row = next(row for row in changed["source_files"]
                       if row["role"] == role and row["path"] == path)
            row["path"] = "unselected-file"
            with self.subTest(role=role, path=path):
                with self.assertRaises(model.Refused):
                    model.decode_contract(model.canonical(changed))
        changed = copy.deepcopy(self.value)
        genesis = next(row for row in changed["source_files"]
                       if row["role"] == "node" and row["path"] == "docker/devnet/genesis.json")
        genesis["sha256"] = "a" * 64
        with self.assertRaisesRegex(model.Refused, "genesis_source_binding"):
            model.decode_contract(model.canonical(changed))

    def test_host_admission_and_counterexamples(self):
        good = {"system": "Linux", "machine": "x86_64",
                "available_memory_bytes": 13 << 30, "effective_cpu_count": 4,
                "free_bytes": 19 << 30}
        result = model.admit_host(self.contract, good)
        self.assertIs(result["OS_aggregate_quota_or_runtime_enforcement_proven"], False)
        for key, value in (("system", "Darwin"), ("machine", "arm64"),
                           ("available_memory_bytes", (12 << 30) - 1),
                           ("effective_cpu_count", True), ("free_bytes", (19 << 30) - 1)):
            with self.subTest(field=key):
                changed = dict(good)
                changed[key] = value
                with self.assertRaises(model.Refused):
                    model.admit_host(self.contract, changed)

    def admission(self):
        return model.admit_engine(self.contract, "selected-engine", "a" * 32, [], [], [])

    def test_dispatch_binds_source_contract_and_actual_run(self):
        revision = "1" * 40
        environment = {
            "GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted",
            "RUNNER_OS": "Linux", "RUNNER_ARCH": "X64",
            "GITHUB_REPOSITORY": "edgepillar/zenon-spv", "GITHUB_ACTOR": "edgepillar",
            "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_SHA": revision,
            "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1",
        }
        event = {"inputs": {"execute_owned_fixture": "true",
                           "ack_contract_sha256": self.contract.sha256,
                           "expected_source_revision": revision}}
        run = {"id": 123, "run_attempt": 1, "event": "workflow_dispatch",
               "path": ".github/workflows/owned-devnet-query.yml",
               "head_sha": revision, "head_branch": "main",
               "repository": {"full_name": "edgepillar/zenon-spv"},
               "head_repository": {"full_name": "edgepillar/zenon-spv"},
               "actor": {"login": "edgepillar"}, "triggering_actor": {"login": "edgepillar"}}
        expected = model.ExecutionIdentity(revision, 123, 1, "edgepillar")
        self.assertEqual(model.require_dispatch_metadata(
            self.contract, environment, event, run, revision), expected)
        for key, value in (
                ("GITHUB_EVENT_NAME", "pull_request"), ("GITHUB_EVENT_NAME", "push"),
                ("GITHUB_ACTOR", "another"), ("GITHUB_REPOSITORY", "another/fork"),
                ("GITHUB_SHA", "2" * 40), ("GITHUB_RUN_ATTEMPT", "2"),
                ("GITHUB_RUN_ID", True), ("RUNNER_ENVIRONMENT", "self-hosted"),
                ("RUNNER_OS", "Darwin"), ("RUNNER_ARCH", "ARM64")):
            with self.subTest(environment=key, selected=value):
                changed = dict(environment)
                changed[key] = value
                with self.assertRaises(model.Refused):
                    model.require_dispatch_metadata(self.contract, changed, event, run, revision)
        for key, value in (
                ("execute_owned_fixture", False), ("execute_owned_fixture", 1),
                ("ack_contract_sha256", "2" * 64),
                ("expected_source_revision", "2" * 40)):
            with self.subTest(input=key):
                changed = copy.deepcopy(event)
                changed["inputs"][key] = value
                with self.assertRaises(model.Refused):
                    model.require_dispatch_metadata(self.contract, environment, changed, run, revision)
        for key, value in (
                ("id", 124), ("run_attempt", 2), ("event", "push"),
                ("head_sha", "2" * 40), ("head_branch", "unselected"),
                ("repository", {"full_name": "another/fork"}),
                ("head_repository", {"full_name": "another/fork"}),
                ("actor", {"login": "another"}), ("triggering_actor", {"login": "another"}),
                ("path", ".github/workflows/another.yml")):
            with self.subTest(run=key):
                changed = copy.deepcopy(run)
                changed[key] = value
                with self.assertRaises(model.Refused):
                    model.require_dispatch_metadata(self.contract, environment, event, changed, revision)

    def test_malformed_boundary_types_refuse_without_type_errors(self):
        changed = copy.deepcopy(self.value)
        changed["source_files"][0]["role"] = []
        with self.assertRaises(model.Refused):
            model.decode_contract(model.canonical(changed))
        with self.assertRaises(model.Refused):
            model.admit_host(self.contract, {
                "system": "Linux", "machine": [], "available_memory_bytes": 13 << 30,
                "effective_cpu_count": 4, "free_bytes": 19 << 30})
        with self.assertRaises(model.Refused):
            model.admit_engine(self.contract, "engine\nanother", "a" * 32, [], [], [])

    def creation(self, value):
        return {"actual_exit": 0, "output_complete": True,
                "stdout": (value["Id"] + "\n").encode("ascii")}

    def container(self, admission, identity="1" * 64, service="rpc"):
        return {"Id": identity, "Config": {"Labels": model.labels(admission, service)},
                "State": {"Running": False, "Restarting": False, "Dead": False,
                          "Pid": 0, "ExitCode": 0}}

    def test_fresh_engine_refuses_preexisting_resources(self):
        for containers, volumes, networks in ((["1" * 64], [], []),
                                              ([], ["zeno-devnet"], []),
                                              ([], [], ["zeno-devnet"])):
            with self.subTest(containers=bool(containers), volumes=bool(volumes)):
                with self.assertRaises(model.Refused):
                    model.admit_engine(self.contract, "engine", "a" * 32,
                                       containers, volumes, networks)

    def test_container_identity_journal(self):
        admission = self.admission()
        value = self.container(admission)
        owned = model.record_created_container(admission, "selected-engine", value, self.creation(value))
        self.assertEqual(model.require_stopped_container(
            admission, owned, "selected-engine", value), value["Id"])
        mutations = [
            lambda v: v.__setitem__("Id", "2" * 64),
            lambda v: v["Config"]["Labels"].__setitem__(model.LABEL_OWNER, "b" * 32),
            lambda v: v["Config"]["Labels"].__setitem__(model.LABEL_CONTRACT, "b" * 64),
            lambda v: v["Config"]["Labels"].__setitem__(model.LABEL_SERVICE, "gateway"),
            lambda v: v["Config"]["Labels"].__setitem__(model.LABEL_PROJECT, "unrelated"),
            lambda v: v["State"].__setitem__("Running", True),
            lambda v: v["State"].__setitem__("Pid", 7),
            lambda v: v["State"].__setitem__("Restarting", True),
            lambda v: v["State"].__setitem__("Dead", True),
            lambda v: v["State"].__setitem__("ExitCode", 137),
            lambda v: v["State"].__setitem__("ExitCode", False),
        ]
        for mutate in mutations:
            with self.subTest(mutation=mutations.index(mutate)):
                changed = copy.deepcopy(value)
                mutate(changed)
                with self.assertRaises(model.Refused):
                    model.require_stopped_container(admission, owned,
                                                    "selected-engine", changed)
        with self.assertRaises(model.Refused):
            model.require_owned_container(admission, owned, "another-engine", value)
        reused = model.Admission(admission.engine_id, admission.nonce,
                                 admission.contract_sha256, frozenset({value["Id"]}))
        with self.assertRaises(model.Refused):
            model.record_created_container(reused, "selected-engine", value, self.creation(value))

    def test_incomplete_or_unbound_create_receipts_refuse(self):
        admission = self.admission()
        value = self.container(admission)
        good = self.creation(value)
        cases = [
            {"actual_exit": 0, "output_complete": False, "stdout": good["stdout"]},
            {"actual_exit": False, "output_complete": True, "stdout": good["stdout"]},
            {"actual_exit": 1, "output_complete": True, "stdout": good["stdout"]},
            {"actual_exit": 0, "output_complete": True, "stdout": b"2" * 64 + b"\n"},
            {"actual_exit": 0, "output_complete": True, "stdout": good["stdout"] + b"log"},
            {"actual_exit": 0, "output_complete": True, "stdout": good["stdout"][:-1]},
            {"actual_exit": None, "output_complete": False, "stdout": b""},
        ]
        for receipt in cases:
            with self.subTest(exit=receipt["actual_exit"], size=len(receipt["stdout"])):
                with self.assertRaises(model.Refused):
                    model.record_created_container(admission, "selected-engine", value, receipt)

    def test_exact_six_service_closure(self):
        admission = self.admission()
        values = [self.container(admission, format(i + 1, "064x"), service)
                  for i, service in enumerate(model.SERVICES)]
        owned = [model.record_created_container(admission, "selected-engine", value, self.creation(value))
                 for value in values]
        self.assertIs(model.require_runtime_closure(admission, owned,
                                                   "selected-engine", values), True)
        builder = self.container(admission, "f" * 64, "buildkit")
        for inspected in (values[:-1], values + [builder], values[:-1] + [builder],
                          values[:-1] + [values[0]]):
            with self.assertRaises(model.Refused):
                model.require_runtime_closure(admission, owned,
                                              "selected-engine", inspected)

    def test_volume_names_and_labels_do_not_authorize_removal(self):
        with self.assertRaises(model.Refused):
            model.volume_or_image_removal_authority(
                "zeno-devnet_rpc-data", {"org.zenon-spv.owner": "a" * 32})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receipt", type=Path)
    parser.add_argument("--source-revision")
    args = parser.parse_args()
    if args.source_revision is not None:
        model.digest(args.source_revision, model.HEX40)
    result = unittest.TextTestRunner(verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(ModelTests))
    receipt = {"format": "owned-devnet-query-model-controls/v1",
               "source_revision": args.source_revision, "root_tests": result.testsRun,
               "failures": len(result.failures), "errors": len(result.errors),
               "skipped": len(result.skipped), "successful": result.wasSuccessful(),
               "engine_or_service_or_signing_executed": False}
    if args.receipt is not None:
        with args.receipt.open("xb") as stream:
            stream.write(model.canonical(receipt))
    print(json.dumps(receipt, sort_keys=True))
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
