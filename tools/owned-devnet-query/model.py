# SPDX-License-Identifier: GPL-3.0-only
"""Reviewed input and ownership model for one owned devnet experiment.

This module performs no Docker, RPC, signing or deployment operation. A parsed
contract and a matching content hash are configuration identity, not authority.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

FORMAT = "owned-devnet-batch-query-contract/v1"
MAX_CONTRACT_BYTES = 64 << 10
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
NONCE = re.compile(r"[0-9a-f]{32}\Z")
SERVICES = ("pillar", "pillar2", "pillar3", "rpc", "executor", "gateway")
PROJECT = "zeno-devnet"
LABEL_OWNER = "org.zenon-spv.owner"
LABEL_CONTRACT = "org.zenon-spv.contract"
LABEL_PROJECT = "com.docker.compose.project"
LABEL_SERVICE = "com.docker.compose.service"
SOURCE_PINS = {
    "devnet": ("Zeno-L2/zeno-devnet", "04dc0797f7bcc02e48e0acba3b0ac49df2d3289d", "git"),
    "node": ("digitalSloth/go-zenon", "938fca3b7787da86827a5eb63371509b36e14761", "git"),
    "executor": ("Zeno-L2/zeno-executor", "caeaf764270b1489a53c860c6006026af208f924", "git"),
    "contract_sdk": ("Zeno-L2/zeno-contract-sdk-rs", "bc1548d75473797f24bb3eb79f5594969c596e39", "git"),
    "typescript_client": ("Zeno-L2/zeno-client-ts", "e9e02d8b12fa4053b8d19b1a4d6257d933bfdc0a", "npm-lock"),
    "typescript_sdk": ("digitalSloth/znn-typescript-sdk", "e3b75183440f8e6543511f7a55e6c66e5736014e", "npm-lock"),
}
QUALIFIED_COMPONENT_REVISION = "8b5deaa16fd0a26249b385946501f088bffef607"
SELECTION = {
    "chain_id": 69, "domain_id": 1, "batch_id_decimal": "0",
    "settlement_hex": "01b3b6e5adcb4d0cad7fcef33598c6318c6318c0",
    "genesis_file_bytes": 8137,
    "genesis_file_sha256": "0dd33b18b147f70b3d3d5f07199a2b45311f6e9b84a98b3f86d8f6c6b45f419a",
    "genesis_h1_hash": "fab7609bae7fd78eb7d2b0d4a5023832f1a6730921b862f2415da25524698dc9",
    "anchor_height": 2, "source_expected_first_v3_height": 3,
    "descriptor_sha256": "cc426de7117a58812a1d43e914de044827abbd4941f4fb4ec123964a5b665d43",
    "query_profile_sha256": "667fb607cd644f3851c491482d30d49034b86fb06442df1d5c78576016aefcd2",
    "choose_another_batch_on_absence": False,
}
LIMITS = {
    "min_free_bytes": 10 << 30, "expected_allocation_bytes": 8 << 30,
    "safety_margin_bytes": 1 << 30, "min_available_memory_bytes": 12 << 30,
    "min_effective_cpus": 4, "max_elapsed_seconds": 2700,
    "max_new_disk_bytes": 8 << 30, "max_source_worktree_bytes": 256 << 20,
    "max_source_tree_records": 16384, "max_header_targets": 512,
    "oracle_targets_per_call": 64, "header_depth": 1,
    "stdout_bytes": 2 << 20, "stderr_bytes": 2 << 20,
    "max_evidence_bytes": 64 << 20,
    "builder_memory_bytes": 4 << 30, "builder_cpu_millis": 2000,
    "node_memory_bytes": 768 << 20, "node_cpu_millis": 500,
    "executor_memory_bytes": 1536 << 20, "executor_cpu_millis": 2000,
    "gateway_memory_bytes": 3 << 30, "gateway_cpu_millis": 2000,
    "pids_per_service": 256, "log_file_bytes": 4 << 20, "log_files": 2,
}
SCOPE = {
    "experimental_only": True, "public_fixture_accounts_only": True,
    "execution_requires_explicit_dispatch": True,
    "actual_devnet_already_qualified": False,
    "authenticated_election_or_fork_choice": False,
    "authenticated_distribution": False, "production_qualified": False,
    "finality_or_funds_release": False,
}
IMAGES = {
    "node_build": "golang:1.23-alpine@sha256:383395b794dffa5b53012a212365d40c8e37109a626ca30d6151c8348d380b5f",
    "runtime": "alpine:3.22@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8",
    "buildkit": "moby/buildkit@sha256:97719ccb2ac86fb44fd36f330a6d302f63dddd5326f3ada24f9c05ccac0d9098",
}
NODE_TOOLCHAIN = {
    "version": "22.23.0", "filename": "node-v22.23.0-linux-x64.tar.xz",
    "archive_url": "https://nodejs.org/dist/v22.23.0/node-v22.23.0-linux-x64.tar.xz",
    "sha256": "14d7de44f235534799f8b171a4050d9a6a4bc99c87e053a25d3d54afa580aa20",
    "archive_bytes": 31048380, "max_archive_bytes": 64 << 20,
    "max_selected_regular_bytes": 256 << 20, "selected_regular_count": 4690,
    "selected_regular_bytes": 194624701, "npm_version": "10.9.8",
    "decoded_tar": {"sha256": "f3d201f6dfca57448c17d30fd5aa023aee110baacadf18037a64507b7bcf6087",
                    "bytes": 202117120},
    "selected_manifest": {"sha256": "acb84491f51aee53487fad603e709eaddabf62ff80771fe70d209d80abc31f7e",
                          "bytes": 1070757},
    "node_binary": {"sha256": "b587d8a062552ab52ecae2a7b0bcd079351d1dc61cf2555fd5994f558274ae58",
                    "bytes": 124835408},
}
RUNTIME = {
    "project": PROJECT, "services": list(SERVICES), "platform": "linux/amd64",
    "runner": "ubuntu-24.04", "fresh_github_hosted_runner_required": True,
    "builder_stopped_before_runtime": True,
    "closed_oracle_private_mount_and_network": True,
    "closed_oracle_readonly_docker_root": "/var/lib/docker",
    "closed_oracle_supervisor_timeout_seconds": 100,
    "executor_root_privileged_private_cgroup_required": True,
    "host_docker_socket_mounted_into_containers": False,
    "host_ports": [35991, 35997, 35998, 35999],
    "builder_host_port": 12340, "publish_address": "127.0.0.1",
    "manual_volume_or_image_removal": False,
}
TOP = {"format", "sources", "source_files", "qualified_components", "node_toolchain",
       "selection", "limits", "runtime", "scope", "images", "vault_module"}


class Refused(ValueError):
    def __init__(self, reason):
        self.reason = reason
        super().__init__(reason)


def require(value, reason):
    if not value:
        raise Refused(reason)


def exact_keys(value, keys, reason):
    require(type(value) is dict and set(value) == set(keys), reason)


def uint(value, maximum=(1 << 64) - 1, minimum=1):
    require(type(value) is int and minimum <= value <= maximum, "integer_bounds")
    return value


def canonical(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode("utf-8")


def same(actual, expected, reason):
    # bool must not compare equal to an integer in a selected policy.
    require(canonical(actual) == canonical(expected), reason)


def digest(value, pattern=HEX64):
    require(type(value) is str and pattern.fullmatch(value) is not None
            and set(value) != {"0"}, "digest_format")
    return value


def pin(value, maximum):
    exact_keys(value, {"sha256", "bytes"}, "pin_fields")
    digest(value["sha256"])
    uint(value["bytes"], maximum)
    return value


def relative_name(value):
    require(type(value) is str and 0 < len(value) <= 256 and value.isascii()
            and "\\" not in value and ":" not in value
            and not value.startswith("/") and all(
                re.fullmatch(r"[A-Za-z0-9_.-]+", part) is not None
                and part not in {"", ".", ".."} for part in value.split("/")),
            "relative_path")
    return value


def parse(raw):
    require(type(raw) is bytes and 0 < len(raw) <= MAX_CONTRACT_BYTES, "contract_bounds")

    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate_field")
            result[key] = value
        return result

    def integer(text):
        require(len(text) <= 20 and text.isdecimal(), "integer_encoding")
        return int(text)

    def unsupported(_):
        raise Refused("number_encoding")

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                           parse_int=integer, parse_float=unsupported,
                           parse_constant=unsupported)
        require(canonical(value) == raw, "canonical_encoding")
    except (UnicodeError, json.JSONDecodeError, RecursionError, OverflowError) as error:
        raise Refused("contract_encoding") from error
    return value


@dataclass(frozen=True)
class Contract:
    raw: bytes
    sha256: str

    @property
    def data(self):
        # No caller receives mutable access to the reviewed internal selection.
        return json.loads(self.raw)


def decode_contract(raw):
    value = parse(raw)
    exact_keys(value, TOP, "contract_fields")
    require(value["format"] == FORMAT, "contract_version")
    same(value["selection"], SELECTION, "selected_query_changed")
    same(value["limits"], LIMITS, "resource_policy_changed")
    same(value["scope"], SCOPE, "scope_changed")
    same(value["runtime"], RUNTIME, "runtime_changed")
    same(value["images"], IMAGES, "build_image_changed")
    expected_sources = {name: {"repository": repo, "revision": revision, "fetch": fetch}
                        for name, (repo, revision, fetch) in SOURCE_PINS.items()}
    same(value["sources"], expected_sources, "source_cohort_changed")
    files = value["source_files"]
    require(type(files) is list and 20 <= len(files) <= 128, "source_file_count")
    seen = set()
    for row in files:
        exact_keys(row, {"role", "path", "git_blob", "sha256", "bytes"}, "source_file_fields")
        require(type(row["role"]) is str and row["role"] in SOURCE_PINS, "source_file_role")
        name = relative_name(row["path"])
        key = (row["role"], name)
        require(key not in seen, "duplicate_source_file")
        seen.add(key)
        digest(row["git_blob"], HEX40)
        pin({"sha256": row["sha256"], "bytes": row["bytes"]}, 256 << 10)
    require({("devnet", p) for p in ("docker-compose.yml", "package.json",
            "package-lock.json", "sources.txt", "src/devnet.ts", "src/cli.ts",
            "flows/deposit.ts", "flows/lib.ts", "config/executor.json",
            "config/gateway.json", "scripts/devnet.sh")} <= seen, "missing_source_input")
    require({("node", p) for p in ("docker-compose.yml", "docker/devnet/Dockerfile",
            "docker/devnet/entrypoint.sh", "docker/devnet/rpc/config.json",
            "docker/devnet/genesis.json")} <= seen
            and ("executor", "Dockerfile") in seen, "missing_runtime_source_input")
    require({("contract_sdk", "examples/vault/artifacts/vault." + suffix)
             for suffix in ("wasm", "hashes.json", "interface.json")} <= seen,
            "missing_vault_input")
    genesis = next(row for row in files if row["role"] == "node"
                   and row["path"] == "docker/devnet/genesis.json")
    require(genesis["sha256"] == SELECTION["genesis_file_sha256"]
            and genesis["bytes"] == SELECTION["genesis_file_bytes"], "genesis_source_binding")
    components = value["qualified_components"]
    exact_keys(components, {"source_revision", "consumer", "parent_oracle"}, "component_fields")
    require(components["source_revision"] == QUALIFIED_COMPONENT_REVISION, "component_revision")
    for name, expected_run, expected_binaries in (
            ("consumer", 42113991642, {"fetch-bundle", "zenon-spv"}),
            ("parent_oracle", 42113991877, {"spv-closed-parent-oracle.exe"})):
        item = components[name]
        keys = {"run_id", "run_attempt", "artifact_id", "archive", "binaries"}
        if name == "consumer":
            keys |= {"payload", "decoded_tar"}
        exact_keys(item, keys, "artifact_fields")
        require(type(item["run_id"]) is int and item["run_id"] == expected_run
                and type(item["run_attempt"]) is int and item["run_attempt"] == 1,
                "artifact_run")
        uint(item["artifact_id"])
        pin(item["archive"], 32 << 20)
        require(type(item["binaries"]) is dict and set(item["binaries"]) == expected_binaries,
                "binary_selection")
        for filename, selected in item["binaries"].items():
            relative_name(filename)
            pin(selected, 32 << 20)
        if name == "consumer":
            exact_keys(item["payload"], {"filename", "sha256", "bytes"}, "payload_fields")
            require(item["payload"]["filename"] == "candidate-v1.tar.xz", "payload_name")
            pin({k: item["payload"][k] for k in ("sha256", "bytes")}, item["archive"]["bytes"])
            pin(item["decoded_tar"], 64 << 20)
    node = value["node_toolchain"]
    same(node, NODE_TOOLCHAIN, "node_toolchain_selection_changed")
    vault = value["vault_module"]
    exact_keys(vault, {"sha256", "bytes", "code_hash_sha3_256", "Rust_rebuild_required"},
               "vault_module_fields")
    pin({k: vault[k] for k in ("sha256", "bytes")}, 1 << 20)
    digest(vault["code_hash_sha3_256"])
    require(vault["Rust_rebuild_required"] is False, "vault_build_scope")
    source_pin = next(row for row in files if row["role"] == "contract_sdk"
                      and row["path"] == "examples/vault/artifacts/vault.wasm")
    require(vault["sha256"] == source_pin["sha256"] and vault["bytes"] == source_pin["bytes"],
            "vault_source_binding")
    return Contract(raw, hashlib.sha256(raw).hexdigest())


def read_contract(path):
    path = Path(path)
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= MAX_CONTRACT_BYTES,
            "contract_file_type_or_size")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "rb") as stream:
        opened = os.fstat(stream.fileno())
        require(stat.S_ISREG(opened.st_mode) and os.path.samestat(before, opened),
                "contract_file_identity")
        raw = stream.read(MAX_CONTRACT_BYTES + 1)
        after = os.fstat(stream.fileno())
    final = path.lstat()
    require(stat.S_ISREG(final.st_mode) and os.path.samestat(opened, after)
            and os.path.samestat(opened, final)
            and opened.st_size == after.st_size == final.st_size == len(raw)
            and opened.st_mtime_ns == after.st_mtime_ns == final.st_mtime_ns,
            "contract_file_changed")
    return decode_contract(raw)


def admit_host(contract, observations):
    exact_keys(observations, {"system", "machine", "available_memory_bytes",
               "effective_cpu_count", "free_bytes"}, "host_observation_fields")
    require(type(observations["system"]) is str and type(observations["machine"]) is str
            and observations["system"] == "Linux" and observations["machine"] in
            {"x86_64", "amd64"}, "native_linux_host_required")
    limits = contract.data["limits"]
    uint(observations["available_memory_bytes"], minimum=limits["min_available_memory_bytes"])
    uint(observations["effective_cpu_count"], minimum=limits["min_effective_cpus"])
    required_free = sum(limits[k] for k in (
        "min_free_bytes", "expected_allocation_bytes", "safety_margin_bytes"))
    uint(observations["free_bytes"], minimum=required_free)
    return {"minimum_free_bytes_with_allocation_and_margin": required_free,
            "runtime_memory_limit_sum": 4 * limits["node_memory_bytes"]
            + limits["executor_memory_bytes"] + limits["gateway_memory_bytes"],
            "OS_aggregate_quota_or_runtime_enforcement_proven": False}


@dataclass(frozen=True)
class ExecutionIdentity:
    source_revision: str
    run_id: int
    run_attempt: int
    actor: str


def require_dispatch_metadata(contract, environment, event, run, source_revision):
    """Check an explicitly selected dispatch; this is not operator approval.

    The caller must obtain the operator's execution decision separately. These
    checks prevent a push, pull request, rerun or changed branch head from using
    the same execution path accidentally. They do not attest the host.
    """
    require(type(environment) is dict and type(event) is dict and type(run) is dict,
            "workflow_metadata")
    selected = {
        "GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted",
        "RUNNER_OS": "Linux", "RUNNER_ARCH": "X64",
        "GITHUB_REPOSITORY": "edgepillar/zenon-spv", "GITHUB_ACTOR": "edgepillar",
        "GITHUB_EVENT_NAME": "workflow_dispatch",
    }
    require(all(environment.get(k) == v for k, v in selected.items()), "workflow_scope")
    digest(source_revision, HEX40)
    require(environment.get("GITHUB_SHA") == source_revision, "workflow_revision")
    run_id = environment.get("GITHUB_RUN_ID")
    require(type(run_id) is str and re.fullmatch(r"[1-9][0-9]{0,19}", run_id) is not None,
            "workflow_run_id")
    require(environment.get("GITHUB_RUN_ATTEMPT") == "1", "workflow_rerun")
    inputs = event.get("inputs")
    exact_keys(inputs, {"execute_owned_fixture", "ack_contract_sha256",
                       "expected_source_revision"}, "dispatch_inputs")
    execute = inputs["execute_owned_fixture"]
    require(execute is True or (type(execute) is str and execute == "true"),
            "dispatch_not_selected")
    require(inputs["ack_contract_sha256"] == contract.sha256
            and inputs["expected_source_revision"] == source_revision,
            "dispatch_selection_changed")
    return bind_owned_workflow_run(run, source_revision, int(run_id))


def bind_owned_workflow_run(run, source_revision, run_id):
    """Bind supplied workflow metadata to the explicitly selected attempt."""
    require(type(run) is dict and type(run.get("id")) is int and run["id"] == run_id
            and type(run.get("run_attempt")) is int and run["run_attempt"] == 1,
            "workflow_run_binding")
    require(run.get("event") == "workflow_dispatch"
            and run.get("path") == ".github/workflows/owned-devnet-query.yml"
            and run.get("head_sha") == source_revision
            and type(run.get("head_branch")) is str
            and run["head_branch"] in {"main", "codex/owned-devnet-query-runner"},
            "workflow_source_binding")
    for field, key, expected in (
            ("repository", "full_name", "edgepillar/zenon-spv"),
            ("head_repository", "full_name", "edgepillar/zenon-spv"),
            ("actor", "login", "edgepillar"), ("triggering_actor", "login", "edgepillar")):
        require(type(run.get(field)) is dict and run[field].get(key) == expected,
                "workflow_actor_or_repository")
    return ExecutionIdentity(source_revision, run_id, 1, "edgepillar")


@dataclass(frozen=True)
class Admission:
    engine_id: str
    nonce: str
    contract_sha256: str
    preexisting_container_ids: frozenset


@dataclass(frozen=True)
class OwnedContainer:
    identity: str
    service: str
    engine_id: str
    nonce: str
    contract_sha256: str


def admit_engine(contract, engine_id, nonce, containers, volume_projects, network_projects):
    require(type(engine_id) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9:._-]{0,255}",
                                                 engine_id) is not None, "engine_identity")
    require(type(nonce) is str and NONCE.fullmatch(nonce) is not None, "owner_nonce")
    require(type(containers) is list and not containers, "fresh_engine_required")
    for projects in (volume_projects, network_projects):
        require(type(projects) is list and all(type(p) is str for p in projects),
                "engine_inventory")
        require(PROJECT not in projects, "preexisting_fixed_project")
    return Admission(engine_id, nonce, contract.sha256, frozenset())


def labels(admission, service):
    require(service in (*SERVICES, "buildkit"), "service_scope")
    return {LABEL_OWNER: admission.nonce, LABEL_CONTRACT: admission.contract_sha256,
            LABEL_PROJECT: PROJECT, LABEL_SERVICE: service}


def inspect_container(admission, current_engine_id, value):
    require(current_engine_id == admission.engine_id, "engine_changed")
    require(type(value) is dict and type(value.get("Config")) is dict, "container_inspection")
    identity = digest(value.get("Id"))
    selected = value["Config"].get("Labels")
    require(type(selected) is dict, "container_labels")
    service = selected.get(LABEL_SERVICE)
    expected = labels(admission, service)
    require(all(selected.get(k) == v for k, v in expected.items()), "container_owner")
    return identity, service


def creation_identity(receipt):
    """Decode only the actual complete stdout of a successful Docker create."""
    exact_keys(receipt, {"actual_exit", "output_complete", "stdout"}, "creation_receipt")
    require(type(receipt["actual_exit"]) is int and receipt["actual_exit"] == 0
            and receipt["output_complete"] is True, "creation_not_complete")
    raw = receipt["stdout"]
    require(type(raw) is bytes and len(raw) == 65 and raw.endswith(b"\n"),
            "creation_identity")
    try:
        return digest(raw[:-1].decode("ascii"))
    except UnicodeError as error:
        raise Refused("creation_identity") from error


def record_created_container(admission, current_engine_id, value, creation_receipt):
    identity, service = inspect_container(admission, current_engine_id, value)
    require(identity == creation_identity(creation_receipt), "creation_identity_mismatch")
    require(identity not in admission.preexisting_container_ids, "preexisting_container")
    return OwnedContainer(identity, service, admission.engine_id, admission.nonce,
                          admission.contract_sha256)


def require_owned_container(admission, owned, current_engine_id, value):
    require(type(owned) is OwnedContainer and owned.engine_id == admission.engine_id
            and owned.nonce == admission.nonce
            and owned.contract_sha256 == admission.contract_sha256, "journal_owner")
    identity, service = inspect_container(admission, current_engine_id, value)
    require(identity == owned.identity and service == owned.service, "container_replaced")
    return owned.identity


def require_stopped_container(admission, owned, current_engine_id, value):
    require_owned_container(admission, owned, current_engine_id, value)
    state = value.get("State")
    require(type(state) is dict and state.get("Running") is False
            and state.get("Restarting") is False and state.get("Dead") is False
            and type(state.get("Pid")) is int and state["Pid"] == 0
            and type(state.get("ExitCode")) is int and state["ExitCode"] == 0,
            "container_not_gracefully_stopped")
    return owned.identity


def require_runtime_closure(admission, owned, current_engine_id, inspected):
    require(type(owned) is list and type(inspected) is list
            and len(owned) == len(inspected) == len(SERVICES), "runtime_container_count")
    require(all(type(item) is OwnedContainer for item in owned), "runtime_journal_type")
    require({item.service for item in owned} == set(SERVICES), "runtime_service_set")
    by_id = {}
    for item in inspected:
        identity, _ = inspect_container(admission, current_engine_id, item)
        require(identity not in by_id, "duplicate_container")
        by_id[identity] = item
    require(set(by_id) == {item.identity for item in owned}, "runtime_identity_set")
    for item in owned:
        require_owned_container(admission, item, current_engine_id, by_id[item.identity])
    return True


def volume_or_image_removal_authority(*_):
    # Names/labels alone cannot establish replacement-safe volume ownership.
    # The fresh hosted VM, rather than a global prune, disposes these resources.
    raise Refused("manual_volume_or_image_removal_not_authorized")


def preparation_report(contract, source_revision=None):
    if source_revision is not None:
        digest(source_revision, HEX40)
    return {"format": "owned-devnet-query-preparation/v1", "status": "PLAN_ONLY",
            "source_revision": source_revision, "contract_sha256": contract.sha256,
            "project": PROJECT, "services": list(SERVICES),
            "required_free_bytes": sum(contract.data["limits"][k] for k in (
                "min_free_bytes", "expected_allocation_bytes", "safety_margin_bytes")),
            "runtime_memory_limit_sum": 4 * LIMITS["node_memory_bytes"]
            + LIMITS["executor_memory_bytes"] + LIMITS["gateway_memory_bytes"],
            "qualified_component_revision": QUALIFIED_COMPONENT_REVISION,
            "execution_authorized": False, "engine_contacted": False,
            "wallet_or_signing_started": False, "actual_devnet_query_executed": False,
            "production_qualified": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", type=Path, default=Path(__file__).with_name("contract.json"))
    parser.add_argument("--source-revision")
    args = parser.parse_args(argv)
    try:
        result = preparation_report(read_contract(args.contract), args.source_revision)
        sys.stdout.buffer.write(canonical(result))
        return 0
    except (Refused, OSError, ValueError) as error:
        reason = error.reason if isinstance(error, Refused) else "input_or_output_failure"
        sys.stderr.write(json.dumps({"format": "owned-devnet-query-preparation/v1",
                                    "status": "REFUSED", "reason": reason}) + "\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
