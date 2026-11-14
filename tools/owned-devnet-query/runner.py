# SPDX-License-Identifier: GPL-3.0-only
"""Manual owned chain-69 execution on one fresh GitHub-hosted runner."""
from __future__ import annotations

import os
from pathlib import Path
import platform
import re
import stat
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from artifacts import API_LIMIT, Artifacts, api_json
from budget import Budget, evidence_bytes
import capture
from engine import Engine, NODE_ROLES, STOP_STATE_FILE
from images import Builder
import model
from model import Refused, canonical, require, same
from node_toolchain import Installer
from packages import Preparer as Packages, installed_entries
from process import CommandFailed, Recorder, regular_pin
from sources import Preparer as Sources

SYSTEM = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C",
          "GOTOOLCHAIN": "local", "GOMAXPROCS": "2", "PYTHONDONTWRITEBYTECODE": "1"}
REVIEW_FILES = {"dispatch-selection.json", "engine-admission.json", "image-preparation.json",
    "image-build-node.json", "image-build-executor.json",
    "selected-sources.json", "runtime-layout.json", "runtime-input-pins.json", "package-preparation.json",
    "selected-query-header.json", "selected-capture-frontier.json", "closed-ledger-provenance.json",
    "query-config.json", "query-request.json", "query-context-pins.json", "consumer-comparison.json",
    "owned-container-cleanup.json", "budget-report.json", "terminal.json",
    "input-consumer-selection.json", "input-parent-oracle-selection.json", "node-toolchain-intake.json"}


def fresh_directory(path):
    path = Path(path)
    require(path.is_absolute() and path.parent.resolve(strict=True) == path.parent
            and path.parent.stat().st_uid == os.getuid(), "runner_workspace_parent")
    path.mkdir(mode=0o700)
    return path


def dispatch(recorder, environment, gh_environment, checkout, workspace):
    event_path = Path(environment["GITHUB_EVENT_PATH"])
    with event_path.open("rb") as stream:
        event = api_json(stream.read(API_LIMIT + 1))
    revision = model.digest(environment["GITHUB_SHA"], model.HEX40)
    run_id = environment["GITHUB_RUN_ID"]
    require(re.fullmatch(r"[1-9][0-9]{0,19}", run_id) is not None, "dispatch_run_id")
    inputs = event.get("inputs")
    require(type(inputs) is dict and "ack_contract_sha256" in inputs, "dispatch_inputs")
    contract = model.read_selected_contract(HERE, inputs["ack_contract_sha256"])
    # Check exact inputs before any artifact transport or Docker operation.
    result = recorder.run("dispatch-api", ["/usr/bin/gh", "api", "--method", "GET",
        f"repos/edgepillar/zenon-spv/actions/runs/{run_id}/attempts/1"], workspace,
        gh_environment, timeout=25, stdout_cap=API_LIMIT, stderr_cap=4096)
    execution = model.require_dispatch_metadata(contract, environment, event,
        api_json(result.stdout(API_LIMIT)), revision)
    verify_checkout(recorder, checkout, execution, "initial")
    recorder.seal("dispatch-selection.json", canonical({"format": "owned-devnet-dispatch-selection/v1",
        "repository": "edgepillar/zenon-spv", "source_revision": revision, "contract_sha256": contract.sha256,
        "run_id": execution.run_id, "run_attempt": execution.run_attempt, "actor": execution.actor,
        "host_attested": False, "explicit_dispatch_selected": True}))
    return contract, execution


def verify_checkout(recorder, checkout, execution, phase):
    def git(label, *args, cap=1024):
        return recorder.run(phase + "-checkout-" + label,
            ["/usr/bin/git", "--no-optional-locks", *args], checkout, SYSTEM,
            stdout_cap=cap, stderr_cap=4096, timeout=12).stdout(cap)

    require(git("revision", "rev-parse", "HEAD") == (execution.source_revision + "\n").encode("ascii")
            and git("status", "status", "--porcelain=v1", "-z", "--untracked-files=all") == b"",
            "runner_source_checkout_changed")


def fixture_flow(contract, recorder, engine, sources, node, prepared, phase, guard):
    source_root = sources.paths["devnet"]
    if phase == "configure":
        engine.require_running_closure(NODE_ROLES)
        script, arguments, timeout = "src/cli.ts", ["configure"], 420
    elif phase == "deposit":
        engine.require_running_closure()
        script, arguments, timeout = "flows/deposit.ts", [], 420
    else:
        raise Refused("fixture_flow_scope")
    sources.verify()
    same(installed_entries(contract, source_root), prepared.report["installed_entries"],
         "fixture_packages_changed")
    same(regular_pin(node.node, 128 << 20), contract.data["node_toolchain"]["node_binary"],
         "fixture_node_binary_changed")
    environment = prepared.environment
    environment.update({key: value for key, value in engine.environment.items() if key.startswith("DOCKER_")})
    tsx = source_root / "node_modules/tsx/dist/cli.mjs"
    recorder.run("fixture-" + phase, [str(node.node), str(tsx), script, *arguments], source_root,
                 environment, guard=guard, timeout=timeout, stdout_cap=1 << 20, stderr_cap=1 << 20)
    sources.verify()
    engine.require_running_closure(NODE_ROLES if phase == "configure" else model.SERVICES)


def evidence_index(recorders, extra):
    entries = []
    for recorder in recorders:
        recorder.check()
        allowed = set(REVIEW_FILES)
        if recorder.directory.name == "evidence":
            allowed.update(name for name in recorder.names if STOP_STATE_FILE.fullmatch(name) is not None)
        for record in recorder.records:
            for field in ("launch", "started", "receipt"):
                if record[field] is not None:
                    allowed.add(record[field]["file"])
        allowed.update(extra.get(recorder.directory.name, ()))
        for name in sorted(recorder.names & allowed):
            path = recorder.directory / name
            entries.append({"path": f"{recorder.directory.name}/{name}", **regular_pin(path, 2 << 20)})
    return entries


def publish_paths(path, workspace, entries):
    path = Path(path)
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid()
            and path.resolve(strict=True) == path, "workflow_output_identity")
    files = [workspace / entry["path"] for entry in entries]
    files.append(workspace / "evidence/evidence-index.json")
    require(all("\n" not in str(name) and "\r" not in str(name) for name in files), "workflow_output_path")
    descriptor = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "a", encoding="utf-8") as stream:
        require(os.path.samestat(info, os.fstat(stream.fileno())), "workflow_output_identity")
        stream.write("evidence_paths<<SPV_OWNED_EVIDENCE_END\n")
        for name in files:
            stream.write(str(name) + "\n")
        stream.write("SPV_OWNED_EVIDENCE_END\n")


def execute(environment, workspace, checkout):
    record = Recorder(workspace / "evidence")
    transport = Recorder(workspace / "transport")
    private = fresh_directory(workspace / "scratch")
    tool_environment = dict(SYSTEM, TMPDIR=str(private))
    gh_environment = dict(tool_environment, GH_TOKEN=environment["GH_TOKEN"],
        GH_HOST="github.com", GH_CONFIG_DIR=str(private / "gh"), GH_PROMPT_DISABLED="1",
        GH_NO_UPDATE_NOTIFIER="1", GH_NO_EXTENSION_UPDATE_NOTIFIER="1")
    engine = budget = execution = contract = rpc = None
    stage, outcome, reason = "dispatch", "UNKNOWN", None
    extra = set()
    try:
        contract, execution = dispatch(record, environment, gh_environment, checkout, workspace)
        descriptor, profile = capture.selected_profile(contract, checkout)
        # Take the reviewed supervisor bytes before dependency scripts run.
        # The privileged interpreter executes this snapshot, not a later path.
        with (HERE / "closed_reader.py").open("rb") as stream:
            reader_raw = stream.read((16 << 10) + 1)
        require(0 < len(reader_raw) <= 16 << 10, "closed_reader_source_bound")
        reader_source = reader_raw.decode("utf-8")
        stage = "host-admission"
        budget = Budget(contract, workspace, record)
        guard = budget.check
        engine = Engine(contract, execution, record, workspace / "engine", ["/usr/bin/docker"],
                        tool_environment, guard)
        engine.probe()
        require(engine.docker_root == contract.data["runtime"]["closed_oracle_readonly_docker_root"],
                "closed_reader_docker_root")
        budget.bind_engine_filesystem(engine.docker_root)
        stage = "inputs"
        artifacts = Artifacts(contract, transport, workspace / "binaries", ["/usr/bin/gh"],
                              gh_environment, guard)
        artifacts.preflight()
        consumer = artifacts.fetch("consumer").binaries
        oracle = artifacts.fetch("parent_oracle").binaries
        node = Installer(contract, transport, workspace / "node-toolchain",
                         ["/usr/bin/curl", "--disable"], tool_environment, guard).fetch()
        consumer.enable_execution()
        oracle.enable_execution()
        node = node.enable_execution()
        stage = "sources"
        sources = Sources(contract, record, workspace / "source", ["/usr/bin/git"],
                          tool_environment, guard).prepare()
        stage = "runtime-inputs"
        files = engine.prepare_files(sources)
        stage = "packages"
        prepared = Packages(contract, record, sources, node, workspace / "packages",
                            tool_environment, guard).prepare()
        stage = "images"
        images = Builder(contract, engine, sources, workspace / "images").prepare()
        stage = "nodes"
        files.verify()
        engine.create_layout()
        for role in model.SERVICES[:4]:
            engine.create(role, images.image_for(role), files)
            engine.start(role)
        rpc = capture.LocalRpc(contract, record, workspace, "/usr/bin/curl", tool_environment, guard)
        rpc.wait_height(contract.data["selection"]["source_expected_first_v3_height"], starting=True)
        opening = rpc.opening()
        extra.add("opening-momentums.json")
        stage = "fixture-configuration"
        fixture_flow(contract, record, engine, sources, node, prepared, "configure", guard)
        stage = "fixture-deposit"
        for role in ("executor", "gateway"):
            engine.create(role, images.image_for(role), files)
            engine.start(role)
        rpc.wait_gateway()
        fixture_flow(contract, record, engine, sources, node, prepared, "deposit", guard)
        selected = rpc.select_query_header()
        rpc.wait_height(selected.height + contract.data["limits"]["header_depth"])
        stage = "provider-capture"
        engine.stop_producers_and_clients()
        window = capture.collect(contract, record, rpc, consumer, opening, selected,
                                 workspace, tool_environment, guard)
        extra.add("provider.json")
        stage = "closed-ledger"
        ledger = engine.close_rpc()
        schedule = capture.read_closed_schedule(contract, record, engine, ledger, window, sources,
                                                oracle, workspace, tool_environment, guard, reader_source)
        for index, _ in enumerate(capture.oracle_requests(contract, window), 1):
            extra.update({f"parent-oracle-{index:02d}.request.json", f"parent-oracle-{index:02d}.stdout"})
        stage = "consumer"
        matched = capture.query(contract, record, window, schedule, descriptor, profile, consumer,
                                workspace, tool_environment, guard)
        extra.add("consume-query.stdout")
        verify_checkout(record, checkout, execution, "final")
        budget.check(force=True)
        require(matched["gateway_stored_fields_match"] is True, "gateway_stored_fields_differ")
        outcome = "DEVNET_CONSUMER_ACCEPTED"
    except CommandFailed as error:
        outcome = "FAILURE" if error.result.receipt["output_complete"] is True else "UNKNOWN"
        reason = "command_failed" if outcome == "FAILURE" else "command_incomplete"
    except Refused as error:
        outcome, reason = "REFUSED", error.reason
    except KeyboardInterrupt:
        outcome, reason = "UNKNOWN", "controller_interrupted"
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
        outcome, reason = "FAILURE", type(error).__name__
    finally:
        closure = None
        if engine is not None:
            try:
                closure = engine.cleanup()
            except (OSError, ValueError, KeyError, TypeError):
                closure = None
        closed = closure is not None and all(row["observed_closed"] is True for row in closure)
        if budget is not None:
            record.seal("budget-report.json", canonical(budget.report()))
        if outcome == "DEVNET_CONSUMER_ACCEPTED" and not closed:
            outcome, reason = "UNKNOWN", "owned_service_closure_unresolved"
        if outcome == "DEVNET_CONSUMER_ACCEPTED" and evidence_bytes(record.directory, record.identity) \
                > model.LIMITS["max_evidence_bytes"] - (2 << 20):
            outcome, reason = "REFUSED", "final_evidence_reservation"
        record.seal("terminal.json", canonical({"format": "owned-devnet-query-terminal/v1",
            "outcome": outcome, "stage": stage, "reason": reason,
            "source_revision": execution.source_revision if execution else None,
            "contract_sha256": contract.sha256 if contract else None,
            "owned_runtime_observed_closed": closed and bool(closure),
            "run_id": execution.run_id if execution else None,
            "run_attempt": execution.run_attempt if execution else None,
            "production_qualified": False, "consensus_finality_or_funds_release": False}))
        if rpc is not None:
            extra.update(rpc.retained_frontiers)
        entries = evidence_index((record, transport), {"evidence": extra})
        index = canonical({"format": "owned-devnet-evidence-index/v1",
            "files": entries, "transport_archive_copies": 0,
            "raw_service_logs_or_private_configuration_exported": False})
        require(sum(row["bytes"] for row in entries) + len(index) <= model.LIMITS["max_evidence_bytes"],
                "retained_evidence_bound")
        record.seal("evidence-index.json", index)
        publish_paths(environment["GITHUB_OUTPUT"], workspace, entries)
    return 0 if outcome == "DEVNET_CONSUMER_ACCEPTED" else 1


def main():
    try:
        environment = dict(os.environ)
        require(platform.system() == "Linux" and os.geteuid() != 0
                and environment.get("GITHUB_ACTIONS") == "true"
                and environment.get("RUNNER_ENVIRONMENT") == "github-hosted"
                and environment.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
                and environment.get("GITHUB_REPOSITORY") == "edgepillar/zenon-spv"
                and environment.get("GITHUB_ACTOR") == "edgepillar", "owned_dispatch_host")
        checkout = HERE.parents[1]
        require(checkout == Path(environment["GITHUB_WORKSPACE"]).resolve(strict=True), "owned_dispatch_checkout")
        workspace = fresh_directory(Path(environment["RUNNER_TEMP"]) / "spv-owned-devnet")
        return execute(environment, workspace, checkout)
    except (OSError, ValueError, KeyError, TypeError):
        sys.stderr.write("Owned devnet controller refused or did not complete.\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
