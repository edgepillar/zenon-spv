# SPDX-License-Identifier: GPL-3.0-only
"""Bounded read-only capture and finite schedule selection for one owned node."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import time

from artifacts import api_json
from closed_reader import LEDGER, ORACLE_NAME
import model
from model import Refused, canonical, exact_keys, require, same, uint
from process import CommandFailed, regular_pin
from query_checks import address_bytes, consumer_result, fingerprints, header_facts, schedule_hash

RPC_URL = "http://127.0.0.1:35997"
GATEWAY_URL = "http://127.0.0.1:35999"
ORACLE_REPORT_BYTES = 256 << 10
ORACLE_TRUE = {"read_only_ledger", "frontier_unchanged", "manager_stop_succeeded"}
ORACLE_FALSE = {"Chain_Init_called", "Chain_Start_called", "consensus_Start_called",
    "header_signature_checked", "accepting_schedule_created",
    "authenticated_election_or_fork_choice", "network_or_state_value_accepted", "production_qualified"}
ORACLE_FIELDS = ORACLE_TRUE | ORACLE_FALSE | {
    "format", "node_revision", "genesis", "frontier", "request_sha256", "rows"}
ORACLE_ROW_FIELDS = {"header", "parent", "version", "state_root", "timestamp", "producing_addr",
                     "source_parent_slot", "matches_stored_key_producer"}
SLOT_FIELDS = {"timestamp", "tick", "slot_start", "slot_end", "producer",
               "name", "proof_time", "proof_block", "proof_block_timestamp"}


def rpc_result(raw, request_id, limit):
    envelope = api_json(raw, limit)
    exact_keys(envelope, {"jsonrpc", "id", "result"}, "owned_rpc_result_envelope")
    require(envelope["jsonrpc"] == "2.0" and type(envelope["id"]) is int
            and envelope["id"] == request_id and type(envelope["result"]) is dict,
            "owned_rpc_result_identity")
    return envelope["result"]


@dataclass(frozen=True)
class Header:
    height: int
    hash: str
    parent_hash: str
    version: int
    root: str
    timestamp: int
    producing_addr: str | None

    @classmethod
    def read(cls, row, chain):
        facts = header_facts(row)
        require(row["chainIdentifier"] == chain, "observed_chain")
        model.digest(facts["hash"])
        return cls(**{key: facts[key] for key in cls.__dataclass_fields__})

    def identifier(self):
        return {"hash": self.hash, "height": self.height}


def opening_headers(contract, rows):
    selected = contract.data["selection"]
    require(type(rows) is list and len(rows) == 3, "opening_header_count")
    genesis, anchor, first = (Header.read(row, selected["chain_id"]) for row in rows)
    require((genesis.height, anchor.height, first.height) ==
            (1, selected["anchor_height"], selected["source_expected_first_v3_height"])
            and (genesis.version, anchor.version, first.version) == (1, 1, 3)
            and genesis.hash == selected["genesis_h1_hash"]
            and genesis.parent_hash == "0" * 64
            and anchor.parent_hash == genesis.hash and first.parent_hash == anchor.hash
            and genesis.timestamp < anchor.timestamp < first.timestamp,
            "observed_genesis_anchor_or_v3_boundary")
    return genesis, anchor, first


class LocalRpc:
    """The three fixed read methods of the loopback-owned RPC service."""
    def __init__(self, contract, recorder, directory, curl, environment, guard):
        self.contract, self.recorder, self.directory = contract, recorder, Path(directory)
        self.curl, self.environment, self.guard = curl, environment, guard
        self.calls = 0

    def _read(self, method, parameters, cap, *, stdout_name=None):
        self.calls += 1
        require(self.calls <= 96, "owned_rpc_call_bound")
        request_id = self.calls
        label = "rpc-" + str(request_id).zfill(2)
        request = {"jsonrpc": "2.0", "id": request_id, "method": method, "params": parameters}
        raw = json.dumps(request, separators=(",", ":"), allow_nan=False)
        self.recorder.seal(label + ".request.json", raw.encode("ascii") + b"\n")
        result = self.recorder.run(label, [self.curl, "--disable", "--silent", "--show-error",
            "--fail", "--noproxy", "*", "--proto", "=http", "--connect-timeout", "2",
            "--max-time", "5", "--max-filesize", str(cap), "--header", "Content-Type: application/json",
            "--data-binary", raw, GATEWAY_URL if method == "zeno_getHead" else RPC_URL],
            self.directory, self.environment,
            timeout=7, stdout_cap=cap, stderr_cap=4096, stdout_name=stdout_name, guard=self.guard)
        return rpc_result(result.stdout(cap), request_id, cap)

    def frontier(self):
        return Header.read(self._read("ledger.getFrontierMomentum", [], 128 << 10),
                           self.contract.data["selection"]["chain_id"])

    def opening(self):
        result = self._read("ledger.getMomentumsByHeight", [1, 3], 384 << 10,
                            stdout_name="opening-momentums.json")
        rows = result.get("list")
        require(type(result.get("count")) is int and result["count"] >= 3,
                "opening_frontier_count")
        return opening_headers(self.contract, rows)

    def _wait(self, read, ready, *, starting):
        # Preserve every actual attempt. A freshly published loopback port can
        # accept and then close a request before RPC initialization completes.
        # Retry only a complete, quiescent startup failure with no response
        # bytes; malformed data, partial responses and later read failures stop.
        until = time.monotonic() + 90
        for _ in range(30):
            self.guard()
            require(time.monotonic() < until, "owned_rpc_readiness_deadline")
            try:
                value = read()
            except CommandFailed as error:
                receipt = error.result.receipt
                stdout_bytes = receipt["outputs"]["stdout"]["bytes"]
                if not (starting and receipt["output_complete"] is True
                        and receipt["launch_outcome"] == "STARTED"
                        and receipt["process_group_quiescent"] is True and receipt["reason"] is None
                        and type(receipt["actual_exit"]) is int and receipt["actual_exit"] in (7, 28, 56)
                        and type(stdout_bytes) is int and stdout_bytes == 0):
                    raise
            else:
                if ready(value):
                    return value
            time.sleep(3)
        raise Refused("owned_rpc_readiness_deadline")

    def wait_height(self, height, *, starting=False):
        return self._wait(self.frontier, lambda frontier: frontier.height >= height, starting=starting)

    def wait_gateway(self):
        domain = self.contract.data["selection"]["domain_id"]
        return self._wait(lambda: self._read("zeno_getHead", [domain], 32 << 10),
                          lambda row: row.get("status") == "OK", starting=True)

    def select_query_header(self):
        selection = self.contract.data["selection"]
        batch = int(selection["batch_id_decimal"])
        row = self._read("embedded.settlement.getBatch", [selection["domain_id"], batch], 32 << 10)
        same(row.get("domainId"), selection["domain_id"], "selected_batch_domain")
        same(row.get("batchId"), batch, "selected_batch_identity")
        # This DTO is a readiness observation. Its fields never select proof
        # bytes, a new batch, or the header's StateRoot.
        header = self.frontier()
        require(header.version == 3, "selected_query_version")
        self.recorder.seal("selected-query-header.json", canonical(header.identifier()))
        return header


def captured_headers(contract, opening, query, frontier, provider):
    exact_keys(provider, {"version", "momentums", "witnesses", "gateway"}, "owned_provider_fields")
    same(provider["version"], 1, "owned_provider_version")
    genesis, anchor, first = opening
    limits = contract.data["limits"]
    rows = provider["momentums"]
    count = frontier.height - anchor.height
    require(type(rows) is list and len(rows) == count and 1 <= count < limits["max_header_targets"]
            and first.height <= query.height <= frontier.height - limits["header_depth"],
            "selected_header_range_or_depth")
    headers = [genesis, anchor]
    chain = contract.data["selection"]["chain_id"]
    for row in rows:
        header, parent = Header.read(row, chain), headers[-1]
        require(header.version == 3 and header.height == parent.height + 1
                and header.parent_hash == parent.hash and header.timestamp > parent.timestamp,
                "observed_header_continuity")
        headers.append(header)
    require(headers[2] == first and headers[query.height - 1] == query and headers[-1] == frontier,
            "observed_header_selection_changed")
    return tuple(headers)


@dataclass(frozen=True)
class Window:
    headers: tuple[Header, ...]
    query: Header
    provider: object
    provider_result: object


def collect(contract, recorder, rpc, binaries, opening, query, directory, environment, guard):
    """Collect only after the controller stops the producers and clients."""
    frontier = rpc.frontier()
    selection, limits = contract.data["selection"], contract.data["limits"]
    anchor = opening[1]
    require(frontier.version == 3 and query.height <= frontier.height - limits["header_depth"]
            and 1 <= frontier.height - anchor.height < limits["max_header_targets"],
            "selected_header_range_or_depth")
    recorder.seal("selected-capture-frontier.json", canonical(frontier.identifier()))
    require(binaries.verify() == contract.data["qualified_components"]["consumer"]["binaries"],
            "selected_consumer_binary_pins")
    result = recorder.run("collect-provider", [str(binaries.directory / "fetch-bundle"),
        "experimental-batch-context", "--rpc", RPC_URL, "--chain-id", str(selection["chain_id"]),
        "--anchor-height", str(anchor.height), "--anchor-hash", anchor.hash,
        "--height", str(query.height), "--header-hash", query.hash,
        "--tip-height", str(frontier.height), "--tip-hash", frontier.hash,
        "--domain-id", str(selection["domain_id"]), "--batch-id", selection["batch_id_decimal"],
        "--compare-gateway"], directory, environment, stdout_name="provider.json",
        timeout=120, stdout_cap=limits["stdout_bytes"], stderr_cap=16 << 10, guard=guard)
    provider = api_json(result.stdout(limits["stdout_bytes"]), limits["stdout_bytes"])
    headers = captured_headers(contract, opening, query, frontier, provider)
    require(rpc.frontier() == frontier, "capture_frontier_moved")
    return Window(headers, query, provider, result)


def oracle_requests(contract, window):
    limit = contract.data["limits"]["oracle_targets_per_call"]
    for offset in range(1, len(window.headers), limit):
        targets = window.headers[offset:offset + limit]
        raw = json.dumps({"expected_frontier": window.headers[-1].identifier(),
            "targets": [header.identifier() for header in targets], "version": 1},
            sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii") + b"\n"
        require(len(raw) <= 32 << 10, "closed_oracle_request_bound")
        yield raw, targets


def oracle_schedule(contract, window, reports):
    """Require the closed ledger's own parent calculation for every target."""
    reports = iter(reports)
    node = contract.data["sources"]["node"]["revision"]
    entries = []
    for raw, targets in oracle_requests(contract, window):
        report = next(reports, None)
        require(report is not None, "closed_oracle_report_count")
        exact_keys(report, ORACLE_FIELDS, "closed_oracle_report_fields")
        require(report["format"] == "zenon-closed-devnet-parent-slots/v1"
                and report["node_revision"] == node
                and report["request_sha256"] == hashlib.sha256(raw).hexdigest()
                and all(report[k] is True for k in ORACLE_TRUE)
                and all(report[k] is False for k in ORACLE_FALSE), "closed_oracle_provenance")
        same(report["genesis"], window.headers[0].identifier(), "closed_oracle_genesis")
        same(report["frontier"], window.headers[-1].identifier(), "closed_oracle_frontier")
        rows = report["rows"]
        require(type(rows) is list and len(rows) == len(targets), "closed_oracle_row_count")
        for header, row in zip(targets, rows):
            parent = window.headers[header.height - 2]
            exact_keys(row, ORACLE_ROW_FIELDS, "closed_oracle_row_fields")
            for key, value in {"header": header.identifier(), "parent": parent.identifier(),
                    "version": header.version, "state_root": header.root,
                    "timestamp": header.timestamp, "producing_addr": header.producing_addr,
                    "matches_stored_key_producer": True}.items():
                same(row[key], value, "closed_oracle_header_or_parent_binding")
            slot = row["source_parent_slot"]
            exact_keys(slot, SLOT_FIELDS, "closed_oracle_slot_fields")
            producing_addr = address_bytes(slot["producer"]).hex()
            require(producing_addr == row["producing_addr"]
                    and uint(slot["timestamp"]) == uint(slot["slot_start"]) == header.timestamp
                    and uint(slot["slot_end"]) > header.timestamp, "closed_oracle_slot_binding")
            uint(slot["tick"], minimum=0)
            uint(slot["proof_time"], minimum=0)
            proof_block = slot["proof_block"]
            exact_keys(proof_block, {"hash", "height"}, "closed_oracle_proof_block")
            proof = window.headers[uint(proof_block["height"], maximum=parent.height) - 1]
            same(proof_block, proof.identifier(), "closed_oracle_proof_block")
            same(slot["proof_block_timestamp"], proof.timestamp, "closed_oracle_proof_block_time")
            if header.version == 3:
                entries.append({"height": header.height, "timestamp_unix": slot["timestamp"],
                                "producing_addr": producing_addr})
    require(next(reports, None) is None, "closed_oracle_report_count")
    schedule = {"chain_id": contract.data["selection"]["chain_id"],
        "coverage": [{"from_height": window.headers[2].height,
                      "through_height": window.headers[-1].height}], "entries": entries,
        "generated_at": 0, "source_peers": [], "source_heights": {}}
    schedule["schedule_hash"] = schedule_hash(schedule).hex()
    return schedule


def selected_profile(contract, checkout):
    selection = contract.data["selection"]
    directory = Path(checkout) / "internal/testdata/conformance"
    values = []
    for name, key in model.metadata_files(contract):
        path = directory / name
        pin = regular_pin(path, 16 << 10)
        with path.open("rb") as stream:
            raw = stream.read((16 << 10) + 1)
        require(len(raw) == pin["bytes"] and hashlib.sha256(raw).hexdigest() ==
                pin["sha256"] == selection[key], "selected_local_profile_pin")
        values.append(api_json(raw, 16 << 10))
    descriptor, profile = values
    require(profile["version"] == 2 and profile["entry"]["version"] == 2
            and profile["entry"]["runtime_identity"] == selection["descriptor_sha256"]
            and profile["entry"]["domain_id"] == selection["domain_id"]
            and profile["entry"]["settlement"] == selection["settlement_hex"], "selected_profile_binding")
    return descriptor, profile


def query_inputs(contract, window, schedule, profile):
    selected, limits = contract.data["selection"], contract.data["limits"]
    genesis, anchor, first = window.headers[:3]
    tip, target = window.headers[-1], window.query

    def trust_root(header):
        return {"chain_id": selected["chain_id"], "height": header.height, "header_hash": header.hash}

    config = {"version": 1,
        "header_profile": {"version": 1, "genesis": trust_root(genesis), "anchor": trust_root(anchor),
            "first_v3_height": first.height, "valid_through": tip.height,
            "node_revision": contract.data["sources"]["node"]["revision"],
            "source": "Pinned chain-69 genesis and closed owned RPC ledger parent-slot calculation"},
        "header_policy": {"w": limits["header_depth"], "retain_headers": tip.height - target.height + 1,
                          "max_batch_headers": tip.height - anchor.height},
        "producer_schedule": schedule, "query_profile": profile}
    request = {"context": fingerprints(config)["context"], "height": target.height, "header_hash": target.hash,
               "tip_height": tip.height, "tip_hash": tip.hash, "batch_id": int(selected["batch_id_decimal"])}
    return config, request, fingerprints(config, request)


def read_closed_schedule(contract, recorder, engine, ledger, window, sources, binaries,
                         directory, environment, guard, reader_source):
    """Run only the source-bound oracle against the stopped owned volume."""
    require(LEDGER.fullmatch(ledger) is not None and engine.closed_ledger() == ledger,
            "closed_reader_ledger_binding")
    selected = contract.data["qualified_components"]["parent_oracle"]["binaries"]
    require(binaries.verify() == selected, "selected_oracle_binary_pins")
    oracle, pin = binaries.directory / ORACLE_NAME, selected[ORACLE_NAME]
    genesis = sources.paths["node"] / "docker/devnet/genesis.json"
    selection = contract.data["selection"]
    same(regular_pin(genesis, 16 << 10), {"sha256": selection["genesis_file_sha256"],
        "bytes": selection["genesis_file_bytes"]}, "closed_reader_genesis_pin")
    parent_mount = str(os.stat("/proc/self/ns/mnt").st_ino)
    parent_network = str(os.stat("/proc/self/ns/net").st_ino)
    seconds = contract.data["runtime"]["closed_oracle_supervisor_timeout_seconds"]
    receipts = []

    def reports():
        for index, (raw, _) in enumerate(oracle_requests(contract, window), 1):
            label = "parent-oracle-" + str(index).zfill(2)
            request = recorder.seal(label + ".request.json", raw)
            path = recorder.directory / request["file"]
            result = recorder.run(label, ["/usr/bin/sudo", "-n", "--", "/usr/bin/timeout",
                "--kill-after=3s", f"{seconds}s", "/usr/bin/unshare", "--mount", "--net",
                "--propagation", "private", "--", "/usr/bin/python3", "-I", "-B", "-c", reader_source,
                ledger, str(oracle), str(path), str(genesis), str(pin["bytes"]), pin["sha256"],
                parent_mount, parent_network], directory, environment, guard=guard, stdin_lease=True,
                timeout=seconds + 7, terminate_grace=5, stdout_cap=ORACLE_REPORT_BYTES, stderr_cap=4096)
            receipts.append({"request": request, "stdout": result.receipt["outputs"]["stdout"]})
            yield api_json(result.stdout(ORACLE_REPORT_BYTES), ORACLE_REPORT_BYTES)

    schedule = oracle_schedule(contract, window, reports())
    require(engine.closed_ledger() == ledger, "closed_reader_ledger_changed")
    recorder.seal("closed-ledger-provenance.json", canonical({
        "format": "owned-devnet-closed-ledger-provenance/v1",
        "rpc_container_id": engine.owned["rpc"].identity, "engine_id": engine.admission.engine_id,
        "genesis": window.headers[0].identifier(), "anchor": window.headers[1].identifier(),
        "frontier": window.headers[-1].identifier(), "first_v3": window.headers[2].identifier(),
        "oracle_binary": pin, "oracle_reports": receipts, "schedule_hash": schedule["schedule_hash"],
        "reader_source_sha256": hashlib.sha256(reader_source.encode("utf-8")).hexdigest(),
        "ledger_copied": False, "ledger_opened_read_only": True}))
    return schedule


def query(contract, recorder, window, schedule, descriptor, profile, binaries, directory, environment, guard):
    config, request, pins = query_inputs(contract, window, schedule, profile)
    config_file = recorder.seal("query-config.json", canonical(config))
    request_file = recorder.seal("query-request.json", canonical(request))
    recorder.seal("query-context-pins.json", canonical(pins))
    same(binaries.verify(), contract.data["qualified_components"]["consumer"]["binaries"],
         "selected_consumer_binary_pins")
    provider = window.provider_result
    with provider.open_stdout(contract.data["limits"]["stdout_bytes"]):
        result = recorder.run("consume-query", [str(binaries.directory / "zenon-spv"),
            "query-experimental-batch-context", "--config", str(recorder.directory / config_file["file"]),
            "--request", str(recorder.directory / request_file["file"]),
            "--expect-header-context", pins["header_context"], "--expect-query-context", pins["context"],
            "--compare-gateway", str(provider.directory / provider.stdout_name)],
            directory, environment, guard=guard, timeout=60, stdout_cap=256 << 10, stderr_cap=4096)
    report = api_json(result.stdout(256 << 10), 256 << 10)
    matched = consumer_result(report, config, request, window.provider, window.query.root, descriptor)
    recorder.seal("consumer-comparison.json", canonical(matched))
    return matched
