# SPDX-License-Identifier: GPL-3.0-only
"""Bounded read-only capture and finite schedule selection for one owned node."""
from __future__ import annotations

import base64
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
from query_checks import (address_bytes, consumer_result, fingerprints, header_facts, ledger_keys,
                          opening_batch_witness, schedule_hash)

RPC_URL = "http://127.0.0.1:35997"
STARTUP_FRONTIER_URLS = {"pillar": "http://127.0.0.1:35991", "rpc": RPC_URL}
GATEWAY_URL = "http://127.0.0.1:35999"
READINESS_ATTEMPTS = 30
READINESS_WAIT_SECONDS = 90
INITIAL_HEIGHT_WAIT_SECONDS = 180
INITIAL_FINAL_PROBE_SECONDS = 1
ORACLE_REPORT_BYTES = 256 << 10
SYNC_INFO_BYTES = 8 << 10
SYNC_REPORT = "startup-sync.json"
POST_SYNC_REPORT = "startup-post-sync-frontier.json"
STARTUP_FRONTIERS_REPORT = "startup-peer-frontiers.json"
FRONTIER_BYTES = 128 << 10
OPENING_PROOF_FILE = "opening-batch-proof.json"
OPENING_PROOF_BYTES = 32 << 10
OPENING_PROOF_VERSION_UNAVAILABLE = "opening_proof_version_unavailable"
RPC_CALL_LIMIT = 96
CONSUMER_STDOUT = "consume-query.stdout"
CONSUMER_FAILURE_BYTES = 4096
# Fixed read-only report text from both selected consumer revisions. Raw
# stdout is eligible only when every field has a known source-defined shape.
CONSUMER_CAVEATS = [
    "Configured fingerprints do not authenticate network activation, file provenance or independently selected trust inputs.",
    "Configured-header membership does not establish canonicality, consensus finality, STF correctness, funds release or recipient receive.",
    "No witness availability, freshness or production state-value guarantee is established.",
    "Current-H domain/config does not establish submission-time context or STF execution.",
    "Gateway stored-field comparison is separate; a mismatch does not invalidate the historical membership result.",
]
CONSUMER_FAILURES = {
    1: {"headers": {"not_accepted"}, "query": {"query_identity_mismatch", "gateway_mismatch",
        "source_rule_mismatch", "invalid_witness"}},
    2: {"headers": {"not_accepted"}, "query": {"required_row_absent", "typed_value_absent",
        "unsupported_bounds", "outside_owned_scope"}, "witness": {"unavailable"}, "gateway": {"unavailable"}},
}
CONSUMER_HEADER_FAILURES = {
    1: {"ReasonHeightNonMonotonic", "ReasonBrokenLinkage", "ReasonChainIDMismatch", "ReasonInvalidResourcePrice",
        "ReasonInvalidHash", "ReasonInvalidSignature", "ReasonUnauthorizedProducer"},
    2: {"ReasonMissingEvidence", "ReasonOversizedHeaders", "ReasonWindowNotMet", "ReasonUnsupportedHeaderVersion",
        "ReasonHeaderVersionInactive", "ReasonProtocolProfileCoverage", "ReasonProducerSetUnknown"},
}
SYNC_REASONS = {"OBSERVED": {None}, "NOT_ATTEMPTED": {"shared_call_limit", "budget_refused"},
    "FAILURE": {"command_failed"}, "UNKNOWN": {"command_incomplete", "capture_interrupted"},
    "REFUSED": {"capture_refused"}}
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


def opening_proof_result(raw, request_id, limit):
    # The selected node emits this exact response for an unavailable tree
    # version. Only these fixed bytes are eligible for refusal retention.
    unavailable = (b'{"jsonrpc":"2.0","id":%d,"error":{"code":-32000,'
                   b'"message":"trie: no such version"}}\n') % request_id
    if raw == unavailable and len(raw) <= limit:
        raise Refused(OPENING_PROOF_VERSION_UNAVAILABLE)
    return rpc_result(raw, request_id, limit)


def sync_info(row):
    """Validate the source-pinned stats DTO without assigning chain authority."""
    exact_keys(row, {"state", "currentHeight", "targetHeight"}, "startup_sync_fields")
    return {"state": uint(row["state"], 3, minimum=0),
            "current_height": uint(row["currentHeight"]),
            "target_height": uint(row["targetHeight"], minimum=0)}


def diagnostic_failure(report, error):
    receipt = error.result.receipt
    if receipt.get("reason") == "interrupted":
        raise KeyboardInterrupt from error
    failed = (receipt["output_complete"] is True
              and type(receipt["actual_exit"]) is int and receipt["actual_exit"] != 0)
    report.update(status="FAILURE" if failed else "UNKNOWN",
                  reason="command_failed" if failed else "command_incomplete")


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


def opening_proof_target(contract, profile, header):
    selection = contract.data["selection"]
    require(header.height == selection["source_expected_first_v3_height"] and header.version == 3,
            "opening_proof_header")
    key = ledger_keys(profile, int(selection["batch_id_decimal"]))["batch_entry"]
    return key, [header.height, base64.b64encode(key).decode("ascii")]


class LocalRpc:
    """Bounded read methods of the selected loopback-owned services."""
    def __init__(self, contract, recorder, directory, curl, environment, guard):
        self.contract, self.recorder, self.directory = contract, recorder, Path(directory)
        self.curl, self.environment, self.guard = curl, environment, guard
        self.calls = 0
        self.retained_frontiers = set()
        self.startup_sync_evidence = set()
        self.startup_sync_attempted = False
        self.startup_sync_observed_request = None
        self.post_sync_evidence = set()
        self.post_sync_attempted = False
        self.post_sync_observed_request = None
        self.startup_frontier_attempted = False
        self.startup_frontier_evidence = set()

    def _read(self, method, parameters, cap, *, stdout_name=None, startup_role=None, deadline=None,
              decode=rpc_result):
        connect_limit, http_limit, command_limit = "2", "5", 7
        if deadline is not None:
            # curl treats zero as unlimited. Round the allowance down and
            # refuse before allocating an ID if less than a millisecond remains.
            remaining_ms = int((deadline - time.monotonic()) * 1000)
            require(remaining_ms > 0, "owned_rpc_readiness_deadline")
            http_seconds = min(5000, remaining_ms) / 1000
            connect_limit = f"{min(2, http_seconds):.3f}"
            http_limit = f"{http_seconds:.3f}"
            command_limit = http_seconds + 2
        url = GATEWAY_URL if method == "zeno_getHead" else RPC_URL
        label = f"rpc-{self.calls + 1:02d}"
        if startup_role is not None:
            require(type(startup_role) is str and startup_role in STARTUP_FRONTIER_URLS
                    and method == "ledger.getFrontierMomentum" and parameters == [], "startup_frontier_read_scope")
            label = f"startup-{startup_role}-frontier"
            url = STARTUP_FRONTIER_URLS[startup_role]
            require(stdout_name == label + ".json" and cap == FRONTIER_BYTES, "startup_frontier_output_scope")
        self.calls += 1
        require(self.calls <= RPC_CALL_LIMIT, "owned_rpc_call_bound")
        request_id = self.calls
        request = {"jsonrpc": "2.0", "id": request_id, "method": method, "params": parameters}
        raw = json.dumps(request, separators=(",", ":"), allow_nan=False)
        self.recorder.seal(label + ".request.json", raw.encode("ascii") + b"\n")
        result = self.recorder.run(label, [self.curl, "--disable", "--silent", "--show-error",
            "--fail", "--noproxy", "*", "--proto", "=http", "--connect-timeout", connect_limit,
            "--max-time", http_limit, "--max-filesize", str(cap), "--header", "Content-Type: application/json",
            "--data-binary", raw, url],
            self.directory, self.environment,
            timeout=command_limit, stdout_cap=cap, stderr_cap=4096, stdout_name=stdout_name, guard=self.guard)
        return decode(result.stdout(cap), request_id, cap)

    def _frontier(self, name, *, startup_role=None, deadline=None):
        row = self._read("ledger.getFrontierMomentum", [], FRONTIER_BYTES,
                         stdout_name=name, startup_role=startup_role, deadline=deadline)
        return Header.read(row, self.contract.data["selection"]["chain_id"])

    def frontier(self, *, deadline=None):
        name = f"rpc-{self.calls + 1:02d}.frontier.json"
        header = self._frontier(name, deadline=deadline)
        # Retain the original response only after envelope/header parsing.
        # Readiness is a candidate observation, never accepted-header authority.
        self.retained_frontiers.add(name)
        return header

    def opening(self):
        result = self._read("ledger.getMomentumsByHeight", [1, 3], 384 << 10,
                            stdout_name="opening-momentums.json")
        rows = result.get("list")
        require(type(result.get("count")) is int and result["count"] >= 3,
                "opening_frontier_count")
        return opening_headers(self.contract, rows)

    def opening_proof(self, header, profile):
        key, parameters = opening_proof_target(self.contract, profile, header)
        witness = self._read("ledger.getProof", parameters, OPENING_PROOF_BYTES,
                             stdout_name=OPENING_PROOF_FILE, decode=opening_proof_result)
        return opening_batch_witness(profile, header.root, key, witness)

    def capture_startup_sync(self):
        """One diagnostic after node readiness fails; never retry readiness."""
        require(not self.startup_sync_attempted, "startup_sync_already_attempted")
        self.startup_sync_attempted = True
        report = {"format": "owned-devnet-startup-sync/v1", "trigger": "owned_rpc_readiness_deadline",
            "status": "NOT_ATTEMPTED", "reason": "shared_call_limit", "request_id": None,
            "response_file": None, "accepted_header_authority": False, "production_qualified": False}
        request_id = self.calls + 1
        label, response = f"rpc-{request_id:02d}", f"rpc-{request_id:02d}.sync-info.json"
        try:
            if self.calls >= RPC_CALL_LIMIT:
                return
            report.update(status="UNKNOWN", reason="capture_interrupted")
            try:
                self.guard()
            except Refused:
                report.update(status="NOT_ATTEMPTED", reason="budget_refused")
                return
            try:
                sync_info(self._read("stats.syncInfo", [], SYNC_INFO_BYTES, stdout_name=response))
            except CommandFailed as error:
                diagnostic_failure(report, error)
            except Refused:
                report.update(status="REFUSED", reason="capture_refused")
            else:
                report.update(status="OBSERVED", reason=None, response_file=response)
                self.startup_sync_observed_request = request_id
        finally:
            request = label + ".request.json"
            if request in self.recorder.names:
                report["request_id"] = request_id
                self.startup_sync_evidence.add(request)
            if report["status"] == "OBSERVED":
                self.startup_sync_evidence.add(response)
            self.recorder.seal(SYNC_REPORT, canonical(report))
            self.startup_sync_evidence.add(SYNC_REPORT)
        return report

    def capture_post_sync_frontier(self, after_request_id):
        """Retain one later candidate hash without restarting readiness."""
        uint(after_request_id, RPC_CALL_LIMIT)
        require(after_request_id == self.calls == self.startup_sync_observed_request
                and not self.post_sync_attempted, "post_sync_frontier_scope")
        self.post_sync_attempted = True
        report = {"format": "owned-devnet-post-sync-frontier/v1", "after_sync_request_id": after_request_id,
            "status": "NOT_ATTEMPTED", "reason": "shared_call_limit", "request_id": None,
            "response_file": None, "accepted_header_authority": False, "production_qualified": False}
        request_id = self.calls + 1
        label, response = f"rpc-{request_id:02d}", f"rpc-{request_id:02d}.frontier.json"
        try:
            if self.calls >= RPC_CALL_LIMIT:
                return
            report.update(status="UNKNOWN", reason="capture_interrupted")
            try:
                self.guard()
            except Refused:
                report.update(status="NOT_ATTEMPTED", reason="budget_refused")
                return
            try:
                self.frontier()
            except CommandFailed as error:
                diagnostic_failure(report, error)
            except Refused:
                report.update(status="REFUSED", reason="capture_refused")
            else:
                report.update(status="OBSERVED", reason=None, response_file=response)
                self.post_sync_observed_request = request_id
        finally:
            request = label + ".request.json"
            if request in self.recorder.names:
                report["request_id"] = request_id
                self.post_sync_evidence.add(request)
            # The validated body is already selected by retained_frontiers.
            self.recorder.seal(POST_SYNC_REPORT, canonical(report))
            self.post_sync_evidence.add(POST_SYNC_REPORT)
        return report

    def capture_startup_peer_frontiers(self, after_request_id):
        """Bracket one pillar read with the preceding and following RPC reads."""
        uint(after_request_id, RPC_CALL_LIMIT)
        require(after_request_id == self.calls == self.post_sync_observed_request
                and not self.startup_frontier_attempted, "startup_frontier_scope")
        self.startup_frontier_attempted = True
        observations = []
        report = {"format": "owned-devnet-startup-peer-frontiers/v1",
                  "after_rpc_request_id": after_request_id, "observations": observations,
                  "accepted_header_authority": False, "production_qualified": False}
        have_slots = after_request_id + len(STARTUP_FRONTIER_URLS) <= RPC_CALL_LIMIT
        try:
            for role in STARTUP_FRONTIER_URLS:
                row = {"role": role, "status": "NOT_ATTEMPTED", "reason": "shared_call_limit",
                       "request_id": None, "response_file": None}
                observations.append(row)
                if not have_slots:
                    break
                row.update(status="UNKNOWN", reason="capture_interrupted")
                try:
                    self.guard()
                except Refused:
                    row.update(status="NOT_ATTEMPTED", reason="budget_refused")
                    break
                request_id = self.calls + 1
                label = f"startup-{role}-frontier"
                request, response = label + ".request.json", label + ".json"
                try:
                    self._frontier(response, startup_role=role)
                except CommandFailed as error:
                    diagnostic_failure(row, error)
                except Refused:
                    row.update(status="REFUSED", reason="capture_refused")
                else:
                    row.update(status="OBSERVED", reason=None, response_file=response)
                    self.startup_frontier_evidence.add(response)
                finally:
                    if request in self.recorder.names:
                        row["request_id"] = request_id
                        self.startup_frontier_evidence.add(request)
                if row["status"] != "OBSERVED":
                    break
        finally:
            self.recorder.seal(STARTUP_FRONTIERS_REPORT, canonical(report))
            self.startup_frontier_evidence.add(STARTUP_FRONTIERS_REPORT)
        return report

    def _wait(self, read, ready, *, starting, wait_seconds=READINESS_WAIT_SECONDS,
              reserve_final_probe=False):
        # Preserve every actual attempt. A freshly published loopback port can
        # accept and then close a request before RPC initialization completes.
        # Retry only a complete, quiescent startup failure with no response
        # bytes; malformed data, partial responses and later read failures stop.
        until = time.monotonic() + wait_seconds
        interval = wait_seconds / READINESS_ATTEMPTS
        for attempt in range(READINESS_ATTEMPTS):
            self.guard()
            require(time.monotonic() < until, "owned_rpc_readiness_deadline")
            final_probe = reserve_final_probe and attempt + 1 == READINESS_ATTEMPTS
            try:
                value = read(deadline=until) if final_probe else read()
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
                    require(time.monotonic() < until, "owned_rpc_readiness_deadline")
                    return value
            if attempt + 1 < READINESS_ATTEMPTS:
                remaining = until - time.monotonic()
                require(remaining > 0, "owned_rpc_readiness_deadline")
                delay = min(interval, remaining)
                if reserve_final_probe and attempt + 2 == READINESS_ATTEMPTS:
                    # Use the last allowed read near the end of the initial
                    # window. Earlier reads keep their established cadence.
                    delay = max(0, remaining - INITIAL_FINAL_PROBE_SECONDS)
                if delay > 0:
                    time.sleep(delay)
        raise Refused("owned_rpc_readiness_deadline")

    def wait_height(self, height, *, starting=False):
        wait_seconds = INITIAL_HEIGHT_WAIT_SECONDS if starting else READINESS_WAIT_SECONDS
        return self._wait(self.frontier, lambda frontier: frontier.height >= height,
                          starting=starting, wait_seconds=wait_seconds,
                          reserve_final_probe=starting)

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


def consumer_failure(raw, code):
    """Check a complete fixed-schema refusal before exporting its original bytes."""
    require(type(code) is int and code in CONSUMER_FAILURES, "consumer_failure_exit")
    report = api_json(raw, CONSUMER_FAILURE_BYTES)
    fields = {"schema_version": 1, "command": "query-experimental-batch-context",
        "scope": "EXPERIMENTAL_CONFIGURED_HEADER_THREE_ROW_MEMBERSHIP",
        "status": "rejected" if code == 1 else "refused", "exit_code": code,
        "header_context": None, "query_context": None, "result": None, "gateway_comparison": None,
        "persistence": "read_only", "rpc_requests": 0, "production_state_value_guarantee": False,
        "gateway_comparison_requested": True, "caveats": CONSUMER_CAVEATS}
    exact_keys(report, fields.keys() | {"error", "headers"}, "consumer_failure_fields")
    same({key: report[key] for key in fields}, fields, "consumer_failure_scope")
    error = report["error"]
    exact_keys(error, {"stage", "category"}, "consumer_failure_error")
    stage, category = error["stage"], error["category"]
    require(type(stage) is str and type(category) is str and category in CONSUMER_FAILURES[code].get(stage, ()),
            "consumer_failure_error")
    headers = report["headers"]
    if stage == "headers":
        exact_keys(headers, {"outcome", "reason", "failed_at"}, "consumer_failure_headers")
        require(headers["outcome"] == ("REJECT" if code == 1 else "REFUSED")
                and type(headers["reason"]) is str and headers["reason"] in CONSUMER_HEADER_FAILURES[code],
                "consumer_failure_headers")
        if code == 1:
            uint(headers["failed_at"], model.LIMITS["max_header_targets"] - 1, minimum=0)
        else:
            same(headers["failed_at"], -1, "consumer_failure_headers")
    elif stage == "query":
        same(headers, {"outcome": "ACCEPT", "reason": "ReasonOK", "failed_at": -1}, "consumer_failure_headers")
    else:
        same(headers, None, "consumer_failure_headers")
    return {"actual_exit": code, "error": error, "headers": headers}


def retainable_consumer_failure(result):
    receipt = result.receipt
    code = receipt.get("actual_exit")
    if (type(code) is not int or code not in CONSUMER_FAILURES
            or receipt.get("label") != "consume-query" or result.stdout_name != CONSUMER_STDOUT
            or receipt.get("launch_outcome") != "STARTED" or receipt.get("output_complete") is not True
            or receipt.get("process_group_quiescent") is not True or receipt.get("reason") is not None):
        return False
    try:
        consumer_failure(result.stdout(CONSUMER_FAILURE_BYTES), code)
    except (Refused, OSError):
        return False
    return True


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
