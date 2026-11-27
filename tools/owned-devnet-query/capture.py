# SPDX-License-Identifier: GPL-3.0-only
"""Bounded read-only capture and finite schedule selection for one owned node."""
from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import tempfile
import time

from artifacts import api_json
from closed_reader import LEDGER, ORACLE_NAME
import model
from model import Refused, canonical, exact_keys, require, same, uint
from process import CommandFailed, regular_pin
from query_checks import (address_bytes, binary, compare_frontier_batch, consumer_result, fingerprints,
                          header_facts, hex_bytes, ledger_keys, opening_batch_witness, schedule_hash,
                          selected_semantics, witness_rows)

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
OPENING_FILE = "opening-momentums.json"
OPENING_BYTES = 384 << 10
CLOSED_OPENING_REPORT = "closed-opening-authorization.json"
DEPOSIT_TIMEOUT_BATCH = "deposit-timeout-batch.json"
DEPOSIT_TIMEOUT_HEADER = "deposit-timeout-query-header.json"
DEPOSIT_TIMEOUT_PROOFS = {name: "deposit-timeout-" + name.replace("_", "-") + "-proof.json"
                          for name in ("batch_entry", "domain_record", "domain_config")}
DEPOSIT_TIMEOUT_BATCH_FORMAT = "owned-devnet-deposit-timeout-batch/v1"
DEPOSIT_TIMEOUT_BATCH_GATEWAY_FORMAT = "owned-devnet-deposit-timeout-batch/v2"
DEPOSIT_TIMEOUT_GATEWAY = "deposit-timeout-frontier-batch.json"
DEPOSIT_TIMEOUT_GATEWAY_BYTES = 32 << 10
DEPOSIT_TIMEOUT_RANGE = "deposit-timeout-header-range.json"
DEPOSIT_TIMEOUT_REPLAY = "deposit-timeout-native-replay.json"
DEPOSIT_TIMEOUT_REPLAY_FORMAT = "owned-devnet-deposit-timeout-native-replay/v1"
DEPOSIT_TIMEOUT_REPLAY_WITHOUT_GATEWAY_FORMAT = "owned-devnet-deposit-timeout-native-replay-without-gateway/v1"
DEPOSIT_TIMEOUT_REPLAY_REUSING_OPENING_FORMAT = "owned-devnet-deposit-timeout-native-replay/v2"
DEPOSIT_TIMEOUT_REPLAY_REUSING_HEADERS_FORMAT = "owned-devnet-deposit-timeout-native-replay/v3"
DEPOSIT_TIMEOUT_ORACLE = "timeout-parent-oracle"
DEPOSIT_TIMEOUT_CONSUMER = "timeout-consume-query"
DEPOSIT_TIMEOUT_STDOUT = DEPOSIT_TIMEOUT_CONSUMER + ".stdout"
OPENING_SIGNATURE_REPORT = "opening-signatures.json"
OPENING_SIGNATURE_LABELS = ("opening-signature-h2", "opening-signature-h3")
OPENING_SIGNATURE_OK = b"Signature Verified Successfully\n"
ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
OPENING_PROOF_FILE = "opening-batch-proof.json"
OPENING_PROOF_BYTES = 32 << 10
OPENING_PROOF_VERSION_UNAVAILABLE = "opening_proof_version_unavailable"
OPENING_BATCH_ALREADY_PRESENT = "opening_batch_already_present"
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


@dataclass(frozen=True)
class DepositTimeoutBatch:
    report: dict
    header: Header
    header_row: dict
    witnesses: dict | None = None
    gateway: dict | None = None


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


def opening_signature_report(opening, response_pin):
    return {"format": "owned-devnet-opening-signatures/v1", "opening_response": response_pin,
            "headers": [header.identifier() for header in opening[1:]],
            "accepted_header_authority": False, "producer_schedule_verified": False}


def verify_opening_signatures(recorder, opening, rows, private, environment, guard,
                              *, openssl="/usr/bin/openssl"):
    """Verify signatures over the already checked opening hashes."""
    require(len(opening) == len(rows) == 3, "opening_signature_rows")
    response_pin = regular_pin(recorder.directory / OPENING_FILE, OPENING_BYTES)
    with tempfile.TemporaryDirectory(dir=private, prefix="opening-signatures-") as staging:
        directory = Path(staging)
        config = directory / "empty.cnf"
        config.touch()
        env = dict(environment, OPENSSL_CONF=str(config))
        for label, header, row in zip(OPENING_SIGNATURE_LABELS, opening[1:], rows[1:]):
            same(row["hash"], header.hash, "opening_signature_hash")
            public = binary(row["publicKey"], 32)
            signature = binary(row["signature"], 64)
            require(len(public) == 32 and len(signature) == 64, "opening_signature_width")
            (directory / "public-key.der").write_bytes(ED25519_SPKI_PREFIX + public)
            (directory / "message.bin").write_bytes(hex_bytes(header.hash, 32))
            (directory / "signature.bin").write_bytes(signature)
            result = recorder.run(label, [openssl, "pkeyutl", "-verify", "-rawin", "-pubin",
                "-keyform", "DER", "-inkey", "public-key.der", "-in", "message.bin",
                "-sigfile", "signature.bin", "-provider", "default", "-propquery", "provider=default"],
                directory, env, timeout=10, stdout_cap=128, stderr_cap=4096, guard=guard)
            receipt = result.receipt
            require(result.stdout(128) == OPENING_SIGNATURE_OK and result.stderr(4096) == b""
                    and receipt["process_group_quiescent"] is True and receipt["reason"] is None,
                    "opening_signature_result")
    recorder.seal(OPENING_SIGNATURE_REPORT, canonical(opening_signature_report(opening, response_pin)))


def opening_proof_target(contract, profile, header):
    selection = contract.data["selection"]
    require(header.height == selection["source_expected_first_v3_height"] and header.version == 3,
            "opening_proof_header")
    key = ledger_keys(profile, int(selection["batch_id_decimal"]))["batch_entry"]
    return key, state_proof_parameters(header, key)


def state_proof_parameters(header, key):
    return [header.height, base64.b64encode(key).decode("ascii")]


def deposit_timeout_target_height(contract, frontier):
    selected, limits = contract.data["selection"], contract.data["limits"]
    # This retained diagnostic needs the immediate signed parent of the tip.
    # The reviewed chain-69 contracts select a depth of one.
    require(limits["header_depth"] == 1 and frontier.version == 3
            and frontier.height > selected["source_expected_first_v3_height"] + 1,
            "deposit_timeout_no_later_target")
    return frontier.height - limits["header_depth"]


def deposit_timeout_header(contract, frontier, result):
    height = deposit_timeout_target_height(contract, frontier)
    rows = result.get("list")
    require(type(result.get("count")) is int and result["count"] >= 1
            and type(rows) is list and len(rows) == 1, "deposit_timeout_header_range")
    header = Header.read(rows[0], contract.data["selection"]["chain_id"])
    require(header.version == 3 and header.height == height and header.hash == frontier.parent_hash
            and header.timestamp < frontier.timestamp, "deposit_timeout_header_link")
    return header, rows[0]


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
        return Header.read(row, self.contract.data["selection"]["chain_id"]), row

    def frontier(self, *, deadline=None):
        header, _ = self.frontier_with_row(deadline=deadline)
        return header

    def frontier_with_row(self, *, deadline=None):
        name = f"rpc-{self.calls + 1:02d}.frontier.json"
        observation = self._frontier(name, deadline=deadline)
        # Retain the original response only after envelope/header parsing.
        # Readiness is a candidate observation, never accepted-header authority.
        self.retained_frontiers.add(name)
        return observation

    def opening(self):
        result = self._read("ledger.getMomentumsByHeight", [1, 3], OPENING_BYTES,
                            stdout_name=OPENING_FILE)
        rows = result.get("list")
        require(type(result.get("count")) is int and result["count"] >= 3,
                "opening_frontier_count")
        return opening_headers(self.contract, rows), rows

    def opening_proof(self, header, profile):
        key, parameters = opening_proof_target(self.contract, profile, header)
        witness = self._read("ledger.getProof", parameters, OPENING_PROOF_BYTES,
                             stdout_name=OPENING_PROOF_FILE, decode=opening_proof_result)
        return opening_batch_witness(profile, header.root, key, witness)

    def deposit_timeout_batch(self, frontier, descriptor, profile):
        """Capture ready proofs under the stopped producers' candidate frontier."""
        height = deposit_timeout_target_height(self.contract, frontier)
        frontier_request = self.calls
        require(frontier_request + 2 <= RPC_CALL_LIMIT, "deposit_timeout_rpc_budget")
        header, header_row = deposit_timeout_header(self.contract, frontier, self._read(
            "ledger.getMomentumsByHeight", [height, 1], FRONTIER_BYTES, stdout_name=DEPOSIT_TIMEOUT_HEADER))
        batch = int(self.contract.data["selection"]["batch_id_decimal"])
        keys = ledger_keys(profile, batch)

        def proof(name):
            return self._read("ledger.getProof", state_proof_parameters(header, keys[name]), OPENING_PROOF_BYTES,
                              stdout_name=DEPOSIT_TIMEOUT_PROOFS[name])

        entry = proof("batch_entry")
        observed = opening_batch_witness(profile, header.root, keys["batch_entry"], entry)
        totals = gateway_comparison = witnesses = gateway = None
        if observed["presence"] == "present" and self.calls + 2 <= RPC_CALL_LIMIT:
            try:
                rows = {"batch_entry": entry, "domain_record": proof("domain_record"),
                        "domain_config": proof("domain_config")}
                checked = witness_rows(profile, batch, header.root, rows)
                selected_semantics(descriptor, checked["decoded"])
                totals = checked["totals"]
                witnesses = rows
            except (OSError, ValueError, KeyError, TypeError):
                # Preserve the independently checked entry even if its two
                # companion reads or the typed context check refused.
                pass
        if totals is not None and self.calls < RPC_CALL_LIMIT:
            try:
                domain = self.contract.data["selection"]["domain_id"]
                row = self._read("embedded.settlement.getBatch", [domain, batch],
                                 DEPOSIT_TIMEOUT_GATEWAY_BYTES, stdout_name=DEPOSIT_TIMEOUT_GATEWAY)
                gateway_comparison = compare_frontier_batch(row, domain, batch, checked["decoded"]["entry"],
                                                            raw_rpc=True)
                gateway = row
            except (OSError, ValueError, KeyError, TypeError):
                # The three proofs remain useful without a gateway observation.
                pass
        report = {"format": DEPOSIT_TIMEOUT_BATCH_FORMAT, "frontier_request_id": frontier_request,
                  "header": header.identifier(), "state_root": header.root, "batch_witness": observed,
                  "context_proof_totals": totals}
        if gateway_comparison is not None:
            report.update(format=DEPOSIT_TIMEOUT_BATCH_GATEWAY_FORMAT, gateway_comparison=gateway_comparison)
        return DepositTimeoutBatch(report, header, header_row, witnesses, gateway)

    def deposit_timeout_window(self, opening, frontier, batch, *, opening_row, frontier_row, deadline):
        require(batch.witnesses is not None and self.calls == batch.report["frontier_request_id"] + 5
                and self.calls <= RPC_CALL_LIMIT, "deposit_timeout_replay_rpc_budget")
        parameters = deposit_timeout_middle_range(self.contract, opening, frontier)
        result = request_id = None
        if parameters is not None:
            require(self.calls < RPC_CALL_LIMIT, "deposit_timeout_replay_rpc_budget")
            result = self._read("ledger.getMomentumsByHeight", parameters,
                                self.contract.data["limits"]["stdout_bytes"],
                                stdout_name=DEPOSIT_TIMEOUT_RANGE, deadline=deadline)
            request_id = self.calls
        window = deposit_timeout_window_from_retained_headers(self.contract, opening, frontier, batch,
            opening_row=opening_row, frontier_row=frontier_row, middle_result=result)
        return window, request_id

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

    def _wait(self, read, ready, *, starting, initial_frontier=False):
        # Preserve every actual attempt. A freshly published loopback port can
        # accept and then close a request before RPC initialization completes.
        # Retry only a complete, quiescent startup failure with no response
        # bytes; malformed data, partial responses and later read failures stop.
        start = time.monotonic()
        if initial_frontier:
            until = start + INITIAL_HEIGHT_WAIT_SECONDS
            last_probe = until - INITIAL_FINAL_PROBE_SECONDS
            interval = (last_probe - start) / (READINESS_ATTEMPTS - 1)
        else:
            until = start + READINESS_WAIT_SECONDS
            interval = READINESS_WAIT_SECONDS / READINESS_ATTEMPTS
        for attempt in range(READINESS_ATTEMPTS):
            if initial_frontier and attempt:
                # Let response and capture time use part of the interval.
                # Skip fully elapsed slots after a prolonged local stall.
                final = attempt == READINESS_ATTEMPTS - 1
                scheduled = last_probe if final else start + attempt * interval
                now = time.monotonic()
                if not final and now >= scheduled + interval:
                    continue
                if now < scheduled:
                    time.sleep(scheduled - now)
            self.guard()
            require(time.monotonic() < until, "owned_rpc_readiness_deadline")
            try:
                value = read(deadline=until) if initial_frontier else read()
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
            if not initial_frontier and attempt + 1 < READINESS_ATTEMPTS:
                remaining = until - time.monotonic()
                require(remaining > 0, "owned_rpc_readiness_deadline")
                delay = min(interval, remaining)
                if delay > 0:
                    time.sleep(delay)
        raise Refused("owned_rpc_readiness_deadline")

    def wait_height(self, height, *, starting=False):
        return self._wait(self.frontier, lambda frontier: frontier.height >= height,
                          starting=starting, initial_frontier=starting)

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


def captured_headers(contract, opening, query, frontier, provider, *, compare_gateway=True):
    fields = {"version", "momentums", "witnesses"}
    if compare_gateway:
        fields.add("gateway")
    exact_keys(provider, fields, "owned_provider_fields")
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


def deposit_timeout_range(contract, opening, frontier):
    anchor = opening[1].height
    size = frontier.height - anchor
    # The pinned RPC accepts up to 1,024 rows. The owned contract bounds this range below 512.
    require(1 <= size < contract.data["limits"]["max_header_targets"], "deposit_timeout_range_size")
    return [anchor + 1, size]


def deposit_timeout_middle_range(contract, opening, frontier):
    start, size = deposit_timeout_range(contract, opening, frontier)
    # The H3 opening, selected parent and frozen tip already have captured rows.
    require(size >= 3, "deposit_timeout_range_size")
    return [start + 1, size - 3] if size > 3 else None


def deposit_timeout_window_from_retained_headers(contract, opening, frontier, batch, *, opening_row,
                                                 frontier_row, middle_result):
    parameters = deposit_timeout_middle_range(contract, opening, frontier)
    middle = []
    if parameters is None:
        require(middle_result is None, "deposit_timeout_middle_unexpected")
    else:
        count = parameters[1]
        require(type(middle_result) is dict and type(middle_result.get("list")) is list
                and len(middle_result["list"]) == count, "deposit_timeout_middle_range")
        uint(middle_result.get("count"), minimum=count)
        middle = middle_result["list"]
    return deposit_timeout_window(contract, opening, frontier, batch,
                                  [opening_row, *middle, batch.header_row, frontier_row])


def deposit_timeout_window(contract, opening, frontier, batch, rows):
    require(batch.witnesses is not None, "deposit_timeout_replay_inputs")
    provider = {"version": 1, "momentums": rows, "witnesses": batch.witnesses}
    compare_gateway = batch.gateway is not None
    if compare_gateway:
        provider["gateway"] = batch.gateway
    headers = captured_headers(contract, opening, batch.header, frontier, provider, compare_gateway=compare_gateway)
    return Window(headers, batch.header, provider, None)


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


def require_opening_frontier(opening, identifier, version, timestamp):
    first = opening[2]
    require(version == 3 and (identifier == first.identifier() and timestamp == first.timestamp
            or identifier["height"] > first.height and timestamp > first.timestamp),
            "closed_opening_frontier")


def oracle_requests(contract, headers, frontier=None, *, separate_opening=False):
    frontier = headers[-1].identifier() if frontier is None else frontier
    limit = uint(contract.data["limits"]["oracle_targets_per_call"])
    if separate_opening:
        require(len(headers) >= 4 and limit >= 2, "closed_oracle_opening_reuse_scope")
    offset = 1
    while offset < len(headers):
        count = 2 if separate_opening and offset == 1 else limit
        targets = headers[offset:offset + count]
        raw = json.dumps({"expected_frontier": frontier,
            "targets": [header.identifier() for header in targets], "version": 1},
            sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii") + b"\n"
        require(len(raw) <= 32 << 10, "closed_oracle_request_bound")
        yield raw, targets
        offset += len(targets)


def oracle_schedule(contract, headers, reports, frontier=None, *, separate_opening=False):
    """Require the closed ledger's own parent calculation for every target."""
    frontier = headers[-1].identifier() if frontier is None else frontier
    reports = iter(reports)
    node = contract.data["sources"]["node"]["revision"]
    entries = []
    for raw, targets in oracle_requests(contract, headers, frontier, separate_opening=separate_opening):
        report = next(reports, None)
        require(report is not None, "closed_oracle_report_count")
        exact_keys(report, ORACLE_FIELDS, "closed_oracle_report_fields")
        require(report["format"] == "zenon-closed-devnet-parent-slots/v1"
                and report["node_revision"] == node
                and report["request_sha256"] == hashlib.sha256(raw).hexdigest()
                and all(report[k] is True for k in ORACLE_TRUE)
                and all(report[k] is False for k in ORACLE_FALSE), "closed_oracle_provenance")
        same(report["genesis"], headers[0].identifier(), "closed_oracle_genesis")
        same(report["frontier"], frontier, "closed_oracle_frontier")
        rows = report["rows"]
        require(type(rows) is list and len(rows) == len(targets), "closed_oracle_row_count")
        for header, row in zip(targets, rows):
            parent = headers[header.height - 2]
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
            proof = headers[uint(proof_block["height"], maximum=parent.height) - 1]
            same(proof_block, proof.identifier(), "closed_oracle_proof_block")
            same(slot["proof_block_timestamp"], proof.timestamp, "closed_oracle_proof_block_time")
            if header.version == 3:
                entries.append({"height": header.height, "timestamp_unix": slot["timestamp"],
                                "producing_addr": producing_addr})
    require(next(reports, None) is None, "closed_oracle_report_count")
    schedule = {"chain_id": contract.data["selection"]["chain_id"],
        "coverage": [{"from_height": headers[2].height,
                      "through_height": headers[-1].height}], "entries": entries,
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


def read_closed_parent_schedule(contract, recorder, engine, ledger, headers, frontier, sources, binaries,
                                directory, environment, guard, reader_source, *, services=model.SERVICES,
                                label_prefix="parent-oracle", reuse_opening=None):
    """Run only the source-bound oracle against the stopped owned volume."""
    require(LEDGER.fullmatch(ledger) is not None and engine.closed_ledger(services=services) == ledger,
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
    first_result = None
    separate_opening = reuse_opening is not None
    provenance = {
        "format": "owned-devnet-closed-ledger-provenance/v1",
        "rpc_container_id": engine.owned["rpc"].identity, "engine_id": engine.admission.engine_id,
        "genesis": headers[0].identifier(), "anchor": headers[1].identifier(),
        "frontier": frontier, "first_v3": headers[2].identifier(),
        "oracle_binary": pin,
        "reader_source_sha256": hashlib.sha256(reader_source.encode("utf-8")).hexdigest(),
        "ledger_copied": False, "ledger_opened_read_only": True}
    requests = oracle_requests(contract, headers, frontier, separate_opening=separate_opening)

    def reports():
        nonlocal first_result
        if separate_opening:
            previous, first_result = reuse_opening
            for name, expected in provenance.items():
                same(previous[name], expected, "closed_oracle_opening_reuse_scope")
            (original,) = previous["oracle_reports"]
            raw, _ = next(requests)
            request = {"file": "parent-oracle-01.request.json", "bytes": len(raw),
                       "sha256": hashlib.sha256(raw).hexdigest()}
            same(original["request"], request, "closed_oracle_opening_request")
            require(first_result.directory == recorder.directory
                    and first_result.stdout_name == "parent-oracle-01.stdout", "closed_oracle_opening_output")
            same(first_result.receipt["outputs"]["stdout"], original["stdout"], "closed_oracle_opening_output")
            receipts.append(original)
            yield api_json(first_result.stdout(ORACLE_REPORT_BYTES), ORACLE_REPORT_BYTES)
        for index, (raw, _) in enumerate(requests, 1):
            label = f"{label_prefix}-{index:02d}"
            request = recorder.seal(label + ".request.json", raw)
            path = recorder.directory / request["file"]
            result = recorder.run(label, ["/usr/bin/sudo", "-n", "--", "/usr/bin/timeout",
                "--kill-after=3s", f"{seconds}s", "/usr/bin/unshare", "--mount", "--net",
                "--propagation", "private", "--", "/usr/bin/python3", "-I", "-B", "-c", reader_source,
                ledger, str(oracle), str(path), str(genesis), str(pin["bytes"]), pin["sha256"],
                parent_mount, parent_network], directory, environment, guard=guard, stdin_lease=True,
                timeout=seconds + 7, terminate_grace=5, stdout_cap=ORACLE_REPORT_BYTES, stderr_cap=4096)
            if first_result is None:
                first_result = result
            receipts.append({"request": request, "stdout": result.receipt["outputs"]["stdout"]})
            yield api_json(result.stdout(ORACLE_REPORT_BYTES), ORACLE_REPORT_BYTES)

    schedule = oracle_schedule(contract, headers, reports(), frontier, separate_opening=separate_opening)
    require(engine.closed_ledger(services=services) == ledger, "closed_reader_ledger_changed")
    provenance.update(oracle_reports=receipts, schedule_hash=schedule["schedule_hash"])
    return schedule, provenance, first_result


def read_closed_schedule(contract, recorder, engine, ledger, window, sources, binaries,
                         directory, environment, guard, reader_source):
    schedule, provenance, _ = read_closed_parent_schedule(contract, recorder, engine, ledger,
        window.headers, window.headers[-1].identifier(), sources, binaries, directory, environment,
        guard, reader_source)
    recorder.seal("closed-ledger-provenance.json", canonical(provenance))
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


def _query_provider(contract, recorder, window, schedule, descriptor, profile, binaries, directory, environment,
                    guard, provider_path, label, stdout_name, *, compare_gateway=True):
    config, request, pins = query_inputs(contract, window, schedule, profile)
    config_file = recorder.seal("query-config.json", canonical(config))
    request_file = recorder.seal("query-request.json", canonical(request))
    recorder.seal("query-context-pins.json", canonical(pins))
    same(binaries.verify(), contract.data["qualified_components"]["consumer"]["binaries"],
         "selected_consumer_binary_pins")
    command = [str(binaries.directory / "zenon-spv"),
        "query-experimental-batch-context", "--config", str(recorder.directory / config_file["file"]),
        "--request", str(recorder.directory / request_file["file"]),
        "--expect-header-context", pins["header_context"], "--expect-query-context", pins["context"]]
    if compare_gateway:
        command.append("--compare-gateway")
    command.append(str(provider_path))
    result = recorder.run(label, command, directory, environment, guard=guard, timeout=60,
                          stdout_cap=256 << 10, stderr_cap=4096, stdout_name=stdout_name)
    report = api_json(result.stdout(256 << 10), 256 << 10)
    matched = consumer_result(report, config, request, window.provider, window.query.root, descriptor,
                              compare_gateway=compare_gateway)
    recorder.seal("consumer-comparison.json", canonical(matched))
    return matched


def query(contract, recorder, window, schedule, descriptor, profile, binaries, directory, environment, guard):
    provider = window.provider_result
    with provider.open_stdout(contract.data["limits"]["stdout_bytes"]):
        return _query_provider(contract, recorder, window, schedule, descriptor, profile, binaries,
                               directory, environment, guard, provider.directory / provider.stdout_name,
                               "consume-query", CONSUMER_STDOUT)


def deposit_timeout_provider(contract, window):
    raw = canonical(window.provider)
    require(0 < len(raw) <= contract.data["limits"]["stdout_bytes"], "deposit_timeout_provider_size")
    return raw, {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def replay_deposit_timeout(contract, recorder, window, schedule, descriptor, profile, binaries,
                           directory, environment, guard):
    raw, expected = deposit_timeout_provider(contract, window)
    with tempfile.TemporaryDirectory(dir=environment["TMPDIR"], prefix="timeout-provider-") as temporary:
        path = Path(temporary) / "provider.json"
        path.write_bytes(raw)
        path.chmod(0o400)
        _query_provider(contract, recorder, window, schedule, descriptor, profile, binaries,
                        directory, environment, guard, path, DEPOSIT_TIMEOUT_CONSUMER, DEPOSIT_TIMEOUT_STDOUT,
                        compare_gateway="gateway" in window.provider)
        same(regular_pin(path, len(raw)), expected, "deposit_timeout_provider_changed")
    return expected
