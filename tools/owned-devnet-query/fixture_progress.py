# SPDX-License-Identifier: GPL-3.0-only
"""Allowlisted diagnostics for a timed-out deposit on the reviewed fixture source."""
from __future__ import annotations

import io
import re

import model
from model import Refused, exact_keys, require, same

COMMAND = "fixture-deposit"
REPORT = "fixture-deposit-progress.json"
FORMAT = "owned-devnet-fixture-deposit-progress/v1"
DEVNET_SOURCE = {"repository": "Zeno-L2/zeno-devnet",
                 "revision": "cf1c9c0e0f0ca3b257bdbd019c5589c2c27f748f", "fetch": "git"}

# flows/lib.ts prints each step after its conservation check. Keep the fixed
# sequence from flows/deposit.ts and discard every interpolated value.
MARKERS = tuple((name, re.compile(pattern)) for name, pattern in (
    ("vault_artifacts", rb"ok vault artifacts verified \(code hash [a-f0-9]{64}\)"),
    ("vault_deploy_started", rb"ok vault deploy started"),
    ("vault_chunks_sent", rb"ok vault sent [1-9][0-9]{0,5} chunks"),
    ("vault_chunks_held", rb"ok all [1-9][0-9]{0,5} chunks held by Settlement"),
    ("vault_finalize_step", rb"ok vault finalize sent"),
    ("vault_deployed", rb"ok deployed vault as [a-f0-9]{64}"),
    ("storage_purchase_step", rb"ok buy 96 bytes of storage"),
    ("deposit_step", rb"ok deposit sent"),
    ("deposited_total_check", rb"ok totalDeposited grew by the deposit"),
    ("latest_balance_check", rb"ok balance read at latest"),
    ("finalized_balance_check", rb"ok balance read at finalized"),
    ("conservation_checks", rb"ok conservation held after [1-9][0-9]{0,5} checks"),
))
CHECKPOINTS = tuple(name for name, _ in MARKERS)


def supports(contract):
    return contract.data["sources"]["devnet"] == DEVNET_SOURCE


def reported_prefix(raw):
    """Read complete lines and keep the ordered prefix of known step markers."""
    checkpoints = []
    for line in io.BytesIO(raw):
        if not line.endswith(b"\n"):
            break
        name, marker = MARKERS[len(checkpoints)]
        if marker.fullmatch(line.removesuffix(b"\n").removesuffix(b"\r")):
            checkpoints.append(name)
            if len(checkpoints) == len(MARKERS):
                break
    return checkpoints


def observe(result):
    receipt = result.receipt
    checkpoints = None
    if receipt["process_group_quiescent"] is True:
        try:
            checkpoints = reported_prefix(result.stdout(model.FIXTURE_OUTPUT_BYTES))
        except (OSError, Refused):
            pass
    return {"format": FORMAT, "stdout": receipt["outputs"]["stdout"],
            "reported_checkpoints": checkpoints}


def recorded(evidence, contract, timeout):
    if f"evidence/{REPORT}" not in evidence.pins:
        return None
    require(timeout is not None and timeout["command"] == COMMAND and supports(contract),
            "review_fixture_progress_scope")
    report = evidence.json(REPORT, 2 << 10)
    exact_keys(report, {"format", "stdout", "reported_checkpoints"}, "review_fixture_progress_fields")
    same(report["format"], FORMAT, "review_fixture_progress_format")
    receipt = evidence.json(COMMAND + ".complete.json")
    stdout = report["stdout"]
    exact_keys(stdout, {"file", "bytes", "sha256"}, "review_fixture_progress_stdout")
    outputs = receipt.get("outputs")
    exact_keys(outputs, {"stdout", "stderr"}, "review_fixture_progress_stdout")
    same(stdout, outputs["stdout"], "review_fixture_progress_stdout")
    same(stdout["file"], COMMAND + ".stdout", "review_fixture_progress_stdout")
    model.uint(stdout["bytes"], model.FIXTURE_OUTPUT_BYTES, minimum=0)
    model.digest(stdout["sha256"])
    checkpoints = report["reported_checkpoints"]
    require(checkpoints is None or (type(checkpoints) is list and timeout["process_group_quiescent"]
            and tuple(checkpoints) == CHECKPOINTS[:len(checkpoints)]
            and (not checkpoints or stdout["bytes"] > 0)), "review_fixture_progress_checkpoints")
    return {**report, "original_stdout_independently_rechecked": False}
