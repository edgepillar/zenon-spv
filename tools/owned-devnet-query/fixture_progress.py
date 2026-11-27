# SPDX-License-Identifier: GPL-3.0-only
"""Allowlisted diagnostics for timed-out commands on the reviewed fixture source."""
from __future__ import annotations

import io
import re

import model
from model import Refused, exact_keys, require, same

COMMAND = "fixture-deposit"
REPORT = "fixture-deposit-progress.json"
FORMAT = "owned-devnet-fixture-deposit-progress/v1"
CONFIGURE_COMMAND = "fixture-configure"
CONFIGURE_REPORT = "fixture-configure-progress.json"
CONFIGURE_FORMAT = "owned-devnet-fixture-configure-progress/v1"
TIMEOUT_SCOPES = {
    "fixture-configuration": (CONFIGURE_COMMAND, model.NODE_SERVICES),
    "fixture-deposit": (COMMAND, model.SERVICES),
}
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

# src/cli.ts skips configuration already present and prints each label after
# receiving its block. Keep only the labels in the order used by that source.
CONFIGURE_RECEIPTS = {
    b"fuse admin": "fuse_admin_received",
    b"fuse executor": "fuse_executor_received",
    b"fuse user": "fuse_user_received",
    b"registerDomain": "register_domain_received",
    b"registerExecutor": "register_executor_received",
    b"setApprovedDAModes": "set_approved_da_modes_received",
    b"setAssetConfig": "set_asset_config_received",
    b"setPeripheryConfig": "set_periphery_config_received",
    b"registerExecutor (confirm)": "confirm_executor_received",
    b"setApprovedDAModes (confirm)": "confirm_approved_da_modes_received",
    b"setAssetConfig (confirm)": "confirm_asset_config_received",
    b"setPeripheryConfig (confirm)": "confirm_periphery_config_received",
}
CONFIGURE_CHECKPOINTS = (*CONFIGURE_RECEIPTS.values(), "configured")
CONFIGURE_LINE = re.compile(rb"([A-Za-z][A-Za-z ()]{0,39}) received at momentum [1-9][0-9]{0,19}")


def supports(contract):
    return contract.data["sources"]["devnet"] == DEVNET_SOURCE


def complete_lines(raw):
    for line in io.BytesIO(raw):
        if not line.endswith(b"\n"):
            break
        yield line.removesuffix(b"\n").removesuffix(b"\r")


def reported_prefix(raw):
    """Read complete lines and keep the ordered prefix of known step markers."""
    checkpoints = []
    for line in complete_lines(raw):
        name, marker = MARKERS[len(checkpoints)]
        if marker.fullmatch(line):
            checkpoints.append(name)
            if len(checkpoints) == len(MARKERS):
                break
    return checkpoints


def reported_configuration(raw):
    """Keep an ordered subsequence of the pinned configure command's labels."""
    positions = {name: index for index, name in enumerate(CONFIGURE_CHECKPOINTS)}
    checkpoints = []
    last = -1
    for line in complete_lines(raw):
        if line == b"already configured":
            return checkpoints or ["already_configured"]
        if line == b"configured":
            return checkpoints + ["configured"]
        match = CONFIGURE_LINE.fullmatch(line)
        checkpoint = CONFIGURE_RECEIPTS.get(match[1]) if match else None
        if checkpoint is not None and positions[checkpoint] > last:
            checkpoints.append(checkpoint)
            last = positions[checkpoint]
    return checkpoints


def observe(result, *, configuration=False):
    receipt = result.receipt
    checkpoints = None
    if receipt["process_group_quiescent"] is True:
        try:
            read_checkpoints = reported_configuration if configuration else reported_prefix
            checkpoints = read_checkpoints(result.stdout(model.FIXTURE_OUTPUT_BYTES))
        except (OSError, Refused):
            pass
    return {"format": CONFIGURE_FORMAT if configuration else FORMAT, "stdout": receipt["outputs"]["stdout"],
            "reported_checkpoints": checkpoints}


def valid_checkpoints(checkpoints, configuration):
    if not configuration:
        return tuple(checkpoints) == CHECKPOINTS[:len(checkpoints)]
    return checkpoints == ["already_configured"] or checkpoints == [
        name for name in CONFIGURE_CHECKPOINTS if name in checkpoints]


def recorded(evidence, contract, timeout):
    configuration = f"evidence/{CONFIGURE_REPORT}" in evidence.pins
    deposit = f"evidence/{REPORT}" in evidence.pins
    if not configuration and not deposit:
        return None
    command, filename, expected_format = ((CONFIGURE_COMMAND, CONFIGURE_REPORT, CONFIGURE_FORMAT)
                                          if configuration else (COMMAND, REPORT, FORMAT))
    require(not (configuration and deposit) and timeout is not None and timeout["command"] == command
            and supports(contract),
            "review_fixture_progress_scope")
    report = evidence.json(filename, 2 << 10)
    exact_keys(report, {"format", "stdout", "reported_checkpoints"}, "review_fixture_progress_fields")
    same(report["format"], expected_format, "review_fixture_progress_format")
    receipt = evidence.json(command + ".complete.json")
    stdout = report["stdout"]
    exact_keys(stdout, {"file", "bytes", "sha256"}, "review_fixture_progress_stdout")
    outputs = receipt.get("outputs")
    exact_keys(outputs, {"stdout", "stderr"}, "review_fixture_progress_stdout")
    same(stdout, outputs["stdout"], "review_fixture_progress_stdout")
    same(stdout["file"], command + ".stdout", "review_fixture_progress_stdout")
    model.uint(stdout["bytes"], model.FIXTURE_OUTPUT_BYTES, minimum=0)
    model.digest(stdout["sha256"])
    checkpoints = report["reported_checkpoints"]
    require(checkpoints is None or (type(checkpoints) is list and timeout["process_group_quiescent"]
            and valid_checkpoints(checkpoints, configuration)
            and (not checkpoints or stdout["bytes"] > 0)), "review_fixture_progress_checkpoints")
    return {**report, "original_stdout_independently_rechecked": False}
