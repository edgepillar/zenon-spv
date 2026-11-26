# SPDX-License-Identifier: GPL-3.0-only
"""Exercise fixture timeouts and diagnostics without starting the fixture."""

import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import fixture_progress as progress
import model
from process import CommandFailed, Recorder, Result, _file_identity
import runner

CONTRACT = model.read_contract(HERE / "reference-gas-renewal-1-contract.json")
VAULT_ID = b"a" * 64
VAULT_ARTIFACT_STEP = b"ok vault artifacts verified (code hash " + VAULT_ID + b")\n"
THROUGH_DEPOSIT = (b"unrelated private diagnostic\n" + VAULT_ARTIFACT_STEP
    + b"ok vault deploy started\nok vault sent 15 chunks\nok all 15 chunks held by Settlement\n"
    + b"ok vault finalize sent\nok deployed vault as " + VAULT_ID + b"\n"
    + b"ok buy 96 bytes of storage\nok deposit sent\n")
THROUGH_CONFIGURATION = (b"unrelated private diagnostic\nfuse admin received at momentum 12\n"
                         b"registerDomain received at momentum 21\nsetAssetConfig received at momentum 36\r\n")


class FixtureProgressTests(unittest.TestCase):
    def test_only_complete_ordered_checkpoints_from_the_pinned_flow(self):
        through_deposit = ["vault_artifacts", "vault_deploy_started", "vault_chunks_sent",
                           "vault_chunks_held", "vault_finalize_step", "vault_deployed",
                           "storage_purchase_step", "deposit_step"]
        self.assertEqual(progress.reported_prefix(THROUGH_DEPOSIT + b"ok totalDeposited grew by the deposit"),
                         through_deposit)
        self.assertEqual(progress.reported_prefix(THROUGH_DEPOSIT
            + b"ok totalDeposited grew by the deposit\nok balance read at latest\r\n"
            + b"ok balance read at finalized\nok conservation held after 18 checks\n"),
            through_deposit + ["deposited_total_check", "latest_balance_check",
                               "finalized_balance_check", "conservation_checks"])
        self.assertEqual(progress.reported_prefix(b"ok vault deploy started\n" + VAULT_ARTIFACT_STEP
            + b"ok deposit sent receipt at finalized: SUCCESS, batch 0\nok vault sent 15 chunks\n"),
            ["vault_artifacts"])

    def test_configuration_observes_optional_ordered_receipts_and_complete_lines(self):
        seen = ["fuse_admin_received", "register_domain_received", "set_asset_config_received"]
        self.assertEqual(progress.reported_configuration(THROUGH_CONFIGURATION
            + b"fuse user received at momentum 37\nsetAssetConfig (confirm) received at momentum 51"), seen)
        self.assertEqual(progress.reported_configuration(THROUGH_CONFIGURATION
            + b"setAssetConfig (confirm) received at momentum 51\nconfigured\n"),
            seen + ["confirm_asset_config_received", "configured"])
        self.assertEqual(progress.reported_configuration(b"already configured\n"), ["already_configured"])
        self.assertEqual(progress.reported_configuration(b"registerDomain received at momentum 0\nconfigured"), [])

    def test_reference_gas_commands_get_cohort_specific_time_budgets(self):
        original = model.read_contract(HERE / "contract.json")
        reference_gas = model.read_contract(HERE / "reference-gas-contract.json")
        for contract, phase, script, arguments, timeout in (
            (original, "deposit", "flows/deposit.ts", [], 420),
            (original, "configure", "src/cli.ts", ["configure"], 420),
            (reference_gas, "deposit", "flows/deposit.ts", [], 900),
            (reference_gas, "configure", "src/cli.ts", ["configure"], 660),
            (CONTRACT, "deposit", "flows/deposit.ts", [], 900),
            (CONTRACT, "configure", "src/cli.ts", ["configure"], 660),
        ):
            with self.subTest(contract=contract.sha256, phase=phase):
                recorder = Mock()
                sources = Mock(paths={"devnet": HERE})
                node = Mock(node=HERE / "node")
                engine = Mock(environment={})
                prepared = Mock(environment={}, report={"installed_entries": []})
                guard = Mock()
                with patch.object(runner, "installed_entries", return_value=[]), \
                        patch.object(runner, "regular_pin", return_value=contract.data["node_toolchain"]["node_binary"]):
                    runner.fixture_flow(contract, recorder, engine, sources, node, prepared, phase, guard)
                recorder.run.assert_called_once_with(
                    "fixture-" + phase, [str(node.node), str(HERE / "node_modules/tsx/dist/cli.mjs"),
                                        script, *arguments], HERE, {}, guard=guard, timeout=timeout,
                    stdout_cap=model.FIXTURE_OUTPUT_BYTES, stderr_cap=model.FIXTURE_OUTPUT_BYTES)

    @unittest.skipUnless(os.name == "posix", "fixture recorder requires POSIX process groups")
    def test_only_the_bounded_summary_is_exported_on_a_selected_fixture_timeout(self):
        for phase, raw, report, checkpoint in (
            ("deposit", THROUGH_DEPOSIT, progress.REPORT, "deposit_step"),
            ("configure", THROUGH_CONFIGURATION, progress.CONFIGURE_REPORT, "set_asset_config_received"),
        ):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory(prefix="owned-fixture-progress-") as directory:
                root = Path(directory)
                recorder = Recorder(root / "evidence")
                stdout = recorder.seal(f"fixture-{phase}.stdout", raw)
                stderr = recorder.seal(f"fixture-{phase}.stderr", b"unrelated private error")
                path = recorder.directory / stdout["file"]
                receipt = {"reason": "timeout", "process_group_quiescent": True, "outputs": {"stdout": stdout}}
                result = Result(recorder.directory, stdout["file"], stderr["file"],
                                model.canonical(receipt), _file_identity(path.lstat()))
                error = CommandFailed(result)
                sources = Mock(paths={"devnet": root})
                node = Mock(node=root / "node")
                engine = Mock(environment={})
                prepared = Mock(environment={}, report={"installed_entries": []})
                with patch.object(recorder, "run", side_effect=error) as run, \
                        patch.object(runner, "installed_entries", return_value=[]), \
                        patch.object(runner, "regular_pin", return_value=CONTRACT.data["node_toolchain"]["node_binary"]):
                    with self.assertRaises(CommandFailed) as caught:
                        runner.fixture_flow(CONTRACT, recorder, engine, sources, node, prepared, phase, None)
                self.assertIs(caught.exception, error)
                self.assertEqual(run.call_count, 1)
                summary = (recorder.directory / report).read_bytes()
                self.assertNotIn(VAULT_ID, summary)
                self.assertNotIn(b"unrelated private", summary)
                self.assertNotIn(b" at momentum ", summary)
                self.assertEqual(json.loads(summary)["reported_checkpoints"][-1], checkpoint)
                self.assertEqual(json.loads(summary)["stdout"]["sha256"], hashlib.sha256(raw).hexdigest())
                entries = runner.evidence_index((recorder,), {})
                self.assertEqual([row["path"] for row in entries], [f"evidence/{report}"])

    def test_unavailable_stdout_never_supplies_checkpoints(self):
        receipt = {"process_group_quiescent": False, "outputs": {"stdout": {}}}
        result = Mock(receipt=receipt, stdout=Mock(side_effect=model.Refused("command_result_changed")))
        self.assertIsNone(progress.observe(result)["reported_checkpoints"])
        result.stdout.assert_not_called()
        receipt["process_group_quiescent"] = True
        self.assertIsNone(progress.observe(result)["reported_checkpoints"])
        result.stdout.assert_called_once_with(model.FIXTURE_OUTPUT_BYTES)


if __name__ == "__main__":
    unittest.main()
