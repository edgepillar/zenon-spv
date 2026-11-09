# SPDX-License-Identifier: GPL-3.0-only
"""Deterministic admission and sampled-budget controls; no host is admitted."""
import argparse
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
HERE = Path(__file__).absolute().parent
sys.path.insert(0, str(HERE))
import budget
import model
from process import Recorder


class HostAdmissionSampleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.contract = model.read_contract(HERE / "contract.json")

    def test_sample_uses_the_exact_runtime_admission_thresholds(self):
        observations = {"system": "Linux", "machine": "x86_64", "available_memory_bytes": 12 << 30,
                        "effective_cpu_count": 4, "free_bytes": 19 << 30}
        for field in (None, "available_memory_bytes", "effective_cpu_count", "free_bytes"):
            with self.subTest(field=field):
                sample = dict(observations)
                if field is not None:
                    sample[field] -= 1
                report = budget.preparation_admission_report(
                    self.contract, HERE, "a" * 40, 100, 2, observe=lambda _: sample)
                self.assertEqual(report["observations"], sample)
                self.assertEqual(report["minimums"], {key: value for key, value in observations.items()
                                                      if type(value) is int})
                self.assertEqual((report["source_revision"], report["run_id"], report["run_attempt"],
                                  report["contract_sha256"]), ("a" * 40, 100, 2, self.contract.sha256))
                self.assertEqual((report["status"], report["reason"]),
                                 ("MEETS_THRESHOLDS", None) if field is None else ("REFUSED", "integer_bounds"))
                self.assertFalse(report["engine_contacted"])
                self.assertFalse(report["experiment_executed"])
                self.assertFalse(report["OS_aggregate_quota_or_runtime_enforcement_proven"])

    def test_observation_failure_is_retained_without_host_details(self):
        def unreadable(_):
            raise OSError("private failure details")

        report = budget.preparation_admission_report(self.contract, HERE, "a" * 40, 100, 1, observe=unreadable)
        self.assertEqual((report["status"], report["reason"], report["observations"]),
                         ("UNAVAILABLE", "observation_failed", None))
        self.assertNotIn(b"private", model.canonical(report))


@unittest.skipUnless(os.name == "posix", "POSIX recorder fixture; actual runner requires Linux")
class BudgetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.contract = model.read_contract(HERE / "contract.json")

    def prepare(self, root, free=30 << 30):
        current = {"system": "Linux", "machine": "x86_64", "available_memory_bytes": 16 << 30,
                   "effective_cpu_count": 4, "free_bytes": free}
        clock = [100.0]
        recorder = Recorder(root / "commands")
        instance = budget.Budget(self.contract, root, recorder, observe=lambda _: dict(current),
                                 clock=lambda: clock[0])
        return instance, current, clock, recorder

    def test_exact_19_gib_admission_and_remaining_allocation_are_distinct(self):
        with tempfile.TemporaryDirectory(prefix="budget-regular-control-") as temporary:
            instance, current, clock, _ = self.prepare(Path(temporary), 19 << 30)
            self.assertEqual(instance.admission["minimum_free_bytes_with_allocation_and_margin"], 19 << 30)
            # Four GiB of the eight-GiB reservation was observed as allocated.
            current["free_bytes"] -= 4 << 30
            clock[0] += 1
            instance.check()
            self.assertEqual(instance.peak_new_disk, 4 << 30)
            self.assertIsNone(instance.failure)

    def test_insufficient_admission_is_not_an_accepted_runtime_observation(self):
        with tempfile.TemporaryDirectory(prefix="budget-regular-control-") as temporary:
            with self.assertRaises(model.Refused):
                self.prepare(Path(temporary), (19 << 30) - 1)

    def test_observed_space_growth_over_eight_gib_is_terminal(self):
        with tempfile.TemporaryDirectory(prefix="budget-regular-control-") as temporary:
            instance, current, clock, _ = self.prepare(Path(temporary))
            current["free_bytes"] -= (8 << 30) + 1
            clock[0] += 1
            with self.assertRaisesRegex(model.Refused, "new_disk_budget"):
                instance.check()
            current["free_bytes"] = 30 << 30
            with self.assertRaisesRegex(model.Refused, "budget_already_refused"):
                instance.check()

    def test_sampled_free_floor_is_not_bypassed_by_earlier_free_space(self):
        with tempfile.TemporaryDirectory(prefix="budget-regular-control-") as temporary:
            instance, current, clock, _ = self.prepare(Path(temporary))
            current["free_bytes"] = (11 << 30) - 1
            clock[0] += 1
            with self.assertRaisesRegex(model.Refused, "minimum_free_space"):
                instance.check()

    def test_observed_space_recovery_does_not_erase_the_peak(self):
        with tempfile.TemporaryDirectory(prefix="budget-regular-control-") as temporary:
            instance, current, clock, _ = self.prepare(Path(temporary))
            current["free_bytes"] -= 3 << 30
            clock[0] += 1
            instance.check()
            current["free_bytes"] += 2 << 30
            clock[0] += 1
            instance.check()
            self.assertEqual(instance.report()["peak_observed_new_disk_bytes"], 3 << 30)
            self.assertFalse(instance.report()["OS_aggregate_quota_or_runtime_enforcement_proven"])

    def test_deadline_leaves_five_minutes_for_scoped_termination(self):
        with tempfile.TemporaryDirectory(prefix="budget-regular-control-") as temporary:
            instance, _, clock, _ = self.prepare(Path(temporary))
            clock[0] += 2399
            instance.check()
            clock[0] += 1
            with self.assertRaisesRegex(model.Refused, "new_work_deadline"):
                instance.check()

    def test_sampling_backoff_does_not_skip_deadline_or_allow_a_backward_clock(self):
        for delta in (-0.01, 2400):
            with self.subTest(delta=delta):
                with tempfile.TemporaryDirectory(prefix="budget-regular-control-") as temporary:
                    instance, _, clock, _ = self.prepare(Path(temporary))
                    clock[0] += delta
                    with self.assertRaises(model.Refused):
                        instance.check()

    def test_evidence_cap_counts_the_active_regular_prefix_without_copying(self):
        with tempfile.TemporaryDirectory(prefix="budget-regular-control-") as temporary:
            instance, _, clock, recorder = self.prepare(Path(temporary))
            path = recorder.directory / "active.stdout"
            # Sparse regular-file metadata fixture: no 64-MiB payload allocation.
            with path.open("xb") as stream:
                stream.truncate((64 << 20) + 1)
            clock[0] += 1
            with self.assertRaisesRegex(model.Refused, "evidence_budget"):
                instance.check()

    def test_filesystem_binding_is_explicit_and_cannot_be_reselected(self):
        with tempfile.TemporaryDirectory(prefix="budget-regular-control-") as temporary:
            root = Path(temporary)
            instance, _, _, _ = self.prepare(root)
            self.assertFalse(instance.report()["engine_filesystem_bound"])
            instance.bind_engine_filesystem(str(root))
            self.assertTrue(instance.report()["engine_filesystem_bound"])
            with self.assertRaisesRegex(model.Refused, "engine_disk_already_bound"):
                instance.bind_engine_filesystem(str(root))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-revision")
    args = parser.parse_args()
    if args.source_revision is not None:
        model.digest(args.source_revision, model.HEX40)
    result = unittest.TextTestRunner(stream=sys.stderr, verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__]))
    sys.stdout.buffer.write(model.canonical({"format": "owned-devnet-budget-controls/v1",
        "source_revision": args.source_revision, "root_tests": result.testsRun,
        "errors": len(result.errors), "failures": len(result.failures), "skipped": len(result.skipped),
        "successful": result.wasSuccessful(), "scope": "DETERMINISTIC_REGULAR_FILE_FIXTURES",
        "real_host_or_container_enforcement_qualified": False}))
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
