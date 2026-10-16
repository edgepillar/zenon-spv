#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Source-default build selection controls; compile and execute no node."""
import copy
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("selected_default_retention_preparation", HERE / "prepare_default_retention.py")
M = importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)


def parent():
    return {"build_argv": ["/selected/go", "test", "-c", "-p=1", "-mod=readonly", "-trimpath",
                           "-buildvcs=false", "-overlay=/owned/test-overlay.json", "-tags",
                           "candidate_hash_bound_versions,candidate_genesis_background",
                           "-o", "/owned/genesis-background-resource.test",
                           "github.com/zenon-network/go-zenon/chain"],
            "history_height": 4096, "retention_test_override": 256}


class DefaultRetentionPreparationControls(unittest.TestCase):
    def test_only_tag_and_output_change_in_the_inherited_build(self):
        before = parent()
        original = copy.deepcopy(before)
        result = M.plan(Path("/owned/new-component"), "/selected/go", before)
        build = list(result["build_argv"])
        self.assertNotIn("-race", build)
        self.assertEqual(build[build.index("-tags") + 1],
                         "candidate_hash_bound_versions,candidate_genesis_background,candidate_default_retention")
        build[build.index("-tags") + 1] = original["build_argv"][original["build_argv"].index("-tags") + 1]
        build[build.index("-o") + 1] = original["build_argv"][original["build_argv"].index("-o") + 1]
        self.assertEqual(build, original["build_argv"])
        self.assertEqual(before, original)

    def test_exact_new_test_is_selected_and_defaults_have_no_override(self):
        result = M.plan(Path("/owned/new-component"), "/selected/go", parent())
        self.assertEqual(result["run_argv"], ["/owned/new-component/generator/default-retention.test",
                                             "-test.v", "-test.timeout=540s",
                                             "-test.run=^TestCandidateDefaultRetention$"])
        self.assertEqual((result["history_height"], result["mutation_keys"],
                          result["source_effective_retention"]), (32768, 256, 17380))
        self.assertEqual((result["retention_override"], result["bulk_batch_override"]), (0, 0))
        self.assertEqual((result["expected_pruned_roots"], result["expected_archive_roots"]), (17381, 32768))
        self.assertEqual(result["parent_probe_compiled_but_not_selected"], [M.P.PROBE, M.G.PROBE])

    def test_old_preparation_record_and_runtime_identity_are_preserved(self):
        before = parent()
        result = M.plan(Path("/owned/new-component"), "/selected/go", before)
        self.assertEqual(result["parent_genesis_prepared_sha256"], M.P.sha(M.P.UTIL.encoded(before)))
        self.assertEqual(before["history_height"], 4096)
        self.assertEqual(result["runtime_tree_without_probes"], M.G.L.MODIFIED_TREE)
        self.assertEqual((result["node_source_blobs"], result["probe_source_files_added"]), (439, 3))
        self.assertFalse(result["runtime_changes_beyond_existing_retained_identity_and_terminal_stop_patches"])
        self.assertEqual(result["consumer_result"], "REFUSED")
        for field in ("reference_backend_executed", "new_network_or_source_acquisition",
                      "existing_database_adopted", "profile_agreed", "accepted_header_root_binding",
                      "production_resources_qualified", "scheduler_checkpoints_injected"):
            self.assertIs(result[field], False)

    def test_existing_destination_is_refused_before_parent_preparation(self):
        with tempfile.TemporaryDirectory(prefix="default-retention-plan-", dir=os.environ["SPV_TASK_SCRATCH"]) as directory:
            with mock.patch.object(M.G, "prepare") as selected:
                with self.assertRaises(ValueError):
                    M.prepare(Path("/unselected/source"), Path(directory), "/selected/go")
                selected.assert_not_called()

    def test_unknown_source_inventory_is_refused_before_source_adoption(self):
        with tempfile.TemporaryDirectory(prefix="default-retention-inventory-", dir=os.environ["SPV_TASK_SCRATCH"]) as directory:
            root = Path(directory)
            (root / "node").mkdir()
            (root / "node/unselected.txt").write_text("isolated fixture\n")
            with self.assertRaises(ValueError):
                M.verify(root)


if __name__ == "__main__":
    unittest.main(verbosity=2)
