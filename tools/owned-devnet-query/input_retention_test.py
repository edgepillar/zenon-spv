# SPDX-License-Identifier: GPL-3.0-only

from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import input_retention

BASE = "1" * 40
REVISION = "2" * 40
MAIN = {
    "GITHUB_REPOSITORY": "edgepillar/zenon-spv",
    "GITHUB_EVENT_NAME": "push",
    "GITHUB_REF": "refs/heads/main",
    "SPV_RENEWAL_BASE": BASE,
    "GITHUB_SHA": REVISION,
}
HEAD = (REVISION + " " + BASE + "\n").encode("ascii")
RENEWAL = input_retention.REQUEST.encode("ascii") + b"\0"


class RetentionTests(unittest.TestCase):
    @patch.object(input_retention.subprocess, "check_output")
    def test_exact_main_push_selects_retention_only_for_the_renewal_path(self, git):
        git.side_effect = (HEAD, RENEWAL)
        self.assertEqual(input_retention.retention_days(MAIN), 21)
        self.assertEqual(git.call_args_list[0].args[0][-4:], ["rev-list", "--parents", "--max-count=1", "HEAD"])
        self.assertEqual(git.call_args.args[0][-4:], [BASE, REVISION, "--", input_retention.REQUEST])
        self.assertIn("--diff-filter=AM", git.call_args.args[0])
        self.assertIn("--no-renames", git.call_args.args[0])

    @patch.object(input_retention.subprocess, "check_output")
    def test_other_events_repositories_and_branches_keep_default(self, git):
        for update in ({"GITHUB_EVENT_NAME": "pull_request"}, {"GITHUB_EVENT_NAME": "workflow_dispatch"},
                       {"GITHUB_REPOSITORY": "other/zenon-spv"}, {"GITHUB_REF": "refs/heads/candidate"},
                       {"GITHUB_REF": "refs/tags/main"}):
            with self.subTest(update=update):
                self.assertEqual(input_retention.retention_days({**MAIN, **update}), 14)
        git.assert_not_called()

    @patch.object(input_retention.subprocess, "check_output")
    def test_missing_zero_or_equal_revisions_keep_default(self, git):
        for update in ({"SPV_RENEWAL_BASE": ""}, {"SPV_RENEWAL_BASE": "0" * 40},
                       {"SPV_RENEWAL_BASE": REVISION}, {"GITHUB_SHA": "HEAD"}):
            with self.subTest(update=update):
                self.assertEqual(input_retention.retention_days({**MAIN, **update}), 14)
        git.assert_not_called()

    @patch.object(input_retention.subprocess, "check_output")
    def test_other_checkout_or_ambiguous_diff_keeps_default(self, git):
        for observations in (((BASE + " " + REVISION + "\n").encode("ascii"),),
                             ((REVISION + " " + "3" * 40 + "\n").encode("ascii"),), (HEAD, b""),
                             (HEAD, RENEWAL + b"other\0"),
                             (HEAD, b"other\0"), (HEAD, b"outer/" + RENEWAL)):
            with self.subTest(observations=observations):
                git.side_effect = observations
                self.assertEqual(input_retention.retention_days(MAIN), 14)

    @patch.object(input_retention.subprocess, "check_output")
    def test_unavailable_history_and_git_timeout_keep_default(self, git):
        for failure in (subprocess.CalledProcessError(128, "git"), subprocess.TimeoutExpired("git", 8), OSError()):
            with self.subTest(failure=type(failure).__name__):
                git.side_effect = (HEAD, failure)
                self.assertEqual(input_retention.retention_days(MAIN), 14)


if __name__ == "__main__":
    unittest.main(verbosity=2)
