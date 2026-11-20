# SPDX-License-Identifier: GPL-3.0-only
"""Select retention for the two existing Linux inputs on a reviewed main push."""

import os
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[2]
REQUEST = ".github/owned-devnet-input-renewal.json"
DEFAULT_DAYS = 14
RENEWAL_DAYS = 21


def retention_days(environment):
    if (environment.get("GITHUB_REPOSITORY"), environment.get("GITHUB_EVENT_NAME"), environment.get("GITHUB_REF")) != (
            "edgepillar/zenon-spv", "push", "refs/heads/main"):
        return DEFAULT_DAYS
    base = environment.get("SPV_RENEWAL_BASE", "")
    revision = environment.get("GITHUB_SHA", "")
    if base == revision or any(not re.fullmatch("[0-9a-f]{40}", oid) or oid == "0" * 40
                               for oid in (base, revision)):
        return DEFAULT_DAYS
    git = ["git", "--no-optional-locks"]
    options = {"cwd": ROOT, "stderr": subprocess.DEVNULL, "timeout": 8}
    try:
        head = subprocess.check_output([*git, "rev-list", "--parents", "--max-count=1", "HEAD"], **options)
        if head.split()[:2] != [revision.encode("ascii"), base.encode("ascii")]:
            return DEFAULT_DAYS
        changed = subprocess.check_output([*git, "diff", "--no-ext-diff", "--no-textconv",
            "--no-renames", "--diff-filter=AM", "--name-only", "-z", base, revision, "--", REQUEST], **options)
    except (OSError, subprocess.SubprocessError):
        return DEFAULT_DAYS
    return RENEWAL_DAYS if changed == REQUEST.encode("ascii") + b"\0" else DEFAULT_DAYS


if __name__ == "__main__":
    print(retention_days(os.environ))
