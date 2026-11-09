# SPDX-License-Identifier: GPL-3.0-only
"""One original transport per selected artifact in one fresh owned workspace.

Run metadata is an additional binding check, not independent authentication of
CI or a release. The controller supplies its separately reviewed contract and
explicit command environment. It must obtain execution authorization separately.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import json
import os
from pathlib import Path
import stat

import inputs
from model import Refused, canonical, require
from process import owned_lease

REPOSITORY = "edgepillar/zenon-spv"
WORKFLOWS = {"consumer": ".github/workflows/ci.yml",
             "parent_oracle": ".github/workflows/closed-devnet-parent-oracle.yml"}
API_LIMIT = 128 << 10


def api_json(raw, limit=API_LIMIT):
    require(type(raw) is bytes and 0 < len(raw) <= limit, "artifact_api_bound")

    def pairs(rows):
        value = {}
        for key, item in rows:
            require(key not in value, "artifact_api_duplicate_field")
            value[key] = item
        return value

    def unsupported(_):
        raise Refused("artifact_api_number")

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                           parse_float=unsupported, parse_constant=unsupported)
    except (UnicodeError, json.JSONDecodeError, RecursionError, ValueError) as error:
        if isinstance(error, Refused):
            raise
        raise Refused("artifact_api_encoding") from error
    require(type(value) is dict, "artifact_api_object")
    return value


def _number(actual, expected, reason):
    require(type(actual) is int and actual == expected, reason)


def bind_metadata(contract, role, run, artifact):
    require(type(role) is str and role in WORKFLOWS, "artifact_component")
    require(type(run) is dict and type(artifact) is dict, "artifact_metadata")
    components = contract.data["qualified_components"]
    selected = components[role]
    _number(run.get("id"), selected["run_id"], "artifact_run_id")
    _number(run.get("run_attempt"), selected["run_attempt"], "artifact_run_attempt")
    require(run.get("status") == "completed" and run.get("conclusion") == "success"
            and run.get("event") == "push" and run.get("head_branch") == "main"
            and run.get("path") == WORKFLOWS[role]
            and run.get("head_sha") == components["source_revision"], "artifact_run_source")
    for name in ("repository", "head_repository"):
        value = run.get(name)
        require(type(value) is dict and value.get("full_name") == REPOSITORY
                and type(value.get("id")) is int and value["id"] > 0,
                "artifact_run_repository")
    _number(artifact.get("id"), selected["artifact_id"], "artifact_identity")
    _number(artifact.get("size_in_bytes"), selected["archive"]["bytes"], "artifact_archive_size")
    require(artifact.get("expired") is False
            and artifact.get("digest") == "sha256:" + selected["archive"]["sha256"],
            "artifact_digest_or_expiry")
    owner = artifact.get("workflow_run")
    require(type(owner) is dict, "artifact_workflow_run")
    _number(owner.get("id"), selected["run_id"], "artifact_workflow_run")
    _number(owner.get("repository_id"), run["repository"]["id"], "artifact_workflow_repository")
    _number(owner.get("head_repository_id"), run["head_repository"]["id"],
            "artifact_workflow_repository")
    require(owner.get("head_sha") == components["source_revision"], "artifact_workflow_revision")
    return {"component": role, "repository": REPOSITORY,
            "source_revision": components["source_revision"],
            "workflow": WORKFLOWS[role], "run_id": selected["run_id"],
            "run_attempt": selected["run_attempt"], "artifact_id": selected["artifact_id"],
            "archive": selected["archive"], "authenticated_distribution": False,
            "new_ci_execution_qualified": False}


@dataclass(frozen=True)
class Materialized:
    original: object
    binaries: inputs.VerifiedBinaries
    binding_raw: bytes

    @property
    def binding(self):
        return json.loads(self.binding_raw)

    def verify(self):
        expected = self.binding["archive"]
        with self.original.open_stdout(expected["bytes"]):
            pass
        return self.binaries.verify()


class Artifacts:
    """A failed attempt is terminal here; it is never treated as a cache hit."""

    def __init__(self, contract, recorder, directory, command, environment, guard):
        self.contract, self.recorder = contract, recorder
        self.directory = Path(directory)
        require(not self.directory.exists() and not self.directory.is_symlink(),
                "artifact_directory_exists")
        require(type(command) is list and command and all(type(a) is str for a in command),
                "artifact_command")
        require(type(environment) is dict and callable(guard), "artifact_environment_or_guard")
        self.command, self.environment = list(command), dict(environment)
        self.guard = guard
        self.directory.mkdir(mode=0o700)
        info = self.directory.lstat()
        self.identity = (info.st_dev, info.st_ino, info.st_uid)
        self.attempted, self.cache = set(), {}

    def check(self):
        self.recorder.check()
        info = self.directory.lstat()
        require(stat.S_ISDIR(info.st_mode)
                and (info.st_dev, info.st_ino, info.st_uid) == self.identity,
                "artifact_directory_changed")

    @contextmanager
    def lease(self, selected):
        # A new immutable lease inode inside this recorder's exclusive directory.
        # No historical workspace, digest filename or discovered file is adopted.
        name = "artifact-" + str(selected["artifact_id"]) + ".lease"
        with owned_lease(self.recorder, name):
            yield

    def fetch(self, role):
        self.check()
        require(type(role) is str and role in WORKFLOWS, "artifact_component")
        if role in self.cache:
            result = self.cache[role]
            result.verify()
            return result
        require(role not in self.attempted, "artifact_attempt_already_consumed")
        self.attempted.add(role)
        selected = self.contract.data["qualified_components"][role]
        label = role.replace("_", "-")

        def command(suffix, endpoint, cap=API_LIMIT, stdout_name=None):
            return self.recorder.run("input-" + label + "-" + suffix,
                                     [*self.command, "api", endpoint], self.directory,
                                     self.environment, stdout_cap=cap, stderr_cap=128 << 10,
                                     timeout=180, stdout_name=stdout_name, guard=self.guard)

        with self.lease(selected):
            self.guard()
            base = "repos/" + REPOSITORY + "/actions/"
            run = command("run", base + "runs/" + str(selected["run_id"])
                          + "/attempts/" + str(selected["run_attempt"]))
            artifact = command("metadata", base + "artifacts/" + str(selected["artifact_id"]))
            binding = bind_metadata(self.contract, role, api_json(run.stdout(API_LIMIT)),
                                    api_json(artifact.stdout(API_LIMIT)))
            self.recorder.seal("input-" + label + "-selection.json", canonical(binding))
            # stdout is the original ZIP, not a separate log later copied to ZIP.
            original = command("archive", base + "artifacts/" + str(selected["artifact_id"])
                               + "/zip", selected["archive"]["bytes"],
                               "artifact-" + str(selected["artifact_id"]) + ".zip")
            receipt = original.receipt
            require(type(receipt["actual_exit"]) is int and receipt["actual_exit"] == 0
                    and receipt["output_complete"] is True
                    and {k: receipt["outputs"]["stdout"][k] for k in ("sha256", "bytes")}
                    == selected["archive"], "artifact_transport_content")
            with original.open_stdout(selected["archive"]["bytes"]) as stream:
                binaries = inputs.unpack_binaries(stream, role, selected, self.directory / role)
            result = Materialized(original, binaries, canonical(binding))
        # Lease reconciliation is part of success. A failure while leaving the
        # scope must not publish a partially reconciled in-memory cache entry.
        self.cache[role] = result
        return result
