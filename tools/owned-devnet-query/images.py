# SPDX-License-Identifier: GPL-3.0-only
"""Two source-bound images through one owned, resource-limited remote builder.

The caller must already have an explicitly authorized fresh hosted execution.
This module does not grant that permission or provide distribution provenance.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re

from artifacts import api_json
from engine import Engine
import model
from model import canonical, require
from packages import _regular_below
from process import regular_pin
from sources import PreparedSources

RECIPES = {"node": "docker/devnet/Dockerfile", "executor": "Dockerfile"}
IMAGE_FORMAT = ('{"Id":{{json .Id}},"Os":{{json .Os}},'
                '"Architecture":{{json .Architecture}},"RepoDigests":{{json .RepoDigests}},'
                '"Config":{"Labels":{{json .Config.Labels}}}}')
RECIPE_LABEL = "org.zenon.spv.recipe-sha256"
SOURCE_LABEL = "org.zenon.spv.source-revision"
NODE_LABEL = "org.zenon.spv.node-context-revision"


def image_id(value):
    require(type(value) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None,
            "built_image_identity")
    return value


def recipe(contract, role, raw):
    """Change only the declared FROM lines and explicit compiler parallelism."""
    require(role in RECIPES and type(raw) is bytes and len(raw) <= 64 << 10, "build_recipe_scope")
    selected = next(row for row in contract.data["source_files"]
                    if row["role"] == role and row["path"] == RECIPES[role])
    original = {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}
    require(original == {key: selected[key] for key in ("sha256", "bytes")}, "build_recipe_source_pin")
    text = raw.decode("ascii")
    images = contract.data["images"]
    expected = (["FROM golang:1.23-alpine AS builder", "FROM alpine:latest"] if role == "node"
                else ["FROM " + images["node_build"] + " AS build", "FROM " + images["runtime"] + " AS runtime"])
    lines = text.splitlines(keepends=True)
    require([line.rstrip("\r\n") for line in lines if line.startswith("FROM ")] == expected
            and text.endswith("\n") and "\r" not in text, "build_recipe_from_lines")
    replacements = ["FROM " + images["node_build"] + (" AS builder" if role == "node" else " AS build"),
                    "FROM " + images["runtime"] + ("" if role == "node" else " AS runtime")]
    result, index = [], 0
    for line in lines:
        if line.startswith("FROM "):
            result.append(replacements[index] + "\n")
            if index == 0:
                result.append("ENV GOMAXPROCS=2 GOFLAGS=-p=2" + (" CGO_ENABLED=1" if role == "node" else "") + "\n")
            index += 1
        else:
            result.append(line)
    derived = "".join(result).encode("ascii")
    return derived, {"original": original, "original_git_blob": selected["git_blob"],
        "derived": {"sha256": hashlib.sha256(derived).hexdigest(), "bytes": len(derived)},
        "compiler_parallelism": 2, "CGO_ENABLED": 1 if role == "node" else 0,
        "original_and_derived_recipes_byte_identical": False}


def build_labels(contract, admission, role, recipe_sha256):
    require(role in RECIPES and model.digest(recipe_sha256) == recipe_sha256, "build_label_scope")
    return {model.LABEL_OWNER: admission.nonce, model.LABEL_CONTRACT: contract.sha256,
            model.LABEL_PROJECT: model.PROJECT, model.LABEL_SERVICE: role + "-image",
            RECIPE_LABEL: recipe_sha256, SOURCE_LABEL: contract.data["sources"][role]["revision"],
            NODE_LABEL: contract.data["sources"]["node"]["revision"]}


def require_image(value, *, expected_id=None, labels=None, distribution=None):
    require(type(value) is dict and value.get("Os") == "linux"
            and value.get("Architecture") == "amd64", "image_platform")
    identity = image_id(value.get("Id"))
    if expected_id is not None:
        require(identity == image_id(expected_id), "image_id_changed")
    if labels is not None:
        actual = value.get("Config", {}).get("Labels")
        require(type(actual) is dict and all(actual.get(k) == v for k, v in labels.items()),
                "image_build_binding")
    if distribution is not None:
        require(type(value.get("RepoDigests")) is list and distribution in value["RepoDigests"],
                "image_distribution_digest")
    return identity


def build_result(iid, metadata, inspected, labels):
    require(type(iid) is bytes and re.fullmatch(rb"sha256:[0-9a-f]{64}\n?", iid) is not None,
            "build_iid_file")
    identity = image_id(iid.decode("ascii").rstrip("\n"))
    require(type(metadata) is dict and metadata.get("containerimage.config.digest") == identity,
            "build_metadata_config_digest")
    require_image(inspected, expected_id=identity, labels=labels)
    return identity


@dataclass(frozen=True)
class PreparedImages:
    engine: Engine
    values_raw: bytes

    @property
    def values(self):
        return json.loads(self.values_raw)

    def image_for(self, role):
        require(role in model.SERVICES and self.engine.builder_closed, "runtime_image_scope")
        selected = self.values["node" if role in ("pillar", "pillar2", "pillar3", "rpc") else "executor"]
        self.engine._info()
        actual = self.engine._run("verify-runtime-image-" + role,
            ["image", "inspect", "--format", IMAGE_FORMAT, selected["id"]])
        return require_image(api_json(actual.stdout(128 << 10)), expected_id=selected["id"],
                             labels=selected["labels"])


class Builder:
    """One attempt, no image archive, second shared-image build or global prune."""
    def __init__(self, contract, engine, sources, directory):
        require(type(engine) is Engine and type(sources) is PreparedSources
                and engine.admission is not None and engine.contract.sha256 == contract.sha256,
                "image_build_context")
        self.contract, self.engine, self.sources = contract, engine, sources
        self.root = Path(directory)
        require(not self.root.exists() and not self.root.is_symlink(), "image_workspace_exists")
        self.root.mkdir(mode=0o700)
        info = self.root.lstat()
        self.identity = info.st_dev, info.st_ino, info.st_uid
        self.started = False

    def _check(self):
        import stat
        info = self.root.lstat()
        require(stat.S_ISDIR(info.st_mode) and (info.st_dev, info.st_ino, info.st_uid)
                == self.identity, "image_workspace_changed")
        self.engine.guard()

    def prepare(self):
        require(not self.started, "image_build_already_attempted")
        self.started = True
        self._check()
        self.sources.verify()
        require(not self.engine.owned and not self.engine.started, "builder_must_precede_runtime")
        reference = self.contract.data["images"]["buildkit"]
        # Distribution content equality is recorded; no signed distribution or
        # independently reproducible image claim follows from this pull.
        self.engine._info()
        self.engine._run("pull-buildkit", ["image", "pull", "--quiet", "--platform", "linux/amd64", reference],
                         timeout=180)
        inspection = self.engine._run("inspect-buildkit-image",
            ["image", "inspect", "--format", IMAGE_FORMAT, reference])
        buildkit = require_image(api_json(inspection.stdout(128 << 10)), distribution=reference)
        self.engine.create("buildkit", buildkit)
        self.engine.start("buildkit")
        name = "spv-" + self.engine.nonce
        self.engine._run("buildx-version", ["buildx", "version"])
        created = self.engine._run("create-remote-builder", ["buildx", "create", "--name", name,
            "--driver", "remote", "tcp://127.0.0.1:12340"])
        require(created.stdout(128) == (name + "\n").encode("ascii"), "remote_builder_creation")
        self.engine._run("remote-builder-ready", ["buildx", "inspect", "--bootstrap", name], timeout=60)
        values, reports = {}, {}
        for role in ("node", "executor"):
            self._check()
            self.sources.verify()
            context = self.sources.paths[role]
            raw = (context / RECIPES[role]).read_bytes()
            derived, pins = recipe(self.contract, role, raw)
            dockerfile = self.root / (role + ".Dockerfile")
            with dockerfile.open("xb") as stream:
                stream.write(derived)
            dockerfile.chmod(0o400)
            labels = build_labels(self.contract, self.engine.admission, role, pins["derived"]["sha256"])
            iidfile, metafile = self.root / (role + ".iid"), self.root / (role + ".metadata.json")
            arguments = ["buildx", "build", "--builder", name, "--platform", "linux/amd64",
                "--load", "--progress", "plain", "--provenance=false", "--file", str(dockerfile),
                "--iidfile", str(iidfile), "--metadata-file", str(metafile),
                "--tag", "spv-owned-" + role + ":" + self.engine.nonce]
            for key, value in sorted(labels.items()):
                arguments += ["--label", key + "=" + value]
            if role == "executor":
                arguments += ["--build-context", "go-zenon=" + str(self.sources.paths["node"])]
            arguments.append(str(context))
            built = self.engine._run("build-" + role, arguments, timeout=900,
                stdout_cap=self.contract.data["limits"]["stdout_bytes"],
                stderr_cap=self.contract.data["limits"]["stderr_bytes"])
            self._check()
            self.sources.verify()
            require(regular_pin(dockerfile, 64 << 10) == pins["derived"], "derived_recipe_changed")
            iid_pin, iid = _regular_below(self.root, iidfile.name, 128, keep=True)
            metadata_pin, metadata = _regular_below(self.root, metafile.name, 256 << 10, keep=True)
            identity = image_id(iid.decode("ascii").rstrip("\n"))
            inspected = self.engine._run("inspect-built-" + role,
                ["image", "inspect", "--format", IMAGE_FORMAT, identity])
            identity = build_result(iid, api_json(metadata), api_json(inspected.stdout(128 << 10)), labels)
            values[role] = {"id": identity, "labels": labels}
            reports[role] = {"image": values[role], "recipe": pins, "iid_file": iid_pin,
                "metadata_file": metadata_pin, "command": built.receipt,
                "additional_node_context": role == "executor"}
            self.engine.recorder.seal("image-build-" + role + ".json", canonical(reports[role]))
        # Resource closure precedes returning images, even after both builds.
        self.engine.close_builder()
        report = {"format": "owned-devnet-image-preparation/v1", "images": reports,
            "buildkit_distribution": reference, "buildkit_image_id": buildkit,
            "builder_closed_before_runtime": True, "shared_images_built": 2,
            "image_archive_written": False, "independently_reproduced_images": False,
            "manual_volume_or_image_removal_performed": False}
        self.engine.recorder.seal("image-preparation.json", canonical(report))
        return PreparedImages(self.engine, canonical(values))
