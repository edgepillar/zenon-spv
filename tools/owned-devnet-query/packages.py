# SPDX-License-Identifier: GPL-3.0-only
"""Owned npm preparation for the pinned devnet; never an implicit global install."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import stat

from model import Refused, canonical, relative_name, require
from sources import PreparedSources, git_environment, lockfile_binding
from node_toolchain import Installation

ENTRYPOINTS = {"zeno-client": "dist/index.js", "znn-typescript-sdk": "dist/index.js",
               "tsx": "dist/cli.mjs"}


def npm_environment(base, node_root, cache_root):
    node_root, cache_root = Path(node_root), Path(cache_root)
    environment = git_environment(base, cache_root / "git-config")
    environment.update({
        "PATH": str(node_root / "bin") + os.pathsep + environment["PATH"],
        "GIT_CONFIG_COUNT": "2",
        "GIT_CONFIG_KEY_0": "url.https://github.com/.insteadOf",
        "GIT_CONFIG_VALUE_0": "ssh://git@github.com/",
        "GIT_CONFIG_KEY_1": "url.https://github.com/.insteadOf",
        "GIT_CONFIG_VALUE_1": "git@github.com:",
        "npm_config_cache": str(cache_root / "npm-cache"),
        "npm_config_userconfig": str(cache_root / "npm-userconfig"),
        "npm_config_globalconfig": str(cache_root / "npm-globalconfig"),
        "npm_config_prefix": str(node_root), "npm_config_nodedir": str(node_root),
        "npm_config_registry": "https://registry.npmjs.org/", "npm_config_strict_ssl": "true",
        "npm_config_engine_strict": "true", "npm_config_ignore_scripts": "false",
        "npm_config_audit": "false", "npm_config_fund": "false",
        "npm_config_progress": "false", "npm_config_update_notifier": "false",
        "npm_config_fetch_retries": "0", "npm_config_fetch_timeout": "60000",
        "npm_config_maxsockets": "2",
        "TMPDIR": str(cache_root / "tmp"), "TMP": str(cache_root / "tmp"),
        "TEMP": str(cache_root / "tmp"), "XDG_CACHE_HOME": str(cache_root / "xdg-cache"),
        "npm_config_devdir": str(cache_root / "node-gyp"),
        "npm_config_logs_dir": str(cache_root / "npm-logs"),
    })
    return environment


def _regular_below(root, relative, bound, keep=False):
    relative_name(relative)
    root, current = Path(root), Path(root)
    root_info = root.lstat()
    require(stat.S_ISDIR(root_info.st_mode), "installed_package_root")
    parts = relative.split("/")
    require(all(part not in ("", ".", "..") for part in parts), "installed_package_path")
    for part in parts[:-1]:
        current /= part
        info = current.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_dev == root_info.st_dev
                and info.st_uid == root_info.st_uid, "installed_package_directory")
    path = root / relative
    before = path.lstat()
    identity = lambda info: (info.st_dev, info.st_ino, info.st_uid, info.st_size, info.st_mtime_ns)
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
            and before.st_dev == root_info.st_dev and before.st_uid == root_info.st_uid
            and before.st_size <= bound, "installed_package_file")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    sha, count, body = hashlib.sha256(), 0, bytearray()
    with os.fdopen(descriptor, "rb") as stream:
        require(os.path.samestat(before, os.fstat(descriptor)), "installed_package_replaced")
        for chunk in iter(lambda: stream.read(65536), b""):
            count += len(chunk)
            require(count <= bound, "installed_package_bound")
            sha.update(chunk)
            if keep:
                body.extend(chunk)
        after = os.fstat(descriptor)
    final = path.lstat()
    require(stat.S_ISREG(final.st_mode) and final.st_nlink == 1
            and identity(before) == identity(after) == identity(final) and count == before.st_size,
            "installed_package_changed")
    return {"sha256": sha.hexdigest(), "bytes": count}, bytes(body) if keep else None


def installed_entries(contract, root):
    root = Path(root)
    lock_pin, lock_raw = _regular_below(root, "package-lock.json", 256 << 10, keep=True)
    declared = json.loads(lock_raw)
    dependencies = lockfile_binding(contract, lock_raw)
    installed_lock = "node_modules/.package-lock.json"
    installed_lock_pin, installed_raw = _regular_below(root, installed_lock, 512 << 10, keep=True)
    installed = json.loads(installed_raw)
    require(type(installed) is dict and type(installed.get("packages")) is dict,
            "installed_lockfile_schema")
    for dependency in dependencies:
        repo, revision = dependency["repository"], dependency["revision"]
        row = installed["packages"].get("node_modules/" + dependency["package"])
        acceptable = {"git+ssh://git@github.com/" + repo + ".git#" + revision,
                      "git+https://github.com/" + repo + ".git#" + revision}
        require(type(row) is dict and row.get("resolved") in acceptable,
                "installed_git_dependency_binding")
        if "integrity" in row:
            require(row["integrity"] == dependency["integrity"], "installed_dependency_integrity")
    expected_versions = {"zeno-client": "0.1.0", "znn-typescript-sdk": "1.0.5",
                         "tsx": declared["packages"]["node_modules/tsx"]["version"]}
    rows = []
    for name, entry in ENTRYPOINTS.items():
        prefix = "node_modules/" + name + "/"
        package_pin, package_raw = _regular_below(root, prefix + "package.json", 64 << 10, keep=True)
        package = json.loads(package_raw)
        require(type(package) is dict and package.get("name") == name
                and package.get("version") == expected_versions[name], "installed_package_version")
        entry_pin, _ = _regular_below(root, prefix + entry, 16 << 20)
        rows.append({"package": name, "version": expected_versions[name],
                     "package_json": package_pin, "entrypoint": entry, "entrypoint_pin": entry_pin})
    return {"root_lockfile": lock_pin, "installed_lockfile": installed_lock_pin,
            "locked_git_dependencies": dependencies, "entrypoints": rows,
            "whole_installed_tree_independently_reproduced": False}


@dataclass(frozen=True)
class PreparedPackages:
    source_root: Path
    environment_raw: bytes
    report_raw: bytes

    @property
    def environment(self):
        return json.loads(self.environment_raw)

    @property
    def report(self):
        return json.loads(self.report_raw)


class Preparer:
    def __init__(self, contract, recorder, sources, node, directory, base_environment, guard):
        require(type(sources) is PreparedSources and type(node) is Installation,
                "package_preparation_inputs")
        require(callable(guard), "package_preparation_guard")
        self.contract, self.recorder, self.sources, self.node = contract, recorder, sources, node
        self.root = Path(directory)
        require(not self.root.exists() and not self.root.is_symlink(), "package_cache_exists")
        self.root.mkdir(mode=0o700)
        self.identity = self.root.stat().st_dev, self.root.stat().st_ino, self.root.stat().st_uid
        for name in ("npm-cache", "tmp", "xdg-cache", "node-gyp", "npm-logs"):
            (self.root / name).mkdir(mode=0o700)
        for name in ("npm-userconfig", "npm-globalconfig", "git-config"):
            with (self.root / name).open("xb"):
                pass
            (self.root / name).chmod(0o400)
        self.environment = npm_environment(base_environment, node.root, self.root)
        self.guard, self.started = guard, False

    def prepare(self):
        require(not self.started, "package_preparation_already_attempted")
        self.started = True
        self.guard()
        require(self.node.execution_enabled is True, "package_toolchain_not_enabled")
        self.node.verify()
        self.sources.verify()
        root = self.sources.paths["devnet"]
        dependencies = lockfile_binding(self.contract, (root / "package-lock.json").read_bytes())
        limits = self.contract.data["limits"]

        def run(name, arguments, timeout=60):
            info = self.root.lstat()
            require(stat.S_ISDIR(info.st_mode) and (info.st_dev, info.st_ino, info.st_uid)
                    == self.identity, "package_cache_changed")
            return self.recorder.run(name, [str(self.node.node), *arguments], root,
                self.environment, stdout_cap=limits["stdout_bytes"],
                stderr_cap=limits["stderr_bytes"], timeout=timeout, guard=self.guard)

        node_version = run("package-node-version", ["--version"])
        npm_version = run("package-npm-version", [str(self.node.npm), "--version"])
        require(node_version.stdout(128) == b"v22.23.0\n" and npm_version.stdout(128) == b"10.9.8\n",
                "package_native_toolchain_version")
        installation = run("package-npm-ci", [str(self.node.npm), "ci", "--no-audit",
                           "--no-fund", "--loglevel=warn"], timeout=600)
        # Upstream SDK preparation is required. Do not suppress scripts or patch
        # the input lockfile merely to obtain a successful-looking install.
        self.sources.verify()
        self.node.verify()
        entries = installed_entries(self.contract, root)
        report = {"format": "owned-devnet-package-preparation/v1", "node_version": "22.23.0",
                  "npm_version": "10.9.8", "npm_ci_actual_exit": installation.receipt["actual_exit"],
                  "npm_ci_output_complete": installation.receipt["output_complete"],
                  "declared_git_dependencies": dependencies, "installed_entries": entries,
                  "user_global_configuration_changed": False, "source_lockfile_changed": False,
                  "source_root_variable": "ZENO_DEVNET_SRC", "package_scripts_executed": True,
                  "service_or_signing_or_devnet_query_executed": False}
        self.recorder.seal("package-preparation.json", canonical(report))
        environment = dict(self.environment)
        environment["ZENO_DEVNET_SRC"] = str(self.sources.source_root)
        return PreparedPackages(root, canonical(environment), canonical(report))
