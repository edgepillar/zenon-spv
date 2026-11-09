# SPDX-License-Identifier: GPL-3.0-only
"""Pinned official Node/npm intake with no symlink or hard-link materialization.

The complete original compressed input remains the transport output. A decoded
TAR is never written. Inspection can verify the same selection without creating
any extracted file. No package script or binary is executed by the codec.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
import json
import lzma
import os
from pathlib import Path
import re
import stat
import tarfile

from inputs import _XZ, _Slice, _exact, _elf64, _hash_stream
from model import Refused, canonical, exact_keys, pin, require, uint
from process import owned_lease

MAX_HEADERS = 16384
MAX_DECODED = 256 << 20
EXPECTED_LINKS = {
    "bin/npm": "../lib/node_modules/npm/bin/npm-cli.js",
    "bin/npx": "../lib/node_modules/npm/bin/npx-cli.js",
    "bin/corepack": "../lib/node_modules/corepack/dist/corepack.js",
}
WRAPPERS = {
    name: ("#!/bin/sh\nTASK_NODE_BIN=${0%/*}\n"
           "case \"$TASK_NODE_BIN\" in /*) ;; *) exit 64 ;; esac\n"
           "exec \"$TASK_NODE_BIN/node\" \"$TASK_NODE_BIN/../lib/node_modules/npm/bin/"
           + name + "-cli.js\" \"$@\"\n").encode("ascii") for name in ("npm", "npx")
}


def _relative(value):
    require(type(value) is str and 0 < len(value) <= 512 and value.isascii()
            and not value.startswith("/") and all(part not in ("", ".", "..")
                and re.fullmatch(r"[A-Za-z0-9_.@+-]+", part) is not None
                for part in value.split("/")), "node_member_path")
    return value


def specification(value):
    exact_keys(value, {"version", "filename", "sha256", "archive_url", "max_archive_bytes",
        "max_selected_regular_bytes", "archive_bytes", "decoded_tar", "selected_manifest",
        "selected_regular_count", "selected_regular_bytes", "node_binary", "npm_version"},
        "node_toolchain_fields")
    require(value["version"] == "22.23.0" and value["filename"] == "node-v22.23.0-linux-x64.tar.xz"
            and value["archive_url"] == "https://nodejs.org/dist/v22.23.0/" + value["filename"],
            "node_toolchain_selection")
    pin({"sha256": value["sha256"], "bytes": value["archive_bytes"]}, 64 << 20)
    require(type(value["max_archive_bytes"]) is int and value["max_archive_bytes"] == 64 << 20
            and type(value["max_selected_regular_bytes"]) is int
            and value["max_selected_regular_bytes"] == 256 << 20, "node_toolchain_limits")
    pin(value["decoded_tar"], MAX_DECODED)
    pin(value["selected_manifest"], 2 << 20)
    pin(value["node_binary"], value["max_selected_regular_bytes"])
    uint(value["selected_regular_count"], MAX_HEADERS)
    uint(value["selected_regular_bytes"], value["max_selected_regular_bytes"])
    require(type(value["npm_version"]) is str and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+",
            value["npm_version"]) is not None, "node_npm_version")
    return json.loads(canonical(value))


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_size, info.st_mtime_ns)


def _dir_identity(path):
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and (not hasattr(os, "geteuid")
            or info.st_uid == os.geteuid()), "node_directory_identity")
    return info.st_dev, info.st_ino, info.st_uid


@dataclass(frozen=True)
class NodeFile:
    path: str
    sha256: str
    size: int
    executable: bool
    identity: tuple


@dataclass(frozen=True)
class Installation:
    root: Path
    directories: tuple
    files: tuple
    inspection_raw: bytes
    execution_enabled: bool = False

    @property
    def inspection(self):
        return json.loads(self.inspection_raw)

    @property
    def node(self):
        return self.root / "bin/node"

    @property
    def npm(self):
        return self.root / "lib/node_modules/npm/bin/npm-cli.js"

    def verify(self):
        expected_dirs = dict(self.directories)
        require("" in expected_dirs and _dir_identity(self.root) == expected_dirs[""],
                "node_root_changed")
        actual_files, actual_dirs = set(), {""}
        for parent, children, names in os.walk(self.root, followlinks=False):
            for name in children:
                path = Path(parent) / name
                relative = path.relative_to(self.root).as_posix()
                require(relative in expected_dirs and _dir_identity(path) == expected_dirs[relative],
                        "node_directory_changed")
                actual_dirs.add(relative)
            actual_files.update((Path(parent) / name).relative_to(self.root).as_posix() for name in names)
        require(actual_dirs == set(expected_dirs) and actual_files == {row.path for row in self.files},
                "node_installation_members")
        for row in self.files:
            path = self.root / row.path
            before = path.lstat()
            require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                    and _identity(before) == row.identity, "node_file_changed")
            if os.name == "posix":
                wanted = 0o500 if self.execution_enabled and row.executable else 0o400
                require(stat.S_IMODE(before.st_mode) == wanted, "node_file_permissions")
            sha, count = hashlib.sha256(), 0
            descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            with os.fdopen(descriptor, "rb") as stream:
                require(os.path.samestat(before, os.fstat(descriptor)), "node_file_changed")
                for chunk in iter(lambda: stream.read(65536), b""):
                    count += len(chunk)
                    require(count <= row.size, "node_file_changed")
                    sha.update(chunk)
                after = os.fstat(descriptor)
            final = path.lstat()
            require(stat.S_ISREG(final.st_mode) and final.st_nlink == 1
                    and _identity(before) == _identity(after) == _identity(final)
                    and count == row.size and sha.hexdigest() == row.sha256, "node_file_changed")
        return self.inspection

    def enable_execution(self):
        require(os.name == "posix", "node_execution_platform")
        self.verify()
        if self.execution_enabled:
            return self
        for row in self.files:
            if row.executable:
                (self.root / row.path).chmod(0o500)
        result = replace(self, execution_enabled=True)
        result.verify()
        return result


class _Sink:
    def __init__(self, destination):
        self.root = Path(destination)
        require(not self.root.exists() and not self.root.is_symlink(), "node_destination_exists")
        self.root.mkdir(mode=0o700)
        self.directories = {"": _dir_identity(self.root)}
        self.files = []

    def open(self, name):
        require(_dir_identity(self.root) == self.directories[""], "node_root_changed")
        path = self.root / _relative(name)
        parent = self.root
        for part in name.split("/")[:-1]:
            parent /= part
            relative = parent.relative_to(self.root).as_posix()
            if relative not in self.directories:
                parent.mkdir(mode=0o700)
                self.directories[relative] = _dir_identity(parent)
            require(_dir_identity(parent) == self.directories[relative], "node_directory_changed")
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                             | getattr(os, "O_NOFOLLOW", 0), 0o600)
        return os.fdopen(descriptor, "wb", buffering=65536)

    def finish_file(self, row):
        path = self.root / row["path"]
        path.chmod(0o400)
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size == row["bytes"],
                "node_materialized_file")
        self.files.append(NodeFile(row["path"], row["sha256"], row["bytes"],
                                   row["executable"], _identity(info)))

    def finish(self, report):
        for name, raw in WRAPPERS.items():
            relative = "bin/" + name
            with self.open(relative) as stream:
                require(stream.write(raw) == len(raw), "node_wrapper_write")
            self.finish_file({"path": relative, "sha256": hashlib.sha256(raw).hexdigest(),
                              "bytes": len(raw), "executable": True})
        result = Installation(self.root, tuple(self.directories.items()), tuple(self.files), canonical(report))
        result.verify()
        return result


def _member(stream, size, name, executable, sink):
    selected = name == "bin/node" or name.startswith(("lib/node_modules/npm/", "include/node/"))
    reader = _Slice(stream, size)
    sha, count, prefix, package = hashlib.sha256(), 0, bytearray(), bytearray()
    target = sink.open(name) if selected and sink is not None else None
    try:
        for chunk in iter(lambda: reader.read(65536), b""):
            count += len(chunk)
            if selected:
                sha.update(chunk)
                if name == "bin/node":
                    prefix.extend(chunk[:max(0, 64 - len(prefix))])
                if name == "lib/node_modules/npm/package.json":
                    require(size <= 64 << 10, "node_npm_package_bound")
                    package.extend(chunk)
                if target is not None:
                    require(target.write(chunk) == len(chunk), "node_file_write")
    finally:
        if target is not None:
            target.close()
    require(count == size, "node_member_size")
    row = {"path": name, "sha256": sha.hexdigest(), "bytes": count, "executable": executable}
    if selected and sink is not None:
        sink.finish_file(row)
    if name == "bin/node":
        _elf64(prefix)
    return row if selected else None, bytes(package)


def unpack_node(stream, selected, destination=None):
    """Check the pinned format, optionally writing a fresh regular-file prefix.

    Original content identity and inspection do not establish native execution,
    an authenticated distribution or permission to run the selected scripts.
    """
    selected = specification(selected)
    archive = {"sha256": selected["sha256"], "bytes": selected["archive_bytes"]}
    _hash_stream(stream, archive)
    decoded = _XZ(stream, archive, selected["decoded_tar"])
    sink = _Sink(destination) if destination is not None else None
    prefix = "node-v22.23.0-linux-x64"
    pending = None
    names, files, links = set(), [], []
    selected_bytes = regular_bytes = headers = 0
    npm = None
    try:
        while True:
            header = _exact(decoded, 512)
            if header == bytes(512):
                require(pending is None and _exact(decoded, 512) == bytes(512), "node_tar_end")
                break
            headers += 1
            require(headers <= MAX_HEADERS, "node_tar_header_bound")
            member = tarfile.TarInfo.frombuf(header, "ascii", "strict")
            require(0 <= member.size <= MAX_DECODED, "node_member_size")
            if member.type == tarfile.GNUTYPE_LONGNAME:
                require(pending is None and 1 < member.size <= 1024
                        and member.name in ("././@LongLink", "@LongLink"), "node_long_name")
                raw = _exact(decoded, member.size)
                require(raw.endswith(b"\0") and b"\0" not in raw[:-1], "node_long_name")
                pending = raw[:-1].decode("ascii")
                require(not any(_exact(decoded, (-member.size) % 512)), "node_tar_padding")
                continue
            name = pending if pending is not None else member.name
            pending = None
            directory = member.type == tarfile.DIRTYPE
            # TarInfo normalizes trailing directory slashes. Inspect the raw
            # name field as well, before that spelling can disappear.
            require(not directory or not header[:100].partition(b"\0")[0].endswith(b"//"),
                    "node_member_path")
            require(not directory or not name.endswith("//"), "node_member_path")
            name = name.rstrip("/") if directory else name
            _relative(name)
            require(name == prefix or name.startswith(prefix + "/"), "node_archive_prefix")
            relative = name[len(prefix):].lstrip("/")
            require(name.casefold() not in names, "node_member_alias")
            names.add(name.casefold())
            if directory:
                require(member.size == 0 and not member.linkname, "node_directory_payload")
                continue
            require(bool(relative), "node_member_path")
            if member.type == tarfile.SYMTYPE:
                require(member.size == 0 and relative in EXPECTED_LINKS
                        and member.linkname == EXPECTED_LINKS[relative], "node_link_selection")
                links.append({"path": relative, "target": member.linkname, "kind": "2"})
                continue
            require(member.type in (tarfile.REGTYPE, tarfile.AREGTYPE) and not member.linkname,
                    "node_member_type")
            is_selected = relative == "bin/node" or relative.startswith(
                ("lib/node_modules/npm/", "include/node/"))
            if is_selected:
                require(len(files) < selected["selected_regular_count"]
                        and selected_bytes + member.size <= selected["selected_regular_bytes"],
                        "node_selection_bound")
            regular_bytes += member.size
            require(regular_bytes <= MAX_DECODED, "node_regular_byte_bound")
            row, package = _member(decoded, member.size, relative, bool(member.mode & 0o100), sink)
            require(not any(_exact(decoded, (-member.size) % 512)), "node_tar_padding")
            if row is not None:
                files.append(row)
                selected_bytes += member.size
                require(len(files) <= selected["selected_regular_count"]
                        and selected_bytes <= selected["max_selected_regular_bytes"],
                        "node_selection_bound")
                if relative == "bin/node":
                    require({k: row[k] for k in ("sha256", "bytes")} == selected["node_binary"],
                            "node_binary_binding")
            if package:
                npm = json.loads(package)
        decoded.finish()
        require({"bin/node", "lib/node_modules/npm/package.json",
                 "lib/node_modules/npm/bin/npm-cli.js", "lib/node_modules/npm/bin/npx-cli.js",
                 "include/node/node_api.h"} <= {row["path"] for row in files}, "node_required_files")
        require(len(files) == selected["selected_regular_count"]
                and selected_bytes == selected["selected_regular_bytes"], "node_selection_closure")
        require({row["path"]: row["target"] for row in links} == EXPECTED_LINKS
                and len(links) == len(EXPECTED_LINKS), "node_link_closure")
        require(type(npm) is dict and npm.get("name") == "npm"
                and npm.get("version") == selected["npm_version"]
                and npm.get("bin") == {"npm": "bin/npm-cli.js", "npx": "bin/npx-cli.js"},
                "node_npm_binding")
        manifest = canonical({"format": "owned-devnet-node-selected-manifest/v1",
                              "files": sorted(files, key=lambda row: row["path"]),
                              "skipped_links": sorted(links, key=lambda row: row["path"])})
        manifest_pin = {"sha256": hashlib.sha256(manifest).hexdigest(), "bytes": len(manifest)}
        require(manifest_pin == selected["selected_manifest"], "node_manifest_binding")
        report = {"format": "owned-devnet-node-intake/v1", "archive": archive,
                  "decoded_tar": selected["decoded_tar"], "selected_manifest": manifest_pin,
                  "selected_regular_count": len(files), "selected_regular_bytes": selected_bytes,
                  "skipped_links": links, "npm_version": selected["npm_version"],
                  "node_version": selected["version"], "binary_or_package_executed": False,
                  "symlink_or_hardlink_created": False, "decoded_tar_written": False,
                  "generated_wrappers": {name: {"sha256": hashlib.sha256(raw).hexdigest(),
                                                "bytes": len(raw)} for name, raw in WRAPPERS.items()},
                  "files_extracted": 0 if sink is None else len(files) + len(WRAPPERS),
                  "authenticated_distribution": False}
        return report if sink is None else sink.finish(report)
    except Refused:
        raise
    except (lzma.LZMAError, tarfile.TarError, UnicodeError, ValueError, EOFError) as error:
        raise Refused("node_archive_encoding") from error


class Installer:
    """One causal, bounded original download; a failed workspace is not retried."""

    def __init__(self, contract, recorder, destination, command, environment, guard):
        self.selected = specification(contract.data["node_toolchain"])
        self.recorder, self.destination = recorder, Path(destination)
        require(not self.destination.exists() and not self.destination.is_symlink(),
                "node_destination_exists")
        require(type(command) is list and command and callable(guard), "node_download_command")
        self.command, self.environment, self.guard = list(command), dict(environment), guard
        self.attempted, self.result = False, None

    def fetch(self):
        if self.result is not None:
            self.result.verify()
            return self.result
        require(not self.attempted, "node_input_attempt_already_consumed")
        self.attempted = True
        with owned_lease(self.recorder, "node-toolchain.lease"):
            self.guard()
            selected = self.selected
            raw = self.recorder.run("node-toolchain-download", [*self.command, "--fail", "--silent",
                "--show-error", "--proto", "=https", "--proto-redir", "=https", "--tlsv1.2",
                "--location", "--connect-timeout", "15", "--max-time", "180", "--max-filesize",
                str(selected["archive_bytes"]), selected["archive_url"]], self.recorder.directory,
                self.environment, stdout_cap=selected["archive_bytes"], stderr_cap=128 << 10,
                timeout=210, stdout_name=selected["filename"], guard=self.guard)
            receipt = raw.receipt
            require(type(receipt["actual_exit"]) is int and receipt["actual_exit"] == 0
                    and receipt["output_complete"] is True
                    and {k: receipt["outputs"]["stdout"][k] for k in ("sha256", "bytes")}
                    == {"sha256": selected["sha256"], "bytes": selected["archive_bytes"]},
                    "node_transport_content")
            with raw.open_stdout_for_validation(selected["archive_bytes"]) as stream:
                result = unpack_node(stream, selected, self.destination)
            self.recorder.seal("node-toolchain-intake.json", canonical(result.inspection))
        self.result = result
        return result
