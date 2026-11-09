# SPDX-License-Identifier: GPL-3.0-only
"""Fresh, source-pinned checkouts for the explicitly authorized owned runner.

This prepares four public repositories. The TypeScript client and SDK remain
the root lockfile's Git dependencies; the console and Rust builds are omitted.
No service, package script, wallet, signing or deployment operation is performed.
"""

from __future__ import annotations

from dataclasses import dataclass
import base64
import hashlib
import json
import os
from pathlib import Path
import stat

from model import Refused, canonical, digest, HEX40, relative_name, require

ROLES = ("devnet", "node", "executor", "contract_sdk")
LAYOUT = {"devnet": "devnet", "node": "devnet/.sources/zenon-network/go-zenon",
          "executor": "devnet/.sources/zeno/zeno-executor",
          "contract_sdk": "devnet/.sources/zeno/zeno-contract-sdk-rs"}
TREE_OUTPUT_LIMIT = 2 << 20


@dataclass(frozen=True)
class TreeFile:
    name: str
    mode: str
    blob: str
    size: int


def parse_tree(raw, max_records, max_bytes):
    require(type(raw) is bytes and 0 < len(raw) <= TREE_OUTPUT_LIMIT and raw.endswith(b"\0"),
            "source_tree_encoding")
    require(type(max_records) is int and 0 < max_records <= 16384
            and type(max_bytes) is int and 0 < max_bytes <= 256 << 20, "source_tree_policy")
    records, names, total = [], set(), 0
    for item in raw[:-1].split(b"\0"):
        require(len(records) < max_records, "source_tree_record_bound")
        metadata, separator, encoded = item.partition(b"\t")
        fields = metadata.split()
        require(separator == b"\t" and len(fields) == 4 and fields[1] == b"blob"
                and fields[0] in (b"100644", b"100755"), "source_tree_file_type")
        try:
            name = relative_name(encoded.decode("ascii"))
            blob = digest(fields[2].decode("ascii"), HEX40)
            size_text = fields[3].decode("ascii")
        except UnicodeError as error:
            raise Refused("source_tree_encoding") from error
        require(size_text.isdecimal() and len(size_text) <= 10, "source_tree_file_size")
        size = int(size_text)
        require(str(size) == size_text, "source_tree_file_size")
        require(name.casefold() not in names and all(part != ".git" for part in name.split("/")),
                "source_tree_path_alias")
        names.add(name.casefold())
        total += size
        require(total <= max_bytes, "source_tree_byte_bound")
        records.append(TreeFile(name, fields[0].decode("ascii"), blob, size))
    return tuple(records)


def _directory_identity(path):
    info = Path(path).lstat()
    require(stat.S_ISDIR(info.st_mode) and (not hasattr(os, "geteuid")
            or info.st_uid == os.geteuid()), "source_directory_identity")
    return (info.st_dev, info.st_ino, info.st_uid)


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_size, info.st_mtime_ns)


def _executable_matches(mode, git_mode):
    require(git_mode in ("100644", "100755"), "source_executable_mode")
    # Git tracks the owner executable bit. A private umask can legitimately
    # remove group/other permissions from an executable checkout.
    return bool(mode & stat.S_IXUSR) if git_mode == "100755" else not (mode & 0o111)


def read_tracked(root, record, expected_identity=None):
    """Check a regular tracked file without following an intermediate link."""
    root = Path(root)
    directory_identity = _directory_identity(root)
    current = root
    for part in record.name.split("/")[:-1]:
        current = current / part
        require(_directory_identity(current)[0] == directory_identity[0], "source_mount_changed")
    path = root / relative_name(record.name)
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
            and before.st_dev == directory_identity[0] and before.st_uid == directory_identity[2]
            and before.st_size == record.size, "source_file_identity")
    if expected_identity is not None:
        require(_identity(before) == expected_identity, "source_file_replaced")
    if os.name == "posix":
        require(_executable_matches(before.st_mode, record.mode),
                "source_executable_mode")
    blob = hashlib.sha1(("blob " + str(record.size) + "\0").encode("ascii"))
    sha, size = hashlib.sha256(), 0
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "rb") as stream:
        opened = os.fstat(stream.fileno())
        require(os.path.samestat(before, opened), "source_file_replaced")
        for chunk in iter(lambda: stream.read(65536), b""):
            size += len(chunk)
            require(size <= record.size, "source_file_size")
            blob.update(chunk)
            sha.update(chunk)
        after = os.fstat(stream.fileno())
    final = path.lstat()
    require(stat.S_ISREG(final.st_mode) and final.st_nlink == 1
            and _identity(before) == _identity(after) == _identity(final)
            and size == record.size and blob.hexdigest() == record.blob
            and _directory_identity(root) == directory_identity, "source_file_content")
    if os.name == "posix":
        require(_executable_matches(final.st_mode, record.mode),
                "source_executable_mode")
    return {"sha256": sha.hexdigest(), "bytes": size}, _identity(final)


def selected_files(contract, role, records):
    by_name = {row.name: row for row in records}
    selected = [row for row in contract.data["source_files"] if row["role"] == role]
    require(bool(selected), "selected_source_files_missing")
    for row in selected:
        actual = by_name.get(row["path"])
        require(actual is not None and actual.blob == row["git_blob"]
                and actual.size == row["bytes"], "selected_source_tree_binding")
    return selected


def lockfile_binding(contract, raw):
    # The file's selected SHA-256 is checked by the source reader. These extra
    # checks make the two Git dependency identities explicit before npm runs.
    require(type(raw) is bytes and 0 < len(raw) <= 256 << 10, "npm_lockfile_bound")
    try:
        def pairs(rows):
            result = {}
            for key, value in rows:
                require(key not in result, "npm_lockfile_duplicate_field")
                result[key] = value
            return result
        value = json.loads(raw, object_pairs_hook=pairs)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise Refused("npm_lockfile_encoding") from error
    require(type(value) is dict and type(value.get("packages")) is dict, "npm_lockfile_schema")
    packages = value["packages"]
    require(type(packages.get("")) is dict and type(packages[""].get("dependencies")) is dict,
            "npm_lockfile_root")
    rows = []
    for role, name in (("typescript_client", "zeno-client"),
                       ("typescript_sdk", "znn-typescript-sdk")):
        selected = contract.data["sources"][role]
        repo, revision = selected["repository"], selected["revision"]
        package = packages.get("node_modules/" + name)
        require(type(package) is dict
                and packages[""]["dependencies"].get(name) == "github:" + repo + "#" + revision
                and package.get("resolved") == "git+ssh://git@github.com/" + repo + ".git#" + revision
                and type(package.get("integrity")) is str and package["integrity"].startswith("sha512-"),
                "npm_dependency_source_binding")
        encoded = package["integrity"][7:]
        try:
            decoded = base64.b64decode(encoded, validate=True)
        except ValueError as error:
            raise Refused("npm_dependency_integrity_encoding") from error
        require(len(decoded) == 64 and base64.b64encode(decoded).decode("ascii") == encoded,
                "npm_dependency_integrity_encoding")
        rows.append({"package": name, "repository": repo, "revision": revision,
                     "integrity": package["integrity"], "second_explicit_checkout": False})
    return rows


def git_environment(base, empty_config):
    require(type(base) is dict and type(base.get("PATH")) is str and bool(base["PATH"]),
            "source_command_environment")
    # No HOME override, inherited credentials, SSH agent, Git options, loaders,
    # proxy, Node options or trace/debug variables are passed to source commands.
    environment = {key: base[key] for key in ("PATH", "LANG", "LC_ALL", "TMPDIR",
                   "SYSTEMROOT", "WINDIR") if key in base and type(base[key]) is str}
    environment.update({"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_SYSTEM": os.devnull,
                        "GIT_CONFIG_GLOBAL": str(empty_config), "GIT_TERMINAL_PROMPT": "0",
                        "GIT_ALLOW_PROTOCOL": "https", "PYTHONDONTWRITEBYTECODE": "1",
                        "NO_COLOR": "1", "TERM": "dumb"})
    return environment


@dataclass(frozen=True)
class Checkout:
    role: str
    path: Path
    directory_identity: tuple
    repository: str
    revision: str
    tree: str
    records: tuple
    identities: tuple
    selected_raw: bytes

    def verify(self):
        require(_directory_identity(self.path) == self.directory_identity, "source_checkout_replaced")
        require(len(self.records) == len(self.identities), "source_snapshot_identity_count")
        selected = {row["path"]: row for row in json.loads(self.selected_raw)}
        for record, identity in zip(self.records, self.identities):
            actual, _ = read_tracked(self.path, record, identity)
            if record.name in selected:
                expected = selected[record.name]
                require(actual == {k: expected[k] for k in ("sha256", "bytes")},
                        "selected_source_content_binding")
        return {"role": self.role, "repository": self.repository, "revision": self.revision,
                "tree": self.tree, "tracked_files": len(self.records),
                "tracked_bytes": sum(row.size for row in self.records),
                "selected_files": list(selected.values())}


@dataclass(frozen=True)
class PreparedSources:
    checkouts: tuple

    @property
    def paths(self):
        return {row.role: row.path for row in self.checkouts}

    @property
    def source_root(self):
        # This is the variable used by the pinned src/devnet.ts, flows and
        # Compose include. There is no home-cache or sibling-repository fallback.
        return self.paths["devnet"] / ".sources"

    def verify(self):
        require({row.role for row in self.checkouts} == set(ROLES)
                and len(self.checkouts) == len(ROLES), "source_checkout_closure")
        return [row.verify() for row in self.checkouts]


class Preparer:
    """Only fresh destinations. Failed or interrupted preparations are terminal."""

    def __init__(self, contract, recorder, directory, git_command, base_environment, guard):
        require(os.name == "posix", "source_preparation_platform")
        require(type(git_command) is list and git_command
                and all(type(a) is str for a in git_command) and callable(guard), "source_command")
        self.contract, self.recorder = contract, recorder
        self.root = Path(directory)
        require(not self.root.exists() and not self.root.is_symlink(), "source_root_exists")
        self.root.mkdir(mode=0o700)
        self.identity = _directory_identity(self.root)
        self.template = self.root / "empty-git-template"
        self.template.mkdir(mode=0o700)
        configuration = self.root / "empty-git-config"
        with configuration.open("xb"):
            pass
        configuration.chmod(0o400)
        self.environment = git_environment(base_environment, configuration)
        temporary = self.root / "git-tmp"
        temporary.mkdir(mode=0o700)
        self.environment["TMPDIR"] = str(temporary)
        self.git_command, self.guard = list(git_command), guard
        self.started = False

    def run(self, role, label, path, *arguments, cap=2 << 20, timeout=180):
        require(_directory_identity(self.root) == self.identity, "source_root_changed")
        self.recorder.check()
        command = [*self.git_command, "-c", "core.autocrlf=false", "-c", "core.eol=lf",
                   "-c", "core.symlinks=false", "-c", "protocol.file.allow=never",
                   "-c", "protocol.ext.allow=never", "-c", "core.hooksPath=" + str(self.template),
                   "-C", str(path), *arguments]
        return self.recorder.run("source-" + role.replace("_", "-") + "-" + label,
                                 command, self.root, self.environment,
                                 stdout_cap=cap, stderr_cap=2 << 20,
                                 timeout=timeout, guard=self.guard)

    def prepare(self):
        require(not self.started, "source_preparation_already_attempted")
        self.started = True
        self.guard()
        total_bytes = total_records = 0
        checkouts = []
        policy = self.contract.data["limits"]
        for role in ROLES:
            path = self.root / LAYOUT[role]
            # Ancestors are the new root or earlier owned checkouts only.
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            ancestor = path.parent
            while ancestor != self.root:
                require(_directory_identity(ancestor)[0] == self.identity[0], "source_mount_changed")
                ancestor = ancestor.parent
            require(not path.exists() and not path.is_symlink(), "source_checkout_exists")
            path.mkdir(mode=0o700)
            selected = self.contract.data["sources"][role]
            revision = selected["revision"]
            self.run(role, "init", path, "init", "--template=" + str(self.template))
            self.run(role, "fetch", path, "fetch", "--depth=1", "--no-tags", "--no-recurse-submodules",
                     "https://github.com/" + selected["repository"] + ".git", revision)
            head = self.run(role, "fetched-head", path, "rev-parse", "--verify", "FETCH_HEAD", cap=128)
            require(head.stdout(128) == (revision + "\n").encode("ascii"), "source_fetched_revision")
            listing = self.run(role, "tree", path, "ls-tree", "-r", "-l", "-z", "FETCH_HEAD",
                               cap=TREE_OUTPUT_LIMIT)
            records = parse_tree(listing.stdout(TREE_OUTPUT_LIMIT), policy["max_source_tree_records"],
                                 policy["max_source_worktree_bytes"])
            selected_rows = selected_files(self.contract, role, records)
            total_records += len(records)
            total_bytes += sum(row.size for row in records)
            require(total_records <= policy["max_source_tree_records"]
                    and total_bytes <= policy["max_source_worktree_bytes"], "source_cohort_budget")
            self.run(role, "checkout", path, "checkout", "--detach", "--no-recurse-submodules", "FETCH_HEAD")
            actual_head = self.run(role, "head", path, "rev-parse", "--verify", "HEAD", cap=128)
            require(actual_head.stdout(128) == (revision + "\n").encode("ascii"), "source_checkout_revision")
            status = self.run(role, "status", path, "status", "--porcelain=v1", "-z", "--untracked-files=all")
            require(status.stdout() == b"", "source_checkout_dirty")
            tree = self.run(role, "tree-id", path, "rev-parse", "HEAD^{tree}", cap=128).stdout(128)
            require(len(tree) == 41 and tree.endswith(b"\n"), "source_tree_identity")
            tree_digest = digest(tree[:-1].decode("ascii"), HEX40)
            identities = tuple(read_tracked(path, record)[1] for record in records)
            checkout = Checkout(role, path, _directory_identity(path), selected["repository"], revision,
                                tree_digest, records, identities, canonical(selected_rows))
            checkout.verify()
            checkouts.append(checkout)
        result = PreparedSources(tuple(checkouts))
        source_report = result.verify()
        lockfile = result.paths["devnet"] / "package-lock.json"
        dependencies = lockfile_binding(self.contract, lockfile.read_bytes())
        self.recorder.seal("selected-sources.json", canonical({
            "format": "owned-devnet-source-preparation/v1", "sources": source_report,
            "source_root_variable": "ZENO_DEVNET_SRC", "locked_git_dependencies": dependencies,
            "tracked_bytes": total_bytes, "tracked_files": total_records,
            "console_or_Rust_build_performed": False, "package_scripts_executed": False,
            "service_or_signing_executed": False}))
        return result
