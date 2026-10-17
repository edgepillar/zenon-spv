#!/usr/bin/env python3
"""Check CI's exported files against its checkout before uploading them."""

import contextlib
import hashlib
import importlib.util
import json
import os
import stat
import struct
import subprocess
import sys
import zipfile
from pathlib import Path
from types import SimpleNamespace

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("candidate_archive", Path(__file__).with_name("check-candidate-archive.py"))
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)

SOURCE_LIMIT = 64 << 20
SOURCE_ENTRIES = 32768


@contextlib.contextmanager
def regular_file(path, limit, category):
    selected = path.lstat()
    checker.require(stat.S_ISREG(selected.st_mode) and 0 <= selected.st_size <= limit, category)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        checker.require(stat.S_ISREG(opened.st_mode) and opened.st_size == selected.st_size
                        and os.path.samestat(selected, opened), category)
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = None
            yield stream, opened.st_size
    finally:
        if descriptor is not None:
            os.close(descriptor)


def chunks(stream, size, category):
    total = 0
    while True:
        raw = stream.read(min(1 << 20, size - total + 1))
        if not raw:
            break
        total += len(raw)
        checker.require(total <= size, category)
        yield raw
    checker.require(total == size, category)


def input_fingerprint(root):
    # Independently reproduce offline-pilot's Go/module/JSON byte encoding.
    with regular_file(root / "go.mod", SOURCE_LIMIT, "source") as (stream, size):
        module = b"".join(chunks(stream, size, "source"))
    line = module.split(b"\n", 1)[0]
    line = line[:-1] if line.endswith(b"\r") else line
    checker.require(line == b"module github.com/0x3639/zenon-spv", "source")
    paths = ["go.mod", "go.sum"]
    pending = [(root / name, 1) for name in ("cmd", "internal", "tools")]
    entries = 0
    while pending:
        directory, depth = pending.pop()
        checker.require(depth <= 32 and directory.is_dir() and not directory.is_symlink(), "source")
        with os.scandir(directory) as children:
            for child in children:
                entries += 1
                checker.require(entries <= SOURCE_ENTRIES and not child.is_symlink(), "source")
                path = Path(child.path)
                if child.is_dir(follow_symlinks=False):
                    pending.append((path, depth + 1))
                elif child.name.endswith((".go", ".json")) or child.name in ("go.mod", "go.sum"):
                    paths.append(path.relative_to(root).as_posix())
    result, total = hashlib.sha256(), 0
    for name in sorted(paths):
        encoded = name.encode("utf-8")
        with regular_file(root / name, SOURCE_LIMIT, "source") as (stream, size):
            total += size
            checker.require(total <= SOURCE_LIMIT, "source")
            result.update(struct.pack(">Q", len(encoded)) + encoded + struct.pack(">Q", size))
            for raw in chunks(stream, size, "source"):
                result.update(raw)
    return result.hexdigest()


def source_pin(root, revision):
    env = {key: value for key, value in os.environ.items() if not key.upper().startswith("GIT_")}

    def git(*args):
        return subprocess.run(["git", *args], cwd=root, env=env, stdin=subprocess.DEVNULL,
                              capture_output=True, check=True, timeout=5).stdout

    top = Path(git("rev-parse", "--show-toplevel").decode().strip()).resolve()
    checker.require(top == root.resolve(), "source")
    checker.require(git("rev-parse", "--verify", "HEAD").decode().strip() == revision, "source")
    checker.require(not git("status", "--porcelain", "--untracked-files=normal"), "source")
    return input_fingerprint(root)


def write_archive(directory, destination, os_name):
    # Explicit legacy packaging utility. Default verification does not call it.
    checker.require(directory.is_dir() and not directory.is_symlink(), "export")
    suffix = ".exe" if os_name == "windows" else ""
    limits = {name + suffix: checker.BINARY_LIMIT for name in checker.COMMANDS}
    limits.update({"manifest.json": 256 << 10, "offline-pilot.json": 4 << 20})
    names = []
    with os.scandir(directory) as children:
        for child in children:
            names.append(child.name)
            checker.require(len(names) <= len(limits), "export")
    checker.require(set(names) == set(limits), "export")
    total = 0
    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_STORED, allowZip64=False) as archive:
        for name in sorted(limits):
            with regular_file(directory / name, limits[name], "export") as (stream, size):
                total += size
                checker.require(size > 0 and total <= checker.ARCHIVE_LIMIT - (64 << 10), "export")
                with archive.open(name, "w") as entry:
                    for raw in chunks(stream, size, "export"):
                        entry.write(raw)


def file_identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


def candidate_layout(directory, expected):
    selected = directory.lstat()
    checker.require(stat.S_ISDIR(selected.st_mode), "export")
    names = set()
    with os.scandir(directory) as children:
        for child in children:
            names.add(child.name)
            checker.require(len(names) <= len(expected), "export")
    checker.require(names == set(expected), "export")
    return selected


class OpenedMembers:
    """Expose each already checked regular descriptor to the validator once."""

    def __init__(self, streams, infos):
        self.streams, self.infos, self.used = streams, infos, set()

    def open(self, info):
        checker.require(self.infos.get(info.filename) is info and info.filename not in self.used, "export")
        self.used.add(info.filename)
        return contextlib.nullcontext(self.streams[info.filename])


@contextlib.contextmanager
def opened_candidate(directory, os_name):
    suffix = ".exe" if os_name == "windows" else ""
    limits = {name + suffix: checker.BINARY_LIMIT for name in checker.COMMANDS}
    limits.update({"manifest.json": 256 << 10, "offline-pilot.json": 4 << 20})
    selected = candidate_layout(directory, limits)
    streams, infos, identities, total = {}, {}, {}, 0
    with contextlib.ExitStack() as stack:
        for name, limit in sorted(limits.items()):
            stream, size = stack.enter_context(regular_file(directory / name, limit, "export"))
            total += size
            checker.require(size > 0 and total <= checker.ARCHIVE_LIMIT - (64 << 10), "export")
            streams[name] = stream
            infos[name] = SimpleNamespace(filename=name, file_size=size)
            descriptor_info = os.fstat(stream.fileno())
            path_info = (directory / name).lstat()
            checker.require(stat.S_ISREG(path_info.st_mode) and path_info.st_size == size
                            and os.path.samestat(descriptor_info, path_info), "export")
            identities[name] = (file_identity(descriptor_info), file_identity(path_info))
        members = OpenedMembers(streams, infos)
        yield members, infos
        checker.require(members.used == set(limits), "export")
        for name, stream in streams.items():
            checker.require(file_identity(os.fstat(stream.fileno())) == identities[name][0]
                            and file_identity((directory / name).lstat()) == identities[name][1], "export")
        checker.require(os.path.samestat(selected, candidate_layout(directory, limits)), "export")


def verify(directory, root, revision, os_name, architecture, require_skip_ledger=False):
    checker.require(type(require_skip_ledger) is bool, "arguments")
    inputs = source_pin(root, revision)
    with opened_candidate(directory, os_name) as (members, infos):
        result = checker.check_payloads(members, infos, revision, inputs, os_name, architecture,
                                        **({"require_skip_ledger": True} if require_skip_ledger else {}))
    checker.require(source_pin(root, revision) == inputs, "source")
    return result


def main(argv=None, output=None):
    output = sys.stdout if output is None else output
    parser = checker.Parser(prog="check-exported-candidate", allow_abbrev=False, add_help=False)
    for name in ("directory", "expect-revision", "expect-os", "expect-architecture"):
        parser.add_argument("--" + name, action=checker.Once, required=True)
    parser.add_argument("--require-skip-ledger", action=checker.OnceBoolean, nargs=0, default=None)
    code = 0
    try:
        args = parser.parse_args(argv)
        checker.require(0 < len(args.directory) <= 4096 and checker.digest(args.expect_revision, (40, 64))
                        and args.expect_os in ("linux", "darwin", "windows")
                        and type(args.expect_architecture) is str
                        and 0 < len(args.expect_architecture) <= 24
                        and all(c in "abcdefghijklmnopqrstuvwxyz0123456789_" for c in args.expect_architecture), "arguments")
        result = verify(Path(args.directory), Path.cwd(), args.expect_revision, args.expect_os, args.expect_architecture,
                        **({"require_skip_ledger": True} if args.require_skip_ledger else {}))
    except checker.Rejected as failure:
        result = {"schema_version": 1, "status": "rejected", "category": failure.category,
                  "binaries": 0, "test_status": None, "skipped_subtests": 0}
        code = 64 if failure.category == "arguments" else 2
    except (Exception, KeyboardInterrupt):
        result = {"schema_version": 1, "status": "rejected", "category": "input",
                  "binaries": 0, "test_status": None, "skipped_subtests": 0}
        code = 2
    try:
        raw = json.dumps(result, separators=(",", ":")) + "\n"
        if output.write(raw) != len(raw):
            return 70
        output.flush()
    except (OSError, ValueError):
        return 70
    return code


if __name__ == "__main__":
    raise SystemExit(main())
