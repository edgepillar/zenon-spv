# SPDX-License-Identifier: GPL-3.0-only
"""Bounded intake of previously qualified, caller-selected Linux binaries.

The original ZIP is read in place. Only selected binaries are materialized; an
XZ payload and decoded TAR are never copied to disk. These checks establish
content identity, not CI execution, publication authority or operator approval.
No command, network, engine, signing or deployment operation is performed here.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import lzma
import os
from pathlib import Path
import stat
import struct
import sys
import tarfile
import zipfile

if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parent))

from model import Refused, canonical, exact_keys, pin, read_contract, relative_name, require, uint

CHUNK = 65536
MAX_ARCHIVE = 64 << 20
MAX_UNPACKED = 64 << 20
MAX_MEMBERS = 128
XZ_MEMORY_LIMIT = 128 << 20
CONSUMER_MEMBERS = frozenset((
    "manifest.json", "offline-pilot.json", "consume-query-report",
    "derive-checkpoints", "derive-producer-schedule", "fetch-bundle",
    "observe-block", "verify-mainnet-genesis", "zenon-spv"))
SELECTED = {"consumer": frozenset(("fetch-bundle", "zenon-spv")),
            "parent_oracle": frozenset(("spv-closed-parent-oracle.exe",))}


def _hash_stream(stream, expected):
    sha, size = hashlib.sha256(), 0
    stream.seek(0)
    for chunk in iter(lambda: stream.read(CHUNK), b""):
        size += len(chunk)
        require(size <= expected["bytes"], "archive_size")
        sha.update(chunk)
    require(size == expected["bytes"] and sha.hexdigest() == expected["sha256"],
            "archive_digest")
    stream.seek(0)


def _zip_preflight(stream, expected_size, *, max_members=MAX_MEMBERS):
    # Reject ZIP64/multipart/comments/trailing data before ZipFile allocates its
    # central-directory objects. The pinned input archives need none of these.
    require(expected_size >= 22, "zip_size")
    stream.seek(-22, os.SEEK_END)
    raw = stream.read(22)
    require(len(raw) == 22, "zip_end")
    signature, disk, directory_disk, count_disk, count, size, offset, comment = (
        struct.unpack("<4s4H2IH", raw))
    directory_end = expected_size - 22
    require(signature == b"PK\x05\x06" and disk == directory_disk == comment == 0
            and 0 < count == count_disk <= max_members
            and 46 * count <= size <= (46 + 4096) * count
            and 4 <= offset and offset + size == directory_end, "zip_directory")
    stream.seek(directory_end - 20)
    require(stream.read(4) != b"PK\x06\x07", "zip64_locator")
    # The advertised count is not a bound on the objects ZipFile will parse.
    # Walk the physical records and bound metadata before giving it the stream.
    position = offset
    for _ in range(count):
        require(position + 46 <= directory_end, "zip_directory_record")
        stream.seek(position)
        record = stream.read(46)
        require(len(record) == 46 and record[:4] == b"PK\x01\x02",
                "zip_directory_record")
        name, extra, note, disk_start = struct.unpack_from("<4H", record, 28)
        require(0 < name and name + extra + note <= 4096 and disk_start == 0,
                "zip_directory_record")
        position += 46 + name + extra + note
    require(position == directory_end, "zip_directory_record_count")
    stream.seek(0)
    require(stream.read(4) == b"PK\x03\x04", "zip_prefix")
    stream.seek(0)
    return count


def _zip_members(archive, count):
    rows, names, total = archive.infolist(), set(), 0
    require(len(rows) == count, "zip_member_count")
    for row in rows:
        name = relative_name(row.orig_filename)
        require(row.filename == name, "zip_member_name")
        mode = row.external_attr >> 16
        require(not row.is_dir() and not row.flag_bits & 0x41
                and row.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
                and stat.S_IFMT(mode) in (0, stat.S_IFREG), "zip_member_type")
        folded = name.casefold()
        require(folded not in names, "zip_member_alias")
        names.add(folded)
        require(0 <= row.file_size <= MAX_UNPACKED, "zip_member_bound")
        total += row.file_size
        require(total <= MAX_UNPACKED, "zip_unpacked_bound")
    return rows


def _identity(value):
    return (value.st_dev, value.st_ino, value.st_uid, value.st_size, value.st_mtime_ns)


def _elf64(prefix):
    require(len(prefix) >= 64 and prefix[:7] == b"\x7fELF\x02\x01\x01"
            and struct.unpack_from("<H", prefix, 16)[0] in (2, 3)
            and struct.unpack_from("<H", prefix, 18)[0] == 62
            and struct.unpack_from("<I", prefix, 20)[0] == 1
            and struct.unpack_from("<H", prefix, 52)[0] == 64,
            "linux_amd64_binary_header")


@dataclass(frozen=True)
class Binary:
    name: str
    sha256: str
    size: int
    identity: tuple


@dataclass(frozen=True)
class VerifiedBinaries:
    directory: Path
    directory_identity: tuple
    binaries: tuple

    def verify(self):
        info = self.directory.lstat()
        require(stat.S_ISDIR(info.st_mode)
                and (info.st_dev, info.st_ino, info.st_uid) == self.directory_identity,
                "binary_directory_changed")
        require({p.name for p in self.directory.iterdir()} == {b.name for b in self.binaries},
                "binary_directory_members")
        for binary in self.binaries:
            path = self.directory / binary.name
            before = path.lstat()
            require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                    and _identity(before) == binary.identity, "binary_file_changed")
            sha, size = hashlib.sha256(), 0
            descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            with os.fdopen(descriptor, "rb") as stream:
                require(os.path.samestat(before, os.fstat(stream.fileno())),
                        "binary_file_changed")
                for chunk in iter(lambda: stream.read(CHUNK), b""):
                    size += len(chunk)
                    require(size <= binary.size, "binary_file_changed")
                    sha.update(chunk)
                after = os.fstat(stream.fileno())
            final = path.lstat()
            require(_identity(before) == _identity(after) == _identity(final)
                    and final.st_nlink == 1 and stat.S_ISREG(final.st_mode)
                    and size == binary.size and sha.hexdigest() == binary.sha256,
                    "binary_file_changed")
        return {b.name: {"sha256": b.sha256, "bytes": b.size} for b in self.binaries}

    def enable_execution(self):
        # This is a separate owner action, after complete intake. It supplies no
        # dispatch authority and does not execute or test a binary or its libc.
        require(os.name == "posix", "binary_execution_platform")
        self.verify()
        for binary in self.binaries:
            (self.directory / binary.name).chmod(0o500)
        self.verify()


def _stream_binary(stream, expected, write=None):
    sha, size, prefix = hashlib.sha256(), 0, bytearray()
    while size < expected["bytes"]:
        chunk = stream.read(min(CHUNK, expected["bytes"] - size))
        require(bool(chunk), "binary_truncated")
        size += len(chunk)
        require(size <= expected["bytes"], "binary_size")
        prefix.extend(chunk[:max(0, 64 - len(prefix))])
        if write is not None:
            require(write(chunk) == len(chunk), "binary_short_write")
        sha.update(chunk)
    require(stream.read(1) == b"", "binary_size")
    digest = sha.hexdigest()
    require(digest == expected["sha256"], "binary_digest")
    _elf64(prefix)
    return {"sha256": digest, "bytes": size}


class _Outputs:
    def __init__(self, destination):
        self.directory = Path(destination)
        require(not self.directory.exists() and not self.directory.is_symlink(),
                "binary_directory_exists")
        # The caller supplies a fresh, owned parent. No existing tree is adopted
        # and failures retain their non-executable partial files for inspection.
        self.directory.mkdir(mode=0o700)
        info = self.directory.lstat()
        self.identity = (info.st_dev, info.st_ino, info.st_uid)
        self.binaries = []

    def write(self, name, stream, expected):
        require("/" not in relative_name(name), "binary_basename")
        path = self.directory / name
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                             | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(descriptor, "wb", buffering=0) as out:
            verified = _stream_binary(stream, expected, out.write)
            os.fsync(out.fileno())
        path.chmod(0o400)
        value = path.lstat()
        self.binaries.append(Binary(name, verified["sha256"], verified["bytes"], _identity(value)))

    def finish(self):
        result = VerifiedBinaries(self.directory, self.identity, tuple(self.binaries))
        result.verify()
        return result


class _XZ:
    def __init__(self, source, compressed, decoded):
        self.source, self.compressed, self.decoded = source, compressed, decoded
        self.decoder = lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=XZ_MEMORY_LIMIT)
        self.input_sha, self.output_sha = hashlib.sha256(), hashlib.sha256()
        self.input_size = self.output_size = 0
        self.ended = False
        self.buffer = bytearray()

    def read(self, size):
        require(type(size) is int and 0 <= size <= CHUNK, "decoded_read_bound")
        if size == 0:
            return b""
        while not self.buffer and not self.ended:
            chunk = self.source.read(CHUNK) if self.decoder.needs_input else b""
            if self.decoder.needs_input:
                require(bool(chunk), "xz_truncated")
                self.input_size += len(chunk)
                require(self.input_size <= self.compressed["bytes"], "xz_input_bound")
                self.input_sha.update(chunk)
            raw = self.decoder.decompress(chunk, max_length=min(
                CHUNK, self.decoded["bytes"] - self.output_size + 1))
            self.output_size += len(raw)
            require(self.output_size <= self.decoded["bytes"], "xz_decoded_bound")
            self.output_sha.update(raw)
            self.buffer.extend(raw)
            if self.decoder.eof:
                require(self.decoder.unused_data == b"" and self.source.read(1) == b"",
                        "xz_trailing_data")
                require(self.input_size == self.compressed["bytes"]
                        and self.input_sha.hexdigest() == self.compressed["sha256"],
                        "xz_input_digest")
                self.ended = True
        raw = bytes(self.buffer[:size])
        del self.buffer[:size]
        return raw

    def finish(self):
        # The end-of-archive marker has already been consumed by _tar. Only TAR
        # zero padding may remain. A second archive or hidden payload is refused.
        for chunk in iter(lambda: self.read(CHUNK), b""):
            require(not any(chunk), "tar_trailing_data")
        require(self.ended and self.output_size == self.decoded["bytes"]
                and self.output_sha.hexdigest() == self.decoded["sha256"],
                "decoded_tar_digest")


class _Slice:
    def __init__(self, stream, size):
        self.stream, self.remaining = stream, size

    def read(self, size):
        if self.remaining == 0:
            return b""
        raw = self.stream.read(min(size, self.remaining))
        require(bool(raw), "tar_truncated")
        self.remaining -= len(raw)
        return raw


def _exact(stream, size):
    raw = bytearray()
    while len(raw) < size:
        chunk = stream.read(min(CHUNK, size - len(raw)))
        require(bool(chunk), "tar_truncated")
        raw.extend(chunk)
    return bytes(raw)


def _tar(decoded, selected, outputs):
    names, total = set(), 0
    while True:
        header = _exact(decoded, 512)
        if header == bytes(512):
            require(_exact(decoded, 512) == bytes(512), "tar_end_marker")
            break
        member = tarfile.TarInfo.frombuf(header, "utf-8", "strict")
        name = relative_name(member.name)
        require(member.type in (tarfile.REGTYPE, tarfile.AREGTYPE)
                and not member.linkname and not member.pax_headers, "tar_member_type")
        require(name in CONSUMER_MEMBERS and name not in names, "tar_member_selection")
        names.add(name)
        require(len(names) <= len(CONSUMER_MEMBERS) and 0 <= member.size <= MAX_UNPACKED,
                "tar_member_bound")
        total += member.size
        require(total <= MAX_UNPACKED, "tar_unpacked_bound")
        stream = _Slice(decoded, member.size)
        if name in selected:
            require(member.size == selected[name]["bytes"], "binary_size")
            outputs.write(name, stream, selected[name])
        else:
            for _ in iter(lambda: stream.read(CHUNK), b""):
                pass
        padding = (-member.size) % 512
        require(not any(_exact(decoded, padding)), "tar_member_padding")
    require(names == CONSUMER_MEMBERS, "tar_member_closure")
    decoded.finish()


class _VerifiedPins:
    def __init__(self):
        self.pins = {}

    def write(self, name, stream, expected):
        self.pins[name] = _stream_binary(stream, expected)

    def finish(self):
        return self.pins


def _consume_archive(stream, kind, specification, make_output):
    require(kind in SELECTED, "binary_component")
    specification = json.loads(canonical(specification))
    keys = {"archive", "artifact_id", "binaries", "run_attempt", "run_id"}
    if kind == "consumer":
        keys |= {"payload", "decoded_tar"}
    exact_keys(specification, keys, "binary_component_fields")
    for field in ("artifact_id", "run_attempt", "run_id"):
        uint(specification[field])
    pin(specification["archive"], MAX_ARCHIVE)
    exact_keys(specification["binaries"], SELECTED[kind], "binary_selection")
    for value in specification["binaries"].values():
        pin(value, MAX_UNPACKED)
    if kind == "consumer":
        payload = specification["payload"]
        exact_keys(payload, {"filename", "sha256", "bytes"}, "payload_fields")
        require(payload["filename"] == "candidate-v1.tar.xz", "payload_selection")
        pin({k: payload[k] for k in ("sha256", "bytes")}, MAX_ARCHIVE)
        pin(specification["decoded_tar"], MAX_UNPACKED)
    try:
        _hash_stream(stream, specification["archive"])
        count = _zip_preflight(stream, specification["archive"]["bytes"])
        with zipfile.ZipFile(stream) as archive:
            rows = _zip_members(archive, count)
            if kind == "consumer":
                require(len(rows) == 1 and rows[0].filename == payload["filename"]
                        and rows[0].compress_type == zipfile.ZIP_STORED
                        and rows[0].file_size == payload["bytes"], "consumer_zip_closure")
                outputs = make_output()
                with archive.open(rows[0]) as encoded:
                    _tar(_XZ(encoded, payload, specification["decoded_tar"]),
                         specification["binaries"], outputs)
            else:
                names = {row.filename for row in rows}
                require(SELECTED[kind].issubset(names), "helper_binary_missing")
                outputs = make_output()
                for row in rows:
                    with archive.open(row) as value:
                        if row.filename in SELECTED[kind]:
                            require(row.file_size == specification["binaries"][row.filename]["bytes"],
                                    "binary_size")
                            outputs.write(row.filename, value, specification["binaries"][row.filename])
                        else:
                            for _ in iter(lambda: value.read(CHUNK), b""):
                                pass
        return outputs.finish()
    except Refused:
        raise
    except (zipfile.BadZipFile, lzma.LZMAError, tarfile.TarError,
            EOFError, UnicodeError, struct.error) as error:
        raise Refused("binary_archive_encoding") from error


def unpack_binaries(stream, kind, specification, destination):
    """Read one seekable original ZIP and materialize the selected binaries.

    The caller binds the archive to its selected source, workflow, run and artifact.
    """
    return _consume_archive(stream, kind, specification, lambda: _Outputs(destination))


def verify_binaries(stream, kind, specification):
    """Stream the selected archive and return binary pins without writing files."""
    return _consume_archive(stream, kind, specification, _VerifiedPins)


def _read_archive_file(path, expected_size, inspect):
    initial = path.lstat()
    require(stat.S_ISREG(initial.st_mode) and initial.st_nlink == 1
            and initial.st_size == expected_size, "archive_file_type_or_size")
    flags = (os.O_RDONLY | getattr(os, "O_BINARY", 0)
             | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(os.open(path, flags), "rb") as stream:
        opened = os.fstat(stream.fileno())
        require(stat.S_ISREG(opened.st_mode) and opened.st_nlink == 1
                and os.path.samestat(initial, opened), "archive_file_identity")
        result = inspect(stream)
        after, final = os.fstat(stream.fileno()), path.lstat()
        require(_identity(after) == _identity(opened) and _identity(final) == _identity(initial)
                and stat.S_ISREG(final.st_mode) and after.st_nlink == final.st_nlink == 1,
                "archive_file_changed")
    return result


def _verify_archive_file(path, kind, specification):
    return _read_archive_file(path, specification["archive"]["bytes"],
                              lambda stream: verify_binaries(stream, kind, specification))


def main(argv=None, stdout=None, stderr=None):
    parser = argparse.ArgumentParser(
        description="Verify one selected CI archive without extracting binaries.", allow_abbrev=False)
    parser.add_argument("--component", choices=tuple(SELECTED), required=True)
    parser.add_argument("--archive", type=Path, required=True)
    args = parser.parse_args(argv)
    stdout = sys.stdout.buffer if stdout is None else stdout
    stderr = sys.stderr if stderr is None else stderr
    try:
        contract = read_contract(Path(__file__).with_name("contract.json"))
        components = contract.data["qualified_components"]
        specification = components[args.component]
        binaries = _verify_archive_file(args.archive, args.component, specification)
        report = canonical({
            "format": "owned-devnet-archive-inspection/v1", "status": "VERIFIED",
            "component": args.component, "contract_sha256": contract.sha256,
            "binary_source_revision": components["source_revision"],
            "run_id": specification["run_id"], "run_attempt": specification["run_attempt"],
            "artifact_id": specification["artifact_id"], "archive": specification["archive"],
            "binaries": binaries, "materialized_binary_bytes": 0,
            "ci_metadata_verified": False, "native_binary_executed": False,
        })
        require(stdout.write(report) == len(report), "inspection_short_output")
        stdout.flush()
        return 0
    except Refused as error:
        stderr.write("Archive inspection refused (" + error.reason + ").\n")
    except (OSError, TypeError, ValueError):
        stderr.write("Archive inspection could not complete.\n")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
