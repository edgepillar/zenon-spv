#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Bounded candidate-v1.tar.xz transport; payload validation stays with its caller.

Only nine canonical, ordered regular members are supported. Nothing is extracted
or executed. The stream and its hashes do not authenticate source or execution.
"""
import contextlib
import hashlib
import lzma
import tarfile
from types import SimpleNamespace

PAYLOAD_NAME = "candidate-v1.tar.xz"
TOTAL_LIMIT = 256 << 20
DICTIONARY = 16 << 20
DECODER_MEMORY = 64 << 20
PIECE = 64 << 10
READ_LIMIT = (4 << 20) + 1
RECORD = 10240


class StreamRejected(ValueError):
    """The declared candidate stream contract was not completed."""


class OutputFailure(OSError):
    """The binary output channel did not accept a complete write."""


def require(value):
    if not value:
        raise StreamRejected("Candidate stream refused")


def layout(names, limits):
    require(type(names) is tuple and len(names) == 9 and all(type(n) is str for n in names)
            and len(set(names)) == 9
            and names[:2] == ("manifest.json", "offline-pilot.json")
            and type(limits) is dict and set(limits) == set(names))
    for name in names:
        require(type(name) is str and 0 < len(name) <= 100 and name.isascii()
                and all(c in "abcdefghijklmnopqrstuvwxyz0123456789-_." for c in name)
                and name not in (".", "..")
                and type(limits[name]) is int and 0 < limits[name] <= TOTAL_LIMIT)


def header(name, size, binary):
    item = tarfile.TarInfo(name)
    item.size = size
    item.mode = 0o755 if binary else 0o600
    item.mtime = item.uid = item.gid = 0
    item.uname = item.gname = ""
    return item.tobuf(format=tarfile.USTAR_FORMAT, encoding="ascii", errors="strict")


def footer(position):
    return 1024 + (-(position + 1024) % RECORD)


class _Encoder:
    def __init__(self, output):
        self.output = output
        self.codec = lzma.LZMACompressor(format=lzma.FORMAT_XZ, check=lzma.CHECK_CRC64,
            filters=[{"id": lzma.FILTER_LZMA2, "preset": 1, "dict_size": DICTIONARY}])
        self.raw_bytes = self.encoded_bytes = 0
        self.raw_hash, self.encoded_hash = hashlib.sha256(), hashlib.sha256()
        self.finished = False

    def emit(self, raw):
        if not raw:
            return
        require(self.encoded_bytes + len(raw) <= TOTAL_LIMIT)
        try:
            written = self.output.write(raw)
        except (OSError, TypeError, ValueError):
            raise OutputFailure("Candidate stream output did not complete") from None
        if type(written) is not int or written != len(raw):
            raise OutputFailure("Candidate stream output did not complete")
        self.encoded_bytes += written
        self.encoded_hash.update(raw)

    def write(self, raw):
        require(not self.finished and type(raw) is bytes
                and self.raw_bytes + len(raw) <= TOTAL_LIMIT)
        self.raw_bytes += len(raw)
        self.raw_hash.update(raw)
        self.emit(self.codec.compress(raw))

    def finish(self):
        require(not self.finished)
        self.write(b"\0" * footer(self.raw_bytes))
        self.finished = True
        self.emit(self.codec.flush())
        return {"payload": {"bytes": self.encoded_bytes, "sha256": self.encoded_hash.hexdigest()},
                "decoded": {"bytes": self.raw_bytes, "sha256": self.raw_hash.hexdigest()}}


class _Tee:
    def __init__(self, source, encoder, size):
        self.source, self.encoder, self.remaining = source, encoder, size

    def read(self, size):
        require(type(size) is int and 0 <= size <= READ_LIMIT)
        wanted = min(size, self.remaining + 1)
        raw = self.source.read(wanted)
        require(type(raw) is bytes and len(raw) <= wanted and len(raw) <= self.remaining)
        self.remaining -= len(raw)
        self.encoder.write(raw)
        return raw


class _WritingMembers:
    def __init__(self, original, infos, names, encoder):
        self.original, self.infos, self.names, self.encoder = original, infos, names, encoder
        self.position = 0
        self.active = False

    @contextlib.contextmanager
    def open(self, info):
        require(not self.active and self.position < len(self.names))
        name = self.names[self.position]
        require(self.infos[name] is info and info.filename == name)
        self.active = True
        with self.original.open(info) as source:
            self.encoder.write(header(name, info.file_size, self.position >= 2))
            reader = _Tee(source, self.encoder, info.file_size)
            yield reader
            require(reader.remaining == 0 and source.read(1) == b"")
            self.encoder.write(b"\0" * (-info.file_size % 512))
        self.position += 1
        self.active = False


def write_checked(members, infos, names, limits, output, validate, postcheck=None):
    """Emit a complete XZ only after the full existing payload validator succeeds.

    A failure may have emitted a prefix. The actual process exit and complete
    validation remain required; an output filename or XZ prefix is not success.
    postcheck can close/check source descriptors and recheck the selected checkout
    before the XZ end marker is emitted.
    """
    layout(names, limits)
    require(type(infos) is dict and set(infos) == set(names))
    total = 0
    for name in names:
        item = infos[name]
        require(item.filename == name and type(item.file_size) is int
                and 0 < item.file_size <= limits[name])
        total += item.file_size
    require(total <= TOTAL_LIMIT - (64 << 10))
    encoder = _Encoder(output)
    wrapped = _WritingMembers(members, infos, names, encoder)
    result = validate(wrapped, infos)
    require(type(result) is dict and result.get("status") == "verified"
            and type(result.get("binaries")) is int and result["binaries"] == 7
            and wrapped.position == len(names) and not wrapped.active)
    if postcheck is not None:
        postcheck()
    pins = encoder.finish()
    return dict(pins, verification=result, members=len(names), output_complete=True)


class _Decoded:
    def __init__(self, source, encoded_size):
        require(type(encoded_size) is int and 0 < encoded_size <= TOTAL_LIMIT)
        self.source, self.encoded_size = source, encoded_size
        self.codec = lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=DECODER_MEMORY)
        self.encoded = self.position = 0
        self.checked_end = False

    def end(self):
        require(self.codec.eof and self.codec.check == lzma.CHECK_CRC64
                and self.codec.unused_data == b"" and self.encoded == self.encoded_size)
        if not self.checked_end:
            require(self.source.read(1) == b"")
            self.checked_end = True

    def read(self, size):
        require(type(size) is int and 0 <= size <= READ_LIMIT)
        result = bytearray()
        try:
            while len(result) < size:
                if self.codec.eof:
                    self.end()
                    break
                if self.codec.needs_input:
                    wanted = min(PIECE, self.encoded_size - self.encoded + 1)
                    raw = self.source.read(wanted)
                    require(type(raw) is bytes and 0 < len(raw) <= wanted)
                    self.encoded += len(raw)
                    require(self.encoded <= self.encoded_size)
                else:
                    raw = b""
                decoded = self.codec.decompress(raw, max_length=min(PIECE, size - len(result)))
                require(self.codec.check in (lzma.CHECK_UNKNOWN, lzma.CHECK_CRC64)
                        and (decoded or self.codec.needs_input or self.codec.eof)
                        and self.position + len(result) + len(decoded) <= TOTAL_LIMIT)
                result.extend(decoded)
                if self.codec.eof:
                    self.end()
        except lzma.LZMAError:
            raise StreamRejected("Candidate stream refused") from None
        self.position += len(result)
        return bytes(result)

    def exact(self, size):
        raw = self.read(size)
        require(len(raw) == size)
        return raw


class _Window:
    def __init__(self, source, size):
        self.source, self.remaining = source, size

    def read(self, size):
        require(type(size) is int and 0 <= size <= READ_LIMIT)
        raw = self.source.exact(min(size, self.remaining))
        self.remaining -= len(raw)
        return raw


class _Index:
    def __init__(self, owner):
        self.owner = owner

    def __getitem__(self, name):
        return self.owner.next_info(name)


class _ReadingMembers:
    def __init__(self, source, encoded_size, names, limits):
        self.source = _Decoded(source, encoded_size)
        self.names, self.limits = names, limits
        self.position = self.total = 0
        self.current = None
        self.active = False

    def next_info(self, name):
        require(not self.active and self.position < len(self.names)
                and name == self.names[self.position])
        if self.current is None:
            raw = self.source.exact(512)
            try:
                parsed = tarfile.TarInfo.frombuf(raw, encoding="ascii", errors="strict")
            except (tarfile.HeaderError, UnicodeError, ValueError):
                raise StreamRejected("Candidate stream refused") from None
            require(parsed.name == name and type(parsed.size) is int
                    and 0 < parsed.size <= self.limits[name]
                    and raw == header(name, parsed.size, self.position >= 2))
            self.total += parsed.size
            require(self.total <= TOTAL_LIMIT - (64 << 10))
            self.current = SimpleNamespace(filename=name, file_size=parsed.size)
        return self.current

    @contextlib.contextmanager
    def open(self, info):
        require(not self.active and self.current is not None and self.current is info)
        self.active = True
        reader = _Window(self.source, info.file_size)
        yield reader
        require(reader.remaining == 0)
        padding = -info.file_size % 512
        require(self.source.exact(padding) == b"\0" * padding)
        self.position += 1
        self.current = None
        self.active = False

    def finish(self):
        require(self.position == len(self.names) and not self.active and self.current is None)
        size = footer(self.source.position)
        require(self.source.exact(size) == b"\0" * size and self.source.read(1) == b"")
        self.source.end()


@contextlib.contextmanager
def open_payload(source, encoded_size, names, limits):
    """Expose one sequential member view; require exact TAR and XZ termination."""
    layout(names, limits)
    members = _ReadingMembers(source, encoded_size, names, limits)
    yield members, _Index(members)
    members.finish()
