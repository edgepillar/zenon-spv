#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Observe a selected ZIP directory tail; never fetch or open member payloads."""
import hashlib
import json
import re
import stat
import struct
import sys
import unicodedata


READ_BYTES = 64 << 10
DEFAULT_LIMITS = {"tail_bytes": 1 << 20, "members": 10000,
                  "unpacked_bytes": 32 << 30, "file_bytes": 16 << 30}
HARD_LIMITS = {"tail_bytes": 4 << 20, "members": 16384,
               "unpacked_bytes": 128 << 30, "file_bytes": 64 << 30}
MAX_ARCHIVE_BYTES = 1 << 40
RESULT_BYTES = 64 << 10
USAGE = ("archive_index.py: require --archive-bytes, --archive-sha256, "
         "--tail-bytes and --tail-sha256; optional --max-tail-bytes, "
         "--max-members, --max-unpacked-bytes and --max-file-bytes. "
         "Stdin is exactly the selected final tail, followed by EOF.\n")


class Refused(ValueError):
    """Static code only: input names and private data never enter diagnostics."""


def require(condition, reason):
    if not condition:
        raise Refused(reason)


def sha(value):
    return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def validate(selection, limits):
    require(type(selection) is dict and set(selection) == {
        "archive_bytes", "archive_sha256", "tail_bytes", "tail_sha256"}, "SELECTION")
    require(type(limits) is dict and set(limits) == set(HARD_LIMITS), "LIMITS")
    for name, maximum in HARD_LIMITS.items():
        require(type(limits[name]) is int and 0 < limits[name] <= maximum, "LIMITS")
    require(type(selection["archive_bytes"]) is int and
            22 <= selection["archive_bytes"] <= MAX_ARCHIVE_BYTES, "ARCHIVE_BYTES")
    require(type(selection["tail_bytes"]) is int and 22 <= selection["tail_bytes"] <=
            min(selection["archive_bytes"], limits["tail_bytes"]), "TAIL_BYTES")
    require(sha(selection["archive_sha256"]) and sha(selection["tail_sha256"]), "DIGEST")


def read_tail(reader, selection):
    remaining = selection["tail_bytes"]
    parts = []
    while remaining:
        value = reader.read(min(READ_BYTES, remaining))
        require(type(value) is bytes and 0 < len(value) <= min(READ_BYTES, remaining), "TAIL_READ")
        parts.append(value)
        remaining -= len(value)
    require(reader.read(1) == b"", "TRAILING_DATA")
    raw = b"".join(parts)
    require(hashlib.sha256(raw).hexdigest() == selection["tail_sha256"], "TAIL_DIGEST")
    return raw


def directory_bounds(raw, archive_bytes, member_limit):
    """Require one complete EOCD, an adjacent directory and no multi-disk ZIP."""
    base = archive_bytes - len(raw)
    candidates = []
    start = max(0, len(raw) - 65557)
    for offset in range(start, len(raw) - 21):
        if raw[offset:offset + 4] == b"PK\x05\x06":
            fields = struct.unpack_from("<4s4H2IH", raw, offset)
            if offset + 22 + fields[-1] == len(raw):
                candidates.append((offset, fields))
    require(len(candidates) == 1, "END_RECORD")
    end, fields = candidates[0]
    _, disk, cd_disk, disk_count, count, size, offset, _ = fields
    require(disk == cd_disk == 0 and disk_count == count, "MULTI_DISK")
    zip64 = count == 65535 or size == 0xffffffff or offset == 0xffffffff
    directory_end = base + end
    if zip64:
        require(end >= 20 and raw[end - 20:end - 16] == b"PK\x06\x07", "ZIP64_LOCATOR")
        _, z_disk, z_offset, disks = struct.unpack_from("<4sIQI", raw, end - 20)
        require(z_disk == 0 and disks == 1, "MULTI_DISK")
        local = z_offset - base
        require(0 <= local <= end - 76, "ZIP64_RANGE")
        record = struct.unpack_from("<4sQ2H2I4Q", raw, local)
        signature, record_bytes, _, needed, z_disk, z_cd_disk, z_disk_count, z_count, z_size, z_cd = record
        require(signature == b"PK\x06\x06" and record_bytes == 44 and needed <= 45 and
                local + 56 == end - 20, "ZIP64_RECORD")
        require(z_disk == z_cd_disk == 0 and z_disk_count == z_count, "MULTI_DISK")
        require((count == 65535 or count == z_count) and
                (size == 0xffffffff or size == z_size) and
                (offset == 0xffffffff or offset == z_cd), "ZIP64_DISAGREEMENT")
        count, size, offset, directory_end = z_count, z_size, z_cd, z_offset
    require(count <= member_limit and size >= count * 46, "MEMBER_LIMIT")
    require(offset >= base and offset + size == directory_end, "DIRECTORY_RANGE")
    return offset - base, size, count, zip64, offset


def extra_values(raw, sizes):
    """ZIP64 values occur only for the corresponding sentinel fields, in order."""
    found = None
    cursor = 0
    while cursor < len(raw):
        require(cursor + 4 <= len(raw), "EXTRA_FIELD")
        tag, length = struct.unpack_from("<HH", raw, cursor)
        cursor += 4
        require(cursor + length <= len(raw), "EXTRA_FIELD")
        if tag == 1:
            require(found is None, "ZIP64_EXTRA")
            found = raw[cursor:cursor + length]
        cursor += length
    needed = [8 if index < 3 else 4 for index, value in enumerate(sizes)
              if value == (0xffffffff if index < 3 else 65535)]
    if found is None:
        require(not needed, "ZIP64_EXTRA")
        return sizes
    require(len(found) == sum(needed), "ZIP64_EXTRA")
    result, cursor = [], 0
    for index, value in enumerate(sizes):
        if value == (0xffffffff if index < 3 else 65535):
            width = 8 if index < 3 else 4
            value = int.from_bytes(found[cursor:cursor + width], "little")
            cursor += width
        result.append(value)
    return result


def safe_name(raw, flags, external, names):
    require(0 < len(raw) <= 512, "MEMBER_NAME")
    try:
        name = raw.decode("utf-8" if flags & 2048 else "cp437")
    except UnicodeError:
        raise Refused("MEMBER_NAME") from None
    require(not any(ord(c) < 32 or ord(c) == 127 or c in "\\:" for c in name), "MEMBER_NAME")
    directory = name.endswith("/")
    parts = name[:-1].split("/") if directory else name.split("/")
    require(all(part and part not in (".", "..") for part in parts), "MEMBER_NAME")
    canonical = unicodedata.normalize("NFC", "/".join(parts)).casefold()
    require(canonical not in names, "MEMBER_ALIAS")
    names[canonical] = directory
    kind = stat.S_IFMT(external >> 16)
    require(kind in (0, stat.S_IFDIR if directory else stat.S_IFREG) and
            (not external & 16 or directory), "MEMBER_TYPE")
    return parts, directory


def observe(reader, selection, limits=None):
    limits = DEFAULT_LIMITS if limits is None else limits
    validate(selection, limits)
    # Freeze the selection before the first input read, including custom readers.
    selection, limits = dict(selection), dict(limits)
    raw = read_tail(reader, selection)
    cursor, directory_bytes, count, zip64, cd_absolute = directory_bounds(
        raw, selection["archive_bytes"], limits["members"])
    end = cursor + directory_bytes
    names, offsets, groups = {}, set(), {}
    totals = {name: 0 for name in ("members", "files", "directories", "compressed_bytes",
                                  "unpacked_bytes", "largest_file_bytes", "ldb", "log", "manifests")}
    while cursor < end:
        require(totals["members"] < count and cursor + 46 <= end, "MEMBER_COUNT")
        fields = struct.unpack_from("<4s6H3I5H2I", raw, cursor)
        signature, _, needed, flags, method, _, _, _, packed, unpacked, n, x, c, disk, _, external, offset = fields
        require(signature == b"PK\x01\x02" and needed <= 45, "DIRECTORY_ENTRY")
        require(flags & ~(2048 | 8 | 2 | 4) == 0 and method in (0, 8) and
                (method == 8 or flags & 6 == 0), "MEMBER_ENCODING")
        next_cursor = cursor + 46 + n + x + c
        require(next_cursor <= end, "DIRECTORY_ENTRY")
        parts, directory = safe_name(raw[cursor + 46:cursor + 46 + n], flags, external, names)
        unpacked, packed, offset, disk = extra_values(raw[cursor + 46 + n:cursor + 46 + n + x],
                                                    [unpacked, packed, offset, disk])
        require(disk == 0, "MULTI_DISK")
        require(offset not in offsets and offset + 30 + n + packed <= cd_absolute, "MEMBER_OFFSET")
        offsets.add(offset)
        require(unpacked <= limits["file_bytes"] and
                (method != 0 or packed == unpacked), "FILE_BYTES")
        require(not directory or packed == unpacked == 0, "DIRECTORY_PAYLOAD")
        group = "/".join(parts[:2]) if len(parts) > 1 else parts[0]
        require(group in groups or len(groups) < 64, "GROUP_LIMIT")
        values = groups.setdefault(group, {name: 0 for name in totals})
        for counters in (totals, values):
            counters["members"] += 1
            counters["directories" if directory else "files"] += 1
            counters["compressed_bytes"] += packed
            counters["unpacked_bytes"] += unpacked
            counters["largest_file_bytes"] = max(counters["largest_file_bytes"], unpacked)
            if not directory:
                counters["ldb"] += int(parts[-1].endswith(".ldb"))
                counters["log"] += int(parts[-1].endswith(".log"))
                counters["manifests"] += int(parts[-1].startswith("MANIFEST-"))
        require(totals["unpacked_bytes"] <= limits["unpacked_bytes"], "UNPACKED_BYTES")
        cursor = next_cursor
    require(cursor == end and totals["members"] == count, "MEMBER_COUNT")
    for name in names:
        parts = name.split("/")
        for index in range(1, len(parts)):
            require(names.get("/".join(parts[:index]), True), "MEMBER_ALIAS")
    result = {"format": "zenon-r1-archive-directory/v1", "status": "SELECTED_DIRECTORY_OBSERVED",
            "selection": selection, "limits": limits, "directory": {
                "format": "ZIP64" if zip64 else "ZIP", "offset": cd_absolute, "bytes": directory_bytes},
            "totals": totals, "groups": groups,
            "scope": {name: False for name in (
                "whole_archive_sha256_verified", "tail_to_archive_pairing_authenticated",
                "local_headers_checked", "member_payloads_opened", "member_CRC_verified",
                "declared_unpacked_sizes_verified", "extraction_safety_qualified",
                "physical_disk_or_RSS_measured", "node_stopped_confirmed", "snapshot_consistency_authenticated",
                "network_frontier_authenticated", "real_R1_dataset_collected", "representative_dataset_accepted",
                "profile_agreed", "state_value_acceptance_enabled")}}
    require(len(json_bytes(result)) <= RESULT_BYTES, "REPORT_BYTES")
    return result


def json_bytes(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()


def emit(writer, value):
    raw = json_bytes(value)
    if writer.write(raw) != len(raw):
        raise OSError("OUTPUT_INCOMPLETE")
    writer.flush()


def parse_args(args):
    required = {"archive_bytes", "archive_sha256", "tail_bytes", "tail_sha256"}
    options = {"--" + key.replace("_", "-"): key for key in required}
    options.update({"--max-" + key.replace("_", "-"): "max_" + key for key in HARD_LIMITS})
    selected, limits, seen = {}, dict(DEFAULT_LIMITS), set()
    require(len(args) % 2 == 0, "OPTIONS")
    for index in range(0, len(args), 2):
        option, value = args[index:index + 2]
        require(option in options and option not in seen, "OPTIONS")
        seen.add(option)
        key = options[option]
        if key.endswith("sha256"):
            selected[key] = value
        else:
            require(len(value) <= 20 and re.fullmatch(r"[0-9]+", value) is not None, "OPTIONS")
            if key.startswith("max_"):
                limits[key[4:]] = int(value)
            else:
                selected[key] = int(value)
    require(set(selected) == required, "OPTIONS")
    validate(selected, limits)
    return selected, limits


def main(args, reader, writer, errors):
    if args == ["--help"]:
        errors.write(USAGE)
        emit(writer, {"status": "UNKNOWN", "reason": "HELP"})
        return 0
    try:
        selected, limits = parse_args(args)
    except Refused:
        emit(writer, {"status": "UNKNOWN", "reason": "OPTIONS"})
        return 64
    try:
        result = observe(reader, selected, limits)
    except Refused as error:
        emit(writer, {"status": "UNKNOWN", "reason": str(error)})
        return 2
    except OSError:
        emit(writer, {"status": "UNKNOWN", "reason": "INPUT_IO"})
        return 70
    except KeyboardInterrupt:
        emit(writer, {"status": "UNKNOWN", "reason": "INTERRUPTED"})
        return 130
    emit(writer, result)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:], sys.stdin.buffer, sys.stdout.buffer, sys.stderr))
    except (OSError, BrokenPipeError):
        sys.exit(70)
    except KeyboardInterrupt:
        sys.exit(130)
