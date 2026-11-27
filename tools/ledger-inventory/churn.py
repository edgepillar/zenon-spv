#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Replay a selected ordered raw-ledger patch into a bounded snapshot digest."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import inventory


PLAN_FORMAT = "zenon-r1-ledger-churn-plan/v1"
REPORT_FORMAT = "zenon-r1-ledger-churn/v1"
PROJECTION_REPORT_FORMAT = "zenon-r1-ledger-churn-projection/v1"
TRANSPORT_REPORT_FORMAT = "zenon-r1-ledger-churn-transport/v1"
PLAN_BYTES = 8 << 10
DEFAULT_PATCH_BYTES = 8 << 20
HARD_PATCH_BYTES = 64 << 20
DEFAULT_PATCH_RECORDS = 32768
HARD_PATCH_RECORDS = 262144
STREAM_FIELDS = {"bytes", "records", "sha256"}
COUNTERS = ("records", "key_bytes", "raw_value_bytes", "put_wire_bytes")
OPERATIONS = ("inserted", "changed", "deleted", "unchanged_puts", "absent_deletes",
              "touched_keys", "repeated_key_operations")
require = inventory.require


def scope():
    return {**inventory.scope(), "momentum_parent_link_authenticated": False,
            "complete_ordered_patch_authenticated": False}


def digest(value):
    return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def exact_fields(value, fields):
    require(type(value) is dict and set(value) == fields, "plan_fields")


def snapshot(row, provenance, caps):
    exact_fields(row, STREAM_FIELDS | {"momentum"})
    inventory.selection({**{key: row[key] for key in STREAM_FIELDS},
                         "record_space": "effective-raw-ledger", "provenance_sha256": provenance}, caps)
    momentum = row["momentum"]
    exact_fields(momentum, {"height", "hash"})
    require(type(momentum["height"]) is int and 0 < momentum["height"] < 1 << 64
            and digest(momentum["hash"]), "momentum_identity")


def read_plan(stream, size, sha256, caps, max_patch_bytes, max_patch_records):
    require(type(size) is int and 0 < size <= PLAN_BYTES and digest(sha256), "plan_pin")
    reader = inventory.Reader(stream, size)
    raw = reader.take(size)
    require(reader.hash.hexdigest() == sha256, "plan_digest")
    plan = json.loads(raw)
    require(raw == inventory.encoded(plan), "plan_encoding")
    exact_fields(plan, {"format", "record_space", "provenance_sha256", "before", "patch", "after"})
    require(plan["format"] == PLAN_FORMAT and plan["record_space"] == "effective-raw-ledger"
            and digest(plan["provenance_sha256"]), "plan_identity")
    for name in ("before", "after"):
        snapshot(plan[name], plan["provenance_sha256"], caps)
    before, after = (plan[name]["momentum"] for name in ("before", "after"))
    require(after["height"] == before["height"] + 1 and after["hash"] != before["hash"],
            "selected_momentum_pair")
    patch = plan["patch"]
    exact_fields(patch, STREAM_FIELDS)
    require(type(patch["bytes"]) is int and 0 <= patch["bytes"] <= max_patch_bytes
            and type(patch["records"]) is int and 0 <= patch["records"] <= max_patch_records
            and patch["records"] <= patch["bytes"] // 2 and digest(patch["sha256"]), "patch_pin")
    return plan


def read_key(reader, caps):
    size = reader.length()
    require(size <= caps["key_bytes"], "key_size")
    return reader.take(size)


def value_size(reader, caps):
    size = reader.length()
    require(size <= caps["value_bytes"], "value_size")
    return size


def operation_kind(current, value):
    if value is None:
        return "absent_deletes" if current is None else "deleted"
    if current is None:
        return "inserted"
    return "unchanged_puts" if current == value else "changed"


class Edit:
    __slots__ = ("family", "first", "last", "value")

    def __init__(self, family, summary, value):
        self.family = family
        self.first = self.last = summary
        self.value = value


def read_patch(stream, pin, caps, families):
    reader = inventory.Reader(stream, pin["bytes"])
    # Only the first operation needs the earlier snapshot. Later transitions
    # can be counted immediately in stream order using the previous patch value.
    edits = {}
    count = 0
    while reader.position < pin["bytes"]:
        require(count < pin["records"], "patch_records")
        tag = reader.byte()
        require(tag in (0, 1), "patch_record_tag")
        key = read_key(reader, caps)
        value = summary = None
        if tag == 1:
            size = value_size(reader, caps)
            value = reader.take(size)
            summary = (size, hashlib.sha256(value).digest())
        edit = edits.get(key)
        if edit is None:
            edits[key] = Edit(inventory.family(key), summary, value)
        else:
            operations = families[edit.family]["operations"]
            operations[operation_kind(edit.last, summary)] += 1
            operations["repeated_key_operations"] += 1
            edit.last, edit.value = summary, value
        count += 1
    require(count == pin["records"], "patch_records")
    require(reader.hash.hexdigest() == pin["sha256"], "patch_digest")
    return edits


def uvarint(value):
    raw = bytearray()
    while value >= 128:
        raw.append((value & 127) | 128)
        value >>= 7
    raw.append(value)
    return bytes(raw)


def add_record(row, key, size, wire):
    row["records"] += 1
    row["key_bytes"] += len(key)
    row["raw_value_bytes"] += size
    row["put_wire_bytes"] += wire


class ReplayedValue:
    """Feed a value to the projector and the selected output check."""

    def __init__(self, read, write):
        self.read, self.write = read, write

    def take(self, size):
        part = self.read(size)
        require(len(part) == size, "truncated_input")
        self.write(part)
        return part

    def value(self, size):
        while size:
            size -= len(self.take(min(size, inventory.CHUNK_BYTES)))
        return False


class Replay:
    def __init__(self, after, write, projector):
        self.after = after
        self.write = write
        self.projector = projector
        self.families = {name: {"before": dict.fromkeys(COUNTERS, 0),
                                "after": dict.fromkeys(COUNTERS, 0),
                                "operations": dict.fromkeys(OPERATIONS, 0)}
                         for name in inventory.FAMILIES}
        self.size = self.count = 0

    def begin_record(self, name, key, size):
        header = b"\x01" + uvarint(len(key)) + key + uvarint(size)
        wire = len(header) + size
        require(self.size + wire <= self.after["bytes"] and self.count < self.after["records"],
                "after_size_or_records")
        add_record(self.families[name]["after"], key, size, wire)
        self.write(header)
        self.size += wire
        self.count += 1

    def apply(self, key, edit, current):
        counts = self.families[edit.family]["operations"]
        counts["touched_keys"] += 1
        counts[operation_kind(current, edit.first)] += 1
        if edit.value is not None:
            self.begin_record(edit.family, key, len(edit.value))
            if self.projector is None:
                self.write(edit.value)
            else:
                self.copy_value(key, len(edit.value), io.BytesIO(edit.value).read)

    def copy_value(self, key, size, read):
        if self.projector is None:
            consume_value(read, size, self.write)
        else:
            self.projector.read_value(ReplayedValue(read, self.write), key, size)

    def totals(self, name, fields):
        return {key: sum(row[name][key] for row in self.families.values()) for key in fields}


def consume_value(read, size, write):
    while size:
        part = read(min(size, inventory.CHUNK_BYTES))
        write(part)
        size -= len(part)


def replay_snapshot(stream, pin, caps, edits, replay):
    reader = inventory.Reader(stream, pin["bytes"])
    pending = iter(sorted(edits))
    next_key = next(pending, None)
    previous, records = None, 0
    while reader.position < pin["bytes"]:
        require(records < pin["records"], "before_records")
        start = reader.position
        require(reader.byte() == 1, "put_record_required")
        key = read_key(reader, caps)
        require(previous is None or key > previous, "key_order")
        size = value_size(reader, caps)
        name = inventory.family(key)
        while next_key is not None and next_key < key:
            replay.apply(next_key, edits.pop(next_key), None)
            next_key = next(pending, None)
        if next_key == key:
            current = hashlib.sha256()
            consume_value(reader.take, size, current.update)
            replay.apply(key, edits.pop(key), (size, current.digest()))
            next_key = next(pending, None)
        else:
            replay.begin_record(name, key, size)
            replay.copy_value(key, size, reader.take)
        add_record(replay.families[name]["before"], key, size, reader.position - start)
        previous = key
        records += 1
    while next_key is not None:
        replay.apply(next_key, edits.pop(next_key), None)
        next_key = next(pending, None)
    require(not reader.raw_read(1), "trailing_input")
    require(records == pin["records"], "before_records")
    require(reader.hash.hexdigest() == pin["sha256"], "before_digest")
    after = replay.after
    require((replay.size, replay.count) == (after["bytes"], after["records"]), "after_size_or_records")


def load_source(name, relative):
    path = Path(__file__).resolve().parents[1] / relative
    spec = importlib.util.spec_from_file_location(name, path)
    source = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(source)
    return source


def projection_options(profile, root, max_leaves):
    if profile is None and root is None and max_leaves is None:
        return None
    require(digest(root), "projection_options")
    projection = load_source("churn_snapshot_projection", "ledger-export/snapshot_projection.py")
    limit = projection.DEFAULT_LEAVES if max_leaves is None else max_leaves
    require(profile == projection.PROFILE and type(limit) is int and 0 < limit <= projection.MAX_LEAVES,
            "projection_options")
    return projection, root, limit


def inspect(stream, plan_bytes, plan_sha256, configured_limits=None, *,
            max_patch_bytes=DEFAULT_PATCH_BYTES, max_patch_records=DEFAULT_PATCH_RECORDS,
            projection_profile=None, expect_candidate_root=None, max_projected_leaves=None,
            after_manifest_bytes=None, after_manifest_sha256=None):
    caps = inventory.limits(configured_limits)
    require(type(max_patch_bytes) is int and 0 < max_patch_bytes <= HARD_PATCH_BYTES
            and type(max_patch_records) is int and 0 < max_patch_records <= HARD_PATCH_RECORDS, "patch_limits")
    options = projection_options(projection_profile, expect_candidate_root, max_projected_leaves)
    transport = None
    if after_manifest_bytes is not None or after_manifest_sha256 is not None:
        require(type(after_manifest_bytes) is int and digest(after_manifest_sha256), "after_manifest_options")
        transport = load_source("churn_transport", "ledger-transport/transport.py")
        require(0 < after_manifest_bytes <= transport.MANIFEST_BYTES, "after_manifest_options")
    plan = read_plan(stream, plan_bytes, plan_sha256, caps, max_patch_bytes, max_patch_records)
    projector = None
    if options is not None:
        projection, root, limit = options
        projector = projection.Projector(root, limit, plan["after"]["momentum"])
    def replay_to(write):
        replay = Replay(plan["after"], write, projector)
        edits = read_patch(stream, plan["patch"], caps, replay.families)
        replay_snapshot(stream, plan["before"], caps, edits, replay)
        return replay

    checked_transport = None
    try:
        if transport is None:
            target = hashlib.sha256()
            replay = replay_to(target.update)
            require(target.hexdigest() == plan["after"]["sha256"], "after_digest")
        else:
            after = plan["after"]
            selected = {**after["momentum"], "bytes": after["bytes"], "sha256": after["sha256"],
                        "record_space": plan["record_space"], "provenance_sha256": plan["provenance_sha256"]}
            checked_transport, replay = transport.verify_emitted(
                stream, after_manifest_bytes, after_manifest_sha256, selected, replay_to,
                {**transport.HARD_LIMITS, "bytes": caps["bytes"]})
        projected = projector.finish() if projector is not None else None
    except ValueError as error:
        if transport is not None and isinstance(error, transport.Refused):
            raise inventory.Refused("after_transport_" + str(error)) from None
        if options is not None and isinstance(error, projection.Refused):
            raise inventory.Refused(str(error)) from None
        raise
    result = {"format": REPORT_FORMAT, "status": "SELECTED_PATCH_REPLAY_MATCHED",
            "selection": plan, "plan": {"bytes": plan_bytes, "sha256": plan_sha256},
            "limits": {**caps, "patch_bytes": max_patch_bytes, "patch_records": max_patch_records},
            "before_totals": replay.totals("before", COUNTERS), "after_totals": replay.totals("after", COUNTERS),
            "operations": replay.totals("operations", OPERATIONS), "families": replay.families,
            "input_bytes": plan_bytes + (after_manifest_bytes or 0) + plan["patch"]["bytes"] + plan["before"]["bytes"],
            "after_snapshot_bytes_read": 0, "derived_snapshot_bytes_written": 0,
            "end_of_stream_observed": True, "scope": scope()}
    if projected is not None:
        result.update(format=PROJECTION_REPORT_FORMAT, status="SELECTED_PATCH_REPLAY_AND_CANDIDATE_PROJECTION_MATCHED",
                      candidate_projection=projected)
    if checked_transport is not None:
        status = ("SELECTED_PATCH_REPLAY_AND_TRANSPORT_MATCHED" if projected is None
                  else "SELECTED_PATCH_REPLAY_TRANSPORT_AND_PROJECTION_MATCHED")
        result.update(format=TRANSPORT_REPORT_FORMAT, status=status, after_transport=checked_transport)
    return result


def main(argv=None, stream=None):
    parser = inventory.Parser(description=__doc__)
    parser.add_argument("--plan-bytes", required=True, type=inventory.decimal)
    parser.add_argument("--plan-sha256", required=True)
    parser.add_argument("--max-patch-bytes", type=inventory.decimal, default=DEFAULT_PATCH_BYTES)
    parser.add_argument("--max-patch-records", type=inventory.decimal, default=DEFAULT_PATCH_RECORDS)
    parser.add_argument("--projection-profile")
    parser.add_argument("--expect-candidate-root")
    parser.add_argument("--max-projected-leaves", type=inventory.decimal)
    parser.add_argument("--after-manifest-bytes", type=inventory.decimal)
    parser.add_argument("--after-manifest-sha256")
    for key, default in inventory.DEFAULT_LIMITS.items():
        parser.add_argument("--max-" + key.replace("_", "-"), type=inventory.decimal, default=default)
    args = parser.parse_args(argv)
    caps = {key: getattr(args, "max_" + key) for key in inventory.DEFAULT_LIMITS}
    return inspect(sys.stdin.buffer if stream is None else stream, args.plan_bytes, args.plan_sha256, caps,
                   max_patch_bytes=args.max_patch_bytes, max_patch_records=args.max_patch_records,
                   projection_profile=args.projection_profile, expect_candidate_root=args.expect_candidate_root,
                   max_projected_leaves=args.max_projected_leaves,
                   after_manifest_bytes=args.after_manifest_bytes, after_manifest_sha256=args.after_manifest_sha256)


if __name__ == "__main__":
    code = 0
    try:
        report = main()
    except inventory.Refused as error:
        code, report = 1, {"format": REPORT_FORMAT, "status": "UNKNOWN", "reason": str(error), "scope": scope()}
    except (OSError, TypeError, ValueError, OverflowError, RecursionError):
        code, report = 1, {"format": REPORT_FORMAT, "status": "UNKNOWN", "reason": "input_refused", "scope": scope()}
    raw = inventory.encoded(report)
    try:
        require(sys.stdout.buffer.write(raw) == len(raw), "output_write")
        sys.stdout.buffer.flush()
    except (inventory.Refused, OSError):
        code = 1
    sys.exit(code)
