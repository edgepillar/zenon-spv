#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Bounded research codec for canonical raw NodeTree store dump records.

The selected goleveldb Batch.Dump returns records, without the journal's
sequence/count header. Batch.Load borrows its input and accepts a broader
language than this export contract. Here only immutable bytes, ordered unique
nonempty keys, put records and minimal uint64 varints are admitted.

Grammar, selection integrity, DAG validity and authenticated header binding
are separate checks. A valid prefix can itself be valid grammar. Neither this
module nor a caller-supplied digest authenticates a snapshot or accepts values.
"""
import hashlib
import re


BATCH_MODULE = "github.com/syndtr/goleveldb"
BATCH_VERSION = "v1.0.1-0.20210819022825-2ae1ddf74ef7"
BATCH_ZIP_SHA256 = "27a3ccd9769cc0df353edf9f2baec88a6fac82c766e317b1c697d06c1654052c"
BATCH_SOURCE_SHA256 = "299129fbb88354f140bd7e7c83ffda6554e9af906ab68589f72e7c212f49c096"
_CAPS = (("bytes", 8 << 20), ("records", 32768),
         ("key_bytes", 128), ("value_bytes", 1 << 20))
_UINT64_MAX = (1 << 64) - 1


def refuse(reason):
    raise ValueError("Raw store dump refused: " + reason)


def _limits(value):
    maximum = dict(_CAPS)
    if value is None:
        return maximum
    if type(value) is not dict:
        refuse("limits")
    items = tuple(value.items())
    if (len(items) != len(maximum)
            or any(type(key) is not str or type(number) is not int for key, number in items)):
        refuse("limits")
    selected = dict(items)
    if set(selected) != set(maximum):
        refuse("limits")
    if any(not 0 < selected[key] <= cap for key, cap in maximum.items()):
        refuse("limits")
    return selected


def _uvarint(number):
    if type(number) is not int or not 0 <= number <= _UINT64_MAX:
        refuse("uint64")
    result = bytearray()
    while number >= 128:
        result.append((number & 127) | 128)
        number >>= 7
    result.append(number)
    return bytes(result)


def _length(raw, position):
    value = 0
    for width in range(10):
        if position >= len(raw):
            refuse("truncated_varint")
        byte = raw[position]
        position += 1
        if width == 9 and byte > 1:
            refuse("varint_overflow")
        value |= (byte & 127) << (7 * width)
        if byte < 128:
            if width and byte == 0:
                refuse("nonminimal_varint")
            return value, position
    refuse("varint_overflow")


def encode_dump(records, limits=None):
    """Encode an already selected ordered record map; perform no file I/O."""
    selected = _limits(limits)
    if ((type(records) is not list and type(records) is not tuple)
            or len(records) > selected["records"]):
        refuse("record_count_or_type")
    parts, total, previous = [], 0, None
    for index, record in enumerate(records):
        if index >= selected["records"]:
            refuse("record_count")
        if type(record) is not tuple or len(record) != 2:
            refuse("record_shape")
        key, value = record
        if type(key) is not bytes or type(value) is not bytes:
            refuse("record_bytes")
        if not 0 < len(key) <= selected["key_bytes"]:
            refuse("key_size")
        if len(value) > selected["value_bytes"]:
            refuse("value_size")
        if previous is not None and key <= previous:
            refuse("key_order")
        key_size, value_size = _uvarint(len(key)), _uvarint(len(value))
        total += 1 + len(key_size) + len(key) + len(value_size) + len(value)
        if total > selected["bytes"]:
            refuse("dump_size")
        parts.extend((b"\x01", key_size, key, value_size, value))
        previous = key
    return b"".join(parts)


def decode_dump(raw, limits=None):
    """Check record grammar only; this does not establish completeness."""
    selected = _limits(limits)
    if type(raw) is not bytes:
        refuse("immutable_bytes_required")
    if len(raw) > selected["bytes"]:
        refuse("dump_size")
    result, position, previous = [], 0, None
    while position < len(raw):
        if len(result) >= selected["records"]:
            refuse("record_count")
        if raw[position] != 1:
            refuse("put_records_only")
        position += 1
        size, position = _length(raw, position)
        if not 0 < size <= selected["key_bytes"]:
            refuse("key_size")
        if size > len(raw) - position:
            refuse("truncated_key")
        key = raw[position:position + size]
        position += size
        if previous is not None and key <= previous:
            refuse("key_order")
        size, position = _length(raw, position)
        if size > selected["value_bytes"]:
            refuse("value_size")
        if size > len(raw) - position:
            refuse("truncated_value")
        value = raw[position:position + size]
        position += size
        result.append((key, value))
        previous = key
    return tuple(result)


def decode_selected_dump(raw, selection, limits=None):
    """Bind bytes/count/digest selected before candidate collection.

    Callers still need the independent raw-store/DAG oracle and trust inputs.
    A selection copied from the candidate supplies no independent expectation.
    """
    selected = _limits(limits)
    if type(raw) is not bytes:
        refuse("immutable_bytes_required")
    if type(selection) is not dict:
        refuse("selection")
    items = tuple(selection.items())
    if (len(items) != 3 or any(type(key) is not str for key, _ in items)):
        refuse("selection")
    pin = dict(items)
    if set(pin) != {"bytes", "records", "sha256"}:
        refuse("selection")
    if (type(pin["bytes"]) is not int or not 0 <= pin["bytes"] <= selected["bytes"]
            or type(pin["records"]) is not int or not 0 <= pin["records"] <= selected["records"]
            or type(pin["sha256"]) is not str
            or re.fullmatch("[0-9a-f]{64}", pin["sha256"]) is None):
        refuse("selection")
    if len(raw) != pin["bytes"]:
        refuse("selection_bytes")
    if hashlib.sha256(raw).hexdigest() != pin["sha256"]:
        refuse("selection_digest")
    result = decode_dump(raw, selected)
    if len(result) != pin["records"]:
        refuse("selection_records")
    return result


def scope():
    return {
        "research_only": True,
        "record_grammar_and_selected_bytes_only": True,
        "journal_header_present": False,
        "source_Load_accepts_broader_inputs": True,
        "mutable_borrowed_input_admitted": False,
        "DAG_or_refcounts_verified": False,
        "authenticated_snapshot_import": False,
        "accepted_header_binding": False,
        "consumer_result": "REFUSED",
        "production_state_value_accepted": False,
    }
