#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Bounded offline inventory of a declared effective raw-ledger put stream.

The input is ordered unique goleveldb Batch.Dump put records, without a journal
header. It describes present logical ledger keys, not physical LevelDB records,
patches, derived NodeTree nodes or an authenticated snapshot. Selection pins
identify bytes; the protected provenance record needs separate owner review.
No state tree, database, network or proof consumer is opened here.
"""
import argparse
import hashlib
import json
import re
import sys


CHUNK_BYTES = 64 << 10
REPORT_BYTES = 128 << 10
DEFAULT_LIMITS = {"bytes": 256 << 20, "records": 2_000_000,
                  "key_bytes": 1024, "value_bytes": 1 << 20}
HARD_LIMITS = {"bytes": 16 << 30, "records": 100_000_000,
               "key_bytes": 1 << 20, "value_bytes": 64 << 20}
FAMILIES = ("empty_key", "typed_balance", "balance_prefix_other_width",
            "contract_storage", "plasma", "plasma_other_width", "frontier",
            "frontier_other_width", "receive_index_06", "receive_index_07",
            "account_other", "account_prefix_short", "mailbox",
            "mailbox_prefix_short", "znn_balance_index", "other_namespace")


class Refused(ValueError):
    """A static, privacy-safe reason code; never includes input bytes or paths."""


def require(condition, code):
    if not condition:
        raise Refused(code)


def scope():
    return {"record_space_declared": "effective-raw-ledger",
            "classification": "candidate-prefix-layout-not-a-protocol-decision",
            "ledger_consistency_authenticated": False,
            "snapshot_completeness_authenticated": False,
            "representative_dataset_accepted": False, "profile_agreed": False,
            "network_activation_authenticated": False,
            "header_authentication_executed": False,
            "absence_or_delete_proof": False, "state_value_acceptance_enabled": False}


def limits(value):
    if value is None:
        return dict(DEFAULT_LIMITS)
    require(type(value) is dict and set(value) == set(HARD_LIMITS), "limits")
    selected = dict(value)
    require(all(type(n) is int and 0 < n <= HARD_LIMITS[k]
                for k, n in selected.items()), "limits")
    return selected


def selection(value, caps):
    keys = {"bytes", "records", "sha256", "provenance_sha256", "record_space"}
    require(type(value) is dict and set(value) == keys, "selection")
    pin = dict(value)
    require(type(pin["record_space"]) is str and
            pin["record_space"] == "effective-raw-ledger", "record_space")
    for key in ("bytes", "records"):
        require(type(pin[key]) is int and 0 <= pin[key] <= caps[key], "selection_" + key)
    require(pin["records"] <= pin["bytes"] // 3, "selection_records")
    for key in ("sha256", "provenance_sha256"):
        require(type(pin[key]) is str and re.fullmatch(r"[0-9a-f]{64}", pin[key]) is not None,
                "selection_" + key)
    return pin


class Reader:
    def __init__(self, stream, size):
        self.stream, self.size, self.position = stream, size, 0
        self.hash = hashlib.sha256()
        self.buffer, self.offset = b"", 0

    def raw_read(self, size):
        require(0 < size <= CHUNK_BYTES, "read_bound")
        try:
            raw = self.stream.read(size)
        except OSError:
            raise Refused("input_read") from None
        require(type(raw) is bytes and len(raw) <= size, "input_read")
        return raw

    def fill(self):
        if self.offset == len(self.buffer):
            # Prefetch only selected bytes. The separate one-byte EOF probe must
            # still observe trailing input or an actual read error before success.
            remaining = self.size - self.position
            require(remaining > 0, "truncated_input")
            self.buffer = self.raw_read(min(CHUNK_BYTES, remaining))
            require(bool(self.buffer), "truncated_input")
            self.offset = 0
            self.hash.update(self.buffer)

    def take(self, size):
        require(0 <= size <= self.size - self.position, "truncated_input")
        raw = bytearray()
        while len(raw) < size:
            self.fill()
            count = min(size - len(raw), len(self.buffer) - self.offset)
            raw.extend(self.buffer[self.offset:self.offset + count])
            self.position += count
            self.offset += count
        return bytes(raw)

    def byte(self):
        require(self.position < self.size, "truncated_input")
        self.fill()
        value = self.buffer[self.offset]
        self.offset += 1
        self.position += 1
        return value

    def length(self):
        number = 0
        for width in range(10):
            byte = self.byte()
            require(width != 9 or byte <= 1, "varint_overflow")
            number |= (byte & 127) << (7 * width)
            if byte < 128:
                require(width == 0 or byte != 0, "nonminimal_varint")
                return number
        raise Refused("varint_overflow")

    def value(self, size):
        require(0 <= size <= self.size - self.position, "truncated_input")
        if size == 32:
            return self.take(32) == bytes(32)
        while size:
            self.fill()
            count = min(size, len(self.buffer) - self.offset)
            self.position += count
            self.offset += count
            size -= count
        return False


class Sizes:
    def __init__(self):
        self.count = self.total = 0
        self.minimum = self.maximum = None
        self.bins = [0] * 65

    def add(self, size):
        self.count += 1
        self.total += size
        self.minimum = size if self.minimum is None else min(self.minimum, size)
        self.maximum = size if self.maximum is None else max(self.maximum, size)
        self.bins[size.bit_length()] += 1

    def report(self):
        return {"count": self.count, "total": self.total,
                "min": self.minimum, "max": self.maximum,
                "bins": [[0 if i == 0 else 1 << (i - 1), (1 << i) - 1, n]
                         for i, n in enumerate(self.bins) if n]}


def family(key):
    if not key:
        return "empty_key"
    if key[0] == 3:
        if len(key) < 22:
            return "account_prefix_short"
        tag = key[21]
        if tag == 3:
            return "typed_balance" if len(key) == 32 else "balance_prefix_other_width"
        if tag == 4:
            return "contract_storage"
        if tag in (0, 5):
            name = "frontier" if tag == 0 else "plasma"
            return name if len(key) == 22 else name + "_other_width"
        if tag in (6, 7):
            return "receive_index_%02d" % tag
        return "account_other"
    if key[0] == 4:
        return "mailbox" if len(key) >= 21 else "mailbox_prefix_short"
    if key[0] == 8:
        return "znn_balance_index"
    return "other_namespace"


def inventory(stream, selected, configured_limits=None):
    """Inventory once with O(max_key_bytes + CHUNK_BYTES) retained input memory.

    Pins and limits are copied before reading. Present-empty records stay
    present. No dictionary of keys, values, addresses or tokens is accumulated.
    """
    caps = limits(configured_limits)
    pin = selection(selected, caps)
    reader = Reader(stream, pin["bytes"])
    stats = {name: {"key_bytes": Sizes(), "raw_value_bytes": Sizes(),
                    "put_wire_bytes": Sizes(), "present_empty_values": 0,
                    "raw_zero32_values": 0, "values_over32": 0} for name in FAMILIES}
    storage_suffix = Sizes()
    top_prefixes, account_prefixes = [0] * 256, [0] * 256
    previous = last_address = None
    records = addresses = 0
    while reader.position < pin["bytes"]:
        require(records < pin["records"], "selection_records")
        start = reader.position
        require(reader.byte() == 1, "put_record_required")
        key_size = reader.length()
        require(key_size <= caps["key_bytes"], "key_size")
        key = reader.take(key_size)
        require(previous is None or key > previous, "key_order")
        value_size = reader.length()
        require(value_size <= caps["value_bytes"], "value_size")
        zero32 = reader.value(value_size)
        name = family(key)
        if key:
            top_prefixes[key[0]] += 1
        if len(key) >= 22 and key[0] == 3:
            account_prefixes[key[21]] += 1
        row = stats[name]
        row["key_bytes"].add(key_size)
        row["raw_value_bytes"].add(value_size)
        row["put_wire_bytes"].add(reader.position - start)
        row["present_empty_values"] += value_size == 0
        row["raw_zero32_values"] += zero32
        row["values_over32"] += value_size > 32
        if name == "contract_storage":
            storage_suffix.add(key_size - 22)
        if name == "typed_balance":
            address = key[1:21]
            if address != last_address:
                addresses += 1
                last_address = address
        previous = key
        records += 1
    require(not reader.raw_read(1), "trailing_input")
    require(reader.hash.hexdigest() == pin["sha256"], "selection_sha256")
    require(records == pin["records"], "selection_records")
    families = {name: {key: value.report() if isinstance(value, Sizes) else value
                       for key, value in row.items()} for name, row in stats.items()}
    return {"format": "zenon-effective-ledger-inventory/v1",
            "status": "SELECTED_STREAM_INVENTORIED", "selection": pin,
            "selection_matched": True, "end_of_stream_observed": True,
            "limits": caps, "records": records, "input_bytes": reader.position,
            "families": families, "storage_suffix_bytes": storage_suffix.report(),
            "top_level_prefix_counts": [["%02x" % i, n] for i, n in enumerate(top_prefixes) if n],
            "account_subprefix_counts": [["%02x" % i, n] for i, n in enumerate(account_prefixes) if n],
            "distinct_typed_balance_addresses": addresses,
            "distinct_tokens_computed": False,
            "byte_accounting": "logical-key/raw-value/canonical-put-wire; not database allocation or proof size",
            "histogram_method": "exact power-of-two inclusive bins [low,high,count]; zero has its own bin",
            "quantile_method": "not computed", "scope": scope()}


def encoded(report):
    raw = (json.dumps(report, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()
    require(len(raw) <= REPORT_BYTES, "report_size")
    return raw


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise Refused("options")


def decimal(value):
    require(type(value) is str and len(value) <= 20 and
            re.fullmatch(r"0|[1-9][0-9]*", value) is not None, "options")
    return int(value)


def main(argv=None, stream=None):
    parser = Parser(description=__doc__)
    parser.add_argument("--expect-bytes", required=True, type=decimal)
    parser.add_argument("--expect-records", required=True, type=decimal)
    parser.add_argument("--expect-sha256", required=True)
    parser.add_argument("--provenance-sha256", required=True,
                        help="digest of the separately protected R1 selection/consistency intake")
    for key, value in DEFAULT_LIMITS.items():
        parser.add_argument("--max-" + key.replace("_", "-"), type=decimal, default=value)
    args = parser.parse_args(argv)
    caps = {key: getattr(args, "max_" + key) for key in DEFAULT_LIMITS}
    pin = {"bytes": args.expect_bytes, "records": args.expect_records,
           "sha256": args.expect_sha256, "provenance_sha256": args.provenance_sha256,
           "record_space": "effective-raw-ledger"}
    return inventory(sys.stdin.buffer if stream is None else stream, pin, caps)


if __name__ == "__main__":
    try:
        result = main()
        sys.stdout.buffer.write(encoded(result))
    except (Refused, OSError, TypeError, ValueError, OverflowError):
        sys.stdout.buffer.write(encoded({"format": "zenon-effective-ledger-inventory/v1",
                                         "status": "UNKNOWN", "reason": "input_or_options_refused",
                                         "selection_matched": False, "scope": scope()}))
        sys.exit(1)
