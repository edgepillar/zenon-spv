# SPDX-License-Identifier: GPL-3.0-only
"""Root-only reconstruction of the selected candidate L1 ledger fold."""

from bisect import bisect_left
from hashlib import sha256, sha3_256


PROFILE = "zenon-l1-balance-storage-sha3/v1"
DEFAULT_LEAVES = 32768
MAX_LEAVES = 100000
DEPTH = 256
ZERO = bytes(32)
VALUE_CHUNK_BYTES = 64 << 10


class Refused(ValueError):
    """A static projection reason with no raw ledger data."""


def frontier_value(frontier):
    """Encode the selected layout's logical HashHeight protobuf value."""
    raw = bytearray(b"\x0a\x22\x0a\x20" + bytes.fromhex(frontier["hash"]))
    height = frontier["height"]
    if height:
        raw.append(0x10)
        while height >= 128:
            raw.append((height & 127) | 128)
            height >>= 7
        raw.append(height)
    return bytes(raw)


def root_from_digests(leaves):
    """Sort owned path/digest pairs in place and fold only the root."""
    if not leaves:
        return ZERO
    leaves.sort()
    for index in range(1, len(leaves)):
        if leaves[index - 1][0] == leaves[index][0]:
            raise Refused("projection_path_collision")

    def fold(start, end, height):
        path, root = leaves[start]
        first_parent = 0
        if end - start > 1:
            # Above the highest differing bit every path in this range is
            # identical. Split once, then fold the shared unary ancestors.
            split_bit = (path ^ leaves[end - 1][0]).bit_length() - 1
            right_path = ((path >> split_bit) + 1) << split_bit
            middle = bisect_left(leaves, (right_path,), start + 1, end)
            left = fold(start, middle, split_bit)
            right = fold(middle, end, split_bit)
            root = ZERO if left == right == ZERO else sha3_256(left + right).digest()
            first_parent = split_bit + 1
        for bit in range(first_parent, height):
            if root == ZERO:
                break
            root = sha3_256(ZERO + root if (path >> bit) & 1 else root + ZERO).digest()
        return root

    return fold(0, len(leaves), DEPTH)


class Projector:
    def __init__(self, expected_root, max_leaves, frontier):
        self.expected_root = expected_root
        self.max_leaves = max_leaves
        self.frontier_value = frontier_value(frontier)
        self.frontier_matched = False
        self.leaves = []
        self.mapping = sha256()
        self.balance_leaves = self.empty_records = 0

    def read_value(self, reader, key, size):
        if key == b"\x00":
            if size != len(self.frontier_value) or reader.take(size) != self.frontier_value:
                raise Refused("projection_frontier_mismatch")
            self.frontier_matched = True
            return False
        if len(key) < 22 or key[0] != 3 or key[21] not in (3, 4):
            return reader.value(size)
        if size == 0:
            self.empty_records += 1
            return False
        if len(self.leaves) == self.max_leaves:
            raise Refused("projection_leaf_limit")
        path = sha3_256(key).digest()
        leaf = sha3_256(path)
        # Match the separately recorded projection mapping encoding. Raw keys
        # arrive in canonical order, so a second sort or value map is unnecessary.
        self.mapping.update(len(key).to_bytes(8, "big") + key + size.to_bytes(8, "big"))
        remaining = size
        zero32 = False
        while remaining:
            chunk = reader.take(min(VALUE_CHUNK_BYTES, remaining))
            leaf.update(chunk)
            self.mapping.update(chunk)
            if size == 32:
                zero32 = chunk == ZERO
            remaining -= len(chunk)
        self.leaves.append((int.from_bytes(path, "big"), leaf.digest()))
        self.balance_leaves += key[21] == 3
        return zero32

    def finish(self):
        if not self.frontier_matched:
            raise Refused("projection_frontier_missing")
        root = root_from_digests(self.leaves).hex()
        if root != self.expected_root:
            raise Refused("projection_root_mismatch")
        return {"profile": PROFILE, "qualification": "MATH_ONLY",
                "expected_root": self.expected_root, "computed_root": root,
                "mapping_sha256": self.mapping.hexdigest(), "leaves": len(self.leaves),
                "balance_prefix_leaves": self.balance_leaves,
                "contract_storage_leaves": len(self.leaves) - self.balance_leaves,
                "empty_folded_records": self.empty_records, "max_leaves": self.max_leaves,
                "value_files_written": 0, "raw_frontier_metadata_matched": True,
                "accepted_header_binding": False,
                "excluded_state_authenticated": False}
