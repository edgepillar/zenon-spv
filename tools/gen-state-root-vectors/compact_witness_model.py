# SPDX-License-Identifier: GPL-3.0-only
"""Selected-path update oracle with independently derived initial witnesses."""
import hashlib
import struct

ZERO = b"\0" * 32
PATH_BITS = 256
LEAF_BASE = 1 << PATH_BITS


def digest(raw):
    return hashlib.sha3_256(raw).digest()


def parent(a, b):
    return ZERO if a == ZERO and b == ZERO else digest(a + b)


class Forest:
    def __init__(self, root, rows):
        # Binary heap indices encode depth and path in one integer. The
        # leading bit marks depth. Shifting right selects the parent.
        self.nodes = {1: root}
        self.values = {}
        self.positions = set()

        def put(index, value):
            if index in self.nodes:
                assert self.nodes[index] == value
            else:
                self.nodes[index] = value

        for row in rows:
            raw = bytes.fromhex(row["proof"])
            position = bytes.fromhex(row["path"])
            index = LEAF_BASE | int.from_bytes(position, "big")
            assert raw[1:33] == position and raw[0] in (0, 1)
            self.positions.add(position)
            if raw[0]:
                value = bytes.fromhex(row["value"])
                self.values[position] = value
                assert raw[33:65] == digest(position + value)
            else:
                assert raw[33:65] == ZERO and row["value"] is None
            put(index, raw[33:65])
            count = int.from_bytes(raw[97:99], "big")
            offset = 99
            seen = 0
            for height in range(PATH_BITS):
                sibling = ZERO
                if raw[65 + height // 8] & (1 << (7 - height % 8)):
                    sibling = raw[offset:offset + 32]
                    assert len(sibling) == 32 and sibling != ZERO
                    offset += 32
                    seen += 1
                put(index ^ 1, sibling)
                index >>= 1
            assert seen == count

    def update(self, position, value):
        assert position in self.positions and (value is None or type(value) is bytes)
        if value is None:
            self.values.pop(position, None)
        else:
            self.values[position] = value
        index = LEAF_BASE | int.from_bytes(position, "big")
        current = ZERO if value is None else digest(position + value)
        self.nodes[index] = current
        for _ in range(PATH_BITS):
            sibling = self.nodes.get(index ^ 1, ZERO)
            current = parent(sibling, current) if index & 1 else parent(current, sibling)
            index >>= 1
            self.nodes[index] = current
        return current

    def root(self):
        return self.nodes[1]

    def proof(self, position):
        assert position in self.positions
        index = LEAF_BASE | int.from_bytes(position, "big")
        value = self.values.get(position)
        present = position in self.values
        mask = bytearray(32)
        siblings = []
        for height in range(PATH_BITS):
            sibling = self.nodes.get(index ^ 1, ZERO)
            if sibling != ZERO:
                mask[height // 8] |= 1 << (7 - height % 8)
                siblings.append(sibling)
            index >>= 1
        leaf = ZERO if not present else digest(position + value)
        raw = bytes([int(present)]) + position + leaf + bytes(mask) + struct.pack(">H", len(siblings)) + b"".join(siblings)
        return raw + (struct.pack(">I", len(value)) + value if present else b"")
