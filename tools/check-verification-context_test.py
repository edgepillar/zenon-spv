#!/usr/bin/env python3
"""Corruption controls for the synthetic diagnostic context byte encoder."""

import copy
import importlib.util
import json
import pathlib
import struct
import sys
import unittest


# Keep the CI checkout pristine for the subsequent candidate source capture.
sys.dont_write_bytecode = True
ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("context_bytes", ROOT / "tools/check-verification-context.py")
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)
POLICY_LIMITS = (
    "max_bundle_bytes", "max_headers", "max_commitments", "max_flat_evidence_members",
    "max_total_flat_evidence_members", "max_segments", "max_segment_blocks",
    "max_total_segment_blocks", "max_state_value_proofs", "max_state_proof_nodes",
    "max_state_proof_bytes",
)
GOLDEN = {
    "v1": "3f474880411601e44f9978c0b7e1bc1fe78817f421a2b2a50b4b524edaef12f4",
    "v1-schedule-checkpoints": "7951c89b57addd9905a3decf2240dbfca8a0429ad3264d0023149ebab25d8037",
    "v2-retention": "ef9f08a47c655657f2a2bcdce2c2f69f1fda7e53a88f17a887a33555c998be15",
}


def vector(name):
    return json.loads((ROOT / "internal/testdata/verification-context" / (name + ".json")).read_text())


def replace(context, path, value):
    owner = context
    for part in path[:-1]:
        owner = owner[part]
    owner[path[-1]] = value


class ContextByteTests(unittest.TestCase):
    def test_stored_golden_vectors(self):
        for name, expected in GOLDEN.items():
            with self.subTest(vector=name):
                context = vector(name)
                self.assertEqual(context["fingerprint"], expected)
                self.assertEqual(CHECKER.fingerprint(context), expected)

    def test_schema_requires_an_exact_supported_integer(self):
        for value in (True, False, 1.0, 2.0, "1", None, [], {}, -1, 0, 3, 1 << 32, 1 << 64):
            with self.subTest(value=value):
                context = vector("v1")
                context["schema_version"] = value
                with self.assertRaises(ValueError):
                    CHECKER.fingerprint(context)

    def test_unsigned_scalars_require_exact_uint64(self):
        cases = [(name, path) for name in GOLDEN
                 for path in (("anchor", "chain_id"), ("anchor", "height"), ("policy", "w"))]
        cases += [(name, ("protocol_profile", field)) for name in ("v1", "v2-retention")
                  for field in ("valid_through", "v2_from_height")]
        cases += [("v1-schedule-checkpoints", ("checkpoints", i, "height")) for i in range(4)]
        for name, path in cases:
            for value in (True, False, None, "0", 0.0, 1.0, [], {}, -1, 1 << 64):
                with self.subTest(vector=name, field=path, value=value):
                    context = vector(name)
                    replace(context, path, value)
                    with self.assertRaises(ValueError):
                        CHECKER.fingerprint(context)

    def test_profile_version_uses_uint32_before_uint64_encoding(self):
        for name in ("v1", "v2-retention"):
            for value in (True, False, None, "1", 1.0, [], {}, -1, 1 << 32, (1 << 64) - 1):
                with self.subTest(vector=name, value=value):
                    context = vector(name)
                    context["protocol_profile"]["version"] = value
                    with self.assertRaises(ValueError):
                        CHECKER.fingerprint(context)

    def test_policy_limits_use_nonnegative_int64(self):
        for name in GOLDEN:
            fields = POLICY_LIMITS + (("retain_headers",) if name == "v2-retention" else ())
            for field in fields:
                for value in (True, False, None, "0", 0.0, 1.0, [], {}, -1, 1 << 63, (1 << 64) - 1):
                    with self.subTest(vector=name, field=field, value=value):
                        context = vector(name)
                        context["policy"][field] = value
                        with self.assertRaises(ValueError):
                            CHECKER.fingerprint(context)

    def test_zero_and_upper_representation_boundaries(self):
        # Independently checked against Go's typed diagnostic encoder. These
        # scalar ranges do not assert verified-state constructor acceptance.
        for upper, expected in (
            (False, "4e839b81ef8bca5e4cd497224ce0758b166acd81989155203a1d24420d939a8e"),
            (True, "6b360d296d7f5c55c3ce5814e78bd560a8446cacaf65ae68c6fb98b2eb8e83a4"),
        ):
            with self.subTest(upper=upper):
                context = vector("v2-retention")
                u64 = (1 << 64) - 1 if upper else 0
                context["anchor"].update(chain_id=u64, height=u64)
                context["policy"]["w"] = u64
                for field in POLICY_LIMITS + ("retain_headers",):
                    context["policy"][field] = (1 << 63) - 1 if upper else 0
                context["protocol_profile"].update(version=(1 << 32) - 1 if upper else 0,
                                                    valid_through=u64, v2_from_height=u64)
                context["checkpoints"] = [{"height": u64, "header_hash": "ab" * 32}]
                context["producer"]["schedule_hash"] = "cd" * 32
                self.assertEqual(CHECKER.fingerprint(context), expected)

    def test_hashes_require_exact_fixed_width_hexadecimal_strings(self):
        cases = [(name, ("anchor", "header_hash")) for name in GOLDEN]
        cases += [("v1-schedule-checkpoints", ("producer", "schedule_hash"))]
        cases += [("v1-schedule-checkpoints", ("checkpoints", i, "header_hash")) for i in range(4)]
        for name, path in cases:
            for value in (None, True, False, [], {}, b"a" * 32, "", "ab" * 24, "ab" * 31,
                          "ab" * 33, "ab" * 40, "a" * 63, "a" * 65, "gg" * 32,
                          "0x" + "ab" * 32, "ab " * 32, " " + "ab" * 32, "ab" * 32 + "\n"):
                if path == ("producer", "schedule_hash") and value is None:
                    continue  # A nil schedule hash has a separate presence marker.
                with self.subTest(vector=name, field=path, value=value):
                    context = vector(name)
                    replace(context, path, value)
                    with self.assertRaises(ValueError):
                        CHECKER.fingerprint(context)
        for name, expected in GOLDEN.items():
            with self.subTest(uppercase_vector=name):
                context = vector(name)
                context["anchor"]["header_hash"] = context["anchor"]["header_hash"].upper()
                if context["producer"]["schedule_hash"] is not None:
                    context["producer"]["schedule_hash"] = context["producer"]["schedule_hash"].upper()
                for checkpoint in context["checkpoints"]:
                    checkpoint["header_hash"] = checkpoint["header_hash"].upper()
                self.assertEqual(CHECKER.fingerprint(context), expected)
        context = vector("v1-schedule-checkpoints")
        context["producer"]["schedule_hash"] = None
        self.assertNotEqual(CHECKER.fingerprint(context), GOLDEN["v1-schedule-checkpoints"])

    def test_checkpoint_hash_width_redistribution_is_rejected(self):
        context = vector("v1-schedule-checkpoints")
        first, second = context["checkpoints"][:2]
        original = (bytes.fromhex(first["header_hash"]) + struct.pack(">Q", second["height"])
                    + bytes.fromhex(second["header_hash"]))
        raw = bytes.fromhex(second["header_hash"])
        first["header_hash"] += struct.pack(">Q", second["height"]).hex()
        second.update(height=int.from_bytes(raw[:8], "big"), header_hash=raw[8:].hex())
        moved = (bytes.fromhex(first["header_hash"]) + struct.pack(">Q", second["height"])
                 + bytes.fromhex(second["header_hash"]))
        self.assertEqual(original, moved)
        self.assertEqual((len(first["header_hash"]), len(second["header_hash"])), (80, 48))
        with self.assertRaises(ValueError):
            CHECKER.fingerprint(context)

    def test_valid_typed_byte_mutations_change_the_fingerprint(self):
        changes = (("anchor", "chain_id"), ("anchor", "height"), ("policy", "w"),
                   ("protocol_profile", "valid_through"), ("protocol_profile", "v2_from_height"))
        changes += tuple(("policy", field) for field in POLICY_LIMITS)
        for path in changes:
            with self.subTest(field=path):
                context = vector("v1")
                owner = context[path[0]]
                owner[path[1]] += 1
                self.assertNotEqual(CHECKER.fingerprint(context), GOLDEN["v1"])
        context = vector("v1-schedule-checkpoints")
        context["checkpoints"][0]["header_hash"] = "ab" * 32
        self.assertNotEqual(CHECKER.fingerprint(context), GOLDEN["v1-schedule-checkpoints"])

    def test_presentation_and_excluded_metadata_remain_outside_the_hash(self):
        for name, expected in GOLDEN.items():
            with self.subTest(vector=name):
                context = vector(name)
                before = copy.deepcopy(context)
                context["fingerprint"] = "PRIVATE_EXPECTED_LABEL"
                context["fingerprint_status"] = "PRIVATE_DIAGNOSTIC_LABEL"
                context["private_metadata"] = "PRIVATE_PATH_LABEL"
                if context["protocol_profile"] is not None:
                    context["protocol_profile"]["source"] = "PRIVATE_PROVENANCE_LABEL"
                self.assertEqual(CHECKER.fingerprint(context), expected)
                self.assertEqual(CHECKER.fingerprint(before), expected)


if __name__ == "__main__":
    unittest.main()
