#!/usr/bin/env python3
"""Type and field-boundary controls for independent node-byte checkers.

All successful cases use unchanged node-produced fixtures. Corruption controls
retain their original hashes and signatures; no signing, node, wallet or RPC
implementation is invoked. These checks establish offline serialization only.
"""

import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


HERE = Path(__file__).resolve().parent
CORPUS_DIR = HERE.parents[1] / "internal/testdata/conformance"
sys.path.insert(0, str(HERE))

import check as CHECKER
from check_account import check_account


def load_checker(filename):
    spec = importlib.util.spec_from_file_location(filename.replace("-", "_"), HERE / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SCALING = load_checker("check-content-scaling.py")
LINKED = {
    name: load_checker("check-" + name + ".py")
    for name in ("account-segments", "contract-batches", "delayed-inclusion")
}


def corpus(name):
    return json.loads((CORPUS_DIR / (name + ".json")).read_text(encoding="utf-8"))


def with_corpus_file(value, action):
    with tempfile.TemporaryDirectory(prefix="node-byte-control-") as directory:
        path = Path(directory) / "corpus.json"
        path.write_text(json.dumps(value), encoding="utf-8")
        with contextlib.redirect_stdout(io.StringIO()):
            return action(path)


def check_momentum_corpus(value):
    def action(path):
        with mock.patch.object(sys, "argv", [str(HERE / "check.py"), str(path)]):
            CHECKER.main()
    return with_corpus_file(value, action)


def redistributed_content_vector(original):
    """Redistribute 28 bytes without changing the concatenated preimage."""
    vector = copy.deepcopy(original)
    wire_rows, projected = vector["momentum"]["content"], vector["content"]
    previous, last = projected[-2:]
    tail_hash = bytes.fromhex(last["hash"])
    enlarged = (bytes.fromhex(previous["hash"]) + bytes.fromhex(last["address"]) +
                last["height"].to_bytes(8, "big")).hex()
    previous["hash"] = wire_rows[-2]["hash"] = enlarged
    last["address"] = tail_hash[:20].hex()
    last["height"] = wire_rows[-1]["height"] = int.from_bytes(tail_hash[20:28], "big")
    last["hash"] = wire_rows[-1]["hash"] = tail_hash[28:].hex()
    wire_rows[-1]["address"] = "z1mm8h3t7c7aqx3lt0t05hg8jgw3r2rjhjth0tfz"
    return vector


class ByteRepresentationChecks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.momentum = corpus("momentum-v1-v2")
        cls.amounts = corpus("account-amounts")
        cls.scaling = corpus("content-scaling")
        cls.accounts = corpus("account-segments")
        cls.v1 = cls.momentum["vectors"][0]

    def reject_vector(self, vector):
        with self.assertRaises(ValueError):
            CHECKER.check_vector(vector)

    def test_all_unchanged_momentum_vectors(self):
        vectors = (self.momentum["vectors"] + self.momentum["chain"]["vectors"] +
                   self.momentum["transition"]["vectors"])
        self.assertEqual(len(vectors), 21)
        for vector in vectors:
            with self.subTest(vector=vector["name"]):
                CHECKER.check_vector(vector)
        check_momentum_corpus(self.momentum)

    def test_all_unchanged_amount_vectors(self):
        self.assertEqual(len(self.amounts["vectors"]), 7)
        by_name = {vector["name"]: vector for vector in self.amounts["vectors"]}
        for vector in self.amounts["vectors"]:
            with self.subTest(vector=vector["name"]):
                self.assertEqual(check_account(vector["block"], vector["rpc"]),
                                 bytes.fromhex(vector["amount_bytes"]))
        self.assertLess(by_name["negative-alias"]["block"]["amount"], 0)
        self.assertEqual(by_name["negative-alias"]["amount_bytes"], by_name["ordinary"]["amount_bytes"])
        self.assertGreater(len(bytes.fromhex(by_name["wide-1025-bit-value"]["amount_bytes"])), 32)

    def test_uint64_boundaries_are_exact_eight_bytes(self):
        self.assertEqual(CHECKER.uint64(0), b"\x00" * 8)
        self.assertEqual(CHECKER.uint64(2**64 - 1), b"\xff" * 8)

    def test_uint64_rejects_non_unsigned_integer_values(self):
        for value in (-1, 2**64, True, False, 0.0, 1.0, 0.5, "0", None, [], {}, b"0"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    CHECKER.uint64(value)

    def test_hash_fields_are_exactly_32_parsed_bytes(self):
        self.assertEqual(CHECKER.hash_bytes("12" * 32), b"\x12" * 32)
        for value in ("ab" * 31, "ab" * 33, "gg" * 32, "ab" * 16 + " " * 32,
                      True, None, b"ab" * 32):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    CHECKER.hash_bytes(value)

    def test_momentum_unsigned_fields_on_each_projection(self):
        for side in ("momentum", "header"):
            for field in ("version", "chainIdentifier", "height", "timestamp"):
                original = self.v1[side][field]
                aliases = [float(original)]
                if original in (0, 1):
                    aliases.append(bool(original))
                for value in aliases:
                    with self.subTest(side=side, field=field, value=value):
                        vector = copy.deepcopy(self.v1)
                        vector[side][field] = value
                        self.reject_vector(vector)

    def test_v1_unhashed_prices_on_each_projection(self):
        for side in ("momentum", "header"):
            for field in ("nextFusionPrice", "nextWorkPrice"):
                for value in (False, 0.0):
                    with self.subTest(side=side, field=field, value=value):
                        vector = copy.deepcopy(self.v1)
                        self.assertEqual(vector[side][field], 0)
                        vector[side][field] = value
                        self.reject_vector(vector)

    def test_v1_unhashed_prices_still_require_uint64(self):
        # Equal projections cannot legalize an un-hashed price's type or range.
        for field in ("nextFusionPrice", "nextWorkPrice"):
            for value in (-1, 2**64, True, 1.0, "0", None):
                with self.subTest(field=field, value=value):
                    vector = copy.deepcopy(self.v1)
                    vector["momentum"][field] = vector["header"][field] = value
                    self.reject_vector(vector)

    def test_content_heights_on_each_projection(self):
        original = self.accounts["chain"]["vectors"][2]
        self.assertEqual(original["momentum"]["content"][0]["height"], 1)
        for side in ("momentum", "projection"):
            for value in (True, 1.0):
                with self.subTest(side=side, value=value):
                    vector = copy.deepcopy(original)
                    rows = vector["momentum"]["content"] if side == "momentum" else vector["content"]
                    rows[0]["height"] = value
                    self.reject_vector(vector)

    def test_redistributed_content_widths_preserve_signed_preimage(self):
        original = self.momentum["vectors"][2]
        self.assertEqual(original["name"], "v1-sorted-content")
        vector = redistributed_content_vector(original)
        self.assertEqual(vector["header"], original["header"])
        for field, value in original["momentum"].items():
            if field != "content":
                self.assertEqual(vector["momentum"][field], value)
        self.assertEqual([len(bytes.fromhex(row["hash"])) for row in vector["content"][-2:]], [60, 4])
        self.assertEqual(CHECKER.address_bytes(vector["momentum"]["content"][-1]["address"]).hex(),
                         vector["content"][-1]["address"])

        def rows(value):
            return [bytes.fromhex(row["address"]) + row["height"].to_bytes(8, "big") +
                    bytes.fromhex(row["hash"]) for row in value["content"]]

        before, after = rows(original), rows(vector)
        self.assertEqual(after, sorted(after))
        self.assertEqual(b"".join(before), b"".join(after))
        self.assertEqual(CHECKER.digest(b"".join(after)).hex(), original["header"]["contentHash"])
        self.reject_vector(vector)

    def test_account_unsigned_fields_on_each_projection(self):
        original = self.amounts["vectors"][1]
        for side in ("block", "rpc"):
            for field in ("version", "chainIdentifier", "blockType", "height", "fusedPlasma", "difficulty"):
                expected = original[side][field]
                aliases = [float(expected)]
                if expected in (0, 1):
                    aliases.append(bool(expected))
                for value in aliases:
                    with self.subTest(side=side, field=field, value=value):
                        vector = copy.deepcopy(original)
                        vector[side][field] = value
                        with self.assertRaises(ValueError):
                            check_account(vector["block"], vector["rpc"])

    def test_account_acknowledged_height_on_each_projection(self):
        original = self.amounts["vectors"][1]
        for side in ("block", "rpc"):
            with self.subTest(side=side):
                vector = copy.deepcopy(original)
                vector[side]["momentumAcknowledged"]["height"] = float(original[side]["momentumAcknowledged"]["height"])
                with self.assertRaises(ValueError):
                    check_account(vector["block"], vector["rpc"])

    def test_nested_descendant_unsigned_projections(self):
        original = corpus("contract-batches")["segments"][0]["vectors"][2]
        self.assertEqual(len(original["rpc"]["descendantBlocks"]), 2)
        for field in ("version", "chainIdentifier", "blockType", "height", "fusedPlasma", "difficulty"):
            expected = original["rpc"]["descendantBlocks"][0][field]
            aliases = [float(expected)]
            if expected in (0, 1):
                aliases.append(bool(expected))
            for alias in aliases:
                with self.subTest(field=field, value=alias):
                    vector = copy.deepcopy(original)
                    vector["rpc"]["descendantBlocks"][0][field] = alias
                    with self.assertRaises(ValueError):
                        check_account(vector["block"], vector["rpc"])
        vector = copy.deepcopy(original)
        acknowledged = vector["rpc"]["descendantBlocks"][0]["momentumAcknowledged"]
        acknowledged["height"] = float(acknowledged["height"])
        with self.assertRaises(ValueError):
            check_account(vector["block"], vector["rpc"])

        # A deeper scalar control keeps the parent's immediate child hashes
        # unchanged. It makes no claim about the new subtree's ledger validity.
        vector = copy.deepcopy(original)
        deeper = copy.deepcopy(original["rpc"]["descendantBlocks"][1])
        vector["rpc"]["descendantBlocks"][0]["descendantBlocks"].append(deeper)
        deeper["version"] = True
        with self.assertRaises(ValueError):
            check_account(vector["block"], vector["rpc"])

        # The full wrapper compares nested dictionaries with their separately
        # supplied node vectors; numerical equality must not hide these types.
        for field in ("version", "acknowledged_height"):
            with self.subTest(wrapper_field=field):
                value = corpus("contract-batches")
                child = value["segments"][0]["vectors"][2]["rpc"]["descendantBlocks"][0]
                if field == "version":
                    child[field] = True
                else:
                    child["momentumAcknowledged"]["height"] = float(child["momentumAcknowledged"]["height"])
                with self.assertRaises(ValueError):
                    with_corpus_file(value, LINKED["contract-batches"].check)

    def test_compact_reconstructed_header_unsigned_fields(self):
        for field in ("version", "chainIdentifier", "height", "timestamp", "nextFusionPrice", "nextWorkPrice"):
            with self.subTest(field=field):
                value = copy.deepcopy(self.scaling)
                header = value["samples"][0]["headers"][0]
                header[field] = float(header[field])
                with self.assertRaises(ValueError):
                    SCALING.check(value)

    def test_compact_target_height_aliases(self):
        for alias in (True, 1.0):
            with self.subTest(value=alias):
                value = copy.deepcopy(self.scaling)
                self.assertEqual(value["samples"][0]["targets"][0]["height"], 1)
                value["samples"][0]["targets"][0]["height"] = alias
                with self.assertRaises(ValueError):
                    SCALING.check(value)

    def test_compact_member_count_aliases(self):
        for alias in (True, 1.0):
            with self.subTest(value=alias):
                value = copy.deepcopy(self.scaling)
                self.assertEqual(value["samples"][0]["members"], 1)
                value["samples"][0]["members"] = alias
                with self.assertRaises(ValueError):
                    SCALING.check(value)

    def test_compact_anchor_unsigned_fields(self):
        for field in ("chain_id", "height"):
            with self.subTest(field=field):
                value = copy.deepcopy(self.scaling)
                value["anchor"][field] = float(value["anchor"][field])
                with self.assertRaises(ValueError):
                    SCALING.check(value)

    def test_linked_anchor_unsigned_fields(self):
        for series in ("chain", "transition"):
            for field in ("chain_id", "height"):
                with self.subTest(corpus="momentum-v1-v2", series=series, field=field):
                    value = copy.deepcopy(self.momentum)
                    value[series]["anchor"][field] = float(value[series]["anchor"][field])
                    with self.assertRaises(ValueError):
                        check_momentum_corpus(value)
        for name, checker in LINKED.items():
            for field in ("chain_id", "height"):
                with self.subTest(corpus=name, field=field):
                    value = corpus(name)
                    value["chain"]["anchor"][field] = float(value["chain"]["anchor"][field])
                    with self.assertRaises(ValueError):
                        with_corpus_file(value, checker.check)

    def test_linked_activation_height_aliases(self):
        value = copy.deepcopy(self.momentum)
        value["transition"]["v2_from_height"] = float(value["transition"]["v2_from_height"])
        with self.assertRaises(ValueError):
            check_momentum_corpus(value)
        value = corpus("delayed-inclusion")
        value["chain"]["v2_from_height"] = float(value["chain"]["v2_from_height"])
        with self.assertRaises(ValueError):
            with_corpus_file(value, LINKED["delayed-inclusion"].check)

    def test_contract_batch_metadata_aliases(self):
        for field, aliases in (("commit_heights", (True, 1.0)),
                               ("receive_height", (3.0,)),
                               ("previous_height", (False, 0.0))):
            for alias in aliases:
                with self.subTest(field=field, value=alias):
                    value = corpus("contract-batches")
                    batch = value["batches"][0]
                    if field == "commit_heights":
                        batch[field][0] = alias
                    elif field == "previous_height":
                        batch["previous"]["height"] = alias
                    else:
                        batch[field] = alias
                    with self.assertRaises(ValueError):
                        with_corpus_file(value, LINKED["contract-batches"].check)


if __name__ == "__main__":
    unittest.main()
