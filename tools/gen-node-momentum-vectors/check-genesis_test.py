#!/usr/bin/env python3
"""Corruption controls for the independent historical genesis checker."""

import base64
import copy
import importlib.util
import json
from pathlib import Path
import unittest


MODULE_PATH = Path(__file__).with_name("check-genesis.py")
SPEC = importlib.util.spec_from_file_location("genesis_checker", MODULE_PATH)
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


class HistoricalGenesisChecks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.corpus = json.loads(CHECKER.DEFAULT_CORPUS.read_text(encoding="utf-8"))

    def copy(self):
        return copy.deepcopy(self.corpus)

    def reject(self, corpus):
        with self.assertRaises(ValueError):
            CHECKER.check_corpus(corpus)

    def test_pinned_node_genesis(self):
        self.assertGreater(CHECKER.check_corpus(self.corpus), 0)

    def test_empty_nullable_rpc_fields(self):
        for rpc, projected in ((None, None), ("", ""), (None, ""), ("", None)):
            with self.subTest(rpc=rpc, projected=projected):
                corpus = self.copy()
                corpus["vector"]["momentum"]["data"] = rpc
                for field in ("publicKey", "signature"):
                    corpus["vector"]["momentum"][field] = rpc
                    corpus["vector"]["header"][field] = projected
                self.assertGreater(CHECKER.check_corpus(corpus), 0)

    def test_v1_prices_excluded_from_preimage(self):
        # This is a serialization control, not another generated genesis or
        # evidence that a node would accept nonzero genesis price fields.
        corpus = self.copy()
        for field, value in (("nextFusionPrice", 2**64 - 1), ("nextWorkPrice", 2**53 + 1)):
            corpus["vector"]["momentum"][field] = value
            corpus["vector"]["header"][field] = value
        self.assertGreater(CHECKER.check_corpus(corpus), 0)

    def test_source_and_configuration_pins(self):
        for group, fields in (("source", CHECKER.NODE_SOURCE), ("genesis_config", CHECKER.GENESIS_CONFIG)):
            for field in fields:
                with self.subTest(group=group, field=field):
                    corpus = self.copy()
                    corpus[group][field] = "substituted source"
                    self.reject(corpus)
        for field in ("source", "genesis_config"):
            corpus = self.copy()
            corpus[field]["unexpected"] = "extra"
            self.reject(corpus)

    def test_data_and_digest_corruption(self):
        for field in ("data", "dataHash", "contentHash", "changesHash", "hash"):
            with self.subTest(field=field):
                corpus = self.copy()
                if field == "data":
                    corpus["vector"]["momentum"][field] = base64.b64encode(b"altered data").decode("ascii")
                else:
                    corpus["vector"]["header"][field] = "ab" * 32
                self.reject(corpus)
        corpus = self.copy()
        corpus["vector"]["momentum"]["data"] = "invalid base64!"
        self.reject(corpus)

    def test_consistent_projections_still_require_preimages(self):
        for mutation in ("changes", "claimed hash", "content member"):
            with self.subTest(mutation=mutation):
                corpus = self.copy()
                vector = corpus["vector"]
                if mutation == "changes":
                    vector["momentum"]["changesHash"] = "ab" * 32
                    vector["header"]["changesHash"] = "ab" * 32
                elif mutation == "claimed hash":
                    vector["momentum"]["hash"] = "ab" * 32
                    vector["header"]["hash"] = "ab" * 32
                    corpus["anchor"]["header_hash"] = "ab" * 32
                else:
                    vector["momentum"]["content"][0]["hash"] = "ab" * 32
                    vector["content"][0]["hash"] = "ab" * 32
                self.reject(corpus)

    def test_content_rows_and_order(self):
        for side in ("momentum", "projection"):
            for field, value in (("height", 2), ("hash", "ab" * 32), ("address", "00" * 20)):
                with self.subTest(side=side, field=field):
                    corpus = self.copy()
                    rows = corpus["vector"]["momentum"]["content"] if side == "momentum" else corpus["vector"]["content"]
                    rows[0][field] = value
                    self.reject(corpus)
        for mutation in ("empty", "missing", "reverse", "duplicate"):
            with self.subTest(mutation=mutation):
                corpus = self.copy()
                for rows in (corpus["vector"]["momentum"]["content"], corpus["vector"]["content"]):
                    if mutation == "empty":
                        rows.clear()
                    elif mutation == "missing":
                        rows.pop()
                    elif mutation == "reverse":
                        rows.reverse()
                    else:
                        rows.insert(0, copy.deepcopy(rows[0]))
                self.reject(corpus)

    def test_rpc_address_checksum(self):
        for mutation in ("checksum", "uppercase", "padding"):
            with self.subTest(mutation=mutation):
                corpus = self.copy()
                member = corpus["vector"]["momentum"]["content"][0]
                address = member["address"]
                if mutation == "checksum":
                    member["address"] = address[:-1] + ("q" if address[-1] != "q" else "p")
                elif mutation == "uppercase":
                    member["address"] = address.upper()
                else:
                    member["address"] = address + "q"
                self.reject(corpus)

    def test_anchor_domain_and_hash(self):
        for field, value in (("chain_id", 1), ("height", 2), ("header_hash", "ab" * 32), ("header_hash", "00" * 32)):
            with self.subTest(field=field, value=value):
                corpus = self.copy()
                corpus["anchor"][field] = value
                self.reject(corpus)

    def test_genesis_shape_and_projection(self):
        mutations = (("version", 2), ("chainIdentifier", 1), ("height", 2),
                     ("timestamp", 1666083601), ("previousHash", "ab" * 32))
        for field, value in mutations:
            for both in (False, True):
                with self.subTest(field=field, both=both):
                    corpus = self.copy()
                    corpus["vector"]["momentum"][field] = value
                    if both:
                        corpus["vector"]["header"][field] = value
                    self.reject(corpus)
        corpus = self.copy()
        corpus["vector"]["header"]["nextFusionPrice"] = 1
        self.reject(corpus)

    def test_empty_rpc_field_types_and_bytes(self):
        for field in ("publicKey", "signature", "data"):
            for side in (("momentum",) if field == "data" else ("momentum", "header")):
                for value in (False, 0, [], {}, "!", "AA=="):
                    with self.subTest(field=field, side=side, value=value):
                        corpus = self.copy()
                        corpus["vector"][side][field] = value
                        self.reject(corpus)

    def test_integer_widths_and_boolean_aliases(self):
        for field in ("version", "chainIdentifier", "height", "timestamp", "nextFusionPrice", "nextWorkPrice"):
            for value in (-1, 2**64, True, "1", 1.0, None):
                with self.subTest(field=field, value=value):
                    corpus = self.copy()
                    corpus["vector"]["momentum"][field] = value
                    corpus["vector"]["header"][field] = value
                    self.reject(corpus)
        for field in ("chain_id", "height"):
            corpus = self.copy()
            corpus["anchor"][field] = True
            self.reject(corpus)

    def test_hash_widths_and_encoding(self):
        for field in ("dataHash", "contentHash", "changesHash", "hash", "previousHash"):
            for value in ("ab" * 31, "ab" * 33, "AB" * 32, "gg" * 32, None, "ab " * 32):
                with self.subTest(field=field, value=value):
                    corpus = self.copy()
                    corpus["vector"]["header"][field] = value
                    self.reject(corpus)

    def test_schema_and_required_fields(self):
        for group in ("corpus", "anchor", "vector", "momentum", "header"):
            for mutation in ("extra", "missing"):
                with self.subTest(group=group, mutation=mutation):
                    corpus = self.copy()
                    if group == "corpus":
                        target = corpus
                    elif group in ("anchor", "vector"):
                        target = corpus[group]
                    else:
                        target = corpus["vector"][group]
                    if mutation == "extra":
                        target["unexpected"] = "extra"
                    else:
                        del target[next(iter(target))]
                    self.reject(corpus)
        for value in (True, 2):
            corpus = self.copy()
            corpus["format_version"] = value
            self.reject(corpus)
        corpus = self.copy()
        corpus["vector"]["name"] = "synthetic-genesis"
        self.reject(corpus)


if __name__ == "__main__":
    unittest.main()
