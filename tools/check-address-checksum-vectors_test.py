"""Corruption controls for the independent address-byte checker."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

PATH = Path(__file__).with_name("check-address-checksum-vectors.py")
SPEC = importlib.util.spec_from_file_location("address_vectors", PATH)
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


class AddressVectorControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.expected = CHECKER.build_vectors(CHECKER.ROOT / "internal/testdata/conformance")

    def changed(self, mutate):
        document = copy.deepcopy(self.expected)
        mutate(document)
        self.assertFalse(CHECKER.validate_document(document, self.expected))

    def test_original(self):
        self.assertTrue(CHECKER.validate_document(self.expected, self.expected))

    def test_decoded_byte(self):
        def change(d):
            value = d["vectors"][0]["decoded_hex"]
            d["vectors"][0]["decoded_hex"] = ("01" if value[:2] != "01" else "02") + value[2:]
        self.changed(change)

    def test_occurrences(self):
        self.changed(lambda d: d["vectors"][0].update(occurrences=0))

    def test_source_pin(self):
        self.changed(lambda d: d["sources"][0].update(sha256="0" * 64))

    def test_schema_boolean(self):
        self.changed(lambda d: d.update(format_version=True))

    def test_occurrence_float(self):
        self.changed(lambda d: d.update(total_occurrences=float(d["total_occurrences"])))

    def test_extra_member(self):
        self.changed(lambda d: d.update(extra="unexpected"))

    def test_missing_vector(self):
        self.changed(lambda d: d["vectors"].pop())

    def test_duplicate_json_member(self):
        with self.assertRaises(ValueError):
            json.loads('{"format_version":1,"format_version":1}', object_pairs_hook=CHECKER.unique_object)

    def test_corrupt_checksum(self):
        address = self.expected["vectors"][0]["encoded"]
        altered = address[:-1] + ("q" if address[-1] != "q" else "p")
        with self.assertRaises(ValueError):
            CHECKER.address_bytes(altered)


if __name__ == "__main__":
    unittest.main()
