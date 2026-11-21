#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Check the selected fixture formats and the verification-only report."""
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("first_v3_signature_controls", HERE / "check-first-v3-signatures.py")
CHECK = importlib.util.module_from_spec(spec)
spec.loader.exec_module(CHECK)


class FirstV3SignatureControls(unittest.TestCase):
    def test_legacy_boundary_and_complete_v3_projection(self):
        records = CHECK.select_headers(*CHECK.load_fixtures())
        self.assertEqual([record["height"] for record in records], list(range(1, 15)))
        self.assertTrue(records[0]["unsigned"])
        self.assertEqual([len(record["preimage"]) for record in records[-4:]], [176, 208, 208, 208])
        for record in records[-3:]:
            checks = list(CHECK.checks(record))
            self.assertEqual([expected for _, _, expected in checks], [True, False, False])
            self.assertEqual({name for name, _, _ in checks}, {"original", "without-state-root", "different-state-root"})
            self.assertEqual(len({message for _, message, _ in checks}), 3)

    def test_signed_rpc_projection_requires_the_recorded_header(self):
        boundary, rpc = CHECK.load_fixtures()
        row = rpc["rows"][0]
        wire = json.loads(row["wire_json"])
        wire["nextFusionPrice"] += 1
        row["wire_json"] = json.dumps(wire)
        with self.assertRaisesRegex(CHECK.SIG.Refused, "fixture_rpc_projection"):
            CHECK.select_headers(boundary, rpc)

    def test_every_signed_rpc_header_is_required(self):
        boundary, rpc = CHECK.load_fixtures()
        rpc["rows"].pop(0)
        with self.assertRaisesRegex(CHECK.SIG.Refused, "fixture_rpc_roster"):
            CHECK.select_headers(boundary, rpc)

    def test_backend_refusal_retains_earlier_and_actual_failed_outcomes(self):
        failure = CHECK.SIG.Refused("backend_deadline", {"returncode": None})
        with patch.object(CHECK.SIG, "Backend") as backend:
            backend.return_value.verify.side_effect = [(True, {"returncode": 0}), failure]
            with self.assertRaisesRegex(CHECK.SIG.Refused, "backend_deadline"):
                CHECK.run("selected-openssl", "ab" * 20)
        self.assertEqual([row["height"] for row in failure.outcomes], [2, 3])
        self.assertIs(failure.outcomes[0]["actual"], True)
        self.assertIsNone(failure.outcomes[1]["actual"])
        self.assertIsNone(failure.outcomes[1]["returncode"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
