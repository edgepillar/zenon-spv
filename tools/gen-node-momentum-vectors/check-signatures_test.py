#!/usr/bin/env python3
"""Corpus selection, unsigned semantics, backend failure and privacy controls.

Tests use unchanged node-produced data and controller simulations. The separate
check-signatures.py command performs real OpenSSL verification in every CI job.
No generator, signing or live network operation is used here.
"""

import base64
import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("signature_checker", HERE / "check-signatures.py")
CHECKER = importlib.util.module_from_spec(spec)
spec.loader.exec_module(CHECKER)
CORPUS_DIR = HERE.parents[1] / "internal/testdata/conformance"


def corpus(name):
    return json.loads((CORPUS_DIR / (name + ".json")).read_text())


def process(code, stdout=b"", stderr=b""):
    return subprocess.CompletedProcess(["simulated-backend"], code, stdout, stderr)


class SignatureControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows, cls.identities = CHECKER.collect(CORPUS_DIR)
        cls.user = next(row for row in cls.rows if row["kind"] == "account" and not row["unsigned"])

    def test_all_corpora_keep_signed_unsigned_and_invalid_scalar_counts(self):
        self.assertEqual(len(self.identities), 7)
        self.assertEqual(len(self.rows), 102)
        self.assertEqual(sum(not r["unsigned"] for r in self.rows), 91)
        self.assertEqual(sum(r["kind"] == "account" and r["unsigned"] for r in self.rows), 10)
        self.assertEqual(sum(r["kind"] == "momentum" and r["unsigned"] for r in self.rows), 1)
        self.assertEqual(sum(r["invalid_amount"] for r in self.rows), 4)
        self.assertTrue(all(not r["unsigned"] for r in self.rows if r["invalid_amount"]))

    def test_checked_account_preimages_preserve_invalid_magnitudes(self):
        vectors = corpus("account-amounts")["vectors"]
        for vector in vectors:
            encoded, preimage = CHECKER.account_bytes(vector["block"], vector["rpc"])
            self.assertEqual(encoded.hex(), vector["amount_bytes"])
            self.assertEqual(CHECKER.BYTES.digest(preimage).hex(), vector["block"]["hash"])
        self.assertGreater(len(CHECKER.account_bytes(vectors[5]["block"], vectors[5]["rpc"])[0]), 32)

    def test_boolean_amount_cannot_alias_integer_zero(self):
        vector = copy.deepcopy(corpus("account-amounts")["vectors"][0])
        vector["block"]["amount"] = False
        with self.assertRaises(ValueError):
            CHECKER.account_bytes(vector["block"], vector["rpc"])

    def test_duplicate_json_member_is_refused(self):
        with self.assertRaises(CHECKER.Refused):
            CHECKER.parse(b'{"format_version":1,"format_version":1}')

    def test_bool_format_and_wrong_node_source_are_refused(self):
        original = corpus("momentum-v1-v2")
        for field, value in (("format_version", True), ("source", {"commit": "00" * 20})):
            altered = copy.deepcopy(original)
            altered[field] = value
            with self.assertRaises(CHECKER.Refused):
                CHECKER.parse(json.dumps(altered).encode())

    def test_missing_user_signature_is_not_an_unsigned_exemption(self):
        vector = copy.deepcopy(corpus("account-segments")["segments"][0]["vectors"][0])
        for field in ("publicKey", "signature"):
            altered = copy.deepcopy(vector["block"])
            altered[field] = ""
            _, preimage = CHECKER.account_bytes(vector["block"], vector["rpc"])
            with self.assertRaises(CHECKER.Refused):
                CHECKER.record("user", "account", altered, preimage)

    def test_embedded_account_must_remain_unsigned(self):
        vector = corpus("account-segments")["segments"][1]["vectors"][0]
        block = copy.deepcopy(vector["block"])
        _, preimage = CHECKER.account_bytes(block, vector["rpc"])
        block["signature"] = base64.b64encode(self.user["signature"]).decode()
        with self.assertRaises(CHECKER.Refused):
            CHECKER.record("embedded", "account", block, preimage, unsigned=True)

    def test_changed_envelope_cannot_keep_original_claim(self):
        vector = copy.deepcopy(corpus("momentum-v1-v2")["vectors"][0])
        vector["momentum"]["timestamp"] += 1
        vector["header"]["timestamp"] += 1
        with self.assertRaises(ValueError):
            CHECKER.BYTES.check_vector(vector)

    def test_controls_preserve_original_and_make_scalar_noncanonical(self):
        original = copy.deepcopy(self.user)
        cases = list(CHECKER.variants(self.user))
        self.assertEqual(self.user, original)
        self.assertEqual(len(cases), 6)
        self.assertEqual(cases[0][1:3], (self.user["message"], self.user["signature"]))
        self.assertGreaterEqual(int.from_bytes(cases[-1][2][32:], "little"), CHECKER.ORDER)
        self.assertTrue(all(not expected for _, _, _, expected in cases[1:]))

    def test_backend_diagnostic_error_is_not_a_signature_rejection(self):
        for code, stdout, stderr in ((1, b"", b"private backend/path unavailable"),
                                     (2, b"Signature Verification Failure\n", b""),
                                     (0, b"Signature Verified Successfully\n", b"private warning")):
            with self.assertRaises(CHECKER.Refused):
                CHECKER.outcome(process(code, stdout, stderr))

    def test_backend_crlf_streams_keep_expected_semantics(self):
        self.assertTrue(CHECKER.outcome(process(0, b"Signature Verified Successfully\r\n")))
        self.assertFalse(CHECKER.outcome(process(1, b"Signature Verification Failure\r\n")))

    def test_malformed_widths_fail_before_backend_or_staging(self):
        backend = CHECKER.Backend.__new__(CHECKER.Backend)
        backend.call = mock.Mock(side_effect=AssertionError("must not invoke backend"))
        with tempfile.TemporaryDirectory() as temporary:
            backend.root = Path(temporary)
            for key, message, sig in ((self.user["key"][:-1], self.user["message"], self.user["signature"]),
                                      (self.user["key"], self.user["message"], self.user["signature"][:-1]),
                                      (self.user["key"], b"", self.user["signature"]),
                                      (self.user["key"], self.user["message"], self.user["signature"] + b"\0")):
                with self.assertRaises(CHECKER.Refused):
                    backend.verify(key, message, sig)
            backend.call.assert_not_called()
            self.assertEqual(list(backend.root.iterdir()), [])

    def test_backend_failure_keeps_safe_actual_exit_and_stream_hashes(self):
        backend = CHECKER.Backend.__new__(CHECKER.Backend)
        backend.call = mock.Mock(return_value=process(1, b"", b"private error path"))
        with tempfile.TemporaryDirectory() as temporary:
            backend.root = Path(temporary)
            with self.assertRaises(CHECKER.Refused) as raised:
                backend.verify(self.user["key"], self.user["message"], self.user["signature"])
            self.assertEqual(raised.exception.details["returncode"], 1)
            self.assertEqual(raised.exception.details["stderr_sha256"], CHECKER.sha(b"private error path"))
            self.assertNotIn("private", json.dumps(raised.exception.details))
            self.assertEqual((backend.root / "public-key.der").read_bytes(), CHECKER.SPKI_PREFIX + self.user["key"])
            backend.call.assert_called_once_with(CHECKER.OPERATION)

    def test_backend_deadline_is_a_failure_with_safe_partial_streams(self):
        backend = CHECKER.Backend.__new__(CHECKER.Backend)
        backend.path, backend.root, backend.env = Path(sys.executable), HERE, {}
        failure = subprocess.TimeoutExpired(["backend"], 20, output=b"partial", stderr=b"private")
        with mock.patch.object(CHECKER.subprocess, "run", side_effect=failure):
            with self.assertRaises(CHECKER.Refused) as raised:
                backend.call(CHECKER.OPERATION)
        self.assertEqual(raised.exception.stage, "backend_deadline")
        self.assertIsNone(raised.exception.details["returncode"])

    def test_clean_backend_environment_and_version_gate(self):
        with tempfile.TemporaryDirectory() as temporary:
            with mock.patch.object(CHECKER.subprocess, "run", return_value=process(0, b"OpenSSL 3.6.3 9 Jun 2026\n")) as run:
                with mock.patch.dict(os.environ, {"OPENSSL_MODULES": "private-provider", "OPENSSL_CONF": "private-config"}):
                    backend = CHECKER.Backend(sys.executable, Path(temporary))
            self.assertEqual(backend.version, "3.6.3")
            environment = run.call_args.kwargs["env"]
            self.assertNotIn("OPENSSL_MODULES", environment)
            self.assertEqual(environment["OPENSSL_CONF"], str(Path(temporary) / "empty.cnf"))
            self.assertEqual(run.call_args.kwargs["stdin"], subprocess.DEVNULL)
            self.assertEqual(run.call_args.kwargs["timeout"], 20)
            with mock.patch.object(CHECKER.subprocess, "run", return_value=process(0, b"LibreSSL 3.3.6\n")):
                with self.assertRaises(CHECKER.Refused):
                    CHECKER.Backend(sys.executable, Path(temporary))

    def test_launch_failure_has_no_invented_backend_returncode(self):
        backend = CHECKER.Backend.__new__(CHECKER.Backend)
        backend.path, backend.root, backend.env = Path(sys.executable), HERE, {}
        with mock.patch.object(CHECKER.subprocess, "run", side_effect=OSError("private launch path")):
            with self.assertRaises(CHECKER.Refused) as raised:
                backend.call(CHECKER.OPERATION)
        self.assertEqual(raised.exception.stage, "backend_launch")
        self.assertIsNone(raised.exception.details["returncode"])
        self.assertNotIn("private", json.dumps(raised.exception.details))

    def test_final_identity_failure_retains_completed_process_outcomes(self):
        for failure in (CHECKER.Refused("backend_changed"), OSError("private executable path")):
            backend = mock.Mock()
            backend.verify.side_effect = [(expected, {"returncode": 0 if expected else 1,
                "stdout_sha256": CHECKER.sha(b"simulated"), "stderr_sha256": CHECKER.sha(b"")})
                for _, _, _, expected in CHECKER.variants(self.user)]
            backend.identity.side_effect = failure
            with mock.patch.object(CHECKER, "collect", return_value=([self.user], self.identities)):
                with mock.patch.object(CHECKER, "Backend", return_value=backend):
                    with self.assertRaises(CHECKER.Refused) as raised:
                        CHECKER.run(CORPUS_DIR, "simulated-backend")
            self.assertEqual(len(raised.exception.outcomes), 6)
            self.assertEqual([r["returncode"] for r in raised.exception.outcomes], [0, 1, 1, 1, 1, 1])
            self.assertNotIn("private", json.dumps(raised.exception.outcomes))

    def test_argument_errors_do_not_echo_private_values(self):
        for arguments in (["--unknown-private-argument", "private-value"], ["--open", "private-backend"]):
            stdout, stderr = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                code = CHECKER.main(arguments)
            self.assertEqual(code, 2)
            self.assertEqual(json.loads(stdout.getvalue())["error_stage"], "arguments")
            self.assertNotIn("private", stdout.getvalue() + stderr.getvalue())

    def refused_cli(self, arguments, wanted, command=None):
        command = command or [sys.executable, "-I", "-B", str(HERE / "check-signatures.py"), *arguments]
        process = subprocess.Popen(command,
                                   stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   start_new_session=True)
        try:
            stdout, stderr = process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            if os.name == "posix":
                os.killpg(process.pid, signal.SIGKILL)
            else:
                process.kill()
            process.communicate(timeout=5)
            self.fail("nonregular file blocked before refusal")
        self.assertEqual(process.returncode, 2)
        self.assertEqual(stderr, b"")
        report = json.loads(stdout)
        self.assertEqual(report["error_stage"], wanted)
        self.assertEqual(report["signature_process_outcomes"], 0)
        self.assertEqual(report["outcomes"], [])
        self.assertNotIn("private", stdout.decode())

    @unittest.skipUnless(hasattr(os, "mkfifo"), "native FIFO creation is unavailable")
    def test_real_fifo_inputs_are_refused_without_waiting_for_a_writer(self):
        with tempfile.TemporaryDirectory(prefix="private-fifo-control-") as temporary:
            root = Path(temporary)
            os.mkfifo(root / "momentum-v1-v2.json", 0o600)
            self.refused_cli(["--corpus-dir", str(root), "--openssl", "unavailable-private-backend"], "corpus_file")
            executable = root / "selected-backend"
            os.mkfifo(executable, 0o700)
            self.refused_cli(["--openssl", str(executable)], "backend_identity")
            # Model replacement after a regular precheck, using a real FIFO
            # for open/fstat. Without O_NONBLOCK this owned child would hang.
            ordinary = root / "ordinary.json"
            ordinary.write_bytes(b"ordinary data")
            code = '''import importlib.util, json, os, sys
from pathlib import Path
from unittest import mock
spec = importlib.util.spec_from_file_location("checker", sys.argv[1])
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)
selected = os.stat(sys.argv[3])
try:
    with mock.patch.object(Path, "stat", return_value=selected):
        with checker.regular_file(Path(sys.argv[2]), 1024, "corpus_file"):
            raise AssertionError("special descriptor reached a reader")
except checker.Refused as error:
    print(json.dumps({"error_stage": error.stage, "signature_process_outcomes": 0, "outcomes": []}))
    raise SystemExit(2)
'''
            self.refused_cli([], "corpus_file", [sys.executable, "-I", "-B", "-c", code,
                             str(HERE / "check-signatures.py"), str(root / "momentum-v1-v2.json"), str(ordinary)])

    def test_opened_descriptor_type_is_checked_and_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "input.json"
            path.write_bytes(b"ordinary input")
            actual_fstat = CHECKER.os.fstat
            descriptors = []
            def replaced_descriptor(fd):
                descriptors.append(fd)
                fields = list(actual_fstat(fd))
                fields[0] = stat.S_IFIFO | 0o600
                return os.stat_result(fields)
            with mock.patch.object(CHECKER.os, "fstat", side_effect=replaced_descriptor):
                with self.assertRaises(CHECKER.Refused):
                    with CHECKER.regular_file(path, 1024, "corpus_file"):
                        self.fail("special descriptor reached a reader")
            self.assertEqual(len(descriptors), 1)
            with self.assertRaises(OSError):
                actual_fstat(descriptors[0])

    def test_oversized_corpus_stops_before_parsing_or_backend(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "momentum-v1-v2.json"
            with path.open("wb") as stream:
                stream.truncate(8 * 1024**2 + 1)
            with mock.patch.object(CHECKER, "parse", side_effect=AssertionError("must not parse")):
                with mock.patch.object(CHECKER, "Backend", side_effect=AssertionError("must not launch")):
                    with self.assertRaises(CHECKER.Refused) as raised:
                        CHECKER.run(Path(temporary), "unavailable-backend")
            self.assertEqual(raised.exception.stage, "corpus_file")

    def test_truncated_corpus_read_stops_before_parsing_or_backend(self):
        @contextlib.contextmanager
        def changed_file(*_):
            yield io.BytesIO(b"short"), mock.Mock(st_size=100)
        with mock.patch.object(CHECKER, "regular_file", changed_file):
            with mock.patch.object(CHECKER, "parse", side_effect=AssertionError("must not parse")):
                with mock.patch.object(CHECKER, "Backend", side_effect=AssertionError("must not launch")):
                    with self.assertRaises(CHECKER.Refused) as raised:
                        CHECKER.run(CORPUS_DIR, "unavailable-backend")
        self.assertEqual(raised.exception.stage, "corpus_changed")


if __name__ == "__main__":
    unittest.main()
