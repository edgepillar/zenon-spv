#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Controlled HTTPS-handler and CLI checks; no live archive or payload files."""

import hashlib
import http.client
import importlib.util
import io
import json
from email.message import Message
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock
import urllib.error
import urllib.request
import urllib.response


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("r1_archive_tail", HERE / "archive_tail.py")
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def selected(size=8):
    return {"url": "https://archive.example.test/selected.zip?opaque=PRIVATE",
            "archive_bytes": 1 << 35, "archive_sha256": "12" * 32,
            "tail_bytes": size, "etag": '"selected-version"'}


class Response:
    def __init__(self, raw=b"abcdefgh", pin=None):
        self.pin = selected(len(raw)) if pin is None else dict(pin)
        self.raw, self.position, self.requests = raw, 0, []
        self.closed, self.status, self.short = False, 206, None
        self.headers = Message()
        self.headers["Content-Range"] = "bytes %d-%d/%d" % (
            self.pin["archive_bytes"] - self.pin["tail_bytes"],
            self.pin["archive_bytes"] - 1, self.pin["archive_bytes"])
        self.headers["Content-Length"] = str(self.pin["tail_bytes"])
        self.headers["ETag"] = self.pin["etag"]

    def geturl(self):
        return self.pin["url"]

    def read(self, requested):
        if not 0 < requested <= 64 << 10:
            raise AssertionError("unbounded read")
        self.requests.append(requested)
        count = requested if self.short is None else min(requested, self.short)
        part = self.raw[self.position:self.position + count]
        self.position += len(part)
        return part

    def close(self):
        self.closed = True


class ArchiveTailTests(unittest.TestCase):
    def check(self, response=None, pin=None, caps=None):
        response = Response() if response is None else response
        pin = selected() if pin is None else pin
        writer = io.BytesIO()
        requests = []

        def opener(request, timeout):
            requests.append((request, timeout))
            return response

        report = tool.fetch(pin, writer, caps, opener)
        return report, writer.getvalue(), requests

    def refuse_before_body(self, response):
        with self.assertRaises(tool.Refused):
            self.check(response)
        self.assertEqual(response.requests, [])
        self.assertTrue(response.closed)

    def test_exact_request_and_literal_tail_receipt(self):
        response = Response()
        report, raw, requests = self.check(response)
        self.assertEqual(raw, b"abcdefgh")
        self.assertEqual(len(requests), 1)
        request, timeout = requests[0]
        self.assertEqual(request.get_method(), "GET")
        self.assertEqual(request.full_url, selected()["url"])
        self.assertEqual(request.get_header("Range"), "bytes=34359738360-34359738367")
        self.assertEqual(request.get_header("If-match"), '"selected-version"')
        self.assertEqual(request.get_header("Accept-encoding"), "identity")
        self.assertEqual(timeout, 15)
        self.assertEqual(report["status"], "SELECTED_TAIL_CAPTURED")
        self.assertEqual(report["tail"], {"offset": (1 << 35) - 8, "bytes": 8, "sha256": sha(raw)})
        self.assertEqual(report["archive"], {"bytes": 1 << 35, "sha256_selection": "12" * 32})
        self.assertTrue(all(v is False for v in report["scope"].values()))
        self.assertNotIn("PRIVATE", json.dumps(report))
        self.assertNotIn("url", report)
        self.assertEqual(response.requests, [8, 1])
        self.assertTrue(response.closed)

    def test_short_reads_are_hashed_and_streamed_once(self):
        response = Response()
        response.short = 1
        report, raw, _ = self.check(response)
        self.assertEqual(raw, b"abcdefgh")
        self.assertEqual(report["tail"]["sha256"], sha(raw))
        self.assertEqual(response.position, 8)
        self.assertEqual(len(response.requests), 9)

    def test_incremental_network_read_is_preferred_to_coalescing_read(self):
        class Incremental(Response):
            def read(self, requested):
                raise AssertionError("coalescing response read selected")

            def read1(self, requested):
                return Response.read(self, requested)

        response = Incremental()
        report, raw, _ = self.check(response)
        self.assertEqual(raw, b"abcdefgh")
        self.assertEqual(report["status"], "SELECTED_TAIL_CAPTURED")
        self.assertEqual(response.requests, [8, 1])

    def test_hard_limit_virtual_tail_uses_bounded_reads(self):
        pin = selected(4 << 20)

        class Virtual(Response):
            def read(self, requested):
                self.assert_bound(requested)
                self.requests.append(requested)
                count = min(requested, pin["tail_bytes"] - self.position)
                self.position += count
                return b"x" * count

            @staticmethod
            def assert_bound(requested):
                if not 0 < requested <= 64 << 10:
                    raise AssertionError("unbounded virtual read")

        class Sink:
            count = 0
            digest = hashlib.sha256()

            def write(self, raw):
                self.count += len(raw)
                self.digest.update(raw)
                return len(raw)

            def flush(self):
                pass

        response, writer = Virtual(b"", pin), Sink()
        report = tool.fetch(pin, writer, {"tail_bytes": 4 << 20, "timeout_seconds": 15},
                            lambda request, timeout: response)
        expected = hashlib.sha256()
        for _ in range(64):
            expected.update(b"x" * (64 << 10))
        self.assertEqual(writer.count, 4 << 20)
        self.assertEqual(report["tail"]["sha256"], expected.hexdigest())
        self.assertEqual(writer.digest.hexdigest(), expected.hexdigest())
        self.assertEqual(len(response.requests), 65)

    def test_invalid_selection_is_refused_before_request(self):
        cases = [("archive_bytes", v) for v in (0, -1, True, 1.0, (1 << 40) + 1)]
        cases += [("tail_bytes", v) for v in (0, True, 1.0, (1 << 20) + 1)]
        cases += [("archive_sha256", v) for v in ("PRIVATE", "A" * 64, 12, "0" * 63)]
        cases += [("etag", v) for v in ('W/"weak"', '"bad\r\nPRIVATE"', "bare", '"' + "x" * 511 + '"', 1)]
        for field, value in cases:
            pin = selected()
            pin[field] = value
            opener = mock.Mock(side_effect=AssertionError("request before admission"))
            with self.subTest(field=field, value=value), self.assertRaises(tool.Refused):
                tool.fetch(pin, io.BytesIO(), opener=opener)
            opener.assert_not_called()
        for pin in ({}, {**selected(), "unknown": 1}, {**selected(), "archive_bytes": 7}):
            with self.assertRaises(tool.Refused):
                tool.fetch(pin, io.BytesIO(), opener=mock.Mock(side_effect=AssertionError))

    def test_invalid_urls_cannot_open_or_disclose_inputs(self):
        urls = ["http://archive.test/a", "file:///PRIVATE", "https://user:PRIVATE@archive.test/a",
                "https:///PRIVATE", "https://archive.test/a#fragment", "https://archive.test/a#",
                " https://archive.test/a", "https://archive.test/PRIVATE\n", "https://archive.test:0/a",
                "https://archive.test:65536/a", "https://archive.test:/a", "https://archive.test/\u2603"]
        for url in urls:
            pin = {**selected(), "url": url}
            with self.subTest(url=url), self.assertRaises(tool.Refused):
                tool.fetch(pin, io.BytesIO(), opener=mock.Mock(side_effect=AssertionError))

    def test_invalid_limits_are_refused_before_request(self):
        for caps in ([], 1, {}, {"tail_bytes": 1, "timeout_seconds": 0},
                     {"tail_bytes": 4 << 20, "timeout_seconds": 61},
                     {"tail_bytes": True, "timeout_seconds": 1},
                     {"tail_bytes": (4 << 20) + 1, "timeout_seconds": 1}):
            with self.subTest(caps=caps), self.assertRaises(tool.Refused):
                tool.fetch(selected(), io.BytesIO(), caps, mock.Mock(side_effect=AssertionError))

    def test_complete_archive_small_enough_for_tail_is_explicit(self):
        pin = {**selected(), "archive_bytes": 8}
        report, raw, requests = self.check(Response(pin=pin), pin)
        self.assertEqual(raw, b"abcdefgh")
        self.assertEqual(requests[0][0].get_header("Range"), "bytes=0-7")
        self.assertFalse(report["scope"]["whole_archive_sha256_verified"])

    def test_full_body_error_redirect_and_unsatisfiable_statuses_are_not_read(self):
        for status in (200, 201, 204, 301, 302, 307, 308, 401, 412, 416, 500):
            response = Response()
            response.status = status
            with self.subTest(status=status):
                self.refuse_before_body(response)

    def test_response_origin_must_remain_selected(self):
        response = Response()
        response.pin["url"] = "https://other.test/PRIVATE"
        self.refuse_before_body(response)

    def test_exact_content_range_admission(self):
        for value in ("bytes 0-7/8", "bytes 34359738360-34359738367/*",
                      "bytes 34359738361-34359738367/34359738368", "bytes 34359738360-34359738368/34359738368",
                      "bytes 034359738360-34359738367/34359738368", "bytes */34359738368"):
            response = Response()
            response.headers.replace_header("Content-Range", value)
            with self.subTest(value=value):
                self.refuse_before_body(response)

    def test_missing_or_duplicate_framing_is_refused(self):
        for name in ("Content-Range", "Content-Length", "ETag"):
            for duplicate in (False, True):
                response = Response()
                if duplicate:
                    response.headers[name.swapcase()] = response.headers[name]
                else:
                    del response.headers[name]
                with self.subTest(name=name, duplicate=duplicate):
                    self.refuse_before_body(response)

    def test_exact_length_and_strong_etag_admission(self):
        for name, value in (("Content-Length", "08"), ("Content-Length", "7"),
                            ("Content-Length", "9"), ("Content-Length", "8, 8"),
                            ("ETag", 'W/"selected-version"'), ("ETag", '"another"')):
            response = Response()
            response.headers.replace_header(name, value)
            with self.subTest(name=name, value=value):
                self.refuse_before_body(response)

    def test_transfer_and_content_encoding_changes_are_not_read(self):
        for name, value in (("Transfer-Encoding", "chunked"), ("Transfer-Encoding", "identity"),
                            ("Content-Encoding", "gzip"), ("Content-Encoding", "identity, identity")):
            response = Response()
            response.headers[name] = value
            with self.subTest(name=name, value=value):
                self.refuse_before_body(response)
        response = Response()
        response.headers["Content-Encoding"] = "identity"
        response.headers["content-encoding"] = "identity"
        self.refuse_before_body(response)
        response = Response()
        response.headers["Content-Encoding"] = "identity"
        self.assertEqual(self.check(response)[1], b"abcdefgh")

    def test_header_admission_caps_and_folded_values(self):
        for field, value in (("X-Oversize", "x" * (16 << 10)), ("X-Folded", "a\n PRIVATE")):
            response = Response()
            response.headers[field] = value
            self.refuse_before_body(response)
        response = Response()
        for i in range(65):
            response.headers["X-Count-" + str(i)] = "x"
        self.refuse_before_body(response)

    def test_truncation_and_extra_body_refuse_without_success(self):
        for raw in (b"abc", b"abcdefghx"):
            response = Response(raw, selected())
            output, diagnostic = io.BytesIO(), io.StringIO()
            code = tool.main(self.arguments(), output, diagnostic, lambda request, timeout: response)
            self.assertEqual(code, 2)
            self.assertEqual(json.loads(diagnostic.getvalue())["status"], "UNKNOWN")
            self.assertLessEqual(len(output.getvalue()), 8)
            self.assertTrue(response.closed)

    def test_nonbyte_and_oversized_reader_results_refuse(self):
        for result in (None, "PRIVATE", bytearray(b"x"), b"x" * 9):
            response = Response()
            response.read = lambda requested: result
            with self.subTest(result=type(result).__name__), self.assertRaises(tool.Refused):
                self.check(response)
            self.assertTrue(response.closed)

    def test_eof_must_be_empty_bytes(self):
        for extra in (None, "", bytearray(), b"x"):
            response = Response()
            original = response.read
            response.read = lambda count: extra if response.position == 8 else original(count)
            with self.subTest(extra=type(extra).__name__), self.assertRaises(tool.Refused):
                self.check(response)
            self.assertTrue(response.closed)

    def test_selection_and_limits_are_frozen_before_open(self):
        pin = selected()
        caps = {"tail_bytes": 8, "timeout_seconds": 15}
        response = Response()

        def opener(request, timeout):
            pin["tail_bytes"] = 100
            pin["etag"] = '"changed"'
            caps["tail_bytes"] = 0
            return response

        raw = io.BytesIO()
        self.assertEqual(tool.fetch(pin, raw, caps, opener)["tail"]["bytes"], 8)
        self.assertEqual(raw.getvalue(), b"abcdefgh")

    def test_elapsed_checks_before_and_after_io(self):
        for ticks in ([0, 16], [0, 0, 16], [0, 0, 0, 0, 16]):
            response = Response()
            iterator = iter(ticks)
            with self.subTest(ticks=ticks), self.assertRaises(tool.Refused):
                tool.fetch(selected(), io.BytesIO(), opener=lambda request, timeout: response,
                           clock=lambda: next(iterator))
        response = Response()
        iterator = iter([0, 0, 0, 0, 0, 0, 0, 16])
        with self.assertRaises(tool.Refused):
            tool.fetch(selected(), io.BytesIO(), opener=lambda request, timeout: response,
                       clock=lambda: next(iterator))

    def test_read_output_and_close_errors_preserve_unknown(self):
        for failure in (OSError("PRIVATE"), http.client.IncompleteRead(b"PRIVATE"), KeyboardInterrupt()):
            response = Response()

            def broken(requested):
                raise failure

            response.read = broken
            raw, diagnostic = io.BytesIO(), io.StringIO()
            code = tool.main(self.arguments(), raw, diagnostic, lambda request, timeout: response)
            self.assertEqual(code, 130 if isinstance(failure, KeyboardInterrupt) else 70)
            self.assertNotIn("PRIVATE", diagnostic.getvalue())
            self.assertEqual(json.loads(diagnostic.getvalue())["status"], "UNKNOWN")
            self.assertTrue(response.closed)

        class Short(io.BytesIO):
            def write(self, raw):
                super().write(raw[:1])
                return 1

        class FlushFailure(io.BytesIO):
            def flush(self):
                raise OSError("PRIVATE")

        for writer in (Short(), FlushFailure()):
            error = io.StringIO()
            code = tool.main(self.arguments(), writer, error, lambda request, timeout: Response())
            self.assertNotEqual(code, 0)
            self.assertEqual(json.loads(error.getvalue())["status"], "UNKNOWN")
            self.assertNotIn("PRIVATE", error.getvalue())

        response = Response()
        response.close = mock.Mock(side_effect=OSError("PRIVATE"))
        error = io.StringIO()
        self.assertEqual(tool.main(self.arguments(), io.BytesIO(), error,
                                   lambda request, timeout: response), 70)
        self.assertEqual(json.loads(error.getvalue())["status"], "UNKNOWN")
        self.assertNotIn("PRIVATE", error.getvalue())

    def test_diagnostic_failure_cannot_return_success(self):
        class Broken(io.StringIO):
            def write(self, value):
                return 1

        self.assertEqual(tool.main(self.arguments(), io.BytesIO(), Broken(),
                                   lambda request, timeout: Response()), 70)

        class FailedFlush(io.StringIO):
            def flush(self):
                raise OSError("PRIVATE")

        self.assertEqual(tool.main(self.arguments(), io.BytesIO(), FailedFlush(),
                                   lambda request, timeout: Response()), 70)

    def test_untrusted_exception_text_is_not_a_diagnostic(self):
        for exception in (tool.Refused("PRIVATE"), urllib.error.URLError("PRIVATE"),
                          ValueError("PRIVATE"), TimeoutError("PRIVATE"), RuntimeError("PRIVATE")):
            def opener(request, timeout):
                raise exception
            error = io.StringIO()
            self.assertNotEqual(tool.main(self.arguments(), io.BytesIO(), error, opener), 0)
            self.assertNotIn("PRIVATE", error.getvalue())

    def test_default_opener_has_no_global_install_or_redirect(self):
        request = urllib.request.Request(selected()["url"])
        response = Response()
        fake = mock.Mock()
        fake.open.return_value = response
        with mock.patch.object(tool.urllib.request, "build_opener", return_value=fake) as factory, \
                mock.patch.object(tool.urllib.request, "install_opener", side_effect=AssertionError):
            self.assertIs(tool.https_open(request, 15), response)
        self.assertEqual(factory.call_count, 1)
        self.assertIsInstance(factory.call_args.args[0], tool.NoRedirect)
        fake.open.assert_called_once_with(request, timeout=15)
        self.assertIsNone(tool.NoRedirect().redirect_request(request, None, 302, "", Message(), "https://other.test"))

    def test_default_http_error_is_closed_without_reading_body(self):
        response = Response()
        error = urllib.error.HTTPError(selected()["url"], 302, "PRIVATE", Message(), response)
        fake = mock.Mock()
        fake.open.side_effect = error
        with mock.patch.object(tool.urllib.request, "build_opener", return_value=fake), self.assertRaises(tool.Refused):
            tool.https_open(urllib.request.Request(selected()["url"]), 15)
        self.assertEqual(response.requests, [])
        self.assertTrue(response.closed)

    def arguments(self):
        pin = selected()
        return ["--url", pin["url"], "--archive-bytes", str(pin["archive_bytes"]),
                "--archive-sha256", pin["archive_sha256"], "--tail-bytes", str(pin["tail_bytes"]),
                "--etag", pin["etag"]]

    def test_main_success_keeps_binary_and_receipt_separate(self):
        raw, diagnostic = io.BytesIO(), io.StringIO()
        self.assertEqual(tool.main(self.arguments(), raw, diagnostic, lambda request, timeout: Response()), 0)
        self.assertEqual(raw.getvalue(), b"abcdefgh")
        report = json.loads(diagnostic.getvalue())
        self.assertEqual(report["status"], "SELECTED_TAIL_CAPTURED")
        self.assertNotIn("PRIVATE", diagnostic.getvalue())

    def test_help_and_options_do_not_connect_or_echo(self):
        for args in ([], ["PRIVATE"], self.arguments() + ["--url", "PRIVATE"],
                     self.arguments() + ["--timeout-seconds", "00"],
                     self.arguments() + ["--unknown", "PRIVATE"]):
            raw, error = io.BytesIO(), io.StringIO()
            with self.subTest(args=args):
                self.assertEqual(tool.main(args, raw, error, mock.Mock(side_effect=AssertionError)), 64)
                self.assertEqual(raw.getvalue(), b"")
                self.assertNotIn("PRIVATE", error.getvalue())
        raw, error = io.BytesIO(), io.StringIO()
        self.assertEqual(tool.main(["--help"], raw, error, mock.Mock(side_effect=AssertionError)), 0)
        self.assertEqual(raw.getvalue(), b"")
        self.assertEqual(json.loads(error.getvalue().splitlines()[-1])["status"], "UNKNOWN")

    def test_actual_cli_usage_exits_without_payload_or_network(self):
        for args, expected in (([], 64), (["--help"], 0),
                               (["--url", "file:///PRIVATE"], 64),
                               ([*self.arguments()[:1], "http://archive.test/PRIVATE", *self.arguments()[2:]], 64)):
            result = subprocess.run([sys.executable, "-I", "-B", str(HERE / "archive_tail.py"), *args],
                                    capture_output=True, timeout=10)
            self.assertEqual(result.returncode, expected)
            self.assertEqual(result.stdout, b"")
            self.assertNotIn(b"PRIVATE", result.stderr)
            self.assertEqual(json.loads(result.stderr.splitlines()[-1])["status"], "UNKNOWN")

    def test_actual_entrypoint_with_controlled_https_handler(self):
        # The real entrypoint and stdlib handler/error chain run in a child.
        # Only HTTPS response acquisition is replaced; no live TLS/network claim.
        harness = '''import io, runpy, sys, urllib.request, urllib.response
from email.message import Message
class Fixture(urllib.request.HTTPSHandler):
 def https_open(self, request):
  assert request.get_method() == "GET"
  assert request.get_header("Range") == "bytes=34359738360-34359738367"
  assert request.get_header("If-match") == '"selected-version"'
  headers=Message()
  headers["Content-Range"]="bytes 34359738360-34359738367/34359738368"
  headers["Content-Length"]="8"
  headers["ETag"]='"selected-version"'
  response=urllib.response.addinfourl(io.BytesIO(b"abcdefgh"),headers,request.full_url,206)
  response.msg="Partial Content"
  return response
original=urllib.request.build_opener
urllib.request.build_opener=lambda *handlers: original(*handlers,Fixture())
sys.argv=sys.argv[1:]
runpy.run_path(sys.argv[0],run_name="__main__")
'''
        result = subprocess.run([sys.executable, "-I", "-B", "-c", harness,
                                 str(HERE / "archive_tail.py"), *self.arguments()],
                                capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b"abcdefgh")
        report = json.loads(result.stderr)
        self.assertEqual(report["tail"]["sha256"], sha(result.stdout))
        self.assertFalse(report["scope"]["whole_archive_sha256_verified"])

    def test_actual_entrypoint_refuses_full_response_and_redirect_before_read(self):
        harness = '''import io, runpy, sys, urllib.request, urllib.response
from email.message import Message
status=int(sys.argv[1])
class NeverRead(io.BytesIO):
 def read(self,*args):raise AssertionError("response body consumed before admission")
 read1=read
class Fixture(urllib.request.HTTPSHandler):
 calls=0
 def https_open(self,request):
  self.calls+=1
  assert self.calls==1,"redirect or retry occurred"
  headers=Message()
  headers["Content-Length"]="8"
  headers["Location"]="https://other.example.test/PRIVATE"
  result=urllib.response.addinfourl(NeverRead(b"abcdefgh"),headers,request.full_url,status)
  result.msg="Controlled response"
  return result
original=urllib.request.build_opener
urllib.request.build_opener=lambda *handlers: original(*handlers,Fixture())
sys.argv=sys.argv[2:]
runpy.run_path(sys.argv[0],run_name="__main__")
'''
        for status in (200, 302, 412):
            result = subprocess.run([sys.executable, "-I", "-B", "-c", harness, str(status),
                                     str(HERE / "archive_tail.py"), *self.arguments()],
                                    capture_output=True, timeout=10)
            with self.subTest(status=status):
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(result.stdout, b"")
                report = json.loads(result.stderr)
                self.assertEqual(report["status"], "UNKNOWN")
                self.assertEqual(report["reason"], "http_status")
                self.assertNotIn(b"PRIVATE", result.stderr)

    def test_selected_tail_feeds_the_independent_directory_observer(self):
        import struct
        raw = struct.pack("<4s4H2LH", b"PK\x05\x06", 0, 0, 0, 0, 0, 0, 0)
        pin = {**selected(len(raw)), "archive_bytes": len(raw)}
        report, body, _ = self.check(Response(raw, pin), pin)
        command = [sys.executable, "-I", "-B", str(HERE / "archive_index.py"),
                   "--archive-bytes", str(len(raw)), "--archive-sha256", pin["archive_sha256"],
                   "--tail-bytes", str(len(raw)), "--tail-sha256", report["tail"]["sha256"]]
        result = subprocess.run(command, input=body, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        checked = json.loads(result.stdout)
        self.assertEqual(checked["status"], "SELECTED_DIRECTORY_OBSERVED")
        self.assertFalse(checked["scope"]["whole_archive_sha256_verified"])

    def test_portable_qualification_includes_sources_and_license(self):
        for name in ("archive_tail.py", "archive_tail_test.py"):
            self.assertIn(b"# SPDX-License-Identifier: GPL-3.0-only\n", (HERE / name).read_bytes())
            self.assertIn(name, (HERE / "THIRD_PARTY_NOTICES").read_text())
        license_text = (HERE.parent / "gen-state-root-vectors/LICENSE").read_text()
        self.assertIn("GNU GENERAL PUBLIC LICENSE", license_text)
        self.assertIn("END OF TERMS AND CONDITIONS", license_text)


class RecordingResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.roots, self.subtests = [], {"passed": 0, "failed": 0}

    def addSuccess(self, test):
        super().addSuccess(test)
        self.roots.append({"name": test._testMethodName, "status": "PASS"})

    def addSubTest(self, test, subtest, error):
        super().addSubTest(test, subtest, error)
        self.subtests["passed" if error is None else "failed"] += 1


def run_tests(args):
    destination = None
    if args:
        if len(args) != 2 or args[0] != "--report":
            raise SystemExit("expected optional --report PATH")
        destination = Path(args[1])
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(ArchiveTailTests)
    expected = [test._testMethodName for test in suite]
    result = unittest.TextTestRunner(verbosity=2, resultclass=RecordingResult).run(suite)
    report = {"format": "zenon-r1-archive-tail-tests/v1", "passed": result.wasSuccessful(),
              "selected_roots": expected, "roots": result.roots, "tests_run": result.testsRun,
              "failures": len(result.failures), "errors": len(result.errors),
              "skips": [{"name": test._testMethodName, "reason": reason} for test, reason in result.skipped],
              "subtests": result.subtests, "real_R1_dataset_used": False,
              "live_HTTPS_or_TLS_peer_qualified": False, "root_state_acceptance_enabled": False}
    raw = (json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if destination is not None:
        with destination.open("xb") as stream:
            stream.write(raw)
    sys.stdout.buffer.write(raw)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(run_tests(sys.argv[1:]))
