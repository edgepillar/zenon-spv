#!/usr/bin/env python3
"""Qualify actual offline observer diagnostics through the standalone reader.

Inputs and expected identities precede execution. Four explicit ordinary Go
binaries use pinned node-generated fixtures and synthetic trust selections;
collection contacts only an owned loopback fixture. No network pilot is run.
"""

import argparse
import copy
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import threading


ROOT = Path(__file__).resolve().parent.parent
READER = Path(__file__).with_name("consume-observer-report.py")
NODE_PATH = Path(__file__).with_name("check-node-query-consumer.py")
spec = importlib.util.spec_from_file_location("observer_node_inputs", NODE_PATH)
node = importlib.util.module_from_spec(spec)
spec.loader.exec_module(node)
MODES = ("local-file", "collected")
COMMANDS = ("verify-commitment", "verify-segment")
VARIANTS = ("actual", "wrong_target", "wrong_pin")


class Failure(ValueError):
    def __init__(self, stage, counts=None):
        self.stage, self.counts = stage, dict(counts or {})
        super().__init__("offline observer consumer qualification failed")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, separators=(",", ":"), sort_keys=True) + "\n").encode()


def require(condition, stage, counts=None):
    if not condition:
        raise Failure(stage, counts)


def selected_inputs():
    # Use the existing independent context/target derivation, not an observed
    # report or a newly collected candidate. Its corpus byte pins are checked.
    program = node.programs()[-1]
    corpus = node.load_corpora()["delayed-inclusion.json"]
    expected = {command: copy.deepcopy(program["expectations"][(5017, command)]) for command in COMMANDS}
    for command in COMMANDS:
        require(len(expected[command]["targets"]) == 6, "selected_targets")
    return program, corpus, expected


class Fixture:
    def __init__(self, corpus):
        owner = self
        self.condition, self.active, self.unexpected = threading.Condition(), 0, 0
        self.requests = {"ledger.getMomentumsByHeight": 0, "ledger.getAccountBlocksByHeight": 0}
        self.momenta = [v["momentum"] for v in corpus["chain"]["vectors"]]
        self.accounts = {s["rpc_address"]: [v["rpc"] for v in s["vectors"]] for s in corpus["segments"]}

        class Server(ThreadingHTTPServer):
            daemon_threads = False

            def process_request(self, request, address):
                with owner.condition:
                    owner.active += 1
                try:
                    super().process_request(request, address)
                except BaseException:
                    with owner.condition:
                        owner.active -= 1
                        owner.condition.notify_all()
                    raise

            def finish_request(self, request, address):
                try:
                    request.settimeout(5)
                    super().finish_request(request, address)
                finally:
                    with owner.condition:
                        owner.active -= 1
                        owner.condition.notify_all()

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_POST(self):
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                    if not 0 < length <= 4096:
                        raise ValueError("request bound")
                    request = json.loads(self.rfile.read(length))
                    method, params = request.get("method"), request.get("params")
                    if request.get("jsonrpc") != "2.0" or type(request.get("id")) is not int:
                        raise ValueError("request identity")
                    if method == "ledger.getMomentumsByHeight" and params in ([5017, 1], [5001, 17]):
                        start, count = params
                        rows = owner.momenta[start - 5001:start - 5001 + count]
                    elif (method == "ledger.getAccountBlocksByHeight" and type(params) is list and len(params) == 3 and
                          type(params[0]) is str and params[0] in owner.accounts and params[1:] == [1, 3]):
                        rows = owner.accounts[params[0]]
                    else:
                        raise ValueError("unselected request")
                    raw = encoded({"jsonrpc": "2.0", "id": request["id"], "result": {"list": rows}})
                    with owner.condition:
                        owner.requests[method] += 1
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(raw)))
                    self.end_headers()
                    self.wfile.write(raw)
                except (OSError, ValueError, TypeError, AttributeError):
                    with owner.condition:
                        owner.unexpected += 1
                    self.send_error(400, "unselected fixture request")

        self.server = Server(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=False)
        self.thread.start()
        self.url = "http://127.0.0.1:%d" % self.server.server_address[1]

    def settled(self):
        with self.condition:
            return self.condition.wait_for(lambda: self.active == 0, timeout=5)

    def close(self):
        settled = self.settled()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(5)
        return settled and not self.thread.is_alive() and self.active == 0


class Runner:
    def __init__(self, binaries):
        self.binaries = binaries
        self.counts = {"seed_attempted": 0, "seed_completed": 0, "observer_attempted": 0,
                       "observer_completed": 0, "reader_attempted": 0, "reader_completed": 0}
        self.environment = {key: value for key, value in os.environ.items()
                            if not key.startswith("ZENON_SPV_") and key.upper() not in {"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"}}

    def child(self, role, arguments, raw=None):
        self.counts[role + "_attempted"] += 1
        command = ([sys.executable, "-I", "-B", str(READER)] if role == "reader" else
                   [str(self.binaries["zenon-spv" if role == "seed" else "observe-block"])]) + arguments
        try:
            result = subprocess.run(command, input=raw, capture_output=True, timeout=30, env=self.environment)
        except (OSError, subprocess.SubprocessError):
            raise Failure("child_completion", self.counts) from None
        self.counts[role + "_completed"] += 1
        require(len(result.stdout) <= 4 << 20 and not result.stderr, "private_child_output", self.counts)
        return result


def qualification(binaries, revision):
    program, corpus, expectations = selected_inputs()
    selected_ids = [mode + "_" + command.removeprefix("verify-") + "_" + variant
                    for mode in MODES for command in COMMANDS for variant in VARIANTS]
    # Freeze the helper and selected binary pins before seed/observer execution.
    paths = {name: Path(path).resolve(strict=True) for name, path in binaries.items()}
    pins = {name: {"sha256": sha(path.read_bytes()), "bytes": path.stat().st_size} for name, path in paths.items()}
    reader_pin = sha(READER.read_bytes())
    runner = Runner(paths)
    rows, outer = [], []
    with tempfile.TemporaryDirectory(prefix="observer-consumer-") as directory:
        root = Path(directory)
        root.chmod(0o700)
        inputs = {}

        def write(name, value):
            path = root / name
            raw = encoded(value)
            path.write_bytes(raw)
            path.chmod(0o600)
            inputs[path] = raw
            return str(path)

        anchor, profile, schedule = [write(name + ".json", program[name]) for name in ("anchor", "profile", "schedule")]
        bundle = write("bundle.json", program["bundle"])
        expected_paths = {}
        for command, expected in expectations.items():
            expected_paths[(command, "actual")] = write(command + ".json", expected)
            changed = copy.deepcopy(expected)
            changed["targets"][0]["account_header"]["hash"] = "2" * 64
            expected_paths[(command, "wrong_target")] = write(command + "-wrong-target.json", changed)
        seed = {key: program["bundle"][key] for key in ("version", "chain_id", "claimed_genesis")}
        seed["headers"] = program["headers"][:17]
        seed_path = write("seed.json", seed)
        state = root / "state.json"
        common = ["--genesis-config", anchor, "--protocol-profile", profile, "--schedule", schedule,
                  "--state", str(state), "--expect-context", program["context"]["fingerprint"], "--window", "low", "--retain-headers", "16"]
        result = runner.child("seed", ["verify-headers", "--json", *common, seed_path])
        require(result.returncode == 0, "seed_result", runner.counts)
        document = json.loads(result.stdout)
        require(document["outcome"] == "ACCEPT" and document["exit_code"] == 0, "seed_report", runner.counts)
        inputs[state] = state.read_bytes()
        lock = Path(str(state) + ".lock")
        if lock.exists():
            inputs[lock] = lock.read_bytes()
        staging = root / "staging"
        staging.mkdir(mode=0o700)
        fixture = Fixture(corpus)
        try:
            def compare(case_id, raw, mode, count, actual, wanted):
                result = runner.child("reader", ["--mode", mode, "--expected-targets", str(count), "--observer-exit-code", str(actual)], raw)
                require(result.returncode == wanted, "reader_decision", runner.counts)
                value = json.loads(result.stdout)
                require(value["status"] == ("matched" if wanted == 0 else "not_matched") and
                        value["checked_targets"] == (count if wanted == 0 else 0), "reader_summary", runner.counts)
                rows.append({"id": case_id, "actual_observer_exit": actual, "expected_targets": count,
                             "reader_exit": result.returncode, "observer_report_sha256": sha(raw), "reader_summary_sha256": sha(result.stdout)})

            for mode in MODES:
                for command in COMMANDS:
                    for variant in VARIANTS:
                        case_id = mode + "_" + command.removeprefix("verify-") + "_" + variant
                        selected = list(common)
                        if variant == "wrong_pin":
                            original = program["context"]["fingerprint"]
                            selected[selected.index("--expect-context") + 1] = ("0" if original[0] != "0" else "1") + original[1:]
                        args = ["--verifier", str(paths["zenon-spv"]), "--verifier-sha256", pins["zenon-spv"]["sha256"],
                                "--consumer", str(paths["consume-query-report"]), "--consumer-sha256", pins["consume-query-report"]["sha256"],
                                "--command", command, *selected, "--private-dir", str(staging),
                                "--expectations", expected_paths[(command, "wrong_target" if variant == "wrong_target" else "actual")]]
                        before = dict(fixture.requests)
                        if mode == "local-file":
                            args += ["--bundle", bundle]
                        else:
                            args += ["--collector", str(paths["fetch-bundle"]), "--collector-sha256", pins["fetch-bundle"]["sha256"],
                                     "--rpc", fixture.url, "--height", "5017", "--count", "16"]
                            if command == "verify-commitment":
                                args += ["--commitments", ",".join(s["rpc_address"] for s in corpus["segments"])]
                            else:
                                args += ["--segments", ",".join(s["rpc_address"] + ":1-3" for s in corpus["segments"])]
                        actual = runner.child("observer", args)
                        wanted = 0 if variant == "actual" else 2
                        require(actual.returncode == wanted, "observer_result", runner.counts)
                        require(fixture.settled() and fixture.unexpected == 0, "fixture_join", runner.counts)
                        require((before != fixture.requests) == (mode == "collected"), "selected_rpc_only", runner.counts)
                        require(all(p.read_bytes() == raw for p, raw in inputs.items()) and not list(staging.iterdir()), "read_only_cleanup", runner.counts)
                        outer.append({"id": case_id, "actual_exit": actual.returncode, "report_sha256": sha(actual.stdout)})
                        count = len(expectations[command]["targets"])
                        compare(case_id + "_actual_status", actual.stdout, mode, count, actual.returncode, wanted)
                        compare(case_id + "_changed_status", actual.stdout, mode, count, 2 if wanted == 0 else 0, 2)
                        if wanted == 0:
                            compare(case_id + "_wrong_count", actual.stdout, mode, count - 1, 0, 2)
                            compare(case_id + "_wrong_mode", actual.stdout, MODES[1] if mode == MODES[0] else MODES[0], count, 0, 2)
                            compare(case_id + "_partial", actual.stdout[:-2], mode, count, 0, 2)
            request_counts = dict(fixture.requests)
            require(request_counts == {"ledger.getMomentumsByHeight": 12, "ledger.getAccountBlocksByHeight": 6}, "fixture_request_counts", runner.counts)
        finally:
            require(fixture.close(), "fixture_completion", runner.counts)
        require([row["id"] for row in outer] == selected_ids and len(rows) == 36, "complete_case_set", runner.counts)
        require(all(p.read_bytes() == raw for p, raw in inputs.items()), "fixed_inputs", runner.counts)
    require(all(sha(path.read_bytes()) == pins[name]["sha256"] for name, path in paths.items()) and
            sha(READER.read_bytes()) == reader_pin, "executable_or_reader_changed", runner.counts)
    return {"schema_version": 1, "status": "offline_observer_consumer_qualified", "source_revision": revision,
            "source_revision_is_caller_asserted": True, "checker_sha256": sha(Path(__file__).read_bytes()),
            "reader_sha256": reader_pin, "node_selector_sha256": sha(NODE_PATH.read_bytes()),
            "corpus_sha256": node.CORPUS_PINS, "executables": pins, "ordinary_observer_outcomes": outer,
            "reader_cases": rows, "process_counts": runner.counts, "reader_decisions": 36,
            "matched": 4, "refused": 32, "controlled_loopback_request_counts": request_counts,
            "all_inputs_and_state_bytes_unchanged_after_seed": True, "all_private_staging_roots_empty": True,
            "fixture_handlers_and_server_joined": True, "external_rpc_calls": 0, "network_pilot": False,
            "synthetic_trust_inputs": True, "independent_human_review": False,
            "canonicality_finality_activation_election_or_state_value_proof": False}


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise Failure("configuration")


def main():
    parser = Parser(description=__doc__, allow_abbrev=False)
    for name in ("observer", "verifier", "consumer", "collector", "source-revision"):
        parser.add_argument("--" + name, required=True)
    try:
        args = parser.parse_args()
        require(re.fullmatch(r"[a-f0-9]{40}", args.source_revision) is not None, "source_selection")
        result = qualification({"observe-block": args.observer, "zenon-spv": args.verifier,
                                "consume-query-report": args.consumer, "fetch-bundle": args.collector}, args.source_revision)
    except (Failure, node.oracle.Invalid, OSError, ValueError, KeyError, TypeError) as error:
        failure = {"schema_version": 1, "status": "offline_observer_consumer_not_qualified",
                   "stage": error.stage if isinstance(error, Failure) else "input_or_shape",
                   "process_counts": error.counts if isinstance(error, Failure) else {}, "network_pilot": False}
        print(json.dumps(failure, sort_keys=True))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
