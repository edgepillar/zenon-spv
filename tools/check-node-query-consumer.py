#!/usr/bin/env python3
"""Check actual compiled offline verifier reports against preselected expectations.

The existing pinned node-generated corpora describe synthetic chains, not a live
network. Python selects targets, tips, activation, schedule and context bytes
before either trusted executable runs. No RPC, wallet or deployment is used.
"""

import argparse
import base64
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("node_consumer_oracle", Path(__file__).with_name("check-query-consumer.py"))
oracle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(oracle)

NODE_COMMIT = "3a4131e63881058b6ce2ee81d3a41d0033fafc99"
CORPUS_PINS = {
    "contract-batches.json": "d85809454d0e8c3cf21aed055ef3e6b0668d89c2923e2a41021b3713f1e9dcdf",
    "delayed-inclusion.json": "97b2278c2dbf4368281fae4cf3013e8160830d64d7103903b1ebc1292b06183f",
}
DEFAULT_LIMITS = (64 << 20, 100000, 10000, 100000, 1000000, 1000,
                  10000, 100000, 1000, 1024, 4 << 20)
COMMANDS = ("verify-commitment", "verify-segment")
VARIANTS = ("actual", "restart", "reordered", "wrong_target", "wrong_context",
            "missing_row", "tampered_context", "pin_failure", "prior_report_failed_process")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def schedule_from_corpus(corpus):
    # The substantive schedule encoding is documented in producer-set-verification.md.
    # Values come only from synthetic fixture headers; this does not authenticate an election.
    vectors = corpus["chain"]["vectors"]
    coverage = [{"from_height": vectors[0]["header"]["height"],
                 "through_height": vectors[-1]["header"]["height"]}]
    entries = []
    for vector in vectors:
        header = vector["header"]
        key = base64.b64decode(header["publicKey"], validate=True)
        if len(key) != 32:
            raise oracle.Invalid("fixture producer key")
        address = b"\x00" + hashlib.sha3_256(key).digest()[:19]
        entries.append({"height": header["height"], "timestamp_unix": header["timestamp"],
                        "producing_addr": address.hex()})
    raw = bytearray(struct.pack(">QQ", corpus["chain"]["anchor"]["chain_id"], len(coverage)))
    for item in coverage:
        raw.extend(struct.pack(">QQ", item["from_height"], item["through_height"]))
    raw.extend(struct.pack(">Q", len(entries)))
    for item in entries:
        raw.extend(struct.pack(">QQ", item["height"], item["timestamp_unix"]))
        raw.extend(bytes.fromhex(item["producing_addr"]))
    return {"chain_id": corpus["chain"]["anchor"]["chain_id"], "coverage": coverage,
            "entries": entries, "generated_at": 0, "source_peers": [], "source_heights": {},
            "schedule_hash": hashlib.sha3_256(raw).hexdigest()}


def load_corpora():
    corpora = {}
    for name, pin in CORPUS_PINS.items():
        raw = (ROOT / "internal/testdata/conformance" / name).read_bytes()
        if len(raw) > 64 << 10 or sha(raw) != pin:
            raise oracle.Invalid("fixture bytes")
        corpus = json.loads(raw)
        if corpus["format_version"] != 1 or corpus["source"]["commit"] != NODE_COMMIT:
            raise oracle.Invalid("fixture provenance")
        corpora[name] = corpus
    return corpora


def select_program(name, corpus, retain=0, delayed=False):
    anchor = copy.deepcopy(corpus["chain"]["anchor"])
    vectors = corpus["chain"]["vectors"]
    context = {"schema_version": 2 if retain else 1, "anchor": anchor,
               "policy": {"w": 6, **dict(zip(oracle.LIMITS, DEFAULT_LIMITS))},
               "protocol_profile": None, "checkpoints": [],
               "producer": {"mode": "Disabled", "source": "None", "kind": "disabled", "schedule_hash": None}}
    if retain:
        context["policy"]["retain_headers"] = retain
    profile = schedule = None
    if delayed:
        profile = {"version": 1, "anchor": anchor, "valid_through": 5019,
                   "v2_from_height": 5009, "source": "synthetic offline consumer profile"}
        context["protocol_profile"] = {key: profile[key] for key in ("version", "valid_through", "v2_from_height")}
        schedule = schedule_from_corpus(corpus)
        context["producer"] = {"mode": "Required", "source": "OperatorAttested", "kind": "schedule",
                               "schedule_hash": schedule["schedule_hash"]}
    context["fingerprint"] = oracle.context_fingerprint(context)
    context["fingerprint_status"] = "available"
    commitments = [{"height": v["header"]["height"], "target": copy.deepcopy(target),
                    "flat": {"sorted_headers": copy.deepcopy(v["content"])}}
                   for v in vectors for target in v["content"]]
    segments = [{"address": s["address"], "blocks": [copy.deepcopy(v["block"]) for v in s["vectors"]]}
                for s in corpus["segments"]]
    bundle = {"version": 1, "chain_id": anchor["chain_id"], "claimed_genesis": anchor["header_hash"],
              "headers": [], "commitments": commitments, "segments": segments}
    trust = ["TRUST_CONFIGURED_ANCHOR", "TRUST_PERSISTED_STATE", "TRUST_RETAINED_WINDOW_DEPTH"]
    if delayed:
        trust += ["TRUST_EXTERNAL_PROTOCOL_PROFILE", "TRUST_EXTERNAL_PRODUCER_SCHEDULE"]
    targets = {}
    targets[COMMANDS[0]] = [{"scope": "commitment", "index": i, "momentum_height": item["height"],
                            "account_header": copy.deepcopy(item["target"])} for i, item in enumerate(commitments)]
    targets[COMMANDS[1]] = [{"scope": "segment", "index": i, "block_index": j,
                            "account_header": {key: block[key] for key in ("address", "height", "hash")}}
                           for i, s in enumerate(segments) for j, block in enumerate(s["blocks"])]
    # Freeze all expected targets and tips before any child or diagnostic is available.
    expectations = {}
    heights = (5016, 5017, 5018, 5019) if delayed else (4009,)
    for height in heights:
        header = vectors[height - anchor["height"] - 1]["header"]
        for command in COMMANDS:
            expectations[(height, command)] = {
                "schema_version": 1, "command": command, "context_fingerprint": context["fingerprint"],
                "verification_tip": {"height": height, "hash": header["hash"]},
                "targets": copy.deepcopy(targets[command]), "required_guarantees": ["CONTENT_INCLUSION"],
                "allowed_trust_assumptions": list(trust),
            }
    return {"id": name, "anchor": anchor, "context": context, "profile": profile, "schedule": schedule,
            "bundle": bundle, "headers": [copy.deepcopy(v["header"]) for v in vectors],
            "expectations": expectations, "retain": retain, "delayed": delayed}


def programs():
    corpora = load_corpora()
    return [select_program("direct_legacy", corpora["contract-batches.json"]),
            select_program("direct_retained", corpora["contract-batches.json"], retain=16),
            select_program("delayed_retained", corpora["delayed-inclusion.json"], retain=16, delayed=True)]


def selected_case_ids():
    ids = [name + "_" + command.removeprefix("verify-") + "_" + variant
           for name in ("direct_legacy", "direct_retained", "delayed_retained")
           for command in COMMANDS for variant in VARIANTS]
    ids += ["delayed_retained_" + command.removeprefix("verify-") + "_" + stage
            for stage in ("before_depth", "oldest_retained", "expired") for command in COMMANDS]
    return ids


class WorkflowFailure(oracle.Invalid):
    def __init__(self, case_id, stage, counts):
        self.details = {"node_consumer_schema_version": 1, "status": "node_consumer_comparison_failed",
                        "case_id": case_id, "stage": stage, "comparison_counts": dict(counts)}
        super().__init__("offline node consumer comparison failed")


class Runner:
    def __init__(self, verifier, consumer):
        self.verifier, self.consumer = verifier, consumer
        self.counts = {"selected": len(selected_case_ids()), "reference_checked": 0,
                       "verifier_attempted": 0, "verifier_completed": 0,
                       "consumer_attempted": 0, "consumer_compared": 0, "skipped": 0}
        self.rows = []

    def require(self, case_id, stage, condition):
        if not condition:
            raise WorkflowFailure(case_id, stage, self.counts)

    def child(self, case_id, kind, arguments):
        self.counts[kind + "_attempted"] += 1
        try:
            result = subprocess.run([str(self.verifier if kind == "verifier" else self.consumer), *arguments],
                                    capture_output=True, timeout=15, check=False)
        except (OSError, subprocess.SubprocessError):
            raise WorkflowFailure(case_id, "child_run", self.counts) from None
        self.counts[kind + ("_completed" if kind == "verifier" else "_compared")] += 1
        self.require(case_id, "child_output", len(result.stdout) <= oracle.REPORT_BYTES and not result.stderr)
        return result

    def compare(self, case_id, raw, expected, process_exit, category, directory):
        wanted = oracle.summary(category, 0 if category else len(expected["targets"]), 2 if category else 0)
        expected_raw = oracle.encoded(expected)
        self.counts["reference_checked"] += 1
        self.require(case_id, "reference_decision", oracle.consume(raw, expected_raw, process_exit) == wanted)
        paths = [directory / "report.json", directory / "expectations.json"]
        for path, data in zip(paths, (raw, expected_raw)):
            path.write_bytes(data)
            path.chmod(0o600)
        result = self.child(case_id, "consumer", ["--report", str(paths[0]), "--expectations", str(paths[1]),
                                                  "--verifier-exit-code", str(process_exit)])
        self.require(case_id, "compiled_decision", (result.returncode, result.stdout) == wanted)
        self.require(case_id, "input_changed", all(p.read_bytes() == data for p, data in zip(paths, (raw, expected_raw))))
        self.rows.append({"id": case_id, "process_exit": process_exit, "exit_code": result.returncode,
                          "category": category, "checked_targets": 0 if category else len(expected["targets"]),
                          "report_sha256": sha(raw), "expectations_sha256": sha(expected_raw),
                          "summary_sha256": sha(result.stdout)})

    def program(self, selected, directory):
        name = selected["id"]
        directory.mkdir(mode=0o700)
        inputs = {}

        def write(filename, value):
            path = directory / filename
            data = oracle.encoded(value)
            path.write_bytes(data)
            path.chmod(0o600)
            inputs[path] = data
            return str(path)

        anchor = write("anchor.json", selected["anchor"])
        query = write("proof-only.json", selected["bundle"])
        state = directory / "state.json"
        config = ["--json", "--window", "low", "--genesis-config", anchor, "--state", str(state)]
        if selected["retain"]:
            config += ["--retain-headers", str(selected["retain"])]
        if selected["profile"] is not None:
            config += ["--protocol-profile", write("profile.json", selected["profile"]),
                       "--schedule", write("schedule.json", selected["schedule"])]
        pin = selected["context"]["fingerprint"]

        def unchanged(case_id, state_raw):
            self.require(case_id, "state_changed", state.read_bytes() == state_raw)
            self.require(case_id, "configuration_changed", all(p.read_bytes() == data for p, data in inputs.items()))

        def extend(start, end):
            case_id = name + "_seed_" + str(end)
            seed = {key: selected["bundle"][key] for key in ("version", "chain_id", "claimed_genesis")}
            seed["headers"] = selected["headers"][start:end]
            path = write("seed-%d.json" % end, seed)
            result = self.child(case_id, "verifier", ["verify-headers", *config, "--expect-context", pin, path])
            self.require(case_id, "seed_completion", result.returncode == 0)
            report = json.loads(result.stdout)
            self.require(case_id, "seed_diagnostic", report["outcome"] == "ACCEPT" and report["exit_code"] == 0)

        def query_result(case_id, command, height, code=0, wrong_pin=False):
            state_raw = state.read_bytes()
            value = (("0" if pin[0] != "0" else "1") + pin[1:]) if wrong_pin else pin
            result = self.child(case_id, "verifier", [command, *config, "--retained-only", "--expect-context", value, query])
            unchanged(case_id, state_raw)
            self.require(case_id, "verifier_completion", result.returncode == code)
            report = json.loads(result.stdout)
            if wrong_pin:
                self.require(case_id, "pin_diagnostic", report["error"]["stage"] == "context_pin" and report["exit_code"] == 70)
                return result
            expected = selected["expectations"][(height, command)]
            self.require(case_id, "selected_report_identity", report["verification_tip"] == expected["verification_tip"] and
                         report["verification_context"] == selected["context"] and
                         report["mode"] == "retained_only" and report["persistence"] == "read_only" and
                         report["exit_code"] == code and report["outcome"] == ("ACCEPT" if code == 0 else "REFUSED") and
                         [r["reference"] for r in report["results"]] == expected["targets"])
            reasons = ["ReasonOK"] * len(expected["targets"])
            if height == 5016:
                reasons = (["ReasonOK"] * 4 + ["ReasonInsufficientFinality"] * 2 if command == COMMANDS[0]
                           else ["ReasonOK", "ReasonOK", "ReasonInsufficientFinality"] * 2)
            elif height == 5019:
                reasons = (["ReasonHeightOutOfWindow"] * 2 + ["ReasonOK"] * 4 if command == COMMANDS[0]
                           else ["ReasonHeightOutOfWindow", "ReasonParentNotAccepted", "ReasonParentNotAccepted"] * 2)
            self.require(case_id, "selected_row_outcomes", [r["reason"] for r in report["results"]] == reasons and
                         [r["outcome"] for r in report["results"]] == ["ACCEPT" if r == "ReasonOK" else "REFUSED" for r in reasons])
            return result

        def compare_case(case_id, raw, expected, process_exit, category=None):
            state_raw = state.read_bytes()
            self.compare(case_id, raw, expected, process_exit, category, directory)
            unchanged(case_id, state_raw)

        extend(0, 16 if selected["delayed"] else len(selected["headers"]))
        if selected["delayed"]:
            for command in COMMANDS:
                case_id = name + "_" + command.removeprefix("verify-") + "_before_depth"
                result = query_result(case_id, command, 5016, 2)
                compare_case(case_id, result.stdout, selected["expectations"][(5016, command)], result.returncode, "process_failure")
            extend(16, 17)
        height = 5017 if selected["delayed"] else 4009
        for command in COMMANDS:
            prefix = name + "_" + command.removeprefix("verify-") + "_"
            expected = selected["expectations"][(height, command)]
            actual = query_result(prefix + "actual", command, height)
            compare_case(prefix + "actual", actual.stdout, expected, actual.returncode)
            resumed = query_result(prefix + "restart", command, height)
            self.require(prefix + "restart", "restart_diagnostic_changed", resumed.stdout == actual.stdout)
            compare_case(prefix + "restart", resumed.stdout, expected, resumed.returncode)
            reordered = json.loads(actual.stdout)
            reordered["results"].reverse()
            compare_case(prefix + "reordered", oracle.encoded(reordered), expected, actual.returncode)
            wrong_target = copy.deepcopy(expected)
            target = wrong_target["targets"][-1]["account_header"]
            target["hash"] = ("0" if target["hash"][0] != "0" else "1") + target["hash"][1:]
            compare_case(prefix + "wrong_target", actual.stdout, wrong_target, actual.returncode, "target_mismatch")
            wrong_context = copy.deepcopy(expected)
            wrong_context["context_fingerprint"] = ("0" if pin[0] != "0" else "1") + pin[1:]
            compare_case(prefix + "wrong_context", actual.stdout, wrong_context, actual.returncode, "report_mismatch")
            missing = json.loads(actual.stdout)
            missing["results"].pop()
            compare_case(prefix + "missing_row", oracle.encoded(missing), expected, actual.returncode, "target_mismatch")
            tampered = json.loads(actual.stdout)
            tampered["verification_context"]["policy"]["w"] += 1
            compare_case(prefix + "tampered_context", oracle.encoded(tampered), expected, actual.returncode, "invalid_report")
            failed = query_result(prefix + "pin_failure", command, height, 70, wrong_pin=True)
            compare_case(prefix + "pin_failure", failed.stdout, expected, failed.returncode, "process_failure")
            # Reusing an earlier ACCEPT report cannot replace the actual failed process status.
            compare_case(prefix + "prior_report_failed_process", actual.stdout, expected, failed.returncode, "process_failure")
        if selected["delayed"]:
            for end, stage, code in ((18, "oldest_retained", 0), (19, "expired", 2)):
                extend(end - 1, end)
                height = 5000 + end
                for command in COMMANDS:
                    case_id = name + "_" + command.removeprefix("verify-") + "_" + stage
                    result = query_result(case_id, command, height, code)
                    compare_case(case_id, result.stdout, selected["expectations"][(height, command)], result.returncode,
                                 "process_failure" if code else None)


def compare(verifier, consumer, source_revision):
    selected = programs()  # No executable or diagnostic participates in input selection.
    input_paths = [ROOT / "internal/testdata/conformance" / name for name in CORPUS_PINS]
    binaries = {key: path.read_bytes() for key, path in (("verifier", verifier), ("consumer", consumer))}
    runner = Runner(verifier, consumer)
    with tempfile.TemporaryDirectory(prefix="node-consumer-conformance-") as directory:
        directory = Path(directory)
        directory.chmod(0o700)
        for program in selected:
            runner.program(program, directory / program["id"])
    runner.require("complete", "case_coverage", sorted(r["id"] for r in runner.rows) == sorted(selected_case_ids()))
    runner.require("complete", "fixture_changed", all(sha(p.read_bytes()) == CORPUS_PINS[p.name] for p in input_paths))
    runner.require("complete", "executable_changed", verifier.read_bytes() == binaries["verifier"] and consumer.read_bytes() == binaries["consumer"])
    counts = runner.counts
    runner.require("complete", "comparison_coverage", counts["reference_checked"] == counts["consumer_attempted"] ==
                   counts["consumer_compared"] == counts["selected"] == 60 and
                   counts["verifier_attempted"] == counts["verifier_completed"] == 30 and counts["skipped"] == 0)
    return {"node_consumer_schema_version": 1, "status": "node_consumer_comparison_passed",
            "source_revision": source_revision, "source_revision_is_caller_asserted": True,
            "executables": {key: {"sha256": sha(raw), "bytes": len(raw)} for key, raw in binaries.items()},
            "checker_sha256": sha(Path(__file__).read_bytes()), "oracle_sha256": sha(Path(oracle.__file__).read_bytes()),
            "node_source_commit": NODE_COMMIT, "corpus_sha256": CORPUS_PINS,
            "selected_programs": [{"id": p["id"], "context_fingerprint": p["context"]["fingerprint"],
                                   "context_schema_version": p["context"]["schema_version"],
                                   "targets_per_command": len(p["bundle"]["commitments"])} for p in selected],
            "cases": runner.rows, "comparison_counts": counts,
            "matched": sum(row["exit_code"] == 0 for row in runner.rows),
            "refused": sum(row["exit_code"] != 0 for row in runner.rows),
            "readonly_query_state_bytes_unchanged": True, "selected_input_and_executable_bytes_unchanged": True,
            "explicit_private_state_transitions": 6, "external_rpc_calls": 0,
            "synthetic_node_generated_chains": True, "independent_human_review": False, "network_pilot": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verifier", required=True, type=Path)
    parser.add_argument("--consumer", required=True, type=Path)
    parser.add_argument("--source-revision", required=True)
    args = parser.parse_args()
    if re.fullmatch(r"[0-9a-f]{40}", args.source_revision) is None:
        parser.error("source revision must be a full lowercase commit identifier")
    try:
        result = compare(args.verifier.resolve(strict=True), args.consumer.resolve(strict=True), args.source_revision)
    except WorkflowFailure as failure:
        parser.exit(1, json.dumps(failure.details, sort_keys=True, separators=(",", ":")) + "\n")
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        parser.exit(1, "Offline node consumer comparison failed; private inputs and diagnostics omitted\n")
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    os.umask(0o077)
    main()
