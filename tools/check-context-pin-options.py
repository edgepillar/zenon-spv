#!/usr/bin/env python3
"""Exercise compiled context-pin selection on preselected offline node fixtures.

The existing synthetic node-generated corpora and independent Python encoder
select context bytes before the executable runs. No live network, election,
activation or finality claim follows from these finite argument checks.
"""

import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("pin_node_oracle", Path(__file__).with_name("check-node-query-consumer.py"))
node = importlib.util.module_from_spec(spec)
spec.loader.exec_module(node)
VERIFY = ("verify-headers", "verify-commitment", "verify-segment", "verify-state-value")
WORKFLOWS = (*VERIFY, "inspect-state", "watch", "watch-once")
POSITIVE = (*VERIFY, "inspect-state")
SPELLINGS = ("omitted", "lowercase", "uppercase", "wrong")
VARIANTS = ("identical_separate", "wrong_then_matching", "matching_then_wrong",
            "empty_then_matching", "private_then_matching", "matching_then_private",
            "malformed_then_matching", "single_dash", "mixed_dash_and_equals",
            "uppercase_identical", "three_occurrences")
DUPLICATE_ERROR = b"--expect-context must occur at most once\n"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def metadata(path):
    value = path.stat()
    # Reading a file can change its access time. Identity, mode, size and
    # modification time are the observable read-only boundary checked here.
    return value.st_dev, value.st_ino, value.st_mode, value.st_size, value.st_mtime_ns


def different(pin):
    return ("0" if pin[0] != "0" else "1") + pin[1:]


def duplicate_options(pin):
    wrong = different(pin)
    return dict(zip(VARIANTS, (
        ["--expect-context", pin, "--expect-context", pin],
        ["--expect-context", wrong, "--expect-context", pin],
        ["--expect-context", pin, "--expect-context", wrong],
        ["--expect-context=", "--expect-context=" + pin],
        ["--expect-context=PRIVATE_PIN", "--expect-context", pin],
        ["--expect-context", pin, "--expect-context=PRIVATE_PIN"],
        ["--expect-context=" + "z" * 64, "--expect-context=" + pin],
        ["-expect-context", pin, "-expect-context", pin],
        ["-expect-context=" + wrong, "--expect-context", pin],
        ["--expect-context=" + pin, "-expect-context=" + pin.upper()],
        ["--expect-context", pin, "--expect-context", wrong, "--expect-context", pin],
    )))


def selected_programs():
    selected = node.programs()
    return [copy.deepcopy(selected[i]) for i in (0, 2)]


def selected_ids(programs):
    rows = []
    for program in programs:
        prefix = program["id"] + "/"
        rows.append(prefix + "seed")
        rows.extend(prefix + command + "/" + spelling for command in POSITIVE for spelling in SPELLINGS)
        rows.extend(prefix + command + "/" + variant for command in WORKFLOWS for variant in VARIANTS)
        rows.extend(prefix + command + "/missing_inputs" for command in WORKFLOWS)
    if len(rows) != 210 or len(set(rows)) != len(rows):
        raise ValueError("invalid selected inventory")
    return rows


def document(raw):
    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                raise ValueError("duplicate report field")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(ValueError("constant")))


def report_matches(result, command, code, context=None, stage=None):
    if result.returncode != code or result.stderr or len(result.stdout) > node.oracle.REPORT_BYTES:
        return False
    try:
        report = document(result.stdout)
        if (type(report["schema_version"]) is not int or report["schema_version"] != 1 or
                report["command"] != command or type(report["exit_code"]) is not int or report["exit_code"] != code):
            return False
        if stage is not None:
            error = {"stage": stage, "category": "usage" if code == 64 else "operational"}
            if (report["error"] != error or report["verification_context"] is not None or
                    report["state_trust"] != []):
                return False
            if command == "inspect-state":
                return report["status"] == "error" and report["retained_window"] is None and report["persistence"] == "read_only"
            return report["outcome"] is None and report["verification_tip"] is None and report["results"] == []
        return report["error"] is None and report["verification_context"] == context
    except (ValueError, KeyError, TypeError, RecursionError):
        return False


class Failure(Exception):
    def __init__(self, details):
        self.details = details
        super().__init__("Offline context-pin checks failed; private data omitted")


class Runner:
    def __init__(self, executable, ids):
        self.executable, self.ids = executable, ids
        self.outcomes, self.matched = [], 0

    def counts(self):
        return {"selected": len(self.ids), "attempted": len(self.outcomes),
                "completed": sum(row["completed"] for row in self.outcomes), "matched": self.matched,
                "unattempted": len(self.ids) - len(self.outcomes), "retries": 0}

    def require(self, case_id, stage, condition):
        if not condition:
            raise Failure({"status": "context_pin_options_failed", "case_id": case_id, "stage": stage,
                           "counts": self.counts(), "process_outcomes": copy.deepcopy(self.outcomes)})

    def child(self, case_id, arguments):
        self.require(case_id, "selected_order", case_id == self.ids[len(self.outcomes)])
        row = {"id": case_id, "completed": False, "actual_exit": None}
        self.outcomes.append(row)
        try:
            result = subprocess.run([str(self.executable), *arguments], capture_output=True, timeout=15, check=False)
        except subprocess.TimeoutExpired as exc:
            out, err = exc.stdout or b"", exc.stderr or b""
            row.update(stdout_sha256=sha(out), stderr_sha256=sha(err), stdout_bytes=len(out), stderr_bytes=len(err))
            self.require(case_id, "child_run", False)
        except (OSError, subprocess.SubprocessError):
            self.require(case_id, "child_run", False)
        row.update(completed=True, actual_exit=result.returncode,
                   stdout_sha256=sha(result.stdout), stderr_sha256=sha(result.stderr),
                   stdout_bytes=len(result.stdout), stderr_bytes=len(result.stderr))
        return result

    def check(self, case_id, condition):
        self.require(case_id, "child_decision", condition)
        self.matched += 1


def compare(executable, source_revision):
    programs = selected_programs()  # No diagnostic or executable participates in selection.
    ids = selected_ids(programs)
    runner = Runner(executable, ids)
    binary = executable.read_bytes()
    corpus = {name: (ROOT / "internal/testdata/conformance" / name).read_bytes() for name in node.CORPUS_PINS}
    failure = None
    directory = tempfile.TemporaryDirectory(prefix="context-pin-options-")
    try:
        for program in programs:
            exercise(runner, program, Path(directory.name) / program["id"])
        runner.require("complete", "inventory", runner.counts() == {
            "selected": 210, "attempted": 210, "completed": 210, "matched": 210, "unattempted": 0, "retries": 0})
        runner.require("complete", "input_changed", executable.read_bytes() == binary and all(
            (ROOT / "internal/testdata/conformance" / name).read_bytes() == raw for name, raw in corpus.items()))
    except Failure as exc:
        failure = exc
    except (OSError, ValueError, KeyError, TypeError, RecursionError):
        try:
            runner.require("complete", "offline_check", False)
        except Failure as exc:
            failure = exc
    try:
        directory.cleanup()
    except OSError:
        details = {"status": "context_pin_options_failed", "case_id": "complete", "stage": "cleanup",
                   "counts": runner.counts(), "process_outcomes": copy.deepcopy(runner.outcomes)}
        if failure:
            details["prior_failure"] = failure.details
        raise Failure(details) from None
    if failure:
        raise failure
    return {"context_pin_options_schema_version": 1, "status": "context_pin_options_passed",
            "source_revision": source_revision, "source_revision_is_caller_asserted": True,
            "verifier": {"sha256": sha(binary), "bytes": len(binary)},
            "checker_sha256": sha(Path(__file__).read_bytes()), "node_selector_sha256": sha(Path(node.__file__).read_bytes()),
            "context_oracle_sha256": sha(Path(node.oracle.__file__).read_bytes()),
            "node_source_commit": node.NODE_COMMIT, "corpus_sha256": node.CORPUS_PINS,
            "selected_programs": [{"id": p["id"], "context_fingerprint": p["context"]["fingerprint"],
                                   "context_schema_version": p["context"]["schema_version"]} for p in programs],
            "counts": runner.counts(), "process_outcomes": runner.outcomes,
            "duplicate_option_refusals": 168, "omitted_or_single_pin_checks": 40, "private_seed_transitions": 2,
            "selected_input_and_executable_bytes_unchanged": True, "query_state_bytes_and_metadata_unchanged": True,
            "checked_state_metadata": ["device", "inode", "mode", "size", "mtime_ns"],
            "duplicate_options_created_no_files_or_locks": True, "external_rpc_used": False,
            "synthetic_node_generated_chains": True, "network_pilot": False, "independent_human_review": False}


def exercise(runner, program, directory):
    directory.mkdir(mode=0o700)
    inputs = {}

    def write(name, value):
        path = directory / name
        raw = node.oracle.encoded(value)
        path.write_bytes(raw)
        path.chmod(0o600)
        inputs[path] = raw
        return str(path)

    config = ["--json", "--window", "low", "--genesis-config", write("anchor.json", program["anchor"])]
    if program["retain"]:
        config += ["--retain-headers", str(program["retain"])]
    if program["profile"] is not None:
        config += ["--protocol-profile", write("profile.json", program["profile"]),
                   "--schedule", write("schedule.json", program["schedule"])]
    pin = program["context"]["fingerprint"]
    prefix = program["id"] + "/"
    seed = {key: program["bundle"][key] for key in ("version", "chain_id", "claimed_genesis")}
    seed["headers"] = program["headers"][:17] if program["delayed"] else program["headers"]
    state = directory / "seeded-state.json"
    result = runner.child(prefix + "seed", ["verify-headers", *config, "--state", str(state),
                                             "--expect-context", pin, write("seed.json", seed)])
    runner.check(prefix + "seed", report_matches(result, "verify-headers", 0, program["context"]) and
                 document(result.stdout)["outcome"] == "ACCEPT")
    query = write("proof-only.json", program["bundle"])
    state_raw = state.read_bytes()
    state_stat = metadata(state)
    positive_config = [*config, "--state", str(state)]
    height = 5017 if program["delayed"] else 4009
    for command in POSITIVE:
        for spelling in SPELLINGS:
            case_id = prefix + command + "/" + spelling
            options = ([] if spelling == "omitted" else ["--expect-context", different(pin) if spelling == "wrong"
                       else pin.upper() if spelling == "uppercase" else pin])
            args = [command, *positive_config, *options]
            if command != "inspect-state":
                if command != "verify-headers":
                    args += ["--retained-only"]
                args += [query]
            result = runner.child(case_id, args)
            code = 70 if spelling == "wrong" else 2 if command in ("verify-headers", "verify-state-value") else 0
            match = report_matches(result, command, code, program["context"], "context_pin" if code == 70 else None)
            if match and command in node.COMMANDS and code == 0:
                report = document(result.stdout)
                expected = program["expectations"][(height, command)]
                match = (report["outcome"] == "ACCEPT" and report["verification_tip"] == expected["verification_tip"] and
                         [row["reference"] for row in report["results"]] == expected["targets"])
            elif match and code != 70:
                report = document(result.stdout)
                match = (report["status"] == "inspected" and report["retained_window"]["tip"] ==
                         program["expectations"][(height, "verify-commitment")]["verification_tip"]
                         if command == "inspect-state" else report["outcome"] == "REFUSED")
            runner.check(case_id, match)
            runner.require(case_id, "state_changed", state.read_bytes() == state_raw and metadata(state) == state_stat)
    # A separate copy has no preexisting writer companion to conceal lock creation.
    guarded = directory / "guarded-state.json"
    guarded.write_bytes(state_raw)
    guarded.chmod(0o600)
    inputs[guarded] = state_raw
    frozen = {path: (path.read_bytes(), metadata(path)) for path in inputs}
    files = set(directory.iterdir())
    guarded_config = [*config, "--state", str(guarded)]
    missing = str(directory / "PRIVATE_MISSING.json")
    for command in WORKFLOWS:
        for variant, options in duplicate_options(pin).items():
            duplicate(runner, prefix + command + "/" + variant, command, guarded_config, options, query, missing)
            runner.require(prefix + command + "/" + variant, "file_or_lock_changed", set(directory.iterdir()) == files and all(
                path.read_bytes() == raw and metadata(path) == stat_pin for path, (raw, stat_pin) in frozen.items()))
    for command in WORKFLOWS:
        config_missing = ["--json", "--state", missing, "--genesis-config", missing,
                          "--protocol-profile", missing, "--schedule", missing]
        case_id = prefix + command + "/missing_inputs"
        duplicate(runner, case_id, command, config_missing, duplicate_options(pin)["private_then_matching"], missing, missing)
        runner.require(case_id, "missing_input_created", set(directory.iterdir()) == files)


def duplicate(runner, case_id, command, config, options, query, missing):
    args = ["watch" if command == "watch-once" else command, *config, *options]
    if command.startswith("watch"):
        # Poisoned anchor prevents an accidental regression from starting a loop.
        # The expected usage refusal must precede even that missing-file error.
        args += ["--genesis-config", missing, "--rpc", "http://127.0.0.1:1"]
        if command == "watch-once":
            args += ["--once"]
    elif command != "inspect-state":
        if command != "verify-headers":
            args += ["--retained-only"]
        args += [query]
    result = runner.child(case_id, args)
    match = (result.returncode == 64 and result.stdout == b"" and result.stderr == DUPLICATE_ERROR
             if command.startswith("watch") else report_matches(result, command, 64, stage="arguments"))
    runner.check(case_id, match)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verifier", required=True, type=Path)
    parser.add_argument("--source-revision", required=True)
    args = parser.parse_args()
    if re.fullmatch(r"[0-9a-f]{40}", args.source_revision) is None:
        parser.error("source revision must be a full lowercase commit identifier")
    try:
        result = compare(args.verifier.resolve(strict=True), args.source_revision)
    except Failure as exc:
        parser.exit(1, json.dumps(exc.details, sort_keys=True, separators=(",", ":")) + "\n")
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        parser.exit(1, "Offline context-pin checks failed; private data omitted\n")
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    os.umask(0o077)
    main()
