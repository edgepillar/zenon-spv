# SPDX-License-Identifier: GPL-3.0-only
"""Bounded, public-safe observations of the four owned startup nodes."""
import re

from model import exact_keys, require, uint

REPORT = "startup-node-diagnostics.json"
ROLES = ("pillar", "pillar2", "pillar3", "rpc")
COMMAND_FILE = re.compile(
    r"docker-[0-9]{3,6}-startup-(?:engine-info|(?:inspect|logs)-(?:pillar|pillar2|pillar3|rpc))"
    r"\.(?:(?:launch|started|complete)\.json|stdout|stderr)\Z")
LOG_BYTES = 32 << 10
LOG_LINES = 128
MAX_LINES = 512
MAX_FRAMES = 16
EVENT_MESSAGES = {
    "producer_triggered": "momentum producer triggered",
    "generation_failed": "failed to generate momentum",
    "broadcast": "broadcasting own momentum",
    "late_broadcast": "do not broadcast own momentum",
    "ignored_event": "do not process current event",
}
REASONS = {
    "sync_not_done": "sync is not done",
    "producer_not_defined": "pillar has no producer address defined",
    "another_producer": "not our event",
    "event_early": "current time is before start time",
    "event_expired": "current time is after the event's finish time",
}
EVENTS = tuple((*EVENT_MESSAGES, *REASONS, "producing", "panic", "fatal"))
STACK_FILES = frozenset((
    "pillar/manager.go", "pillar/worker.go", "pillar/worker_momentum.go",
    "pillar/worker_contract_generator.go", "pillar/worker_updater.go",
    "consensus/consensus.go", "consensus/election.go", "consensus/election_algorithm.go",
    "chain/chain.go", "zenon/zenon.go", "node/node.go", "node/config.go",
))
FRAME = re.compile(r"\s*/app/([A-Za-z0-9_./-]+\.go):([1-9][0-9]{0,4})(?: \+0x[0-9a-f]{1,16})?\s*\Z")
STATE_BOOLS = frozenset(("Running", "Restarting", "Dead", "OOMKilled", "Paused"))
STATE_FIELDS = STATE_BOOLS | {"Pid", "ExitCode", "Status"}
STATES = frozenset(("created", "running", "paused", "restarting", "removing", "exited", "dead"))
PHASE_REASONS = {
    "NOT_ATTEMPTED": {"preceding_observation_unavailable"},
    "OBSERVED": {None},
    "FAILURE": {"command_failed"},
    "UNKNOWN": {"command_incomplete", "capture_interrupted"},
    "REFUSED": {"capture_refused"},
}


def empty_phase():
    return {"status": "NOT_ATTEMPTED", "reason": "preceding_observation_unavailable",
            "command": None, "actual_exit": None, "output_complete": None,
            "outputs": None, "data": None}


def complete_command(phase, result):
    receipt = result.receipt
    phase.update(command=receipt["label"], actual_exit=receipt["actual_exit"],
                 output_complete=receipt["output_complete"], outputs={
                     key: {field: receipt["outputs"][key][field] for field in ("sha256", "bytes")}
                     for key in ("stdout", "stderr")})


def failed_command(phase, error):
    complete_command(phase, error.result)
    receipt = error.result.receipt
    if receipt.get("reason") == "interrupted":
        phase.update(status="UNKNOWN", reason="capture_interrupted")
        raise KeyboardInterrupt from error
    failed = (receipt["output_complete"] is True and type(receipt["actual_exit"]) is int
              and receipt["actual_exit"] != 0)
    phase.update(status="FAILURE" if failed else "UNKNOWN",
                 reason="command_failed" if failed else "command_incomplete")


def log_summary(stdout, stderr):
    """Emit fixed event names and canonical source locations, excluding raw text."""
    require(all(type(raw) is bytes and len(raw) <= LOG_BYTES for raw in (stdout, stderr)),
            "startup_log_byte_bound")
    invalid = False
    texts = []
    for raw in (stdout, stderr):
        try:
            texts.append(raw.decode("utf-8"))
        except UnicodeDecodeError:
            invalid = True
            texts.append(raw.decode("utf-8", errors="replace"))
    lines = [line for text in texts for line in text.splitlines()]
    require(len(lines) <= MAX_LINES, "startup_log_line_bound")
    events, frames, classified = dict.fromkeys(EVENTS, 0), set(), 0
    for line in lines:
        matched = False
        for field, choices in (("msg", EVENT_MESSAGES), ("reason", REASONS)):
            for code, text in choices.items():
                if re.search(r"(?:^|\s)" + field + "=" + re.escape('"' + text + '"') + r"(?:\s|$)", line):
                    events[code] += 1
                    matched = True
        stripped = line.strip()
        for code, present in (("producing", stripped == "Producing momentum ..."),
                              ("panic", stripped.startswith("panic: ")),
                              ("fatal", stripped.startswith("fatal error: "))):
            if present:
                events[code] += 1
                matched = True
        frame = FRAME.fullmatch(line)
        if frame and frame[1] in STACK_FILES:
            frames.add((frame[1], int(frame[2])))
            matched = True
        classified += int(matched)
    ordered = sorted(frames)
    return {"events": events, "total_lines": len(lines), "classified_lines": classified,
            "unclassified_lines": len(lines) - classified, "invalid_utf8": invalid,
            "source_frames": [{"file": name, "line": number} for name, number in ordered[:MAX_FRAMES]],
            "source_frames_truncated": len(ordered) > MAX_FRAMES, "raw_logs_exported": False}


def check_log_summary(row):
    exact_keys(row, {"events", "total_lines", "classified_lines", "unclassified_lines", "invalid_utf8",
                     "source_frames", "source_frames_truncated", "raw_logs_exported"}, "review_node_log_fields")
    total = uint(row["total_lines"], MAX_LINES, minimum=0)
    classified = uint(row["classified_lines"], total, minimum=0)
    require(uint(row["unclassified_lines"], total, minimum=0) == total - classified,
            "review_node_log_counts")
    exact_keys(row["events"], set(EVENTS), "review_node_log_events")
    for value in row["events"].values():
        uint(value, total, minimum=0)
    require(type(row["invalid_utf8"]) is bool and type(row["source_frames_truncated"]) is bool
            and row["raw_logs_exported"] is False, "review_node_log_privacy")
    frames = row["source_frames"]
    require(type(frames) is list and len(frames) <= MAX_FRAMES, "review_node_log_frames")
    values = []
    for frame in frames:
        exact_keys(frame, {"file", "line"}, "review_node_log_frame_fields")
        require(type(frame["file"]) is str and frame["file"] in STACK_FILES, "review_node_log_frame_path")
        values.append((frame["file"], uint(frame["line"], 99999)))
    require(values == sorted(set(values)), "review_node_log_frame_order")


def check_state_summary(row):
    exact_keys(row, {"state_is_object", "fields", "unavailable_fields", "error_class"},
               "review_node_state_fields")
    fields = row["fields"]
    require(type(row["state_is_object"]) is bool and type(fields) is dict and set(fields) <= STATE_FIELDS
            and row["unavailable_fields"] == sorted(STATE_FIELDS - set(fields))
            and type(row["error_class"]) is str
            and row["error_class"] in ("missing", "empty", "nonempty", "invalid"), "review_node_state_scope")
    for key, value in fields.items():
        if key in STATE_BOOLS:
            require(type(value) is bool, "review_node_state_boolean")
        elif key == "Pid":
            uint(value, 2 ** 31 - 1, minimum=0)
        elif key == "ExitCode":
            require(type(value) is int and -1 <= value <= 255, "review_node_state_exit")
        else:
            require(type(value) is str and value in STATES, "review_node_state_status")
    require(row["state_is_object"] or not fields and row["error_class"] == "missing",
            "review_node_state_object")
