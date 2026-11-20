# SPDX-License-Identifier: GPL-3.0-only
"""Bounded observations of the pinned node's two regular log files."""
import hashlib
import io
import re
import tarfile

from model import Refused, exact_keys, require, uint
import model
import node_diagnostics as nodes

REPORT = "startup-file-logs.json"
FORMAT_V5 = "owned-devnet-startup-file-logs/v5"
FORMAT = "owned-devnet-startup-file-logs/v6"
ARCHIVE_BYTES = 64 << 10
TAIL_BYTES = nodes.LOG_BYTES
FILES = (("run", "/root/.znn/log/zenon.log"),
         ("error", "/root/.znn/log/error/zenon.error.log"))
COMMAND_FILE = re.compile(
    r"docker-[0-9]{3,6}-startup-file-(?:pillar|pillar2|pillar3|rpc)-(?:run|error)"
    r"\.(?:(?:launch|started|complete)\.json|stdout|stderr)\Z")
# Fixed source messages at node 2835c436b197fece5c76adf4ba8dc1decca2e3ea.
# Their presence is a diagnostic assertion, never a state-value acceptance input.
EVENTS = {"vm_panic": "vm panic when applying momentum", "worker_started": "producing momentum",
          "producer_finished": "momentum producer trigger finished", "forced_stop": "force-stopping producer task"}
REASONS = {
    "vm_panic": "supervisor - VM panic", "data_missing": "data non existent",
    "momentum_version": "momentum version is invalid",
    "momentum_chain": "momentum chain-identifier mismatch (belongs to another chain)",
    "momentum_state_root_early": "momentum state-root must be zero before the state-root spork is active",
    "momentum_state_root": "momentum state-root is different than the one computed",
    "momentum_changes_hash": "momentum changes-hash is different than the one computed",
    "momentum_hash": "momentum hash is different than the one computed",
    "momentum_content": "momentum content is too big",
    "momentum_time_future": "momentum timestamp is in the future (more than 10 seconds)",
    "momentum_time_order": "momentum timestamp is lower than previous timestamp",
    "momentum_signature_missing": "momentum signature is missing",
    "momentum_signature": "momentum signature is invalid",
    "momentum_producer": "momentum producer is invalid",
    "momentum_parent": "momentum previous momentum is missing",
    "momentum_minimum": "momentum minimum value is invalid",
    "state_version_missing": "trie: no such version", "state_corrupt": "trie: corrupt tree database",
    "state_unstaged": "trie: commit called without a staged write-set",
    "state_commit_order": "trie: commit height must be exactly one above the frontier",
    "db_stopped": "can't add transaction to stopped db", "db_parent": "can't find prev",
}
SOURCE_FILES = nodes.STACK_FILES | {"common/errors.go", "vm/supervisor.go", "vm/vm.go",
    "vm/vm_context/momentum_context.go", "vm/vm_context/state.go", "vm/vm_context/lifecycle.go",
    "chain/momentum_pool.go", "chain/momentum/ledger_store.go", "verifier/momentum.go",
    "common/trie/nodestore.go", "common/db/versioned_db.go"}
SOURCE_LOCATION = re.compile(r"/app/(" + "|".join(re.escape(name) for name in sorted(SOURCE_FILES))
                             + r"):([1-9][0-9]{0,4})(?=$|[\s\"\\+])")


def field_pattern(key, text):
    values = [re.escape('"' + text + '"')]
    if not any(c.isspace() for c in text):values.append(re.escape(text))
    return re.compile(r"(?:^|\s)" + key + "=(?:" + "|".join(values) + r")(?=\s|$)")


# Both calls use this exact LogfmtFormat layout in the pinned node. Match a
# complete record so logger tags inside values or a truncated line cannot
# supply an origin. The identifier is part of the shape and is never exported.
LOGFMT_INFO = (r't=[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}[+-][0-9]{4} '
               r'lvl=info ')
BROADCAST_RECORD = re.compile(
    LOGFMT_INFO + r'msg="broadcasting own momentum" module=(?P<module>[a-z]+) '
    r'submodule=(?P<submodule>[a-z]+) identifier="\{Hash:(?P<hash>[0-9a-f]{64}) '
    r'Height:(?P<height>0|[1-9][0-9]{0,19})\}"')
BROADCAST_LOGGERS = {("pillar", "worker"): "worker_before_insert",
                     ("handler", "broadcaster"): "protocol_after_insert"}
BROADCAST_ORIGINS = (*BROADCAST_LOGGERS.values(), "unattributed")
HEIGHT_TWO_IDENTIFIER = r'"\{Hash:(?P<hash>[0-9a-f]{64}) Height:2\}"'
HEIGHT_TWO_POOL = re.compile(LOGFMT_INFO + r'msg="inserting new momentum" module=chain '
                             r'submodule=momentum-pool identifier=' + HEIGHT_TWO_IDENTIFIER)
HEIGHT_TWO_TRANSFER = re.compile(LOGFMT_INFO + r'msg="propagated momentum to peers" module=handler '
                                 r'num-peers=(?P<targets>0|[1-9][0-9]{0,18}) momentum-identifier='
                                 + HEIGHT_TWO_IDENTIFIER)
HEIGHT_TWO_FIELDS = {"worker_before_insert", "pool_entered", "own_post_insert", "pool_then_own_post_insert",
                     "own_post_insert_then_nonzero_targets", "own_post_insert_then_zero_targets_only"}

EVENT_PATTERNS = {key: field_pattern("msg", text) for key, text in EVENTS.items()}
REASON_PATTERNS = {key: field_pattern("reason", text) for key, text in REASONS.items()}
TAIL_REASON_PATTERNS = {**REASON_PATTERNS, "late_production": field_pattern("reason", "too-late")}


def read_method(state):
    """Use exec only for a positively observed executable container state."""
    nodes.check_state_summary(state)
    fields = state["fields"]
    executable = all(fields.get(key) is value for key, value in (
        ("Running", True), ("Paused", False), ("Restarting", False), ("Dead", False)))
    return "byte-tail" if executable else "whole-file"


def read_method_for_file(state, kind):
    """Keep a bounded error file's first record without a tail-boundary guess."""
    require(type(kind) is str and kind in dict(FILES), "startup_file_kind")
    selected = read_method(state)
    return "whole-file" if kind == "error" else selected


def height_two_summary(lines):
    """Match distinct H2 identifiers in one file window, in record order."""
    worker, pool, post_insert = set(), set(), set()
    after_pool, nonzero_targets, zero_targets = set(), set(), set()
    for line in lines:
        if match := HEIGHT_TWO_POOL.fullmatch(line):
            pool.add(match["hash"])
            continue
        match = BROADCAST_RECORD.fullmatch(line)
        if match and match["height"] == "2":
            identifier = match["hash"]
            origin = BROADCAST_LOGGERS.get(match.group("module", "submodule"))
            if origin == "worker_before_insert":
                worker.add(identifier)
            elif origin == "protocol_after_insert":
                post_insert.add(identifier)
                if identifier in pool:
                    after_pool.add(identifier)
            continue
        match = HEIGHT_TWO_TRANSFER.fullmatch(line)
        if match and match["hash"] in post_insert:
            targets = int(match["targets"])
            if targets == 0:
                zero_targets.add(match["hash"])
            elif targets < 1 << 63:
                nonzero_targets.add(match["hash"])
    return {"worker_before_insert": len(worker), "pool_entered": len(pool),
            "own_post_insert": len(post_insert), "pool_then_own_post_insert": len(after_pool),
            "own_post_insert_then_nonzero_targets": len(nonzero_targets),
            "own_post_insert_then_zero_targets_only": len(zero_targets - nonzero_targets)}


def classify(payload, *, tail=False, broadcast_count=None, with_height_two=False):
    patterns = TAIL_REASON_PATTERNS if tail else REASON_PATTERNS
    events, reasons, locations = dict.fromkeys(EVENTS, 0), dict.fromkeys(patterns, 0), set()
    text = payload.decode("utf-8", errors="replace")
    for line in text.splitlines():
        for key, pattern in EVENT_PATTERNS.items():events[key] += int(pattern.search(line) is not None)
        for key, pattern in patterns.items():reasons[key] += int(pattern.search(line) is not None)
        if EVENT_PATTERNS["vm_panic"].search(line) and re.search(r"(?:^|\s)stack=", line):
            for match in SOURCE_LOCATION.finditer(line):locations.add((match[1], int(match[2])))
    ordered = sorted(locations)
    classification = {
        "events": events, "reasons": reasons,
        "source_locations": [{"file": name, "line": number} for name, number in ordered[:nodes.MAX_FRAMES]],
        "source_locations_truncated": len(ordered) > nodes.MAX_FRAMES,
    }
    if broadcast_count is not None:
        origins = dict.fromkeys(BROADCAST_ORIGINS, 0)
        complete_lines = text.split("\n")[:-1]
        for line in complete_lines:
            record = BROADCAST_RECORD.fullmatch(line)
            if record and (origin := BROADCAST_LOGGERS.get(record.group("module", "submodule"))):
                origins[origin] += 1
        origins["unattributed"] = broadcast_count - sum(origins.values())
        classification["broadcast_origins"] = origins
        if with_height_two:
            classification["height_two"] = height_two_summary(complete_lines)
    return classification


def archive_summary(raw, kind, *, complete_prefix=False, with_broadcast_origins=False, with_height_two=False):
    """Read one bounded regular TAR entry in memory; never extract a pathname."""
    paths = dict(FILES)
    require(type(complete_prefix) is bool and (not complete_prefix or kind == "error"),
            "startup_file_prefix_mode")
    require(type(kind) is str and kind in paths and type(raw) is bytes and 0 < len(raw) <= ARCHIVE_BYTES
            and len(raw) % 512 == 0, "startup_file_archive_bound")
    expected = paths[kind].rsplit("/", 1)[-1]
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
            entry = archive.next()
            require(entry is not None and entry.name == expected and entry.type in (tarfile.REGTYPE, tarfile.AREGTYPE)
                    and not entry.linkname and entry.sparse is None, "startup_file_archive_entry")
            # Check the advertised size before getmembers can seek past this entry.
            uint(entry.size, nodes.LOG_BYTES, minimum=0)
            require(set(entry.pax_headers) <= {"atime", "ctime", "mtime"}
                    and all(type(v) is str and re.fullmatch(r"-?[0-9]{1,20}(?:\.[0-9]{1,9})?", v)
                            for v in entry.pax_headers.values()), "startup_file_archive_metadata")
            require(len(archive.getmembers()) == 1, "startup_file_archive_members")
            end = ((entry.offset_data + entry.size + 511) // 512) * 512
            require(len(raw) >= end + 1024 and not any(raw[end:]), "startup_file_archive_trailing")
            stream = archive.extractfile(entry)
            require(stream is not None, "startup_file_archive_payload")
            with stream:
                payload = stream.read(nodes.LOG_BYTES + 1)
            require(len(payload) == entry.size, "startup_file_archive_size")
    except (tarfile.TarError, EOFError, OSError, ValueError, OverflowError) as error:
        if isinstance(error, Refused):
            raise
        raise Refused("startup_file_archive_encoding") from error
    end = payload.rfind(b"\n") + 1 if complete_prefix else len(payload)
    selected = payload[:end]
    log = nodes.log_summary(selected, b"")
    result = {"content": {"bytes": len(payload), "sha256": hashlib.sha256(payload).hexdigest()},
              "log": log, "classification": classify(selected, tail=complete_prefix,
                  broadcast_count=log["events"]["broadcast"] if with_broadcast_origins or with_height_two else None,
                  with_height_two=with_height_two)}
    if complete_prefix:
        result["window"] = {"scope": "bounded-complete-lines-from-file-start", "whole_file_coverage": False,
                            "leading_discarded_bytes": 0, "trailing_discarded_bytes": len(payload) - end,
                            "classified_bytes": end}
    return result


def tail_summary(raw, *, with_broadcast_origins=False, with_height_two=False):
    """Classify only complete lines inside a bounded, non-atomic byte tail."""
    require(type(raw) is bytes and len(raw) <= TAIL_BYTES, "startup_file_tail_bound")
    first = raw.find(b"\n")
    start = len(raw) if first < 0 else first + 1
    end = max(start, raw.rfind(b"\n") + 1)
    selected = raw[start:end]
    log = nodes.log_summary(selected, b"")
    return {"content": {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()},
            "window": {"scope": "bounded-complete-lines", "whole_file_coverage": False,
                       "leading_discarded_bytes": start, "trailing_discarded_bytes": len(raw) - end,
                       "classified_bytes": len(selected)},
            "log": log, "classification": classify(selected, tail=True,
                broadcast_count=log["events"]["broadcast"] if with_broadcast_origins or with_height_two else None,
                with_height_two=with_height_two)}


def check_data(data, *, tail=False, complete_prefix=False, with_broadcast_origins=False, with_height_two=False):
    require(type(tail) is bool and type(complete_prefix) is bool and not (tail and complete_prefix),
            "review_file_log_mode")
    windowed = tail or complete_prefix
    exact_keys(data, {"content", "log", "classification"} | ({"window"} if windowed else set()),
               "review_file_log_data")
    exact_keys(data["content"], {"bytes", "sha256"}, "review_file_log_content")
    uint(data["content"]["bytes"], nodes.LOG_BYTES, minimum=0)
    model.digest(data["content"]["sha256"])
    nodes.check_log_summary(data["log"])
    require(data["log"]["total_lines"] <= data["content"]["bytes"], "review_file_log_line_bytes")
    row = data["classification"]
    fields = {"events", "reasons", "source_locations", "source_locations_truncated"}
    if with_broadcast_origins or with_height_two:
        fields.add("broadcast_origins")
    if with_height_two:
        fields.add("height_two")
    exact_keys(row, fields, "review_file_log_classification")
    if with_broadcast_origins or with_height_two:
        origins = row["broadcast_origins"]
        exact_keys(origins, set(BROADCAST_ORIGINS), "review_file_log_broadcast_origins")
        broadcasts = data["log"]["events"]["broadcast"]
        require(sum(uint(value, broadcasts, minimum=0) for value in origins.values()) == broadcasts,
                "review_file_log_broadcast_origin_counts")
    if with_height_two:
        height_two = row["height_two"]
        exact_keys(height_two, HEIGHT_TWO_FIELDS, "review_file_log_height_two")
        line_count = data["log"]["total_lines"]
        for value in height_two.values():
            uint(value, line_count, minimum=0)
        worker = height_two["worker_before_insert"]
        pool = height_two["pool_entered"]
        post_insert = height_two["own_post_insert"]
        targets = (height_two["own_post_insert_then_nonzero_targets"]
                   + height_two["own_post_insert_then_zero_targets_only"])
        require(worker <= origins["worker_before_insert"] and post_insert <= origins["protocol_after_insert"]
                and height_two["pool_then_own_post_insert"] <= min(pool, post_insert)
                and targets <= post_insert and worker + pool + post_insert + targets <= line_count,
                "review_file_log_height_two_counts")
    for name, codes in (("events", EVENTS), ("reasons", TAIL_REASON_PATTERNS if windowed else REASONS)):
        exact_keys(row[name], set(codes), "review_file_log_class_codes")
        for value in row[name].values():uint(value, data["log"]["total_lines"], minimum=0)
    require(type(row["source_locations"]) is list and len(row["source_locations"]) <= nodes.MAX_FRAMES
            and type(row["source_locations_truncated"]) is bool, "review_file_log_locations")
    locations = []
    for location in row["source_locations"]:
        exact_keys(location, {"file", "line"}, "review_file_log_location_fields")
        require(type(location["file"]) is str and location["file"] in SOURCE_FILES,
                "review_file_log_source_file")
        locations.append((location["file"], uint(location["line"], 99999)))
    require(locations == sorted(set(locations)), "review_file_log_location_order")
    if windowed:
        window = data["window"]
        exact_keys(window, {"scope", "whole_file_coverage", "leading_discarded_bytes",
                           "trailing_discarded_bytes", "classified_bytes"}, "review_file_log_window")
        expected_scope = "bounded-complete-lines-from-file-start" if complete_prefix else "bounded-complete-lines"
        require(window["scope"] == expected_scope and window["whole_file_coverage"] is False,
                "review_file_log_window_scope")
        leading, trailing, selected = (uint(window[k], TAIL_BYTES, minimum=0) for k in (
            "leading_discarded_bytes", "trailing_discarded_bytes", "classified_bytes"))
        require(leading + trailing + selected == data["content"]["bytes"]
                and (leading == 0 if complete_prefix else (leading > 0) == (data["content"]["bytes"] > 0))
                and data["log"]["total_lines"] <= selected, "review_file_log_window_accounting")


def recorded(evidence, terminal, startup, receipt_reader):
    commands = {name for name in evidence.pins if name.startswith("evidence/")
                and COMMAND_FILE.fullmatch(name[len("evidence/"):])}
    require(not any(name.endswith((".stdout", ".stderr")) for name in commands), "review_file_log_raw_stream")
    if "evidence/" + REPORT not in evidence.pins:
        require(not commands, "review_file_log_summary_missing")
        return None
    require(startup is not None and startup["summary"]["engine_identity_verified"] is True,
            "review_file_log_startup_binding")
    summary = evidence.json(REPORT, 32 << 10)
    exact_keys(summary, {"format", "trigger", "status", "reason", "observed_before_cleanup",
                        "atomic_snapshot", "accepted_header_authority", "production_qualified",
                        "raw_logs_exported", "nodes"}, "review_file_log_fields")
    legacy_tail = summary["format"] == "owned-devnet-startup-file-logs/v2"
    with_broadcast_origins = summary["format"] in (FORMAT_V5, FORMAT)
    with_height_two = summary["format"] == FORMAT
    by_file = summary["format"] in ("owned-devnet-startup-file-logs/v4", FORMAT_V5, FORMAT)
    mixed = summary["format"] == "owned-devnet-startup-file-logs/v3" or by_file
    require(summary["format"] in ("owned-devnet-startup-file-logs/v1", "owned-devnet-startup-file-logs/v2",
                                  "owned-devnet-startup-file-logs/v3", "owned-devnet-startup-file-logs/v4",
                                  FORMAT_V5, FORMAT)
            and summary["trigger"] == "owned_rpc_readiness_deadline" and terminal["stage"] == "nodes"
            and terminal["outcome"] != "DEVNET_CONSUMER_ACCEPTED" and summary["observed_before_cleanup"] is True
            and summary["atomic_snapshot"] is False and summary["accepted_header_authority"] is False
            and summary["production_qualified"] is False and summary["raw_logs_exported"] is False,
            "review_file_log_scope")
    require((summary["status"] == "OBSERVED" and summary["reason"] is None)
            or (summary["status"] == "UNKNOWN" and type(summary["reason"]) is str
                and summary["reason"] in ("capture_interrupted", "incomplete_diagnostics")),
            "review_file_log_status")
    rows = summary["nodes"]
    require(type(rows) is list and len(rows) == len(nodes.ROLES), "review_file_log_nodes")
    phases, counters = [], []
    base = startup["summary"]
    earlier = [phase["command"] for phase in [base["engine_probe"], *(
        phase for row in base["nodes"] for phase in (row["inspection"], row["logs"]))] if phase["command"]]
    for role, row, original in zip(nodes.ROLES, rows, base["nodes"]):
        exact_keys(row, {"service", "inspection_command", "files"}, "review_file_log_node_fields")
        model.same(row["service"], role, "review_file_log_role")
        expected = original["inspection"]["command"] if original["inspection"]["status"] == "OBSERVED" else None
        model.same(row["inspection_command"], expected, "review_file_log_inspection")
        node_method = read_method(original["inspection"]["data"]) if mixed and expected is not None else None
        require(type(row["files"]) is list and len(row["files"]) == len(FILES), "review_file_log_files")
        for (kind, _), item in zip(FILES, row["files"]):
            exact_keys(item, {"kind", "phase"} | ({"method"} if mixed else set()), "review_file_log_item")
            model.same(item["kind"], kind, "review_file_log_kind")
            method = (read_method_for_file(original["inspection"]["data"], kind)
                      if by_file and expected is not None else node_method)
            if mixed:
                model.same(item["method"], method, "review_file_log_method_binding")
            tail = legacy_tail or (mixed and method == "byte-tail")
            phase = item["phase"];phases.append(phase)
            exact_keys(phase, set(nodes.empty_phase()), "review_file_log_phase")
            status, reason, label = phase["status"], phase["reason"], phase["command"]
            require(type(status) is str and status in nodes.PHASE_REASONS
                    and (reason is None or type(reason) is str) and reason in nodes.PHASE_REASONS[status],
                    "review_file_log_phase_status")
            if expected is None:
                model.same(phase, nodes.empty_phase(), "review_file_log_unowned")
            if label is None:
                require(status not in ("OBSERVED", "FAILURE") and reason != "command_incomplete"
                        and all(phase[key] is None for key in ("actual_exit", "output_complete", "outputs", "data")),
                        "review_file_log_no_command")
                continue
            require(expected is not None and status != "NOT_ATTEMPTED" and type(label) is str
                    and re.fullmatch(r"docker-([0-9]{3,6})-startup-file-" + role + "-" + kind, label),
                    "review_file_log_command")
            counters.append(uint(int(label.split("-", 2)[1]), 999999))
            receipt = receipt_reader(evidence, label, "review_file_log_receipt")
            require(receipt is not None and type(receipt.get("outputs")) is dict
                    and {"stdout", "stderr"} <= set(receipt["outputs"]), "review_file_log_receipt")
            require((type(phase["actual_exit"]) is int or phase["actual_exit"] is None)
                    and type(phase["output_complete"]) is bool, "review_file_log_exit_type")
            for key in ("actual_exit", "output_complete"):
                model.same(phase[key], receipt[key], "review_file_log_receipt_binding")
            exact_keys(phase["outputs"], {"stdout", "stderr"}, "review_file_log_outputs")
            for channel, limit in (("stdout", TAIL_BYTES if tail else ARCHIVE_BYTES), ("stderr", 4096)):
                pin = phase["outputs"][channel]
                exact_keys(pin, {"bytes", "sha256"}, "review_file_log_pin")
                uint(pin["bytes"], limit, minimum=0);model.digest(pin["sha256"])
                stream = receipt["outputs"][channel]
                require(type(stream) is dict and stream.get("file") == label + "." + channel,
                        "review_file_log_stream")
                model.same(pin, {key: stream[key] for key in pin}, "review_file_log_stream_binding")
            if status == "OBSERVED":
                require(phase["actual_exit"] == 0 and phase["output_complete"] is True
                        and receipt.get("launch_outcome") == "STARTED" and receipt.get("reason") is None
                        and receipt.get("process_group_quiescent") is True, "review_file_log_success")
                group = uint(receipt.get("process_group"))
                model.same(evidence.json(label + ".started.json"), {"format": "owned-devnet-command-started/v1",
                    "label": label, "pid": group, "process_group": group, "new_session_requested": True},
                    "review_file_log_start")
                check_data(phase["data"], tail=tail, complete_prefix=(by_file and kind == "error"),
                           with_broadcast_origins=with_broadcast_origins, with_height_two=with_height_two)
                size = phase["outputs"]["stdout"]["bytes"]
                if tail:
                    model.same(phase["data"]["content"], phase["outputs"]["stdout"],
                               "review_file_log_tail_pin")
                else:
                    require(size >= 1536 and size % 512 == 0
                            and phase["data"]["content"]["bytes"] <= size - 1536,
                            "review_file_log_tar_bound")
            else:
                require(phase["data"] is None, "review_file_log_unvalidated")
                if status == "FAILURE":
                    require(type(phase["actual_exit"]) is int and phase["actual_exit"] != 0
                            and phase["output_complete"] is True, "review_file_log_failure")
                if reason == "command_incomplete":
                    require(phase["output_complete"] is False, "review_file_log_incomplete")
    require(counters == sorted(set(counters)) and (not counters or min(counters) > max(
        int(label.split("-", 2)[1]) for label in earlier)), "review_file_log_order")
    stops = [int(match[1]) for name in evidence.pins if (match := re.fullmatch(
        r"evidence/docker-([0-9]{3,6})-(?:inspect-(?:pillar|pillar2|pillar3|rpc)-stop-state\.json"
        r"|stop-(?:pillar|pillar2|pillar3|rpc)\.(?:started|complete)\.json)", name))]
    require(not counters or not stops or max(counters) < min(stops), "review_file_log_cleanup_order")
    complete = all(phase["status"] == "OBSERVED" for phase in phases)
    require(summary["status"] != "OBSERVED" or complete, "review_file_log_complete")
    require(summary["reason"] != "incomplete_diagnostics" or not complete, "review_file_log_incomplete_status")
    return {"summary": summary, "diagnostic_assertions_only": True,
            "original_tar_or_text_independently_rechecked": False, "accepted_header_authority": False}
