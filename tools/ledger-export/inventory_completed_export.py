#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Reconcile export completion, then recount the same retained put stream.

The caller selects the frontier, provenance, limits and actual producer capture
through a protected channel. No database, network, child or output file is opened.
This joins existing checks; it does not authenticate the caller or ledger state.
"""
import importlib.util
import io
import json
from pathlib import Path
import sys


sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


COMPLETION = load("completed_export_completion", HERE / "consume_completion.py")
INVENTORY = load("completed_export_inventory", HERE.parent / "ledger-inventory/inventory.py")
FORMAT = "zenon-completed-frontier-inventory/v1"
RECEIPT_OPTION = "--producer-receipt-json"
RESULT_BYTES = COMPLETION.REPORT_BYTES + INVENTORY.REPORT_BYTES + 4096
USAGE = ("inventory-completed-export: require --producer-receipt-json JSON and the "
         "consume-completion selection, actual capture and optional --max-* arguments; "
         "feed the same retained put stream on stdin\n")


def scope():
    return {"outer_completion_authenticated": False, "ledger_origin_authenticated": False,
            "snapshot_completeness_authenticated": False,
            "physical_scan_statistics_independently_verified": False,
            "representative_dataset_accepted": False, "profile_agreed": False,
            "network_activation_authenticated": False, "header_authentication_executed": False,
            "canonical_chain_qualified": False, "absence_or_delete_proof": False,
            "state_value_acceptance_enabled": False}


def unknown(reason, completion=None):
    return {"format": FORMAT, "status": "UNKNOWN", "reason": reason,
            "producer_completion_matched": completion is not None,
            "stream_recount_completed": False, "producer_completion": completion,
            "stream_inventory": None, "scope": scope()}


def arguments(args):
    COMPLETION.require(type(args) in (list, tuple) and len(args) <= 34 and
                       all(type(v) is str for v in args) and
                       sum(map(len, args)) <= 32 << 10, "options")
    common, receipt, index = [], None, 0
    while index < len(args):
        key, separator, value = args[index].partition("=")
        if key == RECEIPT_OPTION:
            COMPLETION.require(receipt is None, "options")
            if not separator:
                index += 1
                COMPLETION.require(index < len(args), "options")
                value = args[index]
            COMPLETION.require(bool(value) and len(value) <= COMPLETION.REPORT_BYTES, "options")
            receipt = value.encode("utf-8")
            COMPLETION.require(len(receipt) <= COMPLETION.REPORT_BYTES, "options")
        else:
            common.append(args[index])
        index += 1
    COMPLETION.require(receipt is not None, "options")
    return common, receipt


def run(args, stream, output, diagnostics):
    completed = None
    try:
        if type(args) in (list, tuple) and len(args) == 1 and args[0] in ("--help", "-h"):
            diagnostics.write(USAGE)
            result, code = unknown("help_only"), 0
        else:
            common, receipt = arguments(args)
            capture = io.StringIO()
            code = COMPLETION.run(common, io.BytesIO(receipt), capture, diagnostics)
            matched = json.loads(capture.getvalue())
            if code != 0 or matched["status"] != "SELECTED_EXPORT_COMPLETION_MATCHED":
                result = unknown("completion_" + matched["reason"])
                code = code or 2
            else:
                completed = matched
                report = INVENTORY.inventory(stream, matched["inventory_selection"],
                                             matched["inventory_limits"])
                INVENTORY.encoded(report)  # Retain the inventory's own report bound.
                result = {"format": FORMAT, "status": "SELECTED_EXPORT_INVENTORIED", "reason": None,
                          "producer_completion_matched": True, "stream_recount_completed": True,
                          "producer_completion": matched, "stream_inventory": report,
                          "scope": scope()}
                code = 0
    except COMPLETION.Refused:
        result, code = unknown("options"), 64
    except INVENTORY.Refused:
        result, code = unknown("stream_inventory_refused", completed), 2
    except (ValueError, TypeError, RecursionError, OverflowError):
        result, code = unknown("input_or_options", completed), 64
    except OSError:
        result, code = unknown("input_or_output", completed), 70
    except KeyboardInterrupt:
        result, code = unknown("cancelled", completed), 130
    raw = json.dumps(result, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n"
    if len(raw.encode("utf-8")) > RESULT_BYTES:
        raw = json.dumps(unknown("result_size"), sort_keys=True, separators=(",", ":")) + "\n"
        code = 70
    try:
        if output.write(raw) != len(raw):
            raise OSError("short result write")
        output.flush()
    except OSError:
        try:
            diagnostics.write("inventory-completed-export: result write failed\n")
        except OSError:
            pass
        return 70
    except KeyboardInterrupt:
        return 130
    return code


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:], sys.stdin.buffer, sys.stdout, sys.stderr))
