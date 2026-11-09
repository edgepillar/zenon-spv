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
TRANSPORT = load("completed_export_transport", HERE.parent / "ledger-transport/transport.py")
FORMAT = "zenon-completed-frontier-inventory/v1"
TRANSPORT_FORMAT = "zenon-completed-frontier-transport-inventory/v1"
RECEIPT_OPTION = "--producer-receipt-json"
MANIFEST_BYTES_OPTION = "--transport-manifest-bytes"
MANIFEST_SHA_OPTION = "--transport-manifest-sha256"
RESULT_BYTES = COMPLETION.REPORT_BYTES + INVENTORY.REPORT_BYTES + 4096
USAGE = ("inventory-completed-export: require --producer-receipt-json JSON and the "
         "consume-completion selection, actual capture and optional --max-* arguments; "
         "feed the same retained put stream on stdin. To check transport during the "
         "recount, supply --transport-manifest-bytes and --transport-manifest-sha256 "
         "and feed the exact manifest immediately before the put stream.\n")


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
    COMPLETION.require(type(args) in (list, tuple) and len(args) <= 38 and
                       all(type(v) is str for v in args) and
                       sum(map(len, args)) <= 32 << 10, "options")
    common, selected, index = [], {}, 0
    option_limits = {RECEIPT_OPTION: COMPLETION.REPORT_BYTES,
                     MANIFEST_BYTES_OPTION: 20, MANIFEST_SHA_OPTION: 64}
    while index < len(args):
        key, separator, value = args[index].partition("=")
        if key in option_limits:
            COMPLETION.require(key not in selected, "options")
            if not separator:
                index += 1
                COMPLETION.require(index < len(args), "options")
                value = args[index]
            COMPLETION.require(0 < len(value) <= option_limits[key], "options")
            selected[key] = value
        else:
            common.append(args[index])
        index += 1
    COMPLETION.require(RECEIPT_OPTION in selected, "options")
    receipt = selected[RECEIPT_OPTION].encode("utf-8")
    COMPLETION.require(len(receipt) <= COMPLETION.REPORT_BYTES, "options")
    manifest = None
    if len(selected) > 1:
        COMPLETION.require(MANIFEST_BYTES_OPTION in selected and MANIFEST_SHA_OPTION in selected, "options")
        size = COMPLETION.decimal(selected[MANIFEST_BYTES_OPTION])
        digest = selected[MANIFEST_SHA_OPTION]
        COMPLETION.require(0 < size <= TRANSPORT.MANIFEST_BYTES and COMPLETION.hex_digest(digest), "options")
        manifest = size, digest
    else:
        COMPLETION.require(len(args) <= 34, "options")
    return common, receipt, manifest


def run(args, stream, output, diagnostics):
    completed = None
    try:
        if type(args) in (list, tuple) and len(args) == 1 and args[0] in ("--help", "-h"):
            diagnostics.write(USAGE)
            result, code = unknown("help_only"), 0
        else:
            common, receipt, manifest = arguments(args)
            capture = io.StringIO()
            code = COMPLETION.run(common, io.BytesIO(receipt), capture, diagnostics)
            matched = json.loads(capture.getvalue())
            if code != 0 or matched["status"] != "SELECTED_EXPORT_COMPLETION_MATCHED":
                result = unknown("completion_" + matched["reason"])
                code = code or 2
            else:
                completed = matched

                def recount(payload):
                    return INVENTORY.inventory(payload, matched["inventory_selection"], matched["inventory_limits"])

                transport = None
                if manifest is None:
                    report = recount(stream)
                else:
                    pin = {**matched["inventory_selection"], **matched["selected_frontier"]}
                    del pin["records"]  # Transport binds bytes and the full frontier, not record counts.
                    caps = {**TRANSPORT.HARD_LIMITS, "bytes": matched["inventory_limits"]["bytes"]}
                    transport, report = TRANSPORT.verify_with(stream, *manifest, pin, recount, caps)
                INVENTORY.encoded(report)  # Retain the inventory's own report bound.
                result = {"format": FORMAT, "status": "SELECTED_EXPORT_INVENTORIED", "reason": None,
                          "producer_completion_matched": True, "stream_recount_completed": True,
                          "producer_completion": matched, "stream_inventory": report,
                          "scope": scope()}
                if transport is not None:
                    result.update(format=TRANSPORT_FORMAT, transport_verification=transport)
                code = 0
    except COMPLETION.Refused:
        result, code = unknown("options"), 64
    except TRANSPORT.Refused as error:
        result, code = unknown("transport_" + str(error), completed), 2
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
