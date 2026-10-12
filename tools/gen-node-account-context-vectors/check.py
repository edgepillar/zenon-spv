#!/usr/bin/env python3
"""Check recorded context failures with independent bytes and exact store traces.

This checker executes no node, signature backend, database or network request.
The selected nil faults are programmatic recording-store observations only.
"""
import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys

HERE = Path(__file__).resolve().parent
FIXTURES = HERE.parents[1] / "internal/testdata/conformance"
spec = importlib.util.spec_from_file_location("context_account_bytes", HERE.parent / "gen-node-account-vectors/check.py")
ACCOUNT = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ACCOUNT)
CORPUS_SHA256 = "5fa1dd0d1960d9d25ae1f1294d84e50034fb83fa5046f67fd7485b634aab18e7"
INPUTS = {"account-segments.json": ACCOUNT.INPUTS["account-segments.json"]}
NODE = {k: v for k, v in ACCOUNT.NODE.items() if k != "function"}
NODE["methods"] = ["verifier.AccountBlockVerifier.AccountBlock", "verifier.AccountBlockVerifier.AccountBlockTransaction"]
SCOPE = {"actual_node_entry_point_execution": True, "synthetic_recording_store": True,
         "context_failure_only": True, "programmatic_nil_store_inputs": True,
         "basic_account_checks_reached": False, "hash_signature_checks_reached": False,
         "new_signatures_generated": False, "database_opened": False, "network_transport": False,
         "full_node_validation": False, "authenticated_context": False, "canonicality": False,
         "consensus_finality": False, "state_value_acceptance": False}
PROFILES = ("height-zero", "previous-nonzero-at-one", "previous-zero-at-two", "ack-zero",
            "previous-missing", "previous-height-exists", "previous-cemented", "frontier-error", "by-hash-error",
            "global-momentum-nil", "global-account-nil", "global-frontier-nil")
METHODS = ("AccountBlock", "AccountBlockTransaction")


def expected_rows():
    source = ACCOUNT.read_selected(FIXTURES / "account-segments.json", INPUTS["account-segments.json"])
    originals = {v["name"]: v["rpc"] for segment in source["segments"] for v in segment["vectors"]}
    ACCOUNT.need(len(originals) == 4, "context_input_inventory")
    rows = []
    for baseline in ("user-type-2", "embedded-type-5"):
        profiles = PROFILES + (("ack-store-missing",) if baseline == "embedded-type-5" else ())
        for profile in profiles:
            wire = copy.deepcopy(originals[baseline])
            plan = {"ack_store_present": True, "global_momentum_present": True, "global_account_present": True,
                    "frontier_present": True, "frontier_height": 0, "frontier_error": False,
                    "by_hash_present": False, "by_hash_error": False}
            calls = []
            early = {"height-zero": "height_missing", "previous-nonzero-at-one": "previous_must_be_zero",
                     "previous-zero-at-two": "previous_missing", "ack-zero": "ack_zero"}
            error = early.get(profile, "account_previous_missing")
            result = "REJECT"
            if profile == "height-zero": wire["height"] = 0
            if profile == "previous-nonzero-at-one": wire["previousHash"] = "01" + "00" * 31
            if profile == "previous-zero-at-two": wire["height"] = 2
            if profile == "ack-zero": wire["momentumAcknowledged"] = {"hash": "00" * 32, "height": 0}
            if profile in ("previous-height-exists", "previous-cemented", "by-hash-error"): plan["frontier_height"] = 1
            if profile == "previous-cemented": plan["by_hash_present"] = True
            if profile == "frontier-error": plan["frontier_error"] = True
            if profile == "by-hash-error": plan["by_hash_error"] = True
            if profile == "global-momentum-nil": plan["global_momentum_present"] = False
            if profile == "global-account-nil": plan["global_account_present"] = False
            if profile == "global-frontier-nil": plan["frontier_present"] = False
            if profile == "ack-store-missing": plan["ack_store_present"] = False
            if profile not in early:
                if baseline == "embedded-type-5":
                    calls.append({"method": "Chain.GetMomentumStore", "identifier": copy.deepcopy(wire["momentumAcknowledged"])})
                if profile == "ack-store-missing":
                    error = "ack_store_missing"
                else:
                    # Both independently selected baselines are first blocks,
                    # with no descendants and the complete zero Previous() ID.
                    ACCOUNT.need(wire["height"] == 1 and wire["previousHash"] == "00" * 32 and
                                 wire["descendantBlocks"] == [], "context_first_block_selection")
                    calls += [{"method": "Chain.GetAccountStore", "address": wire["address"],
                               "identifier": {"hash": "00" * 32, "height": 0}},
                              {"method": "Chain.GetFrontierMomentumStore"}]
                    if profile == "global-momentum-nil": result, error = "PANIC", "nil_pointer"
                    else:
                        calls.append({"method": "Momentum.GetAccountStore", "address": wire["address"]})
                        if profile == "global-account-nil": result, error = "PANIC", "nil_pointer"
                        else:
                            calls.append({"method": "Account.Frontier"})
                            if profile == "global-frontier-nil": result, error = "PANIC", "nil_pointer"
                            elif profile == "frontier-error": error = "internal_store_error"
                            elif plan["frontier_height"] > 0:
                                calls.append({"method": "Account.ByHash", "hash": "00" * 32})
                                error = {"previous-height-exists": "previous_height_exists",
                                         "previous-cemented": "previous_cemented",
                                         "by-hash-error": "internal_store_error"}[profile]
            _, digest = ACCOUNT.projection(wire)
            for method in METHODS:
                rows.append({"name": baseline + "/" + profile + "/" + method, "baseline": baseline,
                             "profile": profile, "method": method, "store_plan": copy.deepcopy(plan),
                             "account_block": copy.deepcopy(wire), "computed_hash": digest.hex(),
                             "node_context_result": result, "node_error": error, "context_calls": copy.deepcopy(calls)})
    return rows


def check(document):
    expected = {"format_version": 1, "source": NODE, "scope": SCOPE, "input_files_sha256": INPUTS,
                "observations": expected_rows()}
    ACCOUNT.need(ACCOUNT.exact(document, expected), "context_exact_document_bytes_calls_and_outcomes")
    rows = document["observations"]
    ACCOUNT.need(len(rows) == 50 and sum(r["node_context_result"] == "REJECT" for r in rows) == 38 and
                 sum(r["node_context_result"] == "PANIC" for r in rows) == 12, "context_complete_selection")
    return {"status": "recorded_node_context_failures_checked", "source_node_commit": NODE["commit"],
            "corpus_sha256": CORPUS_SHA256, "recorded_entry_point_calls": 50, "methods": 2,
            "complete_byte_preimages_checked": 50, "recorded_REJECT": 38, "recorded_PANIC": 12,
            "actual_node_calls_in_checker": 0, "actual_signature_processes": 0,
            "basic_account_checks_reached": False, "hash_signature_checks_reached": False,
            "context_authenticated": False, "runtime_acceptance_changed": False,
            "network_or_production_qualified": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-revision")
    args = parser.parse_args()
    if args.source_revision is not None:
        ACCOUNT.need(re.fullmatch(r"[0-9a-f]{40}", args.source_revision) is not None, "context_source_revision")
    document = ACCOUNT.read_selected(FIXTURES / "node-account-context.json", CORPUS_SHA256)
    report = check(document)
    report["source_revision"] = args.source_revision
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (ACCOUNT.signatures.Refused, ValueError, KeyError, TypeError, OSError):
        print(json.dumps({"status": "REFUSED", "stage": "node_account_context_corpus"}), file=sys.stderr)
        sys.exit(1)
