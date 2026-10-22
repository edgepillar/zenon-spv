"""Validate finite public Chain read/Stop observations against sealed witnesses."""
import hashlib
import json

CONTRACT_SHA256 = "e211b1f8b7679b77480aeb31e390d9c5c39ebc1a57ae5b03c216a93bc6000688"
HEX64 = set("0123456789abcdef")
FLAGS = ("accepted_header_binding", "production_state_value_accepted",
         "Chain_Start_selected", "Node_entrypoint_selected",
         "wallet_or_signing_or_user_transaction_selected", "chain_networking_selected")

def require(value):
    if not value:
        raise ValueError("Public Chain read/Stop observation refused")

def integer(value, maximum=120_000_000_000):
    require(type(value) is int and 0 <= value <= maximum)
    return value

def digest(value):
    require(type(value) is str and len(value) == 64 and set(value) <= HEX64)
    return value

def validate(contract, observation, profile):
    require(type(contract) is dict and contract["schema"] == "preselected-public-Chain-proof-Stop-contract-v1")
    require(hashlib.sha256((json.dumps(contract, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()).hexdigest() == CONTRACT_SHA256)
    require(profile in ("ordinary", "race"))
    keys = {"schema", "profile", "node_revision", "runtime_tree", "wire_sha256",
            "build_race_enabled", "init_ready", "warmup_completed_ns", "warmup_row_sha256s",
            "calls", "post_Stop", "Stop", "component_total_ns", "consumer_result", *FLAGS}
    require(type(observation) is dict and set(observation) == keys)
    require(observation["schema"] == "public-Chain-proof-Stop-process-v1")
    require(observation["profile"] == profile)
    require(type(observation["build_race_enabled"]) is bool and observation["build_race_enabled"] is (profile == "race"))
    require(observation["node_revision"] == contract["reference_node_revision"])
    require(observation["runtime_tree"] == contract["reference_runtime_tree"])
    require(digest(observation["wire_sha256"]) == contract["blinded_wire_selection"]["sha256"])
    require(observation["init_ready"] is True and observation["consumer_result"] == "REFUSED")
    require(all(observation[name] is False for name in FLAGS))
    expected = contract["successful_proof_rows"]
    require(type(expected) is list and len(expected) == 128)
    require(observation["warmup_row_sha256s"] == [row["row_sha256"] for row in expected])
    total = integer(observation["component_total_ns"])
    warmup = integer(observation["warmup_completed_ns"])
    stop = observation["Stop"]
    require(type(stop) is dict and set(stop) == {"start_ns", "end_ns", "error", "ready_after", "calls", "idempotent_cleanup_error"})
    start, end = integer(stop["start_ns"]), integer(stop["end_ns"])
    require(warmup <= start < end <= total)
    require(stop["error"] is None and stop["ready_after"] is False and stop["idempotent_cleanup_error"] is None)
    require(type(stop["calls"]) is int and stop["calls"] == 2)
    calls = observation["calls"]
    require(type(calls) is list and len(calls) == 2048)
    outcomes = {"Root_success": 0, "Root_refusal": 0, "GetProof_success": 0, "GetProof_refusal": 0}
    previous = [warmup] * 16
    overlaps = 0
    successful_overlaps = 0
    earliest = total
    def pair(row, index, post=False):
        nonlocal overlaps, successful_overlaps, earliest
        require(type(row) is dict and set(row) == {"index", "worker", "key_index", "Root_start_ns", "Root_end_ns", "GetProof_start_ns", "GetProof_end_ns", "Root", "GetProof"})
        require(type(row["index"]) is int and row["index"] == index)
        require(type(row["worker"]) is int and row["worker"] == (0 if post else index % 16))
        require(type(row["key_index"]) is int and row["key_index"] == index % 128)
        rs, re = integer(row["Root_start_ns"]), integer(row["Root_end_ns"])
        ps, pe = integer(row["GetProof_start_ns"]), integer(row["GetProof_end_ns"])
        require(warmup <= rs <= re <= ps <= pe <= total)
        if post:
            require(rs >= end)
        else:
            require(rs >= previous[index % 16])
            previous[index % 16] = pe
            earliest = min(earliest, rs)
        root, proof = row["Root"], row["GetProof"]
        require(type(root) is dict and set(root) == {"error", "hash"})
        require(type(proof) is dict and set(proof) == {"error", "row_sha256", "value_nil", "proof_nil"})
        require(type(proof["value_nil"]) is bool and type(proof["proof_nil"]) is bool)
        target = expected[index % 128]
        for kind, value, begin, finish in (("Root", root, rs, re), ("GetProof", proof, ps, pe)):
            error = value["error"]
            require(error is None or type(error) is str and error in contract["permitted_API_refusal_classes"])
            if finish < start:
                require(error is None)
            if begin >= end:
                require(error == "state_tree_not_ready")
            if not post and begin < end and finish > start:
                overlaps += 1
                successful_overlaps += int(error is None)
            if kind == "Root":
                require(digest(value["hash"]) == (contract["successful_root"] if error is None else "0" * 64))
            elif error is None:
                require(root["error"] is None)
                require(digest(value["row_sha256"]) == target["row_sha256"])
                require(value["value_nil"] is (not target["present_in_projection"]) and value["proof_nil"] is False)
            else:
                require(value["row_sha256"] is None and value["value_nil"] is True and value["proof_nil"] is True)
            if not post:
                outcomes[kind + ("_success" if error is None else "_refusal")] += 1
    for index, row in enumerate(calls):
        pair(row, index)
    require(start >= earliest)
    completed_before_Stop = sum(row["GetProof_end_ns"] <= start for row in calls)
    require(completed_before_Stop >= contract["minimum_completed_concurrent_pairs_before_Stop"])
    pair(observation["post_Stop"], 0, post=True)
    require(sum(outcomes.values()) == 4096)
    return {"status": "MATCH" if overlaps >= contract["minimum_observed_public_call_intervals_overlapping_Stop"] and successful_overlaps >= contract["minimum_successful_caller_intervals_overlapping_Stop"] else "INCONCLUSIVE",
            "profile": profile, "independent_warmup_witnesses": 128, "concurrent_request_pairs": 2048,
            "individual_Root_and_GetProof_calls": 4354, "public_call_intervals_overlapping_Stop": overlaps,
            "successful_caller_intervals_overlapping_Stop": successful_overlaps,
            "completed_concurrent_pairs_before_Stop": completed_before_Stop,
            "internal_database_interleaving_proven": False, "outcomes": outcomes,
            "consumer_result": "REFUSED", "accepted_header_binding": False,
            "production_state_value_accepted": False, "full_M4_qualified": False}
