#!/usr/bin/env python3
"""Check fixed synthetic consumer contexts with the independent Python oracle."""

import hashlib
import importlib.util
import json
from pathlib import Path
import re


def main():
    root = Path(__file__).resolve().parents[1]
    oracle_path = root / "tools/check-verification-context.py"
    spec = importlib.util.spec_from_file_location("context_byte_oracle", oracle_path)
    oracle = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(oracle)
    path = root / "tools/consume-query-report/testdata/context-fingerprints.json"
    with path.open("rb") as source:
        raw = source.read(512 * 1024 + 1)
    if len(raw) > 512 * 1024:
        raise ValueError("Selected vector bound exceeded")
    vectors = json.loads(raw)
    selected = [(version, count) for version in (1, 2) for count in (0, 16, 256)]
    if not isinstance(vectors, list) or len(vectors) != len(selected):
        raise ValueError("Selected context vector count changed")
    for vector, (version, count) in zip(vectors, selected):
        if set(vector) != {"name", "context", "encoded_input_hex", "expected_fingerprint"}:
            raise ValueError("Selected vector shape changed")
        context = vector["context"]
        expected = vector["expected_fingerprint"]
        encoded = bytes.fromhex(vector["encoded_input_hex"])
        if vector["name"] != f"v{version}/checkpoints_{count}" or context["schema_version"] != version:
            raise ValueError("Selected schema or case changed")
        if len(context["checkpoints"]) != count or re.fullmatch(r"[0-9a-f]{64}", expected) is None:
            raise ValueError("Selected checkpoint count or digest changed")
        if not encoded.startswith(f"zenon-spv/verification-context/v{version}\0".encode("ascii")):
            raise ValueError("Selected encoded domain changed")
        if context["fingerprint"] != expected or hashlib.sha3_256(encoded).hexdigest() != expected:
            raise ValueError("Complete selected message does not bind its digest")
        if oracle.fingerprint(context) != expected:
            raise ValueError("Independent context encoding differs")
    print(json.dumps({
        "status": "consumer_context_hash_vectors_checked",
        "selected_contexts": len(vectors),
        "checkpoint_counts": [0, 16, 256],
        "vectors_sha256": hashlib.sha256(raw).hexdigest(),
        "oracle_sha256": hashlib.sha256(oracle_path.read_bytes()).hexdigest(),
        "trust_inputs_authenticated": False,
    }, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        raise SystemExit("Consumer context hash vector check failed")
