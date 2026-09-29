#!/usr/bin/env python3
"""Check the account-amount corpus with Python's standard library only."""

import json
from pathlib import Path
import sys

from check import require
from check_account import check_account


def check(path):
    corpus = json.loads(Path(path).read_text())
    require(corpus["format_version"] == 1, "unsupported corpus format")
    require(corpus["source"]["commit"] == "3a4131e63881058b6ce2ee81d3a41d0033fafc99", "wrong source pin")
    require(len(corpus["vectors"]) == 7, "incomplete corpus")
    for vector in corpus["vectors"]:
        block, rpc = vector["block"], vector["rpc"]
        amount = block["amount"]
        require(amount == int(rpc["amount"]), "amount differs across wire forms")
        encoded = check_account(block, rpc)
        require(encoded.hex() == vector["amount_bytes"], "amount encoding lost magnitude bytes")
        require(vector["scalar_valid"] == (0 <= amount < 2**255), "wrong scalar classification")
    print("Verified 7 node-derived account amount vectors.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: check-account-amounts.py CORPUS.json")
    check(sys.argv[1])
