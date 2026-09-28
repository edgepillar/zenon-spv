# Node-derived momentum corpus

`momentum-v1-v2.json` is corpus format 1. It contains nine standalone
serialization cases, a six-header synthetic version-1 chain, and a six-header
v1-to-v2 transition (21 momentums total). All expected
hashes, content encodings, Bech32 addresses, and RPC JSON come from
`zenon-network/go-zenon` at
[`3a4131e63881058b6ce2ee81d3a41d0033fafc99`](https://github.com/zenon-network/go-zenon/tree/3a4131e63881058b6ce2ee81d3a41d0033fafc99).

The generator calls `nom.Momentum.ComputeHash`, `MomentumContent.Hash`, the
node's account-header comparator, and the node's JSON marshalers. It imports
no SPV packages. Its separate Go module pins the node source and checks the
dependency version, checksum, and absence of replacements before generating
output. The root module and normal test suite do not depend on go-zenon.

## Coverage and limits

- Version 1: empty and binary data; user and embedded addresses; content
  ordering by address, big-endian height, and hash; integers above 2^32 and
  2^53 and at uint64 maximum; price fields excluded from the v1 hash.
- Version 2: both price fields appended to the signed preimage, including
  zero, large, and maximum values. Hash/RPC tests cover the layout separately
  from activation. Core verification requires an explicit profile and rejects
  prices below the pinned node floor of 1000.
- Linked v1 and transition chains exercise RPC conversion, signatures, header
  extension, content inclusion, strict-past depth, persistence, and tamper
  rejection. The transition changes at synthetic height 2003 and also runs
  through the CLI and a local watch/resume experiment.
- The public all-zero Ed25519 test seed is only for deterministic synthetic
  signatures. No wallet, operator key, live RPC endpoint, or captured user
  data is used.

These are serialization vectors, not assertions that a full node would
accept each momentum. Extreme heights/timestamps, duplicate account
frontiers, nonzero v1 price fields, and the synthetic anchor deliberately
exercise byte-level behavior without claiming consensus validity. The corpus
does not establish network activation, elected producers, canonicality,
state-transition correctness, finality, or state-value proofs. It does not
yet cover account-block serialization or proposed v3 state-root layouts.

The node sorts content when constructing it; `MomentumContent.Hash` itself
hashes the supplied sequence. These fixtures use canonically ordered content.
They do not settle how a consumer should handle noncanonical RPC ordering.

## Reproduction

From the repository root, using Go 1.25 or later:

```sh
(cd tools/gen-node-momentum-vectors && go run -mod=readonly .) > /tmp/momentum-v1-v2.json
cmp internal/testdata/conformance/momentum-v1-v2.json /tmp/momentum-v1-v2.json
python3 tools/gen-node-momentum-vectors/check.py /tmp/momentum-v1-v2.json
go test ./internal/conformance
```

The generator may download the pinned node module and its dependencies.
The Go tests use checked-in JSON and local HTTP servers; they make no
live-node requests. Python's standard-library checker independently
reconstructs SHA3-256 preimages, uint64 byte order, and Bech32 address bytes;
the Go tests check Ed25519 signatures. Generation is deterministic and emits
no local paths, timestamps, or machine metadata.

The source commit is a provenance record, not a deployment claim. Updating
it requires reviewing the node layout and all changed vectors together;
do not regenerate expected values from the implementation under test.
