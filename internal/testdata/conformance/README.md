# Node-derived conformance corpora

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
yet cover complete account-block semantics or proposed v3 state-root layouts.

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

## Account amount corpus

`account-amounts.json` uses the same source pin and generator module, with seven
account-block vectors covering scalar boundaries and raw magnitude encoding.
It includes binary data, a synthetic descendant hash, wide scalar fields, and
synthetic Ed25519 signatures. Invalid amounts are intentionally serialized and
signed to distinguish low-level hash parity from acceptable proof inputs.
See [account amount validation](../../../docs/account-amount-validation.md)
for the exact scope and the pre-fix offline alias reproductions.

```sh
(cd tools/gen-node-momentum-vectors && go run -mod=readonly . --account-amounts) > /tmp/account-amounts.json
cmp internal/testdata/conformance/account-amounts.json /tmp/account-amounts.json
python3 tools/gen-node-momentum-vectors/check-account-amounts.py /tmp/account-amounts.json
go test ./internal/conformance ./internal/verify ./internal/fetch
```

The Python checker independently verifies magnitude bytes, data and descendant
digests, scalar classification, and full hash preimages. Signature checks remain
in Go. The corpus contains no wallet or live-network observations and does not
assert full-node validity, authenticated state transitions, or finality.

## Linked account segments

`account-segments.json` adds four node-derived account blocks: user send and
receive, plus unsigned embedded-contract receive and send. Each address has a
linked two-block segment. A nine-momentum synthetic v1 chain commits all four
account headers at its third momentum and provides six strict-past headers.
Expected account hashes, RPC fields, address/token encodings, content order,
and momentum hashes come from the pinned node module without importing SPV code.

```sh
(cd tools/gen-node-momentum-vectors && go run -mod=readonly . --account-segments) > /tmp/account-segments.json
cmp internal/testdata/conformance/account-segments.json /tmp/account-segments.json
python3 tools/gen-node-momentum-vectors/check-account-segments.py /tmp/account-segments.json
go test ./internal/conformance -run TestNodeAccountSegments
```

The Go test fetches both account segments and momentums from local RPC peers,
compares them with node values, round-trips an offline bundle, and verifies full
and partial segments through the owned state API before and after trusted local
resume. It checks the strict-past boundary, parent-failure propagation, field and
signature tampering, and the different signature guarantees for user and embedded
accounts. Canonicality, producer authorization, and state-value/transition
guarantees must remain absent.

The independent Python checker validates the complete account hash preimages,
RPC projections, Bech32 address and token bytes, account/momentum links, content
membership, and depth. It shares standard-library byte primitives with the
earlier checkers; Ed25519 verification remains in Go.

These are linked serialization and inclusion fixtures, not an executed transfer
or node-accepted ledger. They do not run a VM, validate contract descendants,
prove account balances, derive elected producers, or establish finality. All
keys and anchors are deterministic public synthetic inputs.

## Contract batches

`contract-batches.json` adds five unsigned embedded blocks in two batches, using
the children-before-receive layout: send/send/receive followed by send/receive.
The pinned node's `AccountBlockTransaction.GetCommits` produces their flattened
order, and `NewMomentumContent` includes all five headers in the third of nine
synthetic momentums. Batch metadata records the node's `Previous()` frontier,
which differs from the receive's raw `PreviousHash`.

```sh
(cd tools/gen-node-momentum-vectors && go run -mod=readonly . --contract-batches) > /tmp/contract-batches.json
cmp internal/testdata/conformance/contract-batches.json /tmp/contract-batches.json
python3 tools/gen-node-momentum-vectors/check-contract-batches.py /tmp/contract-batches.json
go test ./internal/conformance -run TestNodeContractBatch
```

Go checks RPC conversion, bundle round trips, full and partial batch verification,
trusted resume, missing direct evidence, flat-content tampering, and descendant
hash tampering. Python independently checks preimages, projections, child order,
batch frontiers, membership, and depth. The tests preserve the existing direct
inclusion path and bounded guarantees. See [contract batch inclusion](../../../docs/contract-batches.md)
for source references and evidence limits. This corpus does not execute a VM or
assert full-node transaction validity.

## Delayed inclusion across versions

`delayed-inclusion.json` contains nineteen momentums across an explicit v1/v2
transition and two three-block account segments. User sends and embedded
receives are committed at three distinct heights, with exact preceding-header
acknowledgements. It uses the same pinned node module, public synthetic seed,
hash/serialization routines and source guard as the other corpora. See
[delayed inclusion](../../../docs/delayed-inclusion.md) for reproduction,
independent Python checks, strict-past and eviction boundaries, and the compiled
collector/watch/query workflow. This is independent byte-level compatibility
evidence, not captured network history or VM execution.

## Compact content scaling

`content-scaling.json` holds three compact synthetic recipes with 1, 1,000 and
100,000 account-header identities, sampled targets and seven signed v2 momentum
projections per recipe. The node computes each content root and linked header;
SPV expands the recipe and verifies the expected roots and signatures. The
Python checker independently expands every member and reconstructs all content
and momentum preimages. These identities have no executed account-block bodies;
the largest recipe stresses a local policy bound, not network traffic limits.

```sh
cd tools/gen-node-momentum-vectors
GOWORK=off GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOFLAGS= go run -mod=readonly . --content-scaling > ../../internal/testdata/conformance/content-scaling.json
cd ../..
python3 tools/gen-node-momentum-vectors/check-content-scaling.py
```

The pinned node module and dependencies must already be cached. See
[flat-content resources](../../../docs/flat-content-resources.md) for measurement
scope, encoded repeated-list sizes, trust inputs and known limitations.
