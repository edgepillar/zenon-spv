# Candidate raw-v3 RPC projection

`fetch.DecodeCandidateV3Momentum` converts one selected-node result object into
an untrusted `chain.CandidateV3Header`, parsed content and a locally derived
producer address. It is a pure decoder. Production fetch, accepted header state,
profiles, context pins, persistence and state-value verification are unchanged.

This is D2 input preparation for the [typed-state delivery plan](typed-state-roadmap.md),
not an owned accepted-v3 path or a completed devnet consumer query.

## Source execution and independent bytes

The selected source is
[`digitalSloth/go-zenon@938fca3b`](https://github.com/digitalSloth/go-zenon/tree/938fca3b7787da86827a5eb63371509b36e14761).
The new [capture harness](../tools/gen-state-root-vectors/candidate-v3-rpc-capture_test.go.txt)
executes the exact `Momentum` DTO and `ledgerMomentumToRpc` function fragments
from `rpc/api/ledger_types.go` with original `nom.Momentum` types. Their bytes
were compared before execution; all 484 original source files remained unchanged.
The whole RPC package, its routes and a network service were **not executed**.

The [recorded fixture](../internal/testdata/conformance/candidate-v3-node-rpc.json)
retains each exact marshalled result as a JSON string, source/harness hashes,
actual execution/output/gate identities and explicit scope. The local execution
used Go 1.25.14 on darwin/arm64 with CGO enabled: one test and eight subtests
passed. All 19 actually used module ZIPs and expanded directories matched the
original `go.sum` using independent h1 calculations. Complete historical module
graph verification remains `NOT_ESTABLISHED`.

Three cases reuse the existing public signatures at heights 12–14 from the
[chain-100 boundary fixture](first-v3-node-boundary.md). Five cases have zero
signature bytes and exercise binary data, both orders of nonempty content,
uint64 boundaries and a zero root. No new signature was created. These cases
remain separate from the selected source genesis, whose chain ID is 69.

An independent Python calculation compared all eight raw data hashes, ordered
content byte streams/hashes, producer addresses and 208-byte header preimages
with the source execution. It checked the Bech32 checksum and public-key address
derivation separately from Go. The exact API fragments and fixture signature
checks do not establish RPC routing, network identity, producer authorization,
activation, consensus finality or accepted state values.

## Decoder contract

The input is one result object, without its JSON-RPC wrapper. All fifteen exact
field names are required once: version, chain identifier, hash, previous hash,
height, timestamp, raw data, content, changes hash, public key, signature, both
prices, state root and producer. Unknown, duplicate, case-aliased, missing, null
and trailing input is refused. Each content member similarly requires exactly
address, height and hash.

Integers fit uint64. Hashes use exactly 64 lowercase hexadecimal characters.
Byte fields use canonical padded Base64; data may be empty. Public keys and
signatures have widths 32 and 64. Addresses use canonical lowercase Zenon
Bech32 with a valid checksum and a 20-byte payload. The wire producer must match
the address derived from the public key. Version must be exactly 3.

The decoder computes SHA3-256 from decoded data. It hashes content in received
order as `address(20) || height(uint64BE) || hash(32)` for each member. The
selected node's `MomentumContent.Hash` does **not** sort its input: its separate
`NewMomentumContent` constructor sorts block headers. The existing SPV
`MomentumContentHash` helper sorts and is deliberately not used here. The two
captured content permutations have different hashes; changing the order without
changing the claimed header hash is refused. Decoding does not establish that a
content sequence satisfies the node's full consensus validation rules.

| Local resource limit | Bound |
| --- | ---: |
| Complete input, including surrounding whitespace | 256 KiB |
| Decoded data | 16 KiB |
| Content members, checked before decoding the next member | 1,024 |
| Signed header preimage | 208 bytes |

These are candidate transport budgets, not agreed network or proof limits. A
failure returns a zero result and the fixed `ErrCandidateV3Momentum` diagnostic;
remote values and addresses are never copied into that error. Returned byte
slices and content are detached from the input and other decodes. Signatures
are checked for representation only: a width-correct invalid signature remains
untrusted candidate data.

## Header projection for the BatchEntry workflow

The collector and the read-only CLI use `DecodeCandidateV3MomentumHeader`.
It hashes each validated content member in received order as the member is
decoded. The two callers retain the projected header. The collector also
keeps the original wire bytes for the provider bundle. The full
`DecodeCandidateV3Momentum` entry point still returns the decoded members.
Both entry points enforce the same field, content count and header hash
checks before returning a candidate.

A local Go 1.25.14 darwin/arm64 comparison used three samples per case and
one benchmark CPU. The baseline at `a7d33feb30793bb8328a54b1c3099798f9479938`
used the full decoder and selected its header.

| Input | Input bytes | Baseline B/op | Header projection B/op | Baseline allocs/op | Header projection allocs/op |
| --- | ---: | ---: | ---: | ---: | ---: |
| Recorded two-member momentum | 960 | 20,176 | 18,928 | 390 | 378 |
| Synthetic momentum at the 1,024-member limit | 146,076 | 3,779,712 | 3,418,577 | 59,681 | 59,659 |

The exact-limit case reuses the conformance test's independently calculated
header hash and repeated fixture member. The measurements cover allocation
volume during decoding. Live RPC latency and process resource limits have
separate measurements.

## Reproduction and remaining acceptance

For the recorded fixture and native decoder controls:

```sh
go test -race -count=1 -json -run '^TestCandidateV3Momentum' ./internal/fetch
```

To reproduce the source capture, verify a fresh isolated copy of the pinned node
and the exact two API fragments first. Copy the published harness to the new path
`chain/nom/spv_rpc_capture_test.go`, refusing an existing file. Select the unchanged
public `first-v3-node-headers.json` with `SPV_PUBLIC_BOUNDARY_INPUT`. With its pinned
dependencies already available, run only the new test:

```sh
GOWORK=off GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off CGO_ENABLED=1 \
  go test -count=1 -json -run '^TestSPVCandidateV3RPCSourceFragments$' ./chain/nom
```

The next integrated path still needs an explicitly selected network/genesis,
anchor, activation profile and producer schedule; the actual selected-genesis
v3 boundary; and one header-root-bound, locally keyed, typed `BatchEntry`
consumer query. The separate [experimental owned-state implementation](experimental-v3-owned-state.md)
now supplies profile/context, finite schedule, immutable header/root and
persistence mechanics under explicit configured inputs. Its recorded workflow
does not establish these selected-network gates. A provider
root, candidate hash or experimental switch supplies none of that authority.
The production v1/v2 gate still rejects these v3 results. Production state-proof
and irreversible-settlement decisions remain `NO_GO`.
