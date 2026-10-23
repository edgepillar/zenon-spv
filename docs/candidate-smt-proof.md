# Native candidate sparse proof comparison

Status: bounded candidate byte comparison, not an enabled state-proof profile.

`internal/proof/candidate_smt.go` supplies a native partial-SMT primitive for
the [accepted-header balance roadmap](native-roadmap.md). It reconstructs the
candidate root from a bounded proof and compares it with a caller-selected
root/path/value or absence. It does not return `verify.Result`, construct an
owned `VerifiedState`, authenticate a header or enable v3/state-value acceptance.

## Inputs and output

| API | Meaning |
| --- | --- |
| `CheckCandidateSMTInclusion` | Compare an explicit value at an already derived 32-byte path. The path is not hashed a second time. |
| `CheckCandidateSMTAbsence` | Compare explicit absence at that path; this alone establishes no application-domain coverage. |
| `CandidateBalanceKey` | Locally derive `03 || address[20] || 03 || token[10]`, exactly 32 bytes. |
| `CheckCandidateBalanceProof` | Derive that balance path locally and compare the selected presence/value bytes. A raw provider key/path cannot replace the local derivation. |

`CandidateSMTMatch` reports presence, detached raw value bytes, sibling count
and a canonical-encoding observation. Stored zero remains present. Present-empty
is representable by the shared core and is distinct from absence; this does not
override the L1 adapter's empty-to-delete rule. An absent typed claim must have
empty value bytes. No decimal amount codec, protocol maximum or spendability
claim is inferred.

The balance helper accepts fixed-width binary address/token types. Text callers
must validate their text grammar and checksums before converting to those types.
The helper does not parse an RPC envelope, choose an endpoint or authenticate
the root supplied by its caller.

## Bounded byte contract

The primitive implements the [candidate contract](state-root-candidate-contract.md):
SHA3-256 path/value leaves, zero empty subtrees at every depth, nonempty parent
hashing, deepest-first siblings and an MSB-first sibling bitmap. At most 256
siblings are consumed. Flags, bitmap popcount, count, exact lengths, leaf bytes,
selected path, explicit presence/value and reconstructed root must agree. Errors
return a zero observation and do not include supplied values in diagnostics.

Both byte caps are mandatory. A zero or negative cap never disables a bound.
The local hard ceilings are 4,096 value bytes and 12,391 proof bytes; these bound
research work and do not approve a balance range. Count and length are checked
before slicing, allocation from a value or proof reconstruction. Successful
returned values are copied once; no sibling map, unbounded proof allocation or
persistent result cache is created.

For a caller selecting a 32-byte value cap, the full 256-sibling present/absent
boundaries are 8,327/8,291 bytes. The original node also represents a 33-byte
magnitude. The native comparison preserves that fact when explicitly permitted
by its local cap and refuses it under a 32-byte cap; it never truncates or wraps
the value. The protocol's balance width remains an agreement gate.

The recorded decoder accepts equivalent proofs with a stored zero sibling.
The primitive preserves their mathematical match and reports `Canonical=false`.
It does not silently impose the offline consumer's stricter experimental policy
as a network rule. An accepting profile must explicitly select its canonical
encoding policy.

## Recorded source and independent checks

The unchanged 152,437-byte corpus has SHA-256
`8b69cdaf78ae4eeaad79cdfa493ed9633a1202e09819178da83e17be385f00d3`.
All 41 original proof outcomes stay attributed to
[`digitalSloth/go-zenon@56ce2c384966f2f1940967257a0788d3998a5eef`](https://github.com/digitalSloth/go-zenon/tree/56ce2c384966f2f1940967257a0788d3998a5eef):
24 matches, four root/value mismatches, two path mismatches and 11 malformed
proofs. This includes both equivalent zero-sibling encodings, all 256 sibling
positions, bit-order boundaries, stored zero, absence and the 33-byte value.

The byte oracle uses Python `hashlib.sha3_256` and a separate bottom-up tree.
An additional synthetic fixture independently fixes the 12,391-byte local
ceiling with 256 nonzero siblings and 4,096 value bytes. Its root is
`473e76a771a89ed1beaa4f4a96bb28ed5b92286319f52141f6eae5bacbdeec30`
and proof SHA-256 is
`fa8829e200f0e9d23fdf00055d1653cd6dce1ef2804f30cd83edcc6963fe2b15`.
The tests also refuse every truncated prefix of the 8,327-byte proof and every
reserved flag, exercise exact/one-short resource caps and verify value ownership.
These are finite primitive and input-boundary controls, not node execution or a
representative import/retention workload.

The source-pinned hash/proof file comparison with selected node revision
[`9c71ae82fc983e16f914ae085d4034030c8ebe3b`](https://github.com/digitalSloth/go-zenon/tree/9c71ae82fc983e16f914ae085d4034030c8ebe3b)
contains comment-only changes in those two files. The original execution is
not reassigned to that revision, and this comparison qualifies no other node
code or lifecycle.

## Qualification and remaining binding

```sh
go test -json -count=1 -run '^TestCandidateSMT' ./internal/proof
go test -race -count=1 ./internal/proof ./internal/chain
go test -race -count=1 -run '^TestVerifyStateValue|UnsupportedMomentumVersion' ./internal/verify
go vet ./...
golangci-lint run --timeout=5m
go test -run '^$' -bench '^BenchmarkCandidateSMT/' -benchtime=2000x -benchmem -cpu=1 -count=3 ./internal/proof
```

The focused JSON test inventory runs on each native CI platform. Benchmark
observations describe only this primitive's time and heap allocation; they do
not measure whole-process memory, disk, the consumer workflow or production
budgets.

The next accepting flow still needs the agreed partial-tree profile and node
provenance rules, an owned accepted v3 header/context, the root from that header,
versioned activation/persistence compatibility, bounded transport and a strict
typed consumer. A provider-selected matching root cannot supply this authority.
The existing v1/v2 path, `IAVL_STATE` reservation and default state-value refusal
are unchanged. No canonicality, finality, freshness or state-transition guarantee
is added.
