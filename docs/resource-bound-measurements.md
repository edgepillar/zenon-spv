# Resource Bound Measurements

Empirical measurements taken from mainnet (`chain_id=1`) on
**2026-05-21** to inform the default bound values now implemented in
`internal/verify/policy.go`.

The numbers below are starting values, not hard ceilings. The
sample is small (one anchor near frontier ~13.3M) and the chain's
behavior at older heights or under load may differ. Defaults can
be tightened or loosened based on future operator observations.

## Setup

- Peers: `https://my.hc1node.com:35997`, `https://node.zenonhub.io:35997`
  (the two operators in `reference_zenon_rpc_peers` memory, confirmed
  serving consistent mainnet as of last verification).
- Frontier observed: height **13307628** at fetch time.
- Tool: `cmd/fetch-bundle` with multi-peer cross-check (unanimous
  agreement required across N=2 peers).

## Header-only bundles

Two samples taken just below frontier:

| Anchor | Count | JSON bytes | Bytes/header | Window span |
|---|---:|---:|---:|---:|
| 13307628 | 6 | 4,530 | 755 | ~60 s |
| 13307536 | 100 | 73,244 | 732 | 1,070 s (~17.8 min) |

**Per-header serialized size** (raw, no indentation): **653 bytes**
uniformly across all 100 headers sampled. With JSON indentation
and the bundle envelope, **effective per-header cost ≈ 732 bytes**.

**Observed block time** (from the 100-header span): ~10.7 s,
consistent with Zenon's nominal 10-second cadence.

### Projected sizes by range

Extrapolating the 732 bytes/header figure (header-only bundles):

| Range | Headers | Approx JSON size |
|---|---:|---:|
| 1 hour | 360 | 263 KB |
| 1 day | 8,640 | 6.3 MB |
| 1 week | 60,480 | 44 MB |
| 10 days | 86,400 | 63 MB |
| 1 month | ~260,000 | ~190 MB |

## Commitments / segments

A 6-header window anchored at frontier with `--commitments
z1qxemdeddedxpyllarxxxxxxxxxxxxxxxsy3fmg` (the Pillar contract)
returned **zero commitments** — that contract was inactive in the
sampled window. Pillar register/revoke events are rare on
mainnet.

**Deferred:** sampling commitment + segment sizes requires either
(a) an address with known recent activity in a near-frontier
window, or (b) walking back to a height where activity is known
(e.g., a known Pillar registration). Both are follow-up work.

Without empirical numbers, the implemented defaults for these caps use
**conservative ceilings derived from the protocol shape**:

- Each momentum's `MomentumContent` is bounded by the per-momentum
  block production rate (typically tens of account blocks per
  momentum, occasional spikes during traffic).
- Each account segment is bounded by the address's own activity
  rate (typically dozens of blocks per day for active addresses;
  thousands per day is the high end for system contracts).

## Implemented defaults

The CLI passes policy-derived byte and count caps to
`proof.LoadHeaderBundleWithLimits`. Array decoding stops before the first
excess header, commitment, segment, or state-value proof, including when the
input uses case-folded or escaped field aliases. This prevents tiny JSON
elements from allocating an over-limit top-level struct slice before
verification. A count breach returns the corresponding `ReasonOversized*`
refusal and exit code 2 before state loading or writer-lock acquisition.

Nested flat-evidence members, segment blocks, and proof-node lists stop at
their respective per-item count caps. Flat-member and segment-block budgets
also span all decoded rows in one load. Repeated nested arrays consume that
budget even if a later field replaces them or clears the evidence. A new load
starts with fresh counters; a failed load does not consume policy for the next.

The `MaxStateProofBytes` cap also applies during decoding to the sum of decoded
`proof_nodes` bytes in each state-value proof. The parser checks base64 decoded
length before allocating node storage, and checks numeric byte arrays before
reading an excess element. Standard base64 padding, JSON escapes, ignored CR/LF,
null, and empty values retain their existing meanings. Replaced or cleared node
arrays consume the same per-proof byte budget; separate proofs get fresh budgets.
Over-limit proof bytes produce a bundle-level `ReasonOversizedStateProof` refusal
before loading state, even if the selected command would not evaluate that proof.

These are input, count, and decoded-node-byte bounds, not a cap on total process
memory or time. JSON buffers, string unescaping, and other byte fields (including
proof keys and claimed values) remain under the overall input-byte cap. Base64
output storage includes up to two padding bytes beyond its decoded length;
numeric array capacity and parser buffers have their own allocation overhead.
Core verification retains its count and byte checks for in-memory callers too.
The legacy input-byte-only loader and zero decode caps remain available for
trusted tooling; direct JSON decoding does not select production limits.
Offline parser, CLI, compiled-command, and differential fuzz checks cover these caps;
these checks do not add new mainnet performance measurements to this document.

Based on the empirical and protocol-shape evidence above, the
following defaults are conservative ceilings (DoS guardrails)
rather than tight typical-case bounds. They are unlikely to be
hit by legitimate use.

```go
// internal/verify/policy.go
MaxBundleBytes              int64 =  64 * 1024 * 1024  // 64 MiB — covers ~10 days of header-only mainnet activity
MaxHeaders                  int   = 100_000            // ~12 days of momentums; legitimate one-shot bundles will be much smaller
MaxCommitments              int   =  10_000            // batch cap; typical bundles have <10
MaxFlatEvidenceMembers      int   = 100_000            // per-commitment cap; typical MomentumContent has <100
MaxTotalFlatEvidenceMembers int   = 1_000_000          // batch cap across all commitments
MaxSegments                 int   =   1_000            // per-bundle account segment count cap
MaxSegmentBlocks            int   =  10_000            // per-segment block count cap
MaxTotalSegmentBlocks       int   = 100_000            // batch cap across all segments
```

### Rationale per cap

- **`MaxBundleBytes = 64 MiB`** — generous header-time-coverage
  (~10 days) without admitting multi-GB hostile bundles. Enforced
  via `io.LimitReader` in `LoadHeaderBundleBounded` so the file is
  never fully read past the cap.
- **`MaxHeaders = 100_000`** — independent cap to catch a malicious
  small-JSON-with-many-headers shape that fits inside
  `MaxBundleBytes` but inflates per-header work.
- **`MaxCommitments = 10_000`** — typical verification bundles
  attest a handful of addresses; 10k is generous batch ceiling.
- **`MaxFlatEvidenceMembers = 100_000`** — bounded by the
  protocol's per-momentum block production. Real values are O(10s);
  100k absorbs any plausible burst plus headroom.
- **`MaxTotalFlatEvidenceMembers = 1_000_000`** — aggregate across
  all commitments, prevents `n × m` flood (many commitments × many
  members each).
- **`MaxSegments`/`MaxSegmentBlocks`/`MaxTotalSegmentBlocks`** —
  parallels the commitment caps for account-segment evidence.
  Same defense-in-depth rationale.

## Commitment batch enforcement

`PreflightCommitmentBounds` is shared by the CLI and `VerifySegment`. It checks
the entry count, every flat list, and total flat members before segment result
allocation or commitment indexing. Unmatched targets and later candidates count
even when an earlier candidate could verify a block. Shared flat pointers count
once per evidence entry, matching the repeated work/wire representation.

Batch refusal is synthetic (`FailedAt=-1`) and carries no proven guarantees.
Exact boundaries remain valid, and zero still disables the corresponding limit.
Aggregate counters consume remaining capacity rather than using an overflowing
sum or `limit+1` sentinel. The CLI's total-segment-block check uses the same
subtraction pattern. These bounds do not cap caller allocations or repeated calls.

Regression tests first reproduced six over-budget input shapes accepting in both
the free and owned segment APIs. They now refuse before block evaluation. Tests
also cover captured policy, state immutability, inclusive limits, zero and
maximum-integer caps, nil proofs, shared flat objects, unused candidates, and
valid fallback proofs. The node-derived five-block contract corpus accepts at
5 evidence entries / 5 members each / 25 repeated members and refuses when any
one limit is lowered. A fuzz oracle checks count semantics and order independence.

## Open follow-ups

1. **Activity-rich commitment/segment sample.** Find a recent
   mainnet window where Pillar registry events or known active
   addresses produced non-empty commitment/segment data; measure
   real sizes; tighten or relax the defaults if warranted.
2. **Compressed / packed wire formats.** The current bundle is
   indented JSON. A future binary form may change per-header
   bytes; the `MaxBundleBytes` cap should be re-checked under
   whatever the production wire format ends up being.
3. **σ_H / σ_B / σ_π conformance numbers** (spec §10). Branch
   2a's measurements are pragmatic guardrails, not the full §10
   conformance characterization, which remains a separate
   deferred item.
