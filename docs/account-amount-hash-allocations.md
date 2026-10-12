# Account amount hash allocations

Account-block hashing allocated a padded amount slice on every call and an
additional magnitude slice for nonzero amounts. Magnitudes that fit 32 bytes
now write directly into a private stack buffer. `big.Int.FillBytes` retains the
absolute-value, zero-extended encoding without changing the caller's integer.
Larger low-level magnitudes retain the existing non-truncating path.

The signed envelope and every digest remain unchanged. The 256-bit fast path
is a serialization detail: RPC and segment verification still reject negative
amounts and values above the existing 255-bit scalar bound. Nil and zero keep
their identical byte meaning. Trust anchors, activation profiles, producer
schedules, context pins and state-value refusal are unchanged.

## Byte and input preservation

The existing fixed-offset Go envelope oracle now extracts low bytes by shifting
a private positive integer. It does not call the production amount encoder,
`Bytes` or `FillBytes`. Its original 17 cases and bounded fuzz target preserve
nil, zero, negative, 255/256-bit and wider magnitudes, unsigned fields and shared
immutable input. Existing scalar, RPC, segment and node-conformance tests remain
required. Python independently reconstructs the account preimages.

`BenchmarkAccountAmountHash` retains all seven vectors from the unchanged
go-zenon corpus pinned to `3a4131e63881058b6ce2ee81d3a41d0033fafc99`, plus a nil
form of its recorded zero. Every timed hash must equal the node-derived digest.
The benchmark checks scalar classification separately and preserves the amount
pointer and numeric value. Invalid magnitudes remain byte controls.

Native Linux/macOS/Windows CI runs all eight workloads three times with
`-benchtime=1000x`, retaining their metrics without allocation or latency pass
thresholds. The existing benchmark smoke cases and independent byte/signature
checks remain required.

## Recorded local comparison

The [complete sample record](account-amount-hash-samples.json) retains all 190
samples: five before and five after samples for each of 19 operations. Both
versions use the same test and benchmark harness on production base
`38af5ef00a537a2403b8f2986e995edc5d54be5c`; only
`internal/chain/account_block.go` differs among the selected source inputs.
Source files, corpora, commands and toolchain are pinned in the record.

The local method uses Go 1.25.14 on darwin/arm64, ordinary builds with CGO and
race instrumentation disabled, `-cpu=1`, five 250-ms samples per operation,
disabled ambient Go settings, and no competing Go workloads. Decoding and
workload preparation are outside `B.Loop`; successful-result checks are inside.
A private collector initially stopped on the successful first command's
footer formatting. All 40 measurements from that command were retained without
rerunning it; the three unexecuted selections then completed the same phase.
No sample was discarded, retried or selected by performance.

The following values are medians. Allocated bytes are cumulative allocation
volume per operation, not live heap or resident memory.

| Isolated account hash | Before B/op | After B/op | Before allocs/op | After allocs/op |
| --- | ---: | ---: | ---: | ---: |
| Nil or zero | 32 | 0 | 1 | 0 |
| Ordinary amount, 1000 | 40 | 0 | 2 | 0 |
| Maximum valid 255-bit amount | 64 | 0 | 2 | 0 |
| First invalid 256-bit amount | 64 | 0 | 2 | 0 |
| Negative alias, -1000 | 40 | 0 | 2 | 0 |
| Wide overflow alias | 656 | 656 | 3 | 3 |
| 1025-bit magnitude | 752 | 752 | 3 | 3 |

| Complete retained operation | Before B/op | After B/op | Before allocs/op | After allocs/op |
| --- | ---: | ---: | ---: | ---: |
| Five-block contract segment | 5,720 | 5,536 | 99 | 91 |
| Three user blocks, K=16/256/4096 | 4,024 | 3,904 | 70 | 64 |
| Three embedded blocks, K=16/256/4096 | 3,664 | 3,568 | 61 | 58 |

The retained cases use node-derived account envelopes inside populated
synthetic windows. Their reported allocation reduction is the same at all
three capacities. Both isolated header controls remain at zero allocation.
All timing samples are retained: some medians increase, including the K=16
user segment and K=4096 embedded segment. No uniform speedup is claimed.

These results qualify the selected local compiler and finite workloads. They
do not establish a portable zero-allocation guarantee, whole-process memory,
real-network capacity or a production latency budget. Green CI and preserved
node bytes do not establish canonicality, consensus finality, activation,
elected producers, state-value proofs or authenticated distribution. Consumer
trust inputs, representative workloads, target budgets and independent review
remain separate acceptance gates.
