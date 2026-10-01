# Content-hash allocation comparison

Flat proofs commit the complete account-header list. The previous hasher
allocated a separate canonical byte slice for every member, plus a slice of
slice descriptors, before sorting and hashing. At 100,000 members that made
roughly 100,000 short-lived allocations for one root computation. Repeated
proofs repeated that work.

The hasher now sorts a private slice of indices into the caller's headers and
encodes each selected header into one reusable 60-byte buffer. It orders
address bytes first, unsigned height second, and hash bytes last. Unsigned
uint64 order is identical to lexicographic order of its eight big-endian bytes.
`AccountHeader.Bytes` and the hash loop share the canonical encoder. The input
slice is never sorted or changed, and byte-identical duplicates still contribute
once per occurrence. No proof is deduplicated or cached.

This changes allocation and sorting work, not cryptographic semantics, accepted
wire data, resource caps, target membership or trust policy. Empty input remains
SHA3-256 of zero bytes. Caller-owned input must remain immutable during a hash
call, as concurrent writes would already be a data race.

## Correctness evidence

The byte-level oracle in `TestMomentumContentHashSerializationContract` builds
canonical rows independently of the production encoder/comparator, sorts the
bytes and hashes their concatenation. Cases exercise address/hash suffixes,
height boundaries through MaxUint64, ties, repeated rows, reverse order, and
concurrent readers. It also checks that the caller's headers are unchanged.
`FuzzMomentumContentHashSerialization` compares arbitrary bounded lists against
that oracle and checks reversal invariance and input preservation.

The existing six pinned node corpora and independent Python checks remain
unchanged. The [large-content corpus](flat-content-resources.md) supplies roots
for 1, 1,000 and 100,000 members. Every workload still requires those expected
roots and successful bounded inclusion under explicit anchor/profile/schedule
and context-pin settings. These are serialization and synthetic resource tests,
not node-executed ledger acceptance or authenticated network trust inputs.

## Measurement method

Use the [complete before/after records](content-hash-samples.json) for every
sample, exact source-input fingerprints and production-file hashes. Both runs
use the same added tests and measurement harness on the same base revision;
the baseline retains the original production hashing files. Source inputs
remain unchanged throughout each run. Documentation and Python checkers are
outside the offline-pilot Go/module/JSON fingerprint scope.

`BenchmarkFlatContent` keeps the four existing M/P workloads and separates
already-decoded verification from bounded file loading plus verification.
`BenchmarkContentHashOrdering` adds sorted, reversed and deterministically
shuffled inputs at 1,000 and 100,000 members. Shuffling uses PCG seeds 1 and 2
outside timing. Every ordering must match the same node-derived root; input
preservation is checked after timing. This prevents a sorted-only result from
hiding a regression for other legal input orders.

The local record uses Go 1.25.14 on darwin/arm64, five 1-second samples per
benchmark operation, `-cpu=1`, no race instrumentation and no competing builds
or tests. Saved Go settings and inherited GOFLAGS are disabled. Input files are
normally warm. Hardware identity is omitted. Each version also runs five
ordinary compiled CLI processes per content workload. Their measurements
include startup, configuration, trusted-state validation, bounded decoding,
inclusion and JSON output; parent fixture construction/builds are excluded.

```sh
go test -count=1 -run '^TestMomentumContentHash' ./internal/chain
go test -run '^$' -fuzz '^FuzzMomentumContentHashSerialization$' -fuzztime=10s -parallel=2 ./internal/chain
go test -run '^$' -bench '^(BenchmarkFlatContent|BenchmarkContentHashOrdering)$' -benchmem -cpu=1 -benchtime=1s -count=5 ./internal/conformance
go test -json -count=5 -run '^TestCompiledContentScalingWorkflow$' ./internal/conformance > ../content-process-events.json
```

Keep raw event streams private. Publish only reviewed, filtered records.
`make bench` includes all four benchmark families; CI runs all 34 workloads
once on Linux/macOS/Windows as functional checks, without timing thresholds.
The offline pilot adds the serialization contract as its 34th scenario.

## Recorded comparison

The source-input fingerprints are:

- Before: `a904e1827f53c5d776142fded425b54c53960a8892351cc430097238fe6b7684`.
- After: `5330eaa50eeb3c8695a6b460a869c48dd67047763b81536c4af7d57865660eb2`.

The production baseline is `12a38c3e4b7b72d808731221363250e64468e744`.
The record contains 140 benchmark samples and 40 compiled-process observations
across the two versions. The following values are medians; MB uses 1,000,000 bytes.

| Members | Ordering | Before ms/op | After ms/op | Before B/op | After B/op | Before allocs/op | After allocs/op |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 1,000 | Sorted | 0.089 | 0.068 | 88,704 | 8,224 | 1,005 | 2 |
| 1,000 | Reversed | 0.097 | 0.068 | 88,704 | 8,224 | 1,005 | 2 |
| 1,000 | Shuffled | 0.194 | 0.114 | 88,704 | 8,224 | 1,005 | 2 |
| 100,000 | Sorted | 8.171 | 6.623 | 8,800,384 | 802,848 | 100,005 | 2 |
| 100,000 | Reversed | 8.916 | 6.647 | 8,800,384 | 802,848 | 100,005 | 2 |
| 100,000 | Shuffled | 26.353 | 19.339 | 8,800,384 | 802,848 | 100,005 | 2 |

At 100,000 members, hash allocation volume falls 90.9% and allocation count
falls from 100,005 to 2 for each tested ordering. Local median times also fall
for all six ordering workloads. These five samples per case do not establish
portable timing thresholds or a statistical latency guarantee.

| Complete workload | Before allocated MB/op | After allocated MB/op | Before ms/op | After ms/op |
| --- | ---: | ---: | ---: | ---: |
| `M100000_P1/Verify` | 8.801 | 0.803 | 8.779 | 7.076 |
| `M100000_P1/LoadAndVerify` | 213.359 | 205.361 | 310.855 | 303.995 |
| `M100000_P4/Verify` | 35.203 | 3.213 | 34.504 | 27.267 |
| `M100000_P4/LoadAndVerify` | 739.459 | 707.469 | 1200.151 | 1192.820 |

The four-proof load-and-verify path reduces allocated bytes by 4.3%; JSON
loading/decoding remains dominant. Its input is still 57,556,508 bytes, and all
400,000 repeated members still consume the aggregate proof budget.

| CLI workload | Before median elapsed ms | After median elapsed ms | Before median peak RSS MB | After median peak RSS MB |
| --- | ---: | ---: | ---: | ---: |
| `M1_P1` | 5.702 | 5.783 | 11.239 | 11.043 |
| `M1000_P1` | 8.542 | 9.032 | 13.386 | 13.255 |
| `M100000_P1` | 315.625 | 317.196 | 99.041 | 98.337 |
| `M100000_P4` | 1219.618 | 1244.054 | 298.713 | 297.910 |

These are whole-child-process observations, not a memory ceiling or an isolated
measurement of the hasher. GC, startup, JSON buffers and OS accounting affect
peak RSS. Keep the full distributions when comparing environments; do not
attribute every observed RSS or elapsed-time difference to this code change.

## Limits

Allocated bytes per operation are cumulative allocation volume, not live heap
or peak resident memory. Reducing hashing allocations does not eliminate the
larger JSON-loading cost observed in the complete CLI workflow. Peak RSS is
recorded separately on Linux/macOS; Windows remains explicitly unavailable.
Five local process samples do not establish a portable RSS improvement or safe
concurrency level.

The complete flat list is still hashed separately for each proof. Count and
byte preflight limits still apply to every repeated list. K/W retention, target
identity, captured profile/schedule, context pins and read-only persistence
behavior are unchanged. No measurement establishes canonicality, consensus
finality, network activation, state-value inclusion or real-network capacity.
Consumer-selected trust inputs, hardware budgets, network observations and
independent release review remain external gates.
