# Owned storage for decoded bundle rows

The bounded bundle array decoder now decodes each row directly into a fresh
slot of its private result slice. Previously, passing a separate row variable
through the JSON callback allocated an additional object per row, followed by
a copy into that slice. Flat-content proofs repeat a complete list per target,
so the largest existing workload incurred 400,000 such temporary allocations.

The array and aggregate count guards still run before appending or decoding an
additional row. Only a successful callback consumes an aggregate slot. The
receiver receives the result slice only after the whole array and its trailing
input check succeed. A partially filled private slot is discarded on error.
Each callback starts with a zero value and uses the original JSON decoder.
The original JSON decoder remains responsible for acceptance. A separate
bounded capacity hint for flat account-header lists is described below. There
is no shared row cache, borrowed input buffer or evidence deduplication.

## Correctness and observations

`TestBundleRowOwnedSlotsReference` retains the exact previous helper body from
`de6f10b083fe1b692c082b5d5a75b2c8fea3e445` as a test-only reference. Its 3,024
cases cover six concrete row types, direct and standard-library entry paths,
disabled and exact count limits, shared budget consumption, null and empty
arrays, malformed input, duplicate and Unicode field aliases, scalar errors,
nested flat/segment evidence, amount tokens and proof-node byte limits. Full
projections and concrete error details must match the reference, including
receivers and input bytes on failure. Nested callback implementations remain
shared so this reference isolates row storage.

Separate controls check error identity, fresh zero-valued callback targets,
refusal before an excess callback, count precedence, and no budget refund.
Ownership controls cross repeated slice growth with 1,024 rows containing
mutable bytes and strings. They check independent adjacent rows and decodes,
preserved old receiver storage, late type/count failures and independence from
the encoded input. A bounded fuzz target compares arbitrary input with the
pinned reference across all six row types and both entry paths.

`BenchmarkProofBundleRowOwnedSlots` measures complete synthetic arrays of
1,000 and 100,000 account headers. Encoding and a full-field reference comparison
are outside timing. Both modes use the same count guard and JSON decoder, with
one iteration per sample, three samples per mode and one benchmark CPU. The
initial local Go 1.25.14 darwin/arm64 observations were:

| Members | Reference B/op | Owned B/op | Reference allocs/op | Owned allocs/op |
| --- | ---: | ---: | ---: | ---: |
| 1,000 | 279,720 | 215,672 | 1,027 | 26 |
| 100,000 | 38,662,824 | 32,262,776 | 100,044 | 43 |

The reference benchmark also creates one extra wrapper for its adapted type;
the per-row difference is one temporary allocation. These are cumulative
allocation observations, not peak RSS, retained heap, a sustainable device
budget or a whole-CI speedup. Native CI repeats the finite controls and all
four benchmark modes on Linux, macOS and Windows without timing thresholds.

The [existing flat-content grid](flat-content-resources.md) remains unchanged:
1/1,000/100,000 members, the full four-proof repeated wire list, independent
node-derived roots, real signature checks, every selected target and tampering
and budget refusals. Anchor/profile/schedule and context-pin requirements are
unchanged. This storage change establishes no canonicality, finality, network
activation, execution eligibility, state-value proof or production acceptance.

## Reproduce

Use cached dependencies and an owned bounded workspace for build caches and
temporary output. Keep raw Go diagnostics private.

```sh
go test -race -count=1 -run '^TestBundleRowOwnedSlots' ./internal/proof
go test -run '^$' -fuzz '^FuzzBundleRowOwnedSlots$' -fuzztime=5s -parallel=2 ./internal/proof
go test -run '^$' -bench '^BenchmarkProofBundleRowOwnedSlots$' -benchtime=1x -benchmem -cpu=1 -count=3 ./internal/proof
go test -race -count=1 -run '^(TestNodeContentScaling|TestCompiledContentScalingWorkflow)$' ./internal/conformance
```

## Bounded flat-list capacity hint

Flat account-header lists additionally reserve private initial slice capacity
to avoid repeatedly allocating and copying growing backing arrays. This hint
is limited to `flat.sorted_headers`; every other production bundle array keeps
its existing growth behavior. It changes storage, not the row or byte limits.

The initial reservation is capped by all of the following:

- The remaining per-array and shared aggregate row allowance, when enabled.
- One row slot per 128 bytes of the encoded array contents.
- 100,000 slots, even when a larger list is permitted.
- The number of top-level values encountered by the bounded storage scan.

An account header occupies at most 64 bytes on the supported Go platforms,
checked by the controls. The requested initial row backing storage therefore
uses at most half the encoded contents length and at most 6,400,000 bytes,
excluding allocator rounding and metadata. Short encodings and lists beyond
this ceiling can still grow normally. This is neither a process-memory cap nor
a new acceptance limit. A malformed list that fails early can reserve more
initial storage than before; the same byte, fixed and active-count bounds apply.

The scan skips quoted spans and counts only enough candidate values to reach
the storage ceiling. It does not validate JSON, interpret fields, authorize a
row or consume budget. Malformed input can produce an inaccurate hint. The
original decoder still makes every syntax, type, trailing-input, byte and count
decision in its original order. Zero remaining aggregate allowance reserves no
slots. The receiver is assigned only after complete success, and repeated or
null fields retain their existing merge and charging semantics.

`TestFlatRowCapacityHint` compares 16,640 valid cases with an independent
standard-library array oracle, checks 8,192 adverse byte substitutions, and
exercises the fixed ceiling and its neighbors. The separate reference controls
compare 6,480 cases across six concrete row types and both entry paths with the
exact prior row helper body from `bbd5546d63b3657f5119ff57a86b23d473283d73`.
Full-flat integration also retains that revision's flat decoder body and checks
234 merge/error/budget cases, complete populated rows, exact active ceilings,
input independence and separate decode ownership. A five-second bounded fuzz
run compares arbitrary input with both references. These references share
unchanged nested callbacks; they isolate storage rather than independently
implement the protocol.

`BenchmarkFlatRowCapacity` excludes fixture encoding and complete projection
checks from timing. Three single-iteration samples per mode use one benchmark
CPU. Initial local Go 1.25.14 darwin/arm64 median observations were:

| Members | Growing B/op | Hinted B/op | Growing allocs/op | Hinted allocs/op | Growing capacity | Hinted capacity |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 1,000 | 215,752 | 68,296 | 27 | 15 | 1,408 | 1,000 |
| 100,000 | 32,262,856 | 6,408,904 | 44 | 15 | 104,832 | 100,000 |

The reference wrapper adds one allocation. The byte reduction comes from
avoiding backing-array growth, and timing includes an extra bounded scan.
These samples do not establish a latency improvement, peak-RSS reduction,
device budget, live-network readiness or whole-CI speedup. The unchanged full
flat-content and compiled consumer grids remain separate qualification checks.
Native CI runs the finite controls and allocation observations on every platform.

```sh
go test -race -count=1 -run '^TestFlatRowCapacity' ./internal/proof
go test -run '^$' -fuzz '^FuzzFlatRowCapacityHint$' -fuzztime=5s -parallel=2 ./internal/proof
go test -run '^$' -bench '^BenchmarkFlatRowCapacity$' -benchtime=1x -benchmem -cpu=1 -count=3 ./internal/proof
```
