# Owned storage for decoded bundle rows

The bounded bundle array decoder now decodes each row directly into a fresh
slot of its private result slice. Previously, passing a separate row variable
through the JSON callback allocated an additional object per row, followed by
a copy into that slice. Flat-content proofs repeat a complete list per target,
so the largest existing workload incurred 400,000 such temporary allocations.

The array and aggregate count guards still run before creating or decoding an
additional row. Only a successful callback consumes an aggregate slot. The
receiver receives the result slice only after the whole array and its trailing
input check succeed. A partially filled private slot is discarded on error.
Each callback starts with a zero value and uses the original JSON decoder.
There is no preallocation from untrusted counts, new parser, shared row cache,
borrowed input buffer or evidence deduplication.

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
