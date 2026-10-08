# Native verification benchmarks

`BenchmarkNativeClient` measures fixed local workloads from the
[node-derived corpus](../internal/testdata/conformance/README.md), pinned to
go-zenon commit `3a4131e63881058b6ce2ee81d3a41d0033fafc99`. The benchmark includes
successful-result checks so a faster rejection path cannot masquerade as a
verification improvement. It makes no RPC requests and needs no credentials.

Run repeated measurements with the repository's Go toolchain on `PATH`:

```sh
go test -run '^$' -bench '^(BenchmarkNativeClient|BenchmarkRetainedCapacity|BenchmarkFlatContent|BenchmarkContentHashOrdering|BenchmarkEnvelopeHash)$' -benchmem -count=5 ./internal/conformance
```

`make bench` runs the same command. For a quick functional check:

```sh
go test -run '^$' -bench '^(BenchmarkNativeClient|BenchmarkRetainedCapacity|BenchmarkFlatContent|BenchmarkContentHashOrdering|BenchmarkEnvelopeHash)$' -benchtime=1x ./internal/conformance
```

CI runs the one-iteration check on native Linux, macOS, and Windows. That
checks executable workloads and result semantics, not performance thresholds.
Ordinary `go test` does not execute benchmark bodies. A CI smoke number is
not a stable performance measurement.

`BenchmarkRetainedCapacity` separately measures [populated K=16/256/4096
windows](retained-capacity-benchmarks.md), including full-window extension,
inclusion, resume and save. Its stress fixture is synthetic and is not generated
by the node corpus module.

## Workload boundaries

Each operation is one full call, not one header or block unless stated.
Reported `headers/op`, `members/op`, and `blocks/op` make the batch size
explicit. `ns/op`, `B/op`, and `allocs/op` retain Go's standard meanings.

| Case | One measured operation |
| --- | --- |
| `HeadersV1/claimed_key` | Verify nine v1 headers from an empty anchored state with `W=6`; construct the immutable successor. Producer authorization is disabled. |
| `HeadersV1/operator_schedule` | The same nine-header extension with an operator-attested schedule already captured in the initial state. |
| `HeadersV1V2/operator_profile` | Verify six headers crossing the pinned synthetic v1/v2 transition under an explicit activation profile and `W=5`. |
| `CommitmentFlat` | Verify one target in five-member flat momentum content against a retained state with sufficient depth. |
| `ContractSegment` | Verify five contract blocks, including child sends and receives, against five direct-inclusion candidates. Includes whole-batch resource checks. |
| `TrustedResume/operator_schedule` | Open/decode a seven-header state file, validate retained integrity, capture the requested configuration, and reauthorize producers. |
| `RetainedSummary` | Produce the detached constant-size bounds/depth summary for the seven-header state. |
| `VerificationContext` | Produce the detached verifier-settings report and its fingerprint. |

The benchmark uses `testing.B.Loop` to exclude setup and cleanup and preserve
measured function calls from compiler elimination. Corpus JSON decoding,
initial-state construction, schedule generation, and initial file creation
are outside the timer. Each header-extension iteration starts from the same
immutable empty state; it does not accumulate an ever-growing chain. Result
checks and their loop/branch overhead remain inside the measurement.

Only the trusted-resume case reads files during timing. Its repeated reads
normally benefit from filesystem caching. It does not measure cold-disk I/O,
state saving, fsync, crash recovery, writer contention, or CLI startup. The
summary case does not include state loading: real `inspect-state` also pays
the loader's integrity-validation cost.

## Recording and comparing runs

Record the repository revision and local-change state, Go version, OS,
architecture, CPU model, benchmark command, and all repeated samples. Keep
source/build records beside the results; see [build identity](build-identity.md)
for missing VCS metadata and the distinction from authenticated provenance.
Compare runs with the same fixture, policy, toolchain, and host configuration,
without competing builds/tests. State whether CPU parallelism was fixed
(for example, `-cpu=1`). Do not compare race-instrumented results to ordinary
builds. Review logs for private paths or environment details before sharing.

The small `BenchmarkNativeClient` workloads provide a reproducible starting point for
verification-cost analysis. They do not characterize maximum resource bounds,
large retained windows, content-size scaling, adversarial inputs, mobile
hardware, or steady-state watch behavior. They establish no public-network
TPS, transfer completion, VM execution, activation, canonicality, producer
elections, balance proof, or consensus-finality guarantee. Representative
target-platform and workload measurements remain a separate gate.

See [flat-content resources](flat-content-resources.md) for the separate
`BenchmarkFlatContent` cardinality/batch grid and compiled-process RSS samples.
`make bench` includes that family as well as the retained-capacity workloads.

The [content-hash allocation comparison](content-hash-allocations.md) adds
`BenchmarkContentHashOrdering` with sorted, reversed and shuffled node-derived
content at 1,000 and 100,000 members.

The [signed-envelope comparison](envelope-hash-allocations.md) adds
`BenchmarkEnvelopeHash`: one v1 or v2 momentum hash and one zero or maximum
valid 255-bit account-amount hash. The input is already decoded; every iteration
must match the pinned node digest. CI and `make bench` include all five families
and 38 workloads. Functional CI runs do not impose allocation or timing limits.

## Whole owned research import observations

The [isolated reference harness](../tools/gen-state-root-vectors/README.md#whole-owned-import-resource-observations)
recorded two generations on Darwin/arm64 with Go 1.25.14: 12 literal families,
three plain and three allocation-observed children per family per generation,
144 fresh children. All first outcomes/samples were retained without replacement
or filtering. Seven families stage; five reject, with complete original targets
and aliases unchanged. The independent oracle checks the complete input/map/
callback bindings; CI reads these recorded observations without executing the
node reference. These are unsigned engineering measurements, not authenticated
execution attestations.

The table uses all six plain elapsed samples and all six cumulative `TotalAlloc`
deltas per family, with no discarded values. RSS is the maximum of all twelve
samples per family, captured immediately after the operation before output
binding. Setup, initial summaries and one prior GC lie outside the timer but
can contribute to process high water. Allocation includes runtime activity in
the process-wide sampling interval and is not peak live memory. Full maps and
callback summaries after the RSS capture, child serialization, parent reporting,
source acquisition/build and storage handoff are outside the measured operation.

| Family | Raw bytes | Initial entries / hex bytes | Result | Plain median ns | Cumulative allocation median bytes | Process high-water maximum bytes |
| --- | ---: | ---: | --- | ---: | ---: | ---: |
| empty-owned-empty | 0 | 0 / 0 | STAGED | 11604.0 | 696.0 | 12206080 |
| records-64-owned-128 | 64384 | 128 / 16384 | STAGED | 633937.5 | 635264.0 | 13631488 |
| records-256-owned-1024 | 257536 | 1024 / 131072 | STAGED | 2297104.5 | 2585640.0 | 17793024 |
| records-1024-owned-4096 | 68608 | 4096 / 524288 | STAGED | 1434541.5 | 1223200.0 | 20643840 |
| raw-ceiling-transient-hex-refusal | 1048576 | 0 / 0 | target_hex_limit | 6327354.5 | 9446744.0 | 23019520 |
| target-entries-4096-noop | 0 | 4096 / 32768 | STAGED | 267791.5 | 328696.0 | 17252352 |
| target-entries-4097-noop | 0 | 4097 / 32776 | target_entry_limit | 4020.5 | 96.0 | 16957440 |
| target-hex-ceiling-noop | 0 | 1 / 1048576 | STAGED | 610875.0 | 992.0 | 17072128 |
| put-then-delete | 101 | 3 / 384 | target_entry_limit | 15125.0 | 2040.0 | 12304384 |
| delete-then-put | 101 | 3 / 384 | STAGED | 18687.5 | 2280.0 | 12353536 |
| selection-mismatch-before-clone | 257536 | 1024 / 131072 | selection_mismatch | 988833.0 | 1372072.0 | 17285120 |
| injected-replay-error-complete | 257536 | 1024 / 131072 | replay_error | 1551250.0 | 2585576.0 | 17514496 |

A raw 1 MiB patch rejects during transient target growth after preflight and
some replay work, so its allocation cost is not represented by its zero-entry
final target. Conversely, cloning the one-entry 1 MiB hex target shares its
immutable payload string. Neither payload caps nor either observed metric
qualify an end-to-end memory budget. No before/after optimization, latency
speedup, cross-platform equivalence, NodeTree retention, real-chain capacity,
snapshot authentication or production state-value acceptance is claimed.

[Complete recorded samples](../tools/gen-state-root-vectors/testdata/candidate-patch-import-resource-samples.json)
and [deterministic conformance bindings](../tools/gen-state-root-vectors/testdata/candidate-patch-import-resources.json)
are kept separately. Reproduction creates new outputs/evidence and preserves
all actual child failures rather than accepting a replacement sample.
