# Native verification benchmarks

`BenchmarkNativeClient` measures fixed local workloads from the
[node-derived corpus](../internal/testdata/conformance/README.md), pinned to
go-zenon commit `3a4131e63881058b6ce2ee81d3a41d0033fafc99`. The benchmark includes
successful-result checks so a faster rejection path cannot masquerade as a
verification improvement. It makes no RPC requests and needs no credentials.

Run repeated measurements with the repository's Go toolchain on `PATH`:

```sh
go test -run '^$' -bench '^BenchmarkNativeClient$' -benchmem -count=5 ./internal/conformance
```

`make bench` runs the same command. For a quick functional check:

```sh
go test -run '^$' -bench '^BenchmarkNativeClient$' -benchtime=1x ./internal/conformance
```

CI runs the one-iteration check on native Linux, macOS, and Windows. That
checks executable workloads and result semantics, not performance thresholds.
Ordinary `go test` does not execute benchmark bodies. A CI smoke number is
not a stable performance measurement.

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

These small synthetic workloads provide a reproducible starting point for
verification-cost analysis. They do not characterize maximum resource bounds,
large retained windows, content-size scaling, adversarial inputs, mobile
hardware, or steady-state watch behavior. They establish no public-network
TPS, transfer completion, VM execution, activation, canonicality, producer
elections, balance proof, or consensus-finality guarantee. Representative
target-platform and workload measurements remain a separate gate.
