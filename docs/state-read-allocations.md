# Bounded saved-state read allocations

The populated-window baseline showed substantial allocation volume during
trusted resume. A local allocation profile identified input-buffer growth in
`io.ReadAll` as one contributor. `LoadHeaderState` now uses the already observed
file size to reserve the initial read buffer, avoiding repeated copying on the
usual stable-file path. The benchmark continues to include complete decoding,
integrity checks, schedule capture and producer reauthorization.

## Preserved boundaries

The stat size is an allocation hint. A stale smaller hint cannot truncate a
growing file, and a stale larger hint cannot turn unused buffer bytes into
input. Accepted input must reach EOF; oversized input is refused after at most
the configured byte limit plus one overflow byte is consumed. Initial buffer
capacity and bounded geometric growth stay within that same limit plus one.
The production limit remains 64 MiB.
Invalid or unusable hints cannot enlarge it.

Non-EOF read errors remain failures even when returned with complete JSON or
the overflow byte. Partial bytes never become a state. The same JSON parser
still rejects duplicate known fields, trailing values and malformed envelopes;
retained-header counts, layout, hashes, signatures, activation and checkpoints
are still validated. Trusted resume still authorizes the complete saved window
before capacity changes can remove any header. State formats, context pins,
writer locking, and save/replacement behavior are unchanged.

`TestSizedStateReadContract` covers byte boundaries, unusable and stale hints,
short reads, data accompanied by EOF/errors, and complete saved-state parsing.
`FuzzSizedStateRead` compares accepted bytes and overflow consumption against
the previous bounded `io.ReadAll` contract. The native offline pilot includes
the deterministic read-contract scenario alongside the full-capacity and
compiled resume workflows.

## Measurement scope

The [complete before/after samples](state-read-samples.json) contain five
1-second samples per capacity on the same darwin/arm64 host with Go 1.25.14,
`-cpu=1`, no race instrumentation, and no competing builds/tests. Host identity
is omitted. Median allocated bytes per operation changed as follows:

| Retained headers | Before (B/op) | After (B/op) | Reduction | Before (ms) | After (ms) |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 16 | 149,032 | 100,112 | 32.8% | 0.744 | 0.729 |
| 256 | 2,158,379 | 1,455,635 | 32.6% | 11.467 | 11.254 |
| 4096 | 38,277,325 | 24,721,330 | 35.4% | 178.230 | 177.762 |

The primary result is lower allocation volume. The small timing differences
are descriptive samples, not a statistically established latency improvement.
Saved file sizes and benchmark bodies are unchanged. The record identifies
the exact base revision and before/after Go/module/JSON source fingerprints;
documentation, CI and Python checkers are outside that fingerprint scope.

Run the unchanged resume workload without competing builds/tests:

```sh
go test -run '^$' -bench '^BenchmarkRetainedCapacity/K(16|256|4096)/TrustedResume$' -benchmem -cpu=1 -benchtime=1s -count=5 ./internal/conformance
```

Allocation volume is cumulative bytes allocated per operation, not peak RSS,
live heap or an absolute process-memory bound. Go allocator rounding, JSON
decoding, header storage and schedule validation still allocate separately.
Reads normally use a warm filesystem cache. This remains a synthetic local
workload; it does not measure cold I/O, network latency, real account traffic or
target-device performance. CI executes the workload as a functional check and
does not enforce timing thresholds.
