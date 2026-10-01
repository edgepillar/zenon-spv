# Populated retained-window measurements

`BenchmarkRetainedCapacity` exercises full K=16, 256 and 4096 windows, with
W=6, v2 headers, an explicit profile and required producer authorization.
Each capacity has four measured operations:

| Operation | Timed work |
| --- | --- |
| `ExtendOne` | Verify one signed successor, evict the oldest header, build the immutable successor and check its summary. Each iteration starts from the same full state. |
| `CommitmentFlat` | Verify one member against the oldest retained header, including current retained-layout policy checks and result guarantees. |
| `TrustedResume` | Open/decode a full saved file, capture options/schedule, validate all retained hashes/signatures and reauthorize every producer. Reads normally use a warm filesystem cache. |
| `Save` | Validate and serialize the full window, replace the fixture file atomically where supported, and perform the platform's file/directory sync behavior. |

Fixture construction, signatures, initial verification and initial file creation
are outside timing. Successful-result checks remain inside. `state-B` records
the saved JSON size; `retained-headers` records K. Standard `B/op` measures bytes
allocated per operation, not retained heap or peak RSS. `allocs/op` counts
allocations; `ns/op` is elapsed operation time. No operation measures RPC
bandwidth or an end-to-end network watch interval.

The load fixture uses SPV hashing and repeated synthetic content. It is a
resource workload, separate from the independently [node-derived delayed
inclusion corpus](delayed-inclusion.md). It does not prove that a node accepts
the history or that those repeated account headers form a valid ledger.

Run measurements without competing builds or tests:

```sh
go test -run '^$' -bench '^BenchmarkRetainedCapacity$' -benchmem -cpu=1 -benchtime=1s -count=5 ./internal/conformance
```

`make bench` includes the native, retained-capacity, flat-content and content-ordering families. CI runs one iteration of every
workload on native Linux, macOS and Windows as a functional check. It does not
enforce timing thresholds. `TestRetainedCapacityWorkloads` also exercises full
windows, exact eviction, immutable predecessors, persistence and resumed
inclusion during ordinary tests and the offline pilot.

Expect costs that grow with K. Full-window immutable copies, retained-layout
validation during queries, save validation and full resume reauthorization
still inspect or copy the retained history. A larger K increases proof
availability; it is not a constant-cost cache. The explicit maximum remains
4096. Transient JSON decoding/validation can allocate much more than the file
size. Hard input caps are not a process-memory ceiling.

These measurements are a local baseline. Representative consumer workloads,
consumer-specific content/proof scaling, target hardware, cold I/O,
contention and real-network latency/bandwidth remain acceptance gates. Do not
interpret local timings as network TPS, production capacity or finality.
The separate [flat-content measurements](flat-content-resources.md) now cover
a synthetic M/P grid and compiled Linux/macOS process RSS.

## Recorded local baseline

This records the original populated-window baseline. The later
[state-read allocation comparison](state-read-allocations.md) measures the
same resume workload after using bounded file-size hints.

The [complete samples](retained-capacity-samples.json) record five 1-second
samples per operation on darwin/arm64 with Go 1.25.14, `-cpu=1` and no race
instrumentation or competing builds/tests. Host identity is omitted. Values
below are medians, in milliseconds except for the JSON file size:

| Retained headers | State bytes | Extend one (ms) | Inclusion (ms) | Resume (ms) | Save (ms) |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 16 | 13,139 | 0.0330 | 0.00110 | 0.751 | 12.291 |
| 256 | 202,500 | 0.0571 | 0.00317 | 11.484 | 20.693 |
| 4096 | 3,232,261 | 0.5403 | 0.04087 | 179.480 | 149.708 |

At K=4096, resume allocated a median 38,277,322 bytes per operation and save
allocated 22,332,353 bytes. Those are cumulative allocation volumes, not
simultaneously resident memory. The inclusion workload has only one content
member; its growth with K includes the current retained-layout scan and says
nothing about large content proofs. Save timing depends on the local
filesystem's replacement and sync behavior.

The record identifies the base revision plus a modified source-input
fingerprint, using the offline-pilot Go/module/JSON input scope. That scope
excludes documentation, CI configuration and Python checkers. It describes the
measured code without claiming an unmodified release or portable timing.
