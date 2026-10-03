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

Expect costs that grow with K. Full-window header-array copies, retained-layout
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

## Owned envelope reuse during extension

`VerifiedState.Extend` now adopts the fresh header array and profile already
created by verification. Older key/signature bytes remain private and immutable;
only the surviving incoming suffix needs a detached copy. Public views still
return copies, and failed extensions preserve the predecessor. This reduces
redundant copies without changing retained capacity K, confirmation depth W,
producer authorization, profile coverage or context pins.

The [complete comparison samples](state-extension-samples.json) contain all
120 measurements: five 1-second samples for each of the four operations and
three capacities, both before and after the change. Both phases used
Go 1.25.14 on darwin/arm64, `-cpu=1`, no race instrumentation and no competing
builds or tests. The baseline revision was
`1b6918a92387221b8215e6f1f7fe320b5b0d8c8d`; the post-change measurement used
modified sources relative to that parent. Separate Go/module/JSON input
fingerprints identify each phase; all six node-derived corpus files stayed
unchanged. Samples were not filtered or retried.

The following values are medians for `ExtendOne`. Allocation volume is in
bytes, and local operation time is in milliseconds:

| K | Before B/op | After B/op | Before allocs/op | After allocs/op | Before ms | After ms |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 16 | 12,224 | 5,824 | 51 | 19 | 0.03579 | 0.03248 |
| 256 | 156,608 | 66,496 | 531 | 19 | 0.06435 | 0.04395 |
| 4096 | 2,491,328 | 1,049,536 | 8,211 | 19 | 0.58248 | 0.24021 |

`CommitmentFlat`, `TrustedResume` and `Save` are recorded as controls; they are
outside the changed path. Saved state sizes remained 13,139, 202,500 and
3,232,261 bytes for K=16, 256 and 4096. These results do not establish a
portable speedup, peak RSS, a hardware memory ceiling or network performance.
The verifier still allocates a header array proportional to K, and query,
save and resume costs still grow with retained history.

Ownership tests cover initially empty, partial and full windows; batches below,
equal to and above K; caller input mutations; predecessor, sibling and
grandchild handles; detached public views and context; failed valid-prefix
extensions; save/resume; and concurrent readers/extensions. A local disposable
overlay that omitted incoming-envelope detachment failed all 12 ownership
matrix scenarios. These signed synthetic tests are behavioral checks, not
evidence of canonicality, finality, network activation or state values.
