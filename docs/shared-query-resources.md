# Shared immutable query resources

`VerifiedState` owns an immutable retained window. Applications can share one
handle across read-only commitment and account-segment queries, provided they do
not mutate evidence while any query is reading it. These measurements exercise
that API boundary; they do not include RPC collection, CLI startup, JSON report
consumption, file reads, or state persistence.

## Reproduce the observations

```sh
go test -run '^$' -bench '^BenchmarkSharedImmutableQueries$' \
  -benchtime=1000x -benchmem -cpu=1,4 -count=3 ./internal/conformance
```

The same command runs in each native Linux, macOS Intel and Windows CI job. It
retains all 48 observations: two full retained capacities (K=256/4096), four
query workloads, two worker counts and three repetitions. Each row has 1,000
timed operations. Fixture construction, signing, window validation, saving,
reference queries and before/after inspection are outside the timer. Go may run
untimed setup/calibration queries in addition to the reported operation count.

`RunParallel` uses one goroutine per `GOMAXPROCS`, with `SetParallelism(1)`. Each
operation queries the same immutable handle and compares every result field with
a serial reference, including reasons, messages, fault indices, exact guarantee
and trust slices, and nil/empty distinctions. Those comparisons and parallel-loop
overhead are included in the timing. Every cell also checks that caller evidence,
retained state and verification context remain unchanged after the workers join.

| Workload | Evidence and verification path |
| --- | --- |
| `CommitmentM1` | One synthetic account header in flat momentum content |
| `CommitmentM1000` | A 1,000-member node-derived content-root vector |
| `SegmentUser` | Three linked node-derived user account blocks with signatures |
| `SegmentEmbedded` | Three linked node-derived embedded account blocks |

All four workloads use a synthetic signed retained history, W=6 and an explicit
operator-attested producer schedule. The content-root vector is independently
checked against node output by the existing fixture helper. The account blocks
come from `delayed-inclusion.json`; placing them in synthetic stress windows does
not establish executed-ledger history or real-network throughput. All seven
node-corpus files remain unchanged.

## Interpret the metrics

Concurrent `ns/op` is total group wall time divided by completed operations. It
is not individual request latency, a sustained service rate, or an end-to-end
consumer performance result. `B/op` and `allocs/op` describe cumulative Go
allocation per operation, including the result checks and benchmark overhead;
they are not peak RSS. `retained-headers` and `workers` identify each row's K and
configured worker count. Timing is observational, without a hardware budget,
universal speedup claim, sample filtering, or a timing acceptance threshold.

The separate `TestNodeConcurrentImmutableQueries` uses the node-derived mixed
v1/v2 delayed-inclusion window, fresh and trusted-resumed handles, four workers
and eight rounds per worker. Nine query variants mix valid, corrupted and missing
flat evidence for commitments and both account-segment kinds. Each variant is
compared with the public low-level verifier before and after mutating only its
detached output. Workers also mutate detached snapshots and trust slices while
other workers query. The test checks full results and preservation of state,
context, caller evidence and serial expectations. It is included in the offline
pilot manifest; Linux CI runs it with the race detector.

These are bounded engineering checks. Independent human review, authenticated
anchor/profile/schedule provenance, a consumer-selected hardware and concurrency
budget, a qualified read-only pilot and authenticated distribution remain
separate requirements. They establish no canonicality, consensus finality,
network activation, authenticated election, or state-value proof.
