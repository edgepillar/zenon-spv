# Selected-height observer resource observations

The explicit-height [block observer](block-observer.md) completed all four
predeclared local resource workloads on 2026-10-04. With K=4096 and four
concurrent observers, group p95 elapsed time was 307.798 ms and maximum sampled
candidate-tree RSS was 151.953 MiB. These are fixed-capture macOS observations;
they do not qualify a network pilot or establish production capacity.

The measured source is
[`1322de3a40cda3895b7cc015b1e8935212640aa6`](https://github.com/edgepillar/zenon-spv/commit/1322de3a40cda3895b7cc015b1e8935212640aa6).
The four ordinary Darwin/arm64 executables came from the tested-candidate
artifact of [main CI run 37197414079](https://github.com/edgepillar/zenon-spv/actions/runs/37197414079),
using Go 1.25.14. Archive, manifest, source-input and executable byte pins were
checked before execution. The source-input fingerprint is
`57b930258cce1346430ac4e44ad0a5df111e4ee384d59400d30e2f413e19a077`.
Later documentation commits do not retarget these measurements.

## Fixed workload and limits

Each invocation used `observe-block` in single-RPC `verify-segment` mode with
the pinned collector, verifier and consumer. It selected one previously chosen
signed account-block target, tip 6144, depth W=6, and
`--momentum-heights 6026`. All five matching commitments were at that confirming
height. K is retained-history capacity, distinct from depth W.

The unchanged checkpoint was requested at `tip-K`, followed by the selected
confirming momentum and one account-block query. Every observer made three
loopback RPC requests, receiving 4,249 response-body bytes and producing a
5,654-byte proof-only bundle. Those counts exclude HTTP framing. Selecting
fewer collection heights still leaves full saved-state validation in the
measured operation. Saved-state JSON sizes were 203,343 bytes for K=256 and
3,240,784 bytes for K=4096.

Historical signed testnet captures and separately prepared expectations were
sealed before measurement. They used an explicit experimental activation
profile and an observed producer schedule from one gateway. They do not supply
independently authenticated activation, elections or consumer selection.
`CONTENT_INCLUSION` and `SIGNATURE_AUTHENTICITY` were required under the selected
trust allowances; a matching result does not remove those allowances.

The plan selected K=256 then K=4096, concurrency one then four, and 21 fresh
process rounds per workload. Each observer had its own ephemeral loopback
fixture. Response JSON was pre-encoded before timing. Each child had a 10-second
timeout and the harness imposed a 15-second group deadline. No live RPC was
contacted, no saved state was advanced, and no policy was renewed.

Before execution, the plan set these local limits:

- Group p95 elapsed time at most 2 seconds for one observer or 3 seconds for four.
- Maximum sampled candidate-tree RSS at most 512 MiB per group.
- Separate outer-process lifetime high-water observation at most 128 MiB.
- Every actual process exit and complete report must match the fixed expectations.

All four workloads met these limits. A local limit pass is not a deployment
approval or a guarantee for other captures, devices, concurrency or workloads.

## Observations

Elapsed values are milliseconds. RSS values are MiB (2^20 bytes). Concurrency
four reports elapsed time for the complete group, not per-request latency or
throughput. Outer high-water is the maximum separately waited observer process
in that workload; it is not added to sampled group RSS.

| K | Concurrent observers | Group p50 ms | Group p95 ms | Group max ms | Max sampled group RSS MiB | Max outer high-water MiB |
|---:|---:|---:|---:|---:|---:|---:|
| 256 | 1 | 89.653 | 96.779 | 1158.100 | 29.672 | 20.719 |
| 256 | 4 | 94.600 | 107.400 | 112.844 | 122.219 | 22.734 |
| 4096 | 1 | 254.368 | 266.763 | 270.862 | 38.203 | 29.406 |
| 4096 | 4 | 283.735 | 307.798 | 322.845 | 151.953 | 29.938 |

The first K=256 serial round took 1.158 seconds and remains included. No warmup,
outlier or failed sample was discarded. Percentiles use nearest rank on all
21 group wall times, `sorted[ceil(p*N)-1]`. All 84 rounds, 210 observer exits,
630 collector/verifier/consumer exits and 630 loopback requests were retained.
Inputs and executable byte pins were unchanged; all private run directories
were cleaned.

An initial harness assertion stopped after 25 rounds because response handlers
can log completed responses in a different order. All exact request multisets,
response sizes, process exits and reports matched. The initial failure and all
25 original rounds were preserved byte-for-byte. A separately sealed
continuation changed that post-run assertion to an exact request multiset and
executed only the remaining 59 rounds. No previously executed round was
repeated; fixture behavior, sampler, candidates, timing boundary and limits
were unchanged.

A separate raw-record checker recalculated all summary statistics and checked
every output, transport record and memory sample without executing a candidate.
This is an additional consistency check by the same development workflow,
not an independent security review. The private unsigned record package contains
616 members and has SHA-256
`2174f749a1e0d3984338d8a6631093f3ffc1578398c11750d19228de7acd2a08`.
Captured trust inputs and raw account data remain private; this document is an
aggregate report, not a publicly reproducible benchmark corpus.

## Measurement boundary

The macOS sampler used PID/PPID/RSS snapshots to select observer processes and
visible descendants, converted RSS from KiB to bytes, and retained only their
aggregate samples. Shared pages may be counted repeatedly and short peaks may
be missed. Sampled RSS is neither aggregate physical memory nor a guaranteed
peak. Separate Darwin `wait4` high-water observations describe the waited outer
processes. Python fixture and harness memory is excluded.

The sampler slept 10 ms between snapshots; actual intervals also include `ps`
runtime. Group timing includes fresh process launches, binary-pin reads,
collection, temporary proof/expectation staging, saved-state validation,
consumption, cleanup and sampling overhead. Fixture setup and shutdown are
excluded. Ordinary OS caching applies; there was no forced cold-cache run.

Do not treat these loopback measurements as real network latency, bandwidth,
freshness or Linux/Windows performance. Earlier contiguous-mode timing records
remain bound to their own source and were not rerun; this report does not infer
a timing speedup across different candidates. Exact proof equality and reduced
response-body counts were checked separately at the measured source.

Independent network corroboration, authenticated anchor/profile/schedule inputs,
independent consumer selection, security review and reviewed source-to-binary
distribution remain qualification gates. These resource observations do not
establish canonicality, consensus finality, balances or state-value proofs.
