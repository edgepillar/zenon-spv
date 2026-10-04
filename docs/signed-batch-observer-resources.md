# Five-block observer resource observations

The read-only collector/verifier/consumer workflow matched five distinct real
signed blocks in every measured round at source
`2f89785eeedb3ba642e08fa04d6ad54df7b92fb3`. All predeclared local latency and
memory limits passed at K=256/4096 and concurrency one/four. These measurements
replayed fixed historical responses over loopback; they do not measure live
network latency or establish a qualified network pilot.

## Source and workload

The Darwin/arm64 executables came from exact-main CI
[run 37204620143](https://github.com/edgepillar/zenon-spv/actions/runs/37204620143).
Their candidate ZIP, paired native report, manifest and executable hashes were
validated before use. The source-input fingerprint was
`57b930258cce1346430ac4e44ad0a5df111e4ee384d59400d30e2f413e19a077`.
The measured machine had six physical CPU cores and 20 GiB of memory.

The separately sealed [five-block live observation](live-signed-batch-observation.md)
provided the raw envelopes, byte oracles and exact preselected identities at
source `ca24277f2af297f171eacaffcc80eeac8c6b8694`. Its observations remain bound
to that source. The new resource run reused five distinct signed blocks at
account heights 1 through 5, confirmed at momentum height 6026. Targets were
not duplicated to enlarge the workload.

Each fresh observer collected one complete segment against the unchanged saved
tip 6144, with W=6 and K=256 or 4096. It consumed all five exact target bindings
under the existing explicit anchor, experimental profile, producer schedule
and context pin. Required guarantees were `CONTENT_INCLUSION` and
`SIGNATURE_AUTHENTICITY`; retained-state and external-policy trust allowances
were preserved. No state advancement or trust-input renewal occurred.

The fixed reply bytes were loaded before timing. Each observer used a fresh
loopback fixture and made three RPC calls: one unchanged checkpoint, the
selected confirming momentum, and the five-block account range. Response
bodies totaled 13,224 bytes; collector proof-only stdout was 9,514 bytes.
These byte counts exclude HTTP overhead. No external RPC request occurred.

## Preserved outcomes

The plan, scripts, inputs and executable pins were sealed before 21 fresh
rounds in each of four workloads, ordered K256 then K4096 and concurrency one
then four. There were 84 group rounds, 210 observer processes and 630 actual
collector/verifier/consumer outcomes. All 840 candidate process outcomes
matched; every observer checked all five targets. All 630 loopback calls,
605 aggregate memory samples and 588 raw run files were retained. No failure
was retried, sample filtered or earlier single-block workload repeated.

Before measurement, standard-library byte checks covered 15 account preimages,
seven momentum preimages and five public-key/address projections against the
sealed inputs and oracles. These checks did not execute an independent Ed25519
implementation. After measurement, a separate audit recalculated every
percentile, memory maximum, process status, target count and transport byte
count from the preserved records without candidate or network execution.

The local limits were serial group p95 <= 2 seconds, four-observer group
p95 <= 3 seconds, maximum sampled candidate-tree RSS <= 512 MiB, and maximum
waited outer-process high-water value <= 128 MiB. These are predeclared limits
for this experiment, not service-level promises.

| K | Concurrent observers | Group p50 ms | Group p95 ms | Group max ms | Max sampled tree RSS MiB | Max outer high-water MiB |
| --- | --- | --- | --- | --- | --- | --- |
| 256 | 1 | 78.919 | 100.238 | 904.467 | 30.375 | 21.016 |
| 256 | 4 | 100.707 | 130.125 | 134.231 | 122.656 | 24.484 |
| 4096 | 1 | 257.648 | 270.911 | 271.118 | 38.422 | 29.516 |
| 4096 | 4 | 294.208 | 329.147 | 481.360 | 152.609 | 30.000 |

Percentiles use nearest rank: sorted group times at `ceil(p*N)-1`. Four-observer
times describe the complete concurrent group, not the sum of four serial
latencies. The K256 serial maximum remains in the records and table; no
outlier was discarded and its cause was not established.

The private unsigned replay package contains 629 verified file members. Its
SHA-256 is `15d1dbad62aafd814e700555a1f01d80bda6044f48e9046c688e14fe459e8db1`.
The exact resource-result SHA-256 is
`bda2f74d1abc5c9c10a20fae3c8ced772d42c6a718a4805031271bfa4fa7e871`;
the read-only raw-record audit SHA-256 is
`30ad3a16423f9d0fe04899187360212318f1ef62223f355f0df18a56e67fbcd4`.
Every packaged byte and file permission was validated. Eleven earlier private
archives remain unchanged. Raw identities, replies, states, trust files and
local paths are private; the package contains no external endpoint configuration.
These fingerprints provide consistency checks, not authenticated distribution.

## Measurement boundary

macOS `ps` PID/PPID/RSS snapshots selected observer processes and visible
descendants, converted RSS from KiB to bytes, and retained only aggregate
samples. Shared pages may be counted repeatedly and short peaks missed.
Sampled RSS is neither aggregate physical memory nor a guaranteed peak.
Separate Darwin `wait4` high-water observations describe the waited outer
processes and are not added as a simultaneous peak. Python fixture and harness
memory is excluded.

The sampler slept 10 ms between snapshots; actual intervals include `ps`
runtime. Group wall time includes fresh launches, executable-pin reads,
collection, temporary proof/expectation staging, saved-state validation,
consumption, cleanup and sampler overhead. Fixture setup and shutdown are
excluded. Ordinary OS caching applies; there was no forced cold-cache run.

The [earlier single-block resource measurements](selected-observer-resources.md)
remain bound to their own workload and source and were not rerun. No timing
speedup is inferred across different workloads or candidates. Native CI on
Linux and Windows checks correctness and packaging; this macOS resource run
does not establish their performance, network freshness or production capacity.

Independent operator corroboration, authenticated anchor/profile/schedule
inputs, independent consumer selection, security review and reviewed
source-to-binary distribution remain qualification gates. These measurements
do not establish activation, authenticated elections, canonicality, consensus
finality, balances or state-value proofs.
