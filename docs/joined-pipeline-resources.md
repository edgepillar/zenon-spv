# Full-retention joined pipeline observations

A synthetic read-only `observe-block` workload exposed substantial buffering
when the verifier decoded a complete JSON commitment array. The top-level
`json.Decoder` copied an already-owned value into its growing buffer before the
existing nested evidence decoders processed it. The successor borrows top-level
encoded value spans after standard-library whole-document syntax and nesting
validation. Scalar conversion, Unicode/case/escaped field matching, duplicate
known-field refusal, atomic receiver publication and nested count/byte budgets
remain in place. Unknown values remain ignored after syntax validation.

The source change reduces allocation and sampled process-tree RSS, with increased
observed CPU/latency cost. It does **not** clear the two predeclared 1 GiB memory
alarms at 256 targets and four observers. This remains a resource constraint for
this particular workload, not a qualified consumer acceptance decision.

## Source and workload

The preserved parent series uses
`1535fe57199295e13e64c007629abfa24b0d3328`; the successor series uses the clean code
commit `b2cd8b57913162474748ac769b3dcf3e31808237`. Later report/test-detail changes do
not retarget these observations. Ordinary local Go 1.25.14 Darwin/arm64 binaries
were built without an overlay or race instrumentation from each recorded source
and pinned separately. Their embedded Go VCS fields were unavailable. Clean
source archives, build records and executable-byte pins bind the local developer
records; these are not authenticated provenance or hosted ARM64 qualification.

Each series contains 12 cells: fully populated retained capacities K=256/4096,
T=1/16/256 distinct commitment targets, and C=1/4 fresh outer observers. Every cell
has 21 rounds, with no discarded warmup, filtering or failed-run retries. The
machine had eight physical cores and 20 GiB RAM; no controlled cold-cache,
randomized alternating-source trial or sustainable arrival-rate experiment was
performed. The parent and successor series ran sequentially. Comparisons are
local observations, not causal performance guarantees.

A public node-derived 1,000-member encoding fixture at go-zenon source
`3a4131e63881058b6ce2ee81d3a41d0033fafc99` supplies member hash preimages. The stress
addresses, chain-99 v1 anchor/v2 history, explicit profile and operator-attested
schedule are synthetic. Selected indices are 999 for T=1, otherwise
`floor(i*999/(T-1))`; nonselected rows use the zero synthetic address, so collector
address selection returns exactly the preselected batch. Every target repeats
all 1,000 flat members in the current JSON evidence format. The 256-target
collector bundle is 36,374,884 bytes. It is an encoding/stress fixture, not new
live-chain or independent-node conformance evidence.

States are filled through height `10000+K`; targets select momentum 10001 before
candidate execution. A separately prepared expiry state advances one header,
removing that target momentum. Python independently reconstructs original and
modified content roots, 13,068 header preimages, schedule canonical bytes/hash,
context fingerprints and normal/expired expectations in each series. Only
`CONTENT_INCLUSION` is required under the explicitly allowed anchor, persisted
state, external profile/schedule and retained-depth assumptions. These synthetic
member hashes do not assert real account-envelope validity or state transitions.

## Full pipeline results

Elapsed time starts with fresh outer process launches and ends with observed
actual exits and private staging cleanup. It includes binary-pin checks,
collection, verifier/consumer launches, retained-state validation and the RSS
sampler. It excludes input construction, compilation and loopback fixture
start/stop. Fixtures return one checkpoint and one confirming momentum per
ordinary successful observer; they make no external RPC requests.

Timing columns are group p50 / p95 / maximum in milliseconds, using nearest-rank
percentiles over all 21 rounds. RSS columns are the maximum sampled sum in MiB.

| K | T | C | Parent time (ms) | Successor time (ms) | Parent RSS (MiB) | Successor RSS (MiB) |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 256 | 1 | 1 | 80.713 / 95.550 / 988.665 | 85.671 / 89.439 / 995.849 | 24.578 | 24.594 |
| 256 | 1 | 4 | 85.148 / 89.359 / 100.495 | 88.027 / 96.038 / 109.675 | 88.734 | 96.891 |
| 256 | 16 | 1 | 142.010 / 152.334 / 154.278 | 140.601 / 147.968 / 150.557 | 45.453 | 37.656 |
| 256 | 16 | 4 | 145.015 / 150.802 / 151.982 | 149.453 / 171.076 / 283.038 | 180.188 | 149.641 |
| 256 | 256 | 1 | 1048.474 / 1103.422 / 1184.787 | 1204.852 / 1219.861 / 1332.659 | 324.547 | 262.062 |
| 256 | 256 | 4 | 1117.021 / 1201.855 / 1228.632 | 1294.229 / 1382.031 / 1387.812 | 1325.609 | 1043.438 |
| 4096 | 1 | 1 | 256.415 / 265.224 / 270.808 | 262.325 / 267.422 / 273.579 | 37.656 | 37.625 |
| 4096 | 1 | 4 | 271.797 / 277.175 / 278.715 | 275.652 / 279.598 / 284.006 | 148.016 | 148.047 |
| 4096 | 16 | 1 | 315.673 / 325.516 / 328.736 | 316.709 / 322.374 / 326.082 | 54.547 | 51.094 |
| 4096 | 16 | 4 | 329.787 / 341.774 / 437.203 | 343.981 / 355.682 / 364.003 | 217.922 | 202.938 |
| 4096 | 256 | 1 | 1224.171 / 1248.259 / 1252.776 | 1387.661 / 1400.284 / 1400.790 | 357.859 | 261.734 |
| 4096 | 256 | 4 | 1309.752 / 1359.902 / 1452.724 | 1472.355 / 1527.902 / 1543.336 | 1298.859 | 1043.297 |

RSS comes from POSIX `ps` samples of selected outer observers and their visible
descendants, at a requested 10 ms interval plus sampler cost. Shared pages can be
counted repeatedly and short peaks can be missed. This is neither aggregate
physical memory nor a guaranteed peak. Python fixture/harness memory is excluded.
Darwin `wait4` outer-process high water is retained separately and is never added
as a simultaneous process-tree peak.

Predeclared local engineering alarms are group p95 above 10 s serial / 30 s
concurrent, sampled group RSS above 1 GiB, or outer-process high water above
256 MiB. Both sources trigger exactly two RSS alarms, at T=256/C=4 for both K
values; neither triggers a latency or outer-high-water alarm. Limits were not
changed after observing results. An independent consumer has not selected these
limits, hardware or workload.

## Fault isolation and evidence preservation

Each source also has 24 four-observer fault groups: timeout, active SIGINT,
incomplete report and target expiry, for all six K/T combinations. All four
collectors must reach explicit live readiness gates before the selected fault.
One observer refuses with actual exit 2 while its three ordinary siblings match.
Timeout/cancellation stop the selected collector and leave verifier/consumer
unstarted; expiry stops at verifier exit 2. For the six incomplete-report groups,
an explicit test helper replaces only that verifier, emits incomplete JSON and
exits 0; the ordinary consumer refuses it with exit 2. That helper is not counted
as an ordinary verifier binary.

Each series preserves 276 group records, 2,004 raw run files, 726 actual outer
outcomes, 2,868 ordinary candidate process outcomes and six helper outcomes:
702 matched observers and 24 expected refusals. All 72 ordinary fault siblings
match. There are 1,440 loopback request events per source. Response-size fields
for cancelled clients describe attempted fixture payload size, not delivered
bandwidth. All selected input/binary bytes remain fixed, private staging is empty,
no state lock file remains, and every complete raw record is recalculated without
candidate or network execution. No failed candidate round was retried or hidden.

The parent preflight also preserves two implementation incidents before candidate
measurement: guard-snapshot serialization and unavailable embedded VCS metadata.
A later empty-directory preflight refusal likewise preceded candidate execution.
The local source-binding limitation above is retained, rather than bypassed or
presented as authenticated provenance. No measurement series was restarted.

## Decoder allocation comparison and checks

`BenchmarkProofBundleFieldSpans` compares an exact test-only top-level decoder
body from the parent against borrowed fields, sharing unchanged nested decoders.
Each mode parses the same complete synthetic 1,000-member repeated-flat bundle
under the same limits. Setup and projection/reference checks are outside timing.
The local command below produces three one-operation observations per mode/cell;
values shown are medians. Go B/op is cumulative allocation, not live heap or RSS.

```sh
go test -run '^$' -bench '^BenchmarkProofBundleFieldSpans$' -benchtime=1x -count=3 -benchmem ./internal/proof
```

| Targets | Buffered B/op | Borrowed B/op | Buffered ms/op | Borrowed ms/op |
| ---: | ---: | ---: | ---: | ---: |
| 1 | 1498432 | 976536 | 3.308 | 3.545 |
| 16 | 16085944 | 7699728 | 47.629 | 57.417 |
| 256 | 249490840 | 115275504 | 735.178 | 891.919 |

The 256-target comparison removes roughly 54% of allocated bytes. Its additional
full syntax validation/span scan is a measured memory/CPU tradeoff; no decoding
or full-pipeline speedup is claimed. A separate allocation-instrumented profile
identified `encoding/json.Decoder.refill` as the main copied-buffer allocation;
its timing is not used as an ordinary baseline.

Differential tests compare accepted projections, exact refusal text, stdlib type
error details, malformed/deep/escaped/Unicode inputs, nested aggregate and byte
budgets, and unchanged receivers after failure. Bounded differential fuzzing
exercises raw inputs up to 64 KiB. Direct malformed calls now validate full syntax
before field processing; syntax-error precedence can change, while refusals
remain refusals. Native CI runs the complete tests, existing independent node
consumer/signature controls and all 18 new allocation observations on each of
Linux, Intel macOS and Windows. Those native checks are separate from these local
Darwin/arm64 process measurements.

Canonicality, consensus finality, authenticated election/activation, state-value
proofs, independent human review, authenticated distribution and a qualified
network pilot remain outside this experiment. The selected review candidate and
prior successor heads stay fixed; this is a separate cumulative successor.
