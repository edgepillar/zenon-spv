# Flat-content scaling and process memory

The native verifier now has a reproducible content-size and proof-count grid.
It measures an accepted read-only inclusion path under explicit synthetic trust
inputs. It does not model real consumer traffic or change production policy
limits. The largest workload uses the existing per-proof cap, not an observed
network momentum size.

## Independently derived inputs

The [compact corpus](../internal/testdata/conformance/content-scaling.json)
comes from the same pinned node revision as the other conformance corpora:
[`3a4131e63881058b6ce2ee81d3a41d0033fafc99`](https://github.com/zenon-network/go-zenon/tree/3a4131e63881058b6ce2ee81d3a41d0033fafc99).
It stores a deterministic public recipe, three sampled targets per size and
seven signed v2 header projections per size. The node computes all roots and
signatures without importing SPV. SPV reconstructs the members and checks them
against those expected values. A Python standard-library checker independently
expands all 101,001 members and checks 21 momentum hash preimages. Python does
not verify Ed25519; Go verification does.

For member index `i` from 1 through M, the recipe uses one synthetic user
address, height `i`, and SHA3-256 of ASCII `synthetic flat content member:`
followed by big-endian uint64 `i`. Content bytes are the sorted concatenation
of address (20 bytes), height (8 bytes) and hash (32 bytes). Only the first
momentum contains that content; the next six provide the requested local depth.
These identities have no executed account-block bodies. This corpus checks
serialization and inclusion, not node ledger acceptance, canonicality, consensus
finality, activation, or state values.

All workloads use an explicit chain-99 checkpoint at 6000, an operator-attested
v2 profile covering 6001–6007, required synthetic producer schedule, W=6, and a
fully populated legacy K=W+1=7 state. Increasing content M and proof count P is
separate from the [retained-capacity K measurements](retained-capacity-benchmarks.md).

| Workload | Members per proof | Proofs | Compact bundle bytes |
| --- | ---: | ---: | ---: |
| `M1_P1` | 1 | 1 | 476 |
| `M1000_P1` | 1,000 | 1 | 142,232 |
| `M100000_P1` | 100,000 | 1 | 14,389,236 |
| `M100000_P4` | 100,000 | 4 | 57,556,508 |

A one-proof workload targets the final member. Four-proof targets are spread
across the list. The wire format repeats the complete content list per proof;
400,000 members are decoded and budgeted in the final workload. In-memory
sharing during fixture setup never reduces serialized size or the aggregate
preflight budget. Every bundle fits the existing 64 MiB byte cap and default
count caps. Tests also require absent/tampered targets and content to reject,
and smaller per-proof/aggregate budgets to refuse without proof guarantees.

## What is measured

`BenchmarkFlatContent` supplies two operations for each row:

- `Verify`: preflight and verify the already-decoded batch, including checks of
  expected targets, successful inclusion, and schedule trust assumptions.
- `LoadAndVerify`: bounded warm file read, JSON decoding, and the same checks.
  State creation, profile/schedule setup and fixture encoding are outside timing.

`B/op` is cumulative allocation volume, not retained heap or peak RSS. The
current implementation hashes the complete flat content for each proof; this
is not a compact Merkle path. `make bench` includes these eight workloads. CI
runs each once on Linux/macOS/Windows for functional coverage, without timing
thresholds.

`TestCompiledContentScalingWorkflow` separately builds the actual CLI, inspects
the selected configuration, checks its fingerprint, and performs one
`verify-commitment --retained-only` query per row. The saved state is checked
for byte/metadata preservation. Each result must identify the requested target,
prove only content inclusion, and retain configured-anchor, external-schedule
and persisted-state trust assumptions.

The measured CLI process includes startup, configuration loading, bounded
bundle decoding, full trusted-state revalidation, proof verification and JSON
report emission. The parent constructs fixtures and builds the executable
before starting that process. Those parent costs are excluded. The child is
an ordinary build (`GOFLAGS` cleared and saved user settings disabled with
`GOENV=off`), even when the test parent uses `-race`. A hostile saved-flags fixture
checks that the child build cannot silently inherit those settings.
Input files normally remain in the filesystem cache. Runtime CPU parallelism
for the CLI uses its ordinary environment; benchmark `-cpu=1` does not set it.

On Linux/macOS, peak RSS comes from the exited child's `os.ProcessState.SysUsage`,
with source `process_rusage`, not a polling sampler or an aggregate of all test
children. Linux's `ru_maxrss` is converted from KiB to bytes; Darwin's value is
already bytes. See the
[Linux accounting documentation](https://man7.org/linux/man-pages/man2/getrusage.2.html)
and [Darwin's accounting source](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_resource.c).

On Windows, the resource harness opens a non-inheritable query handle immediately
after `cmd.Start`, before `cmd.Wait` releases Go's original process handle. An
open handle keeps the process object and its PID alive, even if the child has
already exited; see [Microsoft's process-ID lifetime explanation](https://devblogs.microsoft.com/oldnewthing/20110107-00/?p=11803/)
and [Go's Windows wait implementation](https://github.com/golang/go/blob/go1.25.14/src/os/exec_windows.go).
There is no concurrent Wait/Release, no reopening a PID after Wait, and no access
to Go's private handle representation. The harness retains its own handle through
Wait, queries [GetProcessMemoryInfo](https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-getprocessmemoryinfo)
once, and then closes it. The source `windows_peak_working_set` identifies
[PeakWorkingSetSize in bytes](https://learn.microsoft.com/en-us/windows/win32/api/psapi/ns-psapi-process_memory_counters).
It is neither a sampled maximum nor peak commit, pagefile usage or Go heap size.

The memory observer runs only for resource measurements. Timing covers Start
through Wait, including acquiring the Windows observation handle, but excludes
the final accounting query and handle close. No CLI code or build flags change.
Platform accounting differs; these values are not a normalized cross-platform
heap measurement. They exclude the test parent and are not a process-tree or
container memory limit. Native acquisition/query failure remains null with source
`unavailable`, never zero or an invented estimate. Linux/macOS/Windows tests and
the pilot require positive native counters, so missing accounting cannot produce
a passing supported-platform measurement. Other platforms retain the explicit
unavailable value.

`TestProcessMemoryAccounting` exercises immediate success, nonzero exit,
resident allocation, deadline cancellation and failed start. Windows additionally
tests acquisition after confirmed child exit but before Go's Wait, matches the
retained handle's creation time with Go's original child accounting, checks that
the handle is not inheritable, and refuses measurements after query-access
failure, missing completion or close. These probes run separately from the four
ordinary compiled consumer workloads and supply no consumer benchmark numbers.

The [offline pilot](offline-pilot.md) records four bounded `resource_samples`
under `compiled_content_scaling`, alongside the actual executable digest,
source-input fingerprint, corpus hashes, and native runner identity. These are
single process observations per run, not repeated benchmark distributions.
Missing or inconsistent measurements cannot produce a complete passing report.
No paths, endpoints, environment values or raw diagnostics enter those records.

## Reproduce

Use cached module dependencies and avoid competing builds/tests when recording
resource costs. Run from the repository root with Go 1.25+:

```sh
python3 tools/gen-node-momentum-vectors/check-content-scaling.py
go test -count=1 -run '^TestNodeContentScaling$' ./internal/conformance
go test -run '^$' -bench '^BenchmarkFlatContent$' -benchmem -cpu=1 -benchtime=1s -count=5 ./internal/conformance
go test -json -count=5 -run '^TestCompiledContentScalingWorkflow$' ./internal/conformance > ../content-process-events.json
go run ./tools/offline-pilot > ../offline-pilot.json
```

Raw Go event streams can include local diagnostics; keep them private and
publish only reviewed, filtered records. Keep source inputs unchanged during
the pilot. The node generator reproduction command and exact dependency pin
are in the [corpus guide](../internal/testdata/conformance/README.md).

## Recorded local observations

This is the original content-scaling baseline. The later
[hash allocation comparison](content-hash-allocations.md) measures the same
M/P workloads and adds unsorted inputs after changing the hash implementation.

The [complete samples](flat-content-samples.json) contain five 1-second samples
per benchmark operation and five separate ordinary CLI processes per workload
on darwin/arm64 with Go 1.25.14, without competing builds/tests. Hardware identity
is omitted. The benchmark uses `-cpu=1`; the CLI uses its ordinary runtime settings.
The source-input fingerprint is `a0e323abaf427a0d334207afbca182e9741cb15762fba105faaca5fe83117469`
on modified base `52203601878020e38bfa7c0ce3e8b94e52716f3a`.
That fingerprint follows the offline-pilot Go/module/JSON scope, excluding docs,
CI definitions and Python checkers. It is a measurement identity, not a clean release.

Values below are medians; MB uses 1,000,000 bytes:

| Workload | Verify (ms) | Load + verify (ms) | Load + verify allocated MB/op | CLI elapsed (ms) | CLI peak RSS (MB) |
| --- | ---: | ---: | ---: | ---: | ---: |
| `M1_P1` | 0.001 | 0.028 | 0.010 | 5.650 | 11.043 |
| `M1000_P1` | 0.091 | 3.623 | 2.274 | 8.684 | 13.238 |
| `M100000_P1` | 8.568 | 303.737 | 213.359 | 307.627 | 98.943 |
| `M100000_P4` | 34.561 | 1184.753 | 739.459 | 1205.293 | 300.433 |

The four-proof 57.6 MB input had a measured CLI peak range of 298.2–330.4 MB.
Its roughly 739 MB allocated per benchmark operation is cumulative allocation
volume, not the simultaneous RSS value. JSON loading/decoding dominates the
local timing in this grid; already-decoded verification also grows with both
members and proof count. These samples motivate separate bounded-decoder and
flat-hash allocation work, with this corpus retained as the correctness oracle.
They do not establish stable latency thresholds or a safe concurrency level.

## Remaining acceptance gates

The large list/batch path can allocate and hold much more memory than its JSON
input size. Input bounds are not a total process-memory ceiling. Applications
still need resource budgets for their own hardware and workload, including
concurrent consumers, cold I/O and lifetime retention. Optimization requires
preserving preflight accounting, content/target identity and captured trust
settings, then repeating these measurements against unchanged expected roots.

Real network traffic distributions, consumer-selected targets and trust inputs,
network bandwidth/latency, target hardware and independent
release review remain open. Synthetic roots, successful queries and green CI
do not supply any of those external gates.
