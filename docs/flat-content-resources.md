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

## Fixture staging

The four-proof fixture encodes its shared account-header list once and writes
the encoded list at each of the four proof positions. The file still contains
57,556,508 bytes and 400,000 encoded members. The bounded decoder and both
proof count limits read the complete repeated lists. All four workload files
matched the byte length and SHA-256 of the whole-value JSON encoder.

Three local one-iteration samples on darwin/arm64 with Go 1.25.14, race and
atomic coverage measured the four-proof encoding stage with output sent to
a discard writer. Medians were 1,622 ms for whole-value marshaling and 413 ms
for shared-list staging. The median allocation count fell from 800,073 to
200,105. Cumulative allocated bytes varied with encoder buffer reuse, from
102,358,176 to 370,794,768 for whole-value marshaling and from 92,708,008 to
92,708,040 for shared-list staging. File writes and verifier execution have
their own measurements.

The content hash ordering and shared-query benchmarks use the in-memory
fixture. Running their three fixture setups once avoids 14,673,700 logical
temporary file bytes. The file-based scaling and compiled consumer tests
exercise the actual bundle file.

## What is measured

The [hash/address text buffer comparison](chain-text-hex-allocations.md)
separately measures fixed-size hex conversion allocations used by every
serialized/decoded content member. It preserves this entire M/P grid and its
expected roots; conversion measurements are not whole-workflow timing claims.

The [owned row storage comparison](bundle-row-owned-slots.md) separately
measures removal of one temporary object per decoded row. It retains the
original JSON decoder, refusal order, count/byte guards and complete wire lists.
Its allocation observations are separate from process-memory and timing claims.

The same document's [bounded flat-list capacity hint](bundle-row-owned-slots.md#bounded-flat-list-capacity-hint)
reduces backing-array growth for complete account-header lists. Its initial
reservation is limited by encoded bytes, active row allowances and a fixed
ceiling; it does not replace the original decoder or qualify a latency gain.
The full repeated wire lists and every existing workload below remain intact.

The compact flat-row decoder reuses the most recently decoded address when
the next row contains the same 40 hex bytes. The reuse is local to one
validated array. Each row owns its address value and continues to consume a
slot under both limits. Alternate JSON spellings and malformed address
cases are tested against the ordinary decoder.

Six paired darwin/arm64 samples on Go 1.25.14 decoded 100,000 rows per
operation. With repeated addresses, median time fell from 10.60 to 9.10 ms
for the prevalidated array and from 63.21 to 61.92 ms with JSON validation.
With distinct addresses, medians were 10.50 and 10.68 ms for the array
and 63.68 and 63.35 ms with JSON validation. Allocation counts and bytes
matched in each workload. These timings cover decoding of controlled
arrays with fixture construction outside the timer.

Within a validated commitment array, the decoder can copy the rows of the
previous canonical flat object when the next object's bytes match exactly.
It compares a span of the original document and gives each commitment its
own backing slice. Each occurrence consumes its complete row allowance.
When an allowance is insufficient, the ordinary decoder reaches the same
row-limit refusal. The existing tests exercise all repeated-wire cases and
the compiled retained-only queries.

Four paired darwin/arm64 trials at `-cpu=1` with Go 1.25.14 measured median
structural decode times against `2d1511e`. Both revisions decoded the same
fixture and the timing includes full JSON syntax validation. Fixture
construction was outside the timer.

| Members per proof | Proofs | Baseline ms/op | Updated ms/op |
| ---: | ---: | ---: | ---: |
| 1,000 | 1 | 1.27 | 1.27 |
| 1,000 | 16 | 20.69 | 17.95 |
| 100,000 | 4 | 508.32 | 464.58 |

The 100,000-member workload allocated about 25.63 MB per operation in both
revisions. Each decoded list occupies separate storage.

`BenchmarkFlatContent` supplies two operations for each row:

- `Verify`: preflight and verify the already-decoded batch, including checks of
  expected targets, successful inclusion, and schedule trust assumptions.
- `LoadAndVerify`: bounded warm file read, JSON decoding, and the same checks.
  State creation, profile/schedule setup and fixture encoding are outside timing.

`B/op` counts cumulative allocation volume. Peak RSS is measured separately.
This benchmark uses individual `VerifyCommitment` calls, each of which hashes
its complete flat list. `make bench` includes these eight workloads. CI runs
each once on Linux/macOS/Windows for functional coverage without timing
thresholds.

`TestCompiledContentScalingWorkflow` separately builds the actual CLI, inspects
the selected configuration, checks its fingerprint, and performs one
`verify-commitment --retained-only` query per row. The saved state is checked
for byte/metadata preservation. Each result must identify the requested target,
prove only content inclusion, and retain configured-anchor, external-schedule
and persisted-state trust assumptions.

Within one `verify-commitment` batch, the verifier can reuse the last nonempty
list whose canonical hash matched a retained header. It compares every
account-header field in order and requires the same commitment hash in the
current header. Reordered or different lists use the canonical hasher. Bounds,
retained height, depth and target membership are checked for each proof. The
comparison holds one reference to an existing list and ends with the batch.
The CLI preflights all occurrences and the batch holds one result per input.

A local comparison used the already-decoded `M100000_P4` bundle with four
independently allocated lists. On macOS arm64 with Go 1.25.14, race detection,
atomic coverage and two runtime CPUs, the median for four individual calls
was 153.16 ms and the median for one batch was 68.79 ms. Each path had three
single-iteration samples and returned identical results. The timing starts
after decoding and ends before report emission. The fixture still carries
57,556,508 wire bytes.

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

## Reusing validated bundle arrays

The bundle reader uses the complete JSON syntax check before locating array
fields. It passes the validated spans directly to their bounded readers and
searches quoted text for the next quote, checking the immediately preceding
backslashes. The standard decoder still handles scalar conversion. Controls
compare escaped quotes, duplicate and aliased fields, syntax errors, nested
budgets, and receiver state with the independent buffered path.

Six alternating pairs on darwin/arm64 with Go 1.25.14 measured the standard
load-and-verify operation against `ffb5c20`. Both variants compile the
same conformance test and load the same node-derived content fixture. Each
sample uses two operations on one CPU. All cases verify their target identity
and the configured producer schedule.

| Members per proof | Proofs | Input bytes | Baseline median (ms/op) | Candidate median (ms/op) |
| ---: | ---: | ---: | ---: | ---: |
| 1,000 | 1 | 142,232 | 3.28 | 2.65 |
| 100,000 | 1 | 14,389,236 | 253.51 | 197.56 |
| 100,000 | 4 | 57,556,508 | 1000.09 | 772.88 |

The large four-proof case used one additional allocation per operation. Median
allocated bytes were 116,744,360 and 116,744,056, respectively. The observations
describe this local warm-file workload. The suite also runs the ordinary
compiled retained-state CLI on all four corpus shapes.

## Reading validated flat evidence arrays

A commitment decoded by the standard JSON decoder can pass its sole canonical
`sorted_headers` array directly to the bounded row reader. The enclosing
decoder has checked the complete JSON value. The ordinary object decoder
handles aliases, repeated fields, additional members, and standalone calls.
Concrete type errors retain the field context from the ordinary decoder. Both
paths charge the active per-proof and aggregate limits before decoding an
excess row.

Six paired darwin/arm64 trials with Go 1.25.14 compared normal load-and-verify
execution with `eedd601`. The unchanged node-derived corpus determines the
expected roots and targets. The same two-operation samples run on one CPU
with warm files.

| Members per proof | Proofs | Input bytes | Baseline median (ms/op) | Candidate median (ms/op) |
| ---: | ---: | ---: | ---: | ---: |
| 1,000 | 1 | 142,232 | 2.52 | 1.99 |
| 100,000 | 1 | 14,389,236 | 202.21 | 155.92 |
| 100,000 | 4 | 57,556,508 | 792.81 | 592.61 |

The largest case reduced median allocation count from 170 to 146 and
allocated bytes per operation from 116,744,072 to 116,743,048. These values
describe the complete local workload including proof loading and verification.
The separate native CLI control checks all four corpus shapes.

## Reading commitments from the bundle buffer

The bounded commitment reader receives each element as a span of the JSON
document that has already passed syntax validation. The standard decoder
still binds the commitment fields and applies the flat-proof budgets. The
reader checks the commitment limit before consuming another element. Buffered
reference controls check whitespace-sensitive error offsets, aliases, duplicate
fields, nested limits, and failed receiver updates.

Six paired load-and-verify trials on darwin/arm64 with Go 1.25.14 compared
`b27aa9b` with this change. Both variants use the same node-derived fixture
and two operations per sample on one CPU.

| Members per proof | Proofs | Baseline allocated bytes/op | Candidate allocated bytes/op | Baseline median (ms/op) | Candidate median (ms/op) |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 1,000 | 1 | 743,720 | 221,312 | 1.90 | 2.02 |
| 100,000 | 1 | 54,358,792 | 20,806,232 | 152.16 | 149.29 |
| 100,000 | 4 | 116,743,056 | 83,191,584 | 584.16 | 592.06 |

A separate six-pair run reused one 57,556,508-byte fixture across both ordinary
compiled consumers. Every process returned the same verified output bytes.
Median process peak RSS from Darwin's resource accounting fell from
129,269,760 to 95,330,304 bytes. Median elapsed time was
563.17 and 557.93 ms, respectively. These observations describe the local
read-only workflow with warm files.

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
