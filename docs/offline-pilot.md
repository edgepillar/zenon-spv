# Reproducible offline pilot

`offline-pilot` runs a fixed selection of existing native-client tests and
writes one JSON execution report. It exercises real compiled CLIs, temporary
state files, and loopback RPC servers. No public RPC endpoint, wallet, or live
network credentials are used.

From the repository root, with Go 1.25+ and the module dependencies already
cached:

```sh
go run ./tools/offline-pilot > ../offline-pilot.json
```

Add `--race` to instrument the test processes and their in-process fixtures.
The compiled child CLIs remain ordinary builds. Alternatively, build the
tool first and run that executable from the repository root. The outer
`go run` or `go build` follows the caller's Go configuration; only the pilot's
test/build subprocesses disable module and toolchain downloads. Dependencies
must already be cached. A local Go toolchain must be available on `PATH`.
The runner uses that same resolved tool directory for compiled CLI tests.

Keep source files unchanged during the run. Store the report outside the
checkout so generating evidence does not itself change Git status. The
default driver deadline is ten minutes (`--timeout`, positive and at most one
hour); each selected test package also has a five-minute Go test deadline.
The driver deadline stops the Go command, while spawned test/CLI processes
retain their own timeouts. This tool is not a process-tree supervisor.

## Selected coverage

The 40 named scenarios are defined in
[`manifest.go`](../tools/offline-pilot/manifest.go). They cover:

- Build identity, collection, retained commitment/segment queries, trusted
  resume, state inspection, and competing writers across compiled processes.
- The [reference query consumer](query-report-consumer.md), with whole-batch
  target/guarantee/trust matching, lossless integers, context digest checks,
  explicit retention and actual process-failure handling, plus separate native
  consumer process measurements at 1/16/256 matched targets.
- The [pinned operator workflow](operator-pilot.md): inspect explicit trust
  inputs, initialize, advance and restart watch, collect, query, and refuse
  dropped schedules or changed depth settings before RPC or state writes.
- HTTP redirect refusal in compiled collection and single-step watch, preserving
  existing outputs and context-pinned state without contacting an unselected
  destination or counting it toward quorum.
- Continuous and single-step watch events; stale, unavailable, malformed,
  replayed, forked, or unauthorized peer evidence.
- Activation/profile retention, producer coverage gaps, request limits,
  bounded proof decoding, and ambiguous producer schedule inputs.
- Schedule export, checkpoint network binding, and explicit genesis pinning.
- Injected save failures and recovery, event delivery failures, native writer
  locks, and lock release after process exit or termination.
- Explicit retention/depth separation across compiled commands, delayed
  synthetic segment evidence at different confirming heights, and schema
  migration with full saved-window authorization before resizing.
- Node-derived mixed-height inclusion through v1/v2 and compiled delayed
  collection/watch/restart, plus full K=16/256/4096 state workloads.
- Node-derived flat content with 1/1,000/100,000 members and repeated-list batches,
  plus compiled read-only queries with process resource observations.
- Native process accounting across immediate/nonzero exit, a resident allocation,
  deadline cancellation and failed start. Linux/macOS use child RSS accounting;
  Windows uses a retained-handle peak working set, with a distinct source enum.
- Content-hash serialization against an independent byte-concatenation oracle,
  full-width field boundaries, duplicates and shared immutable reads.
- Signed momentum/account envelopes against fixed-offset byte oracles, including
  the v2 price suffix, full-width integers, nil/negative/wide amounts, unsigned
  fields and shared immutable reads. Invalid scalar cases only exercise the
  low-level hash primitive; verification still rejects them.
- Saved-state read bounds with stale size hints, short reads, simultaneous
  data/errors, malformed suffixes and duplicate fields.
- Proof-file allocation hints against the former bounded reader, preserving
  legacy limits, read-error priority and full-document/count refusals.

These reuse the same assertions as the ordinary test suite. The pilot does
not add another implementation of header or proof verification. It is a
selected conformance run, not the full suite, benchmark, or live deployment
acceptance gate. See [compiled query conformance](compiled-query-conformance.md)
and the [verification contract](verification-contract.md) for the individual
guarantees and their limits.

## Report schema 1

| Field | Meaning |
| --- | --- |
| `mode` | Always `offline_synthetic`. |
| `status` | `passed`, `passed_with_skips`, `failed`, or `incomplete`. |
| `error` | Fixed execution-stage category, or null. Raw diagnostics are omitted. |
| `runner` | Privacy-filtered build identity of the pilot executable, including native OS/architecture. Embedded source metadata may be unavailable. |
| `test_parent_race_enabled` | Whether this run requested `-race` for Go test processes. |
| `source` | Observed checkout revision/modified state, or null fields if Git metadata is unavailable; also a SHA-256 input fingerprint. |
| `source_matches_after_run` | Whether a second source snapshot equals the initial snapshot. This checks the endpoints, not continuous filesystem history. |
| `corpus` | Repository-relative names and SHA-256 hashes of the six compatibility corpus files. This is an input inventory, not a claim that every vector was exercised. |
| `cases` | Fixed scenario IDs, package/test names, statuses, child test counts, hashes of compiled executables actually built by that scenario, and optional bounded `resource_samples` or `query_resource_samples`. |
| `caveats` | Fixed trust and interpretation limits. |

Only `compiled_content_scaling` carries `resource_samples`: four fixed workload
IDs, members per proof, proof count, encoded input bytes, whole-process elapsed
nanoseconds, nullable peak RSS bytes, and an accounting source. Missing, repeated,
malformed or unexpected records make the report incomplete or failed. Each
record must come from its actively executing workload. Unknown fields, private
strings and raw diagnostics are refused or discarded, not echoed. Linux/macOS
require positive process RSS; Windows requires its positive native peak working
set counter with source `windows_peak_working_set`. Other platforms use null
and `unavailable`.
See [flat-content resources](flat-content-resources.md) for counter semantics
and the distinction between samples and performance guarantees. These fields
are additive to schema 1; other cases omit them.

Only `compiled_query_consumer_scaling` carries `query_resource_samples`: three
fixed workload IDs, matched target count, report and expectations byte sizes,
whole consumer-process elapsed nanoseconds, nullable peak memory bytes and the
same platform-specific accounting sources. These measurements exclude verifier
execution and fixture generation. The same execution, completeness and privacy
checks apply. See [query-consumer resources](query-consumer-resources.md) for
the input/memory boundary and remaining consumer acceptance gates.

The source fingerprint covers `go.mod`, `go.sum`, and `.go`, `.json`,
`go.mod`, and `go.sum` files beneath `cmd`, `internal`, and `tools`. Sort
repository-relative names lexically with `/` separators; for each file hash
the big-endian uint64 byte length of its name, its name bytes, the big-endian
uint64 content length, then its content bytes. Symlinked inputs are refused.
This includes test/fixture inputs but excludes documentation, CI definitions,
the module cache, toolchain, environment, and other external build inputs.
A matching fingerprint is not a signed source attestation.
Repository attributes keep these source/fixture inputs at LF line endings on
native checkouts. Exported trees with CRLF module headers are also accepted;
their fingerprints still bind the actual bytes, without normalizing them.

The runner uses `-count=1` and checks every expected top-level test and
package completion. Missing/renamed tests, missing executable records,
interrupted streams, changed source snapshots, or failed processes cannot
produce a passing report. Tests with failed children fail the report even
if their parent is reported as passing. A completely skipped scenario is
incomplete. Child test counts include nested test groups, not just leaves.

`passed_with_skips` means all selected scenarios ran but at least one child
test was skipped. For example, the real read-only-directory save-failure
check is skipped on filesystems or under privileges that still allow the
write. Inspect the relevant scenario before using that boundary as evidence.
The report deliberately does not copy dynamic child names or skip/error text.
Run the named test privately with `go test -count=1 -v` for detailed diagnostics.

The tool exits 0 for `passed` and `passed_with_skips`, 1 for `failed` or
`incomplete`, 64 for invalid arguments, and 70 for setup/report-output errors.
Setup failure may have no JSON report; partial output is not a complete
report. `go run` may translate a child nonzero status into its own exit code.

## CI artifacts and evidence boundary

CI executes the pilot on native Linux, macOS, and Windows. Each job uploads
only its JSON report as an `offline-pilot-*` artifact, retained for 14 days.
Artifacts may contain a failed/incomplete report; successful upload alone
does not establish a pass. Linux enables test-parent race instrumentation.

Reports omit local paths, endpoints, credentials, environment values, and
raw subprocess output. Fixed repository paths, source and binary hashes,
runtime target, and scenario results are intentionally visible. Do not edit
tests to log private values into executable identity records.

The tests, source checkout, local toolchain, module cache, and execution
environment remain trusted. Hashes identify locally observed bytes; they
do not prove reproducible builds or authenticated execution. Test-derived
anchors, producer schedules, activation profiles, and state provenance do
not become independently authenticated network trust inputs. No result
establishes network freshness, canonicality, consensus finality, state
transition execution, or a state-value proof. The independently sourced
network and deployment gates in the verification contract remain open.
