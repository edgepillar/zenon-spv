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

To retain those exact tested binaries with a report-bound manifest, supply
`--export-binaries` with a new absolute directory outside the checkout.
See [tested candidate artifacts](candidate-artifacts.md) for package layout,
failure handling, native CI artifacts and independent ZIP checks.

Keep source files unchanged during the run. Store the report outside the
checkout so generating evidence does not itself change Git status. The
source fingerprint streams selected Go/module/JSON members through a shared
32 KiB buffer, retaining the existing sorted, length-prefixed byte encoding.
The aggregate source payload must fit 64 MiB. Directory discovery reads at most
64 entries per page and permits at most 32,768 child entries across `cmd`,
`internal`, and `tools`, counting directories and ignored extensions too.
Those three roots have depth 1; directory depth must not exceed 32. Entry and
depth ceilings match the independent exported candidate checker. Selected paths
are sorted after discovery, preserving the fingerprint encoding. Directory path
and opened-descriptor checks refuse non-directory roots or replacements; every
opened directory is closed on completion or refusal. At most 32 directory
descriptors and one page per active level are retained, in addition to the
bounded selected-path list. Source file path and descriptor checks refuse nonregular or
oversized members; exact descriptor length and EOF are required. Growth,
shrinkage and read errors discard the entire fingerprint. Preflight refusal
precedes test execution or candidate directory creation; post-run refusal
prevents a successful report or finalized candidate. Linux/macOS opens also
refuse final-component symlink replacement and avoid waiting for a replacement
FIFO writer. The same native open rules apply to directory discovery. Protected
stable paths and same-size contents remain the caller's responsibility; this
does not authenticate or atomically snapshot the checkout. The seven fixed
corpus members are captured separately through one shared 32 KiB buffer, with
their own aggregate 64 MiB ceiling and the same regular-file, descriptor length,
EOF and close checks. Each corpus hash still covers raw bytes only, and the
fixed path order is unchanged. Any failed member discards all corpus records;
preflight failure emits only the fixed corpus diagnostic before test execution
or candidate directory creation. Stable same-size contents remain caller
inputs for both captures. Build caches and complete pipeline memory remain
separate from these source and corpus payload bounds. Discovery limits also impose no filesystem-I/O
deadline or target-device latency budget.

The default driver deadline is ten minutes (`--timeout`, positive and at most one
hour); selected test packages use that same timeout.
The driver deadline stops the direct Go command. Its stdout copy is owned by
`os/exec` and consumed concurrently; command waiting joins that copy before
closing the collector channel. A two-second wait limit also releases inherited
stdio pipes after direct-command exit or cancellation. Truncated/malformed
streams and actual process/timeout failures prevent successful reports and
candidate export, even when all observed test events appear to pass.
Spawned test/CLI processes retain their own timeouts; the driver does not
terminate descendants. This is not a process-tree supervisor or a hard deadline
for source/corpus filesystem reads before and after test execution.

Native helper tests exercise ordinary exit with buffered trailing events,
retained stdout after direct exit and cancellation, malformed streams, collector
rejection during a buffered flood, failed exit, deadline expiry after complete
events and failed start. Helpers use no shell or network and have finite lifetimes;
the owning tests wait for their OS-released fixture locks before cleanup.
These runner helper tests execute in the native Go package suite, outside the
fixed pilot selection.

## Selected coverage

The named scenarios are defined in
[`manifest.go`](../tools/offline-pilot/manifest.go). They cover:

- Build identity, collection, retained commitment/segment queries, trusted
  resume, state inspection, and competing writers across compiled processes.
- The [reference query consumer](query-report-consumer.md), with whole-batch
  target/guarantee/trust matching, lossless integers, context digest checks,
  explicit retention and actual process-failure handling, plus separate native
  consumer process measurements at 1/16/256 matched targets.
- Consumer input type/size checks before open, opened-descriptor validation and
  descriptor cleanup. Linux/macOS also exercise selected and replacement FIFOs
  plus final-component symlink replacement in deadline-owned subprocesses;
  other platforms report the native controls as skipped.
- The selected [block observer](block-observer.md), connecting actual verifier
  and consumer completion under explicit binary/context/trust pins, preserving
  read-only inputs, and refusing drift or target/tip/guarantee mismatches. Its
  native child-process tests cover nonzero exits, stream bounds and deadlines.
- Its explicit single-RPC collection mode, with the ordinary pinned collector,
  verifier and consumer, both target commands, failed collection/deadline/start,
  all binary pins, context/target mismatch, endpoint precedence and unchanged
  private state/inputs. This uses one loopback operator and synthetic trust.
- The same joined RPC mode over mixed v1/v2 delayed-inclusion envelopes,
  preselected signed/embedded segments, exact depth and evicted-history
  refusals, no implicit state advance, and a changed v2 price control.
- Explicit confirming-height collection through that joined workflow, preserving
  every signed/embedded, depth/history and state/context check. Omitting a
  required confirmation stops consumption. Single- and multi-peer collection,
  for both commitment and segment targets, must reproduce the contiguous
  node-corpus proof bytes, including the original checkpoint metadata.
- Exact compiled-binary exports, nonreplacement of existing files, bounded
  copies and report-bound manifest refusal of incomplete or conflicting inputs.
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
- Schedule export, checkpoint network binding, explicit mainnet genesis pinning,
  and opt-in custom genesis observation using a pinned node's historical testnet
  genesis through local peers. This does not select or authenticate a live testnet.
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

## Report schema 2 and historical compatibility

| Field | Meaning |
| --- | --- |
| `mode` | Always `offline_synthetic`. |
| `status` | `passed`, `passed_with_skips`, `failed`, or `incomplete`. |
| `error` | Fixed execution-stage category, or null. Raw diagnostics are omitted. |
| `runner` | Privacy-filtered build identity of the pilot executable, including native OS/architecture. Embedded source metadata may be unavailable. |
| `test_parent_race_enabled` | Whether this run requested `-race` for Go test processes. |
| `source` | Observed checkout revision/modified state, or null fields if Git metadata is unavailable; also a SHA-256 input fingerprint. |
| `source_matches_after_run` | Whether a second source snapshot equals the initial snapshot. This checks the endpoints, not continuous filesystem history. |
| `corpus` | Repository-relative names and SHA-256 hashes of the seven compatibility corpus files. This is an input inventory, not a claim that every vector was exercised. |
| `cases` | Fixed scenario IDs, package/test names, statuses, child test counts, hashes of compiled executables actually built by that scenario, and optional bounded `resource_samples` or `query_resource_samples`. |
| `skip_ledger` | Versioned diagnostic coverage and bounded source-owned records of actual skip completions. Schema 2 always includes this field. |
| `caveats` | Fixed trust and interpretation limits. |

Executable records contain exactly `command` and `sha256`, with nonempty
string values, a lowercase 64-character digest, and at most 256 encoded bytes.
The command must belong to the actively executing case. Duplicate fields,
case aliases, unknown fields, missing values and conflicting digests for one
command within a case fail the run. Identical repeated observations are
accepted and recorded once. These are local build observations; they do not
authenticate execution or binary provenance.

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
remain compatible with schemas 1 and 2; other cases omit them.

Only `compiled_query_consumer_scaling` carries `query_resource_samples`: three
fixed workload IDs, matched target count, report and expectations byte sizes,
whole consumer-process elapsed nanoseconds, nullable peak memory bytes and the
same platform-specific accounting sources. Each record also contains exactly
21 ordered `observations` from sequential fresh processes against unchanged
inputs. Every observation has its own elapsed/memory fields; the first matches
the retained scalar fields. Failures are not retried and samples are not
filtered. These measurements exclude verifier execution, fixture generation
and parent-side preservation checks. The same execution, completeness and
privacy checks apply to the bounded nested observations. See
[query-consumer resources](query-consumer-resources.md) for
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

Schema 2 always includes a version-1 `skip_ledger` object, even when its
`records` list is empty. Records contain only `scenario`, `scope`, `ordinal`,
`control` and `reason`. The ordinal follows actual skip-completion order;
`scope` distinguishes a child from a completely skipped root. Safe control and
reason codes come from a fixed source-owned allowlist. They are bound to the
same active test's marker and actual skip completion. An operating-system name
alone never supplies a reason. A marker without its skip completion cannot
complete the report.

Unreported skips use `unknown` / `unreported` and make diagnostic coverage
`unknown`. Unknown coverage is not complete platform qualification. A skipped
root remains incomplete. A normal diagnostic run may retain
`passed_with_skips` with unknown coverage, but a schema-2 candidate cannot
receive a completion manifest without a complete, consistent ledger. Existing
process, source, binary and scenario checks still apply.

The collector accepts at most 256 ledger records and 256 bytes per recognized
marker. The independent Python reader keeps the existing 256-element metadata
array ceiling. Oversized, duplicated, mismatched, orphaned or unfinished
markers are refused. Raw child names, private diagnostics and hashes of those
names are not exported.

Schema-1 reports and candidate manifests remain readable without rewriting
their bytes. Their absent diagnostic ledger stays unknown. For current M0
qualification, pass `--require-skip-ledger` to either
`tools/check-candidate-archive.py` or `tools/check-exported-candidate.py` with
the usual independently selected source, platform and payload pins. The mode
refuses a schema-1 report. Every schema-2 candidate's ledger is checked even
without that option; the default mode retains historical schema-1 compatibility.
Direct exported-file checking still creates no ZIP or secondary workspace.

`passed_with_skips` continues to mean that all selected scenarios ran and at
least one child was skipped. A known reason documents that omitted boundary;
it does not make the boundary pass. Run the named test privately when more
diagnostic detail is needed. This report-format version is unrelated to a
Zenon header version and enables no new header or state-value acceptance.

The tool exits 0 for `passed` and `passed_with_skips`, 1 for `failed` or
`incomplete`, 64 for invalid arguments, and 70 for setup/report-output errors.
Setup failure may have no JSON report; partial output is not a complete
report. `go run` may translate a child nonzero status into its own exit code.

## CI artifacts and evidence boundary

CI executes the pilot on native Linux, macOS, and Windows. Each job uploads
its JSON report as an `offline-pilot-*` artifact, retained for 14 days.
Artifacts may contain a failed/incomplete report; successful upload alone
does not establish a pass. Linux enables test-parent race instrumentation.
Successful pilot runs also upload the exact tested binaries, report and
manifest as a separate `tested-candidate-*` artifact. These unsigned packages
prepare review; they do not complete independent review or a network pilot.

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
