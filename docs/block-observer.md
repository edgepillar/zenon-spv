# Read-only block observer

`tools/observe-block` is a selected reference application for the native-client
pilot. It performs one account-block inclusion check by running the
reviewed verifier and [query-report consumer](query-report-consumer.md), then
prints a fixed summary with actual child completion and elapsed-time records.
It supports complete commitment or segment batches of 1..256 targets. It does
not choose trust inputs, advance state, or run a background monitor. Its local
file mode makes no RPC requests. An explicit single-RPC mode first runs a pinned
collector for one bounded proof-only collection.

This completes a local application connection, not a public-network pilot or
independent review. `matched` means the entire diagnostic matched the selected
expectations under their explicit trust allowances. It does not prove network
freshness, canonicality, consensus finality, balances or state values. The
summary is unsigned local diagnostic output, not an authenticated receipt.

## Select inputs before checking

Build all three commands from a reviewed candidate. Independently verify source,
toolchain and executable provenance, and retain the selected binary SHA-256
values privately. Hashing an unreviewed downloaded binary is not authentication.
Protect the executables, saved state, trust inputs and input directory against
replacement by other users. The observer's regular-file checks and byte pins
do not close filesystem replacement races or validate directory ownership/ACLs.

Use the [operator workflow](operator-pilot.md) to prepare the anchor-bound
activation profile, producer schedule, explicit K/W selection, saved context
pin, retained state and proof-only bundle. Prepare the consumer expectations
before reading a candidate report, using independently selected account-block
identities and the intended tip/context. Never copy candidate fields to make
a mismatch pass. Profile/schedule sources and saved history remain trusted;
neither the observer nor the consumer authenticates them.

The following Bash example requires those private inputs and reviewed binary
pins. All paths are explicit; no executable is resolved from `PATH`.
Use `.exe` names on Windows. The programs emit UTF-8 bytes; preserve them through
the calling process API rather than recoding JSON through a shell text pipeline.

```bash
"$OBSERVE" \
  --verifier "$SPV" --verifier-sha256 "$SPV_SHA256" \
  --consumer "$CONSUME" --consumer-sha256 "$CONSUME_SHA256" \
  --command verify-segment \
  --genesis-config "$PRIVATE/anchor.json" \
  --protocol-profile "$PRIVATE/activation.json" \
  --schedule "$PRIVATE/producers.json" --state "$PRIVATE/state.json" \
  --bundle "$PRIVATE_RUN/candidate.json" \
  --expectations "$PRIVATE/expectations.json" --private-dir "$PRIVATE_RUN" \
  --expect-context "$PIN" --window low --retain-headers 256 \
  --timeout 30s > "$RECORDS/observation.json"
```

Every selection shown is mandatory except `--timeout`; duplicate options,
extra positional arguments and unknown options are refused. The command is
limited to `verify-commitment` or `verify-segment`. K must exceed the selected
depth W and be at most 4096. Missing profiles/schedules cannot silently select
legacy fallback behavior. A changed retention policy still requires the saved
context pin and full state compatibility checks.

## Process and file boundary

In local file mode, the observer checks both supplied executable hashes before
starting either child, with a 128 MiB input cap per binary. It snapshots at most 256 KiB of the
selected regular expectations file into a fresh private run directory, then
runs the verifier with `--json --retained-only --expect-context` and every
explicit trust/state setting. It captures up to 4 MiB of verifier stdout.
A successful diagnostic from a failed process is never passed off as a match.
After actual verifier success, the complete report and expectations snapshot
are passed to the existing consumer with that actual zero exit status.

Consumer stdout is capped at 1024 bytes and must exactly match its fixed JSON
summary encoding, including a terminating newline. Successful consumption
requires actual consumer exit zero, schema 1, `matched`, null category and a
positive target count. Valid exit-2 refusals preserve a fixed known category;
unknown, duplicate, missing, case-aliased or partial output cannot match.
The underlying consumer retains all target, guarantee, context/tip, lossless
integer and trust checks. The observer does not implement them again.

Each child's stderr is discarded, counted, and capped at 16 KiB. Exceeding
either stream cap cancels that child. Each child has its own positive deadline
(default 30 seconds, at most one minute) and one-second pipe wait limit. An
interrupt cancels the active direct child, waits for completion and attempts
cleanup. This is not a whole-operation deadline or process-tree sandbox;
preflight filesystem reads/hashes have no separate I/O deadline.

The [consumer resource observation guide](consumer-resource-observation.md)
records actual observer and sampler exits separately, uses an isolated existing
staging root and checks its visible contents after both processes settle.
Finite metadata samples do not cover every peak or establish physical storage
usage. The [sampler reference](private-staging-observations.md) retains known
disappearing-entry races and unknown allocation metadata without selecting trust
inputs or deleting remnants.

Temporary expectation/report files use mode 0600 in a newly created directory.
The command attempts removal before emitting its result, and a cleanup failure
cannot report a match. Abrupt termination or cleanup failure can leave raw
files, so the parent directory must already be private; Windows protection
depends on its ACLs. The observer writes no state or companion writer lock.
Keep concurrent writers and all legitimate input replacements under the
application's control; a tip/context mismatch must be investigated explicitly.

## Collect and observe from one explicit RPC

To connect collection and consumption in one invocation, replace `--bundle`
with all of `--collector`, `--collector-sha256`, `--rpc`, `--height`, `--count`
and the command-specific target selection. Every existing trust/state/context,
verifier/consumer pin and private-directory option remains mandatory. Select
expectations before collection; a successful response must not define its own
expected target or trust inputs.

The following example uses the previously selected saved-state tip and query
range from the [operator workflow](operator-pilot.md). `FETCH_SHA256` is the
separately reviewed collector pin and `SEGMENTS` is the explicit account-height
selection. No bundle path is supplied:

```bash
"$OBSERVE" \
  --collector "$FETCH" --collector-sha256 "$FETCH_SHA256" \
  --rpc "$RPC" --height "$TIP" --count "$QUERY_COUNT" \
  --segments "$SEGMENTS" \
  --verifier "$SPV" --verifier-sha256 "$SPV_SHA256" \
  --consumer "$CONSUME" --consumer-sha256 "$CONSUME_SHA256" \
  --command verify-segment \
  --genesis-config "$PRIVATE/anchor.json" \
  --protocol-profile "$PRIVATE/activation.json" \
  --schedule "$PRIVATE/producers.json" --state "$PRIVATE/state.json" \
  --expectations "$PRIVATE/expectations.json" --private-dir "$PRIVATE_RUN" \
  --expect-context "$PIN" --window low --retain-headers 256 \
  --timeout 30s > "$RECORDS/observation.json"
```

`verify-segment` requires only `--segments`; `verify-commitment` requires only
`--commitments` with the collector's comma-separated account addresses. A local
bundle and RPC collection inputs cannot be combined. Height must be positive
and exceed count; count must be 1..K. Frontier selection, peer/quorum discovery,
environment endpoint fallback, checkpoint export and automatic retry are not
offered. The explicit endpoint can contain credentials, which stay out of the
summary. It is limited to 4096 bytes; target arguments are limited to 32 KiB.
Native command-line limits can be stricter.

Optionally add `--momentum-heights "$CONFIRMING_HEIGHTS"` to this RPC mode when
the application has selected the confirming locations. The
[collector's explicit-height rules](fetch-bundle.md#explicit-confirming-momentum-heights)
also apply here: 1..1024 strictly increasing canonical decimal heights inside
`(height-count, height]`. Invalid lists fail before any child runs, and the option
cannot accompany a local bundle. Collection requests the unchanged checkpoint
and each selected momentum instead of the full range. The summary schema,
expectations snapshot and verifier/consumer boundaries are unchanged. Omitting
the option retains contiguous collection; missing evidence still fails the
requested retained-state query. The observer does not infer locations from RPC
confirmation metadata or treat collection as proof of finality.

Before contacting the RPC, the observer checks all three child binary hashes
and required local file paths, then snapshots expectations into its private
directory. The pinned collector receives only the selected endpoint, fixed
height/count, command-specific targets, `--proof-only`, stdout output and the
same deadline. Collector stdout is capped at 64 MiB and must be complete JSON;
stderr is discarded and capped at 16 KiB. Actual exit zero and complete stream
delivery are required before privately writing the candidate and starting the
verifier. Collection failure starts neither verifier nor consumer.

The existing retained-only query still validates the full proof and saved
context; the existing consumer still matches the exact independently prepared
tip/targets and required guarantees/trust allowances. Those checks follow
collection and are not replaced by JSON syntax validation. State, anchor,
profile, schedule and caller expectations are never written. There is no
profile renewal or implicit state initialization/advancement.

Collection uses summary schema 2: the existing seven fields plus a `collector`
process record with the same actual-exit/time/byte fields as the other children.
Local file mode retains schema 1 and its exact seven-field shape. A successful
collector with non-JSON output refuses with `invalid_bundle`; other child,
setup, cleanup and output categories/exit rules remain the same. Each child has
its own deadline, not one deadline for the whole operation or a process-tree
sandbox. Syntax checks and private filesystem work have no separate deadline.

A single-RPC run is suitable for an explicitly operator-trusted engineering
experiment. It does not supply independent operator corroboration, authenticate
activation/election inputs or establish canonicality/finality. Independent
network qualification and reviewed distribution remain separate gates.

[Selected-height resource observations](selected-observer-resources.md) record
fixed signed-capture runs at K=256/4096 and concurrency one/four, including every
actual process outcome, sampled RSS and group elapsed time. Their local limits
and macOS sampling boundary do not establish network or production capacity.

[Five-block resource observations](signed-batch-observer-resources.md) measure
five distinct signed blocks as one complete batch with the same K/concurrency
choices. All predeclared local limits passed, with every raw sample and actual
process outcome preserved. The fixed loopback replies measure replay costs;
live network latency and qualification remain separate.

[Five-block live findings](live-signed-batch-observation.md) record three complete
signed testnet batch matches, exact position/completeness refusals and an offline
missing-commitment refusal before consumption. Identities and byte oracles were
sealed before proof collection, with unchanged trust inputs and state. These
one-gateway observations do not complete network or release qualification.

## Summary and remaining pilot work

Local file mode's schema 1 reports `status`, nullable fixed `category`,
`checked_targets`, total `elapsed_ns`, and separate `verifier`/`consumer` records. Each child record has
nullable actual `exit_code`, elapsed nanoseconds and observed stdout/stderr byte
counts. A child that did not start has null status and zero stream counts.
No paths, target identities, fingerprints, binary pins or raw errors are echoed.
Count zero is a failed match, never evidence that an account or block is absent.

Exit 0 means complete matching, 2 means refusal/process/limit failure, 64 means
invalid invocation, and 70 means local setup, cleanup or output failure. Check
the observer's actual process status too: a broken output channel can leave
partial JSON. Elapsed samples include startup and observed process completion;
total time also includes preflight, private file preparation and cleanup before
encoding output. Byte counts include an observed write that exceeds a stream
cap, not unread bytes after cancellation. These records are observations, not
RSS, cold-I/O, percentile, throughput or real hardware budget guarantees.

`TestCompiledBlockObserver` runs the three ordinary compiled commands against
pinned node-derived v1 segments and v2 flat content, with explicit K=16 and
synthetic anchor/profile/schedule inputs. It covers repeated read-only success,
binary/context/retention drift, wrong targets/tips, unsupported guarantees and
refused header extension. Native child-process tests cover actual nonzero exit,
stream bounds, cancellation, failed start and inherited-pipe delivery failure
despite exit zero. The offline pilot records both.

`TestConcurrentObservationProcessCancellation` starts four real direct children
behind explicit readiness/release gates. It cancels one active child after that
child has emitted a complete matched summary, then exceeds another child's
stdout or stderr cap while two independent siblings remain live. Both siblings
must subsequently complete with their exact unmodified streams and exit zero.
OS-held locks establish actual helper lifetime and release after each runner
returns; all owned runners settle before fixture cleanup. This native offline
case checks per-invocation cancellation, stream isolation and refusal of a
successful diagnostic from a cancelled process. Its settlement guards are test
controls, not latency budgets, process-tree supervision or network evidence.

`TestCompiledRPCBlockObserver` adds ordinary collector/verifier/consumer/observer
execution against node-derived v1 evidence through one loopback RPC. It covers
both target commands, all child pins, collection failure/deadline/failed start,
context and target mismatch, explicit endpoint precedence, recovery, private
cleanup and unchanged inputs/state. It is synthetic conformance, not a live
testnet or independent-operator result.

`TestCompiledRPCObserverDelayedInclusion` exercises the joined command using
the existing mixed v1/v2 node corpus, with separate confirming momentums and
preselected signed and embedded segments. It requires signature authenticity
for the signed segment and refuses that requirement for the embedded segment.
Depth and retained-history refusals stop before consumption; fetched evicted
evidence cannot restore state, and a newer collection cannot advance the
selected tip. A changed v2 price fails collection before verification. Every
case preserves the fixed trust inputs, contexts, expectations and states,
checks actual child exits and removes private files. These remain local
synthetic-attestation checks; they do not establish network activation or
finality.

`TestCompiledRPCObserverSelectedMomenta` repeats those eight boundaries with
explicit confirming-height selection, refuses an omitted required confirmation,
and compares exact proof bytes against contiguous collection for both target
modes with one and two peers. Transport tests separately check sorted selection,
exact returned heights, shared response/evidence limits and whole-peer quorum.

The next acceptance gate is this selected application's controlled network run:
independently authenticated chain/anchor/profile/schedule and approved peers,
real selected block identities, target hardware and memory/latency/concurrency
budgets. Record restart, disconnection, stale peer, expiry and delayed-query
observations separately from synthetic CI. Independent review of the exact
candidate and source/binary/report-channel provenance remain release gates.
