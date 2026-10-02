# Read-only block observer

`tools/observe-block` is a selected reference application for the native-client
pilot. It performs one local account-block inclusion check by running the
reviewed verifier and [query-report consumer](query-report-consumer.md), then
prints a fixed summary with actual child completion and elapsed-time records.
It supports complete commitment or segment batches of 1..256 targets. It does
not poll peers, choose trust inputs, advance state, or run a background monitor.

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

The observer checks both supplied executable hashes before starting either
child, with a 128 MiB input cap per binary. It snapshots at most 256 KiB of the
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

Temporary expectation/report files use mode 0600 in a newly created directory.
The command attempts removal before emitting its result, and a cleanup failure
cannot report a match. Abrupt termination or cleanup failure can leave raw
files, so the parent directory must already be private; Windows protection
depends on its ACLs. The observer writes no state or companion writer lock.
Keep concurrent writers and all legitimate input replacements under the
application's control; a tip/context mismatch must be investigated explicitly.

## Summary and remaining pilot work

Schema 1 reports `status`, nullable fixed `category`, `checked_targets`, total
`elapsed_ns`, and separate `verifier`/`consumer` records. Each child record has
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

The next acceptance gate is this selected application's controlled network run:
independently authenticated chain/anchor/profile/schedule and approved peers,
real selected block identities, target hardware and memory/latency/concurrency
budgets. Record restart, disconnection, stale peer, expiry and delayed-query
observations separately from synthetic CI. Independent review of the exact
candidate and source/binary/report-channel provenance remain release gates.
