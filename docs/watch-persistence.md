# Watch persistence

The watch loop reports an ACCEPT tick only after its state save succeeds.
It then advances the in-memory retained window. This is an operational
ordering guarantee; it does not add consensus, producer authorization,
canonicality, or finality guarantees to the verifier.

## Peer configuration

An explicit `--rpc` without an explicit `--peers` selects that RPC endpoint
instead of `ZENON_SPV_PEERS`. An explicitly empty RPC selection fails before
configuration loading rather than using the environment peer list. When both
flags are provided, a nonempty explicit peer list takes precedence; `--peers
""` clears that list and permits the RPC fallback. Without transport flags,
`ZENON_SPV_PEERS` takes precedence over `ZENON_SPV_RPC`. These rules match
[fetch-bundle peer selection](fetch-bundle.md#peer-selection).

Help and usage text name the environment variables but omit their configured
endpoint values. The runtime defaults are unchanged. This does not redact
arguments from a shell history, process list, or arbitrary argument errors.

The CLI accepts `--quorum 0` for unanimous agreement, or a value from one
through the configured peer count. Negative or excessive values fail with
exit 64 before loading configuration or starting RPC requests.

For embedders, `MultiClient.Quorum = 0` has the same unanimous meaning in
all four fetch methods, including frontier selection. If too few frontiers
are usable, the request returns `ErrNotEnoughPeers` before selecting a target;
an outage does not produce a frontier or advance retained state. Any
disagreement among usable target responses still fails, even when the
configured quorum is smaller than the peer count.

`MultiClient.Validate` and every fetch method reject an empty peer set,
negative or excessive quorum, nil peer, missing HTTP client, empty URL, or
repeated configured URL value with `ErrInvalidPeerConfiguration`.
Validation makes no RPC requests and
does not rewrite the caller's quorum. Watch also checks this configuration
before loading retained state or reporting startup context. Negative quorum
values that previously selected a fallback in some paths are now invalid.

Repeated URL values are compared after removing surrounding whitespace.
Validation refuses the configuration without changing its peer list or quorum;
it does not silently deduplicate votes. Watch's CLI returns exit 64 before
loading anchors, profiles, schedules, or state. Diagnostics identify only the
two list positions and do not echo URLs or credentials.

Distinct URL strings can still resolve or redirect to the same service, or
share an operator. These checks do not establish peer independence, authenticate
the network, or prove consensus finality. Keep transport configuration stable while queries or watch are
running; concurrent mutation of the public client fields is unsupported.

## Retained target consistency

A target at or below the local tip is reported as caught up only when its
hash, public key, and signature match the header retained at that height.
The key and signature matter because the momentum hash does not commit to
them. Agreement among configured peers does not override contradictory local
history. A mismatch returns `REFUSED / ReasonRetainedHeaderMismatch` without
extending or saving the trusted state.

If the target is older than the retained range, watch cannot compare it with
local history and returns `REFUSED / ReasonHeightOutOfWindow`. This includes
stale peers or a safety margin that moves the selected target out of range.
Watch neither re-anchors nor silently rolls back. Continuous mode reports the
refusal and polls again after the interval; `--once` exits 2. Matching retained
targets still follow the ordinary caught-up save and reporting path.

This is a consistency check against trusted local history, not new header
verification or independent evidence of network freshness or canonicality.
Targets above the retained tip still require normal linked-header verification.

## Binding the fetched batch to its target

When a fetched batch reaches the selected target height, its last header must
match the target's hash, public key, and signature from the earlier RPC round.
Unanimous agreement within each round does not prevent a peer set from changing
its answer between rounds. Such a conflict returns
`REFUSED / ReasonTargetHeaderMismatch` before header extension or any state save.
JSON reports `target_binding / header_mismatch` with no verification result.

Matching the target does not replace cryptographic or producer-policy checks.
For example, an identical invalid signature in both rounds is still rejected
by normal verification. A partial batch ending before the target cannot yet
check that target envelope; it retains the same bounded linked-header checks
and can advance without claiming complete catch-up. No target is pinned across
ticks, and this consistency check is not a canonical-chain or finality proof.

## Polling and request bounds

Negative polling intervals are rejected before state loading or RPC requests.
The CLI returns exit 64; embedders receive a setup error from `Loop.Run`.
Zero keeps the existing default of 10 seconds. Successful persisted catch-up
batches may still run immediately; an idle, refused, rejected, or failed-save
tick waits for the configured interval.

Each header-range request is bounded by the remaining distance to the target,
the configured batch size, and a positive `Policy.MaxHeaders`. This lets
embedders use a verification limit smaller than the requested batch size
without repeatedly fetching a batch that the verifier would refuse.
`Policy.MaxHeaders = 0` keeps its existing meaning of disabling that policy
bound. The verifier still independently checks the returned evidence.

In both `Loop.Run` and the CLI, a zero batch size selects 60 headers and a
zero safety margin selects six heights below the agreed median frontier.
These defaults are unchanged; zero does not disable either option. The
safety margin allows peers time to catch up but does not prove availability
or finality.

## Failure and recovery

- A failed save leaves the in-memory state at the last successful save.
- The loop logs the storage failure without logging ACCEPT for that tick.
- The next attempt waits for the configured interval and verifies from
  the retained tip. Storage failure never triggers immediate catch-up.
- Three consecutive failed save attempts stop watch by default. The CLI
  returns its existing operational-error exit code, 70.
- A successful save resets the failure counter. REJECT and REFUSED ticks
  neither save state nor reset that counter.
- Embedders may set `Loop.MaxStateSaveFailures` to a positive limit.
  Zero selects three; negative limits are rejected. No new CLI flag is
  introduced.
- Restart revalidates the complete stored window before reducing its size,
  then applies the configured trust-root, protocol-profile, and producer
  schedule checks.

The existing caught-up tick also saves before reporting ACCEPT. Callers
overriding `Loop.SaveState` must honor the persistence contract; a nil
override uses `verify.SaveHeaderState`.

Watch owns a `VerifiedState` handle and passes a detached snapshot to any
persistence adapter. The adapter cannot mutate the retained state through
its argument. Startup reports the handle's configured-anchor and persisted-
state trust assumptions; see the [verified state API](verified-state-api.md).

## Single-step watch

`watch --once` loads the existing trusted state and attempts one tick, using
the same peer selection, quorum, verification, resource limits, writer lock,
and persistence path as the continuous service. It does not bootstrap an empty
state. `syncer.Loop.RunOnce(ctx)` supplies the same behavior for internal callers.

```sh
zenon-spv watch --once --json --peers "$ZENON_SPV_PEERS" \
  --state trusted-state.json --genesis-config checkpoint.json --batch-size 60
```

| Exit | Meaning |
| --- | --- |
| 0 | The tick accepted and its state save and output completed. It may have advanced one batch or only saved an already caught-up state. |
| 1 | New header evidence was rejected; no state save occurred. |
| 2 | Evidence was unavailable or verification refused; no state save occurred. |
| 64 | Invalid invocation or local options. |
| 70 | Setup, persistence, reporting, or lock release failed. This takes precedence over a verification outcome. |

The operation stops after this tick even when its batch leaves the retained
tip below the target. It never waits for `--interval`, starts another catch-up
batch, or retries a failed save. JSON startup settings report the effective
save-failure limit of one. All options are still validated, including a
negative interval or invalid embedder save-failure limit.

For `RunOnce`, a nil error means the tick was reported and its required save
completed; callers must separately inspect `TickResult.Outcome`. A non-nil
error takes precedence even if header verification returned ACCEPT. Cancellation
before any tick returns the context error, not a successful empty operation.
Cancellation during RPC can produce a completed REFUSED tick. Output failure
does not undo a completed save, and a save failure after replacement does not
prove rollback. After acquisition, writer-lock release is attempted on every
return path, and a release error takes precedence over the tick outcome.

The bound is one batch of header work, not a total memory or wall-clock limit.
RPC timeouts and the supplied context still control network waits. Caught-up
state is relative to configured peers and does not establish independent
freshness, canonicality, or finality. Continuous watch remains the default;
`--once=false` preserves its polling and retry behavior.

## Output delivery

When `Loop.Out` is configured, a write error or short write terminates `Run`
without retrying the message or starting another tick. Startup reporting must
succeed before RPC queries or saves begin. Output failure releases the writer
lock through the normal shutdown path; the companion file remains in place.
The CLI maps returned loop errors to its operational-error exit code, 70.
An embedder can still set `Out` to nil to explicitly discard output.

State saves still precede ACCEPT reporting. If writing an ACCEPT line fails,
the completed save remains valid and is not rolled back. Restart loads and
revalidates that saved tip, even when the previous observer did not receive a
complete line. A short write can leave partial output; it is not a receipt for
successful completion of the watch process.

REJECT and REFUSED output failures do not trigger a save. If both persistence
and its error report fail, the returned error preserves both causes for
`errors.Is`/`errors.As`; the post-replacement save boundary below still applies.
Ordinary output-error formatting does not echo arbitrary writer messages, which
may contain private local paths. Explicitly unwrapped causes remain private.
Successful log formats are unchanged.

`watch --json` selects a separate JSON Lines stream. It distinguishes saved
progress, caught-up state, verification failures, and failed save attempts;
see [watch events](watch-events.md). The same write-failure and persistence
ordering rules apply to both formats.

## Retained-state validation

Save and load reject invalid capacity, wrong chain identity, header hash or
signature mismatches, broken links, noncontiguous heights, and applicable
embedded checkpoint mismatches. If the oldest retained header immediately
follows the configured anchor, its previous hash must match that anchor.
Every stored header is checked before policy-driven truncation, so shrinking
the window cannot discard a corrupt prefix to make a file acceptable.
Repeated top-level state fields are rejected, including case-folded and
escaped aliases. A later window, anchor, profile, version, or capacity cannot
hide an earlier value. Single legacy aliases and unknown metadata fields
remain compatible; this is not a general strict-JSON rule for every nested
header field.

Input and output state files are limited to 64 MiB. Capacity is limited to
100001 headers (`DefaultMaxHeaders + 1`), with the actual window no larger
than the recorded capacity. The byte limit can be reached before the count
limit. Loading stops array decoding before the first header beyond that count,
so a small file containing many tiny elements cannot allocate an unbounded
header slice before validation. These input and count bounds are not a cap on
total process memory or elapsed time. `LoadOrInit` refuses larger policy windows
before allocating a fresh state. Invalid candidate states fail before
replacement; oversized encoded output is confined to a temporary file,
which is removed on failure.

These checks detect corruption and inconsistent local records. A truncated
window cannot reconstruct its evicted ancestry or independently establish
that the retained chain is canonical. An attacker who can replace local
trusted state with a different, internally valid chain is not defeated by
rechecking signatures. State-file provenance, trusted checkpoints, and
producer policy remain necessary. The verified state API preserves in-process
ownership; it does not replace these external provenance requirements.

## Filesystem boundary

The default saver writes a temporary file in the destination directory,
syncs and closes it, replaces the destination, then syncs and closes the
parent directory on non-Windows platforms. All of those errors are
returned. Atomic replacement and durability depend on filesystem and
operating-system support, including correct handling of sync requests.

If parent-directory open, sync, or close fails after the replacement, the
new file may already be visible. The error does not roll that replacement
back. The running loop still withholds ACCEPT and retains its previous
in-memory state; a later restart may load the newly written state. This
is not an assertion that every save error preserves the previous file.

Windows retains best-effort replacement behavior and skips directory
sync. This path does not establish the same crash-durability guarantee.
Watch and stateful verification commands enforce cooperating single-writer
ownership with an OS advisory lock held from load through the final save.
A competing writer fails at startup; retained-only queries remain read-only
and can coexist. See [state writer locks](state-writer-locks.md) for companion
files, path rules, platform support, and the limits of advisory coordination.

## Regression coverage

`internal/syncer/syncer_statesave_test.go` covers retry limits, failure
counter reset, restart after a successful save, save-before-log ordering,
caught-up failures, refusal behavior, and pacing after a failed save.
`internal/syncer/output_failure_test.go` injects errors and short writes at each
startup stage and across accepted, caught-up, rejected, refused, and failed-save
ticks. It checks no RPC/save after failed startup, state/file preservation,
writer-lock release, combined error causes, and resume from a completed save
after losing its ACCEPT report.
An embedded-buffer regression preserves wrappers that override `Write` while
inheriting a `WriteString` method.
`internal/verify/state_file_durability_test.go` covers errors opening and
syncing the parent directory, including the post-replacement boundary.
`internal/verify/state_validation_test.go` covers corrupt retained prefixes,
save preservation, truncated valid windows, byte limits, and capacity bounds.
`internal/verify/state_decode_bounds_test.go` covers count enforcement before
decoding an excess row, empty-window compatibility, malformed arrays,
policy-truncation bypass attempts, and bounded parser fuzzing.
`internal/syncer/state_decode_bounds_test.go` checks rejection before RPC,
startup reporting, or persistence, with the original file preserved and writer
ownership released.
`internal/conformance/cli_inspection_test.go` checks the compiled command's
privacy-safe, read-only error report for over-limit or shadowed retained windows.
`internal/verify/state_json_test.go` covers duplicate known fields, legacy
aliases and metadata, unchanged receivers on failure, trusted resume, profile
shadowing, and bounded parser fuzzing.
`internal/fetch/multi_config_test.go` covers consistent quorum handling,
outages, disagreement, and rejecting invalid clients before request fan-out.
`internal/syncer/peer_config_test.go` covers startup validation and an RPC
outage with an explicit zero quorum without persistence or accepted progress.
`internal/syncer/request_bounds_test.go` checks actual RPC range counts,
policy-sized persisted progress, default options, and negative-interval
rejection before state loading. `cmd/zenon-spv/watch_interval_test.go` covers
CLI interval validation before configuration loading.
The save-ordering and offline peer-fault tests inject responses with more
headers than requested and check refusal without persisting progress.

The tests use synthetic signed headers, local HTTP fixtures, temporary
files, and injected failures. They do not simulate a power cut, prove
storage-hardware behavior, or establish live-network readiness.
