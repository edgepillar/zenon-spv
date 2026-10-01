# Watch persistence

The watch loop reports an ACCEPT tick only after its state save succeeds.
It then advances the in-memory retained window. This is an operational
ordering guarantee; it does not add consensus, producer authorization,
canonicality, or finality guarantees to the verifier.

## Peer configuration

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
