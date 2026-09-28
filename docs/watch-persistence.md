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
negative or excessive quorum, nil peer, missing HTTP client, or empty URL
with `ErrInvalidPeerConfiguration`. Validation makes no RPC requests and
does not rewrite the caller's quorum. Watch also checks this configuration
before loading retained state or reporting startup context. Negative quorum
values that previously selected a fallback in some paths are now invalid.

This checks local configuration only. It does not establish that endpoints
or operators are independent, authenticate the network, or prove consensus
finality. Keep transport configuration stable while queries or watch are
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

## Retained-state validation

Save and load reject invalid capacity, wrong chain identity, header hash or
signature mismatches, broken links, noncontiguous heights, and applicable
embedded checkpoint mismatches. If the oldest retained header immediately
follows the configured anchor, its previous hash must match that anchor.
Every stored header is checked before policy-driven truncation, so shrinking
the window cannot discard a corrupt prefix to make a file acceptable.

Input and output state files are limited to 64 MiB. Capacity is limited to
100001 headers (`DefaultMaxHeaders + 1`), with the actual window no larger
than the recorded capacity. The byte limit can be reached before the count
limit. `LoadOrInit` refuses larger policy windows before allocating a fresh
state. Invalid candidate states fail before replacement; oversized encoded
output is confined to a temporary file, which is removed on failure.

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
Concurrent writers to the same state file are unsupported; each watch
process must have exclusive ownership of its state path.

## Regression coverage

`internal/syncer/syncer_statesave_test.go` covers retry limits, failure
counter reset, restart after a successful save, save-before-log ordering,
caught-up failures, refusal behavior, and pacing after a failed save.
`internal/verify/state_file_durability_test.go` covers errors opening and
syncing the parent directory, including the post-replacement boundary.
`internal/verify/state_validation_test.go` covers corrupt retained prefixes,
save preservation, truncated valid windows, byte limits, and capacity bounds.
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
