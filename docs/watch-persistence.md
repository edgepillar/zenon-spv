# Watch persistence

The watch loop reports an ACCEPT tick only after its state save succeeds.
It then advances the in-memory retained window. This is an operational
ordering guarantee; it does not add consensus, producer authorization,
canonicality, or finality guarantees to the verifier.

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
producer policy remain necessary. This is not a new verified-handle API.

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

The tests use synthetic signed headers, local HTTP fixtures, temporary
files, and injected failures. They do not simulate a power cut, prove
storage-hardware behavior, or establish live-network readiness.
