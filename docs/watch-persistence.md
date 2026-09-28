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
- Restart loads the state file through the existing trust-root and
  producer-schedule checks.

The existing caught-up tick also saves before reporting ACCEPT. Callers
overriding `Loop.SaveState` must honor the persistence contract; a nil
override uses `verify.SaveHeaderState`.

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

The tests use synthetic signed headers, local HTTP fixtures, temporary
files, and injected failures. They do not simulate a power cut, prove
storage-hardware behavior, or establish live-network readiness.
