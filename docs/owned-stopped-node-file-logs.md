# Bounded file observations when a node has stopped

This change selects a diagnostic read. It does not resolve the observed H1/H2
readiness refusals or establish the cause of the recorded nonzero node exits.
The [earlier tail record](owned-startup-log-tails.md) preserves those observations
and the reason for bounding reads independently of a growing log file.

## Selection and bounds

Docker documents that [container exec](https://docs.docker.com/reference/cli/docker/container/exec/)
requires the primary container process to be running and fails for a paused
container. [Container cp](https://docs.docker.com/reference/cli/docker/container/cp/)
can read from a running or stopped container and stream a TAR to stdout.
A tail-only reader therefore cannot collect a stopped node's file records.

The optional `owned-devnet-startup-file-logs/v3` report binds each file's `method`
to the existing prior owned-container inspection:

| Prior typed state | Method | Stdout bound | Decoded content bound |
| --- | --- | ---: | ---: |
| `Running=true`, `Paused=false`, `Restarting=false`, `Dead=false` | `byte-tail` | 32 KiB | 32 KiB window |
| Another validated state, including an unavailable required field | `whole-file` | 64 KiB TAR | 32 KiB whole file |
| Inspection unavailable or ownership/image check refused | No read; `method=null` | None | None |

The path choices remain the two fixed node log paths. There are at most eight
file reads, five seconds per command and 4 KiB of stderr per read, under the
existing resource guard. Whole-file parsing remains in memory and requires one
exact regular member with bounded metadata. No host destination, extraction,
new mount, shell, follow mode, container start or unpause is introduced.

A state change after inspection can still make the selected command fail.
That actual failure or incomplete result remains non-accepting and supplies no
parsed data. It does not select a second method or repeat the read. A stopped
node's whole file can exceed the old cap; that remains an explicit limitation,
not permission to read the whole growing log or silently raise a bound.

## Evidence and compatibility

The reader checks the selected method against the prior typed state summary,
the role/kind, command receipts, stream caps and ordering before cleanup. A tail
keeps its exact stdout/content pin and complete-inner-line window accounting.
A whole-file summary keeps the original TAR/content accounting and has no
tail-window fields. The v1 whole-file and v2 tail readers retain their existing
schemas; historical reports are not rewritten.

Local controls exercise stopped and paused selection, a state change after
inspection, strict boolean/missing-field handling, mixed-method review, caps,
privacy and refusal cases. Archive fixtures are in memory. These controls do
not execute Docker or establish that a stopped container was read on a real
runner. Hosted preparation controls have the same limitation unless an actual
container execution is separately recorded.

The summaries remain diagnostic assertions over omitted private streams. They
are not an independent replay of those streams and give no accepted-header or
state-value authority. Readiness/RPC limits, producer timing, source/profile and
context pins, original cleanup requirements and production NO-GO gates remain
unchanged. Another signed fixture requires a separate source-specific approval.
