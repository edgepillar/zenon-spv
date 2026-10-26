# Bounded ledger export buffering

The [read-only frontier exporter](../tools/ledger-export/README.md) now groups
small record pieces into one fixed **64 KiB** output buffer. Previously each
record issued separate writes for its tag/lengths, key and value. The encoder
also reuses its two length-encoding arrays across records. This prepares the
transport/inventory track for larger R1 inputs without collecting or accepting
a representative dataset.

The canonical put bytes, order, SHA-256, logical scan/output caps, full frontier
identifier checks and write-free database adapter remain the same. No downstream
write request exceeds 64 KiB. Borrowed keys/values are copied into that fixed
buffer or written in bounded pieces; the encoder keeps no key/value map or
whole-stream copy. Tiny exports pay the fixed buffer allocation even when the
previous encoder would allocate less.

## Completion and failure

The pending tail is flushed only after iterator EOF, a successful iterator error
check and the final full-identifier lookup. A failed iterator, changed identifier
or exceeded budget discards that tail. There is no deferred flush on a failure
path. Cancellation is checked before and after the final flush; failed, short or
invalid-count writes refuse. Owned iterator/snapshot/store release and store
closure remain required for success.

A failed export may therefore leave a shorter stdout prefix than before.
Preserve the actual captured prefix and exit as UNKNOWN. A full-looking stream
without the actual successful producer completion is still insufficient. The
[completion consumer](../tools/ledger-export/README.md#reconcile-completion-then-inventory-the-retained-object)
and subsequent independent inventory retain their separate checks.

## Finite local observations

The same new benchmark source was compiled with the encoder at
`da0c1080ebda0e1b04d362c60b8fa510b6ab5834` and with the buffered encoder.
Each iteration exports 10,000 generated 32-byte values plus the fixed frontier
identifier: **400,043 put-wire bytes**. A literal wire oracle and counting writer
check the bytes, SHA-256 and write bound independently of the buffer. The old
encoder fails that new write-count regression; the buffered encoder passes it.

Local macOS arm64 observations used Go 1.25.14, `-cpu=1`, ten iterations per
repeat and three repeats. Fixture construction and null-device opening are
outside the timer. The operation includes the encoder, hash and controlled
snapshot/store release, but no database I/O or fixture construction:

| Observation per iteration | Previous encoder | Buffered encoder |
| --- | ---: | ---: |
| Downstream writer calls for this wire stream | 40,004 | 7 |
| Go allocation bytes | 400,896 | 66,513 |
| Go allocations | 20,021 | 24 |
| Discard writer elapsed range | 0.800–0.843 ms | 0.501–0.548 ms |
| Null-device writer elapsed range | 33.673–34.230 ms | 0.487–0.503 ms |

These are short, controlled observations, not representative R1 throughput,
pipe backpressure, physical disk allocation, whole-process RSS or hardware
acceptance. A writer call is not a guaranteed count of operating-system calls.
No wall-time threshold is inferred from these samples.

The local race-enabled suite reports **81 passing terminal test events**, no
failures and no skips. New controls cover buffer boundaries, literal-byte
preservation, unvalidated tails, full/final writes, malformed writer counts,
panics and cancellation. The existing 32 MiB prebuilt-value control still bounds
write size and encoder allocation; the ordinary CLI controls retain their
read-only file, completion, inventory, transition and interrupt checks.

Reproduce the bounded observations with:

```sh
go test -mod=readonly -run '^$' -bench '^BenchmarkExportSmallRecords/' \
  -benchtime=10x -benchmem -cpu=1 -count=3 ./...
```

The exporter workflow also runs these observations on its selected Linux,
macOS and Windows jobs. Hosted execution and artifact qualification must be
reported for their own source revision; the local observations do not supply
those results or transfer independent review to a changed binary. M2 agreement,
accepted-v3 header binding, representative R1 data and state-value acceptance
remain separate gates.
