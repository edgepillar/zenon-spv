# Bounded ledger inventory buffering

The [effective ledger inventory](../tools/ledger-inventory/README.md) now reads
small record fields through one fixed **64 KiB** buffer. Previously, a tag, each
length, the key and a 32-byte value caused separate underlying reads and hash
updates. Buffering prepares the R1 measurement pipeline for larger inputs
without needing a network dataset or enabling a new verification claim.

## Input, completion and memory

The selected record count, SHA-256, strictly increasing keys, minimal varints,
field limits, family statistics and v1 JSON report remain unchanged. The buffer
never requests bytes beyond the selected length; only the existing final
one-byte EOF probe can consume one extra byte, which refuses. A read error at
refill or at that EOF probe cannot produce a successful report.

Prefetch may read up to one selected buffer before a malformed record is
rejected. It does not promise the same stream position or error timing on an
invalid input. Use the separately retained immutable input, not a live database
or a shared stream that needs to resume after refusal. Static selection/limit
checks still happen before any read. Short reads remain supported.

The reader retains at most one 64 KiB input buffer and the bounded current/
previous keys. Long values are skipped through that same buffer without keeping
a value or key map. Tiny inputs may retain more bytes than the previous reader;
the limit is input memory, not total-process RSS. Hashing prefetched bytes does
not authorize a partial inventory: every record, count, digest and actual EOF
must still pass before a report is returned.

## Finite local comparison

One generated stream contains 8,192 distinct five-byte keys with 32-byte zero
values: **327,680 canonical put bytes**. The same private observation driver ran
the reader from `5728d9d18cab33941282626b05e2a9e86dc9e08f` and the buffered
reader, three repeats each. Fixture construction is outside the timer. The
inventory call, parsing, hashing and statistics are inside it.

| Observation | Previous reader | Buffered reader |
| --- | ---: | ---: |
| Underlying `read()` calls, including EOF | 40,961 | 6 |
| Hash updates for the selected input | 40,960 | 5 |
| Local macOS ARM64 elapsed range | 66.898–71.299 ms | 43.502–46.930 ms |

The complete encoded report is identical, with SHA-256
`867084e53b4760031edb8e76b979aacfd8d9f95e8ab6250f54ca1813f3aad40b`.
The new read-count control fails with the previous reader. Read calls are not
operating-system call counts; these timings do not establish representative
throughput, pipe behavior, hardware acceptance or a wall-time test threshold.
No large fixture file, input copy, chunk file or additional payload ZIP is needed.

One actual inventory CLI invocation also reused the retained node-source genesis
stream: 103,824 records and 11,779,928 put bytes. All statistics and every
non-limit report field match the prior inventory, including 14,091 typed balance
and 5,166 contract-storage records. The comparison controller selected the
current default 256 MiB byte cap instead of the prior 64 MiB cap, so its expected
whole-report byte equality failed. That FAILURE remains retained. The completed
exit-zero output was reconciled without repeating the CLI, exporter, node build
or dataset acquisition. This comparison does not claim identical report bytes
when declared limits differ, or representative R1 data.

The complete local inventory suite also exercises a generated 32 MiB value,
65,536 fragmented records, literal wire bytes, malformed/truncated fields,
cross-buffer varints/keys/zero32 values, read errors, privacy-safe CLI refusal,
copied selection/limits and the final EOF boundary. Its traced Python allocation
peak during each generated-value/record call stays below the existing 2 MiB
control limit; that accounting excludes fixture construction and is not RSS.

The existing Linux, macOS and Windows CI invocations retain their small JSON
reports separately. Uploading a report does not qualify its contents: reconcile
the actual job/run/attempt/source, complete test-name ledger, source digests and
measurements before using it as evidence. No extra native run or representative
dataset acquisition is implied by that artifact.

R1 consistency and representativeness, M2 agreement, accepted-header StateRoot
binding, independent consumer/reviewer acceptance and authenticated distribution
remain separate requirements. Runtime state-value requests remain refused.
