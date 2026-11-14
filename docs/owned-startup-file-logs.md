# Bounded startup node file logs

## The retained attempt

The single authorized source-`4f0b9f738041c368477c365e1b65fb01f71a2c1c`
[attempt 43640873250](https://github.com/edgepillar/zenon-spv/actions/runs/43640873250)
ended `REFUSED` at `nodes`, with `owned_rpc_readiness_deadline`. Its original
338,548-byte result ZIP has SHA-256
`4020bdba1a525ad275362b3cfe3d8bb87e5454c6eda594c5674a2ef1372ee976`.
The hosted reader verified 689 indexed files and exited 1 with
`HOSTED_RECORDED_NON_ACCEPTING_OUTCOME`. The original ZIP was retained once,
without extraction or repackaging. The failed outcome remains preserved.

The frontier remained v1 H1. The later stats read reported `SyncDone` with current
and target height one; the next frontier again returned H1 with hash
`fab7609bae7fd78eb7d2b0d4a5023832f1a6730921b862f2415da25524698dc9`.
These are sequential diagnostic reads. No H2 anchor, accepted v3 header, fixture
configuration, deposit, proof or native consumer result was reached. The single
dispatch permission was consumed; this source change authorizes no new attempt.

The controller recorded all four nodes as running before cleanup, with
`OOMKilled: false`. Its stdout summaries counted 5/4/1 `Producing momentum ...`
lines for the three producers. The original raw inspection/log streams were
excluded, so these remain source-bound diagnostic assertions. They establish
neither successful block production nor an absence of production errors.

The sampled peak new disk use was 3,001,384,960 bytes and sampled peak evidence
use was 547,082 bytes, with no budget refusal. Transient peaks, unrelated-writer
attribution and OS-enforced aggregate quotas were not established.

## Source-derived gap

At pinned node `2835c436b197fece5c76adf4ba8dc1decca2e3ea`,
[`common.InitLogging`](https://github.com/digitalSloth/go-zenon/blob/2835c436b197fece5c76adf4ba8dc1decca2e3ea/common/logs.go#L33-L61)
installs file handlers for `<DataPath>/log/zenon.log` and
`<DataPath>/log/error/zenon.error.log`. The selected devnet config uses
`/root/.znn` as `DataPath`. Those handlers do not mirror their output to Docker
stdout. The handlers can record the same error in both files; per-file counters
must not be summed as distinct events.

The [producer manager](https://github.com/digitalSloth/go-zenon/blob/2835c436b197fece5c76adf4ba8dc1decca2e3ea/pillar/manager.go#L94-L105)
prints the observed stdout line before calling the worker. Generation errors and
broadcast outcomes use the file logger. The
[supervisor](https://github.com/digitalSloth/go-zenon/blob/2835c436b197fece5c76adf4ba8dc1decca2e3ea/vm/supervisor.go#L194-L218)
also records recovered momentum VM panics there. Stdout alone cannot distinguish
a generation error, delayed worker, failed broadcast or other production issue.
The underlying reason for H1 not advancing remains open.

## Fixed-path, bounded observation

After the existing initial-height refusal and nine startup diagnostic commands,
the controller can request the two fixed log files for each inspected owned node.
Each request is exactly `docker container cp <owned-id>:<fixed-log-path> -`.
The destination is stdout. No host destination, shell, container executable,
recursive directory copy or configurable pathname is selected.

There are at most eight additional read commands, seventeen Docker commands in
total. Each retains its five-second command deadline and fresh resource guard.
Archive stdout is capped at 64 KiB, stderr at 4 KiB, and the decoded log entry at
32 KiB. A file that does not fit is unavailable; there is no automatic retry,
limit increase or fallback to an unbounded copy. This observes one advertised
archive-entry size, not an atomic view of a growing log file.

The in-memory TAR reader requires one exact regular basename, bounded timestamps
and complete framing. It rejects links, directories, FIFO entries, sparse files,
other paths, extra entries and nonzero trailing data. It writes no decoded file.
Only a content pin, fixed event/reason counters and allowlisted relative source
locations enter `startup-file-logs.json`. Arbitrary reasons, panic text, stack
arguments, peer addresses, raw TAR bytes and log text remain outside the index.
Unknown messages remain unclassified; a zero counter is not proof of absence.

The optional report binds each read to the prior validated owned-node inspection.
Its reader checks actual exit/completeness and stream pins, successful start
records, role/file bounds and command order before cleanup. Missing or failed
file reads retain their actual outcomes, without inventing an empty successful
log. The excluded original TAR/text cannot be independently replayed, so the
reader explicitly marks the summaries as diagnostic assertions.

Legacy archives without this optional report retain their report shape. Existing
archives receive no backfilled data. Anchor, profile, producer schedule, context
pins, the 90-second / 30-attempt readiness bound, shared 96 RPC-call cap and
overall resource/cleanup limits remain unchanged. The original readiness refusal
still ends the experiment even if diagnostics suggest activity.

## Controls and remaining gates

The controls include an independently encoded USTAR entry, timestamp-bearing PAX,
framing/type/size refusals (including oversized numeric header fields), privacy
classification, exact owned read arguments,
interruption and failure receipts, old-result compatibility and archive-reader
binding. The actual recorder/finalizer control uses owned Python children and
regular files, without a Docker daemon or signing. FIFO/link cases are in-memory
archive metadata, not nonregular filesystem fixtures.

Local execution passed 239 selected test roots, including the 24 new roots,
with no failures, errors or skips. Re-reading the retained H1 result with the
new reader produced the original report unchanged, without another download.
The discovered preparation inventory is 330 roots; discovery alone does not
qualify execution of the complete suite.

Exact-source hosted CI/artifact review and a later separately approved owned
fixture have separate qualification requirements. Selected-network
D2/D3/D5 acceptance, representative R1 measurements and applicable independent
review/release/production gates remain open.
