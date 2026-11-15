# Bounded startup log tails

## Retained execution and observed limit

The separately authorized main-source
[`7cb3fdda54a7febd11ed6c8e2901d3a5d066cd53` attempt](https://github.com/edgepillar/zenon-spv/actions/runs/43653383092)
ended `REFUSED` at `nodes`, reason `owned_rpc_readiness_deadline`. Its original
351,317-byte ZIP has SHA-256
`79bba4eed277ea9328cba856c28304cc4aecc8e2f44332870d4c7a49119b9b80`.
The hosted reader verified 714 indexed files, materialized zero bytes and exited
1 with `HOSTED_RECORDED_NON_ACCEPTING_OUTCOME`. The outcome remains refused;
observed runtime closure was not established for the complete owned set.

The later sync observation reported `SyncDone` at current/target height two.
The following frontier read returned candidate v1 H2, hash
`6203eed405db9b47b93628ed4178740150d35dbb3353bcee75fd622133c9798e`.
This is a sequential, unauthenticated diagnostic observation. It neither selects
an accepted anchor nor establishes the first incoming v3 boundary. The original
readiness refusal still ends the attempt: no fixture setup/deposit, proof or
native consumer result was reached. Its one-dispatch permission is consumed.

The file-log extension ran. One producer's run-log command reached the 65,536-byte
stdout cap and retained incomplete output. Another completed a 56,832-byte TAR
but yielded no parsed data. These remain UNKNOWN/REFUSED respectively; the raw
streams were excluded, so the second parse refusal cannot be narrowed further.
Other bounded files were observed, including two `do not broadcast own momentum`
records in the first producer's error file. The selected
[worker source](https://github.com/digitalSloth/go-zenon/blob/2835c436b197fece5c76adf4ba8dc1decca2e3ea/pillar/worker.go#L107-L114)
emits that message when its clock is later than the event start plus three seconds.
This identifies a recorded branch, not the cause of slow production.

## Follow-up contract

Keep the two fixed file paths, prior owned-image inspection, eight-read maximum,
five-second deadline and fresh resource guard. Replace whole-file TAR transport
with the selected runtime image's absolute BusyBox applet:

```text
docker container exec <owned-id> /bin/busybox tail -c 32768 -- <fixed-log-path>
```

The selected node Dockerfile uses an Alpine runtime. The helper runs inside the
already inspected owned image; it is not a separately pinned BusyBox release.
[BusyBox documents the byte-tail operation](https://busybox.net/downloads/BusyBox.html#tail),
but actual applet availability and execution remain runtime checks. There is no
shell, follow mode, new container/mount, configurable command or host output path.
The helper reads files; it does not select a profile, sign or submit a transaction.

The command transport is capped at 32 KiB stdout and 4 KiB stderr. Full log size
does not authorize more transport or local allocation. Concurrent growth can
still cause an incomplete command; no automatic second read or bound increase
is allowed. The existing overall 50-minute / 8 GiB / initial 19 GiB admission
contract, 90-second / 30-attempt readiness and shared 96-call RPC limit remain.
No producer or consensus timing rule is changed.

## Window semantics and compatibility

`owned-devnet-startup-file-logs/v2` records the exact captured-window bytes and
SHA-256, plus fixed summaries of its complete inner records. The first line is
always discarded as a possible leading fragment, even for a short file. An
unfinished final line is also omitted. Leading, classified and trailing byte
counts must sum to the captured size. Zero classified records do not establish
an empty file, absent error or successful block production.

The window pin must equal the command stdout pin. Successful parsing additionally
requires actual exit zero, complete capture, a successful recorded process start
and owned inspection/role/kind/order binding before cleanup. Failed/incomplete
reads retain their actual outcomes and provide no parsed data. Raw text, private
configuration and arbitrary reasons remain outside the index. The additional
fixed `too-late` reason is v2-only. Summaries are diagnostic assertions because
omitted original text cannot be independently replayed.

The [v1 whole-file reader](owned-startup-file-logs.md) retains its exact original
schema, classification keys, TAR limits and report shape. Historical partial
reads are neither repaired nor relabeled as tails. Both the source-4f0b9f7 H1
and source-7cb3fdd H2 diagnostic archives remain independent non-accepting records.

## Controls and gates

Controls cover exact owned applet arguments and byte caps, large-log windows,
independent boundary/pin vectors, invalid UTF-8, fragment exclusion, line/byte
limits, v1/v2 schema separation, receipt bindings and actual recorder/finalizer
behavior with benign Python children. Archive special-entry controls remain
in memory; no filesystem FIFO, symlink or socket fixture is added.

The selected local run passed 259 test roots in 8.066 seconds, including 20
additional tail/reader cases, with no skips, failures or errors. Both retained
fixture ZIPs were reread in place and produced their original report structures;
no artifact transport was repeated. Discovery found 350 preparation-suite roots;
discovery alone is not execution of that complete suite.

Local runtime controls, exact-source Linux/macOS/Windows CI and artifact checks,
and a later separately approved real fixture have distinct qualification scopes.
The underlying production delay and actual selected H3/header/proof/CLI workflow
remain unresolved. Production state proofs, canonicality, consensus finality,
fund release and recipient receive are not established by this diagnostic change.
