# First insertion point catch-up

The owned chain-69 experiment at source `bf6ab4e43dba4fd5c2a2ca3328eba51e11f5159c`
([run 43704355778, attempt 1](https://github.com/edgepillar/zenon-spv/actions/runs/43704355778))
stopped at node readiness. All 30 recorded candidate-frontier responses were
source genesis H1, including the follow-up after the sync response. The typed
consumer did not complete. Two run-file summaries each counted one
`broadcasting own momentum` marker. The marker is shared by the producer worker
and protocol broadcaster, so its count does not establish a stage or delivery.

The selected original node is
`digitalSloth/go-zenon@2835c436b197fece5c76adf4ba8dc1decca2e3ea`, tree
`f89d645c7f5be85dfe10dc7a510d80df7965d22f`. In `consensus/points.go:71`, its
synchronous insertion listener fills every completed period, followed by completed
epochs, before returning. The unchanged public genesis timestamp is `1739923200`.
At `2026-11-15T10:30:00Z`, 182,718 periods of 300 seconds have elapsed. This is a
source-supported cost hypothesis; the recorded experiment does not establish it
as the cause of the readiness deadline or unresolved ledger closes.

The first native measurements at SPV source
`32c44aa15c54005f19d401b7cfe7a2a34f4a57a5`
([run 43708353171, attempt 1](https://github.com/edgepillar/zenon-spv/actions/runs/43708353171))
recorded:

| Platform | Listener seconds, fixed experiment window | Closed consensus logical bytes |
| --- | ---: | ---: |
| Linux amd64 | 38.778142229 | 5,047,967 |
| macOS amd64 | 52.245839178 | 5,047,787 |
| Windows amd64 | 40.2713689 | 5,044,041 |

All three native commands exited zero with complete output and all three cases
passed. Linux/macOS jobs completed successfully. Windows subsequently refused
the documentation source pin because its checkout used CRLF; that CI failure
remains recorded and is not a successful complete qualification. The document
now has an explicit LF checkout rule, which is included in the source pins.

For the fixed window, all three native observations reported 182,718 period
points, 634 epoch points, 365,945 database Gets, 183,353 Puts and 19,619,414 bytes
of Put values. These are one-run bookkeeping observations. They do not establish
the duration under four concurrent containers or identify the readiness failure
cause. Do not change the genesis, slot timing, activation or readiness limits to
convert these observations into a successful pilot.

## Unsigned measurement

`first-insertion-catchup.yml` fetches the exact original node into a fresh hosted
workspace and verifies all original regular sources against their Git blob IDs.
It adds an external-package test and a small test-only export adapter for the
original `consensus` package. Original node sources,
genesis, activation rules, slot timing and readiness limits are unchanged.

The test initializes real ledger/cache/state LevelDB managers. It inserts an
**unauthenticated, unsigned H2 test fixture directly below the verifier** into
that isolated database. The original point listener uses a fresh LevelDB. The
one-period case invokes the listener through the momentum pool. The longer
cases call the original listener synchronously after insertion. The fixture runs
with an in-memory read of the Ledger RPC handler and isolated databases. The
unsigned input exercises node bookkeeping. Its measurements cover fixture
timing and same-node frontier visibility.

Three independent fresh cases use gaps of one period, one day and the fixed
experiment window. Each retains actual listener duration, database Get/Put calls,
written value bytes, completed period/epoch counts, and the closed consensus
directory's regular-file count and logical byte total. Original sources and the
added input are checked again after execution. All managers must close before
the test's disposable directory is removed.

These observations are neither peak disk/RSS measurements nor APFS physical-space
estimates. No wall-time ratio is a pass criterion. A timeout, incomplete stream,
skipped case, partial point history or failed close fails qualification; preserve
its original streams and last phase. A passing cost control does not diagnose a
live process, reproduce every production callback, authenticate execution or
qualify a devnet consumer.

## Frontier visibility during notification

The one-period case registers the original points listener and holds its first
period database read with a channel. It sends the same fixed
`ledger.getFrontierMomentum` JSON-RPC request before insertion and while the
listener is held. The node's HTTP handler serves the request in memory and the
test checks the response envelope and the expected height and hash, first H1
and then H2. After releasing the read, the test checks insertion completion and
the resulting point records. The one-period duration includes the observation.
The longer cases keep their separate direct measurements.
[Points listener](https://github.com/digitalSloth/go-zenon/blob/2835c436b197fece5c76adf4ba8dc1decca2e3ea/consensus/points.go#L71-L89) ·
[Ledger API](https://github.com/digitalSloth/go-zenon/blob/2835c436b197fece5c76adf4ba8dc1decca2e3ea/rpc/api/ledger.go#L300-L308)

Current qualification requires a v3 visibility record with the fixed RPC method
and in-memory transport. Historical v1 and v2 records retain their local-store
observations and their original scope.

The portable `go test -json` stream can include compiler diagnostics, such as a
macOS dependency deprecation warning. The original stream retains these
records. The qualifier derives observations only from the selected test events
and requires successful command and test completion.

The original momentum pool releases the frontier lock before it notifies
listeners, and the producer broadcaster sends the momentum after insertion
returns. This test checks same-node RPC visibility and callback ordering in the
unsigned fixture. Cross-node propagation and the historical readiness cause
remain unestablished.

## Recorded chain-69 height-two header

The one-period case also verifies the archived 697-byte frontier reply from
request 32 of [run 43653383092, attempt 1](https://github.com/edgepillar/zenon-spv/actions/runs/43653383092),
artifact `14136634774`. Its SHA-256 is
`931a991acef939bd4d9c0f55e293c64402189940b406b612a0e8bed9668acbc4`.
The reply contains the recorded v1 H2 from the post-sync diagnostic. The
run's terminal outcome remains `REFUSED` at the startup deadline.

The test decodes the original reply with the node's Ledger RPC types,
recomputes the signed momentum hash, verifies its Ed25519 signature and derives
the producer address from the public key. The node's original
`VerifyMomentumProducerAt` must match the exact timestamp against the restored
public source genesis H1. It computes the election with an in-memory cache and
the chain stays at H1. The earlier unsigned H2 remains a separate visibility
and cost fixture. Current qualification requires both observations.
[Original producer verification](https://github.com/digitalSloth/go-zenon/blob/2835c436b197fece5c76adf4ba8dc1decca2e3ea/consensus/consensus.go#L98-L115)

The recorded-header result binds the archive reply to its signature and the
source-genesis slot. In a separate temporary database the original node's VM
validates and applies the recorded H2 and reproduces its empty change set.
The ledger, cache and state-tree managers close and reopen at that exact H2.
The state-root rule is inactive at H1 and active at the reopened H2. The
original raw verifier accepts an unsigned H3 with version 3 and rejects incoming
versions 1 and 2. Its hypothetical empty-patch root matches the reopened H2
tree root. The test leaves the reconstructed ledger at H2.
[VM apply path](https://github.com/digitalSloth/go-zenon/blob/2835c436b197fece5c76adf4ba8dc1decca2e3ea/vm/supervisor.go#L109-L133) ·
[Version rule](https://github.com/digitalSloth/go-zenon/blob/2835c436b197fece5c76adf4ba8dc1decca2e3ea/verifier/momentum.go#L149-L167)

This control uses the existing one-period execution and a second short database
lifecycle. Its root is conditional on an empty H3 patch. The selected experiment
must still supply the signed H3, accepted range and typed BatchEntry result.

## Linux CPU comparison

The main revision `5a0d29eb3df7c4ce2f66cae7174e33dea9d8781d` completed the
unconstrained controls on all three platforms. The fixed window took 40.1 seconds
on Linux, 69.3 seconds on macOS and 33.3 seconds on Windows in that run.
[Main measurement run 43711591065](https://github.com/edgepillar/zenon-spv/actions/runs/43711591065)

The Ubuntu job now compiles the original bookkeeping test once. It runs all
three cases with one Go worker and no unit CPU quota. It then runs only the fixed
window using the same binary and a 50 ms quota per 100 ms period. Both transient
units run as the hosted runner user in a private network namespace and have a
768 MiB memory limit, no swap allocation and separate disposable databases. This
uses the per-node limits from the historical reference-gas contract and avoids
building or downloading a node container. The test reads its own kernel limits
immediately before and after the listener and retains CPU time and throttling
counter deltas. The comparison requires identical period, epoch, Get, Put and
written-value counts, and binds both runs to one test binary digest.

The 90 second comparison is against the recorded readiness deadline. It covers
one listener with an isolated disk workload. The signed fixture also includes
other nodes, networking, production callbacks and a different build environment.
A sample above 90 seconds shows that the listener can occupy that much time by
itself under the measured constraints. A shorter sample still leaves those other
costs to investigate. The comparison uses the original deadline regardless of
its result.

## Resource and evidence limits

Admission requires a 10 GiB free-space floor plus a 3 GiB expected allocation and
1 GiB safety margin. This is admission budgeting, not an OS aggregate quota.
The hosted job is limited to 15 minutes and each native test run to 180 seconds
of execution. Each Linux transient unit also has a 190 second system limit.
Compilation is capped at 480 seconds on Linux, and the portable command is
capped at 600 seconds including compilation. Both command streams are capped
at 2 MiB. The final closed consensus directory must not exceed
256 MiB per case. No binary or temporary ledger is uploaded: the small artifact
retains source inputs, original source pins, toolchain context, actual command
streams/receipts and the three measurements. Source-pinned inputs reproduce the
disposable fixture; failed command output remains evidence.

Driver controls run with:

```sh
python -I -B tools/gen-state-root-vectors/qualify_first_insertion_test.py -v
```

The hosted driver uses `prepare` and `qualify` modes with explicit fresh workspace,
evidence directory and native platform arguments. Its manifest binds source and
tree, feature/checkout revisions, run/attempt, platform, actual complete command
output and each selected test. The existing closed-parent oracle retains its
separate read-only H1 scope. No signed experiment or automatic retry is authorized
by this lane; no production state-proof, canonicality or finality gate changes.
