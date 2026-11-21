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
source-genesis slot. In the same short replay database, an in-memory writer
passes the signed envelope through the node's `p2p.Send` and `Msg.Decode`.
The qualifier checks the 213-byte RLP message against the independent digest
`e2ed995b4d375303bdfb9a5b94862b9cbd52c8a0eb7c00faf079b56c3a7cbff1`.
The message is the two-element list of momentum and empty prefetched blocks.
Within the momentum, version, chain ID, hash, parent, height, timestamp, data,
content, changes hash, public key and signature are encoded in that order.
The three trailing optional zero fields are omitted. The archive preserves
one size/digest observation for these in-memory bytes.
[Node message codec](https://github.com/digitalSloth/go-zenon/blob/2835c436b197fece5c76adf4ba8dc1decca2e3ea/p2p/message.go#L46-L55) ·
[Momentum field order](https://github.com/digitalSloth/go-zenon/blob/2835c436b197fece5c76adf4ba8dc1decca2e3ea/chain/nom/momentum.go#L38-L67)

The original fetch queue takes the decoded H2, looks up its parent and calls
`ChainBridge` to check and insert it through the node's VM, cache, state tree
and ledger. A fixture listener holds the synchronous insertion notification.
The in-memory Ledger RPC returns H1 before enqueue and H2 while the notification
is held. Insertion returns after release and the fetcher hands that exact H2
to an in-memory propagation callback. The check reuses the existing one-period
database and native test invocation.
[Fetch queue](https://github.com/digitalSloth/go-zenon/blob/2835c436b197fece5c76adf4ba8dc1decca2e3ea/protocol/fetcher/fetcher.go#L444-L515) ·
[Peer handler](https://github.com/digitalSloth/go-zenon/blob/2835c436b197fece5c76adf4ba8dc1decca2e3ea/protocol/handler.go#L428-L453)

The checked changes hash commits the empty patch. All managers close and
reopen at the exact H2. The state-root rule is inactive at H1 and active at the
reopened H2. The original
raw verifier accepts version 3 for an unsigned H3 candidate and rejects incoming
versions 1 and 2. Its hypothetical empty-patch root matches the reopened H2
tree root. The reconstructed ledger stays at H2 for this observation.
[Receiver insertion](https://github.com/digitalSloth/go-zenon/blob/2835c436b197fece5c76adf4ba8dc1decca2e3ea/protocol/chain_bridge.go#L451-L500) ·
[Version rule](https://github.com/digitalSloth/go-zenon/blob/2835c436b197fece5c76adf4ba8dc1decca2e3ea/verifier/momentum.go#L149-L167)

The current qualification requires both the queue and bridge records in the existing
one-period case. Historical direct VM replays retain their original report
shape. The root remains conditional on an empty H3 patch. Cross-node delivery
and the selected signed H3, accepted range and typed BatchEntry result still
require an actual selected experiment.

### Settlement proofs at the reopened H2

For domain 1 and batch 0 the test derives the exact full keys for BatchEntry,
domainRecord and domainConfig. The original node's local tree produces three
bounded absence proofs at the recorded H2. The same node's Ledger API returns
`ErrStateRootNotActivated` for its root and all three proof reads at H2. That
v1 header carries an all-zero StateRoot.
[Ledger proof rule](https://github.com/digitalSloth/go-zenon/blob/2835c436b197fece5c76adf4ba8dc1decca2e3ea/rpc/api/ledger.go#L329-L385)

The original trie verifier checks these proofs against the reconstructed tree
root and refuses a match to the v1 header root. The qualification log retains
the three exact proof byte strings and keys for independent replay. The local
tree observes the unconfigured startup state. A typed consumer requires all
three rows present under the StateRoot of its separately accepted header.

### Ledger reads at the reopened unsigned H3 fixture

The original peer insertion path refuses the unsigned H3 with
`ErrMSignatureMissing` while the frontier stays at H2. The test then inserts
this empty-patch fixture in its
temporary ledger and reopens the original managers at the exact H3 hash.
The Ledger API returns the root in that header and supplies three absence
proofs, each of which the original trie verifier checks against that root.
The same API still refuses the old H2 root and all three proofs.

The H3 report retains the new header hash and digest/size references to the
identical proof bytes already recorded at H2. The qualifier independently
reconstructs the 208-byte unsigned header preimage and checks all three
references. This extends the existing one-period test and leaves the fixed
CPU comparison workload intact. The result is local fixture evidence.
The selected experiment still needs a signed H3 and a completed consumer
query against its accepted header range.

### Historical Ledger reads with one successor

The one-period fixture also extends the reopened H3 with an unsigned H4 in
the same disposable database. A single fixture-only storage marker gives H4
a different StateRoot. The original Ledger API must return H3's root and the
same three Settlement absence proofs both before and after reopening at H4.
For the marker itself, the original trie verifies absence at H3 and membership
at H4. This makes an accidental read of the current tree observable.

The new record references the existing proof bytes by length and SHA-256.
The qualifier reconstructs the one-put patch digest and the H4 hash, checks
the H3-to-H4 link, and binds the historical reads to the same three proof
references. The fixed-window CPU control keeps its existing workload. This
checks one retained-height read at the original node, the depth used by the
owned query. The selected network still requires a signed range and three
present typed witnesses.

### Historical membership of the three typed rows

The same disposable ledger continues from H4 to H5 and H6. H5 inserts the
pinned BatchEntry, domainRecord and domainConfig ABI bytes under their
locally selected Settlement keys. H6 deletes BatchEntry and changes the
StateRoot. The original Ledger API returns all three H5 membership proofs
before and after reopening at H6. The proof bytes match the initial H5 reads.
The H6 read returns a canonical absence proof for the deleted batch.

The qualifier independently derives the two patch hashes and unsigned header
hashes, then reconstructs the roots from the three membership proofs and one
absence proof. The test keeps one copy of each proof in the native output and
records digest references in the manifest. Both successors reuse the existing
one-period database and compiled test. The earlier H2 through H4 records and
the fixed-window CPU workload retain their original scope.

The inserted ABI values come from the recorded three-row source fixture.
These raw ledger patches run below the VM verifier with unsigned headers.
The result qualifies historical membership reads in that isolated node fixture.
Selected-network header authority and the real typed consumer remain open.

### Pruned versions and retained absence at the RPC boundary

The one-period control closes the disposable ledger and uses the original
NodeTree to prune below H6. It reopens the original managers at the same tip.
The H5 momentum remains in the ledger. Its pruned tree version returns a
JSON-RPC error from `ledger.getStateRoot` and from `ledger.getProof` for each
of the three selected Settlement keys. The retained H6 proof read succeeds
with `value: null` and the same canonical BatchEntry absence proof.

The original HTTP handler runs in memory over the existing isolated chain.
The qualifier binds the error body to the exact selection and reconstructs
the successful H6 response from the prior canonical proof and header root.
This explicit cutoff tests pruned-read behavior with the existing database
and compiled test. The configured production retention depth and the signed
devnet consumer retain their separate acceptance gates.

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
