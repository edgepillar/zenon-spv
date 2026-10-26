# Source-genesis ledger export compatibility

One local control compares the unchanged
[`go-zenon@9c71ae8`](https://github.com/digitalSloth/go-zenon/tree/9c71ae82fc983e16f914ae085d4034030c8ebe3b)
logical frontier with the ordinary read-only exporter, its completion consumer,
stream transport and independent inventory. All components matched the same
retained bytes. This is source-derived genesis data, not a collected or accepted
representative R1 dataset.

## Selected source and operations

The original node tree is `d0f5dfb09e737a806cfc743bb6ba9ddd101ebcd6`.
Its 467 source blobs were checked against
[`node-recovery-9c71-source-pins.json`](../tools/gen-state-root-vectors/node-recovery-9c71-source-pins.json).
The older `source-pins.json` and `node-recovery-source-pins.json` select other
revisions and are not substitutes for this input.

The [separate probe](../tools/gen-state-root-vectors/source_genesis_frontier.go)
was added to an owned build view without changing node implementation files.
One ordinary Go 1.25.14 Darwin ARM64 executable called `Chain.Init`, read the
real ledger manager's logical frontier and called `Stop`. The source-selected
genesis identifier is height **1**, hash
`9e204601d1b7b1427fe12bc82622e610d8a6ad43c40abf020eb66e538bb8eeb0`.
The probe also matched the source genesis patch's 10,849,399 bytes and SHA-256
`a222aac55304b1a489d395235c61af4182ac08b887d24d0c3f654aa402f35e75`.

It used the node library's original `leveldb.Batch.Put/Dump` encoder to hash
each ordered final logical record without writing a second expected stream.
The iterator was released before manager closure. `Chain.Start`, node/P2P/RPC,
wallet, signing and broadcast were not selected. The unsigned v1 genesis has a
zero header StateRoot; this does not establish accepted-header state proofs.

The node source and executable, exporter executable, dependency inputs, actual
exits, full outputs, file images and failed controller outcomes remain bound in
protected records. Declared revision strings and an unsigned digest do not
authenticate their own origin or qualify a release.

## Matched stream

| Measurement | Observed control value |
| --- | ---: |
| Final logical records | 103,824 |
| Canonical put-stream bytes | 11,779,928 |
| Typed balance records | 14,091 |
| Contract storage records | 5,166 |
| Typed present-empty / raw zero32 / values over 32 bytes | 0 / 0 / 0 |
| Fixed 1 MiB transport chunks, including the final short chunk | 12 |

The node's independent logical-stream hash, the captured exporter output and
the independently parsed inventory all matched SHA-256
`d0ffb31dece29d9d8459fbcf5cf542eb395712f5a1f906cd7f5409578f70a6fb`.
All family counts and put-wire byte totals also reconciled. Family record counts
are in the size measurements such as `key_bytes.count`; there is no direct
family-level `records` field. Scope declaration strings are retained alongside
the false authority flags.

The stream's first 42 bytes independently match the source-genesis identifier:

```text
01 01 00 26 0a 22 0a 20
9e204601d1b7b1427fe12bc82622e610d8a6ad43c40abf020eb66e538bb8eeb0
10 01
```

These are a put record, one-byte logical key `00`, a 38-byte protobuf value,
the selected hash and height 1. The physical existence marker is not part of
that exported value. The small exporter controls retain this literal separately
from their existing height-3000 fixture and protobuf width boundaries.

## Reuse and actual completion

The producer completed with actual exit 0. The selected node writes its fixed
`Initialized NoM. Height: 1, Hash: ...` line before the probe's JSON record.
Retain the whole stdout. A controller must match the exact source-selected
banner and then decode one strict JSON value; it must not discard arbitrary
prefix lines or infer completion from the JSON alone. Help, failed exits and
incomplete captures are not a completed producer result.

The initial controller expected JSON without that banner and closed FAILURE.
Its completed native output and all closed fixture files were preserved. A
separate controller restored only the ledger's nine files, 12,155,691 logical
bytes, as independent APFS clones. It restored neither the cache nor state tree.
The copy has new file identities; no historical ownership metadata was rebound.

The ordinary exporter then completed with actual exit 0 and matched the node's
independent count, byte count and hash. The input file image was checked
immediately after export. The completion consumer, transport describe, transport
verify and independent inventory each completed with actual exit 0 over the
same retained raw CAS object. The binary input feeder's actual child exits,
input counts, hashes and EOF records were reconciled separately.

That controller subsequently closed FAILURE after looking for a non-existent
family-level `records` field. Both failed task outcomes remain unchanged. A
separate qualification read the protected completed outputs after task closure,
checked the actual nested counts and exact pinned scope schemas, and matched
the complete pipeline. It repeated no producer, compiler or transfer. The final
private qualification record is 3,596 bytes, SHA-256
`e59d6f84d02d71899c59fcce59133409149855c19715d9490b4ea6cc819564bd`.
Its hash is an integrity reference, not authenticated distribution.

No chunk files, combined manifest/payload file or additional payload ZIP was
created. The one raw object was reused throughout. Only the new tasks' declared
scratch and registered aliases were removed after terminal process checks;
source data, reports and protected evidence remain retained.

The original native task stopped before its planned post-build module-cache
verification. Its selected dependency payloads had been checked against source
`go.sum` h1 values before compilation. Do not report the unexecuted post-build
check as passed or treat this as reproducible/authenticated node distribution.

## Reproduce under an owned controller

Select the exact original node source, full source pins, Go toolchain, probe
source and resource limits before building. The controller must supply its own
registered cache/output paths and an existing empty physical control directory.
For example, from the selected owned node module:

```sh
go build -mod=readonly -p=2 -trimpath -buildvcs=false \
  -tags candidate_source_genesis_frontier -o "$FRONTIER_PROBE" \
  "$SPV_SOURCE/tools/gen-state-root-vectors/source_genesis_frontier.go"
GOMAXPROCS=2 "$FRONTIER_PROBE" --root "$EMPTY_OWNED_CONTROL_DIRECTORY"
```

The fixed probe limits are 64 MiB of logical put bytes, two million records,
1,024-byte keys and 1 MiB values. These are control limits, not protocol or
total-process RSS bounds. The source-genesis construction and storage backend
have their own allocations. Preserve actual failed or interrupted attempts.

Require completed producer exit 0 before treating its generated ledger as a
closed input. Follow the [exporter procedure](../tools/ledger-export/README.md)
and [transport procedure](../tools/ledger-transport/README.md) with separately
retained source/consistency provenance. Preserve one raw stream plus small
receipts by reference, rather than another database archive or stdout copy.

## Storage-manager advance and rollback

The separate [storage-only probe](../tools/gen-state-root-vectors/source_manager_frontier.go)
extends this comparison through the selected original `db.Manager.Add` and
`Pop` implementation. It uses one independent owned copy of only the nine
retained ledger files. It does not rerun `Chain.Init` or create another genesis,
cache or state tree. The controller retains the original files and stream as
inputs; it must not point the probe at a live or historical source database.

The fixed sequence is an initial read, present-empty Put, replacement with
32 zero bytes, Delete, and three Pops back to the original frontier. One
synthetic typed balance key is selected before execution:
`03 || ee[20] || 03 || dd[10]`. The three new identifiers are SHA-256 of
`zenon-source-manager-control/v1/empty`, `/zero` and `/delete` at heights 2,
3 and 4. Their stored commit payloads are explicit storage-control strings.
They are **not validated network Momentums**. The storage manager accepting
these commits says nothing about consensus, a valid header or an activated
StateRoot.

Before mutation, the controller predicts each entire ordered put stream by
merging a small literal metadata/key overlay with the retained baseline stream.
It keeps no full key map or second expected payload. The expected frontier
protobuf, hash-to-height index and height-to-payload index are selected from the
original source layout independently of `Manager.Add`. The probe separately
hashes actual logical records with the original goleveldb encoder. After each
writer Stop, a fresh read-only manager reopens and checks the same full
identifier, selected key state, counts and digest. Only then can the ordinary
exporter, completion helper, transport and inventory consume that closed copy.

The completed local Darwin ARM64 comparison matched all seven snapshots. The
four independently selected logical states were:

| State | Records | Put-wire bytes | Extra typed key |
| --- | ---: | ---: | --- |
| Original source genesis | 103,824 | 11,779,928 | Absent |
| Empty Put | 103,827 | 11,780,049 | Present-empty |
| Zero32 replacement | 103,829 | 11,780,166 | Present, 32 zero bytes |
| Delete | 103,830 | 11,780,186 | Absent |

Their SHA-256 values, in that order, are:

```text
d0ffb31dece29d9d8459fbcf5cf542eb395712f5a1f906cd7f5409578f70a6fb
6f30ae44fa31f481760ba37c89220b2476244b77c969aa2543b5a59baeb96f7b
741210b8e7598d8a0875d244aa734cd3d98b541c516c59a34f8c532ae496b99f
cc248864214b3dc1c78af8d25161d05740a9d527c31b7a9d3796b90f9f330db6
```

The three Pops matched the earlier zero32, present-empty and original hashes
exactly. The final raw stream reused the original CAS object. Physical
tombstones omitted from the iterator fold were 0, 0, 0, 1, 2, 4 and 7 across
the seven snapshots. Typed balance counts were 14,091 or 14,092 as selected;
contract storage stayed at 5,166. Completion, transport and inventory all
matched each separately selected closed snapshot.

In this source, `enableDeleteIterator.Next` also enumerates physical tombstones,
and `Value` returns an empty slice for both a tombstone and a present-empty
value. Iterator values alone are therefore insufficient to select final logical
records. The probe reconciles an empty iterator value with `Get` and `Has` on
the same immutable view, omits only a confirmed absent row and retains a
confirmed present-empty row. Its regression uses the original memory backend
and independent literal put bytes. The ordinary exporter independently checks
the physical existence marker. This does not change the candidate L1 applier's
separate empty-Put-to-delete rule or settle the protocol's value-width rules.

The first probe counted iterator tombstones as present-empty and failed after
the Delete. Its failed actual exit, closed files and held workspace remain
preserved. A regression against that retained old probe fails specifically on
the deleted-row case; the corrected probe passes all five test events with no
skips. Nine already completed ordinary-exporter test events, vet and offline
module verification were reused after checking identical Go/module inputs.
They were not rerun to repair controller bookkeeping. The final source-control
task retains its expected red exit 1 as FAILURE; all other 49 commands completed
with actual exit 0 and complete capture. A separate post-closure qualification
reconciles these outcomes without changing them.

The corrected task's new generated workspace was removed after terminal process
and identity checks. The earlier held workspace was not changed. No storage
manager implementation or historical ownership record was changed for this
comparison. The private, unsigned local qualification has SHA-256
`df33caaf42205c97eb0eb771ce6ca024c2de8b82b7c5c8eea3457e56356da11f`;
it references the complete 80,986-byte native report. These integrity references
do not authenticate distribution or qualify another native platform. The
selected node's 467 original files remain unchanged; its whole-module post-build
verification was not executed. Served dependency `.mod` and source ZIP payloads
were checked against the source `go.sum` before use; `.info` metadata retains
its separate captured digest and version checks.

The probe requires an existing physical root containing exactly `ledger/` and
a regular `SOURCE_MANAGER_CONTROL` file with bytes
`zenon-source-manager-control/v1\n`. This marker is an explicit control guard,
not proof of ownership, isolation, consistency or provenance. The outer
controller must establish those properties, reject links/hard links and protect
the original inputs. It selects canonical step numbers 0 through 6 and separate
before/after digests; a help exit is still an UNKNOWN observation.

From the selected unchanged owned node module, build only the probe:

```sh
go build -mod=readonly -p=2 -trimpath -buildvcs=false \
  -tags candidate_source_manager_frontier -o "$MANAGER_PROBE" \
  "$SPV_SOURCE/tools/gen-state-root-vectors/source_manager_frontier.go"
GOMAXPROCS=2 "$MANAGER_PROBE" --root "$OWNED_CONTROL_ROOT" --step "$STEP" \
  --expect-input-sha256 "$EXPECTED_BEFORE" \
  --expect-output-sha256 "$EXPECTED_AFTER"
```

Run its small original-backend regression from that same owned node module:

```sh
go test -mod=readonly -p=2 -count=1 -tags candidate_source_manager_frontier \
  "$SPV_SOURCE/tools/gen-state-root-vectors/source_manager_frontier.go" \
  "$SPV_SOURCE/tools/gen-state-root-vectors/source_manager_frontier_test.go"
```

Preserve every actual command, completed or incomplete output, expected stream
selection and file image. Reuse one CAS object per digest: rollback should
return to already retained logical streams, rather than require a database ZIP
or another expected-output file. A failed/interrupted mutation is UNKNOWN;
do not implicitly retry or qualify it using a success-looking JSON receipt.

The exporter's ordinary CLI regression separately uses seven snapshots of one
small physical fixture in `TestCompiledCLI/closed-frontier-transitions`, sharing
the existing compiled executable. Those portable controls are distinct from executing the
original node manager. Keep each actual platform's native execution and skip
ledger separate.

## Remaining gates

This control establishes finite source-layout and workflow compatibility for
one genesis sample. Representative key counts/churn, hardware budgets, import,
retention/reorg/interruption and activation still need their declared inputs
and actual measurements. The partial-SMT agreement, accepted v3 header/context,
excluded-state provenance, independent review and authenticated distribution
remain separate roadmap exits. Existing runtime state-value refusal is unchanged.
Raw-ledger storage `Pop` does not qualify derived SMT root identity, retention,
pruning or full node recovery.
