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

## Remaining gates

This control establishes finite source-layout and workflow compatibility for
one genesis sample. Representative key counts/churn, hardware budgets, import,
retention/reorg/interruption and activation still need their declared inputs
and actual measurements. The partial-SMT agreement, accepted v3 header/context,
excluded-state provenance, independent review and authenticated distribution
remain separate roadmap exits. Existing runtime state-value refusal is unchanged.
