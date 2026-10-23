# Owned state persistence

`VerifiedState.Save` reuses the validation established when its privately owned,
immutable window was constructed, extended or resumed. It writes through the
same bounded atomic writer as `SaveHeaderState`, without repeating the retained
window's hashes and signatures on every save.

`SaveHeaderState` still validates every caller-owned window before writing.
`LoadHeaderState` and trusted resume still validate the complete saved window
before any truncation. Detached snapshots and header views cannot change the
data used by the owned saver. A zero handle returns `ErrUninitializedState`.

The shared writer retains the existing encoding and byte limit, private
temporary file, file sync, close, rename and parent-directory sync behavior.
Windows retains its existing replacement and durability limits. Callers still
need exclusive ownership of the selected state path across load, verify and
save. Matching saved bytes do not authenticate their source or recover evicted
history.

## Measured cost

The selected baseline is
[`2ef70f7fa10a79a1f3431a65b4d1801a9b982a52`](https://github.com/edgepillar/zenon-spv/commit/2ef70f7fa10a79a1f3431a65b4d1801a9b982a52).
A local Go 1.25.14 run on Darwin arm64, with the race detector and atomic
coverage, spent 220 seconds in `TestRetainedCapacitySequenceModel`. Its 18 cases
keep K=16, 256 and 4096, all three profile/schedule modes, both W selections and
20 composed operations per case.

CPU sampling of its existing K=4096/v1/W=6 case attributed 5.39 seconds of
39.59 sampled CPU seconds to revalidation inside the saver. This selected
instrumented observation supplied the reason to reuse owned validation.

The new benchmark supplies the same private immutable fixture directly to the
public mutable-state validator and to the owned method. The control matches the
old `VerifiedState.Save` call shape without adding a `Snapshot` allocation.
Both methods still encode and write the complete file. Three one-operation
samples per method/capacity, with benchmark CPU=1, produced these local medians:

| K | Mutable-state validation and save | Owned save | Complete file bytes |
| --- | ---: | ---: | ---: |
| 16 | 26.09 ms | 15.28 ms | 12,688 |
| 4096 | 2,023.95 ms | 197.84 ms | 3,198,287 |

Before the change, the owned K=4096 method's median was 2,066.68 ms. The unchanged
capacity model took 152.69 seconds in the changed local run. These are selected
local observations with race/coverage overhead, filesystem syncs and a small
sample count. They do not establish a universal ratio, production latency or a
hosted-CI speed guarantee. Serialized size is unchanged.

## Compatibility controls

The source-bound local comparison retains eight complete serialized byte pins
from before the runtime change: empty legacy state, legacy v1 and profiled v1/v2,
explicit retention with and without a profile/schedule, trusted resume and
resized resume. Every byte pin and all benchmark output-file pins matched.

Five new test roots produce 21 named passes. They also check detached-view
mutation, malformed mutable input preserving an existing file, zero handles,
writer failures and concurrent saves to separately owned paths. The existing
sequence, capacity, persistence and ownership tests remain unchanged.

The changed local managed-workspace invocation passed 234 verifier roots with
628 named results and 119 syncer results, plus full repository vet and lint.
Its two existing transient file-type controls were excluded only from that local
invocation; complete canonical CI continues to execute them. A local post-reader
initially rejected one valid benchmark row split across Go JSON `Output` events.
Reconciliation reconstructed the bounded ordered output with 14 parser controls
and retained the failed parent record. Native tests and benchmarks were not
repeated for that reader correction.

Reproduction commands include the complete filesystem controls:

```sh
go test -race -count=1 ./internal/verify ./internal/syncer
go test -race -count=1 -run '^TestRetainedCapacitySequenceModel$' ./internal/verify
go test -race -covermode=atomic -cover -count=1 -json -run '^TestVerifiedStateSave' ./internal/verify
go test -race -covermode=atomic -cover -run '^$' -bench '^BenchmarkOwnedStatePersistence/' -benchtime=1x -benchmem -cpu=1 -count=3 -json ./internal/verify
```

The dedicated CI controls check the five roots and all 12 benchmark rows on
Linux, macOS Intel and Windows, in addition to the existing complete package
tests. Qualify actual exact-source runs and artifact contents before merging;
the workflow source alone is not execution evidence.

This persistence change supplies no new verification guarantee. Anchor, profile,
schedule, context-pin, accepted-header and state-value boundaries remain as
defined by the [verification contract](verification-contract.md) and
[native roadmap](native-roadmap.md). Independent review and authenticated
distribution remain separate release requirements.
