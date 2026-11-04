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

## Bounded native JSON encoding

The native v1/v2 writer now encodes the same top-level metadata and each retained
header through one reused `encoding/json` value buffer. A separate output buffer
starts at 1 KiB for an empty window and grows with the selected header count up
to 32 KiB. This avoids assembling and indenting the entire retained array in one
JSON buffer. One metadata value, including a selected profile's source label,
can still require a larger value buffer; this is not a fixed total-memory bound.

Field order, indentation, escaping, final newline and null/empty representations
remain byte-for-byte compatible with the preceding whole-object encoder. The
global file-byte limit applies before destination writes. The existing private
temporary file, sync, close, rename and parent-directory sync protocol remains
unchanged, including cleanup after an encoding failure. No validation is removed:
mutable saves, loads and trusted resume retain their complete checks. The separate
experimental version-4 state encoder is unchanged.
Short destination writes become `io.ErrShortWrite`, including metadata values
large enough to use the output buffer's direct-write path. Even a destination
that returns a short count without an error cannot leave that path making zero
progress indefinitely.

The reason for inspecting this path was a source-pinned Go 1.25.14 darwin/arm64
profile of the existing K4096/scheduled/W6 capacity-sequence leaf at
[`2e46e91329a492dc106530c002f0b056b39e2c3d`](https://github.com/edgepillar/zenon-spv/commit/2e46e91329a492dc106530c002f0b056b39e2c3d).
It passed all 20 existing operations with race and atomic coverage instrumentation.
The leaf's elapsed diagnostic was 24.84 seconds. Sampling attributed substantial
allocation to JSON buffer growth and indentation, alongside required signature
verification and race instrumentation. CPU and allocation profiles remain separate
from representative device, dataset or network measurements.

A paired encoding-only benchmark uses the preceding whole-object encoder and
the new writer in the same executable, writing identical synthetic data to
`io.Discard`. Go 1.25.14 darwin/arm64, benchmark CPU=1, three repetitions of three
operations produced all 18 retained rows:

| Retained headers | Whole-object B/op | Bounded B/op | Whole-object allocs/op | Bounded allocs/op |
| ---: | ---: | ---: | ---: | ---: |
| 16 | 68,368 | 30,992-31,008 | 101 | 116 |
| 256 | 990,224 | 183,573 | 1,310 | 1,557 |
| 4096 | 18,103,597-18,103,642 | 2,395,506 | 20,526-20,527 | 24,598 |

The observed whole-object/bounded time ranges were 74.6-85.0 / 49.2-56.2 us/op
at 16 headers, 788.3-827.9 / 704.1-748.7 us/op at 256, and 12.36-13.03 /
11.28-11.78 ms/op at 4096. The preceding encoder prototype's 18 rows remain
retained at `99f7509e984acdb0de6960b82c444c8d02a010f0`; they include overlapping
small-input timings and the 73.3 us bounded sample. Increased allocation counts
remain explicit. These small local observations establish
reduced allocated bytes for these encodings, not a whole-CI speedup, filesystem
latency, process RSS, sustained workload budget or selected-network acceptance.

The new controls compare complete bytes with the previous `encoding/json`
whole-object encoder across all three native schema versions, 0/1/16/256/4096
headers, profile escaping, invalid UTF-8 replacement and empty/null values.
They also check unchanged input bytes, partial/short destination failures,
output-cap boundaries and the global byte limit. Existing ownership, roundtrip
and post-rename durability controls stay separate. The revised local components
completed 12 roots and 89 subtest events with the race detector, all 18 benchmark
rows, focused vet and module verification. The outer wrapper was interrupted
with actual exit -9 during later cache cleanup; its capture remains incomplete
and its outcome remains FAILURE. The source-bound component reconciliation uses
the completed phase records and retains that distinct wrapper failure. It does
not report a successful wrapper or repeat completed tests/benchmarks. Canonical
CI must still qualify each changed source and its actual artifacts; local
component evidence does not transfer a prior native run.

```sh
go test -race -count=1 -run '^(TestPersistedStateEncoding.*|TestVerifiedStateSave.*|TestSaveHeaderState_Parent.*|TestSaveLoadHeaderState_RoundTrip)$' ./internal/verify
go test -run '^$' -bench '^BenchmarkPersistedStateEncoding$' -benchtime=3x -benchmem -cpu=1 -count=3 ./internal/verify
```

The encoding comparison creates no large input/output fixture files. Its owned
module/build/test workspace is disposable; the interrupted cleanup remainder
stays held for a scoped decision. Source pins, actual phase results, all benchmark
rows and the earlier profiles remain protected evidence. Header,
producer, profile, context, native inclusion and production state-value trust
boundaries are unchanged.
