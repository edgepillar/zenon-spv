# Source-node parent-snapshot slot capture

A finite source oracle now records six producer lookups against the exact
selected genesis H1 snapshot. It uses the original node's normal consensus
defaults: 10-second slots, 30 slots per tick, RandCount 15, and ZNN delegation
weight. The three genesis pillars are not substituted for NodeCount.

This is D0 conformance preparation. It creates neither an accepting SPV
ProducerSchedule nor network height assignments. It does not authenticate
elections, fork choice, a live network or a v3 activation boundary.

## Source and execution

The node and exact chain-69 configuration are the same pins as the
[source-genesis record](selected-devnet-genesis.md):
digitalSloth/go-zenon revision
938fca3b7787da86827a5eb63371509b36e14761, tree
f3b7947d2267ebdb806f18ff0c02bba5bffae9c4. The
[recorded corpus](../internal/testdata/conformance/selected-parent-slots.json)
contains original consensus file/blob pins, helper digests, command/output
references, used-module integrity references and the complete projected trace.

Only an [added local adapter](../tools/gen-state-root-vectors/parent-schedule-adapter.go.txt)
and an [external test harness](../tools/gen-state-root-vectors/parent-schedule-capture_test.go.txt)
were injected into a new owned build view. All 484 original files remained
byte-identical. The split avoids the original genesis -> VM -> consensus import
cycle; the adapter is not an upstream production API.

The harness constructs the original source genesis, initializes real disk
ledger/cache managers once, and selects its full height/hash identity. It calls
the original internal election lookup with that selected momentum-store view,
rather than substituting the current ambient frontier. An ephemeral in-memory
consensus-result cache is separate from the snapshot. It records the proof time,
proof block, tick, slot, producer address and pillar name for each query.

The one Go 1.25.14 darwin/arm64 CGO test execution returned actual exit 0 with
complete output: ten refusal subtests and the parent test passed. Its 25 used
modules matched the original go.sum through independent ZIP and expanded-file
h1 checks. The full historical module graph remains NOT_ESTABLISHED.

The surrounding controller later exited 1 while removing read-only temporary
Go module directories. Its original FAILURE and cleanup HOLD remain preserved,
separately from the completed node test. Reading and qualifying the saved output
did not repeat native execution. These digest references are integrity links,
not authenticated distribution or independent review.

## Queries and refusals

The snapshot is unsigned v1 H1, momentum hash
fab7609bae7fd78eb7d2b0d4a5023832f1a6730921b862f2415da25524698dc9,
at genesis timestamp 1739923200. Query offsets are 10, 20, 290, 300, 590 and
600 seconds. They cross ticks 0, 1 and 2 while the selected ledger stays at H1.

For tick < 2, the original proof time is genesis + 1 second. Otherwise it is
genesis + (tick - 1) * 300 seconds. The proof block remains H1 in this empty
source snapshot, including the tick-2 lookup. No higher-frontier recovery,
fork, evolving delegation set or authenticated seed transition was executed.

The helper refuses foreign parent hashes/heights, pre-genesis and off-slot
timestamps, unordered or duplicate queries, more than 64 queries, an empty
request, a timestamp beyond its explicit ten-year work bound, and a valid
prefix followed by an invalid tail. Refusals return no partial row set.
The ten-year limit is a local fixture work bound, not a protocol rule.

Chain.Start and consensus.Start are never called. No signed momentum, wallet,
transaction, network request or live service is created. Chain.Stop succeeds
and the frontier retains its original H1 identity.

## Small independent replay

The standard-library Python reader independently checks integer types and
widths, exact parent/proof identities, query order, tick and slot arithmetic,
proof times, normal parameters, genesis-pillar membership, bounded shapes and
scope flags. A digest binds the actual observed ordering to the node trace.
The reader does not independently reimplement election ordering or rebuild
genesis state.

A different real genesis producer can satisfy membership and timing checks;
it must still be refused if it differs from the recorded node output. Regression
controls exercise this distinction, malformed inputs and attempted authority
upgrades.

    python -I -B tools/gen-state-root-vectors/check_parent_snapshot_slots_test.py -v
    python -I -B tools/gen-state-root-vectors/check_parent_snapshot_slots.py

Linux/macOS/Windows CI runs these small replays. It does not rerun the source
node, create databases, download its modules or qualify node execution on those
platforms.

To reproduce the node capture separately, prepare a new owned copy of the exact
node and verified dependencies. Add the adapter as
consensus/spv_parent_schedule_adapter.go and the external harness as
consensus/spv_parent_schedule_capture_test.go. With CGO enabled and network
module fetching disabled, run:

    go test -mod=readonly -p 1 -json -count=1 -timeout=60s -run '^TestSPVParentSnapshotProducerCapture$' ./consensus

Do not install the adapter into a deployed node or point the harness at existing
data. Retain actual exit/completeness, source/dependency bindings and failure
records. Account for Go's read-only module directories when closing a newly
owned temporary workspace; a failed cleanup does not authorize removal of
unknown files or alteration of protected evidence.

## Remaining gates

The [query contract](batch-entry-query-contract.md) still needs the actual
selected network identity, explicit anchor/provenance, finite schedule/profile
inputs and one positive typed BatchEntry witness/consumer result. The H1 source
oracle supplies no height-2 anchor and does not capture the first chain-69 v3
momentum. Production state proofs, canonicality and consensus finality remain
unestablished.
