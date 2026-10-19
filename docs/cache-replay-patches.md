# Native cache replay-patch availability

This M2 component experiment reproduces startup with a missing required ledger
patch and tests a separate experimental availability preflight. It changes no
SPV acceptance path and enables no state-value claim. The selected node source is
[`digitalSloth/go-zenon@9c71ae82fc983e16f914ae085d4034030c8ebe3b`](https://github.com/digitalSloth/go-zenon/tree/9c71ae82fc983e16f914ae085d4034030c8ebe3b).

| Selection | Runtime tree | Complete build tree |
| --- | --- | --- |
| Retained intact parent control | `40cc88bb9671cef130cb87ccb3c726f7e8977299` | `79407b35b780db4d7f36c17ec085f42e5b20d197` |
| Remaining four parent cases | `40cc88bb9671cef130cb87ccb3c726f7e8977299` | `9653bd305d8c5d8ee818a06dea5c9fa956660677` |
| Required-patch preflight candidate | `0cf17322154e55ce77a4e51c834af5219d8161f3` | `09b42a6c73d98e9d79e419f78e0405d4d12bed22` |

All three complete source identities are reconstructed from pinned bytes. The
original source has 467 blobs. The parent builds have 472; the candidate has 473,
including one additional component test file. Relative to the selected parent,
the runtime replacement changes only `chain/cache.go`. Module inputs, disk format,
the cache-manager interface and the partial SMT profile remain unchanged.

## Observed startup behavior

The selected manager returns a nil patch for a missing patch row. Cache replay
passes it to `ApplyMomentum`; a momentum with account blocks then calls
`changes.Replay` and panics. Empty-content successors do not consume that patch.

The experiment primes the source's unsigned genesis and three unsigned empty
successors through height four using real disk ledger, cache and NodeTree
managers. Only one closed fixture patch row is removed. Momentum bodies and
frontier metadata remain present. Every gapped case performs two public
`Chain.Init`, query and `Stop` attempts, explicitly restores the fixture row,
then performs two more attempts. Restoration is not runtime repair.

| Fixture | Parent | Candidate |
| --- | --- | --- |
| Intact ledger, empty cache | Replay and clean reopen succeed | Same witness and final logical cache |
| Missing genesis patch, empty cache | Two recovered `Init` panics; queries refuse | Two ordinary missing-patch errors; complete logical cache unchanged |
| Missing genesis patch, current cache | Patch is not needed; startup succeeds | Same behavior |
| Missing genesis patch, cache at genesis | Replay starts after genesis; startup succeeds | Same behavior |
| Missing empty successor patch, empty cache | Empty-content patch is not needed | Same behavior |
| Exact fixture row restored | Replay and clean reopen resume | Same behavior |

All ten intended case-process exits are zero because their callers finish the
observations. That exit is never equated with successful startup. Every observed
`Stop` completes and withdraws readiness. Failed startup exposes no root, value
or proof. All final logical cache images match across both generations.

The candidate extends the existing complete-header-window preflight to check
patch availability for every replay header with nonempty content before the
first logical cache write. It also checks again during application. It does not
require historical patches outside that replay range or empty-content patches.
This is an availability check, not patch-to-ChangesHash authentication, execution
validation, complete patch-retention qualification or a transaction across later
I/O. A later application-pass failure can preserve an acknowledged prefix.

## Native controls and independent byte checks

The final candidate passed 15 race-enabled native roots, 58 test results and two
packages with no skips. Every previous 46 pass name is retained. The new controls
cover first/later/final required gaps before writes, a patch disappearing during
application, empty-content nil patches, historical/current-cache exclusions and
source read errors. Later required-patch and dynamic-gap cases use test doubles;
the real-manager required-gap case is the source genesis patch.

The [recording](../tools/gen-state-root-vectors/testdata/native-cache-replay-patches.json)
contains 260 events and 36 queries: 32 available component witnesses and four
refused queries. The portable reader decodes one shared 930,529-byte genesis
metadata fixture, including all 14,094 ordered account headers, and reconstructs
the empty successor's 218-byte metadata. It checks all three metadata puts, full
identifiers, four distinct v1 hash frames and the selected 256-level witness
model. The genesis fixture is stored once rather than copied into each case.

The stored genesis patch is larger than the raw source changes: `Manager.Add`
appends the three `SetFrontier` puts. The local qualification independently
rehashes the retained source changes followed by that metadata before comparing
the full stored length and digest. The public reader does not carry or rehash
the 10,849,399-byte source VM dump; that full augmented digest remains a recorded
native/private-byte-check observation. Complete database digests also remain
observations, not independently rebuilt stores or authenticated receipts.

Original failures remain explicit. The older probe's later faulty stored-value
comparison failed before its selected target startup, so only its completed
intact case is reused. A corrected capture fixture produced the other four
parent observations; its caller later failed during cleanup. A first candidate
test build also failed on a pointer method called on a temporary identifier,
after 18 storage controls passed and before any candidate case ran. The final
addressable-variable fixture passed all 58 controls and five cases, and its
generated workspace closed successfully. None of those failed tasks is relabeled.

```sh
python3 -I -B tools/gen-state-root-vectors/prepare_cache_replay_patches_test.py -v
python3 -I -B tools/gen-state-root-vectors/cache_replay_patch_bytes_test.py -v
python3 -I -B tools/gen-state-root-vectors/cache_replay_patch_records_test.py -v
python3 -I -B tools/gen-state-root-vectors/check_cache_replay_patches_test.py -v
python3 -I -B tools/gen-state-root-vectors/check_cache_replay_patches.py
```

The 48 portable controls cover source and binary substitutions, malformed byte
encodings, hidden panics, false readiness, leaked queries, altered cache images,
missing events, incomplete output and inflated evidence. Source-selection reuse
is limited to one serial recorded-control test class; full source bytes and the
real selection are checked before and after. Metadata decoding still executes.
Hosted checks replay the recorded Darwin ARM64 observations; they do not rebuild
or execute this reference node on Linux, macOS or Windows. Exact-head CI and
artifact qualification are separate from workflow presence.

## Resource and trust boundary

One private compiler/module cache is reused serially for the successful
candidate's race tests and ordinary build. All 75 dependency payloads for 25
linked modules come from retained verified inputs through an owned file proxy;
there is no new remote dependency acquisition. Whole-module-graph verification
remains not qualified. No closed historical cache is adopted.

The preparer starts no compiler or backend. A new native reproduction requires
an admitted private workspace, registered capture files, bounded outputs, exact
source/compiler/platform pins, retained failures and ownership-aware cleanup.
Its plan retains a 10 GiB free-space floor plus expected allocations, a 2 GiB
expected need and a 4 GiB task quota. These are admission settings, not measured
production hardware requirements. No physical APFS reclaim or pipeline peak is
claimed.

```sh
python3 -I -B tools/gen-state-root-vectors/prepare_cache_replay_patches.py plan \
  --workspace "$NEW_PRIVATE_WORKSPACE" --go "$PINNED_GO"
```

Full node service, concurrent lifecycle, live reorg, real power loss,
representative retention/churn and patch-retention guarantees remain open.
Profile agreement, authenticated activation, accepted-header/root binding,
independent review and authenticated distribution remain separate gates.
Anchor, schedule and context-pin inputs stay explicit. The consumer remains
`REFUSED`; production state-value acceptance stays disabled.
