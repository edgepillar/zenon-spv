# Short-lived patch-read snapshots

This M2 resource experiment releases the snapshots used inside two selected
LevelDB patch readers. It extends the [required replay-patch experiment](cache-replay-patches.md)
without changing SPV acceptance, disk format, dependencies or the partial SMT
profile. State-value consumers remain `REFUSED`.

The selected source is
[`digitalSloth/go-zenon@9c71ae82fc983e16f914ae085d4034030c8ebe3b`](https://github.com/digitalSloth/go-zenon/tree/9c71ae82fc983e16f914ae085d4034030c8ebe3b).
This repository carries an experimental full-file replacement and reproduction
tools. It does not modify that node repository.

| Selection | Runtime tree | Complete build tree | Blobs |
| --- | --- | --- | ---: |
| Isolated component parent | `d0f5dfb09e737a806cfc743bb6ba9ddd101ebcd6` | `90df13e378af5662f1d885a1b41b666d3629fb02` | 468 |
| Isolated snapshot candidate | `664df2f156262f056fb77f51deda10fe1e90e94d` | `6c658c226b189724286e8f78fab9e9de8f327310` | 468 |
| Previous integrated candidate | `0cf17322154e55ce77a4e51c834af5219d8161f3` | `09b42a6c73d98e9d79e419f78e0405d4d12bed22` | 473 |
| Integrated snapshot candidate | `890520349329851e2d39bd134d5643baf59531b6` | `3102dcb18c0b2e7f069be060420be67544f89b13` | 474 |

The preparer reconstructs these identities from pinned source bytes. The original
467 source blobs, earlier five runtime replacements and six additional probe/test
files retain their identities. The new runtime replacement affects only
`common/db/versioned_db.go`; one additional tagged Go test file is added.

## Behavior and ownership

`getPatch` and `getRollback` acquire a snapshot, decode a patch and return the
decoded value. In the selected parent neither helper explicitly releases its
snapshot. The dependency supplies a finalizer: this experiment demonstrates
delayed reclamation, and does **not** establish a permanent leak.

The candidate checks the snapshot acquisition error and defers `Release` before
reading or decoding. Successful, missing-row and decode-panic paths all release
their short-lived snapshot. `Get` and `Frontier` return database views with a
different lifetime; their snapshot ownership is unchanged. A failed acquisition
now propagates the underlying closed-database error instead of continuing with
a nil snapshot. That diagnostic difference is intentional and tested.

For each of two readers, the isolated parent and candidate each perform 64 reads
of a present patch, absent patch and invalid dump, under disabled and inherited
GC policies: 12 cases per generation. The integrated candidate repeats those 12
cases alongside the earlier native controls.

| Observation | Parent component | Candidate component and integrated candidate |
| --- | --- | --- |
| Live snapshots after 64 reads with GC disabled, each of six cases | 64 | 0 |
| Live snapshots after bounded explicit GC, all cases | 0 | 0 |
| Present patch | Same 17-byte put/delete dump | Same |
| Missing patch | Nil | Same |
| Invalid dump | Recovered decode panic | Same |
| Ordered logical database before/after reads | Equal | Equal |

Inherited-GC parent counts depend on collection timing and are retained as
observations. Disabling GC isolates ownership behavior; it is not a realistic
production load. The candidate additionally keeps returned patches across a
database rewrite, collection and manager `Stop`, then verifies both `Dump` and
`Replay`. A separate closed-handle control checks both acquisition-error paths.

## Execution and portable checks

The recorded reference execution used Go 1.25.14 on Darwin ARM64 with the race
detector. The isolated parent produced 13 passing test names; the isolated
candidate produced 15. The integrated candidate produced 73 passing names from
18 roots across three packages, retaining every previous 58 name. Its five real
public `Chain.Init`/`Stop` cases preserve the earlier candidate's exact stdout
bytes, including 130 events, zero `Init` panics, two expected missing-patch
prewrite refusals and explicit fixture restoration. Exit zero is not equated
with successful initialization.

A separate run selected all 22 original DB roots and produced 27 passing names
with no original test-body changes or skips. It includes the source's 3,000,000
stress puts. The random seed was not captured, so that exact random stress vector
is not reproducible. The supervised run took approximately 45.21 seconds;
Darwin `time -l` reported maximum RSS of 2,113,699,840 bytes. That report is neither
an aggregate concurrent process-tree peak nor a representative production budget.

The first parent recording parser rejected four observations because the node's
diagnostic logger put complete JSON rows immediately after a trace suffix. The
original native command completed with exit zero; its caller remains failed.
The retained bytes were reconciled without rerunning or rewriting that command.
Failures, raw captures, source and binary pins remain protected separately.

The bounded [portable reader](../tools/gen-state-root-vectors/check_patch_snapshot_lifetime.py)
checks the 36 recorded observation rows, test inventories, acquisition/return
controls and source identities. It independently constructs the 17-byte patch
dump and the six reader/state database models using ordered, eight-byte length
frames. It rejects boolean counters, substituted namespaces, changed bytes,
incomplete commands, missing/extra/failed/skipped tests and inflated acceptance.
The five unchanged startup payloads are referenced from the prior pinned corpus
by digest rather than copied into this recording again.

```sh
python3 -I -B tools/gen-state-root-vectors/prepare_patch_snapshot_lifetime_test.py -v
python3 -I -B tools/gen-state-root-vectors/check_patch_snapshot_lifetime_test.py -v
python3 -I -B tools/gen-state-root-vectors/check_patch_snapshot_lifetime.py
```

These 37 portable controls and the positive reader start no compiler, reference
backend, service or transport. Hosted checks replay the recorded Darwin evidence;
workflow definitions alone do not establish a successful hosted run. Hashes bind
published bytes and projections, not authenticated private execution provenance.

## Reproduction and resource boundary

Preparation copies verified original source into a **new** caller-owned workspace,
applies the selected replacements, adds pinned tests and seals a plan. It starts
no compiler or backend. Verification checks the complete 474-file inventory,
bytes, modes and plan. An existing destination is refused.

```sh
python3 -I -B tools/gen-state-root-vectors/prepare_patch_snapshot_lifetime.py plan \
  --workspace "$NEW_PRIVATE_WORKSPACE" --go "$PINNED_GO"
python3 -I -B tools/gen-state-root-vectors/prepare_patch_snapshot_lifetime.py prepare \
  --node-source "$VERIFIED_ORIGINAL_NODE_SOURCE" \
  --workspace "$NEW_PRIVATE_WORKSPACE" --go "$PINNED_GO"
python3 -I -B tools/gen-state-root-vectors/prepare_patch_snapshot_lifetime.py verify \
  --workspace "$NEW_PRIVATE_WORKSPACE" --go "$PINNED_GO"
```

Before executing the plan, the caller must admit storage, register capture and
case namespaces, select `SPV_SNAPSHOT_CASE_ROOT` and
`SPV_EXPECT_PATCH_SNAPSHOT_RELEASE=true` for the tagged snapshot test, supervise
bounded outputs and retain actual exits. Original DB tests and the ordinary
startup probe have separate commands and lifetimes; the ordinary probe's source
pin is preserved separately from the snapshot probe. Close and clean only owned
disposable work, retaining evidence on failure or interruption.

The plan preserves a 10 GiB free-space floor plus expected allocations, a 2 GiB
expected need and a 4 GiB task quota. Those admission settings are configurable
operation limits, not production hardware requirements. The recorded execution
reused 75 verified dependency payloads for 25 linked modules with no new remote
dependency transport. Whole-module-graph verification remains unqualified. It
does not adopt or clean a historical cache or promise physical APFS reclaim.

Full node recovery, live reorg, concurrent lifecycle, representative retention
and resource workloads remain open. Profile agreement, activation, authenticated
accepted-header/root binding, independent review and authenticated distribution
are separate gates. This change enables no state-value acceptance.
