# Experimental terminal state-tree Stop

This M2 component proposal makes Stop terminal for one state-tree instance and
serializes background-build admission. It extends the
[hash-bound retained-version proposal](state-tree-hash-bound-versions.md).
It does not enable production v3 headers or state-value proof acceptance.

## Source and changes

The complete selected upstream source remains
[digitalSloth/go-zenon at 33d7d1e](https://github.com/digitalSloth/go-zenon/tree/33d7d1ee1b6a915c40aea196e2a10f1e893d171f),
tree `40d71efb7e462d5bbd0f27d83ed7588e121c3cb6`, with 439 pinned blobs.
The parent identity proposal has derived tree
`28c9eec1156633836357028e16a3958edbc635c4`.
The new [patch descriptor](../tools/gen-state-root-vectors/lifecycle-stop-patch.json)
changes only `chain/state_tree.go`. Complete-file before/after hashes, unique
replacements and their inverse bind derived tree
`d3d9215bc9ea23b2e700aad53ebb23d4bdea3428`.
These are uncommitted experimental node trees, not upstream commits.

The parent can open and become ready after an initial Stop has consumed its
one-time close operation. A subsequent Stop then leaves that new handle open.
A Stop waiting for the component changes lock also leaves the old ready flag
visible to new reads. Two delayed build launches can snapshot the same previous
worker and publish new workers after Stop has already returned.

The proposal checks the closed quit channel before opening or catching up,
makes public readiness and reads refuse once stop intent is visible, and checks
stop intent before update/truncate work. A separate launch mutex serializes
previous-worker joining and publication. Stop closes quit before waiting for
that mutex, captures the current worker without holding the changes lock while
joining it, clears readiness and the root memo, then closes the backend.
A stopped instance requires replacement; its quit channel and one-time Stop are
never reset. An already admitted ComputeStateRoot can finish while Stop waits
for its changes lock.

This adds no disk format, SMT profile, migration or header-acceptance change.
The parent's experimental disk marker 3 remains distinct from Momentum version 3.

## Controlled observations

The recorded local comparison runs actual state-tree Init/Stop, disk NodeTree
reads and a gated ComputeStateRoot callback against fresh small LevelDB data.
It uses six deliberately selected scenarios per variant:

| Scenario | Selected observation |
| --- | --- |
| Stop before Init | The parent reopens; the proposal returns the terminal stopped error without opening. |
| Init before Stop | Both close; reinitialization returns database-closed in the parent and stopped in the proposal. |
| Stop waiting for the changes lock | New parent root/proof reads still succeed; proposed reads refuse. |
| Init waiting on the manager frontier | Parent catch-up folds after stop intent; the proposal refuses before catch-up work. |
| Compute already admitted | Both finish that compute; proposed new reads refuse during the wait. |
| Two held build launches | Parent publishes two controlled workers after Stop; the proposal publishes neither. |

Each paired generation records 14 Init calls, 14 Stop calls, six build-launch
calls, 34 phase observations, 82 selected read observations and 46 complete sorted
logical record snapshots, including clean backend reopens.
The independent Python model selects the schedule outcomes and constructs sparse
roots, proofs, compressed records and refcounts before the first backend run.
Actual observations matched that sealed expectation.

Each variant was compiled once with Go 1.25.14, CGO and the race detector on
darwin/arm64, using a shared private compiler/module cache and offline dependency
proxy. Each compiled binary ran two fresh complete generations. Source,
toolchain, dependency ZIP and binary pins, actual exits and complete output are
retained separately. The temporary compiler and database directories closed.

Three declared test-only checkpoints control launch entry, the previous-worker
snapshot and the claimed worker before its loop. They are injected separately
from the uninstrumented proposal tree. The baseline and proposal use explicit
variant-specific barriers; this is not a claim that arbitrary schedules match.
Every controlled worker is joined by its own exit channel before teardown.
The parent Stop-before-Init case explicitly records the still-open backend and
the additional harness close needed to release that owned test database.

The selected workers execute no background build batch. No Chain.Start, full
node, upstream test suite, network, RPC, wallet, signing or transaction runs.
The new update/truncate stop guards receive source and compilation checks; the
six cases do not directly execute those two methods. Race-detector success for
these cases does not qualify all production interleavings, live builds, storage
faults, physical crash recovery or realistic retention/resource budgets.

Thirty adverse controls bind the closed case inventory, exact types, readiness,
quit state, errors, callbacks, worker counts, records, proofs, source pins and
scope. Linux, macOS and Windows CI check the recorded corpus and these controls.
They do not rebuild or rerun the local reference node experiment.

## Reproduction

Select the full pinned source and a new caller-owned, quota-accounted workspace:

```sh
python3 -I -B tools/gen-state-root-vectors/prepare_lifecycle_stop.py \
  --node-source NODE_SOURCE --workspace NEW_OWNED_WORKSPACE \
  --variant monotonic-stop --go SELECTED_GO_1_25
```

Prepare the hash-bound parent in another new workspace. Inspect the returned
source inventory, checkpoint hashes, explicit six-file upstream-test compiler
overlay, module bytes, race-build arguments and required ZENON_STOP_VARIANT.
Only the new lifecycle root test is selected; the parent identity probe is
compiled for its fixture helpers and its own root test is not executed here.
Run returned commands through the approved bounded storage/process supervisor
with private caches. The preparer downloads, executes, adopts and cleans nothing.

```sh
python3 -I -B tools/gen-state-root-vectors/check_lifecycle_stop_test.py -v
python3 -I -B tools/gen-state-root-vectors/check_lifecycle_stop.py
```

The checker is a bounded recorded-data reader; it starts no node or subprocess.
Historical source selectors, records and manifests remain unchanged. All
state-value consumer results stay `REFUSED`. Agreed profile/activation,
authenticated header/root provenance, real advancing consumer inputs,
representative node/resource qualification, independent review and authenticated
distribution remain external acceptance gates.

