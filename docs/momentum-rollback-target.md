# Momentum rollback target preflight

This M2 experiment prevents a missing ledger rollback target from causing a nil
pointer panic. It extends the [snapshot candidate](patch-snapshot-lifetime.md)
with one experimental replacement in `chain/momentum_pool.go`. It changes no
SPV acceptance, dependency, disk format or SMT profile. State-value consumers
remain `REFUSED`.

The selected reference is
[`digitalSloth/go-zenon@9c71ae82fc983e16f914ae085d4034030c8ebe3b`](https://github.com/digitalSloth/go-zenon/tree/9c71ae82fc983e16f914ae085d4034030c8ebe3b).
The experiment is carried in this repository; the node repository is unchanged.

| Selection | Runtime tree | Complete build tree | Blobs |
| --- | --- | --- | ---: |
| Ordinary parent probe | `890520349329851e2d39bd134d5643baf59531b6` | `f37671741ec343600b5eb336fd830b3625ee7ce5` | 468 |
| Ordinary candidate probe | `cac9fa0446b0372ca37e9b15b0be2276f6d33cdf` | `3d84ab1bdcfc9ae823c71086a1ef37f67be199e1` | 468 |
| Candidate unit controls | `cac9fa0446b0372ca37e9b15b0be2276f6d33cdf` | `35f941e588e8cd784bac5d1c62a2000eee38dc5f` | 468 |

Each build has the selected 467 runtime files plus **one** additional source.
The ordinary probe and unit tests have distinct build trees. Earlier snapshot,
cache and recovery runtime changes remain present; their additional test files
are not silently included in these focused builds.

## Failure and change

The selected height lookup returns `(nil, nil)` when the momentum is absent.
`RollbackTo` then reads `momentum.Hash`. The candidate checks for nil and returns
an explicit missing-target error before any pop. It also compares the complete
hash/height identifier, retaining the existing mismatch error. Lookup errors
remain unchanged. The actual pop loop, listeners and partial-pop uncertainty
classification are unchanged.

Two ordinary Go binaries exercised the public `MomentumPool` with a real
disk-backed manager. Each committed the source's embedded unsigned genesis and
a locally constructed unsigned second momentum. These are controlled ledger
inputs, not signature- or consensus-validated network blocks.

| Call | Parent | Candidate |
| --- | --- | --- |
| Missing height zero, above frontier or maximum uint64 | Recovered API panic | Missing-target error |
| Removed height after rollback | Recovered API panic | Missing-target error |
| Nil locker | Existing error | Same |
| Wrong hash at current height | Identifier mismatch | Same |
| Matching frontier | Successful no-op | Same |
| Valid one-step rollback | Returns to genesis; one delete callback | Same |
| Close and reopen manager | Genesis image; removed height absent | Same |

The probes recover API panics for explicit observation. **Both processes exit
zero**, while the parent records four API panics and the candidate records zero.
The invalid calls preserve the current ordered logical image and callback counts.
Both valid rollback paths produce the initial genesis image again, including
after closing and reopening the manager. This does not qualify power-loss
durability, multi-step atomicity, concurrent lifecycle or a live reorg.

The delete-aware iterator can expose nil deletion markers. The logical image
omits those markers and retains non-nil empty values. An independent one-row
memory control and Python length-frame digest check this distinction. The first
observer incorrectly counted deletion markers and failed its own assertion
before emitting the valid rollback post-image. Its parent command exited two;
the candidate was not run. That attempt and its raw outputs remain a failure,
separate from the corrected experiment.

## Recorded evidence and checks

The native reference execution used Go 1.25.14 on Darwin ARM64. Three new test
roots cover preflight, a controlled same-hash/wrong-height metadata fixture and
lookup-error propagation. Two existing roots check the distinction between the
first-pop failure and a failure after mutation. The focused run produced 11
passing test names from five roots, with no skips or failures. This run did not
select the race detector or repeat the earlier three-million-put DB stress run.

The bounded [recorded reader](../tools/gen-state-root-vectors/check_momentum_rollback_target.py)
checks 26 events, exact exits, raw stdout digests, case ordering, logical images,
callbacks, source trees and the unit inventory. It independently derives the
160-byte v1 second-momentum hash frame and the small present-empty logical frame.
The full genesis KV image remains a recorded pin; this reader does not rederive
that complete payload. Hashes bind published data, not authenticated private
execution provenance.

```sh
python3 -I -B tools/gen-state-root-vectors/prepare_momentum_rollback_target_test.py -v
python3 -I -B tools/gen-state-root-vectors/check_momentum_rollback_target_test.py -v
python3 -I -B tools/gen-state-root-vectors/check_momentum_rollback_target.py
```

Hosted checks replay these recorded bytes and source controls. They do not run
the reference ledger on three operating systems. `Chain.Init`, `Chain.Start`,
the cache, state tree, full node service, network and signing are outside this
experiment.

## Bounded reproduction

The [preparer](../tools/gen-state-root-vectors/prepare_momentum_rollback_target.py)
verifies original source, applies pinned replacements into a new owned workspace
and seals a plan. It starts no compiler, transport or backend, overwrites no
existing destination and rejects substituted bytes or linked source paths.

```sh
python3 -I -B tools/gen-state-root-vectors/prepare_momentum_rollback_target.py plan \
  --workspace "$NEW_PRIVATE_WORKSPACE" --go "$PINNED_GO" --variant candidate
python3 -I -B tools/gen-state-root-vectors/prepare_momentum_rollback_target.py prepare \
  --node-source "$VERIFIED_ORIGINAL_NODE_SOURCE" \
  --workspace "$NEW_PRIVATE_WORKSPACE" --go "$PINNED_GO" --variant candidate
python3 -I -B tools/gen-state-root-vectors/prepare_momentum_rollback_target.py verify \
  --workspace "$NEW_PRIVATE_WORKSPACE" --go "$PINNED_GO" --variant candidate
```

Select `--variant parent` in a separate fresh workspace for the ordinary parent
probe, or `--unit-controls` for the separate candidate test build. Execute only
the command matching that selection. Before execution, admit storage, register
new case/build/capture namespaces and supervise actual exits with bounded output.
The case directory must already exist and be empty. Keep failure bytes and source,
binary, module and command pins; clean only owned disposable generated data after
all related processes have exited.

The recorded work used a 1 GiB expected allocation and 2 GiB task quota, preserving
a 10 GiB free-space floor plus reservations. Parent and candidate builds shared
one temporary build/module cache. They reused 25 verified archive/info pairs and
served 550 source-bound module definitions through a bounded local catalog,
without new external transports or archive downloads. The 25 linked modules were
checked against the selected `go.sum`; the complete archive graph remains
unqualified. Logical quotas and closed-workspace inventories do not establish
physical APFS reclaim or representative production budgets.

M2 profile agreement and full node recovery remain open. This experiment supplies
no canonicality, finality, activation, accepted-header StateRoot binding or state
value proof, and does not satisfy the independent consumer or release gates.
