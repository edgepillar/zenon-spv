# Experimental hash-bound retained versions

This M2 research candidate extends the earlier startup quarantine with retained
Momentum hash metadata. It restores matching ahead-tree rollback and refuses a
different hash at the retained target height. It is a patch proposal and a
recorded component comparison in this SPV fork. Production v3 and state-value
proof acceptance remain disabled.

## Deliberately selected current source

The baseline is
[digitalSloth/go-zenon at 33d7d1e](https://github.com/digitalSloth/go-zenon/tree/33d7d1ee1b6a915c40aea196e2a10f1e893d171f),
Git tree `40d71efb7e462d5bbd0f27d83ed7588e121c3cb6`. The complete
[source inventory](../tools/gen-state-root-vectors/node-recovery-source-pins.json)
pins 439 blobs, Git modes, Git blob IDs, SHA-256 and lengths. The older
56ce/394-blob fixtures, source selectors and evidence retain their original pins.

Only `common/trie/nodestore.go` and `chain/state_tree.go` change in the
[experimental descriptor](../tools/gen-state-root-vectors/hash-bound-versions-patch.json).
Its exact replacements bind complete before/after files and a complete inverse.
The derived tree, without the test probe, is
`28c9eec1156633836357028e16a3958edbc635c4`. It is an uncommitted experimental
source tree, not an upstream commit or an activated network protocol.

## Storage and component changes

The candidate changes the NodeTree **disk format from 2 to 3**. This marker is
separate from Momentum header version 3. It adds:

```text
06 || uint64_be(height) -> Momentum_hash_32
```

Regular and bulk commits write this identity in the same LevelDB batch as the
root, node references and frontier. Root, Prove, ComputeRoot and Truncate require
the stored hash as well as the height. Only the all-zero HashHeight denotes the
implicit empty origin. A nonzero retained empty root still needs its identity.
Prune and Truncate collect the paired hash metadata with the root record; Prune
refuses a horizon that would remove the active frontier. Regular Commit refuses
the maximum-height wrap to origin. This does not bound general large-height
traversal or qualify maximum-height pruning/rollback resources.

A constructor checks the recovered frontier identity and root read, and refuses
orphan records at an empty origin. Nonzero node references missing from the read
or copy-on-write path return corruption. This is not a full database integrity
scan: a missing unvisited child can leave the component ready until a query
needs that child. The dedicated missing-primary case records exactly that
limitation; a ready flag is not proof that every stored value is readable.

The chain wrapper releases a failed new handle and preserves incompatible
records. Init resets readiness, ancestry state and the last-root memo before
reconciling. ComputeStateRoot serializes with component changes, checks that the
exact parent remains retained and readable before a cache hit, and invalidates
the memo when the retained set changes. Stop clears readiness. The comparison
covers a warmed cache after prune, truncate and an independently closed backend.

This candidate supplies **no existing-database migration**. Legacy format 2 and
foreign format 4 are refused without changing logical records. The unpatched
baseline automatically wipes an unfamiliar format, including this format 3.
Never open experimental data with that baseline. Reproduction requires separate
fresh owned directories for each variant; no real user database is transformed.

## Recorded evidence and its limits

The actual chain constructor, Init, state-tree wrapper and NodeTree APIs run
against small new disk LevelDB fixtures. A recording manager, cache and genesis
supply independently selected unsigned version-2 Momentums and balance patches.
Two keys distinguish the forks after a later overwrite of the primary value.
No Chain.Start, background build, full-node service, upstream test suite, network,
RPC, wallet, signing or transaction path executes.

Each complete comparison generation has:

- 26 chain scenarios per variant, including three clean-reopen repetitions and
  three two-phase previously-ready cases.
- 11 low-level scenarios per variant, including empty versions, a bulk gap,
  staged replay failure, frontier pruning and origin wrap.
- 64 component Init observations, 946 selected read observations and 322 complete
  sorted logical database snapshots across both variants.

Both variants were built once locally with Go 1.25.14 and CGO on darwin/arm64,
using a shared private compiler/module cache and an offline dependency proxy.
Each binary ran two fresh complete generations. The byte-for-byte observations
matched expectations sealed before the first backend execution. All actual
exits and complete streams, toolchain/source/binary pins and module ZIP digests
are retained separately. The temporary build and database workspaces closed
after qualification.

The independent Python oracle builds full 256-level sparse roots and canonical
proofs, and separately constructs compressed node records and shared refcounts.
It binds the exact format, version/hash/frontier records, cache callbacks,
manager traces, failure outcomes and reopens. Forty regression controls reject
substituted identities, roots, proofs, records, source pins, types, missing cases
and stronger trust claims.

Linux, macOS and Windows CI run the recorded-data checks and controls. Those
jobs do not rerun the local node/CGO component experiment and do not qualify the
complete current node. Native SPV binaries and the remaining evidence families
retain their separate exact-source artifact checks.

## Reproduction

Select the full pinned source and a nonexistent, quota-accounted workspace:

```sh
python3 -I -B tools/gen-state-root-vectors/prepare_hash_bound_versions.py \
  --node-source NODE_SOURCE --workspace NEW_OWNED_WORKSPACE \
  --variant hash-bound --go SELECTED_GO_1_25
```

Inspect the returned full-source pins, compiler overlay, module bytes, build
arguments and required `ZENON_HASH_BOUND_VARIANT` value. The explicit overlay
excludes six upstream chain test files; their bytes remain unchanged. Execute
the returned build/run commands only through the caller's approved bounded
storage/process supervisor with private caches and temporary directories.
Prepare the baseline in a different new workspace. The preparer performs no
download, subprocess execution, database adoption or cleanup.

```sh
python3 -I -B tools/gen-state-root-vectors/check_hash_bound_versions_test.py -v
python3 -I -B tools/gen-state-root-vectors/report_hash_bound_versions.py
```

Retained caller-supplied hash metadata does not authenticate accepted headers,
state transitions, canonical history, consensus finality or freshness. A coherent
replacement of both identity and state still needs an independent authoritative
header/root binding. Agreed SMT/key/value/proof and activation contracts,
independent node review, representative retention/resource measurements, storage
fault and concurrency qualification, migration/downgrade policy, a selected
consumer, anchors, producer schedule, context pins and authenticated distribution
remain separate gates. Every state-value consumer result is `REFUSED`.

