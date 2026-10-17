# Offline rebuild identity compatibility on the selected successor

This separate component experiment selects all 467 source blobs of
`digitalSloth/go-zenon@9c71ae82fc983e16f914ae085d4034030c8ebe3b`, its own
module/sum files, and the experimental identity and terminal-instance patches.
It characterizes an integration gap in that experimental parent and tests a
separate caller correction. It does not enable production state-value proofs.

The selected trees are:

| Selection | Git tree |
| --- | --- |
| Original selected node | `d0f5dfb09e737a806cfc743bb6ba9ddd101ebcd6` |
| Experimental identity parent | `249f3e33e54263efc7c3cad16c02a4784df74040` |
| Experimental terminal parent | `2ab95e67aa184e7faa3f080c6b08d8980a8e16f9` |
| Separate offline caller correction | `e60c875a06361f04d05301c0e4c61fd429995c5a` |

## The compatibility gap

The identity proposal makes `NodeTree.Root` require the stored momentum hash
as well as its height. `RebuildStateTree` in the terminal parent still enumerates
retained roots using `types.HashHeight{Height: h}`. On a retained nonzero identity,
the helper receives a hash mismatch after it has built the tree.

This experiment executes that terminal parent. It does not execute the original
unpatched node as its baseline, demonstrate a remote SPV exploit, or establish a
failure in the production prebuild CLI. The selected source exports
`RebuildStateTree` for cross-package tests. The production offline entry point,
`PrebuildStateTree`, shares the catch-up loop and skips root-map enumeration.

The [caller patch](../tools/gen-state-root-vectors/node-offline-rebuild-9c71-patch.json)
changes only `chain/state_tree.go`. It selects one chain-store snapshot for
enumeration, obtains each complete momentum identifier, rejects an unavailable
store or missing/wrong-height momentum, and passes the complete identifier to
`Root`. The trie's identity checks remain unchanged. Returned partial root maps
are never accepted after an error.

The caller correction preserves the terminal parent's experimental disk format
3. The earlier identity proposal changed original format 2 to format 3; neither
proposal migrates or adopts an existing database automatically.

## Executed local comparison

Two ordinary binaries and two fresh completed processes ran on one macOS arm64
host with Go 1.25.14 and CGO. Each prepared source keeps the selected node's own
module files and eight explicit compiler overlays. The shared recovery probe is
compiled as an adapter library; only `TestCandidateOfflineRebuildSuccessor` is
selected. No scheduler checkpoints or race instrumentation are injected.

The input reuses the successor genesis dump from the earlier source derivation,
with its original execution manifest preserved. This experiment retains that
unchanged provenance and performs no new genesis-generator execution. Before
either backend runs, an independent finite model seals 64 unsigned controlled
identifiers, 256 selected balance addresses, canonical proof expectations, and
the short functional retention boundary. A separate prior full-projection
derivation recomputed the initial and final 64-height projections; this reader
replays the finite witness model without repeating that full derivation.

| Case | Terminal parent | Corrected caller |
| --- | --- | --- |
| Rebuild with source-default retention | Hash mismatch in root enumeration | All 64 roots match |
| Rebuild with explicit retention 5 | Hash mismatch in root enumeration | Six roots, heights 59 through 64, match |
| Archive rebuild with explicit retention 5 | Hash mismatch in root enumeration | All 64 roots match |
| Prebuild and clean reopen | Matches | Matches |
| Prebuild through 32, then bounded catch-up through 64 | Matches | Matches |
| Wrong-height or missing momentum during enumeration | Outside this parent's selected matrix | Refused |
| Wrong hash, unavailable store or injected read error during enumeration | Outside this parent's selected matrix | Refused |
| Missing or wrong persisted hash at retained height 32 | Outside this parent's selected matrix | Refused, logical records unchanged |

The 17 cases produce 1,650 canonical proof matches and 90 explicit `no-version`
proof refusals. Every returned retained root is compared with its independently
selected full identifier. Thirty-four complete closed-reopen snapshots are
checked, in addition to prebuild/fault observations. A complete second snapshot
is represented by its exact canonical digest; the retained preimage must match.
Both variants continue to refuse wrong-hash, height-only and missing-version
root queries.

The seven corrected-caller refusals use declared controlled store/metadata
faults. Enumeration faults select a specific snapshot from the adapter; they do
not qualify a real concurrent chain stop, reorg or an independently operated
provider. Short retention below the rollback cache is an inspection-only test
override, never a production rollback policy.

## Evidence and bounded storage

The private supervisor retains outputs in verified SHA-256 storage before it
acknowledges deletion of each fresh case workspace. It checks the complete
unchanged named LevelDB inventory, process-group quiescence and actual absence.
Unknown files, links, mounts and uncertain processes remain held. Six isolated
inventory/failure-image regressions and fourteen adverse checks on the real
prepared sources are separate from the node's 17 functional cases.

The two original observation payloads total 3,001,051 bytes. The
[portable recorded corpus](../tools/gen-state-root-vectors/testdata/successor-offline-rebuild.json)
is 838,761 bytes: five complete snapshot preimages and explicit references
reconstruct each original payload's exact length and SHA-256. There is no
recursive ZIP or hard-linked evidence. Original captures remain protected.

The whole local execution task took approximately 133 seconds, including source
preparation, both builds, controls and checking. Its final compiler workspace
contained 281,559,062 logical bytes before owned cleanup. That is not a peak disk
measurement, physical reclaim amount, controlled speedup or production budget.
No completed 32,768-height retention sample was repeated for this caller issue.

| Evidence | SHA-256 |
| --- | --- |
| Independent expectations before backend | `fb73dd797dd69fe3659ae7e6d7fec8be6ddb977d49660d7d143a253c879b399f` |
| Independent selection | `f06d4cc4e66a42b68d2647c0d1cab4d65b6e1f4e761557a8ff3d4ea228c10d14` |
| Earlier full-projection prefix derivation | `9d9e748adb5811c2064e38b68d690083d1e5e314a9cdff7bc58e86f62428bbf9` |
| Terminal-parent ordinary binary | `d9f559dd0acb8b8142d531d5323763553357762a001841f80cd734221f042ba6` |
| Corrected-caller ordinary binary | `fa5115eff873111c68943e34bbde512ba00bc6ebbab0ec897fcd9c83ca05c38b` |
| Local comparison and actual receipts | `286665b221847a7992d08ed19b90665616fd6c009c17362e9ef0f2e739731378` |
| Portable corpus | `012ee92e38a9149f5db231d0c3973769376789eae5cd45da7a80dec110de79a1` |

Digests establish byte equality. They do not authenticate the source repository,
toolchain, release distribution or this unsigned evidence record.

## Portable checks and reproduction boundary

```sh
python3 -I -B tools/gen-state-root-vectors/prepare_offline_rebuild_successor_test.py -v
python3 -I -B tools/gen-state-root-vectors/check_offline_rebuild_successor_test.py -v
python3 -I -B tools/gen-state-root-vectors/check_offline_rebuild_successor_corpus_test.py -v
python3 -I -B tools/gen-state-root-vectors/check_offline_rebuild_successor_corpus.py
```

These 21 portable controls and the recorded reader execute no new node, compiler,
LevelDB or resource measurement. Exact-source native CI and artifact validation
are separate qualification steps; adding the CI commands is not their result.

For a new backend experiment, obtain the complete pinned source in an owned
workspace, verify dependencies against that source's own `go.sum`, retain the
selected genesis provenance, and seal independent expectations before execution.
`prepare_offline_rebuild_successor.py` accepts `--node-source`, a fresh
`--workspace`, `--variant terminal-parent|full-identifier`, and `--go`; it returns
exact commands without running them. The caller owns capped output, immutable
input pins, private caches, quotas, process supervision and evidence-before-cleanup
acknowledgement. Do not reuse an existing node database.

This controlled component does not run `Chain.Init`, `Chain.Start`, a complete
node, a continuous VM history, wallets, signing, transactions or a network.
Logical-record equality does not independently reconstruct every internal
refcount, authenticate snapshots, or qualify crash/power-loss recovery.
Independent consumer/anchor selection, agreed key/value/proof/activation rules,
accepted-v3-header balance binding, target hardware/resource acceptance,
independent review and authenticated distribution remain open. Runtime v1/v2
behavior is preserved and production state values remain `REFUSED`.
