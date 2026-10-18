# Native cache forward-replay preflight experiment

A cache behind the selected ledger can carry a different hash at its starting
height. The recorded parent replays from the next height without checking that
base. Public `Chain.Init()` succeeds, both current identifiers become equal and
the following reopen succeeds, although the small foreign cache never acquired
the canonical genesis contents. This is a local recovery counterexample; it
does not establish a remote SPV acceptance bypass.

The experiment selects `digitalSloth/go-zenon` at
`9c71ae82fc983e16f914ae085d4034030c8ebe3b` and all 467 original source blobs.
Its parent runtime includes the separate
[rollback identity fix](cache-identifier-rollback.md), tree
`49db80f94e48e980f84de35299f80c6f3b4dcb54`. One complete-file replacement of
`chain/cache.go` produces runtime tree
`57759bee9f143a10ef5a60880170b62a61ede7de`. The original node repository and
the SPV runtime are unchanged.

## Preflight behavior

Before replaying the first new momentum, a nonzero cache frontier must
equal the selected ledger momentum's complete hash/height identifier. A nil
predecessor or a different identifier refuses before patch selection, prefetch
or cache mutation. Lookup errors propagate. At height zero only the exact zero
hash/height identifier can start replay; it does not request a height-zero
momentum.

The cache manager interface, disk format and SMT profile stay compatible.
There is no database removal, implicit retry, repair or height-only fallback.
Later replay I/O errors can still leave acknowledged progress. This preflight
does not make the full replay window atomic or authenticate the selected
ledger's canonicality.

## Recorded native execution

The existing parent binary and four observations were retained and reused.
One new ordinary Go 1.25.14 Darwin ARM64 build produced four candidate process
observations. All eight recorded process exits are zero; startup outcomes differ:

| Cache before startup; ledger at A2 | Parent | Candidate |
| --- | --- | --- |
| Canonical A2 | Ready; clean reopen | Ready; clean reopen |
| Canonical A1 | Replay to A2; clean reopen | Replay to A2; clean reopen |
| Foreign B1 at height one | Replays from a foreign base; becomes ready at A2 | Refuses before writing; B1 cache unchanged |
| Empty zero frontier | Replay genesis and A2; clean reopen | Replay genesis and A2; clean reopen |

The three positive final logical cache images are identical across both
runtimes. The parent foreign result has matching current identifiers but a
different, independently reconstructed small cache image. The candidate leaves
that fault image unchanged and its state queries return not-ready without a
value or proof.

All cases use real on-disk ledger, cache and NodeTree managers through public
`Init`, query and `Stop` calls. A2 is a source-reproducible unsigned local
momentum inserted through direct component calls. B1 is only a native frontier
metadata fault, not a complete alternate-chain cache application. `Chain.Start`,
network/consensus execution, wallets, signing and broadcast are not selected.

One race-enabled test invocation separately ran 13 native test roots and 30
passing results across two packages, with no skips. It reruns the 12 earlier
rollback component roots under the changed runtime. Seven new preflight
subcases check foreign hashes, matching hashes with wrong heights, nil
predecessors, original lookup errors, nonzero hashes at height zero, valid
behind-cache progression and valid zero-cache progression. Ordered callback
counts and unchanged cache bytes bind the refusal boundaries. Earlier public
rollback observations keep their original runtime; they are not relabeled as
new full-service recovery evidence.

## Independent byte checks and resources

```sh
python3 -I -B tools/gen-state-root-vectors/prepare_cache_forward_replay_test.py -v
python3 -I -B tools/gen-state-root-vectors/check_cache_forward_replay_test.py -v
python3 -I -B tools/gen-state-root-vectors/check_cache_forward_replay.py
```

The 31 portable controls and reader check 70 recorded events and 15 public
queries. They reconstruct both complete build trees, independently hash the
160-byte v1 A2 header frame, reconstruct three small protobuf/batch/cache images
and fold one preselected 256-level canonical witness. The 14 available queries
must match that witness; the refused query must expose no state value or proof.
The reader starts no compiler, reference backend or network connection.

The native work reused 75 verified proxy inputs for the 25 actually linked
modules and the node's unchanged module files, with zero new transports. The
source-reproducible execution workspaces were closed and removed after process,
identity and complete file-manifest checks. Their post-run logical file totals
were 353,573,046 bytes for the parent and 537,041,429 bytes for the candidate,
including private compiler/module caches and fixtures. Protected inputs,
selected binaries, source controls, raw outputs and manifests remain retained.
Separately registered original-source, proxy and execution aliases are outside
those execution-directory totals.
These totals are not peak disk measurements or measured physical APFS reclaim.

Hosted checks replay these recorded bytes on their host; they do not execute
this reference backend there. Exact-source three-platform CI and artifact
qualification remain separate mechanical publication gates. The unsigned
record does not authenticate private receipts or establish independent review
or authenticated distribution. Whole-module-graph verification remains
**NOT_QUALIFIED** after the earlier missing unused proxy input; it was not
retried or converted into success.

Node/client profile agreement, representative retention/reorg/interruption
workloads, accepted-v3-header binding and activation-aware state-proof delivery
remain open. Runtime state-value acceptance and the consumer remain **REFUSED**.
