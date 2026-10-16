# Source-default retention observations

Six fresh component processes exercised the experimental NodeTree at its source
defaults: 32,768 controlled heights, 256 distinct balance addresses, effective
retention 17,380 and no retention or bulk-batch override. All retained root/hash
pairs, selected canonical proofs, actual patch requests, clean Stop and reopen
matched expectations sealed before the component ran. This extends the earlier
[4,096-height, override-256 observation](state-tree-genesis-background.md).
It is local M4 component evidence; current SPV state-value acceptance remains
disabled.

## Selected source and workload

The original source is
[`digitalSloth/go-zenon@33d7d1ee1b6a915c40aea196e2a10f1e893d171f`](https://github.com/digitalSloth/go-zenon/tree/33d7d1ee1b6a915c40aea196e2a10f1e893d171f),
439 blobs with tree `40d71efb7e462d5bbd0f27d83ed7588e121c3cb6`.
Only the existing experimental
[retained-identity](state-tree-hash-bound-versions.md) and
[terminal Stop](state-tree-terminal-stop.md) proposals change runtime source;
their tree, excluding probes, is
`d3d9215bc9ea23b2e700aad53ebb23d4bdea3428`. This does not establish upstream
adoption, an agreed profile or authenticated activation. Disk format marker 3
is separate from Momentum version 3.

The existing 10,849,399-byte source-genesis dump is reused by SHA-256
`a222aac55304b1a489d395235c61af4182ac08b887d24d0c3f654aa402f35e75`.
Its 19,257 nonempty projection leaves include 14,091 balances and 5,166 storage
values. The complete initial projection and final projection were separately
recomputed; all source balances were decoded independently. Plasma, frontier
and mailbox remain outside this commitment. This is source-derived input,
not an authenticated network checkpoint.

The independent selector sorts balance raw keys, then chooses 256 quantile
positions including both endpoints. These keys belong to 256 distinct addresses.
Height 1 applies genesis; heights 2 through 32,768 cycle those keys. Multiples
of 11 delete; otherwise multiples of 7 store 32 zero bytes; other heights store
big-endian uint256 `1,000,000 + height`. There are 2,978 deletes, 4,256 stored-zero
puts and 25,533 other puts. The actual manager adapter observes every chronological
patch request once. Its binary mutation-frame SHA-256 is
`cc4a72e9e01982bc3c526873aaabff331ce9963867c06b49c7cc341909ef8710`.

The root starts at
`864dbad1c3ef38e2c867950390364878c58238183d01b8bf97ef73e2efa4383d`
and ends at
`22c124db1d7760e3e6b27442485c69546f76ad32deebf5445b120b5c2e68cdaa`.
Identifiers use unsigned SHA3 hashes of
`synthetic-hash-bound-node-v1/G/HEIGHT`. These suffix updates are controlled
fixtures, not execution-validated transactions or authenticated headers.

Before backend execution, the independent witness model sealed all 32,768
expected roots and selected proof bytes. Its initial witnesses cover 269 keys,
using unchanged model batches of 128, 128 and 13. The complete expectation
digest is `c4d175be3d2639a71d795cebd43d23bb941555ee75d7ba41615c46958ea74412`;
the independent selection digest is
`ac2157d776d26f5c4d00ccd4ab3f832224039d5043314d2ea7f2cb7045972622`.

## Actual lifecycle, horizon and proof scope

The controlled manager/cache/genesis adapters feed the actual chain
`Init`, `Start`, background worker and `Stop`, with fresh private disk LevelDB
instances. No scheduler checkpoint is injected into runtime source. The source
rollback cache is 100, the extra retention margin 17,280, bulk batch cap 10,000,
tail batch cap 10 and batch time budget one second. The probe checks these
values and both zero-valued overrides directly.

Pruning removes heights strictly below `frontier - retention`. Thus height
32,768 retains **15,388 through 32,768 inclusive: 17,381 roots**. Archive mode
retains all 32,768 roots. All root/hash pairs are compared with the presealed
model. Each case compares three complete logical-record snapshots and two
query sets across Stop, closed inspection and clean reopen.

Each query set selects the same 15 source-derived proof keys at heights
1, 15,387, 15,388, 15,389, 32,758 and 32,768. These are not individual proof
queries for all 256 mutation keys. Pruned cases have 60 matching canonical
proofs and 30 no-version refusals per set; archive cases have 90 matches.
Across six processes and two sets, there are 900 matching proof observations
and 180 pruned refusals. Wrong-hash lookups separately refuse with
version-hash-mismatch; the origin identifier returns the source's zero root
without an error. Stop revokes public readiness and closes direct backend reads.

The preserved logical-record counts and digests agree across each lifecycle;
every individual node/refcount byte in this larger database was not independently
reconstructed. Generic absence remains absence only from the committed
balance/storage projection.

## Recorded resources

One ordinary Go 1.25.14 binary with CGO was compiled once on a single macOS
arm64 host, using frozen modules, an offline proxy and `GOMAXPROCS=2`.
Its digest is
`83e2b6cf82c5867b00a7fd56745c6605ca54e3a694870b2f9c9e284404091910`.
Three fresh processes per policy ran in the preselected order: all pruned
samples, then all archive samples. No component process was retried or filtered.
These samples are ordinary builds; earlier race-instrumented schedules retain
their separate scope.

| Three observed ordinary processes per policy | Pruned | Archive |
| --- | ---: | ---: |
| Retained root/hash pairs | 17,381 | 32,768 |
| Logical records | 609,448 | 1,076,346 |
| Logical key/value bytes | 58,324,301 | 103,493,643 |
| Final closed regular-file bytes, range | 48,124,093–48,125,801 | 84,583,183–84,584,425 |
| Whole waited-process peak RSS bytes, range | 295,682,048–301,793,280 | 348,651,520–374,521,856 |
| Whole waited-process wall seconds, range | 35.024–36.507 | 78.844–80.554 |

RSS and elapsed time include controlled input/fixture construction, queries,
snapshots and output. They exclude the compiler and Python controller; they are
not isolated NodeTree allocation measurements. Native `wait4` peak RSS is
normalized from Darwin bytes or Linux KiB. A 0.5-second RSS sampler stops an
owned child above 2 GiB; it is not an OS memory quota. The Go deadline is 540
seconds, child supervisor deadline 600 seconds and managed command deadline
720 seconds. Output caps are 64 MiB stdout and 1 MiB stderr.

Closed file lengths are not peak disk, allocated physical blocks or APFS reclaim.
There is no controlled cold-cache comparison, agreed consumer hardware/concurrency
budget, continuous advancing VM workload, complete node, activation observation,
snapshot import or power-loss recovery in this experiment. These observations
do not close those remaining M4 gates.

## Evidence retention and cleanup corrections

Exact input, source, binary, exit, completeness and sample identities are
preserved. Two unique canonical logical-table payloads occupy 8,514,977 bytes,
instead of retaining six equal copies totaling 25,544,931 bytes. Original Go
stdout/stderr can be reconstructed byte for byte from those payloads and the
protected diagnostics; both stream sizes and SHA-256 digests were checked.
There is no second stdout-to-ZIP packaging step.

The first controller stopped before launching a component because it expected
an incorrect task-state label. The first actual component then passed, but its
controller's detached temporary-directory finalizer made cleanup a no-op on
Python 3.9. The controller incorrectly emitted a workspace-removed event. The
storage manager held the remaining database; the original event and an explicit
erratum are preserved. All remaining file names, lengths and digests matched
the closed-file observation, no live process/handle was found, and narrowly
authorized cleanup removed that residue. The successful component was not
executed again. A corrected private supervisor passed 19 isolated controls and
an actual CAS-promotion/acknowledgement/workspace-absence integration fixture;
all five subsequent workspaces closed and disappeared as checked by the manager.

New qualification uses approved owned task storage, independent APFS clones,
explicit 1 GiB reservations and 2 GiB task quotas. The free-space floor remains
10 GiB plus expected allocations/reservations. Protected evidence must be
durable before a fresh disposable database is removed; interrupted or uncertain
cases remain held. Historical caches, existing databases, source changes and
unrelated worktrees are never adopted for cleanup. Private storage implementation
changes are outside this SPV publication.

## Reproduction and portable checks

The [preparer](../tools/gen-state-root-vectors/prepare_default_retention.py)
verifies the full 439-blob snapshot, both existing source patches and inverses,
unchanged module locks, the explicit six-file compiler overlay and three probe
files. It creates only a nonexistent caller-owned workspace and returns a
build/run plan; it downloads, compiles and runs nothing. The older 4,096-height
prepared manifests and corpora are unchanged.

Using an approved managed task with explicit quotas, separately acquire the
pinned complete source, toolchain and verified genesis dump. Seal the independent
expectations before running the returned component plan:

```sh
python3 -I -B tools/gen-state-root-vectors/default_retention_model.py \
  --input VERIFIED_SOURCE_GENESIS_DUMP --node-source PINNED_COMPLETE_NODE_SOURCE
python3 -I -B tools/gen-state-root-vectors/prepare_default_retention.py \
  --node-source PINNED_COMPLETE_NODE_SOURCE --workspace NEW_OWNED_WORKSPACE \
  --go SELECTED_GO_EXECUTABLE
```

Stream the first command's bounded output directly into one SHA-256-verified CAS
object. Compile the returned ordinary plan once and select the published test
regex only. Set the exact input/selection digests, policy and a fresh empty owned
case directory through its required environment contract. Run three independent
processes per policy under the deadlines/output caps above. Preserve actual
failures and complete records; require durable evidence acknowledgement and an
observed cleanup postcondition before removing disposable scratch.

The [recorded corpus](../tools/gen-state-root-vectors/testdata/candidate-default-retention.json)
contains observed root strings once with an explicit hash/height codec and
shared observed query/snapshot tables. Every expansion must reproduce the exact
original complete payload size and SHA-256. This is reversible factoring of
observations, not replacement by model output. The separate witness model then
replays all 32,768 roots and canonical proofs. Full initial genesis decoding
is a separate retained derivation, not repeated by this portable checker.

```sh
python3 -I -B tools/gen-state-root-vectors/default_retention_model_test.py -v
python3 -I -B tools/gen-state-root-vectors/prepare_default_retention_test.py -v
python3 -I -B tools/gen-state-root-vectors/check_default_retention_test.py -v
python3 -I -B tools/gen-state-root-vectors/check_default_retention_corpus_test.py -v
python3 -I -B tools/gen-state-root-vectors/check_default_retention_corpus.py
```

The first native CI head exposed two preparation-fixture errors because the
local managed-scratch environment variable is absent on hosted runners. Fixture
selection now requires local owned task scratch or explicitly selects GitHub
Actions' runner temporary directory; it has no implicit local fallback. The
expected output path also uses the platform's native path representation.
Neither correction changes the prepared component, binary, recorded samples or
independent expectations, so the six component processes are not rerun.

These 64 controls and the recorded comparison are scheduled in native CI.
The portable checks execute no node, Go build, LevelDB, network or new resource
measurement. Exact-head CI success must be verified separately; corpus receipt
hashes do not authenticate execution, the reference host or distribution.
M1 independent consumer qualification, M2 profile/activation agreement, M3
accepted-header binding and M5 independent review/authenticated distribution
remain separate gates. Current runtime v3/state-value requests remain refused.
