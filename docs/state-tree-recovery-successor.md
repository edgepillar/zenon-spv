# Source-pinned recovery successor comparison

This separate research track selects
[`digitalSloth/go-zenon@9c71ae82fc983e16f914ae085d4034030c8ebe3b`](https://github.com/digitalSloth/go-zenon/tree/9c71ae82fc983e16f914ae085d4034030c8ebe3b).
The complete [source manifest](../tools/gen-state-root-vectors/node-recovery-9c71-source-pins.json)
binds 467 files and 7,549,463 logical bytes to Git tree
`d0f5dfb09e737a806cfc743bb6ba9ddd101ebcd6`, including Git modes, blob IDs,
SHA-256 and lengths. Historical 56ce and 33d7 inputs and executed observations
retain their original identities.

The branch history diverged from the selected 33d7 snapshot. A merge-base diff
does not establish complete source equality. Module files, protobuf decoding and
trie helpers changed. The new chain wrapper already refuses an incompatible
database; old baseline wiping observations do not describe this revision.
`chain.Stop` also joins errors from every manager, so a closed state-tree
backend does not prevent the cache and chain managers from receiving `Stop`.
The separately versioned model includes both source changes.

## Experimental patch

The [successor descriptor](../tools/gen-state-root-vectors/node-recovery-9c71-patch.json)
retargets the two-file hash-bound version proposal. Only `chain/state_tree.go`
and `common/trie/nodestore.go` change. Complete before/after bytes, SHA-256, Git
blob IDs, lengths and inverse replacements bind derived tree
`249f3e33e54263efc7c3cad16c02a4784df74040`, without the probe.

The proposal preserves the baseline's foreign-database refusal and existing
error declarations, while adding retained Momentum identities and the original
read/rollback/cache guards. Disk marker 2 becomes 3, independently of Momentum
header version 3. There is no existing-database migration or automatic deletion.
SMT roots and proof encoding are outside the change set.

Source retargeting and Go syntax/format checks do not qualify runtime behavior.
Fresh component runs and independent byte expectations are required before
claiming a successor comparison.

## Preparation contract

`prepare_recovery_successor.py` accepts the complete selected source and a new,
caller-owned workspace. It verifies the source, patch inverse and staged tree.
An explicit compiler overlay excludes eight original upstream chain test files
without modifying their bytes. The tagged probe preserves the 26 chain and 11
low-level selections; only its build tag, environment selector, output kind and
revision change. Historical executions are not successor execution evidence.

The build plan selects the new node's own `go.mod` and `go.sum` with
`-mod=readonly`. It does not substitute the historical research module lock.
The caller selects and verifies the compiler, provisions dependencies, configures
private caches and quotas, supervises processes and preserves actual outcomes.
Keep the free-space reserve plus expected allocations and close owned workspaces.

```sh
python3 -I -B tools/gen-state-root-vectors/prepare_recovery_successor_test.py -v
python3 -I -B tools/gen-state-root-vectors/prepare_recovery_successor.py \
  --node-source COMPLETE_SELECTED_SOURCE --workspace NEW_OWNED_WORKSPACE \
  --variant hash-bound --go SELECTED_GO_1_25
```

The preparer performs no download, compilation, node execution, adoption or
cleanup. Its plan contains private caller paths. Verify the plan with the
independently selected compiler before execution. Use a separate fresh workspace
for each variant.

Local metadata/patch controls and both complete staged variants passed. These
are preparation controls, not a backend comparison or hosted CI qualification.
New recorded comparisons must explicitly account for baseline foreign-format
refusals.

## Independent expectations

`check_recovery_successor.py` separately versions the finite retained-identity
model. It shares the independent SMT-level and compressed-DAG mathematics,
while preserving every historical selector and observation. Both variants now
expect foreign-format refusal without replacing logical records. Model controls
reject context splicing, stale cache results, wrong identities, modified node or
refcount bytes, and relabelled historical observations.

Expected tables are derived and SHA-256 pinned before the successor backend
runs. Each variant covers 26 chain selections and 11 low-level selections.
Together they select 64 initializations, 946 read observations and 322 complete
logical database snapshots per generation. These finite counts are a test
inventory, not a throughput or retention budget.

```sh
python3 -I -B tools/gen-state-root-vectors/check_recovery_successor_test.py -v
python3 -I -B tools/gen-state-root-vectors/check_recovery_successor.py \
  --baseline RECORDED_BASELINE_JSON --hash-bound RECORDED_CANDIDATE_JSON
```

The checker executes no backend. Matching JSON cannot establish command exits,
freshness, native platform, module transport or binary provenance. Keep those
actual outcomes and source/module/toolchain pins in a separate execution record.
Build each variant once and reuse that closed binary in fresh fixture generations.

## Recorded local component comparison

The [execution record](../tools/gen-state-root-vectors/testdata/successor-recovery-execution.json)
binds both complete logical recordings to selected source, module locks, compiler,
binary digests and command outcomes. Go 1.25.14 on macOS arm64 with CGO enabled
ran each variant twice in fresh fixtures. Both generations matched the corrected,
sealed independent expectations byte for byte. The initial model mismatch is
retained separately: it concerned the source's joined shutdown calls, and is not
reported as a passing comparison.

Each variant was compiled once. The first baseline binary was retained and reused
after the model correction, and dependency transports were reused by verified
content. New private caches and staged workspaces occupied 293,498,923 logical
bytes at the end of the final run. That snapshot excludes separately registered
source/proxy aliases and protected objects; it is neither a peak nor physical
allocation measurement. Owned temporary workspaces were removed after success.

The added native CI steps are configured to recheck the recordings and offline
model/preparation controls. This does
not rerun this node experiment on each hosted operating system. A local component
match does not qualify the full node, live recovery, crash safety, realistic
retention costs or production state-value acceptance.

Caller-supplied identity metadata does not authenticate headers, state
transitions, canonicality, finality or activation. Full-node, concurrency,
storage-fault, migration/downgrade, realistic resource, profile, consumer and
independent-review gates remain separate. Production state-value results remain
`REFUSED`.
