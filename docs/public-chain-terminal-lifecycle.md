# Public Chain terminal lifecycle comparison

The selected `digitalSloth/go-zenon` source at
[`9c71ae82fc983e16f914ae085d4034030c8ebe3b`](https://github.com/digitalSloth/go-zenon/commit/9c71ae82fc983e16f914ae085d4034030c8ebe3b)
has an outer lifecycle gap after the experimental identity, terminal-state-tree
and offline-caller fixes. Public `Chain.Init` reads the ledger frontier before
reaching the lower stop guard. With stopped real managers this panics.
Public `Chain.Start` can return success for the stopped instance.

This comparison calls real public `Init`, `Start` and `Stop` with fresh disk
ledger, cache and NodeTree managers and the source's own unsigned embedded
genesis. It uses ordinary builds without test overlays, injected scheduling
checkpoints or a race detector. It starts no full node service, network,
consensus or wallet.

## Source and experimental guard

The [source manifest](../tools/gen-state-root-vectors/node-recovery-9c71-source-pins.json)
binds all 467 original blobs, including that node's own module files. Its tree
is `d0f5dfb09e737a806cfc743bb6ba9ddd101ebcd6`. The
[offline-caller parent](state-tree-offline-rebuild-successor.md) runtime tree is
`e60c875a06361f04d05301c0e4c61fd429995c5a`. The additional
[complete-file patch](../tools/gen-state-root-vectors/node-public-chain-lifecycle-9c71-patch.json)
changes only `chain/chain.go`, producing runtime tree
`8420610538a6a51fd43ed4c6f0e2feb2db8f120f` before the separate entrypoint.

The guard serializes `Init`, `Start` and `Stop` on one instance. `Stop` marks
it terminal before closing managers; later `Init` and `Start` return
`chain instance is stopped` before accessing them. Repeated `Stop` is
idempotent. A different object with fresh managers can reopen the owned data.
This does not establish initialization ordering or concurrent lifecycle/read
correctness. Disk format and SMT profile are unchanged relative to the
experimental parent; its format-3 boundary remains. There is no existing
database adoption, migration or deletion.

## Actual local evidence

The [recorded corpus](../tools/gen-state-root-vectors/testdata/successor-public-chain-lifecycle.json)
preserves six sequential process attempts from two ordinary Darwin ARM64 builds
with Go 1.25.14. Cases and expected outcomes were sealed before execution.

| Case | Parent actual exit and result | Additional guard actual exit and result |
| --- | --- | --- |
| Init after complete stop | 2, nil-pointer panic in public `Chain.Init` | 0, explicit stopped-instance error |
| Start after complete stop | 0, nil return despite stopped instance | 0, explicit stopped-instance error |
| Stop before first Init, then Init | 2, nil-pointer panic in public `Chain.Init` | 0, explicit stopped-instance error |

Both variants' first two cases also complete normal initialization, start, a
selected root/proof query, stop and a clean reopen with a different object and
fresh managers. These four positive paths agree on the selected genesis root,
value and proof. Wrong-momentum-hash root queries are refused. The stopped
instance stays unready; all non-panicking terminal cases repeat `Stop` safely.

The root `864dbad1c3ef38e2c867950390364878c58238183d01b8bf97ef73e2efa4383d`
was selected from the earlier independent projection of the source-derived
genesis dump (SHA-256
`a222aac55304b1a489d395235c61af4182ac08b887d24d0c3f654aa402f35e75`).
The reader separately derives the balance path, leaf and all 256 sibling levels
from canonical proof bytes. The expensive complete projection was not repeated.
This source genesis is distinct from the testnet consumer context and does not
authenticate a network snapshot or activation.

After all six cases, an additional whole-module-graph `go mod verify` failed:
the private offline proxy omitted the unused requirement
`github.com/BurntSushi/toml@v1.2.1`. No checksum mismatch was observed. The
original task remains **FAILURE** and its final comparison record was not
emitted. A separate read-only reconciliation retained every actual command,
exit, output, source image and case result. It recomputed ZIP and module-file
h1 sums, checked version metadata and the extracted cache images for the 25
actually linked dependencies against the selected node's own sums.
Whole-module-graph verification remains **NOT_QUALIFIED**. No unused dependency
was downloaded, no case was rerun, and the failed task was not relabelled.

There were zero new dependency transports. The post-run owned workspace image
contained 408,707,196 logical file bytes; this is neither peak usage nor measured
physical recovery. The public corpus includes complete original stdout bytes
and hashes. Private stderr, process receipts and source images stay protected.
Their public hashes and selected diagnostics do not authenticate origin or let
the reader reconstruct their contents.

## Reproduction and portable controls

The preparer checks the complete selected source, patch inverse and runtime
trees, creates only a new caller-owned workspace, and adds one separately tagged
Go entrypoint. It returns exact ordinary build/run arguments. It performs no
acquisition, compiler execution, backend execution or cleanup. Existing
destinations and symlink ancestors are refused; partial preparation is preserved
for its owner after failure.

```sh
python3 -I -B tools/gen-state-root-vectors/prepare_public_chain_lifecycle_successor.py \
  --node-source "$PINNED_COMPLETE_NODE_SOURCE" \
  --workspace "$NEW_OWNED_WORKSPACE" \
  --variant public-chain-terminal --go "$PINNED_GO"
```

Prepare the parent separately with `--variant offline-identity-parent`. Use
the returned ordinary build command, then each declared case with a separate
empty owned case directory and the corpus's preselected key. Use bounded
foreground supervision, private compiler/module/temp caches and verified
dependencies. Reserve 2 GiB expected allocation within a configurable 3 GiB task
quota, above the 10 GiB floor plus other allocations/reservations. Initial
limits are 240 seconds per build, 90 seconds per case and 4 MiB stdout. Retain
actual nonzero exits and incomplete outputs. A stopped object is not a restart.

These portable checks execute no Go/node/database backend:

```sh
python3 -I -B tools/gen-state-root-vectors/prepare_public_chain_lifecycle_successor_test.py -v
python3 -I -B tools/gen-state-root-vectors/check_public_chain_lifecycle_successor_test.py -v
python3 -I -B tools/gen-state-root-vectors/check_public_chain_lifecycle_successor.py
```

Native CI repeats source and recorded-byte controls on Linux, macOS Intel and
Windows; it does not repeat the actual Darwin ARM64 backend comparison. These
selected sequential public calls do not qualify full node startup, recovery,
import/reorg, concurrent shutdown, power loss, node/client profile agreement,
header/root authentication or production state values. Runtime state-value
acceptance stays refused. Those M2–M5 gates remain separate.
