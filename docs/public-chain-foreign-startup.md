# Public Chain startup with foreign retained identities

This continues the [real-manager terminal lifecycle comparison](public-chain-terminal-lifecycle.md)
at selected node revision
[`9c71ae82fc983e16f914ae085d4034030c8ebe3b`](https://github.com/digitalSloth/go-zenon/commit/9c71ae82fc983e16f914ae085d4034030c8ebe3b).
It tests the existing experimental runtime through public `Chain.Init`, root and
proof queries, and `Chain.Stop`. It adds no runtime fix: the complete 467-blob
runtime tree remains `8420610538a6a51fd43ed4c6f0e2feb2db8f120f`.

The new separately tagged [entrypoint](../tools/gen-state-root-vectors/public_chain_foreign_startup_probe.go)
uses real disk ledger, cache and NodeTree managers. Every case first initializes
and closes a fresh source-genesis ledger. Foreign trees are constructed separately
with the actual native-format NodeTree API, then closed before public startup.
No existing user database is adopted, migrated or deleted. `Chain.Start`, full
node service, network, consensus, wallets, signing and broadcast are not invoked.

## Recorded outcomes

The [byte-pinned corpus](../tools/gen-state-root-vectors/testdata/successor-public-chain-foreign-startup.json)
contains four sequential ordinary Darwin ARM64 processes from one Go 1.25.14
build. The source tree, inputs, selected roots and expected outcomes were sealed
before execution. Every process exited zero with complete captured output;
expected startup errors are checked separately from process success.

Here A1 means the source's unsigned embedded genesis identifier. B1 differs in
hash at the same height; B2 has another hash at height two. These are controlled
database identifiers, not competing authenticated network blocks. In this
document, canonical means only the preselected source-genesis identity A1.

| Fresh tree before public Init | Init and query result | After Stop |
| --- | --- | --- |
| Source-genesis A1 | Ready; A1 root/value/proof available; wrong hash and missing height refused | Same raw store; clean reopen available |
| Foreign B1 at height one | Frontier-identity error; unready; all root/proof calls refused | Identical ordered raw key/value digest and counts |
| Foreign B2 ahead, retained height one belongs to B1 | Retained-hash mismatch; unready; all root/proof calls refused | Identical ordered raw key/value digest and counts |
| Foreign B2 ahead, correct A1 retained below it | Synchronous rollback to A1; only A1 root/value/proof available | A1 frontier and raw store restored; B2 unavailable; clean reopen available |

The two refused starts return no value or proof, including when querying the
foreign tree's own identifiers. The controlled rollback removes the foreign
height-two version before public queries. All four instances become unready
after Stop. The corpus records 38 events, 12 public root/proof query pairs and
two clean reopens. This is selected offline startup/recovery evidence, not live
reorg, fork-choice, concurrent lifecycle or power-loss qualification.

## Independent byte checks and evidence limits

The reader binds all original blobs, the unchanged experimental runtime, the
node's own module files and the exact added command. Their combined build tree
is `6b5c452bd643d1b11e4b640cb398adfdf59ec12b`. The ordinary binary is 19,854,162
bytes, SHA-256 `bb0058427f7fd676d3424a79891991b1206982704c88aa536e6f598345a72dce`.

The source-genesis root and balance witness were selected from earlier independent
projection evidence, not copied from this experiment's response. The reader
derives the path, leaf and all 256 levels for three roots: the original balance,
a single-leaf foreign tree, and the complete projection with that one balance
changed from 100000 to 100001. It does not repeat the expensive full genesis
projection. Neither those folds nor the unsigned genesis authenticate a testnet
snapshot, accepted v3 header, activation schedule or state value.

Before/after raw-store digests cover ordered length-framed key/value bytes read
with closed writer handles. They exclude LevelDB physical file layout and do
not claim byte-identical SSTables, durable power-loss recovery or independently
authenticated database provenance. Public checks rehash the original complete
stdout bytes and compare every recorded field, error class and refusal. Private
stderr, binary/build-info payloads, process receipts and closed-file manifests
remain protected; their public digests do not let this reader reconstruct or
authenticate those payloads.

The run reused 75 verified ZIP/module/info inputs for the 25 actually linked
modules, with independent h1 checks against the selected node's own sums and a
binary module inventory comparison. No source or dependency was downloaded.
The earlier whole-module-graph failure for an unused offline proxy requirement
is preserved and was not retried. Whole-module-graph verification remains
**NOT_QUALIFIED**; this new finite execution task completed successfully.

## Reproduction and portable controls

The preparer creates only a new owned workspace and returns ordinary build and
case arguments. It does not acquire dependencies, run a compiler/backend or
clean caller data. Complete source bytes, regular-file inventory, modes and
fresh destination boundaries are checked. A later preparer verification guard
also explicitly binds the added entrypoint's mode; the already recorded command
bytes and native runtime were unchanged.

```sh
python3 -I -B tools/gen-state-root-vectors/prepare_public_chain_foreign_startup.py \
  --node-source "$PINNED_COMPLETE_NODE_SOURCE" \
  --workspace "$NEW_OWNED_WORKSPACE" --go "$PINNED_GO"
```

Execute the returned build command once and each declared case once with a
separate empty owned directory. Use bounded foreground supervision and verified
offline dependencies. Initial limits are 240 seconds for the build, 90 seconds
per case and 4 MiB stdout. Reserve 2 GiB expected allocation in a configurable
3 GiB task quota, above a 10 GiB floor plus other allocations/reservations.
Preserve actual failures and incomplete outputs before deciding any next step.

The post-run private workspace contained 359,728,029 logical file bytes. This is
neither a peak measurement nor a physical APFS recovery claim. Source-reproducible
owned scratch was removed after terminal-process and complete-file checks;
protected input, binary, output and verification references were retained.
There is no recursive evidence ZIP or second artifact transport.

These portable checks execute no Go/node/database backend or network request:

```sh
python3 -I -B tools/gen-state-root-vectors/prepare_public_chain_foreign_startup_test.py -v
python3 -I -B tools/gen-state-root-vectors/check_public_chain_foreign_startup_test.py -v
python3 -I -B tools/gen-state-root-vectors/check_public_chain_foreign_startup.py
```

CI runs these source/recorded-byte controls on Linux, macOS Intel and Windows.
It does not repeat the actual Darwin ARM64 node experiment on those platforms.
Node/client profile agreement, actual chain transitions and recovery breadth,
realistic resource/hardware limits, independent review and authenticated
distribution remain separate M2–M5 gates. Runtime state-value acceptance and the
consumer result stay **REFUSED**. Storage tool changes are outside this change.
