# Explicit reference-gas source cohort

The experimental header and typed-query APIs accept two exact node revisions.
The header profile selects the node; the query context binds its corresponding
executor. Existing constants, fixtures, profile bytes and context fingerprints
keep their original meanings. There is no latest-source lookup or automatic
checkpoint migration.

This prepares D0-D3 source compatibility. It does not execute or qualify the
selected-network consumer, validate the new gas calibration or change the
production state-proof and irreversible-settlement gates.

## Source selection

The devnet's [7 November update](https://github.com/Zeno-L2/zeno-devnet/commit/cf1c9c0e0f0ca3b257bdbd019c5589c2c27f748f)
selects the reference-hardware gas prices and states that existing devnet data
needs a reset because receipt gas changes for every input.

| Source | Original cohort | Reference-gas cohort |
| --- | --- | --- |
| Devnet | `04dc0797f7bcc02e48e0acba3b0ac49df2d3289d` | `cf1c9c0e0f0ca3b257bdbd019c5589c2c27f748f` |
| Node | `938fca3b7787da86827a5eb63371509b36e14761` | `2835c436b197fece5c76adf4ba8dc1decca2e3ea` |
| Executor | `caeaf764270b1489a53c860c6006026af208f924` | `a14bf0e08dad8eabeb1a0e0add9bbaf1e2adac9f` |
| Contract SDK | `bc1548d75473797f24bb3eb79f5594969c596e39` | unchanged |

Recursive Git trees were reconstructed from the selected tree records. All
484 node archive files and all 339 executor archive files matched their Git
blobs, modes, sizes and independent SHA-256 file manifests.

| New source input | Identity |
| --- | --- |
| Node Git tree | `f89d645c7f5be85dfe10dc7a510d80df7965d22f` |
| Node source archive | 1,612,554 bytes; SHA-256 `76d974ab3588518dddf9ea5eb4032b43228f9a732d14006330477037a905884a` |
| Executor Git tree | `00323994f2165d6dc81da300eabe311ddb30cf43` |
| Executor source archive | 1,232,890 bytes; SHA-256 `5d8f116ad6b4dc09f37bdd5ad31f40938f3149c30b1ce4d8ba0f89cf9b2e9d1e` |

The complete node delta is one file, `vm/constants/settlement.go`: MaxInputGas
drops from 1,000,000,000 to 100,000,000, with explanatory comments. Header
encoding, trie/proof code, Settlement keys/ABI and source-field rules are
byte-identical. The executor delta changes gas pricing, charging and vectors;
its state-store/applier and domain definitions are unchanged. Equal source
bytes do not transfer an earlier revision's execution evidence.

The devnet update also selects TypeScript SDK
`75cd2565bd388c1df6b441bfcc1670e8da483c77` and console
`cce1847a6dadfcf89c08e047fb7357cc38be1271`. This change does not install or
execute either package, adopt the new console, or qualify their runtime.

## Actual original-source controls

New local execution used Go 1.25.14 on darwin/arm64 with CGO disabled:

- The unchanged node `common/trie/TestConformance` passed all 18 named cases,
  plus SHA3Sanity and its parent: 20 passed test events, zero failures/skips.
- The unchanged executor state suite passed its 16 original named cases. The
  existing isolated applier harness additionally executed CV-APPLY-1 and all
  three CV-APPLY-2 steps: 24 passed events in total, zero failures/skips.
- All four generated roots and all 15 complete proof byte strings matched
  independent Python bottom-up tree/proof construction. They also matched the
  retained original-cohort recording.
- All 823 original node/executor files matched their manifests after the
  executor run. Nineteen actually loaded external modules matched the selected
  go.sum through ZIP and expanded-directory h1 checks; directories were
  rechecked afterward. Full historical module-graph verification remains
  `NOT_ESTABLISHED`.

The executor's historical node requirement and relative replacement were
overridden only in a fresh task-owned Go workspace selecting the new node.
Original module files were unchanged. Two dependency/workspace preflight
failures remain recorded; the node pass inside the first failed attempt remains
distinct from its parent's failure. The already passed node test was not
repeated. Executor execution took 27.55 seconds; the post-command workspace
observation was 288,591,490 bytes, not a continuous peak or production budget.
The executor gate is SHA-256
`666fc16cf9911c2a0508fa0bd5dd51aa18a4bdb574b6bedf8b281a403ee1ae89`.

These tests exercise synthetic SMT inputs and the in-memory StateDiff applier.
They do not run WASM gas calibration, produce new network receipts, capture a
new first-v3 boundary or qualify a selected devnet lifecycle.

## Context separation and remaining work

`ExperimentalV3ReferenceGasNodeRevision` is an additional exact opt-in value.
It selects `ExperimentalBatchEntryReferenceGasExecutorRevision` for the query
context. The original exported constants keep the original source pair.
Unknown revisions, short names, branch names, tree IDs and mainnet remain
refused.

The exact revision bytes remain in the header and query fingerprints. A new
selection needs independently selected settings and new expected pins. An old
request, constructor pin or checkpoint cannot be reused with the new context.
The regression replays existing synthetic signed headers and three witnesses;
it does not relabel them as a capture from the new node. Independent Python
framing gives distinct header, single-row and three-row golden fingerprints.
Trusted-local checkpoint provenance, finite producer authorization and W/K
retention assumptions remain explicit.

The [owned experiment contract](../tools/owned-devnet-query/contract.json)
still selects the original cohort and original qualified binaries. Updating
that contract, its closed-parent oracle, source-specific artifacts and actual
devnet capture requires a separate coherent selection. Existing maintainer
feedback remains attached to its original sources. This implementation does
not dispatch an experiment, start services, sign inputs or migrate old data.

The next acceptance exit remains one actual header-bound BatchEntry/domain
context query under the selected devnet contract. Representative R1 data,
node recovery, independent review and authenticated distribution remain
separate gates.
