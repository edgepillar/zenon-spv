# Selected devnet source-genesis identity

The maintained D0 source choice now has a recorded unsigned height-1 identity:
chain **69**, version **1**, momentum hash
`fab7609bae7fd78eb7d2b0d4a5023832f1a6730921b862f2415da25524698dc9`.
This is constructed from selected source, not observed or authenticated from a
running network. It does not install an anchor or accepting SPV profile.

## Recorded node construction

The node is
[`digitalSloth/go-zenon@938fca3`](https://github.com/digitalSloth/go-zenon/tree/938fca3b7787da86827a5eb63371509b36e14761),
Git tree `f3b7947d2267ebdb806f18ff0c02bba5bffae9c4`. All 484 original regular
source files were checked against their Git blobs. The unchanged
[`docker/devnet/genesis.json`](https://github.com/digitalSloth/go-zenon/blob/938fca3b7787da86827a5eb63371509b36e14761/docker/devnet/genesis.json)
is retained as [an exact configuration copy](../internal/testdata/conformance/selected-devnet-genesis-config.json):
8,137 bytes, SHA-256
`0dd33b18b147f70b3d3d5f07199a2b45311f6e9b84a98b3f86d8f6c6b45f419a`.
The configuration digest and momentum hash identify different byte sequences.

The [added lifecycle harness](../tools/gen-state-root-vectors/selected-devnet-genesis-lifecycle_test.go.txt)
called the original `CheckGenesis`, `NewGenesis` and real disk ledger/cache
managers. Two `Chain.Init` / `Stop` cycles reopened the same height-1 hash,
version and zero StateRoot. `Chain.Start`, network services, wallet, signing
and transactions were not selected. A Go 1.25.14 darwin/arm64 CGO execution
passed `TestSPVSelectedDevnetGenesisLifecycle`, with actual exit 0 and complete
output. Its 25 used modules were checked; the full historical module graph
remains `NOT_ESTABLISHED`.

The [small recorded corpus](../internal/testdata/conformance/selected-devnet-genesis.json)
binds the exact harness, source/archive identity, projected header, two cycles,
spork inputs and original execution/output/gate digests. These unsigned digest
references preserve integrity links; they do not authenticate distribution or
re-execute the private receipt chain. Earlier failed preparations remain failures.

## Independent byte replay

The standard-library Python reader reconstructs the 160-byte big-endian v1
preimage and computes SHA3-256 independently of the node and SPV. It also
hashes the configuration and harness bytes, checks the data hash against
`ExtraData`, and refuses altered source/execution/scope fields, malformed JSON,
integer widths, signature material and upgraded authority claims. The SPV's
native chain tests independently hash the same header and mutate every v1
preimage field. Version 1 excludes both v2 prices and StateRoot.

ContentHash and ChangesHash remain captured node outputs: these readers do
not independently rebuild genesis accounts, contract state or VM changes.
The source spork entries are configuration facts, not proof of activation.

```sh
python -I -B tools/gen-state-root-vectors/check_selected_devnet_genesis_test.py -v
python -I -B tools/gen-state-root-vectors/check_selected_devnet_genesis.py
go test -json -count=1 -run '^TestCandidateV3HeaderSelectedDevnetGenesis' ./internal/chain
```

These small replays reuse the completed native capture. They create no node,
database, module cache or second source archive. Linux/macOS/Windows CI runs
the replays; it does not turn reading the fixture into a new node execution on
those platforms. Native, source-scope and artifact qualification remain bound
to their actual revisions and executions.

To reproduce the node construction separately, prepare a new owned copy of
the exact node and verified dependencies. Add the harness exclusively as
`chain/genesis/spv_selected_devnet_genesis_lifecycle_test.go`, then run
`go test -mod=readonly -p 1 -json -count=1 -run '^TestSPVSelectedDevnetGenesisLifecycle$' ./chain/genesis`
with CGO enabled and network module fetching disabled. Preserve actual exits,
complete output and source/dependency bindings. Never point this harness at
live or historical data. Another invocation is separate evidence and is not
needed merely to replay the recorded preimage.

## Remaining D0–D3 gates

The [query contract](batch-entry-query-contract.md) still needs explicit actual
network identity, selected anchor/provenance, finite producer schedule and
profile/query inputs. The source-conditioned first-v3 expectation is height 3;
this H1-only run did not execute that transition. The separate chain-100
[boundary fixture](first-v3-node-boundary.md) does not qualify chain-69 activation.

An owned v3 profile needs an anchor at least at the predecessor boundary,
height 2 for that source expectation. H1 cannot supply it. Positive selected
network BatchEntry proof/consumer acceptance, canonicality, consensus finality,
state-value acceptance and production/release gates remain open.
