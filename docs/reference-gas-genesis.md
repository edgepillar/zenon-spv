# Reference-gas source H1 and manager lifecycle

The selected reference-gas node now has its own actual genesis-only execution
at `2835c436b197fece5c76adf4ba8dc1decca2e3ea`. It constructs the same unsigned
chain-69, version-1, height-1 hash as the original cohort:
`fab7609bae7fd78eb7d2b0d4a5023832f1a6730921b862f2415da25524698dc9`.
The equal result is observed from a new execution; the original recording and
its execution identities remain unchanged.

## Execution and preserved outcomes

The unchanged [lifecycle harness](../tools/gen-state-root-vectors/selected-devnet-genesis-lifecycle_test.go.txt)
ran `CheckGenesis`, `NewGenesis` and two real disk-backed `Chain.Init` / `Stop`
cycles on a newly created private ledger/cache/state directory. Both cycles
reopened H1 with the same hash, version 1 and zero StateRoot. The harness did
not call `Chain.Start`, start a network service, open a wallet or submit input.

| Input or result | Identity or observation |
| --- | --- |
| Node Git tree | `f89d645c7f5be85dfe10dc7a510d80df7965d22f` |
| Source archive | SHA-256 `76d974ab3588518dddf9ea5eb4032b43228f9a732d14006330477037a905884a` |
| Original files verified before/after | 484 |
| Public genesis bytes | 8,137; SHA-256 `0dd33b18b147f70b3d3d5f07199a2b45311f6e9b84a98b3f86d8f6c6b45f419a` |
| Harness bytes | 4,458; SHA-256 `1f2eb54d60b777ed73e6cebd1d1bcdff28a8a7536aa0f1617bad7fb36a3ee542` |
| Toolchain | Go 1.25.14, darwin/arm64, CGO enabled; Apple clang 21.0.0 |
| Actual native result | Exit 0, complete output, one test and package passed; no failures/skips |
| Native output | 23,716 bytes; SHA-256 `8f552843b9647cf43b405de5ca95d674e08fbe01c344d9a8d02b6128da88b6cc` |
| Used external modules | 25; ZIP and expanded-directory h1 checked against selected go.sum, directories rechecked afterward |
| Reconciled execution gate | SHA-256 `59550d5f45f770525aecbfd4b02d3399e5902e175f755a9aaef6dca12251a647` |

The complete worker sequence took 36.63 seconds. Its post-command workspace
observation was 291,898,609 bytes, not a continuous peak or production budget.
Full historical module-graph verification remains `NOT_ESTABLISHED`.

The first preparation failed before native execution because the local file
proxy lacked one dependency. Only the required 55,809-byte ZIP and 40-byte
module file were fetched and verified; they were supplied through the task's
private proxy without modifying the shared cache.

The successful native worker was followed by a controller JSON parsing failure:
the collector treated the opening line of pretty-printed `go env` output as a
complete line-delimited object. The actual exit-0 command, complete native
stream, module/source checks and completed workspace cleanup survived. A
separate reconciliation verified those bytes and extracted the complete test
stream. The controller remains recorded as FAILURE; the native test was not
repeated or its parent relabelled. Disposable new workspaces were removed and
source/output/failure evidence remains protected.

## Independent replay and remaining gates

The [new recording](../internal/testdata/conformance/reference-gas-devnet-genesis.json)
retains the new source and execution pins. The existing reader's default still
selects the original recording and preserves its output format. The explicit
`--cohort reference-gas` reader checks the second fixed recording and returns
its exact node revision. Equal H1 bytes cannot substitute either source's
execution metadata for the other source's metadata.

```sh
python -I -B tools/gen-state-root-vectors/check_selected_devnet_genesis_test.py -v
python -I -B tools/gen-state-root-vectors/check_selected_devnet_genesis.py --cohort reference-gas
go test -count=1 -run '^TestCandidateV3HeaderReferenceGasGenesis$' ./internal/chain
```

Python reconstructs the 160-byte v1 preimage with independent SHA3-256; Go
independently decodes/hashes the same recorded header. These replay commands
start no node or database and do not reexecute the native capture. ContentHash
and ChangesHash remain captured node outputs, not independently rebuilt VM
state. Source spork entries are configuration facts, not activation evidence.

H1 does not supply the required H2-or-later anchor, an executed first incoming
v3 boundary, a producer schedule or an accepted SPV state. The coherent
closed-parent-oracle/owned-runner source selection and actual header-bound
BatchEntry consumer remain separate work. This recording changes no network,
canonicality, consensus-finality, state-value or production acceptance gate.
