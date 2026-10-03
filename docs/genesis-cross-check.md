# Genesis observation cross-check

`tools/verify-mainnet-genesis` compares observations from selected RPC endpoints
with an expected mainnet genesis hash. With no `--expected` option, it uses the
same embedded hash returned by `verify.MainnetGenesis`. It never learns a new
trust root merely because peers agree.

```sh
go run ./tools/verify-mainnet-genesis \
  --peers https://peer-a.example,https://peer-b.example \
  --timeout 60s
```

At least two distinct configured endpoint strings are required. Every endpoint
must return the same complete, locally recomputed height-1 envelope through
`ledger.getMomentumsByHeight(1, 1)`. One unavailable or malformed endpoint fails
the cross-check; it cannot be omitted from the reported agreement. The header
must use mainnet chain ID 1, layout v1, and a zero previous hash.

An explicit `--expected <64-hex-hash>` replaces the default expected hash and
is identified as an explicit pin in the report. A `0x` prefix is supported;
empty, malformed, or all-zero values fail before RPC. An override does not
relax the mainnet genesis shape checks. Independently justify any override:
a value obtained from the same queried peers is not an independent trust root.

For an explicitly chosen custom network, use `--genesis-config <file>` instead
of `--expected`. The file uses the verifier's strict trust-root schema:

```json
{"chain_id": 3, "height": 1, "header_hash": "<independently authenticated 64-hex hash>"}
```

```sh
go run ./tools/verify-mainnet-genesis \
  --peers https://peer-a.example,https://peer-b.example \
  --genesis-config ./genesis.json
```

The example chain ID is illustrative. Select the actual network and authenticate
its genesis provenance independently before choosing peers. This option changes
both the chain ID and expected hash; it requires height 1, layout v1, and a zero
previous hash. It cannot be combined with an explicitly supplied `--expected`,
and repeated `--genesis-config` options are rejected. Empty, oversized,
ambiguous, or otherwise invalid files fail before RPC. File paths and raw loader
errors are omitted from diagnostics. The default remains the embedded mainnet
anchor; this command does not install a testnet default or change verifier state.

The [historical testnet corpus](conformance.md) exercises this opt-in path through
compiled local HTTP peers using an unsigned genesis constructed by a pinned node
from an unchanged, pinned historical configuration. It checks serialization and
explicit pin matching; it does not identify the genesis of a current public
testnet, authenticate that historical deployment, or complete a network pilot.

The timeout covers the overall RPC operation. Invalid peer configuration,
nonpositive timeouts, and positional arguments fail before requests. Environment
endpoints from `ZENON_SPV_PEERS` are supported but are not printed by help.
Runtime errors identify anonymous peers without endpoint credentials or query
parameters.

Stdout contains a report only after complete agreement, shape checks, and hash
matching. Failure exits with status 1 and does not emit a success report. A
stdout write error or short write also fails, although partial report bytes may
already be visible; consumers must check the exit status. Genesis is not treated
as a normally signed producer momentum: the report claims hash recomputation
and pin matching, not signature authorization.

This tool does not change the embedded anchor. Matching observations do not
authenticate endpoint independence, canonical history, finality, a header-version
activation profile, or a producer schedule. The code
and offline tests do not constitute a fresh live-network verification of the
historical mainnet value or its provenance.
