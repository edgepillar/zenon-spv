# Mainnet genesis cross-check

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
authenticate endpoint independence, canonical history, or finality. The code
and offline tests do not constitute a fresh live-network verification of the
historical mainnet value or its provenance.
