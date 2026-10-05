# Optional RPC Base64 allocations

RPC public keys and signatures pass through an optional Base64 decoder. Empty
strings still return nil; ordinary inputs up to 4 KiB use the previous standard
`DecodeString` path. Larger inputs are scanned for CR/LF, which the standard
Base64 decoder ignores. When those bytes are present, they are excluded from
the decoded-output capacity calculation. The original string reaches the
standard decoder, including its line endings and any malformed characters.
Partial output bytes, corruption offsets, padding behavior and nil versus empty
results retain their previous meanings. Other whitespace is not discarded.

This threshold selects an allocation strategy. It does not change accepted
signature lengths, envelope validation, proof policy, context pins, or HTTP
response/range limits. Large decoded values still require storage, and JSON,
transport and caller allocations remain. Every wire byte, including JSON-escaped
line endings, still consumes the response budget. Returned bytes are owned by
the call and are not shared through a scratch pool.

## Reproduce the observations

```sh
go test -race -count=1 ./internal/fetch ./tools/offline-pilot
go test -run '^$' -bench '^BenchmarkRPCOptionalBase64$' -benchtime=3x -benchmem ./internal/fetch
go test -run '^$' -fuzz '^FuzzRPCOptionalBase64MatchesReference$' -fuzztime=10s ./internal/fetch
```

The benchmark preserves the exact helper body from
`b7b9857776ce9352017bb3ead19702aaca41cd73` in tests, with its name changed.
It loads the existing captured account public key and signature. Synthetic
0/32 KiB/1 MiB/8 MiB CR/LF prefixes are prepared outside the timed region;
every iteration requires the same decoded fixture bytes. These prefixes
exercise adversarial allocation behavior and are not representative observed
node traffic. The ordinary inputs give a separate small-field comparison.
Native Linux, macOS and Windows CI retain all 16 observations per platform.

`B/op` measures cumulative allocation for this decoding step, and three
iterations provide a bounded observation. Timings can differ by platform and
do not establish a universal speedup. These results are not peak RSS, complete
fetch/verification cost, live-network throughput, concurrency capacity or a
consumer hardware budget.

The offline contract checks threshold boundaries, line endings within Base64
quanta and next to padding, malformed inputs and partial error results, owned
concurrent outputs, exact response-budget edges, private conversion failures,
and transparent conversion of the captured signed account and all 21 pinned
node-derived v1/v2 momentum vectors. The original corpora remain unchanged.
This compatibility and resource evidence adds no network activation,
canonicality, consensus finality, producer-election or state-value guarantee.
