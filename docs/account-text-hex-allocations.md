# Account nonce and token text buffers

Nonce and token-standard text conversion uses one explicit output buffer for
encoding and a private fixed-size value for decoding. Decoding no longer needs
a temporary string or decoded byte slice. Nonces remain 8 bytes and token
standards remain 10 bytes. There is no shared buffer or evidence cache.

Wire behavior is unchanged: lowercase hex output, uppercase digit acceptance,
an optional lowercase `0x` prefix, exact length errors, and the same invalid
digit errors. An uppercase `0X` prefix remains invalid. A decoder commits its
private value only after success, because `hex.Decode` can partially write
before failing. The caller's input and failed receiver remain unchanged.

`TestAccountTextHexContract` retains the four old codec bodies from
`4a1d03e06c848edebcf611e964e84967d85679d1` as independent references. The shared
[text-codec controls](chain-text-hex-allocations.md) also construct expected
bytes with a separate nibble oracle. The additional finite coverage is:

- 4,608 raw byte-position/value cases;
- 18,432 encoded byte-position/value cases with and without a prefix;
- 100 length cases, plus explicit malformed prefix and whitespace cases;
- late invalid digits, NULs, non-ASCII bytes, malformed UTF-8, receiver atomicity,
  input preservation, independent output buffers, and JSON/null behavior.

`FuzzAccountTextHexContract` compares arbitrary bounded input with the retained
decoders. `BenchmarkAccountTextHex` compares both encoders and decoders against
the references in the same process: 20,000 iterations, three samples, one
benchmark CPU. The existing CI steps include these controls and observations on
Linux, macOS and Windows without reducing any existing workload or checks.
Allocation measurements apply only to these codec calls. They do not establish
whole-query latency, peak RSS, disk savings, or a production resource limit.

Initial local Go 1.25.14 darwin/arm64 observations, identical across three
samples for each row:

| Operation | Reference B/op | Buffers B/op | Reference allocs/op | Buffers allocs/op |
| --- | ---: | ---: | ---: | ---: |
| Nonce encode | 16 | 16 | 1 | 1 |
| Nonce decode | 8 | 0 | 1 | 0 |
| Token-standard encode | 24 | 24 | 1 | 1 |
| Token-standard decode | 16 | 0 | 1 | 0 |

The compiler already avoids the short encoder's intermediate allocations in
this measurement. The measured allocation reduction is in decoding. Timing
samples have no acceptance threshold and do not predict whole-query savings.

```sh
go test -race -count=1 -run '^Test(Chain|Account)TextHexContract$' ./internal/chain
go test -run '^$' -fuzz '^FuzzAccountTextHexContract$' -fuzztime=5s -parallel=2 ./internal/chain
go test -run '^$' -bench '^BenchmarkAccountTextHex$' -benchtime=20000x -benchmem -cpu=1 -count=3 ./internal/chain
```

Use an owned bounded workspace and cached inputs for local qualification.
Signing fields, account hashes, proof budgets, profiles, retained depth and
producer authorization are unchanged. These codec controls do not establish
network activation, canonicality, consensus finality or state-value acceptance.
