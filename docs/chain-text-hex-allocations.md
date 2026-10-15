# Hash and address text buffers

Fixed-size hash and address text conversion now uses one output buffer when
encoding and a private fixed-size value when decoding. The old encoder created
a hex byte buffer, a string and another byte buffer. The old decoder copied the
input to a string and allocated the decoded bytes. These conversions occur for
every member of a flat-content bundle, including every repeated proof list.

This changes allocation work. Hashes remain 32 bytes, addresses remain 20 bytes,
and JSON still emits lowercase hex. Decoding still accepts uppercase digits and
an optional lowercase `0x` prefix, with the same length checks and error values.
An uppercase `0X` prefix remains invalid. Decoding uses a private value because
`hex.Decode` can write a partial prefix before reporting an invalid digit; the
receiver changes only after complete success. Input bytes remain unchanged.
There is no shared buffer, cache, deduplication or evidence alias.

## Correctness and observations

`TestChainTextHexContract` retains the exact four previous codec bodies from
`ed5bc3ec7030c33bfa91a2eb58abb379744c0cf6` as test-only references. An additional
nibble oracle constructs expected hex without either encoder. It checks all
256 values at each raw byte position (13,312 cases), all 256 byte values at each
encoded position with and without a prefix (53,248 cases), and 236 length
cases. Invalid late digits, NULs, non-ASCII bytes, malformed UTF-8, prefix
spellings, unchanged receivers on failure, independent returned buffers and
JSON conversion/null behavior remain explicit checks. The fuzz target compares
arbitrary bounded input with the pinned decoders.

`BenchmarkChainTextHex` compares the references with the new buffers at 20,000
iterations per sample, three samples per row and one benchmark CPU. Native CI
runs the finite controls and all eight benchmark rows on Linux, macOS and
Windows; timings have no acceptance threshold. Allocation counts are scoped
to those conversion calls, not a whole verifier or process-memory budget.

The initial local Go 1.25.14 darwin/arm64 observations were:

| Operation | Reference B/op | Buffers B/op | Reference allocs/op | Buffers allocs/op |
| --- | ---: | ---: | ---: | ---: |
| Hash encode | 192 | 64 | 3 | 1 |
| Hash decode | 96 | 0 | 2 | 0 |
| Address encode | 144 | 48 | 3 | 1 |
| Address decode | 72 | 0 | 2 | 0 |

The existing [flat-content grid](flat-content-resources.md) still reconstructs
the same node-derived roots, repeats each full wire list and checks all target,
tampering and budget boundaries. Cryptographic verification, workload sizes,
retained capacity, signatures, activation profiles, producer schedules and
context pins are unchanged. Neither these observations nor green CI establish
canonicality, finality, network activation, state-value proofs or a production
resource limit.

## Reproduce

Use cached dependencies and a bounded owned temporary workspace for build
caches and test output. Keep raw Go event streams private.

```sh
go test -race -count=1 -run '^TestChainTextHexContract$' ./internal/chain
go test -run '^$' -fuzz '^FuzzChainTextHexContract$' -fuzztime=5s -parallel=2 ./internal/chain
go test -run '^$' -bench '^BenchmarkChainTextHex$' -benchtime=20000x -benchmem -cpu=1 -count=3 ./internal/chain
go test -race -count=1 -run '^TestNodeContentScaling$' ./internal/conformance
```
