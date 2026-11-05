# Incremental retained-state decoding

The native v1/v2 state loader previously asked its top-level JSON decoder to
buffer the complete `retained_window` value. The window's custom decoder then
read the same array with a second decoder. A local race/atomic-coverage CPU and
allocation profile of all 18 full-capacity sequence cells identified state
loading as a substantial cost; sampled `encoding/json` decoder-buffer growth
accounted for about 311 MB as labelled by the profiler over that diagnostic run.
Sampling, race machinery,
fixture construction and repeated test observations prevent interpreting this
as a production memory or device-latency budget.

The state-object decoder now consumes the bounded window value directly. Each
header still uses the existing header decoder. The standalone window decoder
also retains its end-of-input check; the nested value reader leaves the enclosing
object and end-of-input checks to the state-object decoder. This removes one
whole-array decoder buffer, rather than making file loading fully streaming.
The capped input bytes, decoded headers, individual JSON values and metadata
can still occupy memory.

The same rules remain in force: array-or-null shape, nil/empty distinction,
header count before decoding the next row, duplicate known-field refusal after
Unicode case folding and unescaping, compatible unknown fields, complete JSON
syntax, and publication of the decoded state only on success. Persistence
versions 1/2/3 keep the same schema and encoding. Complete header hashes,
signatures, links, checkpoints, anchor/profile matching and producer schedule
authorization still run before a requested smaller capacity can evict evidence.
There is no verification-result or signature cache.

`state_window_stream_test.go` contains the frozen preceding decoder from
`8ada23c4614de8d2770958304076d1ff834d9c1a`, with its source hashes. It compares
field values and refusal outcomes across field order, all three persistence
schemas, nil/empty arrays, v1/v2 structural headers, escaped/case-folded names,
unknown nested fields, malformed delimiters, duplicate fields and trailing data.
Other controls retain the count guard and exercise signed trusted resume and
corruption of a header that a smaller selected capacity would evict. The bounded
fuzz target compares the new parser with the independent preceding parser.

The structural benchmarks construct their inputs outside the loop and decode
K=16/256/4096 windows, including header keys/signatures and v2 prices. They
perform no signature verification, file I/O, persistence or consumer query.
Their allocation observations do not establish RSS, end-to-end latency or a
whole-CI speedup. The preceding decoder runs first; timing is not counterbalanced.

A local darwin/arm64 run with Go 1.25.14, `-cpu=1`, three iterations and three
repeats observed the following allocation ranges. These measurements call the
state object's `UnmarshalJSON` method directly; they exclude the input read and
the outer `json.Unmarshal` syntax pass used by the complete loader.

| Headers | Prior B/op | Incremental B/op | Prior allocations/op | Incremental allocations/op |
| --- | ---: | ---: | ---: | ---: |
| 16 | 58,626–58,642 | 27,472–27,488 | 244 | 232 |
| 256 | 926,210–926,237 | 403,536 | 2,892 | 2,876 |
| 4,096 | 16,407,048 | 8,020,048–8,020,053 | 45,143 | 45,123 |

At K=4096 this structural parser observation allocates about 51% fewer bytes.
It is not a measurement of the complete loader's memory use or elapsed time.

```sh
go test -race -count=1 -run '^TestStreamedStateWindow' ./internal/verify
go test -run '^$' -bench '^BenchmarkStreamedStateWindow/' -benchtime=3x -benchmem -cpu=1 -count=3 ./internal/verify
go test -run '^$' -fuzz '^FuzzStreamedStateWindow$' -fuzztime=10s ./internal/verify
```

The complete unchanged sequence models, native root suites, node-derived byte
conformance and exact-source artifacts remain required. Synthetic parser and
allocation controls establish no real network history, canonicality, consensus
finality, activation, state-value acceptance, independent review or authenticated
distribution. Experimental v3 and production state-proof acceptance gates remain
separate.
