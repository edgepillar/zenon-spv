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

## Decode directly into the retained window

Decoding each header into its zero-initialized slot in the private window
removes a temporary allocation per row. The count guard still runs before
decoding each row, and the decoded window is published only on success.

The same structural benchmark was run against `dea3d39` and this change on
darwin/arm64 with Go 1.25.14 and `-cpu=1`. The values below are medians from six
paired trials of six iterations, alternating which revision ran first.

| Headers | Baseline B/op | Direct B/op | Baseline allocations/op | Direct allocations/op |
| --- | ---: | ---: | ---: | ---: |
| 16 | 27,476 | 23,380 | 232 | 216 |
| 256 | 403,536 | 338,000 | 2,876 | 2,620 |
| 4,096 | 8,020,053 | 6,971,479 | 45,123 | 41,027 |

The timing ranges overlapped at all three capacities. The allocation figures
measure the structural decoder.

The retained-capacity sequence also compares saved state in 32 KiB chunks and
checks EOF after read-only resumes. Each of the 18 cells still runs all 20
operations. Across the selected 132 controls in one paired run, sampled
allocations attributed to `os.readFileContents` were about 242 MiB before the
change and 80 MiB after it. The samples include reads from the complete loader.

```sh
go test -race -count=1 -run '^TestStreamedStateWindow' ./internal/verify
go test -run '^$' -bench '^BenchmarkStreamedStateWindow/' -benchtime=3x -benchmem -cpu=1 -count=3 ./internal/verify
go test -run '^$' -fuzz '^FuzzStreamedStateWindow$' -fuzztime=10s ./internal/verify
```

## Bound large window growth

From 512 decoded headers, the reader grows the private backing slice by up
to twice its length, capped by the requested count bound and the maximum
explicit capacity of 4,096. A full 4,096-header window reaches that capacity
exactly, so trusted resume can keep the slice when the selected capacity is
unchanged. A larger legacy window continues to grow on demand under the
persistence count limit. The writer passes each existing header by address to
the JSON encoder and emits the same indented bytes.

Three paired darwin/arm64 trials used Go 1.25.14 and six iterations per
benchmark at `-cpu=1`. The baseline used the reader and writer from `1d150cc`.
These are median allocation totals for the structural benchmarks at K=4096.

| Operation | Baseline B/op | Updated B/op | Baseline allocations/op | Updated allocations/op |
| --- | ---: | ---: | ---: | ---: |
| Decode from JSON | 6,971,477 | 5,087,314 | 41,027 | 41,024 |
| Encode to a discard writer | 2,395,416 | 1,346,790 | 24,597 | 20,500 |

The full K=4096 sequence was also run three times per revision on the same
machine. Its median test time was 4.95 s before and 4.93 s after. The samples
do not establish a CI or device speedup. The regression controls check that
4,096 decoded headers fit exactly and that bounded growth honors a lower
configured count. Existing independent JSON and signed resume controls cover
file bytes, signatures, producer authorization and trust configuration.

The complete unchanged sequence models, native root suites, node-derived byte
conformance and exact-source artifacts remain required. Synthetic parser and
allocation controls establish no real network history, canonicality, consensus
finality, activation, state-value acceptance, independent review or authenticated
distribution. Experimental v3 and production state-proof acceptance gates remain
separate.
