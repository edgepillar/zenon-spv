# Bounded bundle input allocation comparison

The [content-hash change](content-hash-allocations.md) left the complete
file-loading path allocation-heavy. A subsequent local allocation profile of
`M100000_P4/LoadAndVerify` identified `io.ReadAll` buffer growth as the largest
flat allocation contributor, followed by JSON decoder buffers and decoded row
slices. This change addresses the raw input buffer only.

For a bounded regular file, the loader can now use its stat size to allocate
one input buffer with an extra EOF-probe byte. The common stable-file path
avoids repeated growth and copying of that buffer. Stat metadata does not
establish the input length: the reader still consumes through EOF or the
configured byte limit plus one overflow probe. A smaller file succeeds at its
actual length. If a file outgrows the hint, reading continues through the same
limited reader, including any later error or malformed suffix.

Only positive hints at or below the configured cap and 64 MiB are eligible for
eager allocation. The 64 MiB value is an optimization ceiling, not a new input
policy. Larger, negative, unavailable or oversized hints use the previous
incremental reader. Nonregular inputs also retain that path. A failed stat call
does not introduce a new refusal; the ordinary read still determines its result.
Nonpositive byte limits keep their documented legacy opt-out, and MaxInt64
limits retain the saturated overflow probe.

Non-EOF read errors take precedence even when returned with a complete JSON
document or the overflow byte. Failed reads expose no partial decoded bundle.
The byte cap still precedes JSON decoding. Whole-document syntax/nesting checks,
duplicate known-field aliases, per-proof and aggregate row limits, and all
verification rules are unchanged.

## Correctness evidence

`TestSizedBundleReadContract` compares the new reader with the previous
`io.LimitReader` plus `io.ReadAll` contract, independently of its allocation
strategy. It checks actual consumed bytes, exact refusal/error behavior, short
reads, stale hints, huge unusable hints, simultaneous data/errors and both
legacy and saturated limits. Document tests retain trailing-data, nesting,
duplicate-field and excess-row refusals, plus the regular-file loader's byte
and count checks. `FuzzSizedBundleRead` exercises the same differential contract
with bounded inputs, varied limits/hints and terminal read errors.

The existing six node corpora, independent Python checkers, hash implementation
and benchmark workloads are unchanged. The offline pilot includes the reader
contract as its 35th scenario. CI continues to run all 34 benchmark workloads
on native Linux/macOS/Windows as functional checks, without timing thresholds.

## Measurement method

The [full before/after records](bundle-read-samples.json) contain 80 benchmark
samples and 40 ordinary compiled-process observations. The baseline is the clean
preceding main revision, `f90b4439b9a0d0e56e5cb830489880471764f83d`.
The benchmark harness is identical between versions; the records pin its hash,
production-file hashes and each version's Go/module/JSON source fingerprint.
Documentation, CI configuration and Python checkers are outside that source
fingerprint scope.

Both runs use Go 1.25.14 on darwin/arm64, five 1-second samples per operation,
`-cpu=1`, no race instrumentation and no competing local builds/tests. Saved Go
settings and inherited GOFLAGS are disabled. Files are normally warm. Hardware
identity is omitted. Already-decoded verification is a control; `LoadAndVerify`
includes bounded file reading, decoding, verification and result checks. Input
construction and fixture setup are outside timing.

Five compiled CLI processes per workload separately record elapsed time and
whole-child-process peak RSS. Their ordinary runtime parallelism is retained;
parent fixture construction and builds are excluded.

```sh
go test -count=1 -run '^TestSizedBundleReadContract$' ./internal/proof
go test -run '^$' -fuzz '^FuzzSizedBundleRead$' -fuzztime=10s -parallel=2 ./internal/proof
go test -run '^$' -bench '^BenchmarkFlatContent$' -benchmem -cpu=1 -benchtime=1s -count=5 ./internal/conformance
go test -json -count=5 -run '^TestCompiledContentScalingWorkflow$' ./internal/conformance > ../bundle-process-events.json
```

Keep raw event streams and profiles private. Publish only reviewed, filtered
records. An allocation profile includes untimed setup and is useful for finding
contributors; its aggregate totals are not per-operation memory limits.

## Recorded comparison

- Before source fingerprint: `5330eaa50eeb3c8695a6b460a869c48dd67047763b81536c4af7d57865660eb2`.
- After source fingerprint: `f4a7cd1f010e13c50219bbe326a9e897435589df3ea6dd199b26c3995c29456c`.

The following values are medians. Allocation volume and whole-process RSS
are separate measurements; MB uses 1,000,000 bytes.

| Load-and-verify workload | Before B/op | After B/op | Before allocs/op | After allocs/op | Before ms/op | After ms/op |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `M1_P1` | 10,144 | 10,320 | 152 | 153 | 0.0265 | 0.0269 |
| `M1000_P1` | 2,193,784 | 1,655,112 | 5,194 | 5,177 | 3.7009 | 3.5074 |
| `M100000_P1` | 205,361,284 | 137,771,096 | 500,243 | 500,206 | 300.3576 | 329.7555 |
| `M100000_P4` | 707,469,040 | 450,397,888 | 2,000,447 | 2,000,404 | 1185.5567 | 1201.6433 |

The large single-proof path reduces allocated bytes by 32.9%; the four-proof
path reduces them by 36.3%, from 707,469,040 to 450,397,888 B/op. The tiny
476-byte workload adds 176 B/op and one allocation. The extra file metadata
operation therefore has a cost; this is a large-input allocation improvement,
not a claim that every workload gets cheaper or faster.

The already-decoded `Verify` controls retain the same allocation volume and
count in every workload. Local load-and-verify timing medians are mixed; the
large cases are slower in these samples. No latency improvement is established.

| CLI workload | Before elapsed ms | After elapsed ms | Before peak RSS MB | After peak RSS MB |
| --- | ---: | ---: | ---: | ---: |
| `M1_P1` | 6.411 | 7.402 | 10.994 | 10.977 |
| `M1000_P1` | 8.470 | 10.262 | 13.255 | 12.435 |
| `M100000_P1` | 317.429 | 327.184 | 98.288 | 94.536 |
| `M100000_P4` | 1233.781 | 1263.279 | 297.959 | 287.277 |

Peak RSS medians are lower in this local record, while process elapsed-time
medians are higher. These observations do not establish portable RSS savings
or attribute every timing difference to the reader. Keep the complete samples
and select target hardware/workloads before setting consumer resource budgets.

## Limits

The extra stat call can add overhead for small inputs. Stale hints can still
require buffer growth, and unsupported hints retain the previous allocation
behavior. These records concern the common bounded regular-file path, not a
guaranteed improvement for every reader or filesystem.

Allocated bytes per operation are cumulative allocation volume, not live heap
or peak RSS. JSON decoding and decoded row slices still allocate separately.
Whole-process RSS also reflects startup, GC and OS accounting; Windows peak RSS
remains explicitly unavailable. Five local samples do not establish portable
latency thresholds, a memory ceiling or a safe concurrency level.

This is bounded synthetic resource and serialization evidence. It changes no
wire format, accepted trust input, K/W retention rule, target binding, explicit
anchor/profile/schedule or context-pin boundary. It establishes no canonicality,
consensus finality, network activation, state-value proof or real-network
capacity. Consumer-selected trust inputs, target hardware observations and
independent release review remain external gates.
