# Consumer context hash allocations

The reference query consumer streams the published context encoding into
SHA3-256. It reuses fixed eight-byte integer and 32-byte hash buffers instead
of building the entire encoded message and allocating a decoded buffer for
each checkpoint. Context validation, the encoding order, returned fingerprint,
expectation pin, query matching and trust allowances retain their existing
behavior.

Six explicitly synthetic vectors cover context schemas 1/2 with 0, 16 and
256 checkpoints. Each contains the complete encoded message and its independently
computed Python SHA3-256 digest. The selections include full-width unsigned
heights, leading-zero hash bytes, and absent/present protocol profiles.
`tools/check-consumer-context-hashes.py` also recomputes every context with
the existing independent Python encoder. Go controls check decoding and matching
of each selected digest, plus refusal of an unchanged pin after either an anchor
hash or schedule hash changes. These vectors authenticate no trust inputs.

## Observed allocations

One local Go 1.25.14 `darwin/arm64` benchmark process retained all 84 rows:
six contexts, two implementations and seven repetitions of 1,000 measured
operations. The previous complete function body is preserved in the test file
from base commit `754643b2076f25de98262bcee8d5cb8412f81561`.
Every measured operation checks the preselected digest. No failed measurement
was retried and no sample was filtered.

Both schemas produced the following allocation values in every repetition:

| Checkpoints | Previous B/op | Streamed B/op | Previous allocs/op | Streamed allocs/op |
| --- | ---: | ---: | ---: | ---: |
| 0 | 912 | 176 | 8 | 3 |
| 16 | 3,280 | 176 | 26 | 3 |
| 256 | 53,584 | 176 | 273 | 3 |

Streaming adds hash writes. For the v1 zero-checkpoint case, median function
time was 694.3 ns/op before and 769.8 ns/op after; timing varied by case and
repetition. The selected allocation values do not establish application
latency or capacity. Fixtures, JSON decoding, validation, file reads and process
startup are outside the timed loop. Whole-consumer heap, RSS, concurrency,
real traffic, target hardware, and production budgets remain unmeasured by
this function benchmark. Go and platform changes can change allocation values.

## Reproduce the bounded checks

Run the independent encoded-message check and the consumer controls:

```sh
python3 -I -B tools/check-consumer-context-hashes.py
go test -v -count=1 -run '^TestConsumerContextFingerprintVectors$' ./tools/consume-query-report
go test -count=1 ./tools/consume-query-report
go test -run '^$' -bench '^BenchmarkConsumerContextFingerprint$' \
  -benchtime=1000x -benchmem -cpu=1 -count=7 ./tools/consume-query-report
```

Native CI records the six byte checks, 18 Go controls and all 36 benchmark rows
per Linux/macOS/Windows job with three benchmark repetitions. Existing full
consumer, node-corpus and observer workflows continue checking the compiled
application. Benchmark values are observations, without a fixed timing
acceptance threshold. The [query consumer contract](query-report-consumer.md),
independent report-channel integrity, authenticated anchor/profile/schedule
inputs, human review and release acceptance remain separate requirements.
