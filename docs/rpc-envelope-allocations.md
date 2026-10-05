# RPC envelope extension allocations

Unknown JSON-RPC extension members are accepted when they are valid JSON and
do not alias a known control field. The envelope decoder now discards these
values through a private `UnmarshalJSON` callback. Go's `json.Decoder.Decode`
scans and validates the complete value before invoking the callback, including
malformed strings, numbers, containers and excessive nesting. The callback
avoids the former `json.RawMessage` copy of an extension payload.

Required `jsonrpc`, `id`, `result` and `error` values still use temporary
`json.RawMessage` fields. Error `code`, `message` and `data` fields keep their
existing behavior. Duplicate control fields, escaped duplicate names, case
aliases, incorrect request IDs, ambiguous outcomes and trailing data still
fail before caller output is decoded. Unknown duplicate extension names remain
allowed. Parser errors do not echo peer field names or values.

The response body limit and the shared paginated response budget still count
every extension byte. This change removes a copy; it does not make the HTTP
body or the JSON decoder buffers disappear. A required large result or error
still has its own copies. The byte limit is not a whole-process memory bound,
and concurrent requests can multiply temporary allocations.

## Reproduce the observations

Run the ordinary fetch tests, then compare the current object decoder with
the preserved copy-based helper from commit
`d25b0cd690fff9baf5ed3b447d948662b50233fd`:

```sh
go test -count=1 ./internal/fetch
go test -run '^$' -bench '^BenchmarkRPCEnvelopeExtensions$' -benchtime=3x -benchmem ./internal/fetch
```

The benchmark builds synthetic 32 KiB, 1 MiB and 8 MiB metadata strings outside
the timed region, places them in a nested extension object and checks identical
retained control-field bytes on both paths. `B/op` and `allocs/op` describe one
object decode. Three iterations are a bounded allocation observation, not a
stable latency comparison, peak RSS measurement or end-to-end network result.
The `RPC envelope allocation observations` CI step runs on native Linux,
macOS and Windows. Use the exact tested source revision and job logs when
quoting measurements; the benchmark input is not node-supplied evidence.

Adversarial tests exercise malformed extension values in both the response
envelope and its error object, excessive nesting, large extensions next to
control failures, byte-budget edges and validation with a nil output target.
A loopback test wraps the existing captured account-block result in 1 MiB of
synthetic metadata, preserves its result bytes and recomputes the recorded
block hash. This checks parser transparency for that fixture. It adds no
independent provenance, canonicality, consensus finality, network activation,
producer authorization or state-value proof.
