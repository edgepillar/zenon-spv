# Query-report consumer resource observations

The native offline pilot measures the ordinary compiled
`consume-query-report` process against complete reports containing 1, 16 and
256 commitment targets. This covers the reference consumer's accepted batch
range. It does not measure a real application's traffic or establish a memory
or latency budget for a network pilot.

## Workload and measurement boundary

`TestCompiledQueryConsumerScaling` uses the 1,000-member sample in the pinned
node-derived [flat-content corpus](flat-content-resources.md). That fixture's
synthetic members are independently reconstructed and checked against the
node-produced content root. For one target it selects the last member; larger
batches select distinct evenly spaced members including the first and last.
The anchor, seven-header frontier, activation profile and operator schedule
are the existing explicitly synthetic workload inputs.

For each batch, the test prepares expectations from selected corpus identities
and settings before running the verifier. It runs a context-pinned retained
commitment query, captures the actual successful exit status and report bytes,
then runs the compiled reference consumer against those private regular files.
The consumer runs 21 times sequentially as a fresh process against the same
unchanged inputs and executable. Every process must match the entire batch with
actual exit 0, empty stderr and the exact fixed summary. No failed process is
retried, and no successful observation is dropped or selected as an outlier.
Saved state, report and expectations must preserve their bytes, file identity,
modification time and permissions after each run.

The measured interval starts before the consumer process starts and ends after
it exits. It includes startup, the two bounded file reads, strict decoding,
context-digest recomputation, target/guarantee/trust matching and fixed summary
output. Compilation, corpus expansion, proof-file generation, saved-state
construction, verifier execution and parent-side preservation checks occur
outside each interval. Parent-side allocations, the verifier's RSS and its
repeated flat-evidence input size are
not consumer resource measurements. The consumer makes no network requests.

Each batch contributes 21 ordered observations per pilot run, including the
first process. Input files have just been written and are reused; this is not a
cold-I/O benchmark. Startup, scheduling, filesystem caches, hardware and
operating-system accounting can dominate elapsed time. Retain all observations
when computing an empirical minimum, median or maximum; for 21 observations,
the median is the eleventh value after sorting a separate copy. The original
array preserves process order and contains no precomputed aggregate. This
small sequential sample does not establish population percentiles, statistical
independence, a monotonic latency curve, sustainable throughput, worst-case
latency or maximum memory. The tests do not exercise every legal
4 MiB document shape, concurrent consumers, long-running application state or
network delays. Native CI runners are not independently selected consumer
hardware.

## Bounded input-read allocations

The consumer uses the size of the validated open regular-file descriptor as a
buffer-allocation hint. A stable nonempty file normally needs one input buffer
with space for an EOF probe. Metadata does not select accepted bytes: a file
that grows or shrinks is still read to EOF through at most one overflow byte.
All buffer capacities stay within the selected input limit plus that byte.
An unusable hint falls back to bounded incremental growth. Read failures and
oversized inputs expose no partial bytes and retain the fixed
`input_unavailable` process result. Existing pathname, descriptor, FIFO,
strict-decoding and independently selected expectations checks still apply.
This does not authenticate files or close directory-replacement races.

`TestConsumerInputReadContract`, selected as `bounded_consumer_input_reader`
in the offline pilot, compares accepted bytes, refusals and reader consumption
with the previous `LimitReader` + `ReadAll` contract. It covers short reads,
simultaneous data/EOF or data/error, smaller/larger/unusable size hints, the
256 KiB and 4 MiB limits, one overflow probe and invalid limits before reading.
Complete, truncated and trailing document bytes reach the unchanged decoder.
The fuzz target uses the same independent bounded reference.

Native CI additionally preserves three ordinary allocation observations per
reader and size with `BenchmarkConsumerInputRead`. Sizes include the fixed
T1/T256 report and expectations byte counts (2,264/157,932 and 699/55,897),
plus both input caps. Repeated synthetic bytes isolate reading and do not
constitute a valid report or trust input. The previous reader and the new
descriptor-hint path must return the complete unchanged bytes on every
iteration. All 36 rows per native platform are retained without filtering or
retrying. `B/op` includes the in-memory reader and returned buffer; `allocs/op`
counts Go allocations. Neither field measures resident memory. Timing also
includes the identical complete-byte comparison. These reader observations
exclude filesystem calls, descriptor validation, JSON decoding, matching,
process startup and output. Use the existing 21-process series above for the
whole consumer boundary; reader allocation savings alone do not establish an
application latency or memory budget.

## Oversized-token refusal allocations

The strict consumer already refuses decoded strings above 4,096 bytes and
number tokens above 21 bytes. `json.Decoder.Token` can allocate a large token
before those checks. The consumer now applies an allocation-free necessary
condition before token decoding, after the existing UTF-8 check. An encoded
string cannot use more than six source bytes per accepted decoded byte; the
filter therefore allows up to 24,576 bytes between its quotes, including
escapes. The decoded 4,096-byte limit still applies afterward. Number tokens
retain the same 21-byte limit. Digits inside strings are not number tokens.
This filter neither validates JSON nor relaxes syntax, duplicates, keys,
numeric types/ranges, shape, context or matching checks.

`TestConsumerTokenPrefilter`, selected as `bounded_consumer_tokens`, compares
the full decoder with a test-only copy of the previous strict decoder. It
covers maximum escaped strings, control characters, multibyte UTF-8,
surrogate pairs and replacement runes, quote/backslash parity, numeric
boundaries, oversized tokens and fixed private process refusals. A differential
fuzz target compares decisions and destination values; neither decoder's
failure may become a match.

`BenchmarkConsumerTokenPrefilter` preserves three ordinary native observations
for each decoder and workload. It includes otherwise complete reports with
32 KiB, 1 MiB and 3 MiB oversized caveat strings or integer tokens, plus the
ordinary matching report and a matching report with a maximally escaped
4,096-byte caveat. Every document fits the 4 MiB input limit. Both decoders must
produce the same decision and destination values; valid cases must match the
independently prepared expectations. All 48 rows per platform are retained.
The reported `B/op` and `allocs/op` cover decoding and its result check, with
fixture construction outside measurement. They exclude input reading,
filesystem calls, process startup and output. Invalid workloads measure an
unchanged refusal, not useful query throughput. Valid-workload timing records
the extra byte-scan cost without establishing a latency budget. These are Go
allocation observations, not RSS or whole-process memory measurements.

## Borrowed shape traversal allocations

After the unchanged complete token/syntax, duplicate-key and resource scan, the
consumer checks exact field shapes over borrowed input spans. It no longer
copies nested encoded values into `json.RawMessage` maps and slices. Escaped
keys are still decoded before exact name matching. Required fields, optional
non-null references, nullable documented pointers and field-order independence
keep their previous meaning. The final `json.Unmarshal` owns scalar type/range
checks and destination construction, including its previous partial destination
behavior on a scalar error. The span traversal is not a standalone JSON parser;
the complete bounded token scan must precede it.

`TestConsumerShapeSpans`, selected as `bounded_consumer_shapes`, compares the
decoder with the parent entry point and the separately copied scan/RawMessage
shape reference. It includes decoded/unknown keys, quoted delimiters, nullable
and optional values, scalar failures, existing depth/array limits, input
preservation and fixed private process refusals. Its differential fuzz target
allows documents through the 4 MiB report cap.

`BenchmarkConsumerShapeSpans` retains three native observations for both
decoders at each of six complete workloads: the ordinary report, 256 distinct
targets with 256 small caveats, 256 caveats at the 4,096-byte decoded string
limit, 170 maximally escaped caveats close to the 4 MiB input cap, and both
large caveat documents with an unknown final field. Selected accepted reports
must still match the complete independently prepared expectations. All 36
rows per native platform are retained without retries or sample filtering.
Fixture construction is outside measurement. `B/op` and `allocs/op` cover the
decoder and decision/destination check; they are Go allocations, not RSS. Timing
also includes result comparison and, for accepted reports, contract matching.
Reading, files, process startup, output and network operations are excluded.
These samples cover selected legal and refused shapes, not every legal input,
worst-case resource use or an independently selected application budget.

## Artifact fields and validation

The `compiled_query_consumer_scaling` case in the
[offline report](offline-pilot.md) includes exactly three
`query_resource_samples` records:

| Field | Meaning |
| --- | --- |
| `workload` | Fixed identifier `T1`, `T16` or `T256`. |
| `targets` | Exact expected and matched target count. |
| `report_bytes` | Captured verifier diagnostic bytes, including its newline. |
| `expectations_bytes` | Independently prepared expectations-file bytes. |
| `elapsed_ns` | Whole interval of the first consumer process in nanoseconds. |
| `peak_rss_bytes` | Nullable native peak memory counter of that first process in bytes. |
| `peak_rss_source` | `process_rusage` on Linux/macOS, `windows_peak_working_set` on Windows, or `unavailable` elsewhere. |
| `observations` | Exactly 21 objects in execution order, each containing only `elapsed_ns`, `peak_rss_bytes` and `peak_rss_source`. |

Linux/macOS use the exited child's own `Rusage.Maxrss`, converting Linux KiB
to bytes. Windows retains a native observation handle before waiting and
reads `PeakWorkingSetSize` after exit; that counter has distinct semantics and
must not be silently compared with Unix RSS. Existing process-accounting tests
cover immediate and nonzero exit, resident allocation, cancellation and failed
start. Ordinary compiled children remain outside the test parent's race
instrumentation. Each case records hashes of both binaries it actually built.

The pilot accepts only fixed workload IDs, matching counts, positive byte sizes
within the consumer's 4 MiB/256 KiB input caps, elapsed time up to 60 seconds,
and the correct positive native memory counter for every observation. The
first object's three fields must equal the retained first-process fields.
Each encoded workload record is bounded to 16 KiB, with observation objects
bounded to 256 bytes. Duplicate, missing, unknown, null required or malformed
fields, short/long arrays and inconsistent first-process fields cannot yield
a complete measurement. Split Go test output events are reassembled only for
a recognized bounded record from the same active workload; missing final
fragments or completion before assembly cannot pass. Every record must come from its actively executing
matching subtest. A process failure prevents a complete series from being
emitted and remains a failed test/run; partial successes cannot become a
successful artifact. The shareable artifact contains no query identities,
context pins, paths or raw diagnostics.
The `observations` array is an additive schema-1 field; strict readers must opt
into it. These fields are separate from the verifier's `resource_samples`.

Use exact candidate and merged-main CI artifacts when reviewing a delivery.
Check source/input/corpus fingerprints, binary records, native runner identity,
completion and skipped-test counts alongside the samples. Green CI and matching
diagnostics do not authenticate trust inputs, prove canonicality or finality,
establish activation, or prove state values. The selected block observer's target
hardware and budgets, representative traffic, an authenticated report channel
and independent review remain external acceptance gates.
