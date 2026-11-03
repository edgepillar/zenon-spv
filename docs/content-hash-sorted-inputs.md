# Already ordered content hashing

Native flat-content inclusion still commits every member of the complete list.
After the [index-sort allocation change](content-hash-allocations.md), hashing
100,000 members still allocated an approximately 800 KiB index array even when
the input was already in canonical order.

The hasher now checks adjacent headers using the complete address, unsigned
height and hash ordering. If every adjacent pair is ordered, it hashes the
original list directly through the existing 60-byte encoder. The first
inversion selects the private index sort. The input's field name or a provider's
sortedness claim does not select the path. Duplicate rows remain committed once
per occurrence, and caller-owned headers remain unchanged.

Both paths hash every canonical row. There is no cached root, proof reuse,
deduplication, skipped signature or reduced work limit. Arbitrarily ordered
content remains legal. These resource changes supply no additional authority
for the root, anchor, producer schedule, profile or verification context.

## Correctness and workload coverage

The existing serialization contract independently encodes and sorts byte rows.
It now includes ordered full-width field boundaries and swaps at each adjacent
position, including duplicate rows. Existing empty-input, known-root,
permutation, duplicate and shared-reader checks remain.

Five content-hash roots and 19 subtests passed under the race detector on the
declared local host. The RPC/common-hasher parity test also passed. All four
`TestNodeContentScaling` workloads passed, including the 100,000-member,
four-proof case, changed content, missing targets and aggregate decode/preflight
limits. Its repeated full lists and wire sizes are unchanged.

The independent Python reader checked 101,001 node-derived content members and
21 momentum preimages. A requested five-second fuzz session checked 170,216
inputs against the independent serialization oracle; its reported test elapsed
time was 6.205 seconds. Affected-package vet and root-module verification passed.
These are local source/serialization observations, not a new execution of the
reference node or a real-network consumer experiment.

## Local allocation comparison

The [complete sample record](content-hash-sorted-samples.json) retains all 80
benchmark samples, medians and source/receipt digests. Both ordinary binaries
were built once with the same added tests and benchmarks. Only the baseline's
production `content_hash.go` was replaced with the file from
`cbc6d9edd245653acbbccdf1bb4df88cc3dc8bcb`.

The selected host was Go 1.25.14 on darwin/arm64. Five paired rounds alternate
baseline/candidate order, use `-cpu=1` and `-benchtime=200ms`, and exclude fixture
construction from benchmark timing. Every sample must match the same pinned
node root and preserve its input ordering. `LastSwap` exchanges the final two
members so the complete ordered prefix must be checked before fallback. The
other orders are sorted, reversed and PCG(1,2)-shuffled.

| Members | Order | Before ms/op | After ms/op | Before B/op | After B/op | Before allocs/op | After allocs/op |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 1,000 | Sorted | 0.0694 | 0.0661 | 8,224 | 32 | 2 | 1 |
| 1,000 | Reversed | 0.0690 | 0.0691 | 8,224 | 8,224 | 2 | 2 |
| 1,000 | Shuffled | 0.1160 | 0.1214 | 8,224 | 8,224 | 2 | 2 |
| 1,000 | LastSwap | 0.0686 | 0.0716 | 8,224 | 8,224 | 2 | 2 |
| 100,000 | Sorted | 6.6815 | 6.6155 | 802,848 | 32 | 2 | 1 |
| 100,000 | Reversed | 6.7498 | 6.7952 | 802,848 | 802,848 | 2 | 2 |
| 100,000 | Shuffled | 20.6071 | 21.1992 | 802,848 | 802,848 | 2 | 2 |
| 100,000 | LastSwap | 6.7937 | 7.0021 | 802,848 | 802,848 | 2 | 2 |

The primary measured gain is removal of the index allocation for ordered input.
Timing gains are small there, while fallback median times are up to about 4.7%
higher in this finite comparison. Keep those costs visible: the ordered check
adds work before a late inversion, and these samples establish no portable
latency guarantee. B/op is cumulative allocation volume, not peak RSS, retained
disk, a whole-CLI memory ceiling or a whole-CI speedup. JSON decoding and the
complete repeated-proof wire format retain their existing costs.

## Execution and retention boundaries

An initial direct conformance launch used the module root instead of its package
directory and could not find the relative fixture. The corrected native case
passed; a following isolated Python invocation then lacked its sibling import
path. Both actual exit-1 attempts remain failures. The corrected reader supplied
the explicit trusted sibling path. The already built binaries and successful
race, RPC and native-scaling phases were reused rather than repeated.

New qualification used bounded owned scratch and an offline verified module
proxy, with zero new dependency network downloads. Actual outputs, source and
binary bindings and failures remain protected by reference. Closed disposable
workspaces were removed after identity/inventory and open-handle checks; physical
APFS reclaim was not measured. Historical data and storage-tool code were not
changed. Unsigned receipt digests do not authenticate their origin.

```sh
go test -race -count=1 -run '^TestMomentumContentHash' ./internal/chain
go test -count=1 -run '^TestContentHashOf_ParityWithChainMomentumContentHash$' ./internal/fetch
go test -count=1 -run '^TestNodeContentScaling$' ./internal/conformance
go test -run '^$' -fuzz '^FuzzMomentumContentHashSerialization$' -fuzztime=5s -parallel=2 ./internal/chain
go test -run '^$' -bench '^BenchmarkContentHashOrdering$' -benchmem -cpu=1 -benchtime=200ms -count=5 ./internal/conformance
```

Existing hosted native suites and benchmark smoke select the extended tests on
Linux, macOS and Windows. A local pass does not qualify a hosted revision or
artifact; their exact-source outcomes must be verified separately. Selected
devnet activation, canonicality, consensus finality, state-value acceptance,
representative R1 budgets and independent release review remain separate gates.
