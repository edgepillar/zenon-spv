# Detached header envelope copies

Retained-state snapshots, inspected headers and accepted incoming envelopes
previously allocated separate public-key and signature buffers for each header.
The independent full-capacity sequence model repeatedly inspects current and
predecessor states, making that ownership boundary a measurable allocation cost.

Each copied header now uses one private byte allocation for both fields. The
public-key and signature slices are disjoint and capacity-clipped. Mutating or
appending to either field cannot reach the other field, the input, another
header, another snapshot or another copy. Nil and non-nil empty slices retain
their original shape. There is no shared executable, signature, verification or
query-result cache.

Storage remains private to one header, rather than a complete retained window.
Keeping one key slice therefore does not retain every envelope in the window.
A key can retain its own header's signature storage (96 bytes together for a
normal 32-byte key and 64-byte signature). A smaller allocation count is not a
claim of lower total byte allocation, RSS, whole-CI latency or a representative
device budget.

`TestOwnedHeaderEnvelopeCopyReference` compares every field and byte with the
exact previous copier from `b4ef6d48aa9cabe8a6353cd8e42418ba072ad854`, including
nil, empty, boundary lengths, spare capacity and oversized structural inputs.
Separate controls exercise identical and overlapping inputs, mutation, append,
independent snapshots, unchanged context and accepted inclusion. A bounded fuzz
target covers arbitrary structural byte slices; it does not authenticate signed
headers. Allocation controls and benchmarks compare complete 32/64-byte envelopes
and K=7/256/4096 structural snapshots with the independent prior implementation.

A local darwin/arm64 run with Go 1.25.14, `-cpu=1`, 20 iterations and three
repeats recorded the following counts in every repeat. Fixture construction is
outside the benchmark loop. These are structural copy measurements, with no
signature verification, persistence, file I/O or consumer query in the loop.

| Copy | Prior allocations/op | Owned allocations/op | Bytes/op, both |
| --- | ---: | ---: | ---: |
| One 32/64-byte envelope | 2 | 1 | 96 |
| K=7 snapshot | 15 | 8 | 2,720 |
| K=256 snapshot | 513 | 257 | 90,112 |
| K=4096 snapshot | 8,193 | 4,097 | 1,441,792 |

The reference runs before the owned copier; this is not a counterbalanced
latency experiment. No whole-suite or whole-CI speedup follows from these counts.

The unchanged full-capacity model, extension ownership/concurrency, persistence,
node-derived byte conformance, complete root suites and exact-source candidate
artifacts remain required. This copy helper changes no header serialization,
signature validation, producer authorization, anchor/profile/schedule selection,
context pin, state-file encoding, retention policy or proof acceptance rule.

```sh
go test -race -count=1 -run '^TestOwnedHeaderEnvelope' ./internal/verify
go test -run '^$' -bench '^BenchmarkOwnedHeaderEnvelope' -benchtime=20x -benchmem -cpu=1 -count=3 ./internal/verify
```

Synthetic allocation inputs and green CI establish no executed network history,
canonicality, consensus finality, network activation, state-value acceptance,
independent review or authenticated distribution.
