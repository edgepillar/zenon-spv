# Candidate RPC hash input bounds

The experimental candidate RPC object decoder accepts a hash only as exactly
64 lowercase hexadecimal characters. Its former field path decoded an entire
JSON string before checking that width, and encoded the decoded hash again to
check lowercase spelling. A long invalid token therefore created a proportional
decoded-string allocation despite the fixed 32-byte destination.

The field decoder now checks the encoded token length before string decoding.
Every accepted character is ASCII and can occupy at most six JSON bytes as a
Unicode escape, so `2 + 6 * 64 = 386` bytes covers every accepted spelling.
Whitespace is excluded only from that length calculation; the original bytes
still undergo JSON decoding. Non-JSON Unicode whitespace stays invalid.
Lowercase digits are checked directly, removing the re-encoding allocation.
The hash destination is assigned only after the complete scalar passes.

This shared path covers the candidate momentum's hashes and StateRoot, its
content-member hashes, candidate proof roots and other exact-schema candidate
objects. It does not change the generic `chain.Hash` text format, outer byte
budgets, JSON member policy, content order, header preimage, canonical hash
language, proof validation or root authority. The public candidate APIs still
discard their complete local result on an object error. The internal field
loop itself is not a transactional object decoder.

## Compatibility and bounded controls

The selected new controls exercise 24 scalar/object spellings, three oversized
token allocation cases, four hash fields in an unchanged recorded node header,
and four candidate proof-root cases. Fully escaped valid hashes at the exact
386-byte boundary remain accepted. Prefixes, uppercase, malformed JSON,
non-JSON whitespace, null/non-string values and altered widths remain refused.
Public header and proof decoders retain their fixed errors and empty results.
The standalone scalar refuses the oversized cases without allocating.

The source-bound recorded-header comparison consumes existing signatures; it
does not start a node or sign a new header. Race checks of the new selection,
affected-package vet and offline module integrity passed locally. Full-suite
Linux/macOS/Windows qualification belongs to each new revision separately.

## Finite function observations

Four fresh Go 1.25.14 processes on Darwin ARM64 ran in
baseline/current/current/baseline order, 100 iterations per benchmark case.
The same whole-object benchmark driver and inputs were used throughout. The
baseline overlay uses `candidate_v3.go` from
`d832fbf518388cb02f77f42821bc0b004a176a22`; helper-specific new tests are omitted
from that overlay. This identifies the implementation under comparison, not
execution of the complete historical checkout. Current implementation and
measurement-source digests are retained separately with actual process results.

| Object hash input | Baseline bytes/op | Current bytes/op | Baseline allocations/op | Current allocations/op |
| --- | ---: | ---: | ---: | ---: |
| Literal 64-character hash | 1,576 | 1,448 | 23 | 21 |
| Fully escaped valid hash | 2,328 | 2,200 | 24 | 22 |
| Uppercase refusal | 1,552 | 1,424 | 22 | 20 |
| Invalid 128-KiB literal | 793,344 | 662,112 | 28 | 25 |
| Invalid 32,768-character escaped token | 965,378 | 727,649 | 29 | 25 |

These cases save 128 bytes on the small object paths, about 128.16 KiB for the
large literal and about 232.16 KiB for the large escaped token. Object-level
figures still include JSON decoder buffers and RawMessage copies. The scalar
preflight is not a whole-response heap/RSS bound. Networking, header
authentication, proof checking, complete CLI processes and representative R1
workloads are outside this function comparison. Small-sample timing does not
establish a general latency or whole-CI improvement.

Reproduce current-source observations:

```sh
go test -race -count=1 -run '^TestCandidate(RPCHash|V3HashSpellings|StateWitnessHashSpellings)' ./internal/fetch
go test -run '^$' -bench '^BenchmarkCandidateRPCHashObject$' -benchtime=100x -benchmem -cpu=1 -count=3 ./internal/fetch
```

CI includes the new benchmark in the existing RPC-envelope observation command,
preserving its previous benchmark selection and three-iteration recipe without
adding another Go invocation. Hosted numbers retain their actual source and
platform labels; the local table is not substituted for them.

This is D2/C09 input preparation. Candidate roots remain untrusted, the actual
selected typed consumer exit stays open, and the separately reviewed fixture
source and component contracts remain fixed. No signing, network activation,
canonicality/finality, state-value or production resource guarantee follows.
