# Signed-envelope hash allocations

Momentum and account-block hashes previously grew an initially empty slice
while appending signed fields, then allocated the digest through `Sum(nil)`.
The hasher now starts with a private stack buffer sized for the ordinary
envelope and uses the one-shot SHA3-256 API. Field order and encoding stay the
same: a v1 momentum hashes 160 bytes, v2 hashes 176 bytes, and an account block
with a valid amount hashes 306 bytes.

The account primitive still pads short absolute amounts to 32 bytes and never
truncates wider values. Its append operations can grow beyond the initial
buffer for those wider low-level inputs. RPC and segment verification still
reject negative amounts and amounts wider than the pinned node's 255-bit send
bound. Header verification still rejects unsupported versions and requires an
explicit v2 activation profile. No accepted input, digest, signature payload,
wire format, state schema, trust input or resource cap changes.

## Correctness evidence

`TestSignedEnvelopeHashSerializationContract` constructs preimages at fixed
byte offsets independently of the production append helpers, `HashHeight.Bytes`
and amount encoder. Its 17 cases cover v1/v2, unsupported low-level versions,
full-width integers, nil/zero/maximum-valid amounts, invalid negative and wide
amounts, unsigned fields, and shared immutable reads. The amount oracle uses
`big.Int.FillBytes` on a separate magnitude; the production encoder uses
`big.Int.Bytes`. Both byte oracles use the standard SHA3-256 API.

`FuzzSignedEnvelopeHashSerialization` compares bounded arbitrary inputs,
including the v2 suffix and positive/negative wide magnitudes, against those
oracles and checks input preservation. These checks exercise serialization;
they do not authorize invalid input. The existing node-derived hash/signature,
RPC-conversion and rejection tests remain unchanged, as do all six pinned
corpora and their independent Python byte/digest checks.

`BenchmarkEnvelopeHash` has four already-decoded workloads. Every timed hash
must match its expected digest from the go-zenon corpus pinned to
`3a4131e63881058b6ce2ee81d3a41d0033fafc99`. Decoding stays outside timing; the
successful-result check stays inside. CI runs all 38 benchmark workloads once
on Linux/macOS/Windows as functional checks, without performance thresholds.
The offline pilot includes this byte contract as its 38th scenario.

## Measurement method

The [complete sample record](envelope-hash-samples.json) contains 240 samples:
five before and five after samples for each of 24 operations. It includes the
four isolated hashes, eight existing native-client workloads, and 12 populated
K=16/256/4096 retention workloads. Both versions use the same added test and
benchmark harness on production base `267d2034d993a27ea389b070f047a30dce516dc9`;
only `header.go` and `account_block.go` differ. Production-file hashes, harness
hashes and source-input fingerprints are recorded. Source inputs stayed unchanged
throughout each measurement. The fingerprint scope excludes documentation and
CI configuration, as described in the record and offline-pilot source capture.

The local record uses Go 1.25.14 on darwin/arm64, five 500-ms samples per
operation, `-cpu=1`, ordinary builds without race instrumentation, disabled
ambient Go settings and no competing builds or tests. Hardware identity is
omitted. Retained-state files normally benefit from filesystem caching.

```sh
go test -count=1 -run '^TestSignedEnvelopeHashSerializationContract$' ./internal/chain
go test -run '^$' -fuzz '^FuzzSignedEnvelopeHashSerialization$' -fuzztime=10s -parallel=2 ./internal/chain
go test -run '^$' -bench '^(BenchmarkEnvelopeHash|BenchmarkNativeClient|BenchmarkRetainedCapacity)$' -benchmem -cpu=1 -benchtime=500ms -count=5 ./internal/conformance
```

Source-input fingerprints:

- Before: `22484f628894c92fae4c0cd27e9137d880b78bec8804566bd4e27f015f334da3`.
- After: `a14b3eb374f6ae4ac46e856309271d22d7537f596b8865aafe0e34b387c7f4e9`.

## Recorded comparison

Values below are medians. Allocation volume is cumulative allocated bytes per
operation, not live heap or peak resident memory.

| Isolated hash | Before ns/op | After ns/op | Before B/op | After B/op | Before allocs/op | After allocs/op |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Header v1 | 399.2 | 291.9 | 392 | 0 | 6 | 0 |
| Header v2 | 397.5 | 294.6 | 392 | 0 | 6 | 0 |
| Account, zero amount | 638.2 | 439.9 | 1,080 | 32 | 9 | 1 |
| Account, maximum valid 255-bit amount | 671.0 | 472.0 | 1,112 | 64 | 10 | 2 |

The remaining account allocations come from the existing amount encoder.
These local compiler/toolchain results do not impose a portable allocation
guarantee, and five samples do not establish a latency threshold.

| Complete operation | Before B/op | After B/op | Before allocs/op | After allocs/op | Before ms/op | After ms/op |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Nine v1 headers, claimed key | 8,744 | 5,216 | 77 | 23 | 0.269 | 0.268 |
| Five-block contract segment | 10,960 | 5,720 | 139 | 99 | 0.0132 | 0.0119 |
| K=4096 extend one | 2,491,722 | 2,491,328 | 8,217 | 8,211 | 0.504 | 0.510 |
| K=4096 trusted resume | 24,721,330 | 23,115,693 | 114,946 | 90,370 | 181.857 | 180.046 |
| K=4096 save | 22,332,370 | 20,726,780 | 86,082 | 61,506 | 152.629 | 150.709 |

The full K=4096 resume/save paths each allocate about 1.6 MB less per call and
avoid 24,576 allocations. Extension hashes one new header; it still copies the
retained window, so its allocation-volume reduction is small. The nine-header
verification median is essentially unchanged because signature verification
and state construction remain part of that workload. The full record also
retains unaffected summary/context/inclusion cases and smaller retention sizes;
some median times increase. No uniform timing improvement is claimed.

## Limits

These are synthetic local hash and retained-state workloads. They do not
measure cold storage, sustained watch traffic, network bandwidth/latency,
consumer-selected hardware, or a process-wide memory ceiling. Existing compiled
resource observations remain separate; this comparison does not attribute an
RSS improvement to the hash change. Node-derived hashes and green CI establish
neither canonicality, consensus finality, network activation, state-value proofs
nor real-network capacity. Consumer trust inputs, resource budgets and independent
release review remain external gates.
