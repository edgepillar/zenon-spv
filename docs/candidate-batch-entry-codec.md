# Candidate BatchEntry ABI decoding

`proof.DecodeCandidateBatchEntry` converts one bounded byte value into detached,
untrusted data using the selected node's 17-field Settlement `batchEntry` schema.
It does not check an SMT proof, authenticate a header/root/key/context, interpret
Settlement state or enable `VerifyStateValue`. D2/D3 acceptance remains open.

The [query contract](batch-entry-query-contract.md) still requires an owned
accepted v3 header, locally selected address/domain/batch, agreed profile and
root-bound proof before any accepted consumer can use the decoded fields.
The existing [key/path helpers](candidate-batch-entry-key.md) remain separate.

## Source and original-node bytes

The schema and packing are pinned to
[`digitalSloth/go-zenon@938fca3b7787da86827a5eb63371509b36e14761`](https://github.com/digitalSloth/go-zenon/blob/938fca3b7787da86827a5eb63371509b36e14761/vm/embedded/definition/settlement.go).
The [recorded cases](../internal/testdata/conformance/batch-entry-abi.json)
bind the Git root tree and the blob/SHA-256 identities of the Settlement,
argument, pack and unpack sources. The added
[capture harness](../tools/gen-state-root-vectors/batch-entry-abi_test.go.txt)
was executed against otherwise unchanged original node sources.

`TestSPVBatchEntryABIEncoding` passed all seven packing/unpacking cases locally
on darwin/arm64, Go 1.25.14, with CGO disabled. An independent Python encoder
matched every complete output byte. Cases include empty dynamic values,
ordinary fields, 31/32/33-byte payload boundaries, unsigned-width maxima and
an explicitly non-UTF-8 ABI string. They are synthetic structural values;
zero/maximum protocol, mode or state numbers are not asserted to be valid
ledger rows. No chain, RPC server, wallet or network transaction was started.

Execution record: SHA-256
`6e2a600c4ef659f3b5b310e7b41f5224417f46b12e6e9ca46699f821792d53c8`.
Gate: SHA-256
`7d5296b8a9a6a03f67a72ea6fc92d10ef89da4b95fcef7d0ee75b052dd7ef99f`.
All 21 actually loaded modules matched the selected `go.sum` through independent
ZIP and expanded-directory h1 checks, repeated for directories after the test.
Full historical module-graph verification remains `NOT_ESTABLISHED`.

## Explicit local policy and bounds

The decoder uses 17 words of 32 bytes: a 544-byte head followed by three
length-prefixed, word-padded tails in schema order. The minimum complete value
is 640 bytes, including empty tails.

| Limit or choice | Required behavior |
| --- | --- |
| `MaxValueBytes` | Explicit 640–4,096-byte whole-value cap, checked before parsing |
| `MaxExecutorPillarBytes` | Positive unpadded string-byte cap no larger than the whole-value cap |
| `MaxAssetFlowSummaryBytes` | Positive unpadded payload cap no larger than the whole-value cap |
| `MaxProofDataBytes` | Positive opaque proof-data cap no larger than the whole-value cap |
| `MaxDynamicBytes` | Positive cumulative unpadded payload cap for all three tails |
| `StringRule` | Explicit opaque byte-string or UTF-8 interpretation; zero/unknown choices refuse |

The 4,096-byte ceiling matches the existing candidate SMT research-work ceiling.
It is not a measured BatchEntry maximum, accepted network limit or permission
to enlarge a witness budget. A row outside the chosen bounds returns no value.
The decoder makes dynamic output copies only after every structural check.

Canonical layout requires all unused unsigned-integer bits to be zero, exact
contiguous tail offsets, complete lengths, zero padding and no trailing bytes.
Aliases, reordered/gapped/unaligned tails and offsets into the head refuse.
Lengths are bounded before conversion to native integers or copying payloads.

These are explicit candidate rules. The original unpacker's low-byte integer
reads and dynamic access checks do not establish this complete canonical policy
for the network. A selected accepting query must agree its encoding and string
rules separately. Opaque mode preserves the original string bytes; UTF-8 mode
rejects the non-UTF-8 recorded case. Neither mode validates pillar-name rules.

`ProtocolVersion`, `DaMode` and `State` stay uninterpreted numbers. The decoder
does not enforce sequence ordering, height relationships or domain/runtime
identity. It exposes no `IsFinalized` or release/receive decision. `ProofData`
is opaque data, not an accepted execution proof.

## Checks and reproduction

```sh
go test -json -count=1 -run '^TestCandidateBatchEntry' ./internal/proof
```

The native controls compare all 17 decoded fields with original-node inputs;
exercise every truncated prefix; reject width overflow, bad offsets/lengths,
padding and trailing data; enforce individual/cumulative caps and explicit
string choices; and check that mutable outputs do not alias input or each other.
Failures return a zero value, including late-tail failures.

To reproduce the original packing scope, use a new isolated task-owned copy of
the exact pinned node with verified dependencies. Exclusively copy the published
harness to `vm/embedded/definition/spv_batch_entry_abi_test.go`, refusing an
existing destination. From that isolated node copy, run:

```sh
GOWORK=off GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off CGO_ENABLED=0 \
  go test -mod=readonly -p 1 -json -count=1 -timeout=60s \
  -run '^TestSPVBatchEntryABIEncoding$' ./vm/embedded/definition
```

Concatenate the selected test's output events before decoding the JSON after
`SPV_BATCH_ENTRY_ABI_TRACE`; long log lines may be split. Keep actual exit,
completeness, source/toolchain/dependency pins and prior failure evidence.
The recorded capture took 33.271 seconds locally and removed its owned caches.
Reading its fixtures in hosted SPV tests is not a new original-node execution,
network pilot, production resource measurement or state-value acceptance.
