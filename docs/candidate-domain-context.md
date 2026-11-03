# Candidate Settlement domain context

The candidate helpers implement the independent D1 key/codec slice from the
[domain-context contract](batch-entry-domain-context.md). They return detached,
untrusted data. They do not check supporting proofs, accept state values,
register a network profile or authenticate historical runtime. The experimental
typed query still implements its existing BatchEntry proof only; atomic
composition of all three witnesses remains an implementation gate.

## Local keys and paths

`proof.CandidateSettlementDomainRecordKey` and
`proof.CandidateSettlementDomainConfigKey` take an explicit raw Settlement
address and uint32 domain and derive these 27-byte ledger keys:

```text
domainRecord: 03 || address (20 bytes) || 04 || 01 || domain (u32 BE)
domainConfig: 03 || address (20 bytes) || 04 || 15 || domain (u32 BE)
```

Their Path helpers hash the complete key with SHA3-256 once. The candidate SMT
interface consumes the path without another hash. A five-byte application
subkey, another address/namespace/prefix, little-endian domain or double-hashed
path is a different identity. The key carries no network, header, schema or
context; the caller selects and authenticates those separately. These helpers
do not validate text addresses or choose a domain.

## Strict bounded codecs

`proof.DecodeCandidateDomainRecord` decodes the selected 12-field ABI schema.
Its 384-byte head and two empty length-prefixed tails require at least 448 bytes.
`CandidateDomainRecordLimits` requires a whole-value cap of 448–4,096 bytes and
positive individual profileConfig/chainBinding caps and a cumulative unpadded
cap, each no greater than the whole-value cap. Zero/negative limits refuse;
empty payloads remain structurally valid under positive caps. The 4 KiB ceiling
is a research limit, not a measured network or trie limit.

`proof.DecodeCandidateDomainConfig` requires exactly 64 bytes containing two
uint64 ABI words. Fixed framing needs no configurable allocation budget. Its
delay numbers do not imply valid registration parameters or elapsed delay.

Both codecs reject dirty upper integer bits, truncation and trailing bytes.
The record codec also requires exact contiguous schema-ordered tail offsets,
complete bounded lengths and zero padding. Copies follow every structural and
budget check. Errors return zero values without partial fields; successful
dynamic outputs do not alias the input, each other or another decode. Callers
must not mutate inputs concurrently with decoding.

This explicit local canonical policy is stricter than the original unpacker.
Selectors remain uninterpreted uint8 values; stfSpecHash is an opaque hash and
the two dynamic fields are opaque bytes. Decoding does not enforce
RegisterDomain's selector, empty-field, status or delay rules. It does not
establish network agreement, effective-state timing or accepted proof authority.

## Original node and independent bytes

The [recorded facts](../internal/testdata/conformance/domain-context-abi.json)
pin node `938fca3b7787da86827a5eb63371509b36e14761`, root tree
`f3b7947d2267ebdb806f18ff0c02bba5bffae9c4`, and 13 relevant source files.
The [harness](../tools/gen-state-root-vectors/domain-context-abi_test.go.txt)
ran against otherwise unchanged original node sources on darwin/arm64,
Go 1.25.14, with CGO disabled. The parent and all 16 child cases passed:

- Eight domainRecord packing/unpacking cases cover empty/selected fields,
  31/32/33-byte tails, each empty-tail position and uint8 maxima.
- Four domainConfig packing/unpacking cases cover zero, 30/30, distinct delays
  and uint64 maxima. Names and structural values do not establish registered state.
- Four domain IDs cover both original application-subkey functions, including
  zero, one, byte-order-sensitive data and uint32 maximum.

Independent Python encodings matched all 12 complete ABI values and eight
original subkeys. Python constructed eight full ledger keys/paths using the
source-mapped framing; the original node did not execute a full ledger lookup
or prove those rows. The [independent checker](../tools/gen-state-root-vectors/check_domain_context.py)
replays these byte comparisons without reexecuting the node. CI invokes it
on Linux, macOS and Windows alongside native tests.

Original-node record: SHA-256
`b9a7f79f2c518c384bd3d7d67bf318bb383ab670373ba7e29c51e6b00afb9c4d`.
Gate: SHA-256
`7f8b5230187f366393b343e5d98d026dcf4556c656eb76a2a1d3985763e39f32`.
All 21 loaded modules matched the selected go.sum through independent ZIP and
expanded-directory h1 checks, repeated for directories after execution.
Full historical node module-graph verification remains NOT_ESTABLISHED.
No chain, server, wallet, signing or network transaction ran.

## Native controls and resource scope

Local race-enabled execution passed seven new roots and 89 child pass events,
plus six preserved BatchEntry roots and 59 child pass events. Controls check
every truncated prefix, all integer widths, offsets/lengths, aliases, padding,
trailing data, individual/cumulative limits and mutable ownership. A 1 MiB
unsupported input refuses with zero allocations. The fuzz target compares
successful decodes with an independent canonical re-encoder and requires zero
results on errors. A five-second target produced 216,674 executions; its
reported fuzz test took 6.01 seconds. Vet and root-module verification passed.
Exact-commit hosted native CI and artifacts are separately qualified in the PR.

Local native record: SHA-256
`b2a8d216946ce8d9be50e7ed61e85792191d51955749bb47db3d4983088bb5e0`.

| Attempt | Elapsed seconds in retained report | Largest workspace observation after a phase |
| --- | ---: | ---: |
| Original node ABI/subkeys | 36.319 | 242,551,927 bytes |
| Candidate native controls | 46.703 | 344,112,249 bytes |

These are local observations, not continuous peaks or deployment budgets.
Task limits were 512 MiB and 768 MiB respectively. Temporary caches and isolated
source workspaces closed; reports, source pins and the compressed race binary
remain protected. Source/module archives were read-only local inputs. Only new,
verified, unnecessary module ZIP copies were discarded inside those tasks;
physical disk reclamation was not measured.

Initial candidate preparation refused cross-volume APFS cloning with EXDEV
before native tests ran. Its failure remains preserved. The successful attempt
explicitly quota-accounted portable source copies, reused completed formatting
and isolated fuzz-generated files from the working tree. Historical data,
existing evidence and the private storage implementation remained unchanged.

## Reproduction and remaining authority

Use a fresh isolated owned workspace with bounded caches:

```sh
python3 -I -B tools/gen-state-root-vectors/check_domain_context.py
go test -race -count=1 -run '^TestCandidate(DomainContext|BatchEntry|SettlementBatchEntry)' ./internal/proof
go test -run '^$' -fuzz '^FuzzCandidateDomainContextDecode$' -fuzztime=5s -parallel=1 ./internal/proof
```

For new original-node evidence, copy the exact harness exclusively into a fresh
pinned node copy at `vm/embedded/definition/spv_domain_context_abi_test.go`, with
verified offline dependencies, then run:

```sh
GOWORK=off GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off CGO_ENABLED=0 \
  go test -mod=readonly -p 1 -json -count=1 -timeout=60s \
  -run '^TestSPVDomainContextEncoding$' ./vm/embedded/definition
```

Concatenate output events before decoding JSON after `SPV_DOMAIN_CONTEXT_TRACE`;
long log lines can be split. Retain actual exit/completeness and source,
toolchain and module identities. Hosted candidate replay is not another node run.

Supporting proof composition must still bind all local keys/schemas to one owned
accepted H/hash/root/context, retained tip and aggregate budget, with
all-or-nothing results. Current-H configuration/spec cannot prove an older
batch's submission-time context. These rows do not authenticate an external
executor binary or an L2 transition. The real chain-69 boundary/query,
independent review and production NO-GO gates remain open.
