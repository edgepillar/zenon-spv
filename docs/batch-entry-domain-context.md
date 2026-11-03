# BatchEntry domain context and source bounds

Status: **SOURCE_ONLY_INCOMPLETE_D0_D1**. This records the source-checked part of
the [maintainer review](https://github.com/Zeno-L2/zeno-devnet/issues/1#issuecomment-6612559092)
of the [query contract](batch-entry-query-contract.md) at
`702180aefec3e1d0ee03431e27aa7102db46fcad`. That contract's bytes were unchanged
through `1832694010aa149d54f2442f491746f21ab66abe`; this follow-up changes the
draft. The review is not transferred to these new words or a later binary.

The selected node remains
`digitalSloth/go-zenon@938fca3b7787da86827a5eb63371509b36e14761`, with root tree
`f3b7947d2267ebdb806f18ff0c02bba5bffae9c4`. The retained 1,876,245-byte source
archive has SHA-256
`8ca1512eff8c04ee8b6ed0ff9a5da9e3eeba518660b07833f99a6b74e1dcc3a3`.
Its 484 regular files were checked against the original blob manifest and the
recursive Git tree was reconstructed again. No source download, node execution
or live query was needed for this follow-up.

## BatchEntry source bounds

These are bounds on the pinned normal SubmitBatch write path under its
pillar-name rules, not on every value the general ABI packer can encode.

| Dynamic field | Source condition | Maximum payload bytes |
| --- | --- | ---: |
| executorPillar | Assigned from the active executor pillar; nonempty registered pillar names are limited by Go string byte length | 40 |
| assetFlowSummary | u32 big-endian count n followed by n 96-byte entries; n <= 16 and exact framing | 1,540 |
| proofData | The commitment decoder requires exactly a zero u32 length and no trailing bytes | 0 |

The independent source locations are:

- [Pillar-name validation](https://github.com/digitalSloth/go-zenon/blob/938fca3b7787da86827a5eb63371509b36e14761/vm/embedded/implementation/pillars.go#L24-L33)
  and [40-byte constant](https://github.com/digitalSloth/go-zenon/blob/938fca3b7787da86827a5eb63371509b36e14761/vm/constants/embedded.go#L47).
- [Summary framing](https://github.com/digitalSloth/go-zenon/blob/938fca3b7787da86827a5eb63371509b36e14761/vm/embedded/implementation/settlement.go#L1203-L1252),
  [count and proof-data checks](https://github.com/digitalSloth/go-zenon/blob/938fca3b7787da86827a5eb63371509b36e14761/vm/embedded/implementation/settlement.go#L1431-L1448)
  and [16-asset constant](https://github.com/digitalSloth/go-zenon/blob/938fca3b7787da86827a5eb63371509b36e14761/vm/constants/settlement.go#L16).
- [Stored-field assignment](https://github.com/digitalSloth/go-zenon/blob/938fca3b7787da86827a5eb63371509b36e14761/vm/embedded/implementation/settlement.go#L1589-L1594)
  and [17-field ABI](https://github.com/digitalSloth/go-zenon/blob/938fca3b7787da86827a5eb63371509b36e14761/vm/embedded/definition/settlement.go#L125-L143).

For a canonical encoding with 32-byte ABI words, the computed upper bound is:

```text
17*32                         =  544  head
32 + ceil(40/32)*32            =   96  executorPillar tail
32 + ceil((4 + 16*96)/32)*32   = 1600  assetFlowSummary tail
32 + ceil(0/32)*32             =   32  proofData tail
total                         = 2272  bytes
```

This is a source-conditioned encoding bound, not an executed maximum-size
SubmitBatch or a measured network result. The separate
[MaxOnChainCommitmentSize](https://github.com/digitalSloth/go-zenon/blob/938fca3b7787da86827a5eb63371509b36e14761/vm/constants/settlement.go#L5-L16)
is 15 KiB for the wire commitment. It does not declare a 15 KiB stored-value or
trie limit. The candidate's 4 KiB research ceiling contains this computed ABI
bound but remains an explicit local limit.

The [candidate decoder](candidate-batch-entry-codec.md) is a generic bounded ABI
decoder. Its positive byte caps do not express the source rule that proofData
must be empty, nor do they validate summary entries or pillar-name semantics.
Do not set a zero byte cap or treat a mathematical decode as SubmitBatch
validation. Source-policy checks need their own versioned semantics and tests.

## Two supporting proofs at H

Keep BatchEntry as the one consumer result. Add domainRecord and domainConfig
as supporting context only, with the same independently selected raw Settlement
address and domain ID. Derive their complete ledger keys locally:

```text
domainRecord: 03 || Settlement address (20 bytes) || 04 || 01 || domainId (u32 BE)
domainConfig: 03 || Settlement address (20 bytes) || 04 || 15 || domainId (u32 BE)
```

Both keys are 27 bytes; each SMT path is SHA3-256 of that complete key once.
The five-byte application subkeys are not full ledger keys. The namespace and
address framing are the same as for the [35-byte BatchEntry key](candidate-batch-entry-key.md).
Source prefixes and subkeys are declared in
[Settlement storage](https://github.com/digitalSloth/go-zenon/blob/938fca3b7787da86827a5eb63371509b36e14761/vm/embedded/definition/settlement.go#L440-L501)
and [DomainConfig](https://github.com/digitalSloth/go-zenon/blob/938fca3b7787da86827a5eb63371509b36e14761/vm/embedded/definition/settlement.go#L1854-L1872).

The [domainRecord ABI](https://github.com/digitalSloth/go-zenon/blob/938fca3b7787da86827a5eb63371509b36e14761/vm/embedded/definition/settlement.go#L110-L123)
has these 12 ordered fields:

| Field | ABI type |
| --- | --- |
| domainClass | uint8 |
| runtimeKind | uint8 |
| stfSpecHash | hash |
| inputSource | uint8 |
| execProfile | uint8 |
| foreignProfile | uint8 |
| profileConfig | bytes |
| chainBinding | bytes |
| minExecutors | uint8 |
| proposerPolicy | uint8 |
| finalityModel | uint8 |
| status | uint8 |

The [domainConfig ABI](https://github.com/digitalSloth/go-zenon/blob/938fca3b7787da86827a5eb63371509b36e14761/vm/embedded/definition/settlement.go#L254-L257)
contains withdrawalDelay and runtimeUpgradeDelay, both uint64. Domain ID comes
from the local key, not either stored ABI payload.

[RegisterDomain validation](https://github.com/digitalSloth/go-zenon/blob/938fca3b7787da86827a5eb63371509b36e14761/vm/embedded/implementation/settlement.go#L187-L208)
admits execution class, WASM runtime, L1-native inputs, attestation execution,
no foreign profile, single proposer, delay finality and one executor. It
requires empty profileConfig and chainBinding. These selectors are zero-valued
at this pin; minExecutors is one and status may be active or paused. This does
not prove that domain 1 is registered on a running network, or that it has
never been updated. Generic ABI support must remain distinct from these
source-specific registration rules.

Each supporting witness must pass the same accepted header H/hash/root/context,
owned tip and retention checks as the BatchEntry witness. Bind all three local
keys, schemas and results together; reject mixed heights, roots, domains,
namespaces or contexts. Bound individual value/proof work and the cumulative
three-proof work before allocation. Missing or unavailable context cannot be
silently replaced with provider DTO fields or inferred absence.

The existing typed-query API implements the BatchEntry proof only. Domain keys,
strict codecs, independent byte checks and atomic supporting-proof composition
remain implementation gates; this document does not claim they already exist.

## Current context and submission-time context

At the pinned source,
[acceptBatch](https://github.com/digitalSloth/go-zenon/blob/938fca3b7787da86827a5eb63371509b36e14761/vm/embedded/implementation/settlement.go#L1542-L1594)
reads the current domain configuration and stores
finalizeAtHeight = submittedAtHeight + withdrawalDelay. The
[devnet build](https://github.com/digitalSloth/go-zenon/blob/938fca3b7787da86827a5eb63371509b36e14761/vm/constants/embedded_devnet.go#L13-L18)
sets the minimum withdrawal delay to 30; it does not force every domain's delay
to equal 30 or prove a running binary used that build.

Later administrative calls can change relevant state:

- [SetDomainConfig](https://github.com/digitalSloth/go-zenon/blob/938fca3b7787da86827a5eb63371509b36e14761/vm/embedded/implementation/settlement.go#L383-L421)
  changes withdrawalDelay and runtimeUpgradeDelay after its time challenge.
- [RegisterDomain updates](https://github.com/digitalSloth/go-zenon/blob/938fca3b7787da86827a5eb63371509b36e14761/vm/embedded/implementation/settlement.go#L279-L343)
  can change status and stfSpecHash under their respective rules. The update
  branch also assigns minExecutors when it differs, but this pin's static
  validator requires minExecutors = 1. The same path refuses changes to the
  fixed domain/runtime selectors.

Consequently a proof of domainConfig at H does not establish its value at an
older batch's submission. Do not require an old batch's stored finalizeAtHeight
to equal submittedAtHeight plus the current-H withdrawalDelay. Likewise a
current stfSpecHash does not establish which spec applied at submission.
Historical interpretation requires a separately justified historical root,
effective-state boundary or independently selected immutable interval. Merely
querying the momentum whose number equals submittedAtHeight is insufficient
without checking when the embedded call read and wrote its state.

For the narrow optional delay observation, use only the proven stored predicate
H.height >= row.finalizeAtHeight. That predicate does not prove STF correctness,
W depth, consensus finality, funds release or recipient receive. A full domain
record also does not authenticate an external executor binary, its code hash
or an L2 state transition. Keep the independently selected runtime identity
and its provenance separate.

[getDomainInfo](https://github.com/digitalSloth/go-zenon/blob/938fca3b7787da86827a5eb63371509b36e14761/rpc/api/embedded/settlement.go#L201-L214)
reads frontier context. Its corresponding stored fields can be compared with
the proven domain rows, but a frontier mismatch is not proof that a historical
row is invalid. It cannot supply missing authenticated context or select the
consumer's root, schema, domain or runtime identity.

## Producer authorization

The selected genesis names three initial block-producing addresses, as recorded
in the [source-genesis capture](selected-devnet-genesis.md). A valid signature
from one of those addresses proves a different claim from the selected
[parent-snapshot election check](https://github.com/digitalSloth/go-zenon/blob/938fca3b7787da86827a5eb63371509b36e14761/consensus/consensus.go#L98-L114),
which resolves the elected producer at the timestamp. The maintainer's report
of no devnet delegation changes is operational input, not executed evidence
that an observed header matches that election or a canonical chain.

The current experimental API retains explicit finite height/timestamp/address
authorization. Keep the existing context pin, provenance and expiry checks.
An observed header cannot mint its own trusted schedule entry. A separately
selected genesis-membership prototype would need a distinct versioned policy,
guarantee name and context binding; it must not be a fallback for a failed
finite schedule or silently acquire election/fork-choice/finality claims.
No such policy change is made by this follow-up.

## Remaining implementation and network gates

The next independent D1 slice is local domain key derivation and bounded,
detached codecs, compared with the original ABI and independent bytes. Then
add all-or-nothing supporting proofs at one owned accepted H/context, explicit
source semantics and aggregate work budgets. Negative controls must cover
cross-context/domain substitution, malformed canonical encodings, empty or
missing supporting rows, changed configuration and unsupported source rules.

A real selected-chain-69 H2/H3 transition and matching read-only query still
need selected trust inputs and a capture. The maintainer describes a local
devnet workflow, not a public endpoint or an existing captured batch. This
source review does not start services, sign requests, submit transactions or
deploy a consumer. D0-D3 acceptance, independent review and production NO-GO
gates remain open. The native v1/v2 inclusion track remains independent.
