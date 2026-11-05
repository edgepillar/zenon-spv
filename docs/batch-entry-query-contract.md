# BatchEntry query contract draft

Status: **SOURCE_ONLY_INCOMPLETE_D0**. This is a reviewable contract for the
first read-only typed query in the [delivery plan](typed-state-roadmap.md).
It does not select a live accepted profile or qualify an accepting consumer.
The separate [experimental typed-query binding](experimental-batch-entry-query.md)
now implements the header/root/key/proof/ABI seam under explicit local policy;
its selected-network positive witness and actual consumer remain open.

The proposed first host is an adapter in the existing native CLI. The current
Go module/import identity remains unchanged; a public-library publication is
a separate coherent API and distribution decision.

## Source-selected devnet clarification

The [maintainer clarification](https://github.com/Zeno-L2/zeno-devnet/issues/1#issuecomment-6573540510)
selects the existing node pin and its
[devnet genesis file](https://github.com/digitalSloth/go-zenon/blob/938fca3b7787da86827a5eb63371509b36e14761/docker/devnet/genesis.json).
The exact file is 8,137 bytes with SHA-256
`0dd33b18b147f70b3d3d5f07199a2b45311f6e9b84a98b3f86d8f6c6b45f419a`.
That file digest is distinct from the genesis momentum hash and does not
authenticate a running endpoint.

The retained [source-genesis H1 capture](selected-devnet-genesis.md) derives
momentum hash `fab7609bae7fd78eb7d2b0d4a5023832f1a6730921b862f2415da25524698dc9`
from that exact configuration and node revision. Independent Python and SPV
checks replay its unsigned v1 preimage. This supplies a source-conditioned
identity, without selecting a live trust root, height-2 anchor or v3 profile.

The source declares chain ID 69, three initial pillars, and activated
`merkle-state-root` and `offchain-execution` sporks with enforcement height zero.
`IsSporkActive` returns false at parent frontier height 1. With this selected
genesis, the source-conditioned expectation is v1 at heights 1 and 2 and first
incoming v3 at height 3. An actual selected-chain-69 transition capture is still
required; the isolated chain-100 trace is not reassigned to that network.

The maintainer identifies the normal consensus schedule from the genesis pillar
set, rather than a separate attested schedule file. The
[subsequent review](https://github.com/Zeno-L2/zeno-devnet/issues/1#issuecomment-6612559092)
also suggests signature plus genesis-set membership for a limited prototype.
That is a different authorization policy from checking the elected producer at
a parent snapshot. The experimental SPV API keeps its explicit finite
height/timestamp/address entries and provenance requirements. Observing a
producer in the same provider's header cannot independently authorize that entry.
The [policy distinction](batch-entry-domain-context.md#producer-authorization)
remains explicit; no genesis-set fallback is selected or implemented here.

The [source parent-snapshot slot capture](source-parent-slots.md) now exercises
six explicit timestamp lookups through the original normal-consensus algorithm
against the exact H1 snapshot, with ten refusal controls. It records proof-block
and slot context without assigning network heights or constructing an accepting
schedule. The source oracle does not replace the finite explicit trust inputs.

## One query and its authority

The first result is L1 membership of one Settlement BatchEntry at an owned
accepted header H/hash/context. The stored row is the query output: its value
does not have to be predetermined or copied from a gateway as an expected
answer.

```text
independently selected network / genesis / anchor / profile / producer schedule
  -> owned accepted v3 header H/hash/context, bound to retained state and tip T
  -> StateRoot extracted from H
  -> local Settlement address / domain / batch -> full ledger key -> SMT path
  -> bounded canonical proof against H's root
  -> strict BatchEntry ABI decoding
  -> compare every selected gateway commitment field with the proven row
  -> one detached read-only consumer result
```

A provider root, self-consistent header hash, peer agreement or experimental
flag cannot create header/state acceptance authority. Source pins select code;
they do not authenticate a live network or its activation.

| Input | Contract requirement | Current selection |
| --- | --- | --- |
| Network and genesis | One exact network and genesis hash, selected independently of the witness provider | Pinned chain-69 source genesis and its H1 hash are recorded; running-network identity and exact trust binding remain open |
| Anchor | Height/hash and provenance for the chosen trust start | Open |
| Header and context | Owned accepted H/hash/context plus selected retained-state/tip binding | Experimental header and typed-query mechanics implemented; selected-network qualification remains open |
| Producer schedule | Independently selected authorization, coverage and provenance | Genesis/normal-consensus source identified; finite explicit entries and selected-range provenance remain open |
| First incoming v3 | Actual boundary from v1 genesis and parent-frontier activation behavior | Source-conditioned expectation is height 3 for the pinned devnet genesis; actual transition capture remains open and the [chain-100 fixture](first-v3-node-boundary.md) does not qualify its activation |
| Settlement address | Fixed raw 20-byte address from the selected local profile | Source constant mapped; active network selection remains open |
| Domain | Locally selected uint32 | Prepared owned experiment selects 1 before provider reads; selected-network execution remains open |
| Domain context | Locally derived domainRecord and domainConfig keys; supporting proofs at the same accepted H/root/context | Source schemas and temporal limits are [recorded](batch-entry-domain-context.md); the [separate versioned three-row query](experimental-batch-context-query.md) implements offline supporting-proof composition; selected-network qualification remains open |
| Batch | Locally selected uint64, with bounded exact text parsing at the CLI boundary | Prepared owned experiment selects 0 before provider reads; no fallback to another provider-selected batch |
| Proof and value limits | Explicit positive schema-aware byte, sibling and cumulative-work limits | Experimental schema-1 policy implemented; selected-network review/selection remains open |
| Temporal claims | First query claims membership at H; any additional delay claim is separate | No consensus-finality, receive or spendability claim |

One independently selected operator can support a scoped experiment. Another
operator is not a prerequisite for source work or a deliberately limited
devnet pilot. The selected trust inputs and provenance must still be explicit.

## Prepared local consumer selection

The [canonical metadata descriptor](../internal/testdata/conformance/prepared-devnet-consumer-selection.json)
selects the pinned chain-69 source genesis, Settlement address, domain 1, batch 0
and source domain/runtime metadata before any selected-network provider read.
The [prepared version-2 query profile](../internal/testdata/conformance/prepared-devnet-query-profile.json)
binds its runtime_identity to SHA-256 of the exact canonical descriptor bytes,
including the trailing newline. This is a local metadata identifier, not
authentication of runtime identity or execution. The consumer executable and
its CI/artifact provenance must be pinned separately.

The profile selects the phase-1 source-field rule and explicit work ceilings.
Its positive one-byte proofData work cap does not relax the versioned source
rule requiring an empty proofData value. The source configuration declares an
STF spec hash ending in 01, withdrawal delay 30 and runtime-upgrade delay
17,280. These are independently selected expectations: hashing the descriptor
does not automatically compare them with proven fields. An actual consumer
must check the selected semantic expectations before relying on those claims.

This pair supplies no height-2 anchor hash, finite producer authorizations,
actual v1/v3 transition, accepting header profile, trusted checkpoint or context
pins. It cannot be used alone as an accepting command configuration. The
source-conditioned genesis identity does not authenticate an endpoint; the
selected-network capture and actual read-only consumer result remain open.
Go controls decode the prepared profile through the public API, bind its
metadata digest and compare all three locally derived keys/paths with literal
source-key vectors. They do not start a node, sign or submit transactions.

## Source and schema cohort

The component set is selected from
[zeno-devnet sources.txt](https://github.com/Zeno-L2/zeno-devnet/blob/04dc0797f7bcc02e48e0acba3b0ac49df2d3289d/sources.txt).

| Component | Selected revision |
| --- | --- |
| Devnet orchestration | `04dc0797f7bcc02e48e0acba3b0ac49df2d3289d` |
| Node | `938fca3b7787da86827a5eb63371509b36e14761` |
| Executor | `caeaf764270b1489a53c860c6006026af208f924` |
| Console | `b4726037e01e5e2c2a37f3f7a234cc29daee6cc2` |
| Contract SDK | `bc1548d75473797f24bb3eb79f5594969c596e39` |
| Documentation/vector cohort | `d74ba1fc4b01583af0daf33a2dedfc84ea2b9419` |

The stored
[batchEntry schema](https://github.com/digitalSloth/go-zenon/blob/938fca3b7787da86827a5eb63371509b36e14761/vm/embedded/definition/settlement.go#L591-L615)
has 17 ordered fields:

| Field | Source ABI type |
| --- | --- |
| protocolVersion | uint16 |
| firstInputSeq | uint64 |
| lastInputSeq | uint64 |
| preStateRoot | hash |
| postStateRoot | hash |
| inputRoot | hash |
| receiptRoot | hash |
| eventRoot | hash |
| outboxRoot | hash |
| daHash | hash |
| daMode | uint8 |
| executorPillar | string |
| submittedAtHeight | uint64 |
| finalizeAtHeight | uint64 |
| assetFlowSummary | bytes |
| proofData | bytes |
| state | uint8 |

The query profile must bind the exact L1 ABI/schema and relevant domain/runtime
identity. stfSpecHash alone is insufficient. Two additional locally keyed proofs
for domainRecord and domainConfig can bind the current domain context to the
same accepted H/root. Their fields, mutation paths and remaining implementation
gates are specified in [domain context](batch-entry-domain-context.md).
Current context does not by itself prove the runtime or configuration used when
an older batch was submitted. The three dynamic fields need individual and
cumulative limits, and the selected ABI codec needs explicit offset, length,
padding, integer-width, trailing-data and string rules.
The experimental binding now requires an explicit local schema-1 policy for
those decisions; selected-network agreement and acceptance remain open. A
separate [candidate ABI decoder](candidate-batch-entry-codec.md) supplies
bounded, detached, untrusted encoding data with explicit local canonical/string
choices. It does not provide accepted-header or state-value authority.

[Candidate key helpers](candidate-batch-entry-key.md) already derive the full
35-byte key locally:

```text
03 || Settlement address (20 bytes) || 04 || 02 || domain (u32 BE) || batch (u64 BE)
```

The SMT path is SHA3-256 of that complete key exactly once. The 13-byte
application subkey is not the full ledger key. The address/domain/batch and
network/context remain separate inputs: the raw key contains no chain ID.

## Proof RPC and gateway identity

At the selected node pin, `ledger.getProof(height, key)` resolves the momentum
identifier at that height and returns `{value, proof, root}`.
`ledger.getStateRoot(height)` is a separate convenience read. The consumer's root
comes from the owned accepted header; neither RPC response selects that authority.
The caller retains H/hash/context and exact owned tip identity across the query.
A pre-activation, not-ready, pruned, unavailable or incomplete response is not
application absence.

The selected L1 encoder elides zero siblings. Its decoder can still read an
explicitly stored zero sibling; mathematical equivalence does not select an
acceptance policy. The experimental schema-1 binding requires canonical proofs
for the narrow consumer
as an explicit local policy, without declaring noncanonical node encodings
network-invalid.

Use the selected `embedded.settlement.getBatch(domainId, batchId)` DTO only as
a comparison input. That method reads frontier context, rather than a
caller-selected historical height. Its `domainId`/`batchId` must match the local
key; its 17 stored fields must be compared with the root-proven row. A mismatch
must not replace the proven value or expected query identity.

The DTO's `isFinalized` is derived at the RPC frontier and is not an additional
stored ABI field. If the consumer separately reports the selected source's
Settlement-delay predicate at H, compute `H.height >= row.finalizeAtHeight`
from the proven row at H. Do not substitute the gateway's frontier boolean or
treat that predicate as W depth, consensus finality, funds release or receive.

For the pinned SubmitBatch path, the source bounds are at most 40 bytes for
`executorPillar`, `4 + 96*n` bytes with `n <= 16` for `assetFlowSummary`
(at most 1,540 bytes), and an empty `proofData`. The
[bound derivation](batch-entry-domain-context.md#batchentry-source-bounds)
separates the wire commitment's 15 KiB cap from the stored ABI value. These
source-conditioned field bounds give a computed canonical ABI upper bound of
2,272 bytes. This is not an observed selected-network maximum or a trie-level
protocol cap.

The existing 4 KiB candidate ceiling remains a local unsupported-data boundary.
Its generic codec permits untrusted encodings outside the SubmitBatch business
rules. The opt-in [version 2 query policy](experimental-batch-entry-query.md#version-2-source-field-policy)
adds the source pillar-name, asset-flow framing/ID/order/amount and empty
proofData checks after canonical membership and strict ABI decoding. Version 1
keeps its original interpretation. Both versions retain positive byte caps:
setting MaxProofDataBytes to zero is invalid, including with the empty-data rule.
This source-field subset does not establish all SubmitBatch rules, a state
transition or an agreed selected-network policy. Selected-network review remains
required.

## Bounds and failure contract

The current [candidate proof checker](candidate-smt-proof.md) requires positive
local caps and enforces a 4,096-byte value ceiling and 12,391-byte proof ceiling.
These are research-work limits. They do not establish BatchEntry maximum sizes,
network limits or an agreed canonical encoding policy. A larger witness must
not silently enlarge them or turn unsupported data into an application value.

A supported selected-network query requires a reviewed decision for all
applicable bounds, an owned accepted header and a canonical typed decoder.
The experimental implementation composes these mechanics without registering
a production profile. Standalone mathematical checks remain MATH_ONLY, and the
production state-value path remains refused.

| Condition | Required consumer behavior |
| --- | --- |
| Missing, unsupported, inactive or unknown profile; wrong network/genesis/anchor; expired schedule | Refuse acceptance before using a provider root |
| Altered hash/signature/root/linkage or producer authorization | Reject the invalid header; create no accepted state |
| Different H/hash/context, query address/domain/batch, namespace or path | Reject the mismatched query; preserve its original identity |
| Noncanonical, malformed, oversized or over-budget proof/value | Reject or refuse with its precise category; return no accepted row |
| Missing, pruned, unavailable or incomplete witness | Report unavailable/refused; never convert it to absent or zero |
| Valid absence outside the committed typed key domain | Do not interpret it as application absence |
| Ambiguous ABI, bad integer/offset/padding/length, unapproved schema or unsupported bounds | Return no accepted typed value |
| Gateway field differs from the proven row | Reject that comparison; do not replace the local expected key or root |
| Restart, context change or retention loss | Revalidate the saved context and cache binding; do not reuse an unrelated result |
| Interrupted or incomplete processing | Retain the actual outcome as incomplete/UNKNOWN; do not report success |

The result must bind network/genesis, profile, anchor, H/hash/context, selected
tip/retention interpretation, query key/schema and the proven bytes. Its
returned data must be detached from mutable provider and verification state.
No result-cache entry may outlive a change in that identity or interpretation.

If a later result includes a Settlement-delay predicate, evaluate
`H.height >= row.finalizeAtHeight` at H. W depth, a later tip T, that stored
delay and consensus finality are different conditions. L1 membership also
does not prove STF execution correctness, funds release or recipient receive.

## Exit from draft status

D0 needs actual selected network/genesis/anchor/query/profile/schedule inputs
and an owner-selected contract. D1 then needs all root/proof/path/applier
obligations, actual first-v3 boundary and reviewed canonical/schema caps.
[Original node trie execution](selected-original-node-conformance.md) and
native candidate byte checks close only their named scopes.

The separate experimental API supplies owned-v3 RPC/authentication/context,
persistence and header-root-bound typed ABI mechanics. D2/D3 still require their
selected-network qualification, a matching selected-network witness and one real
read-only consumer. The separate
[positive original-node fixture](recorded-batch-entry-witness.md) exercises the
exported API, persistence and compiled CLI without selecting those live inputs.
No live experiment,
release, activation or accepted state-value result is established by this
document. Independent native v1/v2 inclusion remains a separate track.

