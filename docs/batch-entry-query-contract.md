# BatchEntry query contract draft

Status: **SOURCE_ONLY_INCOMPLETE_D0**. This is a reviewable contract for the
first read-only typed query in the [delivery plan](typed-state-roadmap.md).
It does not select an accepted profile or implement an accepting consumer.

The proposed first host is an adapter in the existing native CLI. The current
Go module/import identity remains unchanged; a public-library publication is
a separate coherent API and distribution decision.

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
| Network and genesis | One exact network and genesis hash, selected independently of the witness provider | Open; source chain ID 69 is a default, not authenticated identity |
| Anchor | Height/hash and provenance for the chosen trust start | Open |
| Header and context | Owned accepted H/hash/context plus selected retained-state/tip binding | Not implemented for supported v3 |
| Producer schedule | Independently selected authorization, coverage and provenance | Open |
| First incoming v3 | Actual boundary from v1 genesis and parent-frontier activation behavior | Open for the selected network; the [isolated node fixture](first-v3-node-boundary.md) does not qualify network activation |
| Settlement address | Fixed raw 20-byte address from the selected local profile | Source constant mapped; active network selection remains open |
| Domain | Locally selected uint32 | Source default 1; active query selection remains open |
| Batch | Locally selected uint64, with bounded exact text parsing at the CLI boundary | Open; the gateway must not select the expected batch |
| Proof and value limits | Explicit positive schema-aware byte, sibling and cumulative-work limits | Open for accepted typed queries |
| Temporal claims | First query claims membership at H; any additional delay claim is separate | No consensus-finality, receive or spendability claim |

One independently selected operator can support a scoped experiment. Another
operator is not a prerequisite for source work or a deliberately limited
devnet pilot. The selected trust inputs and provenance must still be explicit.

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
identity. stfSpecHash alone is insufficient. The three dynamic fields need
individual and cumulative limits, and the selected ABI codec needs explicit
offset, length, padding, integer-width, trailing-data and string rules.
Those acceptance decisions and a strict decoder remain open.

[Candidate key helpers](candidate-batch-entry-key.md) already derive the full
35-byte key locally:

```text
03 || Settlement address (20 bytes) || 04 || 02 || domain (u32 BE) || batch (u64 BE)
```

The SMT path is SHA3-256 of that complete key exactly once. The 13-byte
application subkey is not the full ledger key. The address/domain/batch and
network/context remain separate inputs: the raw key contains no chain ID.

## Bounds and failure contract

The current [candidate proof checker](candidate-smt-proof.md) requires positive
local caps and enforces a 4,096-byte value ceiling and 12,391-byte proof ceiling.
These are research-work limits. They do not establish BatchEntry maximum sizes,
network limits or an agreed canonical encoding policy. A larger witness must
not silently enlarge them or turn unsupported data into an application value.

A supported query requires an explicit profile decision for all applicable
bounds, an owned accepted header and a canonical typed decoder. Until then the
accepting path remains refused; mathematical checks stay MATH_ONLY.

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

D2/D3 still require the owned-v3 RPC/authentication/context/persistence path,
strict ABI decoding and one real read-only consumer. No live experiment,
release, activation or accepted state-value result is established by this
document. Independent native v1/v2 inclusion remains a separate track.

