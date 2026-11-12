# Experimental header-bound BatchEntry query

Status: **IMPLEMENTED_EXPERIMENTAL_BINDING; SELECTED_NETWORK_CONSUMER_OPEN**.
This internal Go API composes the [owned-v3 state](experimental-v3-owned-state.md)
with local key derivation, bounded SMT reads and the strict 17-field ABI codec.
It does not register a production profile or complete D0-D3 acceptance.
The separate [read-only CLI seam](experimental-batch-entry-cli.md) consumes this
API with mandatory configuration pins and a separate local request file. A
[recorded original-node fixture](recorded-batch-entry-witness.md) now exercises
a matching positive proof through the exported API, saved context and compiled
CLI. A public module, matching positive live query and release remain open.

## Authority and request identity

`NewExperimentalBatchEntryQuery` requires an opaque `ExperimentalV3State`, a
valid typed-query policy and an independently selected nonzero context pin.
An empty state is refused. No constructor accepts a raw root, a diagnostic
context, a caller-built retained window or a gateway DTO as header authority.

For each request the handle checks its static context and exact owned tip
height/hash, then obtains the root through `ExperimentalV3State.RootAt` using
H/hash and the header context. The existing W depth, retained scope, explicit
anchor/profile and finite producer schedule remain in force. A copied state
handle remains immutable; extending another handle does not advance it.

The fixed selected Settlement address, locally chosen domain and batch derive:

```text
03 || Settlement[20] || 04 || 02 || domain[u32 BE] || batch[u64 BE]
  -> SHA3-256 exactly once -> selected SMT path
```

The typed-query context binds the complete header-context fingerprint, node,
executor and contract-SDK revisions, the schema identifier, Settlement address,
domain, explicit runtime identity, canonical policy and every work/string limit.
The runtime identity is a configured assertion about the selected domain/runtime,
not authenticated runtime behavior or STF correctness. Source labels are
provenance text and do not affect the fingerprint. The per-query fingerprint
additionally binds H/hash, exact tip height/hash and the local batch ID. No
provider field changes those identities.

The supported source pairs are the original
[query contract cohort](batch-entry-query-contract.md) and the explicit
[reference-gas cohort](reference-gas-source-cohort.md). The header profile's exact
node revision selects the matching executor revision; their context pins are
distinct. Both use schema `zenon-settlement-batch-entry-17/v1` and raw Settlement address
`01b3b6e5adcb4d0cad7fcef33598c6318c6318c0`. A different source schema or
Settlement contract needs an explicit new profile implementation.

## Version 2 source-field policy

Version 1 keeps its original exact profile schema, JSON encoding and context
fingerprint. It does not admit a `source_rule` field, even an empty one. Version
2 requires the additional exact field
`"source_rule": "zenon-phase1-batch-fields/v1"`. Choosing that policy requires
reselecting the query-context pin and request context; a legacy pin cannot
authorize it. The ABI schema, positive local byte caps, header profile, key,
proof limits and trusted-state persistence remain unchanged.

The version 2 rule checks this subset from node revision
`938fca3b7787da86827a5eb63371509b36e14761` after canonical membership and strict
bounded ABI decoding:

- `executorPillar`: 1 through 40 ASCII bytes matching the source
  `^([a-zA-Z0-9]+[-._]?)*[a-zA-Z0-9]$` name rule.
- `assetFlowSummary`: u32 big-endian count at most 16, followed by exactly that
  many 96-byte entries. Each entry has a 32-byte asset ID with 22 zero prefix
  bytes and two unsigned 256-bit amounts. Asset IDs must strictly increase;
  deposit and withdrawal amounts cannot both be zero. A zero count is valid;
  an all-zero asset ID is encoding-valid and is not a token-registry assertion.
- `proofData`: exactly empty. Its configured byte cap must still be positive.

These map to `checkPillarName`, `decodeAssetFlowSummary` and `ZTSFromAssetId`
in the pinned source. They do not verify all SubmitBatch rules, executor
authorization, input/deposit accounting, sequence/state transitions, runtime
execution, registration, activation or finality. Local work caps can be tighter
than these source bounds and still refuse an otherwise source-shaped value.

Context version 2 changes the entry namespace's final version byte to `02`,
encodes the context version as u64 big-endian and appends the rule's
u64-big-endian length plus ASCII bytes after the original limit fields.
The [three-row context](experimental-batch-context-query.md) also requires
version 2, changes its namespace version byte and binds this entry fingerprint.
Every existing version 1 preimage remains byte-identical. Audit source labels
remain excluded from behavior identity. The CLI reports a semantic failure as
exit 1, `query/source_rule_mismatch`, with a null result; accepted headers do
not turn that failure into accepted state data.

The independent Python corpus contains 34 canonical ABI vectors, including
exact 40-byte/16-entry bounds, malformed framing, asset-ID prefix/order,
zero/nonzero amounts and nonempty proof data. Its sparse-tree calculation
reproduces the retained original three-row proof bytes before constructing a
separate negative mathematical tree. Public synthetic headers bind that
negative tree for API and compiled-CLI controls; those are not node execution.
The positive original-node fixture is reused without modification under both
profile versions. These controls do not close selected-network D0-D3 gates.

## Consumer seam and results

An internal Go consumer can use the following sequence with its independently
selected inputs; constructing matching pins is not independent trust selection:

1. Accept recorded or selected-network headers through the owned-v3 API.
2. Construct the typed-query handle with its explicit profile and expected pin.
3. Select H/hash, the exact owned tip and batch in an
   `ExperimentalBatchEntryRequest`.
4. Fetch `ledger.getProof(height, locally_derived_key)` through
   `FetchCandidateBatchEntryProof`, or supply the bounded raw proof directly.
5. Call `QueryWitness` or `Query`; retain the detached result and its identities.
6. If a frontier comparison is needed, fetch the selected
   `embedded.settlement.getBatch(domainId, batchId)` DTO and use
   `QueryWithGateway` to compare all 17 stored fields plus the selected IDs.

The stored value is read from the verified proof, not predetermined by the
gateway. RPC `root` and `value` are consistency hints checked against the owned
root and the proven bytes. Every error returns a zero result with no partial
typed row. Missing/pruned/not-ready RPC results remain unavailable; a valid
absence proof returns a distinct no-typed-value error, never a zero BatchEntry.

A successful result is scoped
`EXPERIMENTAL_CONFIGURED_HEADER_MEMBERSHIP`. It includes header trust
assumptions, typed context, request/query fingerprints, root, full key/path,
detached raw value, SHA3-256 value/proof digests and the decoded row. It is not a
`verify.Result` and adds no production `STATE_VALUE_INCLUSION` guarantee.
Mutating or decoding a result cannot construct a query/state handle.

The gateway's `isFinalized` is retained only as an unauthenticated frontier
hint. It is not a stored 18th ABI field or a fact at H. This API does not emit a
Settlement-delay predicate, consensus finality, STF correctness, funds release,
recipient receive, freshness or spendability. All 17 stored fields are compared;
a matching frontier hint cannot rescue a mismatched proof or row.

## Explicit local limits

| Boundary | Schema-1 rule |
| --- | --- |
| Profile document | At most 16 KiB including outer whitespace; exact required fields |
| Request document | At most 2 KiB including outer whitespace; exact required fields |
| Source label | Nonempty, valid UTF-8, at most 1,024 bytes, no control characters |
| Complete state/gateway RPC response | At most 32 KiB including wrapper and whitespace, independently per call |
| Raw proof | Explicit positive cap from 743 through 12,391 bytes |
| Siblings | Explicit maximum from 0 through 256; zero means no siblings |
| ABI value | Explicit cap from 640 through 4,096 bytes |
| Three dynamic ABI fields | Individual positive byte limits and a positive cumulative limit, each at most the value cap |
| SMT encoding | Canonical encoding required; equivalent stored zero siblings are refused locally |
| ABI encoding | Exact offsets, lengths, integer widths, zero padding and full consumption |
| String interpretation | Explicit UTF-8 or opaque-byte rule; no implicit normalization |

These are local unsupported-data boundaries, not node/trie protocol limits.
Caps are checked before copying provider-sized inputs. A larger witness cannot
silently enlarge the policy. RPC hashes use canonical lowercase hex and byte
fields canonical base64; missing/null/duplicate/unknown/case-alias fields refuse,
except source-compatible nullable value/byte fields. Null whole results are
unavailable. A nil and empty byte field have the same empty ABI interpretation.

Opaque non-UTF-8 executor-pillar bytes can be returned to Go callers, but JSON
result encoding refuses lossy replacement. Such callers need an explicit
lossless binary/hex output policy. The normal selected UTF-8 rule refuses those
bytes during ABI decoding. No persistent result cache or unbounded batch API is
created.

## Executed-control scope and open gates

The tests keep the following evidence scopes separate:

- The unchanged original-node proof and ABI corpora retain their historical
  execution pins. Native reads/composition do not reexecute or relabel a node.
- Independent Python `hashlib`/`struct` bytes fix the 302-byte typed-context and
  158-byte query preimages, plus one 839-byte mathematical proof. Its root is
  deliberately different from the recorded signed-header root.
- Historical recorded signatures exercise owned-header/request/persistence binding
  and RPC-to-query refusal. Wrong provider roots, copied root hints with wrong
  proofs, changed context/tip/key, malformed encodings and resource overflows
  produce no row. Those refusal controls reuse their existing signatures.
- The separate [positive original-node fixture](recorded-batch-entry-witness.md)
  includes its original test-producer signatures and matching stored proof.
  Exported-API, persistence and compiled CLI checks replay that capture without
  producing signatures or running the node again.

The matching recorded-fixture query does not select live trust or qualify a
selected-network consumer. A matching selected-network capture and an actual
selected-network CLI/consumer result remain open,
along with the [D0-D6 gates](typed-state-roadmap.md). The isolated chain-100
fixture does not establish chain-69 activation. Production v1/v2 behavior and
the default state-value refusal remain unchanged.
