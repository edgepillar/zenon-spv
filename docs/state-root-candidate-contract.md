# Candidate state-root commitment contract

Status: source-pinned research specification, not an enabled verifier profile.

The [isolated research tool](../tools/gen-state-root-vectors/README.md) includes
actual `FoldFilter` event fixtures alongside the unsigned v3/SMT byte corpus.
Its 22 key cases and 66 input operations independently match 18 retained
events. The family predicate accepts balance/storage prefixes with a minimum
length of 22 bytes; it does not validate a typed balance key's 10-byte token
suffix. An empty Put remains a Put at this filter stage. The later staged
empty-to-delete applier, persisted tree and chain lifecycle are not executed by
these filter fixtures and remain separate qualification gates.

A separate applier mode now calls public `NodeTree` Update/Commit/Root/Prove
APIs on a fresh temporary in-memory LevelDB. Eight selected raw keys, seven
checkpoints and 88 ordered events produce 56 independently checked proofs.
This bounded component exercise demonstrates zero/empty/delete and duplicate
event semantics; it does not qualify disk recovery, retention, reorgs, startup,
ledger state validity, proof RPC, authenticated headers or network activation.
The node candidate is
[`digitalSloth/go-zenon@56ce2c384966f2f1940967257a0788d3998a5eef`](https://github.com/digitalSloth/go-zenon/tree/56ce2c384966f2f1940967257a0788d3998a5eef).
The client baseline is the [native verification contract](verification-contract.md).
The existing client supports v1/v2 and refuses state-value proofs. This document
does not enable v3, change `Result.Proven`, or authenticate a network activation.

Extend the current client selectively. Keep node commitment lifecycle, snapshot
transport/import, and client proof verification as separate deliveries sharing
this contract. Authenticated election/fork choice and Bitcoin/Portal remain
separate tracks. A state root authenticates a value relative to a selected
header; it does not establish canonicality, consensus finality, freshness,
correct execution of every state transition, or permission to release assets.

## Committed key domain

The candidate's
[`foldKeep`](https://github.com/digitalSloth/go-zenon/blob/56ce2c384966f2f1940967257a0788d3998a5eef/common/trie/momentum_fold.go#L16-L45)
selects the account-store namespace and balance/storage subprefixes. It is a
prefix whitelist, not a validator of every typed key's complete shape.

| Query | Effective Momentum DB key | Candidate commitment / initial client scope |
| --- | --- | --- |
| Token balance | `03 || address[20] || 03 || token_standard[10]` | Included; first typed query, exactly 32 key bytes. |
| Contract storage | `03 || address[20] || 04 || storage_key` | Included by the fold; defer typed storage interpretation and its own bounds. |
| Chain plasma | `03 || address[20] || 05` | Excluded; refuse. |
| Account frontier identifier | `03 || address[20] || 00` | Excluded; refuse. |
| Received-block index / last-received sequencer | Account-local prefixes `06` / `07` | Excluded; these are not the frontier identifier. |
| Mailbox / pending sends | Top-level account mailbox namespace `04 || address[20] || ...` | Excluded; refuse. |
| ZNN balance index | Top-level namespace `08 || ...` | Excluded; a token-balance proof does not authenticate this separate index. |

The namespace is fixed by
[`ledger_store.go`](https://github.com/digitalSloth/go-zenon/blob/56ce2c384966f2f1940967257a0788d3998a5eef/chain/momentum/ledger_store.go#L21-L40)
and [Momentum prefixes](https://github.com/digitalSloth/go-zenon/blob/56ce2c384966f2f1940967257a0788d3998a5eef/chain/momentum/keys.go#L5-L12).
Account-local prefixes are in
[`account/keys.go`](https://github.com/digitalSloth/go-zenon/blob/56ce2c384966f2f1940967257a0788d3998a5eef/chain/account/keys.go#L3-L11).
The frontier uses
[`db.SetFrontier`](https://github.com/digitalSloth/go-zenon/blob/56ce2c384966f2f1940967257a0788d3998a5eef/common/db/store.go#L10-L30)
and the account namespace, rather than prefixes `06` or `07`.

Derive the full balance key locally from the independently selected address and
token. Require exact decoded widths and address/token checksum validation at
text boundaries. Do not let a provider choose a raw key or commitment profile
on the consumer's behalf. An absence proof for an excluded plasma, frontier or
mailbox key can be cryptographically valid under this partial tree even while
the ledger stores that key. Refuse the domain before interpreting the proof.

Use a distinct, versioned balance/storage SMT profile in a future implementation.
Do not silently accept it as `IAVL_STATE`: that existing reserved kind describes
a broader hypothetical state commitment. A research label or a provider's root
does not register a supported commitment kind.

## Balance values and zero

[`SetBalance`](https://github.com/digitalSloth/go-zenon/blob/56ce2c384966f2f1940967257a0788d3998a5eef/chain/account/balance.go#L12-L37)
uses [`common.BigIntToBytes`](https://github.com/digitalSloth/go-zenon/blob/56ce2c384966f2f1940967257a0788d3998a5eef/common/bytes.go#L33-L47),
which left-pads the integer's magnitude to **at least 32 bytes**. It is not a
minimal-width integer codec. In particular, an ordinary stored zero is 32 zero
bytes, not an empty byte slice. Values exceeding 256 bits are not bounded by
this helper alone; the protocol's balance range must be independently pinned
before fixing a typed value limit. Never truncate or wrap an oversized value.

The L1 fold deletes a leaf for a delete operation or a put with a zero-length
value. It preserves a nonempty value, including 32 zero bytes. The shared SMT
core can also represent a present-empty leaf; that core behavior must not be
confused with the L1 adapter's empty-to-delete rule.

The initial consumer contract must distinguish:

- **Present balance:** prove the exact stored bytes, decode with the pinned
  balance codec, and compare with the independently selected claim. A proven
  stored zero remains present.
- **Absent balance key:** prove absence inside the covered balance domain.
  [`GetBalance`](https://github.com/digitalSloth/go-zenon/blob/56ce2c384966f2f1940967257a0788d3998a5eef/chain/account/balance.go#L19-L31)
  returns zero for a missing key; the report may describe that balance semantic
  only under the approved profile and must retain `present=false`.
- **Excluded or unknown key:** refuse, even when a raw SMT absence verifies.

Presence comes from the verified proof flag, not whether RPC `value` is JSON
`null`, empty Base64 or a zero amount. Do not claim account nonexistence, token
nonexistence, total supply correctness, spendability, plasma availability or an
empty mailbox from a balance result.

## Header and activation binding

The candidate's
[`Momentum.ComputeHash`](https://github.com/digitalSloth/go-zenon/blob/56ce2c384966f2f1940967257a0788d3998a5eef/chain/nom/momentum.go#L68-L92)
adds the 32-byte `StateRoot` after the v2 pricing fields. All integer fields use
unsigned 64-bit big-endian encoding. The exact v3 hash preimage is 208 bytes:

| Byte offset | Field | Bytes |
| --- | --- | --- |
| 0 | Version | 8 |
| 8 | Chain identifier | 8 |
| 16 | Previous hash | 32 |
| 48 | Height | 8 |
| 56 | Timestamp | 8 |
| 64 | SHA3-256(data) | 32 |
| 96 | Existing flat account-header content hash | 32 |
| 128 | Changes hash | 32 |
| 160 | Next fusion price | 8 |
| 168 | Next work price | 8 |
| 176 | State root | 32 |

The candidate transaction verifier compares the root with the selected
previous state plus the executed, filtered patch; see
[`verifyStateRoot`](https://github.com/digitalSloth/go-zenon/blob/56ce2c384966f2f1940967257a0788d3998a5eef/verifier/momentum.go#L406-L425).
Client proof verification does not execute that patch and must not claim
`STATE_TRANSITION` from a matching proof.

An accepting implementation needs explicit network/genesis identity, exact
header height/hash, independently sourced anchor, producer schedule and
activation inputs, plus a context pin containing the commitment profile and
new schema versions. Preserve immutable verified state, writer locks and
`W < K <= 4096`; specify migration/refusal instead of reinterpreting saved v1/v2
state. Require all three v3 extension fields at the wire boundary, strict
32-byte root decoding, and exactly the supported version. The hashing helper's
`>= 3` branch is not authorization to accept unknown versions.

[`StateRootSpork`](https://github.com/digitalSloth/go-zenon/blob/56ce2c384966f2f1940967257a0788d3998a5eef/common/types/spork.go#L39-L64)
contains a placeholder and states an ordering relative to Dynamic Plasma.
The [version switch](https://github.com/digitalSloth/go-zenon/blob/56ce2c384966f2f1940967257a0788d3998a5eef/verifier/momentum.go#L147-L165)
prioritizes the state-root flag; it does not itself enforce that ordering.
Qualify pre-activation, activation and post-activation boundaries against the
selected node revision and authenticated profile. The candidate source, peer
agreement, a version field and green CI do not prove network activation.

## Sparse proof byte contract

The source profile in
[`hash.go`](https://github.com/digitalSloth/go-zenon/blob/56ce2c384966f2f1940967257a0788d3998a5eef/common/trie/hash.go#L31-L64)
uses SHA3-256, not Keccak-256:

```text
path = SHA3-256(full_effective_key)
leaf = SHA3-256(path || raw_value)
empty_subtree_at_every_level = zero32
parent(left, right) = zero32 if both are zero32
                     otherwise SHA3-256(left || right)
```

Leaves are at depth 256. Read path bits from the most significant bit at depth
0. The shared path-native core takes the already derived path and does not
hash it a second time. Reconstruct from depth 255 up to depth 0, ordering each
sibling according to the corresponding path bit.

[`proof.go`](https://github.com/digitalSloth/go-zenon/blob/56ce2c384966f2f1940967257a0788d3998a5eef/common/trie/proof.go)
encodes the following compressed proof:

| Field | Bytes / constraint |
| --- | --- |
| Flags | 1; bit 0 is presence, bits 1 through 7 are zero. |
| Path | 32; must equal the locally derived balance path. |
| Leaf hash | 32; zero for absence, exact value hash for presence. |
| Sibling bitmap | 32; index 0 corresponds to depth 255, MSB first within each byte. |
| Sibling count | 2, big-endian; equals bitmap popcount, at most 256. |
| Siblings | `count * 32`, deepest first. |
| Present-only value length | 4, big-endian. |
| Present-only value | Exactly that length, with no trailing bytes. |

An absent proof is `99 + 32 * count` bytes. A present proof is
`103 + 32 * count + value_length` bytes. If an approved first balance profile
limits values to 32 bytes, its maximum proof is 8,327 bytes; the corresponding
absence maximum is 8,291 bytes. The 32-byte value policy remains a decision
gate, not an inferred node-enforced range. Bound decoded bytes, encoded RPC
bytes, siblings, value size, batch size and cumulative work before allocation
or hashing; do not adopt the generic codec's uint32 value capacity as a limit.

The encoder omits zero siblings. The decoder checks count, length, flags and
leaf consistency but does not explicitly reject a stored zero sibling whose
bitmap bit is set. Record such encoding differences in conformance vectors;
agree any stricter canonical-proof policy before accepting network proofs.
Do not report an unexecuted parser comparison as demonstrated compatibility.

The [proof RPC](https://github.com/digitalSloth/go-zenon/blob/56ce2c384966f2f1940967257a0788d3998a5eef/rpc/api/ledger.go#L327-L401)
returns `value`, `proof` and `root`; the byte slices use Base64 on the wire.
Treat all three as untrusted. Require RPC root equality with the root inside
the verified header at the exact selected height/hash, and bind the report to
that identity. The RPC's height lookup does not replace header verification
or independently selected consumer expectations.

## Coordinated implementation and qualification

The [isolated candidate byte corpus](../tools/gen-state-root-vectors/README.md)
now compares ten unsigned Momentum preimages, six sparse roots and 41 actual
candidate proof outcomes with a separate stdlib Python oracle. It records
present zero, absent balance, a 33-byte magnitude boundary and two node-accepted
stored-zero-sibling encodings. This primitive conformance work does not execute
the L1 fold, persisted tree lifecycle, proof RPC or network activation. The
existing production client still refuses v3 and state-value proofs.

The separate in-memory applier corpus executes the actual candidate staged
applier through six `NodeTree` commits. Its independently maintained leaf map
and bottom-up roots match all seven checkpoints and all 56 encoded proofs.
Eighteen controls guard selected keys, synthetic version identities, event
ordering, roots, proof bytes and execution-scope claims. The two earlier
corpora remain unchanged. Native CI runs independent fixture checks; actual
reference API generation and database opening remain a separate local step.
Synthetic version hashes are not authenticated Momentum identities; this
small memory history is not persisted node lifecycle or resource qualification.

| Delivery | Concrete work | Completion gate |
| --- | --- | --- |
| Commitment profile | Exact covered key families, value/zero semantics, root/proof encoding, explicit resource policies and activation/header binding. | Node/client maintainers agree a versioned profile; open policies are resolved and source-pinned. |
| Independent fixtures | Pure verifier and separate byte oracle; node-produced v3 preimages, roots, present/absent balances and refusal vectors. | Compare original bytes and independent computations; preserve every failed case and exact generator/source pin. Synthetic vectors do not demonstrate activation. |
| Client compatibility | Strict v3 models, RPC conversion, bundles, immutable/persisted state, context migration and typed balance reports/consumer checks. | Adversarial tests and exact-source native CI/artifact qualification; existing v1/v2 and refusal behavior remain explicit during development. |
| Node lifecycle | Readiness, activation, build/import, retention, reorg, crash recovery and hash-bound version provenance. | Execute negative tests, including an ahead tree from another fork; independent source review and target-hardware measurements. |
| Snapshot import | Separate chunk/transport digests from reconstructed state roots; canonical keys/values, duplicates, missing records and excluded-state handling. | Recompute the covered root and compare with a verified header. Authenticate or reconstruct excluded consensus-relevant state separately. |
| Read-only pilot | Explicit activated experimental profile, selected address/token and height/hash, exact node/client binaries and private report channel. | Actual node/client proof and consumer outcomes with failures preserved; human review and release provenance remain independent gates. |

Start fixtures with stored zero, absent balance, positive balance and boundary
values. Include wrong address/token, raw-key substitution, double-hashed path,
SHA3/Keccak confusion, sibling order/endian changes, malformed flags/counts,
truncation/trailing bytes, inconsistent RPC value/proof, wrong root/header,
excluded-key absence, unknown profile/version, stale context and activation
boundary cases. A stale or conflicting header requires an explicit trust
policy; a mathematically valid proof cannot establish its canonicality.

For mailbox completeness, one selected send's absence does not prove that no
other pending send exists. SHA3 paths do not preserve address-prefix ordering.
A future mailbox profile needs an authenticated complete collection or a
maintained count/root with atomic send/receive/reorg updates. Merely expanding
the key whitelist does not complete this requirement.

For snapshots, use separate `transportDigest`, reconstructed
`stateCommitmentRoot` and expected `headerStateRoot`. A matching balance/storage
root authenticates only that projection. Plasma, mailbox and frontier can
change without changing it. Do not label the complete snapshot authenticated
without validating those excluded components and their authoritative inputs.

The [startup path](https://github.com/digitalSloth/go-zenon/blob/56ce2c384966f2f1940967257a0788d3998a5eef/chain/state_tree.go#L267-L295)
and [NodeTree truncate](https://github.com/digitalSloth/go-zenon/blob/56ce2c384966f2f1940967257a0788d3998a5eef/common/trie/nodestore.go#L1269-L1319)
are now exercised by the [isolated component startup fixture](../tools/gen-state-root-vectors/README.md#separate-real-chain-component-startup-fixture).
A controlled ahead tree from fork A retains A's root at height H while startup
rollback writes fork B's identifier at H and marks ready. A clean reopen retains
that mismatch. Three independent consumer observations refuse B's selected state
because the returned root remains A's. Hash-bound version provenance is still a
failed qualification gate. This synthetic temporary-database reproduction is
not a demonstrated remote attack or a production crash/reorg qualification. Existing [mid-build reorg tests](https://github.com/digitalSloth/go-zenon/blob/56ce2c384966f2f1940967257a0788d3998a5eef/chain/tests/state_tree_build_test.go#L94-L180)
also mean that a blanket claim that all such reorgs are skipped is unsupported.

The [controlled disk exit/reopen fixture](../tools/gen-state-root-vectors/README.md#separate-controlled-disk-process-exit-and-reopen-fixture)
adds five planned process exits after returned Open/New, Update, Commit,
Truncate or Prune calls, plus a normal-close control. Two reopens per case
independently check roots, values, proof bytes, unavailable versions and logical
record counts in small synthetic one-key databases. It does not qualify the
startup hash-bound provenance failure. The pinned [commit path](https://github.com/digitalSloth/go-zenon/blob/56ce2c384966f2f1940967257a0788d3998a5eef/common/trie/nodestore.go#L268-L333)
uses batch writes with default options. Exiting after the API returns does not
inject a write fault or prove power-loss, torn-write or production crash
recovery. Logical key/value bytes are distinct from physical disk usage and
realistic retention/resource budgets.

The [retention/resource fixture](../tools/gen-state-root-vectors/README.md#separate-retention-and-resource-observations)
adds controlled archive and retain-four policies with 64/256 initial keys and
16/32 commits. A separate full sparse tree and compressed content graph model
reconstructs roots, serialized nodes, shared refcounts, retained version IDs and
the logical record digest. All 504 selected Root/Prove observations remain equal
through clean reopen and manual compaction; stored zero, deletion and a missing
version remain distinct. Variable closed-file lengths, own child RSS and API
timings are preserved outside the deterministic conformance corpus. Compaction
may increase file bytes, and prune write logs can exceed archive file bytes.
These small synthetic samples prepare a measurement method; they do not measure
real chain churn, archive replay, bulk build/import, activation pauses or target
hardware acceptance budgets. The retained-version provenance failure stays open.

Measure actual committed-key count/churn, build/import wall time, peak memory,
archive/pruned disk, compaction, proof latency/size, root computation and insert
pauses for the production content-addressed `NodeTree`. Keep hardware, dataset,
retention, source/binary pin and failed runs with each sample. The candidate's
per-height rate comment does not measure bulk build speed. Neither an
engineer-month estimate nor a calendar date closes a deployment gate.

The isolated [StateProof wire fixture](../tools/gen-state-root-vectors/README.md#separate-stateproof-serializer-and-synthetic-binding-fixture)
calls the actual pinned response serializer and independently checks seven
encoding cases plus seven primitive proofs. Its local root/key, unsigned header
identifier and context-pin selections model binding without authenticating a
header or profile. `StateProof` returns no key, height or Momentum hash; a future
client must preserve those inputs independently and compare the returned root
against an accepted header. A serializer match does not qualify `LedgerApi`
execution, its readiness/activation/retention behavior, a JSON-RPC envelope,
network activation or a production consumer result. Stored zero, absent value
and present-empty shared-core bytes remain distinct; the last is refused as a
typed balance. Production v3/state-value refusal and lifecycle/resource gates
remain unchanged.

The [separate actual LedgerApi method fixture](../tools/gen-state-root-vectors/README.md#separate-actual-ledgerapi-method-fixture)
executes the pinned exported constructor/proof/root methods under explicit
recording synthetic chain/store stubs. Its 40 observations and 160 call events
provide method-forwarding conformance, with independent identifier/key/error
and unsigned root/context checks. The source's `>= 3` method gate does not
authorize future client versions or prove activation. Store-returned
HashHeight and root/proof consistency still require separately selected trust
inputs. Nineteen method errors and seventeen consumer refusals remain distinct
from the three research balance and one research root matches. Injected
readiness/retention errors do not qualify actual chain lifecycle; no RPC
dispatcher, transport or accepted `VerifiedState` integration runs in this mode.
All four previous corpora, strict v3/state-value refusal and the independent
profile/release/lifecycle/resource gates remain intact.

The [separate offline dispatcher fixture](../tools/gen-state-root-vectors/README.md#separate-offline-http-and-json-rpc-dispatcher-fixture)
executes actual HTTP validation, JSON-RPC parameter decoding, two read-only
Ledger delegates and success/error envelopes through in-memory requests and
recorders. Its 86 cases yield 60 actual method calls and 282 recorded chain/store
events; an independent fixed inventory checks request/response bytes and exact
IDs, heights and raw keys. Twenty controls preserve a separate strict synthetic
consumer policy even when the reference codec accepts duplicates, trailing
input, loose ID/version forms or array keys. Returned data with an error never
becomes a success payload. Five earlier corpora stay identical. This mode starts
no listener and uses the same explicit recording stubs; live transport, actual
chain `stateTree`, accepted-header/profile binding and lifecycle/resource
qualification remain separate. Production v3/state-value refusal stays intact.

Research and selective implementation can proceed now. Production state-proof
acceptance remains gated by the profile, verified header/activation binding,
independent conformance, lifecycle qualification and review. Bridge/custody
and irreversible settlement require their own canonicality/finality/freshness
and security decisions.

## Complete fixture seed and retained tail comparison

The [bounded bulk/tail experiment](../tools/gen-state-root-vectors/README.md#scale-churn-and-complete-fixture-seed-with-retained-tail) compares 64/256/1024-key synthetic workloads with cyclic updates, zero and deletion. It independently binds the complete selected raw seed map, the sequential Commit height-gap refusal, one low-level CommitBulk and three tail commits. All four retained versions must have the same canonical root/proof bytes and compressed physical-node/refcount graph as sequential construction and pruning across clean reopen/compaction.

These 756 finite read observations and separately recorded input-preparation, disk/RSS and API samples prepare a construction comparison. They do not execute chain background build or snapshot import, authenticate complete snapshot/excluded state, qualify historical archive replay, repair the retained-version provenance failure or establish real-chain resource budgets. Explicit accepted-header/profile/activation, anchor, schedule, context pin, human review and authenticated release gates remain unchanged. Production state-value acceptance stays disabled.


## Bulk guard and incomplete fixture boundaries

The [finite bulk guard experiment](../tools/gen-state-root-vectors/README.md#bulk-ordering-staged-retry-and-shared-roots) separately executes invalid bulk heights, staged retry, serial zero/delete/reinsert accumulation and empty-write-set shared-root reference accounting on the unchanged NodeTree. An independent full sparse tree and compressed graph bind all 47 logical snapshots and 1,880 finite read cells, including clean reopen and compaction.

An omitted seed zero or accumulated delete still produces a coherent low-level bulk tree. Its proofs match that observed root and fail against the separately selected complete fixture root. Neither successful CommitBulk nor self-consistent proofs authenticate snapshot completeness. Synthetic selected roots do not provide network trust inputs, repair retained-hash provenance, qualify snapshot import/resources or enable production state-value acceptance. Caller exclusivity, accepted header/profile/activation, anchor, schedule, context pin and human review remain independent requirements.
