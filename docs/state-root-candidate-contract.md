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


## Empty retained versions are not unavailable history

The [retained empty-root experiment](../tools/gen-state-root-vectors/README.md#retained-empty-roots-and-last-node-reclamation) independently binds 39 logical snapshots and 1,560 finite cells from the unchanged NodeTree. An empty committed version retains a version-to-zero-root record and canonical absence proofs. Missing folded heights and pruned versions refuse. Stored zero remains inclusion; last-leaf deletion, historical reference reclamation and later reinsertion survive clean reopen/compaction.

These finite synthetic observations do not authenticate selected Momentum hashes or complete snapshots, qualify crash recovery/resource budgets, execute node lifecycle/import or enable production state proofs. The retained-hash failure and explicit header/profile/activation, anchor, schedule, context-pin and independent human-review gates remain open.

### Maximum-height API boundary remains unqualified

The separate [height-boundary research](../tools/gen-state-root-vectors/README.md#low-level-uint64-height-boundary-counterexample)
reproduces a low-level regular `Commit(0)` success after a frontier at the maximum
uint64 height. Height-zero reads ignore its written version record; the next
commit builds from the implicit origin. All three finite consumer cases refuse,
including an empty-root match. This synthetic boundary establishes neither
production reachability nor a fix. Future lifecycle/import callers require an
independent monotonic, profile-bounded height check with non-overflowing successor
arithmetic. It cannot be inferred from an internally valid SMT proof. Hash-bound
retained identity, chain/header validation and production activation remain open.


### Staged replay ownership and failure boundary

The [serial staging experiment](../tools/gen-state-root-vectors/README.md#serial-staging-and-injected-replay-boundaries)
binds seven finite NodeTree cases, 50 logical snapshots, 1,000 direct read cells
and 60 raw replay callbacks. Default LevelDB batch replay returns nil. The seven
injected errors come only from a research implementation of the public Patch
interface, with separately recorded callback cuts; no default failure or
production reachability is inferred.

Failed `Update` preserves the prior stage. Failed `AccumulateFrom` can retain a
partial merged stage, including an empty initialized stage before any callback.
Successful `Update` replaces prior accumulation. A clean reopen discards staging;
a full retry and the default accumulation control recover the independently
selected complete fixture. Callers must check each result, rebuild the entire
intended staged range after an error, and hold exclusive ownership through commit.
Valid own-root proofs do not qualify complete replay: 16 of 28 boundary proofs
fail the selected fixture. All seven consumers remain `REFUSED`, including the
three matching fixture roots. Concurrency, storage faults, resources, snapshot
import, accepted header binding and production state-proof gates remain separate.

### Patch dump decoding before replay

The [patch decode corpus](../tools/gen-state-root-vectors/README.md#patch-dump-decoding-and-diagnostic-replay)
binds 232 finite inputs to the unchanged candidate's constructor and locked
LevelDB dependency. Ordinary Load errors retain completed record indexes and
return a patch alongside the error; the diagnostic replay can therefore deliver
a prefix. A full-input dump hash does not establish successful decoding or
complete callback delivery. Syntax-valid boundary truncations and equivalent
overlong encodings also require independently selected complete-patch bytes.

Huge length fields cause recovered bounds panics in this local 64-bit reference.
These exceptions and deliberate post-error replay are research observations,
not qualified production reachability or an upstream fix. All four pinned
constructor call sites check ordinary errors statically, with panic or error
propagation; none was executed in this mode. Import acceptance must separately
bound raw sizes, lengths and record counts, reject decoder errors, bind the
intended complete input and prevent partial effects. Self-consistent state
cannot replace that contract. All 232 synthetic consumers remain `REFUSED`.

### Bounded import prototype and complete callback staging

The [bounded research import contract](../tools/gen-state-root-vectors/README.md#bounded-patch-import-and-detached-staging)
checks explicit positive raw/record/key/value limits against fixed research
ceilings. Unsigned lengths must fit both the selected cap and remaining bytes
before conversion or slicing. Only a copied input with independently selected
byte count, ChangesHash and record count reaches the unchanged constructor.
Equivalent nonminimal varints and duplicate writes require their own complete
raw selection; final state equality cannot select or normalize an input hash.

Every constructor error or nil patch is rejected. Replay writes only to a
detached owned map and must deliver the exact planned callback sequence in order,
without an error, omission, extra record or changed key/value. The dump remains
bound before and after replay. One map replacement follows all checks. In 264
finite cases, 254 rejections preserve the entire initial map; five reject after
staged callbacks, including an injected error after all three records. Ten
research selections complete staging. All 264 proof consumers remain `REFUSED`.

The injected failures are harness controls, not observed default backend faults.
No panic recovery, production caller, NodeTree or disk import executes here.
Input was already resident in memory; the raw cap precedes the prototype's copy.
The [subsequent initial/transient target contract](../tools/gen-state-root-vectors/README.md#bounded-initial-and-transient-patch-targets)
checks entry/hex-payload caps before raw copying and clones only after complete
input selection, constructor and dump checks. Every prospective callback state
must also fit; a later Delete cannot authorize an earlier transient overflow.
The changed prior mode reproduces all 264 outputs byte for byte. A separate
46-case node-derived corpus binds both full maps and untouched original aliases
with an independently reconstructed fixture manifest digest. Twenty-eight cases
reject, 21 without cloning; 18 stage. All 46 proof consumers remain `REFUSED`.
Hex-text payload caps do not qualify whole-process memory or state domains.
A single exclusive
caller is required; shared-writer atomicity, crash durability and production
resource budgets are unqualified. A selected patch digest cannot authenticate
snapshot completeness, excluded state, canonical roots, finality or network
activation. Accepted header/profile/activation, anchor, schedule, context pin,
retained hash provenance, independent review and authenticated release remain
separate gates. The MIT runtime still refuses production state-value proofs.

### Read-only patch planning consumer

The [raw patch planner](../tools/gen-state-root-vectors/README.md#read-only-raw-patch-plans)
accepts a bounded regular file only with explicit expected ChangesHash, byte and
record counts and raw/record/key/value/output limits. It emits a complete ordered
hex plan after unsigned length, complete-byte selection and output-cap checks.
It does not decode through the node constructor, Replay, stage a map, import a
snapshot or write to storage. Syntax `READY` always retains proof `REFUSED`.

Digest selection is the caller's separate trust input; computing it from the
candidate file cannot authenticate the file or its completeness. The plan keeps
nonminimal spellings, duplicate order, empty Put and Delete semantics distinct.
Bounded file reads and incremental JSON cap checks precede stdout publication;
no path or rejected partial plan is emitted. Input, event and output buffers
still coexist, and interpreter overhead and real memory/latency budgets remain
unqualified. File transport, concurrent writers and disk/crash durability are
outside this read-only contract. The existing reference corpora/source pins,
explicit anchor/profile/schedule/context-pin boundary and production refusal
remain unchanged. A future writer requires its own target-size, exclusive
ownership, rollback/durability, full snapshot and authenticated header gates.

The [separate resource observation workflow](../tools/gen-state-root-vectors/README.md#read-only-patch-planner-resource-observations)
measures six preselected synthetic input families up to the raw/key/record
research ceilings in 36 fresh Python workers. Every complete encoded plan is
independently bound. Operation elapsed time and traced Python allocation peak
have narrower scope than the OS process high-water value; parent work, imports,
pre-exec accounting and cache state are documented separately. Windows working
set and Unix RSS observations keep distinct metrics. No threshold promotes
these observations to production budgets or NodeTree retention evidence. This
does not import a snapshot, authenticate a root/header/profile, or change proof
`REFUSED`.

The [selected-count read comparison](../tools/gen-state-root-vectors/README.md#selected-count-patch-read-allocation-comparison)
bounds raw read requests by the independent selected byte count plus one, with
exact returned length and unchanged descriptor/global/digest/record/output
checks. Its historical read function and historical encoder bytes are pinned,
with unchanged current parser pins;
72 fresh workers compare both readers over the six fixed inputs while binding
every complete plan independently. Reduced Python temporary allocation on small
inputs is an observation, with no latency, OS equivalence, whole-pipeline,
NodeTree or production-budget claim. An exact selected byte count cannot
authenticate snapshot completeness, concurrent consistency, canonical roots or
the accepted header/profile/activation. The proof consumer remains `REFUSED`.

The [bounded output encoder](../tools/gen-state-root-vectors/README.md#bounded-patch-output-encoding-comparison)
returns immutable complete JSON bytes from a bounded in-memory binary buffer.
Every ASCII chunk and the final newline must fit before publication; no writable
view or partial plan is exposed. Its separately pinned prior encoder and the
current default run with unchanged read/parser/plan helpers in 72 fresh matched
workers. Every complete result is independently bound across six fixed profiles.
Historical read comparisons retain the original encoder in both modes, and
standalone resource observations measure the current default. Variable Python
peaks are observations without universal zero-copy, latency, OS causality or
production-budget guarantees. This read-only consumer never imports, stages,
Replays or authenticates snapshot/root/header/profile/activation state; proof
`REFUSED` and the independent trust inputs remain unchanged.

### Whole owned research import resource boundary

The [separate whole import experiment](../tools/gen-state-root-vectors/README.md#whole-owned-import-resource-observations)
brackets raw/target validation, owned raw copying, unsigned selected-input
preflight, the pinned node constructor, detached cloning, replay and replacement
on twelve literal resident-input families. Complete maps, callbacks and original
aliases are independently bound. All 144 fresh-child outcomes and variable
samples are retained separately from deterministic conformance. Allocation
counter deltas are cumulative process-wide allocation; RSS is lifetime process
high water captured before output binding. Fixture/selection/setup and report
work are outside the timed operation, and map cloning shares immutable strings.

This prepares an import measurement method on owned research maps. It does not
measure a file-to-storage handoff or actual NodeTree retention, establish a
production budget, authenticate complete/excluded snapshot state or attach a
shared/durable writer. Retained-hash provenance, ownership/rollback/durability,
accepted VerifiedState/header/profile/activation, anchor, schedule, context pin,
independent review and authenticated release remain open gates. Production
state-value consumers remain `REFUSED`.

### Owned callback reuse boundary

The [fixed prior/candidate experiment](../tools/gen-state-root-vectors/README.md#owned-callback-string-reuse-comparison)
reduces duplicate callback encoding only after complete byte equality with owned
preflight strings. Immutable payloads can be shared; callback Value pointers,
mutable raw slices and original target maps remain separate. Actual mismatch
bytes, ordered callbacks, empty Put/Delete distinctions, selected raw digests,
initial/transient caps and every published/refused outcome are preserved.

All 288 local fresh-process samples and both versions' ownership controls bind
the same whole research operation. Native CI checks the recorded comparison;
it does not remeasure Go import. Observed cumulative allocation is neither peak
live memory nor an authenticated production budget. This change attaches no
storage writer, NodeTree, accepted VerifiedState, authenticated complete snapshot
or excluded-state proof. Caller exclusivity, header/profile/activation, anchor,
schedule, context pin, independent review and authenticated distribution remain
separate requirements. Production state-value consumers remain `REFUSED`.

### Opened regular file handoff boundary

The [private file-to-map research seam](../tools/gen-state-root-vectors/README.md#opened-regular-file-to-owned-map-research-handoff)
accepts a borrowed, stable regular-file descriptor and a caller-exclusive target.
Independent selection and initial caps precede file I/O; positional reads are
bounded by the selected count plus one under the 1 MiB raw ceiling. File type,
observed size, exact count, read errors and a second size check precede the
unchanged owned import contract. The descriptor stays open at its original
cursor, and source, selection or replay failures preserve the original map and
all aliases. No path opener, shared/durable writer or snapshot API is introduced.

Two local generations bind all 67 synthetic cases through the pinned node
constructor/replay, with separate direct read-only-descriptor and raw-ceiling
controls. Native CI binds recorded local conformance without running the Go
handoff. This is unsigned engineering evidence; source pins and file digests
do not authenticate execution provenance or trust inputs. Resource measurement,
atomic filesystem snapshots, actual NodeTree/storage handoff, complete/excluded
snapshot authentication, retained hashes, accepted VerifiedState/header/profile/
activation, anchor, schedule, context pin, independent review and authenticated
release remain separate requirements. Production state-value acceptance remains
`REFUSED`.

### Whole opened file resource boundary

The [separate file resource experiment](../tools/gen-state-root-vectors/README.md#whole-opened-file-handoff-resource-observations)
measures the complete opened-descriptor-to-owned-map call on fifteen literal
families, including source-size/count and initial/transient target refusals.
All 180 fresh child outcomes across two local generations bind complete maps,
ordered callbacks, original aliases, file digests/counters and borrowed cursor.
Fixture creation/opening, selection and initial bindings precede the measured
call; output checks, cleanup and serialization follow resource sampling.

Elapsed time, cumulative Go allocation and process lifetime RSS have distinct
scopes. RSS includes startup and setup; recently written fixtures do not qualify
cold-disk behavior. Native CI checks recorded Darwin/arm64 observations without
executing or remeasuring the Go handoff. Unsigned exit/hash records do not
authenticate execution or independent trust selection. No latency speedup,
cross-platform equivalence or production budget follows.

This evidence attaches no NodeTree/storage or shared/durable writer. Stable
source ownership, complete/excluded snapshot authentication, retained-hash
provenance, accepted VerifiedState/header/profile/activation, anchor, schedule,
context pin, human review and authenticated release remain separate gates.
Production state-value acceptance remains `REFUSED`.

### Complete-map low-level storage handoff boundary

The [separate tree handoff experiment](../tools/gen-state-root-vectors/README.md#complete-opened-file-map-to-low-level-nodetree-seed)
now carries an opened-file import's complete detached balance map into actual
low-level NodeTree Update/CommitBulk and a clean temporary LevelDB reopen. It
checks the balance-only key/value format and compares the full map's SMT root
with a separately selected synthetic root before creating storage. File or
ChangesHash digests cannot substitute for that root. Coherent omitted-zero and
omitted-delete maps, an excluded key, an empty value, a wrong root and import
refusals create no database.

Four finite seed sequences bind 16 complete logical snapshots and 512 root/proof
cells using independent full sparse and compressed graph/refcount models. All
132 actual local child outcomes remain source/corpus/binary bound. Named
file-to-map, root preflight, storage open, complete-patch staging, bulk commit,
close and reopen phases have separate variable elapsed/cumulative allocation
samples. Queries are outside phase measurements; process lifetime RSS includes
setup and interim observations. Closed physical files include LevelDB overhead.
Native CI checks these recorded local observations without Go storage execution.

This is a small, exclusive offline fixture handoff. It establishes no atomic
source snapshot, excluded-state authentication, shared/durable writer, crash
recovery, realistic archive/retention budget, authenticated retained-Momentum
identity or accepted VerifiedState/header/profile/activation. Independent
network trust inputs, anchor, schedule, context pin, human review and release
authentication remain separate gates. Production state-value acceptance stays
`REFUSED`.
