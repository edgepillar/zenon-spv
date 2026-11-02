# Experimental v3 owned header context

The explicit `verify.ExperimentalV3State` path composes the bounded candidate
RPC decoder with root-bound header hashing, signature checks, a finite producer
schedule, immutable retained state and trusted local persistence. It is separate
from production `VerifiedState` and its v1/v2 activation profile. No production
CLI flag, supported-network selection or state-value acceptance is added.

This is implementation evidence toward D2 in the
[typed-state plan](typed-state-roadmap.md). The selected-network first-v3
boundary, agreed trust inputs and real `BatchEntry` consumer exit remain open.
The code and fixture checks do not authenticate activation or close production
state-proof or irreversible-settlement `NO_GO` decisions.

## Explicit inputs and scope

`ExperimentalV3Profile` schema 1 requires every field once: version, network
genesis, selected anchor, first incoming v3 height, coverage end, node revision
and provenance Source. Genesis must be height 1 and have a nonzero hash. Anchor
chain ID must match; a height-1 anchor must equal genesis. The first incoming v3
height is at least 2, and the anchor is at or after its preceding height. This
v3-only path starts after an explicitly trusted anchor; it does not invent the
intervening v1/v2 history or a genesis-to-checkpoint proof.

Mainnet chain ID 1 and unknown schemas/revisions are refused. The selected node
revision is `938fca3b7787da86827a5eb63371509b36e14761`; it selects the known
208-byte v3 encoding. Neither this pin nor a Source label authenticates a live
network or the operator's activation assertion. First-v3 height is distinct
from a spork enforcement height and is never inferred from a peer response.

A finite operator-attested `ProducerSchedule` is mandatory. Its substantive
hash, chain ID, dense covered intervals and entries are revalidated on an owned
copy. An entry binds height, timestamp and the public-key-derived address.
Missing coverage refuses; a covered mismatch rejects. There is no disabled or
custom-authorizer fallback and no extrapolation beyond the schedule.

The independently selected profile, policy and schedule produce an
`ExperimentalV3ContextFor` diagnostic. `NewExperimentalV3State` requires the
matching nonzero expected fingerprint. Computing a diagnostic from provider
inputs and passing its hash back does not authenticate those inputs. The
constructor creates empty state and supplies no header or root.

## RPC, owned extension and root selection

`Client.FetchCandidateV3ByHeight` uses the existing JSON-RPC envelope and paged
range machinery, with caller-selected positive heights/counts. Every returned
height and complete page count must match the query. All pages share one 8 MiB
response budget; a later failure discards the entire range. Decoding still
returns unauthenticated candidates, never an owned state handle. Production
`FetchByHeight` and `FetchFrontier` continue to refuse v3.

`ExperimentalV3State.Extend` checks every candidate's exact version, chain,
profile coverage, selected-node minimum prices, root-bearing hash, Ed25519
signature and producer authorization. Every height/hash must link immediately
to the configured anchor or owned tip. The whole bounded batch succeeds before
a new handle is published. Failure returns the original handle. Earlier handles
and returned header copies remain independent of later caller mutations.

Accepted extension proves header-chain integrity, signature authenticity and
authorization under the configured schedule. Its trust envelope names the
configured anchor, external activation profile and external producer schedule.
Content inclusion, canonicality, state transitions and `STATE_VALUE_INCLUSION`
are not proven. Trusted resume additionally names persisted-state provenance.

`RootAt(H, expectedHeaderHash, expectedContext)` requires the owned context,
that exact retained header identity and at least W later headers. The root is
read from that accepted header, never supplied separately by a provider. It is
a header-root lookup; it does not verify a state proof or claim consensus
finality. Zero/uninitialized, missing, evicted, mismatched and too-shallow
queries return errors and a zero result, not an application absence or balance.

## Context and resource bounds

The context fingerprint is SHA3-256 over domain
`ZENON-EXPERIMENTAL-V3-CONTEXT`, bytes `00 01`, then:

1. Genesis and anchor, each as chain ID uint64BE, height uint64BE, raw hash.
2. Eight uint64BE words: schema version, first-v3 height, coverage end, W, K,
   maximum batch headers, projected-header byte cap and state-file byte cap.
3. The raw 20-byte selected node revision and raw schedule hash.

Source labels, peer metadata, file paths, retained history and executable identity
are excluded. Matching contexts do not authenticate those excluded inputs or
prove two saved files interchangeable. The chain-100 test configuration has an
independent 243-byte Python-derived context vector and independent schedule hash.

| Limit | Bound |
| --- | ---: |
| Complete profile JSON, including whitespace | 16 KiB |
| Profile Source metadata | 1,024 bytes; valid UTF-8 without controls |
| Explicit retained depth/history | `1 <= W < K <= 4096` |
| Explicit headers per extension | `1..4096` |
| Producer entries and coverage intervals | At most 4,096 each |
| Complete experimental persisted file | 8 MiB |
| Projected candidate header | Existing 8 KiB codec bound |
| Candidate RPC range | At most 4,096 headers and 8 MiB cumulative response bytes |

Raw momentum data/content retain their separate
[candidate decoder bounds](candidate-v3-rpc.md). These are local experimental
budgets, not agreed network or representative hardware measurements. Zero does
not disable experimental policy bounds. Typed and JSON inputs are checked.

Extension validates all incoming headers, then copies the retained suffix once;
it avoids shifting K headers after every input row. Contiguous private heights
permit constant-time root/header lookup without a mutable index, repeated
signature work or copying key/signature buffers for root-only reads.

## Persistence and compatibility

The separate file format is `zenon-experimental-v3-owned-state/v1`, with numeric
version 4. Native readers that support versions 1-3 refuse it. Experimental
readers require the exact complete schema and refuse native files. File,
profile, policy and nested header fields reject ambiguous or incomplete input.

`Save` uses the native temp/write/fsync/close/rename sequence and parent-directory
sync on non-Windows systems. Callers must hold exclusive ownership across
load/extend/save, for example with the existing state lock. Windows retains its
weaker replacement/durability contract. A post-rename error may leave a visible
new file whose crash durability remains unconfirmed. Encoding failures clean
their own temporary file and preserve the prior destination.

`LoadTrustedExperimentalV3State` requires a trusted regular local file and the
freshly selected configuration/pin. It bounds the complete bytes and member
count, checks the context, and revalidates every retained root-bearing hash,
signature, producer, coverage and adjacent link before returning authority.
Missing files remain errors. Changed settings refuse rather than silently
resizing or migrating the state. A saved evicted tail cannot re-prove its missing
ancestry or authenticate its own local-file provenance. This does not qualify
original-node state-tree recovery or root rebuilding.

The shared atomic-writer extraction preserves native serialized bytes. A
2,073-byte v1/v2 saved-state vector from the existing public signed fixture has
independent Python SHA-256
`b953f6794b1995cdd70f7836904e5b363a88e70555e1e1176210333d2aaa746f`.

## Executed controls and next gate

The new controls reuse the retained public chain-100 signatures at heights
12-14; no new signature, wallet, transaction or node execution is introduced.
One composed recorded-RPC workflow fetches, verifies, selects a header-derived
root, saves and resumes through the public APIs. It is an isolated fixture
workflow, not a live selected-network pilot. The source chain-69 genesis remains
a distinct cohort.

```sh
go test -race -count=1 -json \
  -run '^Test(ExperimentalV3|CandidateV3RPC)' ./internal/verify ./internal/fetch
```

Controls cover the independent context vector, configuration and schema
substitutions, finite schedule gaps, changed roots/hashes/signatures, atomic
batch failure, alias isolation/concurrent reads, byte/member limits, root depth,
context-bound resume, persistence errors and native refusal/byte compatibility.
Complete-suite and artifact qualification remain required on Linux, macOS and
Windows for each delivered source revision.

The next application binding must accept this owned header/context, derive the
Settlement/domain/batch key locally, verify bounded canonical proof bytes
against its root, strictly decode `BatchEntry` and compare the selected gateway
fields. A raw root or a copied diagnostic context must not substitute for the
owned handle. Actual network/profile selection and a real query remain separate
acceptance gates.
