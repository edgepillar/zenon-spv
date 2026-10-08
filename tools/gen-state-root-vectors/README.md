# Candidate state-root byte research

This isolated tool produces unsigned synthetic fixtures from
[`digitalSloth/go-zenon@56ce2c384966f2f1940967257a0788d3998a5eef`](https://github.com/digitalSloth/go-zenon/tree/56ce2c384966f2f1940967257a0788d3998a5eef).
The complete source tree is `d5abff528566a561e1a53a46103cb4b15ff63c6c`.
The [source manifest](source-pins.json) binds all 394 blobs, sizes, SHA-256
digests and Git modes; the reproduction driver reconstructs the Git tree.
The [candidate contract](../../docs/state-root-candidate-contract.md) defines
the research scope and unresolved protocol decisions.

The fixture contains:

- Ten Momentum hash preimages: v1/v2 ignore a populated root, while v3 appends
  the raw root at byte 176 in a 208-byte preimage. Cases cover empty/binary data,
  ordered content, different roots and unsigned integer boundaries.
- Six independently reconstructed trees: selected balance magnitudes, empty
  and present-empty shared-core states, path/bitmap bit boundaries and full
  256-sibling presence/absence cases.
- Forty-one actual candidate proof-verifier outcomes: 24 matches and 17
  malformed, path-mismatch or root/value-mismatch outcomes. Original canonical
  proof bytes are compared byte for byte with an independent encoder.

The generator calls the node's `Momentum.ComputeHash`, `BigIntToBytes`,
`RootOfLeaves`, `ProveByPath`, `VerifyProofByPath` and `VerifyAbsenceByPath`.
The stdlib Python oracle builds trees bottom up using integer path positions;
the node builds them by recursive path partitioning. No expected root or
preimage is obtained from the SPV verifier. The selected full balance key is
`03 || address[20] || 03 || token[10]`, hashed once with SHA3-256.

Stored zero is 32 zero bytes and remains present. A covered missing balance key
has `present=false` even when its interpreted amount is zero. A 257-bit
magnitude becomes 33 bytes; this low-level helper fixture does **not** establish
a valid ledger balance range. Present-empty path-native leaves are shared-core
cases, not evidence that the L1 fold stores empty values. The default byte
fixture does not execute the L1 fold, persisted `NodeTree`, RPC or
activation/lifecycle paths. The separate filter fixture below calls only the
family-filter API; it does not execute the staged empty-to-delete applier.

Five raw-key absence controls verify mathematically but are refused as typed
balances: plasma, frontier, mailbox, the separate ZNN index and contract
storage. The storage family is covered by the candidate fold but still needs
its own typed query contract. None of these cases proves complete ledger
absence, an empty mailbox or an authenticated full snapshot.

The candidate verifier accepts two equivalent proofs with an explicitly stored
zero sibling, although its encoder omits those siblings. The oracle preserves
that observed byte compatibility and reports the encodings as noncanonical.
Agree any stricter network policy separately; these diagnostics do not silently
change the candidate's acceptance behavior.

## Run independent checks

```sh
python3 -I -B tools/gen-state-root-vectors/check_test.py
python3 -I -B tools/gen-state-root-vectors/check.py
```

Twenty-seven controls cover unchanged node bytes and corrupted inputs, selected
address/token/key substitution, unknown versions, exact integer and field
widths, bitmap direction/count/order, truncation and trailing bytes, zero
semantics, value bounds, source inventory/tree pins and output preservation.
The checker accepts a `--source-revision` argument for an exact-checkout CI
report. A caller-supplied revision is metadata; authenticate the source and
report distribution separately.

The oracle's 2 MiB corpus, 1,024 leaves per tree, 4 KiB value and 1,235 decimal
amount-character limits bound local research work. They are not an agreed
network proof profile or measured production resource budget. The 8,291-byte
absence and 8,327-byte 32-byte-value inclusion cases exercise all 256 bitmap
bits. The inclusion size is conditional on a 32-byte value; the candidate's
balance helper alone does not prove that value bound.

## Reproduce node-derived bytes

Obtain a complete source snapshot at the exact pin through a separately
authenticated source channel. The driver allows root Git metadata but refuses
extra source files, missing files, changed bytes and symlinks. Keep research
metadata sidecars outside the selected snapshot. It copies verified sources
into a private temporary directory, builds only this generator, executes it
twice and requires identical outputs and unchanged source bytes. Go 1.25 and
the separate module's locked dependencies must already be available locally;
automatic module downloads are disabled.

```sh
python3 -I -B tools/gen-state-root-vectors/regenerate.py \
  --node-source NODE_SOURCE \
  --go GO_EXECUTABLE \
  --output NEW_CORPUS_FILE \
  --evidence-directory NEW_PRIVATE_EVIDENCE_DIRECTORY
python3 -I -B tools/gen-state-root-vectors/check.py --corpus NEW_CORPUS_FILE
```

Outputs and evidence use exclusive creation, flush/fsync and read-only file
permissions. Existing outputs are preserved. Failed child outcomes and their
original stdout/stderr remain in the private evidence directory. Review those
files for private paths before sharing. Source acquisition and dependency-cache
preparation are separate from offline reproduction.

The `v0.0.0` node module requirement is a placeholder. The driver installs the
verified snapshot as a temporary local replacement; a direct remote
`go run .` is not a reproduction method. No remote node module checksum is
claimed for this candidate. The root SPV module and runtime are unchanged.

This directory's original generator, oracle, controls and driver are explicitly
GPL-3.0-only; the complete [GPLv3 license](LICENSE) is retained. The reference
node source also carries GPLv3. The isolated tool is outside the root Go module
and is not an SPV runtime dependency or a distributed candidate binary. No node
implementation is copied into the runtime.

## Separate L1 family-filter fixture

`testdata/candidate-l1-fold-filter.json` records actual `trie.FoldFilter` calls
on in-memory `db.Patch` batches. Twenty-two independently selected keys carry
66 input operations: a Put of 32 zero bytes, an empty Put and a Delete per key.
The candidate preserves all three events for six balance/storage family keys
and removes the events for sixteen excluded or short keys, leaving 18 output
operations. No database or tree is opened.

The independent checker derives the selected keys locally, replays the family
predicate and compares every event in order. Fifteen controls cover key
substitution, family/width boundaries, scalar/shape errors, event corruption,
empty Put versus Delete, duplicate-key ordering, bounded inputs and false scope
claims. The original v3/SMT corpus remains byte-identical.

The filter accepts 22-, 31- and 33-byte balance-family keys. This is a raw family
predicate, not validation of the 32-byte selected address/token key contract or
evidence that such synthetic keys represent valid ledger balances. Contract
storage belongs to the committed family but needs its own typed query contract.
The filter preserves empty Put bytes; the later staged applier turns them into
deletions. This fixture does not execute that applier or establish L1 state
transition, persistence, retention or snapshot behavior.

```sh
python3 -I -B tools/gen-state-root-vectors/check_fold_test.py
python3 -I -B tools/gen-state-root-vectors/check_fold.py
python3 -I -B tools/gen-state-root-vectors/regenerate.py \
  --node-source NODE_SOURCE --go GO_EXECUTABLE \
  --fixture-kind fold-filter \
  --output NEW_FILTER_CORPUS_FILE \
  --evidence-directory NEW_PRIVATE_EVIDENCE_DIRECTORY
```

Omitting `--fixture-kind` reproduces the original byte corpus. Linux, macOS
Intel and Windows CI run both independent checkers and their controls on pinned
fixtures. Reference API generation remains a separate offline step. The local
research limits of 1,024 key bytes, 4,096 value bytes, 64 events per case, 128
cases and a 2 MiB file are neither ledger validity rules nor an approved network
profile or production resource budget.

## Separate in-memory NodeTree applier fixture

`testdata/candidate-l1-applier.json` records actual public `NodeTree`
`Update`, `Commit`, `Root` and `Prove` calls on a fresh temporary LevelDB backed
only by `storage.NewMemStorage`. The database is initialized, six synthetic
versions are committed, and it is closed before the generator emits the
fixture. This mode opens a database; the byte and family-filter modes do not.

Eight locally selected raw keys produce seven checkpoints, 88 ordered input
events and 56 actual node proof-verifier outcomes. Five keys belong to the raw
balance/storage families; three are excluded. The independent Python oracle
replays events into a path/value map, hashes each raw key exactly once, computes
each sparse root bottom up and compares every canonical encoder output and
presence/value observation. Eighteen controls cover selected identities, event
ordering, roots, malformed proofs, scope claims and bounded work.

Stored zero survives as a present 32-byte value. Empty Put and explicit Delete
both remove the leaf; later events for the same key win. Restoring zero
recreates the original root. Two full selected balance keys have 14 synthetic
typed observations; storage, short family keys and excluded keys produce 42
typed-query refusals even when their raw proof verifies. This establishes
neither valid ledger balances nor complete ledger or mailbox absence.

The proof-byte comparison is conformance to the candidate's encoder, not an
agreed network rule requiring canonical proofs. The original byte fixture's
observed equivalent stored-zero-sibling compatibility remains unchanged.
Checkpoint hash/height identifiers are synthetic metadata, not authenticated
Momentum headers or evidence of fork identity, canonicality or finality.

```sh
python3 -I -B tools/gen-state-root-vectors/check_applier_test.py
python3 -I -B tools/gen-state-root-vectors/check_applier.py
python3 -I -B tools/gen-state-root-vectors/regenerate.py \
  --node-source NODE_SOURCE --go GO_EXECUTABLE --fixture-kind applier \
  --output NEW_APPLIER_CORPUS_FILE \
  --evidence-directory NEW_PRIVATE_EVIDENCE_DIRECTORY
```

The byte, filter and applier modes run against the same complete source pin;
the previous corpus files remain byte-identical. Native CI checks the offline
fixtures with independent Python oracles. Actual node API generation remains a
separate local step. The inherited 2 MiB file, 1,024-byte key, 4,096-byte value
and 64-event batch limits bound research work; 64 checkpoints is an additional
local guard. They are not a network profile or a production resource budget.

The small in-memory history does not exercise disk reopen, crash recovery,
pruning, historical retention, reorgs, stale prebuild recovery, snapshot import,
node startup, consensus execution or proof RPC. Those lifecycle and resource
tracks remain open. Production v3 and state-value acceptance stays disabled.

## Separate StateProof serializer and synthetic binding fixture

`testdata/candidate-state-proof-wire.json` records the actual pinned
[`api.StateProof`](https://github.com/digitalSloth/go-zenon/blob/56ce2c384966f2f1940967257a0788d3998a5eef/rpc/api/ledger.go#L328-L336)
type's JSON serialization. Seven byte-format cases and seven primitive-proof
cases produce 14 serialized responses. Nil slices become `null`, non-nil empty
slices become empty Base64 strings, stored zero remains 32 present bytes and
the root uses the node hash type's lowercase hexadecimal encoding. Arbitrary
byte-format cases exercise encoding only; they do not assert valid proofs.

An independent bounded parser checks closed response shapes, duplicate fields,
canonical padded Base64, root width and null/presence semantics. Twenty controls
cover malformed wire/proofs, byte bounds, selected-key substitution, provider
root substitution, header identifiers and context pins. JSON whitespace and
escaped strings may preserve decoded transport bytes. Exact fixture spelling
checks the serializer's output, not a network consensus rule. Equivalent
stored-zero-sibling proof decoding remains supported by the research oracle.

The seven proof cases reconstruct roots and paths independently. Four give
synthetic typed-balance matches; mailbox and storage queries are refused, as is
a shared-core present-empty value. The selected raw key is hashed exactly once.
The expected root, unsigned v3 header hash/height and context pin are constructed
locally, never selected from the provider's response. These synthetic selections
model binding only: they are not accepted `VerifiedState` headers or an
authenticated network profile and cannot produce production acceptance.

The optional `candidate_wire` build tag imports the complete reference RPC
package. Its selected Ethereum dependency requires CGO, so this serializer mode
uses CGO and an available C compiler. The three previous modes still build with
CGO disabled. The research module locks the added import closure against the
pinned node's dependency checksums; initial public module acquisition is
separate from offline reference execution. The MIT runtime and its module graph
do not change. This mode does not construct or call `LedgerApi`, open a database,
start a node/RPC service, sign data or exercise a JSON-RPC envelope.

```sh
python3 -I -B tools/gen-state-root-vectors/check_wire_test.py
python3 -I -B tools/gen-state-root-vectors/check_wire.py
python3 -I -B tools/gen-state-root-vectors/regenerate.py \
  --node-source NODE_SOURCE --go GO_EXECUTABLE --fixture-kind wire \
  --output NEW_WIRE_CORPUS_FILE \
  --evidence-directory NEW_PRIVATE_EVIDENCE_DIRECTORY
```

All four modes retain complete 394-blob source validation and two identical
generations per invocation. All three prior fixture files remain byte-identical.
Native CI runs independent Python checks on offline fixtures; reference API
generation and CGO compilation remain separate local steps. Wire work is bounded
by a 2 MiB corpus, 64 cases per inventory, a 32 KiB response, 1,024 key bytes,
4,096 value bytes and the inherited compressed-proof byte limit. These are local
research guards, not a reviewed profile or a production resource budget.

`StateProof` contains value, proof and root only. It cannot authenticate a
selected key, height, Momentum hash or context. Actual `GetProof` readiness,
activation/version gates, retained history, root/proof consistency during
changes and live transport remain unqualified. Connecting a decoded result to
an accepted header/context is separate client work. Production v3 and state-value
acceptance remains disabled.

## Separate actual LedgerApi method fixture

`candidate-rpc-methods.json` records the actual pinned `NewLedgerApi`,
`GetProof` and `GetStateRoot` methods using explicit recording synthetic
`Zenon`, `Chain` and `MomentumStore` stubs. There are 40 method observations:
25 proof calls, 15 root calls and 160 recorded constructor/store/proof/root
call events. The independent checker builds expected identifiers from unsigned
header preimages, computes one-leaf roots/proofs bottom-up, checks exact raw key
bytes and full HashHeight forwarding, and compares error identity/code,
precedence and return bytes against a fixed selected inventory.

The [actual source methods](https://github.com/digitalSloth/go-zenon/blob/56ce2c384966f2f1940967257a0788d3998a5eef/rpc/api/ledger.go#L337-L403)
refuse zero height, lookup errors, missing Momentum and versions below three.
The reference lookup accepts later versions and forwards the identifier the
store returned; neither behavior selects a consumer profile or authenticates
that identifier. The research consumer refuses unsupported versions,
height/hash substitution, key substitution, oversized fields and provider roots
that disagree with its separate unsigned header/context selection. Coherent
provider proof/root replacement can match its own root and still fail this
selection. A nonzero root returned with an error remains an error.

The observations yield 19 reference errors, three synthetic typed balance
matches and one synthetic root match. Seventeen other consumer outcomes refuse
unsupported or mismatched inputs, including present-empty shared-core bytes.
Stored zero remains present, nil value denotes primitive absence, and a nil
request key differs from an empty slice even when their raw path bytes coincide.
Twenty controls cover gates, exact call order/identity, error precedence,
closed shapes/types, bounds, proof/value mismatch, context replacement and the
four previous immutable corpora. A padding-rounded Base64 value may decode at
most two bytes above its value limit before decoded-length refusal; a larger
encoded width refuses before decoding. The fixed 4,097-byte API observation has
a separately bounded expected-byte construction; earlier proof/value bounds
and consumer limits are unchanged.

The optional `candidate_rpc` build uses the already locked reference CGO import
closure. The separate mode does not start a full node or RPC listener, execute
the JSON-RPC dispatcher or transport, call actual chain `stateTree` methods,
open a database, run node tests, sign data or invoke transaction callbacks.
Injected not-ready/not-retained errors qualify API forwarding only. They do not
exercise actual readiness, build, retention, reorgs or recovery. Both earlier
optional RPC research modes need CGO; the first three modes keep CGO disabled.
The byte/filter/applier/wire/method modes validate the same 394 node blobs and
produce two identical outputs; all four earlier corpora remain byte-identical.
Native CI runs independent Python
fixture checks; actual reference method/CGO execution remains separately scoped
to local macOS ARM64.

```sh
python3 -I -B tools/gen-state-root-vectors/check_rpc_methods_test.py
python3 -I -B tools/gen-state-root-vectors/check_rpc_methods.py
python3 -I -B tools/gen-state-root-vectors/regenerate.py \
  --node-source NODE_SOURCE --go GO_EXECUTABLE --fixture-kind rpc-methods \
  --output NEW_RPC_METHOD_CORPUS_FILE \
  --evidence-directory NEW_PRIVATE_EVIDENCE_DIRECTORY
```

Actual JSON-RPC request/envelope behavior, accepted `VerifiedState` binding,
network activation/profile agreement, real chain readiness/retention,
persisted lifecycle, resource budgets, human review and authenticated release
remain separate gates. Production v3 and state-value acceptance stay disabled.

## Separate offline HTTP and JSON-RPC dispatcher fixture

`candidate-rpc-dispatcher.json` records 86 actual calls to the pinned
[`ServeHTTP` handler](https://github.com/digitalSloth/go-zenon/blob/56ce2c384966f2f1940967257a0788d3998a5eef/rpc/server/http.go#L227-L283).
Every request and recorder is in memory. An explicit wrapper registers only
`GetProof` and `GetStateRoot` as Ledger callbacks and delegates them to the real
`LedgerApi`; the server's built-in read-only metadata service remains registered.
The Ledger wrapper does not embed the full API or expose transaction callbacks.
Each server stops and each request body closes before the next case. No listener,
client connection, full node, wallet, signing or transaction runs.

The 40 previous method cases now pass through actual request decoding and
dispatch. Another 46 cases cover raw integer/string/numeric-lexeme IDs, namespace
and method lookup, required/excess/named parameters, exact uint64 heights,
Base64 and byte-array keys, JSON syntax/duplicates/trailing input, notifications,
batches and HTTP validation. The finite inventory yields 60 delegated method
calls and 282 constructor/store/proof/root events. There are 39 success and 41
error envelopes, three empty responses and three HTTP validation errors. The
4,097-byte value counterexample remains outside the consumer's 4,096-byte bound.
The 5 MiB HTTP case changes declared length on a small body; it measures neither
allocation nor real transport/resource limits.

The stdlib Python oracle selects request bytes independently, reconstructs
unsigned header identifiers and primitive proof bytes, and checks exact response
body bytes, raw ID lexemes, status/content type, delegate arguments and call
ordering. The [source response constructors](https://github.com/digitalSloth/go-zenon/blob/56ce2c384966f2f1940967257a0788d3998a5eef/rpc/server/json.go#L94-L129)
discard returned data when an error exists, including a nonzero root. Decode
and method-lookup errors occur before Ledger delegation. Null height becomes
zero and reaches the API's zero-height error. Nil and array keys preserve their
actual decoded bytes. None of these source observations selects a consumer key,
height, supported version or protocol profile.

Some diagnostic requests reach the reference API despite unsupported client
policy: scalar null/boolean/wide or fractional IDs, missing/wrong version,
ignored extra fields, last duplicate fields, trailing input, array keys,
notifications and OPTIONS. The separate research consumer requires one closed
POST request, independently selected typed ID/method/height, a bounded canonical
Base64 raw key and one closed success/error reply. It refuses these diagnostics,
mixed result/error payloads, wrong reply IDs/types, duplicate/trailing response
JSON, root/proof substitutions and changed unsigned context pins. Four balance
and one root results match only this synthetic selection. Seventeen selected
requests yield reference errors; 50 fail request policy and 14 have other
consumer refusals. A valid server response does not establish client trust.

The optional `candidate_dispatcher` build adds only stdlib `httptest` imports
under the existing source-pinned research module lock. All six modes validate
394 node blobs and generate twice; all five previous corpora remain identical.
Twenty new controls run in native Linux/macOS/Windows CI with the independent
fixture checker. Actual reference handler, parameter decoder, Ledger API and
CGO execution remain scoped to local macOS ARM64. Native CI does not execute the
reference node, handler or CGO stack.

```sh
python3 -I -B tools/gen-state-root-vectors/check_dispatcher_test.py
python3 -I -B tools/gen-state-root-vectors/check_dispatcher.py
python3 -I -B tools/gen-state-root-vectors/regenerate.py \
  --node-source NODE_SOURCE --go GO_EXECUTABLE --fixture-kind rpc-dispatcher \
  --output NEW_RPC_DISPATCHER_CORPUS_FILE \
  --evidence-directory NEW_PRIVATE_EVIDENCE_DIRECTORY
```

Actual chain `stateTree`, readiness/retention and hash-bound version provenance,
disk lifecycle/recovery, realistic resource budgets, accepted `VerifiedState`
binding, live transport/pilot, agreed profile/activation, human review and
authenticated release remain separate gates. Production v3/state-value refusal
and all MIT runtime inputs remain unchanged.

## Separate real chain component startup fixture

The optional `candidate_chain_startup` mode calls the actual pinned
`chain.NewChain` constructor and chain component `Init`/`stateTree` methods.
It supplies finite unsigned serialized momentum snapshots, a recording manager,
a cache already aligned with the selected frontier and a synthetic genesis
identity. Every unplanned input method fails. No genesis transaction, ledger
insertion, VM execution, `Chain.Start`, background builder or full node runs.
All 394 node source blobs remain unchanged under the existing module lock.

Ten cases execute eleven component initializations and 66 read API observations.
The empty tree reaches readiness for gaps of two and ten; gap eleven stays
not-ready and all six reads refuse. Equal-height hash mismatch and a mismatched
below-frontier ancestor also refuse. Matching prebuild, short catch-up and valid
rollback provide positive controls. Exact patch lookups, selected identities,
readiness/errors, root/value/proof bytes and the retained frontier after clean
close/reopen are checked independently. Twenty negative controls bind the
finite inputs and synthetic consumer selection.

The above-frontier counterexample is now executed locally: a prebuilt tree
holds A@3 with A@2 retained; the selected chain ends at B@2 with a different
balance. Startup truncates by height, writes B@2 as the tree frontier and reports
ready while preserving A@2's root/value. A second clean initialization continues
to expose that root. The independent consumer retains B's selected state and
refuses all three such observations, including the reopen. A cryptographically
consistent proof under A's root cannot replace B's selection. The backend's
height-only Root/Prove reads also return the same bytes for a different hash at
the same height; that API behavior does not authenticate version provenance.

This mode opens, closes and removes only small owned temporary disk LevelDB
state-tree databases. It demonstrates controlled startup and clean reopen
under synthetic chain/cache/genesis inputs, not a remote exploit, real-chain
reorg, crash/torn-write recovery, pruning, production retention or resource
budgets. Component printf messages and its diagnostic logger are discarded;
all method errors, results and traces remain explicit. The actual CGO reference
execution is local macOS ARM64. Native CI executes independent fixture controls
and comparisons without the node/CGO backend. All six previous corpora and the
MIT runtime remain unchanged.

```sh
python3 -I -B tools/gen-state-root-vectors/check_chain_startup_test.py
python3 -I -B tools/gen-state-root-vectors/check_chain_startup.py
python3 -I -B tools/gen-state-root-vectors/regenerate.py \
  --node-source NODE_SOURCE --go GO_EXECUTABLE --fixture-kind chain-startup \
  --output NEW_CHAIN_STARTUP_CORPUS_FILE \
  --evidence-directory NEW_PRIVATE_EVIDENCE_DIRECTORY
```

Hash-bound retained-version provenance is still a failed candidate qualification
gate. Fixing the reference node requires a separately reviewed upstream change;
this research does not patch the selected source. Accepted `VerifiedState`
binding, agreed profile/activation, human review and authenticated distribution
remain open. Production state-value acceptance remains disabled.

## Separate controlled disk process exit and reopen fixture

The optional `candidate_disk_lifecycle` mode exercises the unchanged pinned
`NodeTree` with six small owned temporary disk LevelDB databases. Five child
processes exit with a selected code after Open/New, Update, Commit, Truncate or
Prune has returned. A sixth child closes normally and writes a close marker.
The parent checks each child outcome and marker, then opens and closes each
database twice. It removes only its own temporary databases. No chain component
initialization, `Chain.Start`, background builder, full node or network runs.

Twelve reopens produce 240 finite root/value/proof observations. Staged writes
remain uncommitted; the returned commit, truncate and prune retain the selected
frontier and heights. The independent byte oracle checks 26 inclusion and 50
absence proofs and 88 exact unavailable-version errors. Twenty controls bind
the selected versions, child exit/close outcomes, method order, raw keys,
canonical proofs, retained records and closed scope. A coherent provider root
and proof cannot replace the independently selected state. Height-only reads
still do not authenticate a different hash at the same height.

The fixture counts logical LevelDB records and their key/value bytes. Retaining
one, two or three versions uses five, eight or eleven records, with 223, 403 or
583 logical bytes in this one-key fixture. The twelve separate observations sum
to 102 records and 5,196 key/value bytes; this is not a physical disk-size,
memory, compaction or latency measurement and does not qualify realistic
resource budgets.

These are planned process exits after completed API calls. They do not inject a
failure during a write, simulate power loss or qualify torn-write/sync durability
or production crash recovery. The pinned backend's batch writes use default
write options; this research changes none of them. Actual pure-Go reference
execution is local macOS ARM64. Native Linux/macOS/Windows CI runs the independent
fixture comparisons and controls without executing the node, LevelDB or child
exit experiment. All seven previous corpora and the MIT runtime remain unchanged.

```sh
python3 -I -B tools/gen-state-root-vectors/check_disk_lifecycle_test.py
python3 -I -B tools/gen-state-root-vectors/check_disk_lifecycle.py
python3 -I -B tools/gen-state-root-vectors/regenerate.py \
  --node-source NODE_SOURCE --go GO_EXECUTABLE --fixture-kind disk-lifecycle \
  --output NEW_DISK_LIFECYCLE_CORPUS_FILE \
  --evidence-directory NEW_PRIVATE_EVIDENCE_DIRECTORY
```

The startup retained-version provenance failure remains open. Accepted
`VerifiedState` binding, an agreed profile and activation, realistic retention
and resource measurements, independent human review and authenticated release
remain separate gates. Production v3/state-value acceptance stays disabled.

## Separate retention and resource observations

The optional `candidate_retention` mode uses the actual unchanged `NodeTree`
and four owned temporary LevelDB databases per generation. Initial states have
64 or 256 balance keys; 16 or 32 commits include cyclic updates, stored zero
values and deletes. Each size compares archive history with retaining the last
four versions. No chain initialization, background build or node service runs.
The reference generator supports Linux and macOS; the fixture checker supports
all native CI platforms and never opens a database or measures resources.

Each case observes roots, values, canonical proofs, frontier and logical records
before close, after clean reopen, and after manual compaction plus a second
reopen. The independent full 256-level sparse tree agrees with a separately
constructed compressed content graph. The graph model deduplicates physical
nodes across retained versions and counts each unique internal edge and version
root edge, reconstructing refcounts and serialized leaf/internal records. A
SHA-256 digest frames every sorted logical key/value record with its uint64
big-endian lengths. It binds node bytes and shared references, beyond counts.

| Initial keys / commits | Policy | Retained versions | Logical nodes | Logical records | Logical key/value bytes |
|---|---|---|---|---|---|
| 64 / 16 | Archive | 1–16 | 620 | 1,258 | 116,777 |
| 64 / 16 | Retain four | 13–16 | 203 | 412 | 36,872 |
| 256 / 32 | Archive | 1–32 | 2,029 | 4,092 | 386,016 |
| 256 / 32 | Retain four | 29–32 | 615 | 1,236 | 109,782 |

The twelve conformance rounds contain 504 Root/Prove observations, including
156 inclusion proofs, 114 absence proofs and 180 unavailable-version errors.
Twenty-one inclusion observations contain a stored zero. A missing historical
version is an error, not a zero balance or an absence proof. Height-only lookup
still does not authenticate a Momentum hash; the startup provenance failure
documented above remains open.

Two reference generations must produce identical conformance bytes. The driver
preserves both raw outputs and records variable samples separately in the private
`resource-samples.json`, bound to the corpus, source, reference binary hash,
Go version and command output digests. It does not compare sample values for
equality. Root/Prove, update, commit, prune, reopen and manual compaction times
use elapsed nanoseconds. Own child `getrusage(RUSAGE_SELF)` provides peak RSS
in bytes after platform unit conversion; this includes the fixture, NodeTree and
LevelDB, but excludes the compiler and other measurement children. It is a
process high-water mark, not a retained tree allocation measurement.

Physical observations sum regular file lengths only after each database closes.
They include all LevelDB files, logs and metadata. They are not filesystem
allocated blocks, write amplification or peak disk measurements. In the local
macOS ARM64 sample, pruned files were larger than archive files before manual
compaction, and archive file bytes increased after compaction. No monotonic
size-reduction assertion is valid. The optional sample checker validates shape,
units, inventory and corpus binding; it neither reproduces these measurements
nor accepts a performance budget. Load, caches, power and thermal state are not
controlled. These tiny local samples are not production capacity estimates.

```sh
python3 -I -B tools/gen-state-root-vectors/check_retention_test.py
python3 -I -B tools/gen-state-root-vectors/check_retention.py
python3 -I -B tools/gen-state-root-vectors/regenerate.py \
  --node-source NODE_SOURCE --go GO_EXECUTABLE --fixture-kind retention-resources \
  --output NEW_RETENTION_CORPUS_FILE \
  --evidence-directory NEW_PRIVATE_EVIDENCE_DIRECTORY
python3 -I -B tools/gen-state-root-vectors/check_retention.py \
  --corpus NEW_RETENTION_CORPUS_FILE \
  --resource-samples NEW_PRIVATE_EVIDENCE_DIRECTORY/resource-samples.json
```

Twenty controls check shared graph/storage semantics, prune policy, compressed
paths, zero/delete/absence, unavailable versions, coherent foreign proof
substitution, canonical bytes and exact scalar types. Separate sample controls
preserve variable measurements, source/binary/command binding and physical growth
without promoting them to production budgets. Linux/macOS/Windows CI checks these
fixtures; actual backend/resource execution remains a separate local experiment.
All eight prior corpora and the MIT runtime remain unchanged. Real-chain
key/churn datasets, bulk build/import, production crash/sync durability, accepted
header/profile binding, activation, independent review and release provenance
remain separate gates. Production v3/state-value acceptance stays disabled.

## Remaining gates

Production v3/state-value acceptance stays disabled. These synthetic research
fixtures leave consensus-valid blocks, network activation, live proof RPC,
real-chain state transitions, node lifecycle, canonicality, consensus finality,
freshness, authenticated producer election, an independently reviewed protocol
profile and release provenance unqualified. Address/token
text checksum boundaries, activation and context migration, verified header/RPC
binding, typed runtime results and realistic `NodeTree` measurements remain
separate implementation and qualification work.

## Scale, churn and complete fixture seed with retained tail

The optional `candidate_bulk_tail` mode compares two fresh `NodeTree` construction
policies for each of three finite synthetic workloads. Initial balance keys,
versions and later operations per version are respectively `(64,16,8)`,
`(256,32,32)` and `(1024,64,128)`. Cyclic updates include stored zero and deletion.
Each comparison uses the same independently described four final states.

Sequential construction stages each version with `Update`, calls `Commit`, and
prunes to retain four versions. Seed construction derives the complete selected
raw-key/value map at `versions-3` before opening the owned database. A regular
`Commit` at that height is deliberately refused by the unchanged node's ordering
guard. The existing `NodeTree.CommitBulk` then constructs that seed, followed by
three regular `Commit` calls for the tail. This executes a low-level bulk API;
chain background build and snapshot import remain unexecuted. The complete
fixture seed is not an authenticated snapshot or a proof of excluded state.

The seed manifest binds its height, present-key count and SHA-256 of sorted raw
records framed as `uint64BE(key length) || key || uint64BE(value length) || value`.
An independent Python leaf-map program derives this manifest, full sparse roots
and canonical proofs. A separate compressed graph model reconstructs serialized
nodes, shared refcounts and the exact logical database digest for all four
retained versions. The two policies must have identical frontier, logical
records and read results, including after clean reopen and manual compaction.
Older unretained and future versions return errors; origin-empty queries do not
create a retained version record. Twenty controls bind seed completeness,
ordering refusal, tail policy, raw domains, proof bytes and explicit open gates.

Six cases, three rounds and 42 Root/Prove cells per round produce 756 finite API
observations. `commit_calls` counts successful regular commits; the separate
`regular_seed_commit_error` records the additional refused regular call and
`bulk_commit_calls` counts successful seed calls. Fewer stored historical
versions or matching roots cannot establish history authentication or finality.
The earlier startup retained-version provenance failure remains open.

Variable measurements stay in a separate private `resource-samples.json` with
source/corpus/reference-binary and unmodified command-output digests. Input
preparation elapsed time includes constructing replay patches or deriving the
complete seed plus tail patches. The separately named prepared-patch aggregate
covers the subsequent Update/Commit/CommitBulk/Prune loop, including the regular
seed refusal, but excludes input preparation and database open. Commit time
includes that refusal and the successful bulk call. Both costs must be retained
when comparing construction; this experiment does not time source acquisition,
real ledger traversal, snapshot parsing/import or insertion pauses.

Own-child RSS is sampled after final close, before JSON encoding and process
exit. It includes input preparation, fixture plans, NodeTree and LevelDB; it is
not tree-only heap, final process RSS or a total system-memory measurement.
Closed regular file lengths are not allocated disk blocks, peak disk usage or
write amplification. Cache, compaction scheduling, thermal state and host load
are uncontrolled. File lengths and elapsed times may grow and are never compared
for deterministic equality or accepted as production resource budgets.

The actual reference runs locally on macOS ARM64 with CGO disabled. Portable
Linux, macOS Intel and Windows CI runs independent fixture controls only; it
neither executes this backend nor collects native resource observations. All
nine earlier corpora, 394 selected node blobs, the research dependency lock and
365 MIT runtime inputs remain unchanged. Real-chain data and churn, historical
archive replay, node build/import, target hardware acceptance, authenticated
retained identifiers, accepted `VerifiedState` binding, profile/activation,
human review and release provenance remain separate gates.

```sh
python3 -I -B tools/gen-state-root-vectors/check_bulk_tail_test.py
python3 -I -B tools/gen-state-root-vectors/check_bulk_tail.py
python3 -I -B tools/gen-state-root-vectors/regenerate.py \
  --node-source NODE_SOURCE --go GO_EXECUTABLE --fixture-kind bulk-tail \
  --output NEW_BULK_TAIL_CORPUS_FILE \
  --evidence-directory NEW_PRIVATE_EVIDENCE_DIRECTORY
python3 -I -B tools/gen-state-root-vectors/check_bulk_tail.py \
  --corpus NEW_BULK_TAIL_CORPUS_FILE \
  --resource-samples NEW_PRIVATE_EVIDENCE_DIRECTORY/resource-samples.json
```

## Bulk ordering, staged retry and shared roots

The optional `candidate_bulk_guards` mode executes four eight-key cases on fresh,
owned `NodeTree` databases. The first distinguishes missing staging from an empty
write-set, refuses origin/same/backward bulk heights and a regular seed gap,
then retries the preserved stage at an allowed height. Successful commits consume
staging. Empty bulk and regular commits reuse the same physical content graph;
each version adds a root reference, and pruning releases obsolete references
without deleting the latest reachable nodes.

The second case calls `AccumulateFrom` serially for complete seed, zero, deletion
and reinsertion patches, then commits one folded height plus a regular tail.
Intermediate folded heights have no version record. The caller controls the whole
staged sequence; this experiment does not qualify concurrent interleaving or replace
the caller's exclusive-lock requirement. Every operation observes the frontier,
Root/Prove bytes and exact sorted logical-record digest. Independent Python leaf
maps reconstruct both full sparse proofs and the compressed physical node graph,
counting each internal edge once and each retained version's root reference.

Two deliberately incomplete inputs omit a stored-zero seed entry or an accumulated
delete. Low-level `CommitBulk` accepts the resulting coherent tree. All sixteen
final proof checks match their own observed root; eight checks from those two
incomplete cases fail against separately described complete fixture roots. The
expected map and root are fixed independently of the observed database. This shows
why successful bulk commit, valid proof bytes and coherent refcounts cannot establish
seed completeness. These selected synthetic roots are not authenticated snapshots,
network trust inputs or a repair of the retained-Momentum-hash provenance failure.

Four cases produce 47 logical-store snapshots and 1,880 finite Root/Prove cells,
including seven guard refusals, stored-zero inclusion, absence and unavailable
versions. The final clean reopen and manual compaction/reopen preserve bytes and
references. Twenty controls reject altered guards, lost staged retry, foreign
coherent state, shared-root accounting, self-selected incomplete roots and promoted
gates. They do not perform additional resource measurements or qualify real-chain
workloads, budgets, crash recovery, snapshot import or accepted header binding.

The actual source-pinned backend runs locally on macOS ARM64 with CGO disabled.
Linux, macOS Intel and Windows CI run fixture controls and the independent byte
checker; they do not execute this reference backend. All ten earlier corpora, 394
selected node blobs, the research dependency lock and 365 MIT runtime inputs remain
unchanged. Production state-value acceptance, profile/activation, canonicality,
finality, freshness, independent human review and authenticated release stay gated.

```sh
python3 -I -B tools/gen-state-root-vectors/check_bulk_guards_test.py
python3 -I -B tools/gen-state-root-vectors/check_bulk_guards.py
python3 -I -B tools/gen-state-root-vectors/regenerate.py \
  --node-source NODE_SOURCE --go GO_EXECUTABLE --fixture-kind bulk-guards \
  --output NEW_BULK_GUARDS_CORPUS_FILE \
  --evidence-directory NEW_PRIVATE_EVIDENCE_DIRECTORY
```


## Retained empty roots and last-node reclamation

Three finite fixtures cover a committed empty bulk seed, deletion of all eight
selected keys and deletion of the last stored-zero leaf. An empty write-set
still requires staging. A successful empty CommitBulk or regular Commit stores
a version-to-zero-root record; it creates no zero-sentinel node or refcount.
Missing folded heights and pruned empty heights return ErrNoVersion. Height zero
remains the implicit empty origin. A stored zero is present, with a nonempty
root; deleting an absent key preserves it, while deleting the last leaf empties
the new version. Earlier retained versions still own their nodes until pruned.

The actual unchanged NodeTree produces 39 logical snapshots and 1,560 finite
Root/Prove cells: heights zero through seven, each root and four selected keys.
The independent Python checker reconstructs complete sparse roots and proof
bytes, compressed physical graphs, version records and shared refcounts. All
29 retained nonzero empty-root reads and 116 corresponding absence proofs are
bound to retained versions. There are 1,115 unavailable-version errors. Fourteen
snapshots have a committed frontier with no physical nodes or refcounts. After
pruning the last nonempty version, clean reopen and manual compaction preserve
the empty state; later reinsertion restores a stored-zero inclusion proof.
Twenty controls reject coherent wrong histories, missing/resurrected versions,
wrong zero/value semantics, phantom sentinel references and self-selected roots.

These complete synthetic fixture maps authenticate no snapshot or retained
Momentum hash. The PR146 height-only provenance failure remains open. Caller
exclusivity across staging and commit, accepted header/profile/activation,
anchor, schedule and context pin remain requirements. This mode measures no
resource costs, starts no node and qualifies no power-loss or crash recovery.
Actual pure-Go backend execution is local macOS ARM64. Linux/macOS Intel/Windows
CI runs fixtures and controls without this reference backend. All eleven earlier
corpora, the 394 selected node blobs, research lock and 365 MIT runtime inputs
remain unchanged. Production state-value acceptance and human review stay gated.

```sh
python3 -I -B tools/gen-state-root-vectors/check_empty_versions_test.py
python3 -I -B tools/gen-state-root-vectors/check_empty_versions.py
python3 -I -B tools/gen-state-root-vectors/regenerate.py \
  --node-source NODE_SOURCE --go GO_EXECUTABLE --fixture-kind empty-versions \
  --output NEW_EMPTY_VERSIONS_CORPUS_FILE \
  --evidence-directory NEW_PRIVATE_EVIDENCE_DIRECTORY
```

## Low-level uint64 height-boundary counterexample

The `height-boundary` mode executes three finite serial cases against the pinned
candidate's actual disk `NodeTree`. Its regular `Commit` checks
`height == frontier.Height + 1` with unsigned arithmetic. At `2**64 - 1`, that
successor is zero. The observed regular `Commit(0)` succeeds in all three cases,
whereas `Commit(1)` and non-increasing `CommitBulk` requests refuse. The preceding
refusals preserve the staged changes for the later successful wrap.

A physical version-zero root record can contain nonempty state. The candidate's
`Root` and `Prove` at height zero always select the implicit empty origin, ignoring
that record. A subsequent `Commit(1)` also builds from origin, losing the intended
base for its current version; still-retained historical maximum-height versions
remain readable. Clean reopen and manual compaction preserve the observed logical
records and this read behavior. No gap is traversed, pruned or truncated.

The independent checker rebuilds every full sparse root/proof and compressed
node/refcount graph for 29 logical snapshots and 580 finite Root/Prove cells. All
12 boundary proofs match their own observed roots, but eight fail the separately
described intended state. The empty-state case still matches that state root;
monotonicity remains unqualified and all three consumer decisions are `REFUSED`.
A root match alone cannot establish a valid version sequence. Twenty controls
bind exact unsigned integers, ordering errors, retained stage, origin masking,
physical records, post-wrap base loss and this independent refusal.

This is a reproduced synthetic low-level API boundary. It does not establish a
reachable production height, an exploitable chain transition or a ledger-wide
height policy. The candidate is unchanged and the counterexample remains open.
A future caller must independently validate strictly increasing, profile-bounded
heights without overflowing its successor calculation. Header authentication,
retained hash provenance, activation and accepted `VerifiedState` binding remain
separate gates. No snapshot import, full node, RPC or resource measurement runs.

```sh
python3 -I -B tools/gen-state-root-vectors/check_height_boundary_test.py
python3 -I -B tools/gen-state-root-vectors/check_height_boundary.py
python3 -I -B tools/gen-state-root-vectors/regenerate.py \
  --node-source NODE_SOURCE --go GO_EXECUTABLE --fixture-kind height-boundary \
  --output NEW_HEIGHT_CORPUS_FILE \
  --evidence-directory NEW_PRIVATE_EVIDENCE_DIRECTORY
```

Offline reference execution remains local macOS ARM64 with CGO disabled. Native
Linux, macOS Intel and Windows CI check fixtures and controls without executing
this candidate backend. All twelve earlier corpora and MIT runtime inputs remain
unchanged. Production state-proof acceptance stays disabled.
