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


## Serial staging and injected replay boundaries

The `staging-boundary` mode runs seven finite serial cases on the unchanged
pinned disk `NodeTree`. It distinguishes the default `db.NewPatch` path, whose
locked LevelDB `Batch.Replay` returns nil, from a research implementation of the
public `db.Patch` interface that returns an injected error after zero, one or two
callbacks. These custom faults establish interface behavior; they do not show
that default replay, storage or a production chain can fail this way.

`Update` replays into a new private map. On error, it preserves the previous
stage, including a nil stage. `AccumulateFrom` initializes its shared stage
before replay and retains delivered prefixes on error. Even an error before any
callback can leave an empty but committable stage. Four deliberate continuations
commit successfully immediately after injected replay errors. Successful
`Update` also replaces an existing accumulation, as the candidate already
documents. These are serial API observations, not concurrent race qualification.

Clean reopen discards the uncommitted stage while preserving committed roots.
A complete retry restores the independently selected state; the default replay
control also matches it. The full sparse and compressed physical graph models
bind 50 logical snapshots, 1,000 finite Root/Prove cells and 60 recorded callbacks.
Seven custom errors, nine default replay successes and three not-staged commit
refusals are reproduced. All 28 final proofs match their own observed roots;
16 fail the separately selected complete fixture. Three case roots match that
fixture, yet all seven consumer decisions remain `REFUSED`.

A lifecycle/import caller must check every staging result, discard or rebuild
the entire intended range after an error, and hold its own exclusive lock through
staging and commit. A coherent proof cannot establish complete replay or caller
ownership. Twenty controls bind prefix cuts and raw callbacks, failure semantics,
replacement, historical-base preservation, reopen, selected roots and refusal.
No candidate fix, default-patch failure, production reachability, crash resilience,
resource budget, snapshot import or accepted `VerifiedState` binding is qualified.

```sh
python3 -I -B tools/gen-state-root-vectors/check_staging_boundary_test.py
python3 -I -B tools/gen-state-root-vectors/check_staging_boundary.py
python3 -I -B tools/gen-state-root-vectors/regenerate.py \
  --node-source NODE_SOURCE --go GO_EXECUTABLE --fixture-kind staging-boundary \
  --output NEW_STAGING_CORPUS_FILE \
  --evidence-directory NEW_PRIVATE_EVIDENCE_DIRECTORY
```

Reference execution remains local macOS ARM64 with CGO disabled. Linux, macOS
Intel and Windows CI run fixture controls without this backend. All thirteen
prior corpora, node source blobs, dependency locks and MIT runtime inputs remain
unchanged. Explicit anchor, profile, schedule and context pin remain required;
production state-proof acceptance stays disabled.

## Patch dump decoding and diagnostic replay

The `patch-decode` mode executes the unchanged candidate's `NewPatchFromDump`
and default LevelDB `Batch.Replay` on 232 finite, unsigned byte fixtures. It
opens no database and calls no NodeTree or production caller. The selected
LevelDB version is `v1.0.1-0.20210819022825-2ae1ddf74ef7` under the existing
research module lock; the offline source review checks its complete module
archive checksum and the decoder's exact bytes.

The corpus includes every one of the 169 byte prefixes of a selected 168-byte
three-record patch, 19 malformed tails at three independently selected record
positions, and six empty, overlong or duplicate-write controls. Only four
prefixes end at valid record boundaries. A syntax-valid prefix still cannot
establish that the intended complete patch was received. Redundant varints are
accepted; an equivalent complete replay can have a different raw dump hash.
Duplicate writes preserve callback order and the last value.

There are 204 ordinary decode errors. The constructor returns a patch alongside
each such error, and 125 error-returned patches deliver at least one diagnostic
callback. The fixture deliberately replays them to observe the boundary. This
is not a safe application workflow: discard the patch on a decode error. Its
dump/hash still covers the entire supplied input, including a malformed tail,
while its completed record indexes can describe only a prefix.

With the reference's explicitly selected 64-bit integer arithmetic, huge
unsigned lengths produce 18 recovered runtime bounds panics during construction
and six during diagnostic replay. A construction panic prevents patch return;
a replay panic can occur after earlier callbacks. These are finite local
counterexamples, not injected custom Replay errors or a demonstrated network
attack. Default Replay otherwise returns nil. The candidate and its dependency
are unchanged; this research supplies no decoder repair.

Static review of all four constructor call sites in the pinned snapshot finds
ordinary errors checked: two use `common.DealWithErr`, which panics on error,
and two return an error. Those callers were not executed here. This result does
not establish that corrupted stored or externally supplied dumps are reachable,
that panic recovery is safe, or that the complete production import path has
bounded, atomic failure handling. A future import contract needs explicit raw
size/record/length bounds and complete-patch selection before any replay effects.

The Python oracle independently decodes raw records, signed length arithmetic,
callback prefixes, ordered writes, full-input hashes and the selected complete
manifest. All 232 consumer results are `REFUSED`; even 13 decode errors with a
matching diagnostic final state cannot become accepted proofs. Twenty-four
controls bind these outcomes, exception boundaries, byte/type/shape limits,
source/dependency pins and the closed production gates.

```sh
python3 -I -B tools/gen-state-root-vectors/check_patch_decode_test.py
python3 -I -B tools/gen-state-root-vectors/check_patch_decode.py
python3 -I -B tools/gen-state-root-vectors/regenerate.py \
  --node-source NODE_SOURCE --go GO_EXECUTABLE --fixture-kind patch-decode \
  --output NEW_PATCH_DECODE_CORPUS_FILE \
  --evidence-directory NEW_PRIVATE_EVIDENCE_DIRECTORY
```

Actual reference generation runs twice locally on macOS ARM64 with CGO disabled.
Linux, macOS Intel and Windows CI check the fixture with the independent oracle;
they do not execute this node decoder. All fourteen previous deterministic
corpora, the 394 pinned node blobs, dependency locks and MIT runtime inputs remain
unchanged. No resources are measured in this mode. Retained hash provenance,
height limits, snapshot import, accepted header/profile/activation binding,
independent review and authenticated distribution remain separate gates.

## Bounded patch import and detached staging

The `patch-import` mode adds a private GPL research prototype around the unchanged
candidate decoder. It imports a selected patch only into an owned in-memory map.
No production caller, database, NodeTree, snapshot importer, network or resource
experiment runs. The reference node and LevelDB source/dependency lock are unchanged.

Explicit positive limits bound raw bytes, records, keys and values. Hard research
ceilings are 1 MiB, 1,024 records, 4,096 key bytes and 65,536 value bytes; default
fixture limits are 1,024 bytes, eight records, 64 key bytes and 128 value bytes.
These are prototype policies, not agreed protocol limits or measured resource
budgets. The raw cap precedes copying the already resident input. An unsigned
length is compared with its cap and remaining bytes before int conversion or
slicing, preventing the known signed-length counterexamples from reaching Load.

Preflight binds an independently selected exact byte count, ChangesHash and
record count. Complete dump selections are constructed from literal record bytes
before candidate decoding; the Python oracle constructs and hashes them separately.
Nonminimal varints retain their raw spelling, and duplicate writes retain order.
An equivalent final map cannot authorize another dump, normalize its hash or
establish whole-snapshot completeness. Empty keys/values describe patch syntax,
not accepted typed state domains.

Constructor errors discard even a nonnil patch. Replay stages into a detached map
and checks the entire planned callback sequence in order, including Deletes.
Errors, missing/extra callbacks, changed values or dump mutation prevent publication.
Successful completion replaces one owned map after all checks. The harness tests
input alias mutation, constructor error/nil results, replay errors after one and
all three callbacks, omitted/extra/changed callbacks and owned-dump mutation.
These faults are deliberately injected; they are not default backend failures.
No panic recovery is used or qualified.

The 264 finite cases reuse all 232 decode inputs and add 32 limit, selection,
staging and alias controls. There are 246 rejections before the constructor,
18 actual constructor calls, 15 default Batch.Replay calls and 34 isolated
callbacks. All 254 rejections preserve the complete initial target map, including
five after staged callbacks. Ten independently selected research inputs publish
one map each and preserve the unrelated initial key. All 264 proof consumers
remain `REFUSED`. Twenty-eight adversarial checker tests bind bytes, strict
types/shapes, complete callback delivery, failure effects and closed trust gates.

```sh
python3 -I -B tools/gen-state-root-vectors/check_patch_import_test.py
python3 -I -B tools/gen-state-root-vectors/check_patch_import.py
python3 -I -B tools/gen-state-root-vectors/regenerate.py \
  --node-source NODE_SOURCE --go GO_EXECUTABLE --fixture-kind patch-import \
  --output NEW_PATCH_IMPORT_CORPUS_FILE \
  --evidence-directory NEW_PRIVATE_EVIDENCE_DIRECTORY
```

Actual reference generation runs twice locally on macOS ARM64 with CGO disabled.
Linux, macOS Intel and Windows CI check the independent fixtures without executing
the node backend. All fifteen preceding deterministic corpora and MIT runtime
inputs remain unchanged. The subsequent [target bounds](#bounded-initial-and-transient-patch-targets)
bound copying and delay it until input/constructor checks pass. The prototype
requires exclusive ownership; it qualifies neither shared writers,
disk/crash durability nor production resource budgets. Authenticated complete and
excluded snapshot state, typed domains, accepted header/profile/activation,
retained hash provenance, anchor, schedule, context pin, independent human review
and authenticated distribution remain separate gates.

## Bounded initial and transient patch targets

The `patch-targets` research mode uses the same selected import contract with
explicit positive limits for initial and staged map entries and key/value hex
string bytes. Hard ceilings are 4,096 entries and 1 MiB of hex text; the new
fixture defaults are eight entries and 1,024 hex bytes. The earlier 264-case
mode uses the ceilings and reproduces its complete prior corpus byte for byte.
These caps count string payloads, including empty syntactic keys and values.
They do not bound map overhead, raw/event/callback buffers, fixture summaries,
the whole process or a production state domain.

The initial map must fit both caps and contain even-length lowercase hex before
raw copying. Complete unsigned preflight, separately selected byte/count/hash
binding, constructor success and exact dump checks precede target cloning.
Replay uses a new owned map; the original map and its aliases remain untouched.
Every complete callback must match the planned sequence before its prospective
entry and hex-payload sizes are checked. Replacement subtracts the old key/value
payload; Delete reclaims capacity. A transient overflow is rejected even if a
later Delete would make the final map fit. No partial stage is published on a
cap, sequence, constructor, dump or replay failure. One replacement follows all
successful checks, including complete replay and post-replay dump binding.

The 46 finite cases include exact initial and transient caps, zero/oversized cap
configuration, odd/uppercase/nonhex strings, entry/byte ceilings and one above
each ceiling, input failures before cloning, injected constructor/replay failures,
empty Put/Delete, duplicate replacement and nonminimal raw spellings. Eighteen
selected research patches stage; 28 reject with the complete original map intact.
Of the rejections, 21 clone no target and 16 copy no raw input. All 46 original
aliases stay unchanged, and all proof consumers remain `REFUSED`. Complete maps
are bound by independently reconstructed sorted JSON manifest SHA-256 digests;
these are fixture identities, not authenticated state roots or snapshot proofs.
The Python oracle recomputes each full prospective map's size, separately from
the Go prototype's incremental counters. Twenty-two adversarial checker controls
bind the entire corpus, outcomes, counters, callback order and closed trust gates.

```sh
python3 -I -B tools/gen-state-root-vectors/check_patch_targets_test.py
python3 -I -B tools/gen-state-root-vectors/check_patch_targets.py
python3 -I -B tools/gen-state-root-vectors/regenerate.py \
  --node-source NODE_SOURCE --go GO_EXECUTABLE --fixture-kind patch-targets \
  --output NEW_PATCH_TARGET_CORPUS_FILE \
  --evidence-directory NEW_PRIVATE_EVIDENCE_DIRECTORY
```

Both the changed prior import mode and the new target mode execute twice locally
against the same complete pinned node snapshot, with CGO disabled. Native Linux,
macOS Intel and Windows CI check the finite fixtures and controls without running
the node backend. No raw planner output is accepted by a storage writer; the
existing read-only planner and its measured read/parse/encode scope remain separate.
The inputs are already resident in the harness, and the exclusive caller must
own the complete validation/clone/replay/replacement interval. Exclusivity is a
precondition, not a lock or concurrent-writer guarantee. Shared/durable writers,
rollback/crash recovery, whole-handoff measurements and real resource budgets
remain unqualified. Full snapshot/excluded-state authentication, retained-hash
provenance, accepted VerifiedState/header/profile/activation, anchor, schedule,
context pin, independent review and authenticated release remain separate gates.

## Whole owned import resource observations

`patch-resources` measures the existing research `importApply` contract in fresh
Go processes, with resident raw input and an exclusively owned target. The
operation includes raw/target cap validation, target hex validation, the owned
raw copy, complete unsigned preflight, selected byte/count/ChangesHash checks,
actual pinned node `NewPatchFromDump`, detached map cloning, actual `Batch.Replay`,
ordered callback/transient-cap checks, post-replay dump binding and replacement.
The map clone copies entries and shares immutable string payloads; it does not
copy every initial key/value string. No shared or durable writer is attached.

Twelve independently rebuilt literal families include empty input, 64/256/1024
records with 128/1024/4096 initial entries, a raw 1 MiB transient hex refusal,
4,096/4,097 initial entries, a 1 MiB initial hex payload, Put/Delete ordering,
selection mismatch and an injected complete-replay error. Seven families stage;
five reject with the complete original target and aliases preserved. All proof
consumers stay `REFUSED`. SHA-256 bindings cover the complete sorted initial,
staging, output and original-alias maps, full ordered callback manifests, and
complete original/post-operation raw bytes. These are unsigned fixture identities,
not SMT roots or authenticated snapshots. The Python oracle rebuilds literal
bytes and each full prospective map independently of Go's incremental counters.

Each of two generations retains all three plain and three allocation-observed
children per family: 72 children per generation, 144 in total. Every child
outcome is also logged before interpretation into the sealed private driver
stderr. A failed child stops the run; no sample replacement/filtering occurs.
The two complete original outputs and ledgers are retained. Only deterministic
conformance is compared; variable samples remain separate in `resource-samples.json`.
The checked-in sample file records this local Darwin/arm64 Go 1.25.14 experiment.
Native Linux, macOS Intel and Windows CI validate the recorded bindings and 24
checker controls; those checks do not execute the Go reference or remeasure import.

Timing brackets only `importApply`. Source/build/startup, fixture construction,
selection, initial map summary and one pre-operation GC are outside timing.
`ReadMemStats` brackets the timer/operation in allocation mode and records
**cumulative** `TotalAlloc`/`Mallocs` deltas and GC-cycle deltas. This process-wide
sampling can include runtime activity; it is not an exclusive importer allocation
counter or an operation peak. Plain children do not sample these counters.
`getrusage(RUSAGE_SELF)` captures process lifetime RSS high water immediately
after the operation and optional stats read, before output binding. It includes
startup, provenance, resident inputs, initial summary, GC and measurement setup;
post-operation map/callback binding, report construction and serialization happen
after the capture. Linux KiB and Darwin byte units are normalized explicitly.
Parent orchestration and source acquisition are not part of child measurements.

```sh
python3 -I -B tools/gen-state-root-vectors/check_patch_resources_test.py
python3 -I -B tools/gen-state-root-vectors/check_patch_resources.py
python3 -I -B tools/gen-state-root-vectors/regenerate.py \
  --node-source NODE_SOURCE --go GO_EXECUTABLE --fixture-kind patch-resources \
  --output NEW_PATCH_RESOURCE_CORPUS_FILE \
  --evidence-directory NEW_PRIVATE_EVIDENCE_DIRECTORY
python3 -I -B tools/gen-state-root-vectors/check_patch_resources.py \
  --corpus NEW_PATCH_RESOURCE_CORPUS_FILE \
  --samples NEW_PRIVATE_EVIDENCE_DIRECTORY/resource-samples.json
```

The reference generator requires Linux or macOS and verifies all 394 pinned node
blobs before an offline CGO-disabled build. The checker is portable and unsigned;
it cannot authenticate reported execution provenance or prove absence of retries.
The private first-outcome ledgers provide the narrower engineering record. The
preceding importer and target corpora remain byte-identical after shared driver
changes. The separate planner read/parse/encode measurements retain their own
scope. This experiment does not measure file acquisition, snapshot reconstruction,
NodeTree bulk/tail/archive retention, storage writers, whole import handoff or
real-chain budgets. It qualifies no speedup, capacity, canonicality, finality,
network activation, accepted-header/profile binding or production state value.
See [the local observations](../../docs/native-benchmarks.md#whole-owned-research-import-observations).

## Owned callback string reuse comparison

The separate research importer now compares callback bytes directly with the
preflight's detached lowercase hex strings. Only a complete operation/key/value
match can reuse those immutable payloads. A Put retains its own mutable Value
pointer; empty Put and Delete stay distinct. The first mismatch still records
actual callback bytes. Later callbacks after refusal return before encoding.
The original target map is still cloned separately and published only after all
selection, replay, transient-cap and final-byte checks succeed.

`compare_patch_import.py` accepts exactly the prior importer Git blob
`ff426a7c2ffc4604f89f888a382c0c503631023a` from development main
`02b3a36410f53d879ca5dd1d21bb3c3d0c8c1b73`. It bounds and checks its byte count,
SHA-256 and Git object identity before any Go execution. Both versions use the
same selected resource harness, node snapshot, toolchain and ownership controls.
There are two baseline generations followed by two candidate generations:
288 fresh children across the same twelve complete conformance families.
All original outputs, child ledgers and samples are retained. Eighteen local Go
ownership tests/subtests pass for each version, including all byte values,
callback byte mutation, separate metadata pointers, empty operations, nibble and
length mismatches, invalid plan spelling, extra callbacks and transient refusals.
The preceding 264 importer and 46 target cases remain byte-identical.

The [recorded comparison](testdata/candidate-patch-import-comparison.json) binds
all selected importer/harness/control bytes and both complete sample inventories.
The independent portable checker and 21 adversarial controls run in native CI;
they check recorded local evidence without executing Go or remeasuring import.
The historical resource corpus and samples are preserved. Cumulative allocation,
plain elapsed time and lifetime RSS retain the measurement boundaries described
above; sequential generations do not establish a latency speedup or causality.
See [all local observations](../../docs/native-benchmarks.md#owned-callback-reuse-comparison).

```sh
git show 02b3a36410f53d879ca5dd1d21bb3c3d0c8c1b73:tools/gen-state-root-vectors/patch_import.go > NEW_BASELINE_FILE
python3 -I -B tools/gen-state-root-vectors/compare_patch_import.py \
  --node-source NODE_SOURCE --baseline-import-source NEW_BASELINE_FILE \
  --go GO_EXECUTABLE --output NEW_COMPARISON_FILE \
  --evidence-directory NEW_PRIVATE_EVIDENCE_DIRECTORY
python3 -I -B tools/gen-state-root-vectors/check_patch_import_comparison.py \
  --comparison NEW_COMPARISON_FILE
python3 -I -B tools/gen-state-root-vectors/check_patch_import_comparison_test.py
```

Source acquisition is separate; no network or node database is used. The report
is unsigned and cannot authenticate its claimed execution or absence of retries.
Sharing owned immutable strings does not establish zero-copy end-to-end import,
whole-process memory budgets, actual NodeTree retention, snapshot/excluded-state
authentication, shared/durable writer atomicity or production state-value proofs.
Caller exclusivity and all explicit header/profile/activation, anchor, schedule,
context-pin, independent-review and authenticated-distribution gates remain.

## Read-only raw patch plans

`plan_patch.py` consumes a regular raw dump file under **explicitly selected**
ChangesHash (SHA3-256), byte count, record count and five positive limits. It
uses the independently checked unsigned byte parser to emit detached ordered
hex events. It never invokes the Go constructor or Replay, replaces a target,
opens a database or calls NodeTree. `READY` is a research syntax plan;
`consumer_result` remains `REFUSED`. The caller must select the expected input
through its own trust process before inspecting the candidate file. Supplying
metadata obtained from that same candidate does not authenticate anything.

For a disposable syntax example, create a raw file with bytes
`0101610162000163`: Put `61` = `62`, then Delete `63`. Use the independently
specified literal digest and counts below. This example is synthetic and carries
no network, snapshot or state-value claim:

```sh
python3 -I -B tools/gen-state-root-vectors/plan_patch.py \
  --raw RAW_DUMP_FILE \
  --changes-hash 2c3cf5d53690ca954fe3bf1f255681f6c4e5dc9fc6499cc2920f4d59309a4a11 \
  --expected-bytes 8 --expected-records 2 \
  --max-raw-bytes 1024 --max-records 8 \
  --max-key-bytes 64 --max-value-bytes 128 --max-plan-bytes 4096
python3 -I -B tools/gen-state-root-vectors/plan_patch_test.py
```

Every option above is required; there are no auto-selected digests or counts.
An optional `--source-revision` binds a caller-supplied lowercase 40-digit source
revision to the output. It is a label and does not verify a running binary.
Limits may not exceed the research ceilings: 1 MiB raw, 1,024 records, 4,096 bytes
per key, 65,536 bytes per value and 4 MiB encoded plan including its newline.
Wrong selection, malformed/truncated records, invalid options, a special file,
a symlink or an exceeded cap refuses with no plan on stdout. Diagnostics omit
input paths and option values. The command writes only its complete plan to
stdout; output transport failure is not an atomic file-publication guarantee.

The regular-file global size check precedes a read of at most the independently
selected byte count plus one. The returned length must equal that selected
count; an extra byte, short read or substituted special descriptor refuses.
This avoids reserving the full global cap for small inputs. Length decoding
inspects at most eleven bytes through a memory view,
without copying each remaining input tail. Every field must fit its selected
cap and the remaining raw bytes before hex encoding. Nonminimal varints and
ordered duplicate writes keep their exact independently selected spelling.
Empty Put values remain distinct from Delete. JSON encoding checks the output
cap incrementally before publication. Raw input, detached events and encoded
output are simultaneously resident; interpreter overhead, latency, shared
writers, crash durability and production memory budgets are not measured here.

The 264 earlier inputs cross-check the plan's byte parsing against the import
oracle: 246 refuse before construction would have been allowed, and eighteen
syntax plans bind their selected bytes. Constructor/replay fault injection is
not executed by this command; none of these plans stages or imports a target.
Native Linux, macOS Intel and Windows run the file/CLI, privacy, bounds and
selection controls; these are Python consumer tests, not native reference-node
execution. The sixteen earlier corpora and pinned node/dependency sources are
unchanged. Snapshot completeness, excluded and typed state, canonical roots,
authenticated retained hashes, accepted VerifiedState/profile/activation,
anchor/schedule/context-pin trust, human review and release distribution remain
separate gates. The MIT verifier still refuses production state-value proofs.

## Read-only patch planner resource observations

`measure_patch_plan.py` observes six fixed synthetic inputs selected in
`testdata/patch-plan-resource-inputs.json`. Their byte counts, record counts,
SHA3-256 ChangesHash and SHA256 are literal selections checked by a separate
byte oracle before any measured worker starts:

| Input | Raw bytes | Put records | Selected workload |
| --- | ---: | ---: | --- |
| empty | 0 | 0 | Empty selected input |
| records-64 | 64,384 | 64 | Two-byte keys and 1,000-byte values |
| records-256 | 257,536 | 256 | The same record shape |
| records-1024 | 1,030,144 | 1,024 | The maximum research record count |
| maximum-raw-values | 1,048,576 | 16 | The exact 1 MiB raw cap; fifteen 65,536-byte values |
| maximum-keys | 1,045,755 | 255 | 4,096-byte keys near the raw cap |

```sh
python3 -I -B tools/gen-state-root-vectors/check_patch_plan_resources_test.py
python3 -I -B tools/gen-state-root-vectors/measure_patch_plan.py \
  --source-revision SELECTED_40_DIGIT_REVISION > RESOURCE_REPORT
python3 -I -B tools/gen-state-root-vectors/check_patch_plan_resources.py \
  --report RESOURCE_REPORT --source-revision SELECTED_40_DIGIT_REVISION
```

The default three repetitions retain 36 fresh worker samples: one plain and one
`tracemalloc` worker per repetition and input. `--repetitions` may select one to
three, with no retries, filtering or budget threshold. The worker operation
timer spans the bounded raw-file read, parsing and complete JSON encoding. It
excludes process launch, imports, independent-oracle work, result hashing and
report transport. The traced worker separately reports its Python allocation
peak for that operation; tracing changes its elapsed time, so plain and traced
timings must remain distinct. Raw input, detached hex events and output buffers
coexist. Parent fixture/oracle allocations and native allocator overhead are
outside the Python trace; this is not whole-pipeline memory measurement.

The OS high-water observation has a different scope. Unix uses
[`getrusage(RUSAGE_SELF)`](https://docs.python.org/3/library/resource.html), with
[Linux KiB converted to bytes](https://man7.org/linux/man-pages/man2/getrusage.2.html)
and [macOS resident-size bytes](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/task_info.h).
Windows reports the distinct
[`PeakWorkingSetSize` in bytes](https://learn.microsoft.com/en-us/windows/win32/api/psapi/ns-psapi-process_memory_counters).
These process high-water values include startup/import scaffolding and do not
isolate operation memory or exclude pre-exec accounting. A new worker is not a
claim that all inherited accounting has been reset. Unavailable OS observations
are explicit `null`, never zero. Reads may be served from the OS cache; these
samples do not measure cold disk performance, aggregate concurrent memory or
process-launch cost.

The independent checker reconstructs every expected ordered event and the
complete compact JSON spelling, including its newline and selected revision.
It binds the encoded length and SHA256 for every sample, the fixed inputs,
code fingerprints, platform metric and closed report schema. A source revision
is a label; report consistency does not authenticate a binary or measurement
channel. The driver publishes a bounded complete report only after all samples
and byte bindings pass. Native Linux, macOS Intel and Windows CI execute this
Python workflow and preserve the observations in their job logs. They do not
execute the reference node or regenerate the earlier sixteen corpora.

These observations qualify neither production resource budgets nor NodeTree
retention, snapshot import, state roots, authenticated header/profile/activation,
accepted VerifiedState or canonicality/finality. The planner's syntax result
stays `READY`; every proof consumer stays `REFUSED`. Representative workloads,
hardware, concurrency and network costs remain separate acceptance inputs.

## Selected-count patch read allocation comparison

`measure_patch_plan_reads.py` compares the current selected-count reader with
the exact historical `read_raw` function from
[`47b859b2b32979b166d1d138da65cf0236951040`](https://github.com/edgepillar/zenon-spv/blob/47b859b2b32979b166d1d138da65cf0236951040/tools/gen-state-root-vectors/plan_patch.py).
The historical reader and encoder bodies are copied verbatim and SHA256-pinned
in the comparison source. Current validation, unsigned event parsing and plan
construction retain separately checked byte pins from that same revision.
Both modes use this historical encoder, the same parser and instrumentation; the
read function is the selected difference. This read comparison does not measure
the current default encoder. The separate standalone resource workflow and
output encoding comparison below measure the current default encoder.
The reference reader still requests the
global raw cap plus one, while the candidate requests the independently
selected byte count plus one and requires the exact returned length.

```sh
python3 -I -B tools/gen-state-root-vectors/plan_patch_test.py
python3 -I -B tools/gen-state-root-vectors/check_patch_plan_reads_test.py
python3 -I -B tools/gen-state-root-vectors/measure_patch_plan_reads.py \
  --source-revision SELECTED_40_DIGIT_REVISION > READ_COMPARISON_REPORT
python3 -I -B tools/gen-state-root-vectors/check_patch_plan_reads.py \
  --report READ_COMPARISON_REPORT --source-revision SELECTED_40_DIGIT_REVISION
```

The same six literal input profiles run three interleaved reference/candidate
pairs in both plain and traced modes: 72 fresh workers by default. Each worker's
complete encoded plan length and SHA256 must match the independent expected
ordered JSON bytes. The independent checker does not execute either reader.
It verifies the historical/shared source pins and projects both complete sample
inventories into the existing strict byte/resource schema. Current source and
the historical reader revision are distinct labels. No arbitrary external
planner file or untrusted code is loaded.

The comparison retains all samples without retries or filtering. It reports
whether every candidate traced peak for the empty and 64-record inputs is below
every corresponding reference traced peak; a non-reduction remains a valid
observation, not budget acceptance. The 1 MiB input, 1,024-record and maximum-key
inputs remain in the comparison so that larger workloads and complete output
semantics stay visible. Variable plain/traced timing and OS high-water values
are recorded with their prior distinct scopes; they do not qualify a latency
speedup, cold-disk performance, operation-only RSS, whole-pipeline memory or
production resource budget. Source hashing/AST checks and parent fixture/oracle
work occur before operation tracing/timing and may contribute to OS high water.

File-type/descriptor/global size checks remain required. The extra-byte probe
detects a tail or growth beyond the selected count, and a short read refuses
before plan construction. Subsequent exact digest/record checks still select
the complete raw spelling. Read errors publish no plan; the existing malformed,
nonminimal, duplicate, empty Put/Delete and privacy controls remain in place.
Concurrent mutations, atomic snapshot reads, storage writers and durable imports
are not qualified. Linux, macOS Intel and Windows run the controls and actual
comparison; no reference node, database, NodeTree, snapshot authentication or
production state-value acceptance executes.

## Bounded patch output encoding comparison

`plan_patch.py` appends ASCII JSON chunks to an in-memory binary buffer, checks
the remaining cap before every write, reserves the final newline and returns
the complete immutable `bytes` result. The
[standard library contract](https://docs.python.org/3.13/library/io.html#io.BytesIO.getvalue)
defines `BytesIO.getvalue()` as returning the entire buffer as bytes; it does
not promise a universal zero-copy implementation. No buffer view or partial
plan escapes the planner. File, digest, count, varint, ordered duplicate and
empty Put/Delete semantics retain their existing boundaries.

`measure_patch_plan_encodings.py` separately compares the exact `encode_plan`
body from
[`f4bf2d2953825fa96f9e52be2d41f003fed4ab65`](https://github.com/edgepillar/zenon-spv/blob/f4bf2d2953825fa96f9e52be2d41f003fed4ab65/tools/gen-state-root-vectors/plan_patch.py)
with the current bounded binary encoder. Historical encoding, unchanged reading,
validation, event parsing and plan construction have independently checked
function pins. Both modes use the unchanged meter and the same six literal
profiles. The current source revision and historical reference revision remain
separate labels; no external planner file is imported.

```sh
python3 -I -B tools/gen-state-root-vectors/check_patch_plan_encodings_test.py
python3 -I -B tools/gen-state-root-vectors/measure_patch_plan_encodings.py \
  --source-revision SELECTED_40_DIGIT_REVISION > ENCODING_COMPARISON_REPORT
python3 -I -B tools/gen-state-root-vectors/check_patch_plan_encodings.py \
  --report ENCODING_COMPARISON_REPORT --source-revision SELECTED_40_DIGIT_REVISION
```

Three interleaved reference/candidate pairs in plain and traced modes retain
72 fresh workers. The independent checker executes neither encoder and binds
every complete output length and SHA256 to independently reconstructed ordered
JSON, including the revision and final newline. It verifies literal profiles,
source pins, exact sample order/types and explicit unavailable metrics. Every
sample remains in the report without retries or filtering. It reports whether
all candidate traced peaks for each of the four larger profiles fall below
all corresponding reference traced peaks; nonreduction is a valid observation.
Empty and 64-record cases remain visible separately. The earlier read comparison
retains its historical encoder and 72 workers; the standalone workflow measures
the current default with 36 workers.

These measurements cover only synthetic Python read/parse/encode work on the
reported runtime. Python tracing excludes parent preparation, source/AST checks
and worker startup. OS process high water can include that scaffolding and
prior process accounting; plain/traced timing, Python peaks and OS metrics have
different scopes. No latency speedup, causal OS-memory delta, cold-disk or
whole-pipeline memory, NodeTree/retention workload, or production budget is
qualified. Linux, macOS Intel and Windows execute the controls and observations;
no candidate node, database, import, Replay, network or proof acceptance runs.
The state-value consumer remains `REFUSED`, with independent snapshot, retained
hash, VerifiedState/header/profile/activation, human review and distribution
gates unchanged.

## Opened regular file to owned map research handoff

`patch_file.go` adds a private research seam around the unchanged `importApply`.
The caller supplies an already opened, stable regular file and exclusively owns
the target until the call returns. The seam validates raw limits, the independent
selected byte count and complete initial target caps before file I/O. It checks
the opened descriptor's regular-file type and size, then uses `ReadAt` at offset
zero with a buffer of at most the selected count plus one. The hard raw ceiling
is 1 MiB. It checks returned count, read errors and a second size observation
before passing detached bytes to the existing parser, selected record/digest
checks, candidate constructor/Dump checks, clone, ordered replay and transient
caps. Only the returned owned map may be replaced after every check succeeds.

The borrowed descriptor stays open with its cursor unchanged. No path opener or
output writer is added. Size observations do not establish an atomic filesystem
snapshot: stable source ownership remains a caller precondition. Matching bytes
must be selected through an independent trust process. A locally computed file
SHA256, ChangesHash, peer agreement or green CI cannot authenticate that choice,
the complete snapshot, its excluded state or a consensus-bound state root.

The [unsigned corpus](testdata/candidate-patch-file.json) contains 67 cases:
all 46 prior target inputs pass through owned regular files, followed by sixteen
explicit source fault controls and five count/size controls. The unchanged node
constructor and default replay execute where the selected checks permit them.
Complete original/staged/returned map digests, callbacks, raw file digests,
positional read counters, refusals and selected source inputs are independently
bound. Nil/closed/directory sources, stat/read failures, invalid returned counts,
visible growth/truncation, same-size byte changes and replay failures preserve
the original map and every alias. Source mutations are injected in owned fixture
files; these observations do not qualify a production corruption path.

`reproduce_patch_file.py` validates and copies the complete 394-blob node pin into
a separate temporary research module. It compiles a test binary with unchanged
dependency locks, runs the complete corpus twice, checks byte identity, and runs
two direct Go controls for a borrowed read-only descriptor and exact 1 MiB raw
input. The latter also checks that a file one byte above that ceiling is refused
before allocation/read/copy. All command outcomes are preserved before their
interpretation. The selected local execution used Darwin/arm64 and Go 1.25.14.
Twenty-three portable adversarial controls bind the recorded corpus. Native CI
runs the Python oracle/controls; it does not execute this Go file handoff.

```sh
python3 -I -B tools/gen-state-root-vectors/reproduce_patch_file.py \
  --node-source NODE_SOURCE --go GO_EXECUTABLE \
  --output NEW_CORPUS --evidence-directory NEW_PRIVATE_EVIDENCE_DIRECTORY
python3 -I -B tools/gen-state-root-vectors/check_patch_file.py --corpus NEW_CORPUS
python3 -I -B tools/gen-state-root-vectors/check_patch_file_test.py
```

This milestone measures no resources and publishes no production API. Whole
file-to-map resource observations are a separate next step. Actual NodeTree
storage handoff, shared/durable writers, retained-hash provenance, complete and
excluded snapshot authentication, accepted VerifiedState/header/profile/activation,
anchor, schedule, context pin, independent review and authenticated distribution
remain separate gates. Every state-value consumer stays `REFUSED`.
