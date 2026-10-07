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
package. Its selected Ethereum dependency requires CGO, so only wire generation
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

## Remaining gates

Production v3/state-value acceptance stays disabled. These are synthetic byte
fixtures, not node consensus-valid blocks, a network activation, a live proof
RPC exercise, state-transition execution, node lifecycle qualification,
canonicality, consensus finality, freshness, authenticated producer election,
an independently reviewed protocol profile or release provenance. Address/token
text checksum boundaries, activation and context migration, verified header/RPC
binding, typed runtime results and realistic `NodeTree` measurements remain
separate implementation and qualification work.
