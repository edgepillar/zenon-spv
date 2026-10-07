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
cases, not evidence that the L1 fold stores empty values. The driver does not
execute the L1 fold, persisted `NodeTree`, RPC or activation/lifecycle paths.

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

## Remaining gates

Production v3/state-value acceptance stays disabled. These are synthetic byte
fixtures, not node consensus-valid blocks, a network activation, a live proof
RPC exercise, state-transition execution, node lifecycle qualification,
canonicality, consensus finality, freshness, authenticated producer election,
an independently reviewed protocol profile or release provenance. Address/token
text checksum boundaries, activation and context migration, verified header/RPC
binding, typed runtime results and realistic `NodeTree` measurements remain
separate implementation and qualification work.
