# Raw NodeTree store roundtrip on the selected successor

This component experiment transports a complete controlled raw NodeTree store
through the selected node's Patch dump/load primitives. An independent model
checks every stored record, retained identifier, root and selected canonical
proof before and after restoration, tail updates, truncation and fork reuse.
It does not implement or authenticate a production snapshot importer.

## Source and input selection

The source is all 467 blobs of
`digitalSloth/go-zenon@9c71ae82fc983e16f914ae085d4034030c8ebe3b`, with its own
`go.mod` and `go.sum`. The unchanged experimental identity, terminal and offline
caller layers select runtime tree `e60c875a06361f04d05301c0e4c61fd429995c5a`.
The original tree is `d0f5dfb09e737a806cfc743bb6ba9ddd101ebcd6`.

Only `common/trie`, raw LevelDB and `common/db` Patch primitives execute.
The staged chain caller is pinned but its wrappers do not compile or execute in
this experiment. One new tagged test is added to a fresh source copy; existing
test sources and module files remain unchanged. The returned build selects
`./common/trie`, and execution selects only
`TestCandidateRawKVRoundtripSuccessor`. No compiler overlays or race hooks are
added. Experimental disk format 3 remains separate from original format 2;
there is no automatic migration, existing-database adoption or activation claim.

Before any probe launch, the independent oracle seals 65 controlled unsigned
identifiers, 64 logical keys and nine proof keys per retained state. Thirty-two
balance-shaped keys and thirty-two contract-storage-shaped keys exercise the
selected L1 whitelist. These are synthetic logical patches, with no source
genesis, ledger traversal or agreed balance-value encoding. A nonempty 32-byte
zero value remains present; an empty Put deletes a leaf in this L1 adapter.
Excluded generic key domains are not promoted to committed state. Present-empty
L2 semantics are outside this selection.

The backend receives only the sealed operations, identifiers, query keys and
policy. Expected roots, proofs, serialized nodes and refcounts stay with the
independent comparator. The model separately compares compressed-DAG roots with
full sparse levels and derives the complete serialized store, including format,
frontier, nodes, refcounts, version roots and retained hash records.

## Recorded local execution

One ordinary binary runs on a macOS arm64 host with Go 1.25.14 and CGO enabled.
Two successful normal processes cover archive retention and an explicit short
retention of 5. This short value is a functional test override, not a production
rollback policy.

| Stage | Archive retained heights | Short retention |
| --- | --- | --- |
| Seed through 64, close and reopen | 1 through 64 | 59 through 64 |
| Restore into a fresh raw database, close and reopen | 1 through 64 | 59 through 64 |
| Append 65, close and reopen | 1 through 65 | 60 through 65 |
| Truncate to selected G/60, close and reopen | 1 through 60 | 60 |
| Reuse height 61 under X/61, close and reopen | G/1 through G/60, X/61 | G/60, X/61 |

The fork applies the same logical changes as G/61. The resulting root is equal,
but G/61 still refuses with `version-hash-mismatch` and X/61 succeeds. Pruned
history does not reappear after truncation. Root and a separate Prove call are
checked for every selected G/X query, including refusals.

The ten stages check 3,015 canonical proof positions and 1,300 root/probe-error
query pairs. They contain eight distinct complete store states, with 2,974 shared
raw-record preimages and 585 unique canonical proof preimages. All raw records,
including serialized internal nodes and refcounts, match the independently
selected model. These controlled records are not evidence of a real ledger's
completeness or a network's canonical root.

Two earlier probe launches refused their inputs before creating a database:
the private supervisor initially supplied mismatched environment names and an
existing workspace path. A later archive process completed successfully, but
the supervisor rejected its output because it selected the wrong frame prefix.
The original failures and database image remain protected. The complete original
archive capture was recovered and checked without another archive process or
build; the corrected extraction logic was also exercised against that capture.
Four isolated supervisor contract controls cover fresh archive/short workspaces,
an existing destination and a missing input. The final short-retention process
completed through the corrected supervisor. These distinctions are retained in
the [execution metadata](../tools/gen-state-root-vectors/testdata/successor-raw-kv-roundtrip-execution.json).

The successful processes took approximately 0.84 and 0.88 seconds, including
fixture construction and all queries. Observed process peak RSS was 67,518,464
and 29,982,720 bytes. These single-host functional observations are not accepted
resource budgets, controlled performance comparisons or production capacity.

## Byte framing and bounded evidence

The selected `goleveldb.Batch.Dump` returns the record body, without the journal's
sequence/count header. Export iterates raw records in key order and creates Put
records. Restore uses `NewPatchFromDump`, checks Load success before Replay, and
replays into one raw LevelDB batch followed by one synchronous Write. No
enableDelete wrapper is used. Load borrows its input, so an owned immutable dump
buffer is retained and its SHA-256 rechecked through replay and write.

The strict research decoder accepts bounded canonical Put-only bodies with
nonempty increasing unique keys and minimal uint64 varints. This is narrower
than the selected node's general Batch parser. A complete record-boundary prefix
can be valid grammar; independently selected length, record count and SHA-256
are still required. Dump SHA-256, record-manifest SHA-256 and SMT roots are
different values and cannot substitute for one another.

The configured bounds are 8 MiB per dump, 32,768 records, 128-byte keys,
1 MiB values, 32 MiB process stdout and a 256 MiB aggregate fresh database
workspace. The observed maximum dump is 275,262 bytes. Task admission retains
the 10 GiB free-space floor plus declared expected allocations and reservations.
Failure images and outputs become durable before any cleanup acknowledgement.
Closed workspaces require complete named-file inventories and quiet process
groups; unknown files, links, mounts and uncertain processes remain held.

The two original JSON observation payloads total 5,444,456 bytes. The
[shared corpus](../tools/gen-state-root-vectors/testdata/successor-raw-kv-roundtrip-corpus.json)
is 1,833,034 bytes. Explicit indexed tables preserve every raw record and proof
byte once and reconstruct the complete observation semantics. Original JSON
whitespace and field order are omitted: original transport bytes are not
reconstructed or rehashed by this reader. Their separately selected capture
digests are bound by the pinned execution metadata. No recursive ZIP, hard-linked
evidence, repeated source download or second reference build is introduced.
This representation reduction is not a historical-cache cleanup or a measured
physical disk reclaim amount.

| Evidence | SHA-256 |
| --- | --- |
| Independent expectations before all launches | `1e25aceb4f8f164e5ea1910dea0db0c9a49cbb2ff1fe2feb71d0e88953fa6512` |
| Operations and identifier selection | `5052b65d63205d8bbe3fc14a22e72fcead69cce83710d75d2bec2f3701ce3b68` |
| Ordinary reference binary | `c27178c52e2c641555be44b49ae632b9e08d0249cf76a918ef48dad83e857030` |
| Local comparison including original failures | `dd1386854b1f8d70266f325c614f36a27c40b59f22636d1d441d59a2d318b5f1` |
| Closed-task/process readback | `467a980403c00d0e1610596b25c5805addf053eaf3fc7c75dbda2183dc4d5f3a` |
| Shared portable corpus | `dc176eaf518f13d9d90f467f98319bbda8269096e0e44b4ca3db49188db62814` |

These unsigned digests establish byte identity, not source or distribution
authentication.

## Portable checks and reproduction

```sh
python3 -I -B tools/gen-state-root-vectors/raw_kv_roundtrip_codec_test.py -v
python3 -I -B tools/gen-state-root-vectors/raw_kv_roundtrip_successor_model_test.py -v
python3 -I -B tools/gen-state-root-vectors/prepare_raw_kv_roundtrip_successor_test.py -v
python3 -I -B tools/gen-state-root-vectors/check_raw_kv_roundtrip_successor_test.py -v
python3 -I -B tools/gen-state-root-vectors/raw_kv_roundtrip_successor_corpus_test.py -v
python3 -I -B tools/gen-state-root-vectors/check_raw_kv_roundtrip_successor_corpus_test.py -v
python3 -I -B tools/gen-state-root-vectors/check_raw_kv_roundtrip_successor_corpus.py
```

The portable controls and recorded reader execute no new node, compiler,
database or resource measurement. Running them on Linux or Windows does not
turn the recorded macOS reference process into native reference execution on
those hosts. Exact-source CI, artifact validation and independent review remain
separate checks.

For a new component observation, obtain the complete selected source in an owned
workspace and verify dependencies against its own sums. The preparer accepts
`--node-source`, a fresh `--workspace` and `--go`, returns commands, and executes
nothing. Independently seal the oracle and input selection first. The caller
owns source acquisition, private caches, process supervision, quotas, exact
environment binding and evidence-before-cleanup acknowledgement. No historical
database or cache is adopted.

The experiment does not run Chain.Init/Start, a full node, network access,
wallets, signing or transactions. A constructor reopening a copied raw store
does not authenticate the entire DAG or a snapshot. Snapshot completeness,
accepted header/profile/activation binding, real consumer trust inputs,
representative resource acceptance, crash/power-loss qualification, independent
review and authenticated distribution remain open. Runtime state values remain
`REFUSED`.
