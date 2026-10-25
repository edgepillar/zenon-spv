# Bounded R1 stream transport

`transport.py` describes or checks the bytes of a separately selected raw-ledger
export. It is a standard-library Python 3.9+ offline tool. It reads stdin, writes
small JSON metadata, opens no paths and creates no chunk, database or archive
files. Use it for the transport row of the [R1 intake](../../docs/state-root-r1-intake.md).
The existing exporter, completion consumer and independent inventory stay separate.

This is a local experimental transport format, not an agreed Zenon snapshot or
state-proof protocol. The tool does not decode put records or reconstruct an SMT.
Every result keeps origin, consistency, snapshot completeness, representative-data
acceptance, header authentication, profile/activation and state-value acceptance
explicitly false. A matching transport cannot authenticate excluded ledger state
or turn a chunk digest into a `StateRoot`.

## Select pins before reading

The controller supplies the exact byte count and SHA-256 of the raw stream, its
full Momentum height/hash and the digest of a separately protected provenance
record. Obtain these from the selected completed export/capture, not from the
candidate transport manifest. The tool checks equality and syntax; it does not
read or authenticate the provenance record or prove that the ledger view is
consistent or complete. Preserve the exporter and outer completion receipts.

Use the approved task-storage manager for capture and retention. Reserve the
operation's budget and free-space floor before acquisition. Preserve one verified
raw object, the small manifest, actual exits, capture completeness and result
receipts by reference. Do not package the raw stream again or keep one file per
chunk. This tool is independent of the local storage manager and adds no storage
adoption, cleanup or eviction behavior.

## Describe a retained stream once

Run this foreground command under the controller, feeding the retained raw object
to stdin and preserving stdout as the manifest object:

```sh
python3 -I -B tools/ledger-transport/transport.py describe \
  --expect-bytes "$R1_BYTES" --expect-sha256 "$R1_SHA256" \
  --expect-height "$R1_HEIGHT" --expect-hash "$R1_HASH" \
  --provenance-sha256 "$R1_PROVENANCE_SHA256"
```

After exact length, chunk hashing, whole-stream hashing and EOF match, stdout is
one `zenon-r1-transport-manifest/v1` object. It contains the supplied selection,
fixed `chunk_bytes`, ordered `{bytes,sha256}` rows and explicit scope flags. All
chunks except the last have the selected chunk size; there are no zero-length
chunks. An empty selected stream has no chunks and must match SHA-256 of empty
bytes. This transport case does not satisfy the exporter's nonempty-ledger gate.

Chunk rows are offsets in one logical stream. Equal chunk contents may repeat;
their hashes need not be unique. There are no filenames or provider-selected
destination paths. Record the manifest's exact byte count and SHA-256 through the
controller's protected completion channel before selecting it for a transfer.

## Check a framed transfer in one pass

Verification stdin consists of **the selected manifest's exact bytes immediately
followed by the selected raw stream**, then EOF. There is no extra separator or
ZIP container. Select `--manifest-bytes` and `--manifest-sha256` separately; never
derive them from an untrusted in-band length. Manifest selection must also match
the separately supplied whole-stream and full Momentum pins.

For example, POSIX stream composition needs no combined file:

```sh
set -o pipefail
cat "$R1_MANIFEST_OBJECT" "$R1_RAW_OBJECT" | \
  python3 -I -B tools/ledger-transport/transport.py verify \
    --manifest-bytes "$R1_MANIFEST_BYTES" \
    --manifest-sha256 "$R1_MANIFEST_SHA256" \
    --expect-bytes "$R1_BYTES" --expect-sha256 "$R1_SHA256" \
    --expect-height "$R1_HEIGHT" --expect-hash "$R1_HASH" \
    --provenance-sha256 "$R1_PROVENANCE_SHA256"
```

The actual qualification controller must retain producer/consumer exits and
complete capture evidence; pipeline syntax alone is not that evidence. Python
controllers can call `describe(reader, selection, limits)` or
`verify(reader, manifest_bytes, manifest_sha256, selection, limits)` with a bounded
binary reader. Neither API seeks, reopens inputs or writes payload bytes.

Require actual exit **0**, complete result capture and
`status: SELECTED_TRANSPORT_MATCHED`. This means the selected manifest, every
ordered chunk, the whole selected stream and EOF matched. Unknown fields,
authority claims, duplicate JSON keys, noninteger sizes, missing/extra chunks,
noncanonical chunk lengths, changed ordering/content, truncation and trailing
data refuse. A changed manifest must be selected explicitly with its new digest.
There is no implicit retry, trust renewal or partial-success receipt.

Feed the **same raw object**, without its manifest prefix, to the existing
[inventory](../ledger-inventory/README.md). Its independent put parser must still
match selected record counts and bytes. Transport success has not run inventory,
imported state, compared a reconstructed root with an accepted header or qualified
a representative workload.

## Resource and failure boundaries

| Limit | Default | Hard cap |
| --- | ---: | ---: |
| `--max-bytes` | 256 MiB | 16 GiB |
| `--max-chunk-bytes` | 16 MiB | 64 MiB |
| `--max-chunks` | 1,024 | 4,096 |
| Manifest/result metadata | 512 KiB | 512 KiB |
| One input read request | 64 KiB | 64 KiB |

The describe operation uses `--max-chunk-bytes` as its fixed chunk size. Verify
allows a selected manifest with chunks no larger than that bound. Chunk count
and declared total are checked before raw payload reads. Every manifest read is
bounded, and the whole manifest is size/digest checked before parsing or payload
consumption. Data is hashed incrementally without a chunk-sized buffer; retained
metadata is O(chunk count). The final EOF check reads at most one detection byte.
These are byte/request bounds, not an OS memory limit, physical I/O measurement,
deadline, or proof that stdin will terminate. Set an outer process deadline.

Invalid options exit 64; refused data exits 2, I/O failure normally exits 70 and
Python interruption exits 130. Failures emit UNKNOWN with a static reason and no
partial manifest or successful chunk count. A broken output can prevent any
complete receipt, and interpreter shutdown can change a nonzero exit: retain the
actual observed exit and bytes. `--help` exits 0 with UNKNOWN, never a match.
Abrupt external termination may have no receipt. Preserve every such attempt;
do not fabricate completion from a digest or repeat a completed transfer because
later metadata retention failed.

## Qualification

```sh
python3 -I -B tools/ledger-transport/transport_test.py
```

Controls use separately framed literal manifests and streams, bounded short reads,
an 8 MiB virtual stream, pre-payload refusals, changed/reordered/repeated chunks,
EOF/error/interruption/output completion and actual CLI processes. The CLI flow
also feeds the same finite put bytes to the separate inventory tool. It creates
no payload files and measures no production RSS, representative throughput or
real network/dataset acceptance.

The dedicated CI matrix runs the same controls on Linux amd64, macOS Intel amd64
and Windows amd64. Its small artifacts contain the portable scripts, README,
license, actual test report and source/run/platform manifest. No database,
payload chunks or Go binary is built or archived by this workflow. Mechanical
artifact checks and green CI remain separate from independent review,
authenticated distribution and the roadmap's real-data/profile gates.
