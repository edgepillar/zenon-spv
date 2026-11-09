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
receipts by reference. Read ranges in place when the full raw object is
available. For an interrupted transfer, reuse the protected fragment references
and retain one object per digest. This tool is independent of the local storage
manager. Ownership and retention stay with the controller.

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

## Verify only the missing range

For an interrupted transfer, choose a contiguous group of missing chunks from
the independently pinned manifest. Indices are zero-based. The following
example plans one chunk using only the exact manifest bytes:

```sh
python3 -I -B tools/ledger-transport/transport.py plan-range \
  --manifest-bytes "$R1_MANIFEST_BYTES" --manifest-sha256 "$R1_MANIFEST_SHA256" \
  --expect-bytes "$R1_BYTES" --expect-sha256 "$R1_SHA256" \
  --expect-height "$R1_HEIGHT" --expect-hash "$R1_HASH" \
  --provenance-sha256 "$R1_PROVENANCE_SHA256" \
  --first-chunk "$R1_MISSING_CHUNK" --chunk-count 1 < "$R1_MANIFEST_OBJECT"
```

`SELECTED_RANGE_PLANNED` provides a zero-based byte offset, exact range length
and ordered chunk pins. Use those fields to bound the replacement acquisition.
The [HTTPS range command](#recover-one-verified-https-range) accepts a single
planned chunk when the URL serves the exact selected stream. For a
range-capable transport, the last byte is `offset + bytes - 1`. Keep source
identity, transfer and storage ownership in the existing controller.
To check the replacement, use `verify-range` with the same arguments and supply
the exact manifest followed immediately by only the selected bytes, then EOF.
An existing manifest object and selected fragment can be streamed together
without writing a combined file.

Require actual exit 0, complete capture and `SELECTED_RANGE_MATCHED`.
It checks each selected chunk's size and digest and the range EOF. The report
keeps `whole_stream_digest_verified` false even for a range covering every
chunk. When the full set is available, stream the manifest and fragments in
order to `verify` or to the [combined inventory recount](../ledger-export/README.md#check-the-transport-manifest-during-the-recount).
That final pass checks the independent whole-stream digest. Prior successful
fragment receipts and actual failed attempts remain distinct records.

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
EOF/error/interruption/output completion and actual CLI processes. The controls
include replacing one missing chunk before final ordered verification and
refusing to treat a range as a verified whole stream. The CLI flow also feeds
the same finite put bytes to the separate inventory tool. Its evidence is scoped
to the bounded synthetic data and process outcomes.

The dedicated CI matrix runs the same controls on Linux amd64, macOS Intel amd64
and Windows amd64. Its small artifacts contain the portable scripts, README,
license notices, actual test report and source/run/platform manifest. The
Python sources retain their GPL-3.0-only SPDX declarations; the package includes
the complete [GPL text](../gen-state-root-vectors/LICENSE), the repository MIT
notice and [component notices](THIRD_PARTY_NOTICES). No database,
payload chunks or Go binary is built or archived by this workflow. Mechanical
artifact checks and green CI remain separate from independent review,
authenticated distribution and the roadmap's real-data/profile gates.

## Observe an archive directory before acquiring its payload

The separate `archive_index.py` is an offline ZIP/ZIP64 directory observer. It
helps budget R1 source acquisition without downloading or unpacking a multi-GiB
archive. Stdin is one separately selected **final tail** of an archive. It opens
no paths, makes no HTTP request, creates no files and never opens a ZIP member.
The existing raw-stream transport commands and manifest remain unchanged.

Select the archive's length and advertised SHA-256 separately, then retain a
bounded tail and its actual completion, exact length and SHA-256 through the
approved manager. An HTTP controller must require the selected range, `206`,
exact `Content-Range` and length, identity content encoding and a matching strong
ETag/conditional request. Refuse a full-body response to a range request. ETag
equality is a transport observation, not snapshot or publisher authentication.
This tool does not perform or authenticate that HTTP selection. Do not retry a
completed transfer merely because later metadata promotion fails.

The separate [conditional tail getter](#acquire-one-selected-https-tail) now
provides this bounded acquisition step. Retain its actual stdout, stderr receipt
and completion under the controller before selecting the tail for this observer.

```sh
python3 -I -B tools/ledger-transport/archive_index.py \
  --archive-bytes "$ARCHIVE_BYTES" --archive-sha256 "$ADVERTISED_ARCHIVE_SHA256" \
  --tail-bytes "$TAIL_BYTES" --tail-sha256 "$TAIL_SHA256" < "$TAIL_OBJECT"
```

Require actual exit 0, complete capture and `SELECTED_DIRECTORY_OBSERVED`.
The observer checks the tail digest/EOF, a unique end record, adjacent complete
directory, ZIP64 agreement, entry count, supported stored/deflated encoding,
single-disk offsets, ordinary member types and unambiguous paths. It returns
aggregate file/byte counts by the first two path components, including `.ldb`,
`.log` and `MANIFEST-` counts. Member names are not listed individually; review
group labels before publishing a report. Noncanonical encodings outside this
tool's subset refuse; refusal does not establish that an archive is invalid ZIP.

| Limit | Default | Hard cap |
| --- | ---: | ---: |
| Selected final tail | 1 MiB | 4 MiB |
| Members | 10,000 | 16,384 |
| Declared total unpacked bytes | 32 GiB | 128 GiB |
| Declared bytes per member | 16 GiB | 64 GiB |
| Archive logical length | 1 TiB | 1 TiB |
| Group count / name bytes / result bytes | 64 / 512 / 64 KiB | same |
| One input read request | 64 KiB | 64 KiB |

The four configurable limits use `--max-tail-bytes`, `--max-members`,
`--max-unpacked-bytes` and `--max-file-bytes`. Limit syntax is checked before
reading. The directory must fit in the selected tail; there is no implicit larger
fetch. Tail bytes, bounded names and group counters determine memory, not the
archive's logical payload length. Set an outer deadline; these are not measured
RSS, I/O or OS quota guarantees. The API freezes selection and limits before the
first read. Diagnostics contain static codes, never input paths.

**Directory sizes are unverified claims.** No local header, member payload, CRC,
decompressed size or whole-archive SHA-256 is checked. The supplied whole digest
is recorded as selection only; the tail cannot authenticate its pairing with
that digest. This result is neither extraction-safety qualification nor a bound
on actual decompressor allocation. It does not establish that the node stopped,
database consistency, network/frontier identity or a collected R1 dataset.

For a later approved acquisition, reserve one complete archive, bounded selected
extraction, any independent working clone and one bounded export, plus the
production floor and other reservations. Charge a clone's full logical size;
do not assume shared APFS blocks reduce the budget. Stream the whole archive
once, verify its selected SHA-256 and completion, then independently enforce
extraction limits. Never use directory observation as permission to extract,
open a database or adopt unowned historical data. The read-only frontier exporter
still requires an independently selected full momentum and a consistent copy.

```sh
python3 -I -B tools/ledger-transport/archive_index_test.py
```

Finite literal directories, a standard-library ZIP encoder, logical >4 GiB
offsets, 10,000 members, malformed ranges/records, alias/type/encoding/size
refusals, short reads, actual CLI exits and failed output controls create no
payload files. They are not real dataset measurements. Three-platform CI retains
only source, licenses and small reports for the stream, directory and tail suites.
The current `zenon-r1-transport-ci/v3` package binds all three suites. Retained
v1 stream-only and v2 stream/directory packages keep their original identities
and coverage; they are not rewritten or relabeled. Raw-stream manifest formats
remain unchanged.

## Acquire one selected HTTPS tail

`archive_tail.py` is a separate read-only HTTPS getter. Select the URL, complete
archive length, advertised archive SHA-256, exact final-tail length and strong
ETag before starting it. These pins come from the intended source/acquisition
record, not a candidate directory manifest. URLs must be ASCII HTTPS references
without userinfo, fragments or control characters; pass credentials through
neither this command nor its output.

```sh
python3 -I -B tools/ledger-transport/archive_tail.py \
  --url "$ARCHIVE_URL" --archive-bytes "$ARCHIVE_BYTES" \
  --archive-sha256 "$ADVERTISED_ARCHIVE_SHA256" \
  --tail-bytes "$TAIL_BYTES" --etag "$STRONG_ETAG"
```

Run it through the approved storage controller. Binary stdout is the raw tail;
stderr is a small JSON receipt. Keep one CAS payload and its actual exit and
complete streams, without a stdout-to-ZIP copy or extracted member files. Only
actual exit 0, complete capture and `SELECTED_TAIL_CAPTURED` admit the tail for
the directory observer. Its `tail.bytes` and `tail.sha256` can then select that
same retained object as the observer's stdin. The tool opens no destination path.
The controller must serialize acquisition under the selected artifact's lease
and reuse a previously verified matching object by reference. This stateless
getter does not acquire storage leases, adopt caches or implement retention.

One GET requests the exact final byte range, `If-Match` with the selected strong
ETag, and identity content encoding. It uses Python's normal verified HTTPS
handler and does not follow redirects, retry, enlarge the tail or fall back to
a full response. A whole very small archive is allowed only when its entire
length was explicitly selected as the bounded tail. The conditional request uses
[HTTP preconditions](https://www.rfc-editor.org/rfc/rfc9110.html#section-13.1.1)
and [byte ranges](https://www.rfc-editor.org/rfc/rfc9110.html#section-14.2); this
tool deliberately supports a restricted response subset.

Before calling a body read, require 206, unchanged response URL, one exact
`Content-Range`, one exact `Content-Length` and one matching strong ETag. Duplicate
framing fields, transfer encoding and non-identity content encoding refuse.
Unknown extra headers do not create authority. The admitted header set is at
most 64 fields / 16 KiB; Python's HTTP parser buffers headers before this check,
so this is not a pre-parser or OS memory bound. Refusal before a body read does
not promise zero wire traffic or zero buffering by the HTTP stack.

| Limit | Default | Hard cap |
| --- | ---: | ---: |
| Selected tail / `--max-tail-bytes` | 1 MiB | 4 MiB |
| Selected archive logical length | caller-supplied | 1 TiB |
| `--timeout-seconds` | 15 | 60 |
| One body read request | 64 KiB | 64 KiB |

The timeout applies to blocking socket operations; an elapsed check also runs
between open/read/flush operations. Incremental `read1` is preferred when the
response supports it, so a progressing peer does not hold one coalescing body
read while elapsed checks wait. An external process deadline is still
required: these checks are not an OS-enforced total latency, RSS or disk quota.
The API freezes selections and limits before opening. A SHA-256 is computed over
the exact streamed tail, followed by the HTTP response body's EOF check and a
successful stdout flush. It does not inspect bytes outside the framed response.

Failures keep binary stdout separate from metadata: a partial tail may already
have been emitted. UNKNOWN receipts have static reasons, without URLs, ETags,
private labels, body bytes or exception text. Invalid options exit 64, rejected
responses/data exit 2, I/O failures normally exit 70 and Python interruption exits
130. Failed diagnostic output can leave no complete receipt; interpreter shutdown
can alter a nonzero exit. Preserve the observed exit and bytes rather than
inferring completion or retrying a finished attempt after a bookkeeping failure.
Help exits 0 with UNKNOWN and no payload.

ETag/range matching is a selected transport observation. The advertised whole
archive digest is recorded only as `sha256_selection`, not verified by a tail.
Neither this getter nor the directory observer establishes archive provenance,
member integrity, database consistency/completeness, reconstructed SMT root,
accepted-header binding, network activation or state-value acceptance. Existing
raw-stream manifests and independent inventory/import gates remain unchanged.

```sh
python3 -I -B tools/ledger-transport/archive_tail_test.py
```

Controls use bounded synthetic readers and the real stdlib HTTPS-handler/error
chain with controlled responses. Actual child entrypoints check binary/receipt
separation and refuse 200/302/412 responses before body consumption. A selected
literal tail also feeds the independent directory observer. No live TLS peer,
real archive, dataset, server deployment or state-proof acceptance is qualified.
The three-platform CI package binds this third suite and its sources separately.

## Recover one verified HTTPS range

Run `plan-range` with `--chunk-count 1` using the independently pinned
manifest. Select the URL and strong ETag for that exact byte representation.
Use the plan's selection length and SHA-256 for the whole-stream pins. Take
the offset from `range.offset` and the length and digest from the sole
`range.chunks` entry. A manifest for a raw export and a URL for a compressed
archive select different byte streams.

```sh
python3 -I -B tools/ledger-transport/archive_tail.py range \
  --url "$ARCHIVE_URL" --etag "$STRONG_ETAG" \
  --archive-bytes "$R1_BYTES" --archive-sha256 "$R1_SHA256" \
  --offset "$R1_RANGE_OFFSET" --range-bytes "$R1_RANGE_BYTES" \
  --range-sha256 "$R1_RANGE_SHA256" --max-range-bytes "$R1_RANGE_BYTES"
```

The range mode uses one conditional GET and the same strict response
admission, deadlines and 64 KiB read bound as the tail command. Its default
limit is 1 MiB. An explicit `--max-range-bytes` permits up to 64 MiB for a
larger manifest chunk. It checks the selected offset and byte count against
the representation before opening the request.

Reserve the selected size with the storage controller and stream stdout
under the artifact lease with the expected length and SHA-256. Reuse a
verified matching CAS object when available. Admit a new fragment only after
actual exit 0, complete capture, a matching object digest and the
`zenon-r1-archive-range/v1` receipt with status `SELECTED_RANGE_MATCHED`.
Retain the receipt with its manifest and chunk references. A refusal may
already have emitted unverified bytes. Keep the actual failure record and
exclude those bytes from the ordered stream.

The successful receipt establishes the selected fragment's length, SHA-256
and framed response EOF. Once every chunk is available, the existing
`verify` command checks the full ordered stream against its independent
digest. The range receipt keeps whole-archive and ledger acceptance fields
false. The portable tests exercise the CLI from a planned middle chunk
through a controlled HTTPS response to the independent `verify-range` check.
