# Candidate stream transport

This implementation prepares a smaller transport for the existing native
candidate evidence. Native CI is configured to package the tested exports into
one source-checked stream and upload it without a second compression layer.
Qualify the actual selected source, run, platform and downloaded artifact before
using a candidate. Workflow configuration alone supplies no hosted execution or
distribution acceptance. Original ZIPs, manifests and source-specific reports
keep their original bytes and identities.

The candidate reader continues to accept its nine-member stored/deflated ZIP
format. It additionally recognizes a ZIP containing exactly one ordinary stored
member, `candidate-v1.tar.xz`. Compression of that outer member is refused. The
inner payload is an XZ stream with CRC64 and a canonical USTAR member sequence:

1. `manifest.json`;
2. `offline-pilot.json`;
3. the seven original command filenames in the existing `COMMANDS` order, with
   the `.exe` suffix for a selected Windows payload.

The same payload validator checks the original source revision and input
fingerprint, corpus pins, report digest, binary byte counts and digests, complete
scenario/resource records and required skip ledger. The compressed format grants
no additional guarantee. Independently select the expected source, run, attempt,
platform, archive SHA-256 and byte count; copying expectations from a candidate
does not authenticate it.

## Bounds and completion

The writer uses LZMA2 preset 1 with a 16 MiB dictionary, without a BCJ filter.
The reader imposes a 64 MiB liblzma decoder limit and decodes at most 64 KiB per
increment. It retains the existing 256 MiB encoded archive limit, applies a
separate 256 MiB decoded-stream bound, and keeps the per-member payload limits.
Bounded metadata reads may return up to the existing
4 MiB report limit. These are implementation bounds, not a total RSS or
OS-enforced resource guarantee.

Headers must exactly match the selected member name, size and canonical USTAR
encoding. Binary permission bits are 0755; metadata permission bits are 0600;
owner/group identifiers, names and modification time are fixed to zero/empty.
No links, directories, PAX/GNU extensions, extra members or reordered members are
accepted. All data padding and the exact record-aligned footer must be zero.
Actual XZ termination, CRC64, compressed EOF and the declared encoded byte count
are required. Trailing bytes and concatenated streams are refused. Nothing is
extracted or executed by the reader.

`pack-candidate-stream.py` checks the existing exported directory against the
selected clean checkout. It streams the very same opened descriptors through
the original payload validator and encoder. Descriptor/path identities and the
checkout are rechecked before the XZ end marker is emitted. Binary stdout is
the only success payload; use a bounded owned capture channel. Keep any output
outside the selected input directory, and do not create an additional
stdout-to-ZIP copy. A failed write, flush, validation or postcheck is failure;
available output is not sufficient evidence of completion.

## Source-checked native CI preparation

After the existing exported-directory, scenario and compiled-consumer checks,
native CI creates a new sibling transport directory under the job's temporary
root. Bash fail-on-error and exclusive redirection prevent replacing an earlier
output or continuing after an incomplete writer. The source-checked writer emits
only `candidate-v1.tar.xz`; no input directory is recursively repackaged.

`check-source-candidate-stream.py` then derives the expected input fingerprint
from the selected clean checkout and hashes the completed regular stream file.
It rewinds the same descriptor, requires complete canonical decoding and applies
the existing seven-binary/report/corpus/scenario/resource/skip-ledger validator.
A final checkout check and unchanged path/descriptor identity, size and timestamp
checks precede its small JSON receipt. Read, decode, checkout, identity or output
delivery failures produce nonzero exits. No payload is extracted or executed,
and no wrapper ZIP or second stream file is created by this readback.

For a locally produced stream, run from the selected checkout:

```sh
python3 -I -B tools/check-source-candidate-stream.py \
  --archive "$SELECTED_XZ" \
  --expect-revision "$SELECTED_CHECKOUT_REVISION" \
  --expect-os "$SELECTED_OS" \
  --expect-architecture "$SELECTED_ARCHITECTURE" \
  --require-skip-ledger
```

The receipt's digest identifies the bytes read. Authenticate a downloaded
artifact separately using its independently selected repository, CI run/attempt,
checkout, platform and GitHub archive digest.

Candidate upload requires successful writer/readback completion in addition to
the existing pilot, exported-directory and scenario gates. The pinned upload
action uses `archive: true` and `compression-level: 0`, producing the existing
single stored-member ZIP envelope. Artifact names, the separate pilot-report
uploads and their 14-day retention remain unchanged. The original nine-member
ZIP reader remains supported; original evidence is never converted or replaced.

The job keeps its tested executables for the existing consumer checks and adds
one bounded compressed file. This change targets retained artifact and transport
bytes; it does not establish a smaller peak CI workspace, total RSS budget or
whole-CI speedup. Keep actual per-source/platform observations separate from the
earlier local comparison below.

## Check a directly selected stream

The existing archive checker accepts a raw XZ only when `--raw-stream` is
explicitly selected. Use the same independently selected revision, input
fingerprint and platform expectations. Here the selected SHA-256 is the raw XZ
file's digest, rather than a wrapping ZIP's digest:

```sh
python3 -I -B tools/check-candidate-archive.py \
  --archive "$SELECTED_XZ" \
  --expect-archive-sha256 "$SELECTED_XZ_SHA256" \
  --expect-revision "$SELECTED_CHECKOUT_REVISION" \
  --expect-inputs "$SELECTED_INPUTS_SHA256" \
  --expect-os "$SELECTED_OS" \
  --expect-architecture "$SELECTED_ARCHITECTURE" \
  --require-skip-ledger --raw-stream
```

This bounded read-only path hashes the selected regular file and applies the
same canonical stream and complete payload checks used inside the single-member
ZIP. It creates no wrapper archive, extracted files or payload copy. Without
the flag, the existing ZIP formats remain required; raw mode refuses either ZIP
layout. Incomplete streams, wrong pins, missing required skip records and output
delivery failures keep their existing nonzero results. This option does not
authenticate a digest supplied by the same untrusted source as the payload.

A local comparison of the retained real Linux, macOS and Windows payloads
matched the direct stream, ZIP-wrapped stream and original ZIP results, including
the five existing Windows skips. That comparison reused the protected source
archives, wrote no output payload files and executed no downloaded binaries.
It qualifies this local read path, not a new hosted candidate or release.

## Measurement and adoption status

An exploratory local prototype processed the retained Linux, macOS and Windows
candidate payloads without downloading them or creating output archive files.
All transformations and incremental readbacks ran on one local host, rather
than on the three target systems. The prototype used lexical TAR member order;
the implementation above uses the validator's required manifest/report-first
order.

| Prototype profile | Original ZIP bytes | XZ bytes | Local summed elapsed time |
| --- | ---: | ---: | ---: |
| Preset 1, no BCJ | 93,275,118 | 59,195,156 | 14.54 s |
| Preset 1, x86 BCJ | 93,275,118 | 59,690,836 | 14.43 s |
| Preset 6, x86 BCJ | 93,275,118 | 57,298,108 | 41.36 s |

Each observation includes source ZIP CRC/EOF, payload hashes and incremental
codec readback. The first Linux observation was reused, not repeated for local
accounting. These finite observations support the prototype profile choice;
they do not qualify current implementation performance, whole-CI speedup,
production RSS budgets or format adoption. No original evidence object or
manifest was replaced, deleted, consolidated or relabelled.

The implementation's subsequent comparison preserved every original member byte
and the existing source, report, binary and skip checks. Its three outer stored
ZIPs would total 59,194,592 bytes, versus 93,275,118 original ZIP bytes: about
36.54% less logical transport. The same inputs were also compared through an
independent standard-library XZ/TAR reader. The summed local observation was
17.55 seconds, including repeated payload validation and independent readbacks;
this is a different workload from the prototype timing above. All comparisons
ran on one local host without downloading, executing or writing archive payload
files. The Windows report still records its original five skips.

The first comparison command completed its macOS assertions, then failed while
closing an in-memory buffer. Its actual failure and output remain retained. The
completed macOS assertions were reconciled from that output; only Linux and
Windows comparisons ran afterward. No overall successful exit is attributed to
the first command, and its full compressed digest was not emitted before failure.

Local stream controls passed 29 test roots and 80 subcases. The unchanged archive
regression passed 48 test roots and 1,018 subcases. These are source-specific local
results. The unchanged exported-directory regression also passed 13 test roots
and 35 subcases, including its source and descriptor checks. Stream controls use
the existing descriptor reader on real temporary exported files for all three
payload platform names; the selected source root is mocked in that small control.
Native platform CI is configured to run the stream controls alongside
the existing checks; that configuration is not evidence of a hosted execution.
The scenario companion also retains all 30 original controls and adds one pin
integrity control, passing 31 roots and 75 subcases locally. The stream suite
loads that companion as an integration control. Its fixed reader byte count and
SHA-256 require an explicit reviewed update; changed-size and same-size changed
helpers remain refused before import. The initial failed companion-pin check
and the new regression's failing result before rebinding remain retained.
For the configured workflow, require exact-head native Linux/macOS/Windows CI
and reconcile every actual artifact, including the source-bound writer/readback
steps on those hosts. The new reader is
not state-root snapshot import, accepted-header verification, network activation,
independent review or authenticated release distribution. Native state-value
refusal and the existing anchor/profile/schedule/context-pin boundaries remain
unchanged.
