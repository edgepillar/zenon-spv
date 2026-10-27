# Candidate stream transport

This local implementation prepares a smaller transport for the existing native
candidate evidence. The workflow still uploads the original direct ZIP layout;
the new format has no hosted CI or distribution qualification yet. Original ZIPs,
manifests and source-specific reports keep their original bytes and identities.

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

Local stream controls passed 24 test roots and 63 subcases. The unchanged archive
regression passed 48 test roots and 1,018 subcases. These are source-specific local
results. The unchanged exported-directory regression also passed 13 test roots
and 35 subcases, including its source and descriptor checks. Stream controls use
the existing descriptor reader on real temporary exported files for all three
payload platform names; the selected source root is mocked in that small control.
Native platform CI is configured to run the stream controls alongside
the existing checks; that configuration is not evidence of a hosted execution.
Workflow adoption still needs exact-head native Linux/macOS/Windows CI with all
actual artifacts reconciled, plus source-bound exported-writer checks on those
hosts. The new reader is
not state-root snapshot import, accepted-header verification, network activation,
independent review or authenticated release distribution. Native state-value
refusal and the existing anchor/profile/schedule/context-pin boundaries remain
unchanged.
