# Fetching a candidate bundle

`fetch-bundle` assembles momentum headers, optional content evidence, and
account segments for later verification. It recomputes hashes and binds RPC
responses to their requested ranges. It does not independently authenticate
the generated checkpoint, validate the full chain, or establish finality.

## Peer selection

- An explicit, nonempty `--peers` list selects those endpoints, even when it
  contains one entry and `--rpc` or `ZENON_SPV_RPC` is also configured.
- An explicit `--rpc` without an explicit `--peers` overrides an environment
  peer list. An explicitly empty RPC selection fails instead of using that list.
- Without transport flags, `ZENON_SPV_PEERS` takes precedence over
  `ZENON_SPV_RPC`. `--peers ""` clears the environment peer list and permits
  the RPC fallback.
- The same resolved selection is used for momentum and account-block queries.
  Quorum zero means unanimity; positive quorum must not exceed the selected
  endpoint count. A single peer therefore permits only quorum zero or one.
- Repeated configured URL values fail before RPC or output writes. The list
  and quorum are not silently reduced, and diagnostics name only list positions.
  Comparison removes surrounding whitespace; distinct strings can still refer
  to the same underlying peer.

Endpoint counts do not establish independent operators. Multi-peer agreement
does not make a checkpoint obtained from those peers an independent trust root.

Help and usage output omit the values of `ZENON_SPV_RPC` and `ZENON_SPV_PEERS`
while preserving their runtime defaults. This keeps endpoint credentials out
of the generated defaults listing; it does not redact shell history, process
arguments, or arbitrary argument errors.

[RPC diagnostics](rpc-diagnostics.md) identify peers by their configured list
positions and omit endpoint credentials and free-form server error messages.
Status codes and failure categories remain available for troubleshooting.

## Input bounds

Invalid options fail before RPC requests or output-file writes. The command
accepts no positional arguments. `--height` must be `-1` for the frontier or
a positive final bundle height. A pinned height must exceed `--count`, leaving
room for a positive checkpoint height. A resolved frontier is checked for the
same condition before requesting its header range.

`--count` is limited to 1 through 100000 momentums, matching the verifier's
default header cap. The RPC request also includes one preceding checkpoint.
`--timeout` must be positive and bounds the overall fetch phase; the underlying
HTTP client's timeout still applies to each request.

Segment queries require positive heights. Each segment is limited to 10000
blocks, with at most 1000 segments and 100000 blocks in total, matching the
default verifier limits. Inclusive ranges ending at `uint64` maximum remain
valid when they meet those limits. Zero starts are rejected before range
arithmetic, including a zero-to-maximum range that would otherwise wrap.

Nodes may impose smaller limits; response byte caps also apply.

## Evidence and output bounds

Assembly permits at most 10000 commitments, 100000 content members per flat
evidence item, and 1000000 flat members in total. The aggregate counts every
serialized repetition: sharing a content slice in memory does not reduce its
wire or verifier cost. The command checks these limits before copying content
or fetching account segments and returns no partial evidence on refusal.

The emitted bundle uses compact JSON with a final newline, capped at 64 MiB
including that newline. Encoding proceeds by individual headers, commitments,
and account blocks so repeated flat evidence cannot create an unbounded
whole-bundle JSON scratch buffer. Headers and commitments are encoded before
account queries begin. Each fetched segment is encoded immediately, then its
decoded objects can be released before the next query. The command does not
retain a decoded list of all requested segments. A byte-limit or source error
stops further segment queries and discards the encoded prefix.

No bundle bytes are written to files or stdout until this bounded encoding
succeeds. This bounds accumulated encoded output, not process memory: header
and commitment objects, the current segment's RPC responses and decoded data
(including per-peer responses for quorum), buffer capacity, and per-item encoder
scratch space require additional memory. A single RPC response still has its
own independent 64 MiB cap. Typed RPC decoding also caps content and descendant
lists at 100,000 members each and 1,000,000 members across one response; see
[RPC query binding](rpc-query-binding.md). These transport guardrails do not
replace the collector's repeated-evidence or verifier policy checks.

The candidate can still fail signature, linkage, commitment, or policy checks.
Authenticate checkpoint provenance and run the verifier before using evidence.

## Evidence for an existing retained window

Use `--proof-only` to emit a bundle for a later
[`--retained-only` query](retained-state-queries.md). This avoids manually
removing the fetched headers. At least one `--commitments` address or
`--segments` range is required. `--checkpoint` is incompatible with this mode;
invalid combinations fail before RPC or output writes. Omitting the flag or
passing `--proof-only=false` preserves the normal header-bundle behavior.

Choose a momentum range overlapping the trusted local window and containing
the requested account blocks' commitments. A target must also have enough
strict-past depth under the query policy. Pinning `--height` to the retained
tip keeps this choice explicit; a newly fetched frontier may already be outside
that window. For example, with the tip height, scan count, account address, and
account heights selected for the application:

```sh
fetch-bundle --proof-only --rpc https://node.example \
  --height "$RETAINED_TIP_HEIGHT" --count "$SCAN_COUNT" \
  --segments "$ACCOUNT:$START_HEIGHT-$END_HEIGHT" --out proof.json

zenon-spv verify-segment --retained-only \
  --state state.json --genesis-config anchor.json proof.json
```

Pass the required protocol profile and producer schedule to the verifier as
usual. The fetcher neither opens nor updates `state.json`; the later query
revalidates that explicitly trusted state and does not write it.

The fetch phase still obtains the usual `count+1` momentum range, recomputes
RPC hashes, and builds flat-content evidence with the same peer, query, count,
byte, timeout, and publication limits. The emitted `headers` array is empty.
`chain_id` and the informational `claimed_genesis` retain their observed RPC
values; neither creates a new trust root. No checkpoint file is exported and
the diagnostics identify the evidence range rather than announce a new anchor.

Fetch success only means candidate assembly succeeded. Even hash-consistent
peer content must match a header in the independently retained state before
it can gain a verification guarantee. Missing commitments or empty matches
do not prove account inactivity, absence, or a zero balance. An unavailable
target or insufficient depth still refuses in the verifier; refresh state
separately when the application needs later headers. This mode does not add
state-value proofs, freshness, canonicality, or consensus finality.

## Output destinations and failures

Bundle and checkpoint destinations must be distinct. Before RPC, the command
resolves parent-directory symlinks and refuses duplicate paths, case-only
aliases, existing hard-link aliases, missing parent directories, and existing
non-regular destinations such as directories, symlinks, or devices. Case-only
aliases are conservatively refused even on case-sensitive filesystems. `-`
means stdout for either output, but may be selected only once.

After encoding, every file is written to a private temporary file in its
destination directory, synced, and closed before any destination is replaced.
Staging failures leave existing outputs unchanged and new outputs absent,
without emitting stdout. Temporary files are cleaned up on normal error returns.
Destinations are rechecked after staging; renamed files have mode 0600 on Unix.
Parent directories are synced after each rename on non-Windows hosts. Any file
destinations are published before stdout.

Each Unix rename replaces one complete file, but the bundle and checkpoint are
**not an atomic pair**. A crash, later rename failure, newly observable filesystem
alias, directory-sync failure, or stdout failure can leave new output visible.
Errors after publication begins report this possibility and do not retry or
roll back automatically. Directory-sync failure leaves durability unconfirmed;
Windows does not receive the Unix rename/directory-sync guarantees. A crash may
also leave a temporary file. Use trusted output directories: path checks do not
provide isolation from concurrent directory replacement or concurrent writers.
After an interrupted run, inspect both artifacts and verify their relationship
before consuming or replacing them.

## Regression evidence

CLI tests serve the pinned node-derived v1 corpus through local HTTP peers,
assert the selected endpoints, load emitted files, and verify their headers
under the synthetic experiment's depth policy. Invalid-input tests assert zero
RPC requests and unchanged existing files or absent new files. No public node
is contacted, and the fetched checkpoint remains an explicit trust assumption.

Synthetic hash-consistent RPC responses exercise repeated-evidence and byte
refusals, asserting unchanged or absent output files. These assembly tests do
not claim valid signatures. Serializer tests compare compact output with the
standard wire encoding, including nil versus empty arrays, optional fields,
exact byte limits, and early termination when the cap is exceeded.

Segment tests serve node-derived synthetic account blocks through local single-
and multi-peer RPC. They cover exact-fit encoding, refusal after a retained
prefix, late RPC errors, cancellation, and stopping later requests. CLI tests
confirm account evidence survives serialization and that late source failures
leave existing outputs unchanged or new outputs absent. Synthetic header
verification does not establish account inclusion or full node validity.

Output tests reproduce path collisions and a bad checkpoint destination before
the fix. Filesystem fault injection covers second-file creation, partial and
short writes, file sync/close, both renames, directory sync, late aliases, and
stdout failure. Tests check preserved bytes during staging, the visible prefix
after publication starts, temporary-file cleanup, and output permissions. These
are local filesystem tests, not power-loss or Windows durability experiments.

Proof-only tests serve the pinned contract-batch corpus through single and
multiple loopback peers, then verify the emitted commitments and all five
embedded blocks against an existing trusted state. They also cover frontier
selection, unchanged default mode, empty targets, forbidden checkpoint outputs,
late account errors, aggregate evidence and encoded-byte limits, and a
hash-consistent peer response whose altered content the retained state rejects.
