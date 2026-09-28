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

Endpoint counts do not establish independent operators. Multi-peer agreement
does not make a checkpoint obtained from those peers an independent trust root.

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
whole-bundle JSON scratch buffer. No bundle bytes are written to files or stdout
until this bounded encoding succeeds. This bounds accumulated encoded output,
not process memory: RPC responses, decoded objects, buffer capacity, and
per-item encoder scratch space require additional memory.

The candidate can still fail signature, linkage, commitment, or policy checks.
Authenticate checkpoint provenance and run the verifier before using evidence.

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

Output tests reproduce path collisions and a bad checkpoint destination before
the fix. Filesystem fault injection covers second-file creation, partial and
short writes, file sync/close, both renames, directory sync, late aliases, and
stdout failure. Tests check preserved bytes during staging, the visible prefix
after publication starts, temporary-file cleanup, and output permissions. These
are local filesystem tests, not power-loss or Windows durability experiments.
