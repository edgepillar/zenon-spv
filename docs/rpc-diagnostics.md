# RPC diagnostics and private inputs

Ordinary RPC error formatting must not copy configured endpoints or free-form
transport and server messages into logs. Endpoints can contain credentials,
private hostnames, paths, or access tokens. A failed HTTP response or JSON-RPC
error can echo those inputs or contain terminal control sequences.

`Client.Call` reports the failing stage and, when available, cancellation or
timeout classification. HTTP failures report the numeric status without reading
or printing the error body. JSON-RPC failures report the numeric code without
printing the remote message. Envelope parsing retains its existing fixed,
field-independent diagnostic messages.

Typed fetch methods also wrap momentum and account-block conversion failures.
The ordinary message identifies the conversion stage and, when available, a
fixed category for hash mismatch, unsupported layout/type, invalid account
envelope, or invalid amount. Invalid remote addresses, token prefixes, and
other free-form conversion values are not echoed. This prevents a response
that reflects a private value from disclosing it through collector or watch
logs, and avoids repeating large invalid strings in ordinary log messages.

Wrapped transport, codec, and parse causes remain available through
`errors.Is` and `errors.As`; cancellation and deadline handling still work.
The structured remote error retains its original message for explicit local
inspection. Those underlying objects are private data: unwrapping and printing
them bypasses the ordinary-formatting boundary.

Direct typed-client conversion failures preserve their original error chain,
including codec error types and validation sentinels. Multi-peer aggregation
retains its existing quorum/disagreement categories and safe per-peer summaries;
it does not expose every individual cause through `errors.Is`.

Multi-peer failures and disagreements identify `peer[1]`, `peer[2]`, and so on,
using one-based positions in the configured list. The genesis, checkpoint,
and producer-schedule tools use the same labels in their diagnostics. Positions
do not establish independent operators or stable peer identity. Keep the
configuration available locally to correlate an error with its endpoint.

Actual requests retain their configured URLs, credentials, and query parameters.
The change does not redact account evidence, verifier results, shell/process
arguments, explicitly inspected causes, or operator provenance files. In
particular, producer schedules still retain their source peers and heights as
audit metadata. This is a boundary for RPC diagnostic formatting, not a general
scrubber for every application input or output.

Regression tests use synthetic private markers and loopback peers. They cover
request encoding, malformed URLs, transport/read/decode errors, cancellation,
deadlines, HTTP bodies, remote error messages, quorum failures, disagreement,
and all three diagnostic tools. They check that error classification and the
actual outgoing credentials survive while ordinary error text omits the markers.
Conversion cases additionally cover single/multi-peer queries, oversized private
strings, watch refusal without a save, and compiled collection that preserves
an existing candidate without partial stdout.
