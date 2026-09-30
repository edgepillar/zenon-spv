# RPC query binding

## Response envelope

`Client.Call` validates the JSON-RPC envelope before decoding a result into
caller output, including when that output is nil. Following the
[JSON-RPC 2.0 response rules](https://www.jsonrpc.org/specification#response_object),
the response must declare version `2.0`, identify the request, and supply one
outcome. This client sends integer IDs and requires the same integer encoding;
string, null, decimal, and exponent-form IDs are not supported.

Missing fields, duplicate control fields, case aliases, trailing data, and
simultaneous `result` and `error` fields return `ErrInvalidRPCResponse`.
An error must contain an integer code and string message. Unrelated extension
members are ignored; a legitimate `result: null` remains valid at the envelope
layer, and a well-formed remote error is returned to the caller. Method-specific
evidence validation remains separate, so null does not supply header evidence.

Envelope failures leave caller output untouched and malformed peer fields or
values are not echoed in parser diagnostics. This does not change diagnostic
handling for valid remote errors, HTTP failures, or method-result decoding.
The existing response byte cap and HTTP timeout remain in force. Control-field
checks apply to the envelope and error object, not recursively to method data.
The ID check correlates the response format; it does not establish freshness
or prevent a peer from replaying an otherwise matching response.

## Heights and accounts

The fetch layer checks that a response answers the requested query before
it can count toward peer quorum. A self-consistent hash does not make a block
from a different height or account an answer to the original request.

`FetchByHeight`, `FetchByHeightDetailed`, and `FetchAccountBlocksByHeight`
require a positive start and count, with an inclusive last height that fits
`uint64`. Account queries also require a valid Zenon address. Invalid local
queries return `ErrInvalidQuery` before any RPC requests, including multi-peer
fan-out. Empty ranges are now rejected instead of returning empty evidence.

Each response must contain exactly the requested count, in ascending order
starting at the requested height. Account blocks must also belong to the
decoded requested address; equivalent uppercase Bech32 input remains valid.
Wrong counts, shifted ranges, duplicate or missing heights, reordered blocks,
and substituted accounts return `ErrQueryMismatch` without partial evidence.
Existing hash recomputation still applies.

Range-list decoding now stops before the first row beyond the requested count,
so an oversized list cannot allocate all of its block structs before the count
check. The response body is still read under the existing byte cap; unknown
metadata and each permitted row's nested content retain that input-byte bound.
This is not a total process-memory or decoding-time limit. A large requested
count does not preallocate that many rows or narrow `uint64` to `int`.

A repeated `list` field returns `ErrInvalidRPCResponse`, including an earlier
null or empty list and escaped/case-folded aliases. A single legacy alias is
still accepted. Other extension fields remain compatible. Decoding failures
leave the destination list unchanged; missing, null, or short lists still fail
the exact-count check. Ordinary diagnostics retain the error category without
echoing peer values, and callers can inspect the wrapped cause with `errors.Is`.

In multi-peer mode, a mismatched response is unusable and does not count
toward quorum. Too few matching responses return `ErrNotEnoughPeers`.
Conflicting usable responses still trigger the existing disagreement policy.
The agreed-frontier lookup also requires the returned header to match the
selected target height, so replaying an older header cannot produce a
caught-up watch tick for that request.

These checks bind evidence to a local query. They do not authenticate peer
identity, network freshness, canonicality, finality, or producer elections.
The fetch layer recomputes hashes; full signature, linkage, anchor, and policy
verification remains the verifier's responsibility. An agreed stale frontier
can still leave watch caught up relative to the configured peers.

Regression tests use local HTTP servers, synthetic momentums, and synthetic
mutations of the existing public account-block fixture. The offline watch
campaign checks replayed targets, oversized batches, and replaced lists through
verification, persistence, and trusted resume; see
[local watch scenarios](local-watch-scenarios.md).
