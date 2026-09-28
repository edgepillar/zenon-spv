# RPC query binding

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
campaign checks replayed targets and batches through verification, persistence,
and trusted resume; see [local watch scenarios](local-watch-scenarios.md).
