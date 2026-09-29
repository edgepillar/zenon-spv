# Account envelope validation

Account segments support account-block version 1 and post-genesis block types
2 through 5. Momentum version 2 support does not imply account-block version 2
support. Unknown account layouts and unsupported types, including genesis
receive blocks, return `REFUSED` with `ReasonUnsupportedAccountBlockVersion`
or `ReasonUnsupportedAccountBlockType`. A genesis account proof needs its own
trust path; the ordinary segment API does not provide one.

The verifier rejects contradictory supported envelopes before computing hashes:

- Chain ID must be positive and equal the captured anchor's chain ID.
- Height must be positive. Height 1 requires a zero previous hash; later heights
  require a nonzero previous hash.
- User addresses require user send/receive types. Embedded-contract addresses
  require contract send/receive types.

Shape violations return `REJECT / ReasonInvalidAccountBlockEnvelope`.
A different positive chain ID returns `REJECT / ReasonChainIDMismatch`.
These checks follow the `version`, `chainIdentifier`, `blockType`, and `previous`
rules in the pinned
[node account verifier](https://github.com/zenon-network/go-zenon/blob/3a4131e63881058b6ce2ee81d3a41d0033fafc99/verifier/account_block.go).

RPC conversion applies the same context-free shape checks. It refuses unknown
versions before decoding fields with the v1 interpretation, and returns no
partial account-block batch if any item fails. Such a peer response cannot vote
in a quorum. RPC conversion has no configured trust root: the segment verifier
performs anchor chain-ID binding and signature validation.

## Regression evidence and scope

Before these gates, synthetic account blocks with unsupported versions/types,
another chain ID, zero height, inconsistent parent shape, or a user/contract
type mismatch could receive an individual `ACCEPT`. Tests reproduce that
boundary using re-signed account blocks committed by a locally verified
synthetic momentum chain. The tests now check both the core verifier and the
owned `VerifiedState` API, including propagation of rejection or refusal to
following blocks without advancing the verified parent.

This is not a signature forgery or evidence that a full node accepted the
synthetic blocks. Hash and signature validity do not establish all supported
protocol constraints by themselves.

A partial segment can still begin above height 1. The first block's nonzero
previous hash does not prove ancestry outside that segment. These checks do not
validate acknowledgements, send/receive execution, token semantics, PoW,
balances, or state transitions. They do not authenticate checkpoint provenance,
producer authorization, canonicality, or finality. Existing guarantee labels
and trust assumptions remain unchanged.
