# Contract batch inclusion

Contract-send descendants precede their contract-receive block on the account
chain. They also appear individually in momentum content. The native light
client verifies each block using its own `AccountHeader` target and flat content
evidence; a receive proof does not substitute for a child's evidence.

## Pinned node behavior

The references below use go-zenon commit
`3a4131e63881058b6ce2ee81d3a41d0033fafc99`:

- [`VM.finalizeEmbedded`](https://github.com/zenon-network/go-zenon/blob/3a4131e63881058b6ce2ee81d3a41d0033fafc99/vm/vm.go)
  assigns consecutive heights and previous hashes to child sends, then creates
  the receive after the last child. The receive commits the ordered child hashes.
- [`AccountBlockTransaction.GetCommits` and `AccountBlock.Previous`](https://github.com/zenon-network/go-zenon/blob/3a4131e63881058b6ce2ee81d3a41d0033fafc99/chain/nom/account_block.go)
  expose children followed by the receive. For a receive with descendants,
  `Previous()` names the frontier before the whole batch; raw `PreviousHash`
  names the last child. Account-segment linkage uses the raw field.
- The [account pool](https://github.com/zenon-network/go-zenon/blob/3a4131e63881058b6ce2ee81d3a41d0033fafc99/chain/account_pool.go)
  stores every batch height and includes whole batches in legacy selection.
  The [Dynamic Plasma selector](https://github.com/zenon-network/go-zenon/blob/3a4131e63881058b6ce2ee81d3a41d0033fafc99/pillar/content_selector.go)
  also includes the children with the receive.
- [`NewMomentumContent`](https://github.com/zenon-network/go-zenon/blob/3a4131e63881058b6ce2ee81d3a41d0033fafc99/chain/nom/momentum_content.go)
  constructs one account header per selected block and sorts those headers.

## Reproducible coverage

The [contract batch corpus](../internal/testdata/conformance/README.md#contract-batches)
contains two consecutive batches: send/send/receive at heights 1–3, then
send/receive at heights 4–5. The generator constructs that VM-shaped layout and
calls the pinned node's transaction flattening, hash, RPC serialization, and
momentum-content functions. Nine synthetic momentums provide six headers after
the committing momentum. No SPV implementation generates the expected values.

The Go tests pass the node RPC fields through local HTTP peers and offline bundle
decoding before owned-state verification and trusted local resume. Full batches,
partial batches, isolated child sends, and isolated receives accept with matching
direct evidence. Children need the full committed content list, but do not need
their sibling account bodies or the receive body for that direct proof.

Receive-only evidence leaves children `REFUSED / MissingProof`, with later
segment entries `REFUSED / ParentNotAccepted`. Removing a member from flat
content rejects the proof. Reordering, dropping, or replacing a receive's child
hashes fails RPC hash verification and returns no partial account batch.

The independent Python checker reconstructs the account and momentum preimages,
checks all RPC projections, the two notions of previous frontier, ordered child
objects, direct content membership, and strict-past depth. Go checks signatures.

## Evidence limits

These are deterministic synthetic serialization and inclusion fixtures. They do
not execute a contract VM, prove that the node would accept a transaction, or
validate a receive's claimed execution effects. Embedded blocks remain unsigned;
accepted results claim content inclusion without account-signature authenticity.
Canonicality, chain-authenticated producer authorization, state transitions,
state values, and consensus finality remain unproven. The source pin records
implementation provenance, not live network observations.
