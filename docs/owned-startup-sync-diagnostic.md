# Bounded startup sync observation

The retained [main-source attempt](owned-devnet-main-readiness-attempt-2026-11-14.md)
showed 29 candidate H1 responses and no H2/H3 transition. Its archive lacks
protocol sync state, so it cannot distinguish a node waiting for peers from a
node reporting sync completion at the unchanged frontier. The cause of the H1
plateau remains open.

## Source contract

At node `2835c436b197fece5c76adf4ba8dc1decca2e3ea`,
[the public stats namespace](https://github.com/digitalSloth/go-zenon/blob/2835c436b197fece5c76adf4ba8dc1decca2e3ea/rpc/apis.go#L113-L121)
exposes `stats.syncInfo`.
[The getter](https://github.com/digitalSloth/go-zenon/blob/2835c436b197fece5c76adf4ba8dc1decca2e3ea/rpc/api/stats.go#L151-L153)
returns the broadcaster's protocol sync information. The DTO contains exactly
`state`, `currentHeight` and `targetHeight`.

[The source enum](https://github.com/digitalSloth/go-zenon/blob/2835c436b197fece5c76adf4ba8dc1decca2e3ea/protocol/interfaces.go#L15-L26)
is `Unknown=0`, `Syncing=1`, `SyncDone=2`, `NotEnoughPeers=3`.
[The implementation](https://github.com/digitalSloth/go-zenon/blob/2835c436b197fece5c76adf4ba8dc1decca2e3ea/protocol/sync.go#L154-L179)
compares the local height with the best protocol peer's target, then applies
the configured `MinPeers` gate. A target of zero is possible without a best
peer. This is the node's reported observation; it does not authenticate the
chain or establish finality, healthy producers or an eventual v3 transition.

The client requires an integer state in `0..3`, a positive uint64 current height
and a uint64 target height including zero. Booleans, strings, additional fields
and larger integers are refused. The DTO itself has no chain ID or header hash.
No trust input or selected header is derived from it.

## Bounded diagnostic reads, followed by the original refusal

The controller invokes the capture only after its initial selected-height
readiness call refuses with `owned_rpc_readiness_deadline`. It preserves that
failure and performs at most one diagnostic read before owned cleanup. There is
no retry or fixture-configuration transition even if a diagnostic reports a
height above the requested threshold. Other failure reasons, successful startup
and gateway readiness do not select this extension.

A valid sync observation permits one later `ledger.getFrontierMomentum` read.
It uses the next shared request ID, a fresh budget check and the existing 128 KiB
frontier bound. This captures a candidate hash alongside the later height report.
An unavailable sync observation selects no follow-up. Both reads keep their
five-second HTTP / seven-second command bounds and share the unchanged 96-call
cap. They provide sequential observations rather than an atomic snapshot.

The checked 90-second / 30-attempt readiness policy, shared 96-call cap, total
evidence bound and resource guard remain. The diagnostic has an 8 KiB response
cap and the existing five-second HTTP / seven-second command bounds. A fresh
budget refusal or exhausted call cap starts no new command. This source change
does not execute an experiment or authorize another signed fixture.

## Evidence and failure handling

The optional `owned-devnet-startup-sync/v1` summary binds the startup trigger,
diagnostic status/reason, selected request ID and an observed response filename.
Its header-authority and production flags must be false. Selection is limited
to that summary and at most one matching `rpc-NN.request.json` /
`rpc-NN.sync-info.json` pair for IDs `1..96`.

For sync `OBSERVED`, the reader requires the exact empty-parameter `stats.syncInfo`
request, original response ID/bytes, bounded DTO and complete successful
quiescent command with its matching started record. An orphan response, mismatched
request/receipt or diagnostic attached to a completed consumer is refused.

Failure and incomplete outcomes preserve actual receipt fields without exporting
the unsuccessful body or stderr. `REFUSED` reports a recorded capture/validation
refusal; its omitted body is not independently revalidated. `UNKNOWN` retains
uncertain capture or interruption, with null exit/completeness when no command
receipt exists. `NOT_ATTEMPTED` describes a shared-call or budget refusal and
does not fabricate a successful transport. An interrupted controller retains
the original trigger while ending as `UNKNOWN`.

No peer lists, names, addresses, service logs or private configuration are added.
The accepted-header path, explicit anchor/profile/schedule/context pins,
header-derived root and three-proof native consumer remain separate. Legacy
archives without the optional diagnostic retain their report shape. The original
non-accepting archives and their failure records are unchanged.

The optional `owned-devnet-post-sync-frontier/v1` summary binds the observed sync
request to the next frontier request. Its body follows the ordinary validated
frontier export path. The reader requires that exact request/response/command
binding and one later candidate. Failed or incomplete reads preserve the actual
receipt without exporting the unsuccessful body. A shared-call refusal must
refer to sync request 96. The original refusal remains, including when the later
candidate has already reached H3 or higher. This observation cannot populate an
anchor, producer authorization or context pin.

The [source-b8bae80 attempt](owned-devnet-sync-attempt-2026-11-14.md) retained the
original single-read format. Its later reported height of two has no captured
matching header hash. Existing archives receive no backfilled observation.

## Controls and remaining execution gate

Portable DTO, selection, budget/call-cap and interruption controls accompany a
real recorder/finalizer/reader control. The latter gives a node a reported height
of 99 while preserving the original refusal and no consumer comparison. Separate
owned child processes exercise exit 7 and a partial-output timeout, retaining
their actual exits while excluding their response bodies.

These are isolated synthetic controls. They run no node or signing operation.
Exact-source hosted CI, archive qualification and any later separately authorized
owned experiment remain distinct exits. Selected-network D2/D3/D5 acceptance,
representative R1 measurements and applicable review/release/production gates
remain open.
